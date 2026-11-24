"""Autonomous Single-Domain Certificate Authority (`AutonomousDomainCAService`).

Eliminates shared multi-domain CA private keys:
- Each instance (`alpha-ca` in `lineage-alpha`, `beta-ca` in `lineage-beta`,
  `payment-ca` in `lineage-pay`) generates and holds ONLY its own single `TrustDomainCA`
  (`ES256`) and its own single `X509DomainAuthority` (`ECDSA P-256`) private keys in RAM.
- Strictly rejects Kubernetes ServiceAccount JWTs from any namespace other than
  `self.allowed_k8s_namespace`.
- Exports read-only public federation bundles (`GET /v1/federation/bundle`: public ES256
  JWKs + X.509 Root CA PEM, zero private keys) for cross-domain verification.
- Issues holder-bound `JWT-SVID` + `X.509-SVID` leaf certificates over caller-generated
  public keys verified via `lct-ca-pop+jwt` Proof-of-Possession.
"""

from __future__ import annotations

import ssl
import threading
import time
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from lineage.audit import AuditCollectorClient, AuditEventType, AuditStreamEmitter
from lineage.common.crypto import (
    CryptoError,
    KeyPair,
    compute_jwk_thumbprint,
    jws_verify_compact,
    require_finite_timestamp,
    sha256_b64url,
)
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.common.mtls import MTLSError, X509DomainAuthority
from lineage.federation.anchors import compute_bundle_trust_anchor
from lineage.federation.locators import (
    DomainDescriptorStore,
    ServiceLocator,
    SignedDomainDescriptor,
    ingest_descriptor_http_request,
)
from lineage.identity import IdentityError, TrustBundleResolver, TrustDomainCA
from lineage.k8s.bootstrap_services import K8sServiceAccountVerifier, _extract_bearer
from lineage.protocol import (
    DPoPError,
    JTIReplayCache,
    LatticeError,
    PermissionLattice,
    TokenError,
    mint_root_token,
)
from lineage.revocation import RevocationError, RevocationEvent

class AutonomousDomainCAService:
    """Physically isolated single-domain CA issuing `JWT-SVID` + `X.509-SVID`."""

    def __init__(
        self,
        trust_domain: str,
        allowed_k8s_namespace: str,
        audit_collector_url: Optional[str] = None,
        authorized_gateway_sa: Optional[str] = None,
        authorized_revocation_sas: Optional[Iterable[str]] = None,
        authorized_directory_sas: Optional[Iterable[str]] = None,
        sa_path_overrides: Optional[Mapping[str, str]] = None,
        k8s_verifier: Optional[K8sServiceAccountVerifier] = None,
        allowed_audiences: Optional[Iterable[str]] = None,
        host: str = "0.0.0.0",
        port: int = 8090,
        federation_port: Optional[int] = None,
        ca_private_key_pem: Optional[str] = None,
        x509_private_key_pem: Optional[str] = None,
        x509_root_cert_pem: Optional[str] = None,
        audit_ssl_context_provider: Optional[Callable[[], Optional[ssl.SSLContext]]] = None,
        audit_locator_provider: Optional[Callable[[], Sequence[ServiceLocator]]] = None,
        audit_ssl_for_locator: Optional[Callable[[ServiceLocator], Optional[ssl.SSLContext]]] = None,
        best_effort_audit: bool = False,
        descriptor_store: Optional[DomainDescriptorStore] = None,
        allowed_locator_cidrs: Optional[Iterable[str] | str] = None,
        on_descriptor_learned: Optional[Callable[[SignedDomainDescriptor], None]] = None,
        oidc_verifier: Optional[Any] = None,
        require_oidc_user_token: bool = False,
    ) -> None:
        self.trust_domain = trust_domain
        self.allowed_k8s_namespace = allowed_k8s_namespace
        self.authorized_gateway_sa = authorized_gateway_sa
        self.sa_path_overrides: Dict[str, str] = dict(sa_path_overrides or {})
        self.descriptor_store = descriptor_store
        self.allowed_locator_cidrs = allowed_locator_cidrs
        self.on_descriptor_learned = on_descriptor_learned
        self.oidc_verifier = oidc_verifier
        self.require_oidc_user_token = bool(require_oidc_user_token)
        self._desc_lock = threading.Lock()
        self._descriptor_version = int(time.time() * 1000)

        domain_short = trust_domain.strip().lower().removeprefix("org-").split(".", 1)[0]
        self.authorized_revocation_sas = frozenset(
            str(s).strip()
            for s in (
                authorized_revocation_sas
                if authorized_revocation_sas is not None
                else (f"{domain_short}-revocation", "revocation", "revocation-svc")
            )
            if str(s).strip()
        )
        self.authorized_directory_sas = frozenset(
            str(s).strip()
            for s in (
                authorized_directory_sas
                if authorized_directory_sas is not None
                else (f"{domain_short}-directory", "directory", "directory-svc")
            )
            if str(s).strip()
        )

        # Strictly ONE domain's ES256 CA + NameConstraints-bound X.509 Root CA!
        init_kp = (
            KeyPair.from_private_pem(ca_private_key_pem)
            if ca_private_key_pem is not None
            else None
        )
        self.ca = TrustDomainCA(trust_domain, alg="ES256", initial_keypair=init_kp)
        self.x509_ca = X509DomainAuthority(
            trust_domain,
            allowed_dns_suffixes=(
                f".{allowed_k8s_namespace}.svc.cluster.local",
                f".{allowed_k8s_namespace}.svc",
                f".{trust_domain}",
                trust_domain,
                "localhost",
            ),
            private_key_pem=x509_private_key_pem,
            root_cert_pem=x509_root_cert_pem,
        )
        self.local_resolver = TrustBundleResolver()
        self.local_resolver.register_domain_ca(self.ca)

        default_auds = (f"lct-ca-{trust_domain}", "lct-federation-ca")
        self.k8s_verifier = k8s_verifier or K8sServiceAccountVerifier(
            allowed_audiences=allowed_audiences or default_auds
        )
        self._pop_replay_cache = JTIReplayCache(ttl_seconds=300.0)
        self._audit_emitter: Optional[AuditStreamEmitter] = (
            AuditStreamEmitter(
                self.ca,
                collector_client=AuditCollectorClient(
                    audit_collector_url or "",
                    ssl_context_provider=audit_ssl_context_provider,
                    locator_provider=audit_locator_provider,
                    ssl_context_for_locator=audit_ssl_for_locator,
                ),
                stream_id=f"spiffe://{trust_domain}/authority/root",
                best_effort_remote=best_effort_audit,
            )
            if (audit_collector_url or audit_locator_provider is not None)
            else None
        )
        self.http = ManagedHTTPService(
            service_name=f"domain-ca-{trust_domain}",
            dispatcher=self._dispatch,
            host=host,
            port=port,
        )
        self.federation_http: Optional[ManagedHTTPService] = (
            ManagedHTTPService(
                service_name=f"domain-ca-fed-{trust_domain}",
                dispatcher=self._dispatch_federation_readonly,
                host=host,
                port=int(federation_port),
            )
            if federation_port is not None
            else None
        )

    def start(self) -> str:
        url = self.http.start()
        if self.federation_http is not None:
            self.federation_http.start()
        return url

    def stop(self) -> None:
        if self._audit_emitter is not None:
            self._audit_emitter.stop()
        if self.federation_http is not None:
            self.federation_http.stop()
        self.http.stop()

    @property
    def base_url(self) -> str:
        return self.http.base_url

    @property
    def federation_base_url(self) -> Optional[str]:
        return self.federation_http.base_url if self.federation_http is not None else None

    @property
    def trust_anchor(self) -> str:
        raw_bundle = self.ca.export_public_bundle()
        raw_bundle["x509_root_pem"] = self.x509_ca.export_root_pem()
        return compute_bundle_trust_anchor(raw_bundle)

    def export_federation_bundle(self) -> Dict[str, Any]:
        """Export public-only ES256 JWKs + X.509 Root CA PEM + SHA-256 trust anchor."""
        bundle = self.ca.export_public_bundle()
        bundle["x509_root_pem"] = self.x509_ca.export_root_pem()
        bundle["trust_anchor"] = compute_bundle_trust_anchor(bundle)
        return bundle

    def publish_domain_locators(
        self,
        locators: Mapping[str, Iterable[ServiceLocator | Mapping[str, Any]]],
        ttl_seconds: float = 3600.0,
    ) -> SignedDomainDescriptor:
        """Sign and publish an updated `SignedDomainDescriptor` with strictly monotonic `version`."""
        with self._desc_lock:
            self._descriptor_version = max(
                self._descriptor_version + 1, int(time.time() * 1000)
            )
            ver = self._descriptor_version
        desc = SignedDomainDescriptor.sign_with_domain_ca(
            self.ca,
            x509_root_pem=self.x509_ca.export_root_pem(),
            locators=locators,
            version=ver,
            ttl_seconds=ttl_seconds,
            allowed_cidrs=self.allowed_locator_cidrs,
        )
        if self.descriptor_store is not None:
            self.descriptor_store.set_own_descriptor(desc)
        return desc

    def _resolve_workload_path(self, k8s_ns: str, k8s_sa: str) -> str:
        if k8s_ns != self.allowed_k8s_namespace:
            raise PermissionError(
                f"Autonomous CA for {self.trust_domain!r} rejects foreign namespace "
                f"{k8s_ns!r} (only {self.allowed_k8s_namespace!r} permitted)"
            )
        if k8s_sa in self.sa_path_overrides:
            return self.sa_path_overrides[k8s_sa]
        if k8s_sa in self.authorized_revocation_sas:
            return "/ns/sys/sa/revocation"
        if k8s_sa in self.authorized_directory_sas:
            return "/ns/sys/sa/directory"
        return f"/ns/{k8s_ns}/sa/{k8s_sa}"

    def _validate_allowed_dns_sans(
        self, k8s_ns: str, k8s_sa: str, requested_dns: Any
    ) -> list[str]:
        canonical = [
            f"{k8s_sa}.{self.trust_domain}",
            f"{k8s_sa}.{k8s_ns}.svc.cluster.local",
            f"{k8s_sa}.{k8s_ns}.svc",
            "localhost",
        ]
        allowed_set = set(canonical)
        if requested_dns is None:
            return canonical
        if not isinstance(requested_dns, list):
            raise ValueError("dns_names must be a list of strings")
        for d in requested_dns:
            ds = str(d).strip().lower()
            if ds and ds not in allowed_set:
                raise ValueError(
                    f"SA {k8s_ns}/{k8s_sa} is forbidden from requesting unauthorized DNS SAN {ds!r}"
                )
        return canonical

    def _dispatch_federation_readonly(
        self, req: HTTPRequestContext
    ) -> Tuple[int, Any, Dict[str, str]]:
        """External cross-cluster federation port: serves ONLY `/healthz` & public bundles."""
        if req.method == "GET" and req.path == "/healthz":
            return (
                200,
                {
                    "status": "ok",
                    "trust_domain": self.trust_domain,
                    "mode": "federation_readonly",
                    "trust_anchor": self.trust_anchor,
                },
                {},
            )
        if req.method == "GET" and req.path in (
            "/v1/federation/bundle",
            "/v1/ca/bundles",
        ):
            return 200, self.export_federation_bundle(), {}
        if req.method == "GET" and req.path == "/v1/federation/descriptors":
            if self.descriptor_store is None:
                return 200, {"trust_domain": self.trust_domain, "descriptors": []}, {}
            return 200, self.descriptor_store.export_gossip_payload(), {}
        if req.method == "POST" and req.path == "/v1/federation/descriptors":
            return ingest_descriptor_http_request(
                req,
                self.descriptor_store,
                on_descriptor_learned=self.on_descriptor_learned,
            )
        return (
            403,
            {
                "error": "federation_endpoint_read_only",
                "detail": f"Route {req.method} {req.path} is forbidden on external read-only federation CA port",
            },
            {},
        )

    def _dispatch(self, req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return (
                200,
                {
                    "status": "ok",
                    "trust_domain": self.trust_domain,
                    "allowed_namespace": self.allowed_k8s_namespace,
                    "trust_anchor": self.trust_anchor,
                },
                {},
            )

        if req.method == "GET" and req.path in (
            "/v1/federation/bundle",
            "/v1/ca/bundles",
        ):
            return 200, self.export_federation_bundle(), {}

        if req.method == "GET" and req.path == "/v1/federation/descriptors":
            if self.descriptor_store is None:
                return 200, {"trust_domain": self.trust_domain, "descriptors": []}, {}
            return 200, self.descriptor_store.export_gossip_payload(), {}

        # All mutating CA routes require a K8s SA JWT strictly in `self.allowed_k8s_namespace`!
        try:
            sa_jwt = _extract_bearer(req.header("Authorization"))
            k8s_ns, k8s_sa, sa_exp = self.k8s_verifier.verify_sa_jwt(sa_jwt)
            workload_path = self._resolve_workload_path(k8s_ns, k8s_sa)
        except Exception as exc:
            return 403, {"error": "k8s_sa_attestation_failed", "detail": str(exc)}, {}

        if req.method == "POST" and req.path == "/v1/ca/issue-workload":
            body = req.json()
            public_jwk = body.get("public_jwk")
            pop_jws = body.get("pop_jws")
            if not isinstance(public_jwk, Mapping):
                return 400, {"error": "missing_public_jwk"}, {}
            if not isinstance(pop_jws, str) or not pop_jws.strip():
                return 400, {"error": "missing_pop_jws"}, {}

            now_ts = time.time()
            try:
                jwk_dict = dict(public_jwk)
                expected_jkt = compute_jwk_thumbprint(jwk_dict)
                _, pop_claims = jws_verify_compact(
                    pop_jws.strip(), jwk_dict, expected_typ="lct-ca-pop+jwt"
                )
                if pop_claims.get("jkt") != expected_jkt:
                    raise CryptoError("PoP jkt mismatch with public_jwk")
                if pop_claims.get("sa_jwt_sha256") != sha256_b64url(sa_jwt.encode("ascii")):
                    raise CryptoError("PoP sa_jwt_sha256 binding mismatch")
                pop_iat = require_finite_timestamp(pop_claims.get("iat"), "pop_jws.iat")
                if abs(now_ts - pop_iat) > 30.0:
                    raise CryptoError("PoP JWS iat outside 30s freshness window")
                pop_jti = str(pop_claims.get("jti") or "").strip()
                if not pop_jti:
                    raise CryptoError("PoP JWS missing jti")
                if not self._pop_replay_cache.check_and_record(
                    f"{k8s_ns}/{k8s_sa}:{pop_jti}", now=now_ts
                ):
                    raise CryptoError("Replayed PoP JWS jti rejected")

                req_ttl = require_finite_timestamp(
                    body.get("ttl_seconds", 1800.0), "ttl_seconds"
                )
                if req_ttl < 1.0 or req_ttl > 7200.0:
                    return 400, {"error": "invalid_ttl_seconds"}, {}
                effective_ttl = min(req_ttl, 7200.0, max(1.0, sa_exp - now_ts + 30.0))

                dns_sans = self._validate_allowed_dns_sans(
                    k8s_ns, k8s_sa, body.get("dns_names")
                )
                spiffe_id, svid, iat, exp = self.ca.sign_svid_for_public_jwk(
                    workload_path=workload_path,
                    public_jwk=jwk_dict,
                    ttl_seconds=effective_ttl,
                )
                x509_leaf_pem = self.x509_ca.issue_x509_svid(
                    spiffe_id=spiffe_id,
                    public_jwk=jwk_dict,
                    dns_names=dns_sans,
                    ip_addresses=("127.0.0.1",),
                    ttl_seconds=effective_ttl,
                )
            except (CryptoError, DPoPError, IdentityError, MTLSError, ValueError, TypeError) as exc:
                return 400, {"error": "invalid_workload_csr", "detail": str(exc)}, {}

            out_issue: Dict[str, Any] = {
                "trust_domain": self.trust_domain,
                "spiffe_id": spiffe_id,
                "workload_svid": svid,
                "x509_leaf_pem": x509_leaf_pem,
                "x509_root_pem": self.x509_ca.export_root_pem(),
                "bundle": self.export_federation_bundle(),
                "issued_at": iat,
                "expires_at": exp,
            }
            if self.descriptor_store is not None:
                out_issue["descriptors"] = self.descriptor_store.export_gossip_payload()[
                    "descriptors"
                ]
            return 200, out_issue, {}

        if req.method == "POST" and req.path in (
            "/v1/ca/learn-descriptors",
            "/v1/federation/descriptors",
        ):
            status_code, out_body, hdrs = ingest_descriptor_http_request(
                req,
                self.descriptor_store,
                on_descriptor_learned=self.on_descriptor_learned,
            )
            return status_code, out_body, hdrs

        # Root user-token minting & domain-CA audit logging gated to authorized entry gateway SA
        if (
            self.authorized_gateway_sa is None
            or k8s_sa != self.authorized_gateway_sa
        ):
            return (
                403,
                {"error": "gateway_only_endpoint", "caller": f"{k8s_ns}/{k8s_sa}"},
                {},
            )

        if req.method == "POST" and req.path == "/v1/ca/mint-root-token":
            body = req.json()
            req_td = str(body.get("trust_domain", self.trust_domain))
            if req_td != self.trust_domain:
                return (
                    403,
                    {
                        "error": "cross_domain_root_mint_forbidden",
                        "detail": (
                            f"Autonomous CA for {self.trust_domain!r} holds ONLY its own root key "
                            f"and cannot mint tokens for {req_td!r}"
                        ),
                    },
                    {},
                )
            raw_oidc_token = str(body.get("user_oidc_token") or "").strip()
            hop0_oidc_detail: Optional[Dict[str, Any]] = None
            resolved_sub = str(body.get("sub") or "").strip()

            if raw_oidc_token or self.require_oidc_user_token:
                if not raw_oidc_token:
                    return (
                        401,
                        {
                            "error": "missing_user_oidc_token",
                            "detail": "Domain CA requires a cryptographic Hop-0 user_oidc_token",
                        },
                        {},
                    )
                if self.oidc_verifier is None:
                    return (
                        401,
                        {
                            "error": "oidc_verifier_not_configured",
                            "detail": "user_oidc_token supplied, but OIDC JWKS verifier is not configured",
                        },
                        {},
                    )
                try:
                    verified_oidc = self.oidc_verifier.verify_jwt(raw_oidc_token)
                except Exception as exc:
                    return (
                        401,
                        {
                            "error": "invalid_user_oidc_token",
                            "detail": str(exc),
                        },
                        {},
                    )
                if resolved_sub and resolved_sub != verified_oidc.canonical_lct_sub:
                    return (
                        403,
                        {
                            "error": "oidc_sub_mismatch",
                            "detail": f"Requested sub {resolved_sub!r} != verified OIDC identity {verified_oidc.canonical_lct_sub!r}",
                        },
                        {},
                    )
                resolved_sub = verified_oidc.canonical_lct_sub
                hop0_oidc_detail = {
                    "hop0_oidc_bridged": True,
                    "oidc_issuer": verified_oidc.issuer,
                    "oidc_username": verified_oidc.username,
                    "oidc_jti": verified_oidc.jti,
                }

            try:
                if not resolved_sub:
                    raise ValueError("Missing sub (provide sub or user_oidc_token)")
                mint_ttl = require_finite_timestamp(
                    body.get("ttl_seconds", 900.0), "ttl_seconds"
                )
                if mint_ttl < 1.0 or mint_ttl > 7200.0:
                    raise ValueError("ttl_seconds must be within [1.0, 7200.0]")
                max_depth_raw = body.get("max_depth", 6)
                if isinstance(max_depth_raw, bool) or not isinstance(max_depth_raw, int):
                    raise ValueError("max_depth must be an integer")
                if max_depth_raw < 1 or max_depth_raw > 16:
                    raise ValueError("max_depth must be within [1, 16]")
                perms = PermissionLattice.from_dict(body["permissions"])
                tok = mint_root_token(
                    self.ca,
                    task_id=str(body["task_id"]),
                    sub=resolved_sub,
                    sender_jkt=str(body["sender_jkt"]),
                    first_hop_spiffe_id=str(body["first_hop_spiffe_id"]),
                    first_hop_jkt=str(body["first_hop_jkt"]),
                    permissions=perms,
                    max_depth=max_depth_raw,
                    ttl_seconds=mint_ttl,
                    hop_segment=str(body.get("hop_segment", "OrchestratorAlpha")),
                    first_hop_public_jwk=body.get("first_hop_public_jwk"),
                    first_hop_return_endpoint=body.get("first_hop_return_endpoint"),
                )
            except (
                KeyError,
                ValueError,
                TypeError,
                CryptoError,
                IdentityError,
                TokenError,
                LatticeError,
            ) as exc:
                return 400, {"error": "invalid_mint_request", "detail": str(exc)}, {}

            if self._audit_emitter is not None:
                self._audit_emitter.emit(
                    event_type=AuditEventType.ROOT_MINT,
                    task_id=tok.task_id,
                    sub=tok.sub,
                    lineage_path=tok.lineage_path,
                    hop_index=0,
                    epoch=0,
                    root_block_hash=tok.root_block_hash,
                    current_block_hash=tok.leaf_block_hash,
                    decision="ALLOW",
                    permissions_summary=perms.to_dict(),
                    action_detail=hop0_oidc_detail,
                )
            out_mint: Dict[str, Any] = {
                "compact_token": tok.encode_compact(),
                "task_id": tok.task_id,
                "sub": tok.sub,
                "lineage_path": tok.lineage_path,
                "root_block_hash": tok.root_block_hash,
                "hop0_oidc_bridged": bool(hop0_oidc_detail),
            }
            if hop0_oidc_detail:
                out_mint["oidc_bridge"] = hop0_oidc_detail
            return 200, out_mint, {}

        if req.method == "POST" and req.path == "/v1/ca/emit-revocation-audit":
            body = req.json()
            req_td = str(body.get("trust_domain", self.trust_domain))
            if req_td != self.trust_domain:
                return 403, {"error": "cross_domain_audit_forbidden"}, {}
            raw_rev = body.get("revocation_event")
            if not isinstance(raw_rev, Mapping):
                return 400, {"error": "missing_revocation_event"}, {}
            try:
                rev_ev = RevocationEvent.from_dict(dict(raw_rev))
                if not rev_ev.service_svid or not rev_ev.service_signature:
                    raise RevocationError("RevocationEvent missing service_svid or signature")
                svid_claims = self.local_resolver.verify_workload_svid(
                    rev_ev.service_svid,
                    expected_spiffe_id=f"spiffe://{self.trust_domain}/ns/sys/sa/revocation",
                )
                _, signed_claims = jws_verify_compact(
                    rev_ev.service_signature,
                    svid_claims["cnf"]["jwk"],
                    expected_typ="lct-revocation-event+jwt",
                )
                if signed_claims != rev_ev.core_claims():
                    raise RevocationError("RevocationEvent signature claims mismatch")
                task_id_str = str(body["task_id"])
                target_prefix_str = str(body["target_prefix"])
                if (
                    rev_ev.trust_domain != self.trust_domain
                    or rev_ev.target != target_prefix_str
                    or not target_prefix_str.startswith(f"/{task_id_str}/")
                ):
                    raise RevocationError("RevocationEvent target/domain mismatch")
                if self._audit_emitter is not None:
                    self._audit_emitter.emit(
                        event_type=AuditEventType.REVOCATION_ISSUED,
                        task_id=task_id_str,
                        sub=str(body["sub"]),
                        lineage_path=target_prefix_str,
                        hop_index=int(body.get("hop_index", 1)),
                        epoch=int(body.get("epoch", 0)),
                        root_block_hash=str(body["root_block_hash"]),
                        current_block_hash=str(body["current_block_hash"]),
                        decision="REVOKED",
                        action_detail={
                            "target": rev_ev.target,
                            "revocation_version": rev_ev.version,
                            "trust_domain": self.trust_domain,
                        },
                    )
            except (
                KeyError,
                ValueError,
                TypeError,
                CryptoError,
                IdentityError,
                RevocationError,
            ) as exc:
                return (
                    403,
                    {"error": "unverified_revocation_audit_rejected", "detail": str(exc)},
                    {},
                )
            return 200, {"logged": True}, {}

        return 404, {"error": "route_not_found"}, {}
