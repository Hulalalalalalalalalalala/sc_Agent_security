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

from collections import OrderedDict
import json
import ssl
import threading
import time
from typing import Any, Callable, Dict, FrozenSet, Iterable, Mapping, Optional, Sequence, Tuple

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
    ContinuationBudgetError,
    DPoPError,
    JTIReplayCache,
    LatticeError,
    LineageToken,
    PermissionLattice,
    RootBlock,
    TaskCheckpoint,
    TokenError,
    decode_token,
    mint_continuation_root_token,
    mint_root_token,
)
from lineage.protocol.token import verify_root_block_signature_ignoring_expiry
from lineage.revocation import RevocationError, RevocationEvent


def parse_consent_issuer_policy(
    raw: Optional[Mapping[str, Tuple[str, Iterable[str]]] | str],
) -> Dict[str, Tuple[str, FrozenSet[str]]]:
    """Parse `k8s_sa -> (bound_owner_sub, allowed_consent_tools)` policy map or semicolon string."""
    if raw is None:
        return {}
    out: Dict[str, Tuple[str, FrozenSet[str]]] = {}
    if isinstance(raw, Mapping):
        for sa_key, val in raw.items():
            clean_sa = str(sa_key or "").strip()
            if not clean_sa:
                continue
            owner_sub, tools_iter = val
            clean_owner = str(owner_sub or "").strip()
            clean_tools = frozenset(str(t).strip() for t in tools_iter if str(t).strip())
            if clean_owner and clean_tools:
                out[clean_sa] = (clean_owner, clean_tools)
        return out

    for entry in str(raw).split(";"):
        part = entry.strip()
        if not part or "=" not in part:
            continue
        sa_name, rhs = part.split("=", 1)
        clean_sa = sa_name.strip()
        if ":" not in rhs:
            continue
        owner_sub, tools_csv = rhs.rsplit(":", 1)
        clean_owner = owner_sub.strip()
        clean_tools = frozenset(t.strip() for t in tools_csv.split(",") if t.strip())
        if clean_sa and clean_owner and clean_tools:
            out[clean_sa] = (clean_owner, clean_tools)
    return out

class AutonomousDomainCAService:
    """Physically isolated single-domain CA issuing `JWT-SVID` + `X.509-SVID`."""

    def __init__(
        self,
        trust_domain: str,
        allowed_k8s_namespace: str,
        audit_collector_url: Optional[str] = None,
        authorized_gateway_sa: Optional[str] = None,
        authorized_gateway_sas: Optional[Iterable[str]] = None,
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
        federation_trust_resolver: Optional[TrustBundleResolver] = None,
        authorized_auditors: Iterable[str] = (),
        consent_issuer_policy: Optional[Mapping[str, Tuple[str, Iterable[str]]] | str] = None,
        max_tracked_roots: int = 16_384,
    ) -> None:
        self.trust_domain = trust_domain
        self.allowed_k8s_namespace = allowed_k8s_namespace
        self.authorized_gateway_sa = authorized_gateway_sa
        gw_set = {str(s).strip() for s in (authorized_gateway_sas or ()) if str(s).strip()}
        if authorized_gateway_sa:
            gw_set.add(str(authorized_gateway_sa).strip())
        self._authorized_gateway_sas = frozenset(gw_set)
        self._consent_issuer_policy = parse_consent_issuer_policy(consent_issuer_policy)
        self._max_tracked_roots = max(256, int(max_tracked_roots))
        self._cont_lock = threading.Lock()
        self._issued_roots: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._consumed_checkpoint_ids: "OrderedDict[str, float]" = OrderedDict()
        self._superseded_prior_roots: "OrderedDict[Tuple[str, str], str]" = OrderedDict()
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
        self.federation_trust_resolver: TrustBundleResolver = (
            federation_trust_resolver if federation_trust_resolver is not None else self.local_resolver
        )
        self.federation_trust_resolver.register_domain_ca(self.ca)

        default_auds = (f"lct-ca-{trust_domain}", "lct-federation-ca")
        self.k8s_verifier = k8s_verifier or K8sServiceAccountVerifier(
            allowed_audiences=allowed_audiences or default_auds
        )
        self._pop_replay_cache = JTIReplayCache(ttl_seconds=300.0)
        remote_collector = (
            AuditCollectorClient(
                audit_collector_url or "",
                ssl_context_provider=audit_ssl_context_provider,
                locator_provider=audit_locator_provider,
                ssl_context_for_locator=audit_ssl_for_locator,
            )
            if (audit_collector_url or audit_locator_provider is not None)
            else None
        )
        self._audit_emitter: AuditStreamEmitter = AuditStreamEmitter(
            self.ca,
            collector_client=remote_collector,
            stream_id=f"spiffe://{trust_domain}/authority/root",
            best_effort_remote=best_effort_audit,
            authorized_auditors=authorized_auditors,
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

    def _record_issued_root(self, root: RootBlock) -> None:
        """Record an issued `RootBlock` in the CA's bounded authoritative root ledger."""
        rh = root.block_hash()
        rec = {
            "root_block_hash": rh,
            "task_id": root.task_id,
            "sub": root.sub,
            "delegate_spiffe_id": root.delegate_spiffe_id,
            "permissions": root.permissions,
            "issuer_trust_domain": root.issuer_trust_domain,
            "iat": root.iat,
            "exp": root.exp,
        }
        with self._cont_lock:
            if rh in self._issued_roots:
                self._issued_roots.pop(rh)
            elif len(self._issued_roots) >= self._max_tracked_roots:
                self._issued_roots.popitem(last=False)
            self._issued_roots[rh] = rec

    def _resolve_verified_prior_root(
        self,
        ckpt: TaskCheckpoint,
        raw_prior_root_token: Any = None,
    ) -> Optional[Dict[str, Any]]:
        """Authoritatively resolve & verify `ckpt.prior_root_block_hash` (fail-closed)."""
        with self._cont_lock:
            existing = self._issued_roots.get(ckpt.prior_root_block_hash)
            if existing is not None:
                if (
                    existing["task_id"] == ckpt.task_id
                    and existing["sub"] == ckpt.sub
                    and existing["issuer_trust_domain"] == self.trust_domain
                ):
                    return dict(existing)

        if raw_prior_root_token is None or raw_prior_root_token == "":
            return None
        try:
            prior_root: Optional[RootBlock] = None
            if isinstance(raw_prior_root_token, Mapping):
                prior_root = RootBlock.from_dict(raw_prior_root_token)
            elif isinstance(raw_prior_root_token, str):
                s = raw_prior_root_token.strip()
                if s.startswith("{"):
                    prior_root = RootBlock.from_dict(json.loads(s))
                else:
                    parsed_t = decode_token(s)
                    if isinstance(parsed_t, LineageToken):
                        prior_root = parsed_t.root
            if prior_root is None:
                return None
            if (
                prior_root.issuer_trust_domain != self.trust_domain
                or prior_root.task_id != ckpt.task_id
                or prior_root.sub != ckpt.sub
                or prior_root.block_hash() != ckpt.prior_root_block_hash
            ):
                return None
            verify_root_block_signature_ignoring_expiry(prior_root, self.local_resolver)
            self._record_issued_root(prior_root)
            return {
                "root_block_hash": prior_root.block_hash(),
                "task_id": prior_root.task_id,
                "sub": prior_root.sub,
                "delegate_spiffe_id": prior_root.delegate_spiffe_id,
                "permissions": prior_root.permissions,
                "issuer_trust_domain": prior_root.issuer_trust_domain,
                "iat": prior_root.iat,
                "exp": prior_root.exp,
            }
        except Exception:
            return None

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
        if req.method == "GET" and req.path == "/v1/audit/local":
            return self._audit_emitter.local_store.serve_http_query(
                req,
                self.federation_trust_resolver,
                node_spiffe_id=self.ca.root_authority_spiffe_id,
                require_task_id=True,
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

        if req.method == "GET" and req.path == "/v1/audit/local":
            return self._audit_emitter.local_store.serve_http_query(
                req,
                self.federation_trust_resolver,
                node_spiffe_id=self.ca.root_authority_spiffe_id,
                require_task_id=True,
            )

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

        if req.method == "POST" and req.path == "/v1/ca/mint-consent-token":
            if k8s_sa not in self._consent_issuer_policy:
                return (
                    403,
                    {
                        "error": "CONSENT_ISSUER_FORBIDDEN",
                        "caller": f"{k8s_ns}/{k8s_sa}",
                        "detail": "Caller ServiceAccount is not authorized in CONSENT_ISSUER_POLICY",
                    },
                    {},
                )
            bound_owner_sub, allowed_consent_tools = self._consent_issuer_policy[k8s_sa]
            body = req.json()
            req_td = str(body.get("trust_domain", self.trust_domain))
            if req_td != self.trust_domain:
                return 403, {"error": "cross_domain_root_mint_forbidden"}, {}

            requested_sub = str(body.get("sub") or bound_owner_sub).strip()
            if requested_sub != bound_owner_sub:
                return (
                    403,
                    {
                        "error": "CONSENT_SUB_MISMATCH",
                        "detail": f"Caller {k8s_sa!r} may only mint consent for {bound_owner_sub!r}, got {requested_sub!r}",
                    },
                    {},
                )

            raw_oidc_consent = str(body.get("user_oidc_token") or "").strip()
            if not raw_oidc_consent:
                return (
                    401,
                    {
                        "error": "OWNER_CONSENT_PROOF_REQUIRED",
                        "detail": "Cryptographic owner user_oidc_token is mandatory for /v1/ca/mint-consent-token",
                    },
                    {},
                )
            if self.oidc_verifier is None:
                return (
                    403,
                    {
                        "error": "OWNER_CONSENT_PROOF_REQUIRED",
                        "detail": "Domain CA oidc_verifier is not configured to verify owner consent",
                    },
                    {},
                )
            try:
                verified_owner = self.oidc_verifier.verify_jwt(raw_oidc_consent)
            except Exception as exc:
                return (
                    401,
                    {
                        "error": "INVALID_OWNER_CONSENT_PROOF",
                        "detail": str(exc),
                    },
                    {},
                )
            if verified_owner.canonical_lct_sub != bound_owner_sub:
                return (
                    403,
                    {
                        "error": "CONSENT_OIDC_SUB_MISMATCH",
                        "detail": f"Verified OIDC owner {verified_owner.canonical_lct_sub!r} != bound {bound_owner_sub!r}",
                    },
                    {},
                )

            try:
                perms_c = PermissionLattice.from_dict(body["permissions"])
                if not perms_c.tools or not set(perms_c.tools).issubset(allowed_consent_tools):
                    return (
                        403,
                        {
                            "error": "CONSENT_TOOL_FORBIDDEN",
                            "detail": f"Requested consent tools {sorted(perms_c.tools)!r} exceed allowed {sorted(allowed_consent_tools)!r}",
                        },
                        {},
                    )
                if perms_c.max_amount is not None and float(perms_c.max_amount) != 0.0:
                    return (
                        403,
                        {
                            "error": "CONSENT_MAX_AMOUNT_FORBIDDEN",
                            "detail": "Co-authorization consent tokens cannot carry positive max_amount spend authority",
                        },
                        {},
                    )
                consent_ttl = require_finite_timestamp(
                    body.get("ttl_seconds", 120.0), "ttl_seconds"
                )
                if consent_ttl < 1.0 or consent_ttl > 300.0:
                    return (
                        403,
                        {
                            "error": "CONSENT_TTL_EXCEEDED",
                            "detail": "Consent token ttl_seconds must be within [1.0, 300.0]",
                        },
                        {},
                    )
                consent_tok = mint_root_token(
                    self.ca,
                    task_id=str(body["task_id"]),
                    sub=bound_owner_sub,
                    sender_jkt=str(body["sender_jkt"]),
                    first_hop_spiffe_id=str(body["first_hop_spiffe_id"]),
                    first_hop_jkt=str(body["first_hop_jkt"]),
                    permissions=perms_c,
                    max_depth=min(int(body.get("max_depth", 4)), 6),
                    ttl_seconds=consent_ttl,
                    hop_segment=str(body.get("hop_segment", "OwnerConsent")),
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
                return 400, {"error": "invalid_consent_mint_request", "detail": str(exc)}, {}

            self._record_issued_root(consent_tok.root)
            consent_detail: Dict[str, Any] = {
                "first_hop_spiffe_id": consent_tok.holder_spiffe_id,
                "consent_grant": True,
                "co_auth_consent": True,
                "hop0_oidc_bridged": True,
                "oidc_issuer": verified_owner.issuer,
                "oidc_username": verified_owner.username,
                "oidc_jti": verified_owner.jti,
            }
            if body.get("requester_sub"):
                consent_detail["requester_sub"] = str(body["requester_sub"])
                consent_detail["co_authorized_principals"] = [
                    str(body["requester_sub"]),
                    consent_tok.sub,
                ]
            if self._audit_emitter is not None:
                self._audit_emitter.emit(
                    event_type=AuditEventType.ROOT_MINT,
                    task_id=consent_tok.task_id,
                    sub=consent_tok.sub,
                    lineage_path=consent_tok.lineage_path,
                    hop_index=0,
                    epoch=0,
                    root_block_hash=consent_tok.root_block_hash,
                    current_block_hash=consent_tok.leaf_block_hash,
                    decision="ALLOW",
                    permissions_summary=perms_c.to_dict(),
                    action_detail=consent_detail,
                )
            return (
                200,
                {
                    "compact_token": consent_tok.encode_compact(),
                    "task_id": consent_tok.task_id,
                    "sub": consent_tok.sub,
                    "lineage_path": consent_tok.lineage_path,
                    "root_block_hash": consent_tok.root_block_hash,
                    "consent_grant": True,
                    "hop0_oidc_bridged": True,
                },
                {},
            )

        # Root user-token minting & domain-CA audit logging gated to authorized entry gateway SA(s)
        if not self._authorized_gateway_sas or k8s_sa not in self._authorized_gateway_sas:
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

            self._record_issued_root(tok.root)
            mint_action_detail: Dict[str, Any] = {
                "first_hop_spiffe_id": tok.holder_spiffe_id,
            }
            if hop0_oidc_detail:
                mint_action_detail.update(hop0_oidc_detail)
            if bool(body.get("co_auth_consent")):
                mint_action_detail["co_auth_consent"] = True
                if body.get("requester_sub"):
                    mint_action_detail["requester_sub"] = str(body["requester_sub"])
                    mint_action_detail["co_authorized_principals"] = [
                        str(body["requester_sub"]),
                        tok.sub,
                    ]

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
                    action_detail=mint_action_detail,
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

        if req.method == "POST" and req.path == "/v1/ca/mint-continuation-token":
            body = req.json()
            req_td = str(body.get("trust_domain", self.trust_domain))
            if req_td != self.trust_domain:
                return (
                    403,
                    {
                        "error": "cross_domain_root_mint_forbidden",
                        "detail": (
                            f"Autonomous CA for {self.trust_domain!r} cannot mint continuation tokens for {req_td!r}"
                        ),
                    },
                    {},
                )
            raw_oidc_token = str(body.get("user_oidc_token") or "").strip()
            hop0_oidc_detail_c: Optional[Dict[str, Any]] = None
            if raw_oidc_token or self.require_oidc_user_token:
                if not raw_oidc_token or self.oidc_verifier is None:
                    return 401, {"error": "missing_or_unconfigured_user_oidc_token"}, {}
                try:
                    verified_oidc = self.oidc_verifier.verify_jwt(raw_oidc_token)
                except Exception as exc:
                    return 401, {"error": "invalid_user_oidc_token", "detail": str(exc)}, {}
                hop0_oidc_detail_c = {
                    "hop0_oidc_bridged": True,
                    "oidc_issuer": verified_oidc.issuer,
                    "oidc_username": verified_oidc.username,
                    "oidc_jti": verified_oidc.jti,
                }

            raw_ckpt = body.get("checkpoint")
            if not isinstance(raw_ckpt, Mapping):
                return 400, {"error": "missing_checkpoint"}, {}
            try:
                ckpt = TaskCheckpoint.from_dict_and_verify(
                    raw_ckpt, self.federation_trust_resolver
                )
            except TokenError as exc:
                return 403, {"error": "invalid_task_checkpoint", "detail": str(exc)}, {}

            if hop0_oidc_detail_c and ckpt.sub != verified_oidc.canonical_lct_sub:
                return 403, {"error": "oidc_sub_mismatch_with_checkpoint"}, {}

            # 1. Fail-closed verification of authoritative prior RootBlock (`[HIGH-M9-01]`)
            prior_root_rec = self._resolve_verified_prior_root(
                ckpt, body.get("prior_root_token")
            )
            if prior_root_rec is None:
                return (
                    403,
                    {
                        "error": "PRIOR_ROOT_NOT_VERIFIED",
                        "detail": (
                            f"Prior RootBlock {ckpt.prior_root_block_hash!r} could not be cryptographically "
                            "verified via CA ledger or prior_root_token"
                        ),
                    },
                    {},
                )

            expected_entry_delegate = str(prior_root_rec["delegate_spiffe_id"])
            if ckpt.signer_spiffe_id != expected_entry_delegate:
                return (
                    403,
                    {
                        "error": "CHECKPOINT_SIGNER_MISMATCH",
                        "detail": (
                            f"Checkpoint signer {ckpt.signer_spiffe_id!r} != authorized entry delegate "
                            f"{expected_entry_delegate!r}"
                        ),
                    },
                    {},
                )
            req_first_hop = str(body.get("first_hop_spiffe_id") or "").strip()
            if req_first_hop != expected_entry_delegate:
                return (
                    403,
                    {
                        "error": "CONTINUATION_HOLDER_MISMATCH",
                        "detail": (
                            f"Requested first_hop_spiffe_id {req_first_hop!r} != authorized entry delegate "
                            f"{expected_entry_delegate!r}"
                        ),
                    },
                    {},
                )
            prior_perms: PermissionLattice = prior_root_rec["permissions"]

            # 2. Atomic check-and-consume anti-replay & single-successor lock (`[CRITICAL-M9-01]`)
            with self._cont_lock:
                if ckpt.checkpoint_id in self._consumed_checkpoint_ids:
                    return (
                        409,
                        {
                            "error": "CONTINUATION_REPLAY_REJECTED",
                            "detail": f"Checkpoint {ckpt.checkpoint_id!r} has already been consumed",
                        },
                        {},
                    )
                if (ckpt.task_id, ckpt.prior_root_block_hash) in self._superseded_prior_roots:
                    return (
                        409,
                        {
                            "error": "CONTINUATION_REPLAY_REJECTED",
                            "detail": (
                                f"Prior RootBlock {ckpt.prior_root_block_hash!r} for task "
                                f"{ckpt.task_id!r} has already been superseded"
                            ),
                        },
                        {},
                    )

                try:
                    mint_ttl_c = require_finite_timestamp(
                        body.get("ttl_seconds", 900.0), "ttl_seconds"
                    )
                    if mint_ttl_c < 1.0 or mint_ttl_c > 7200.0:
                        raise ValueError("ttl_seconds must be within [1.0, 7200.0]")
                    max_depth_c = int(body.get("max_depth", 6))
                    if isinstance(body.get("max_depth"), bool) or max_depth_c < 1 or max_depth_c > 16:
                        raise ValueError("max_depth must be within [1, 16]")
                    req_perms = PermissionLattice.from_dict(body["permissions"])
                    cont_tok = mint_continuation_root_token(
                        authority_ca=self.ca,
                        checkpoint=ckpt,
                        sender_jkt=str(body["sender_jkt"]),
                        first_hop_spiffe_id=req_first_hop,
                        first_hop_jkt=str(body["first_hop_jkt"]),
                        permissions=req_perms,
                        prior_permissions=prior_perms,
                        max_depth=max_depth_c,
                        hop_segment=str(body.get("hop_segment", "AssistantAliceCont")),
                        first_hop_public_jwk=body.get("first_hop_public_jwk"),
                        first_hop_return_endpoint=body.get("first_hop_return_endpoint"),
                        ttl_seconds=mint_ttl_c,
                    )
                except ContinuationBudgetError as exc:
                    return (
                        403,
                        {"error": "CONTINUATION_BUDGET_EXCEEDED", "detail": str(exc)},
                        {},
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
                    return 400, {"error": "invalid_continuation_request", "detail": str(exc)}, {}

                if len(self._consumed_checkpoint_ids) >= self._max_tracked_roots:
                    self._consumed_checkpoint_ids.popitem(last=False)
                self._consumed_checkpoint_ids[ckpt.checkpoint_id] = time.time()

                if len(self._superseded_prior_roots) >= self._max_tracked_roots:
                    self._superseded_prior_roots.popitem(last=False)
                self._superseded_prior_roots[(ckpt.task_id, ckpt.prior_root_block_hash)] = (
                    cont_tok.root_block_hash
                )
                if len(self._issued_roots) >= self._max_tracked_roots:
                    self._issued_roots.popitem(last=False)
                self._issued_roots[cont_tok.root_block_hash] = {
                    "root_block_hash": cont_tok.root_block_hash,
                    "task_id": cont_tok.task_id,
                    "sub": cont_tok.sub,
                    "delegate_spiffe_id": cont_tok.root.delegate_spiffe_id,
                    "permissions": cont_tok.root.permissions,
                    "issuer_trust_domain": cont_tok.root.issuer_trust_domain,
                    "iat": cont_tok.root.iat,
                    "exp": cont_tok.root.exp,
                }

            cont_detail: Dict[str, Any] = {
                "continuation": True,
                "resumes_checkpoint_id": ckpt.checkpoint_id,
                "prior_root_block_hash": ckpt.prior_root_block_hash,
                "consumed_amount": ckpt.consumed_amount,
                "consumed_calls": ckpt.consumed_calls,
                "completed_branches": list(ckpt.completed_branches),
                "remaining_branches": list(ckpt.remaining_branches),
                "first_hop_spiffe_id": cont_tok.holder_spiffe_id,
            }
            if hop0_oidc_detail_c:
                cont_detail.update(hop0_oidc_detail_c)

            self._audit_emitter.emit(
                event_type=AuditEventType.ROOT_MINT,
                task_id=cont_tok.task_id,
                sub=cont_tok.sub,
                lineage_path=cont_tok.lineage_path,
                hop_index=0,
                epoch=0,
                root_block_hash=cont_tok.root_block_hash,
                parent_block_hash=ckpt.prior_root_block_hash,
                current_block_hash=cont_tok.leaf_block_hash,
                decision="ALLOW",
                permissions_summary=req_perms.to_dict(),
                action_detail=cont_detail,
            )
            return (
                200,
                {
                    "compact_token": cont_tok.encode_compact(),
                    "task_id": cont_tok.task_id,
                    "sub": cont_tok.sub,
                    "lineage_path": cont_tok.lineage_path,
                    "root_block_hash": cont_tok.root_block_hash,
                    "prior_root_block_hash": ckpt.prior_root_block_hash,
                    "resumes_checkpoint_id": ckpt.checkpoint_id,
                },
                {},
            )

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
