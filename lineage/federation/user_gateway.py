"""Authenticated Per-Domain User Entry Gateway (`DomainUserGatewayService`).

Provides symmetric non-Alpha entry (e.g., `beta-user-gateway` in `lineage-beta` for `org-beta.io`)
without adding any peer assistant ServiceAccount (`assistant-bob`, etc.) to `AUTHORIZED_GATEWAY_SAS`:
- Enforces mTLS 1.3 client authentication (`req.peer_spiffe_id` against `authorized_caller_spiffe_ids`);
- Enforces mandatory cryptographically verified `user_oidc_token` (`OIDCTokenVerifier`) whose
  `canonical_lct_sub` belongs strictly to `@{self.trust_domain}` and matches requested `sub`;
- Mints `RootBlock` tokens via local `AutonomousDomainCAService` (`/v1/ca/mint-root-token`) using
  its own projected Kubernetes ServiceAccount JWT, and dispatches Hop-0 A2A/MCP calls from inside
  `self.trust_domain` over mTLS 1.3 + RFC 9449 DPoP.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, FrozenSet, Iterable, Mapping, Optional, Tuple
from urllib.parse import urlsplit

import httpx

from lineage.common.crypto import CryptoError, redact_sensitive
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.common.locators import (
    DEFAULT_ALLOWED_LOCATOR_CIDRS,
    LocatorError,
    validate_locator_host,
)
from lineage.common.mtls import WorkloadMTLSBundle
from lineage.identity.spiffe import SpiffeId, WorkloadIdentity
from lineage.identity.trust_bundle import TrustBundleResolver
from lineage.oauth_sts.client import OIDCTokenVerifier
from lineage.protocol.dpop import create_dpop_proof
from lineage.protocol.lattice import PermissionLattice
from lineage.protocol.token import (
    LineageToken,
    TokenError,
    decode_token,
    verify_root_block_signature_ignoring_expiry,
)


class DomainUserGatewayService:
    """mTLS + OIDC hardened entry gateway for non-Alpha autonomous trust domains."""

    def __init__(
        self,
        *,
        identity: WorkloadIdentity,
        local_ca_url: str,
        sa_jwt_provider: Callable[[], str],
        oidc_verifier: Optional[OIDCTokenVerifier],
        mtls_bundle: Optional[WorkloadMTLSBundle] = None,
        authorized_caller_spiffe_ids: Optional[Iterable[str]] = None,
        allowed_locator_cidrs: Optional[Iterable[str] | str] = None,
        readiness_check: Optional[Callable[[], Tuple[bool, Dict[str, Any]]]] = None,
        inbound_host: str = "0.0.0.0",
        inbound_port: int = 8443,
        health_host: str = "127.0.0.1",
        health_port: int = 8081,
    ) -> None:
        self.identity = identity
        self.trust_domain = identity.trust_domain
        self.local_ca_url = local_ca_url.rstrip("/")
        self._sa_jwt_provider = sa_jwt_provider
        self.oidc_verifier = oidc_verifier
        self.mtls_bundle = mtls_bundle
        self.allowed_locator_cidrs = allowed_locator_cidrs
        self._readiness_check = readiness_check
        self._bundle_lock = threading.Lock()
        self._local_resolver: Optional[TrustBundleResolver] = None
        default_callers = {
            identity.spiffe_id,
            "spiffe://org-alpha.io/ns/lineage-alpha/sa/e2e-user-gateway",
        }
        self.authorized_caller_spiffe_ids: FrozenSet[str] = frozenset(
            str(s).strip()
            for s in (
                authorized_caller_spiffe_ids
                if authorized_caller_spiffe_ids is not None
                else default_callers
            )
            if str(s).strip()
        )
        self.inbound_http = ManagedHTTPService(
            service_name=f"user-gateway-{self.trust_domain}",
            dispatcher=self._dispatch_inbound,
            host=inbound_host,
            port=inbound_port,
            ssl_context_provider=(
                mtls_bundle.server_ssl_context_provider(require_client_cert=True)
                if mtls_bundle is not None
                else None
            ),
            peer_cert_verifier=(
                mtls_bundle.trust_store.verify_peer_der_cert
                if mtls_bundle is not None
                else None
            ),
        )
        self.health_http: Optional[ManagedHTTPService] = (
            ManagedHTTPService(
                service_name=f"user-gateway-health-{self.trust_domain}",
                dispatcher=self._dispatch_health,
                host=health_host,
                port=health_port,
            )
            if health_port is not None and health_port >= 0
            else None
        )

    @property
    def base_url(self) -> str:
        return self.inbound_http.base_url

    def start(self) -> str:
        if self.health_http is not None:
            self.health_http.start()
        return self.inbound_http.start()

    def stop(self) -> None:
        self.inbound_http.stop()
        if self.health_http is not None:
            self.health_http.stop()

    def _dispatch_health(self, req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return (
                200,
                {
                    "status": "ok",
                    "spiffe_id": self.identity.spiffe_id,
                    "trust_domain": self.trust_domain,
                },
                {},
            )
        if req.method == "GET" and req.path == "/readyz":
            if self._readiness_check is not None:
                ok, detail = self._readiness_check()
                if not ok:
                    return 503, {"status": "not_ready", **detail}, {}
            return 200, {"status": "ready", "spiffe_id": self.identity.spiffe_id}, {}
        return 404, {"error": "route_not_found"}, {}

    def _verify_caller_and_oidc(
        self, req: HTTPRequestContext, body: Mapping[str, Any]
    ) -> Tuple[Optional[Tuple[int, Dict[str, Any]]], Optional[str], Optional[str]]:
        if self.mtls_bundle is not None:
            peer_spiffe = (req.peer_spiffe_id or "").strip()
            peer_jkt = (req.peer_jkt or "").strip()
            if not peer_spiffe or not peer_jkt:
                return (
                    (
                        401,
                        {
                            "error": "MTLS_CLIENT_CERT_REQUIRED",
                            "detail": "Authenticated mTLS X.509-SVID client certificate is required",
                        },
                    ),
                    None,
                    None,
                )
            if peer_spiffe not in self.authorized_caller_spiffe_ids:
                return (
                    (
                        403,
                        {
                            "error": "MTLS_CALLER_UNAUTHORIZED",
                            "detail": f"Caller {peer_spiffe!r} is not authorized to invoke {self.identity.spiffe_id!r}",
                        },
                    ),
                    None,
                    None,
                )

        raw_oidc = str(body.get("user_oidc_token") or "").strip()
        if not raw_oidc:
            return (
                (
                    401,
                    {
                        "error": "OIDC_USER_TOKEN_REQUIRED",
                        "detail": "Non-empty cryptographic user_oidc_token is mandatory",
                    },
                ),
                None,
                None,
            )
        if self.oidc_verifier is None:
            return (
                (
                    403,
                    {
                        "error": "OIDC_USER_TOKEN_REQUIRED",
                        "detail": "Gateway OIDC verifier is not configured",
                    },
                ),
                None,
                None,
            )
        try:
            verified = self.oidc_verifier.verify_jwt(raw_oidc)
        except Exception as exc:
            return (
                (
                    401,
                    {
                        "error": "INVALID_USER_OIDC_TOKEN",
                        "detail": str(exc),
                    },
                ),
                None,
                None,
            )

        canonical_sub = verified.canonical_lct_sub
        expected_suffix = f"@{self.trust_domain}"
        if not canonical_sub.endswith(expected_suffix):
            return (
                (
                    403,
                    {
                        "error": "GATEWAY_PRINCIPAL_DOMAIN_MISMATCH",
                        "detail": (
                            f"Verified OIDC principal {canonical_sub!r} does not belong to "
                            f"gateway trust domain {self.trust_domain!r}"
                        ),
                    },
                ),
                None,
                None,
            )

        req_sub = str(body.get("sub") or canonical_sub).strip()
        if req_sub != canonical_sub:
            return (
                (
                    403,
                    {
                        "error": "GATEWAY_PRINCIPAL_DOMAIN_MISMATCH",
                        "detail": f"Requested sub {req_sub!r} != verified OIDC principal {canonical_sub!r}",
                    },
                ),
                None,
                None,
            )
        return None, canonical_sub, raw_oidc

    def _mint_root_via_local_ca(
        self,
        *,
        body: Mapping[str, Any],
        canonical_sub: str,
        raw_oidc: str,
        sender_jkt: str,
    ) -> Tuple[int, Dict[str, Any]]:
        try:
            perms = PermissionLattice.from_dict(body["permissions"])
            first_hop_spiffe = SpiffeId.parse(str(body["first_hop_spiffe_id"])).uri
            ca_payload: Dict[str, Any] = {
                "trust_domain": self.trust_domain,
                "task_id": str(body["task_id"]),
                "sub": canonical_sub,
                "sender_jkt": sender_jkt,
                "first_hop_spiffe_id": first_hop_spiffe,
                "first_hop_jkt": str(body["first_hop_jkt"]),
                "permissions": perms.to_dict(),
                "hop_segment": str(body.get("hop_segment", "AssistantBob")),
                "max_depth": int(body.get("max_depth", 6)),
                "ttl_seconds": float(body.get("ttl_seconds", 600.0)),
                "user_oidc_token": raw_oidc,
            }
            if body.get("first_hop_public_jwk") is not None:
                ca_payload["first_hop_public_jwk"] = body["first_hop_public_jwk"]
            if body.get("first_hop_return_endpoint") is not None:
                ca_payload["first_hop_return_endpoint"] = body["first_hop_return_endpoint"]
        except Exception as exc:
            return 400, {"error": "invalid_gateway_mint_request", "detail": str(exc)}

        r_ca = httpx.post(
            f"{self.local_ca_url}/v1/ca/mint-root-token",
            json=ca_payload,
            headers={"Authorization": f"Bearer {self._sa_jwt_provider()}"},
            timeout=10.0,
            trust_env=False,
        )
        return r_ca.status_code, r_ca.json()

    def _get_local_trust_resolver(self) -> TrustBundleResolver:
        with self._bundle_lock:
            if self._local_resolver is not None:
                return self._local_resolver
        r_b = httpx.get(
            f"{self.local_ca_url}/v1/federation/bundle",
            timeout=5.0,
            trust_env=False,
        )
        r_b.raise_for_status()
        res = TrustBundleResolver()
        res.register_bundle(r_b.json())
        with self._bundle_lock:
            self._local_resolver = res
        return res

    def _dispatch_inbound(self, req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return (
                200,
                {
                    "status": "ok",
                    "spiffe_id": self.identity.spiffe_id,
                    "trust_domain": self.trust_domain,
                },
                {},
            )

        if req.method == "POST" and req.path == "/v1/gateway/mint-root":
            body = req.json()
            err, canonical_sub, raw_oidc = self._verify_caller_and_oidc(req, body)
            if err is not None:
                return err[0], err[1], {}
            assert canonical_sub is not None and raw_oidc is not None

            req_sender_jkt = str(body.get("sender_jkt") or "").strip()
            if req_sender_jkt and req_sender_jkt != self.identity.jkt:
                return (
                    403,
                    {
                        "error": "SENDER_JKT_MISMATCH",
                        "detail": (
                            f"DomainUserGatewayService binds sender_jkt strictly to its own "
                            f"workload identity ({self.identity.spiffe_id})"
                        ),
                    },
                    {},
                )
            eff_sender_jkt = self.identity.jkt

            st, out = self._mint_root_via_local_ca(
                body=body,
                canonical_sub=canonical_sub,
                raw_oidc=raw_oidc,
                sender_jkt=eff_sender_jkt,
            )
            return st, out, {}

        if req.method == "POST" and req.path == "/v1/gateway/dispatch":
            body = req.json()
            err, canonical_sub, raw_oidc = self._verify_caller_and_oidc(req, body)
            if err is not None:
                return err[0], err[1], {}
            assert canonical_sub is not None and raw_oidc is not None

            target_endpoint = str(body.get("target_endpoint") or "").strip().rstrip("/")
            target_path = str(body.get("path") or "/a2a/task")
            if not target_endpoint or not target_path.startswith("/"):
                return 400, {"error": "invalid_dispatch_target"}, {}
            sp_t = urlsplit(target_endpoint)
            if sp_t.scheme not in ("https", "http") or not sp_t.hostname:
                return 400, {"error": "invalid_dispatch_target"}, {}
            if self.mtls_bundle is not None:
                if sp_t.scheme != "https":
                    return 400, {"error": "https_required_for_mtls_dispatch"}, {}
                try:
                    validate_locator_host(
                        sp_t.hostname,
                        allowed_cidrs=self.allowed_locator_cidrs,
                        allow_loopback=False,
                    )
                except LocatorError as exc:
                    return (
                        403,
                        {"error": "FORBIDDEN_DISPATCH_TARGET", "detail": str(exc)},
                        {},
                    )
            else:
                if sp_t.scheme != "http":
                    return (
                        400,
                        {
                            "error": "https_requires_mtls_bundle",
                            "detail": "TLS dispatch is forbidden when mtls_bundle is None",
                        },
                        {},
                    )
                eff_cidrs = (
                    self.allowed_locator_cidrs
                    if self.allowed_locator_cidrs is not None
                    else (*DEFAULT_ALLOWED_LOCATOR_CIDRS, "127.0.0.0/8")
                )
                try:
                    validate_locator_host(
                        sp_t.hostname,
                        allowed_cidrs=eff_cidrs,
                        allow_loopback=True,
                    )
                except LocatorError as exc:
                    return (
                        403,
                        {"error": "FORBIDDEN_DISPATCH_TARGET", "detail": str(exc)},
                        {},
                    )

            compact_tok = str(body.get("compact_token") or "").strip()
            mint_meta: Optional[Dict[str, Any]] = None
            if compact_tok:
                try:
                    parsed = decode_token(compact_tok)
                    if not isinstance(parsed, LineageToken):
                        raise TokenError("Supplied compact_token must be a LineageToken")
                    verify_root_block_signature_ignoring_expiry(
                        parsed.root, self._get_local_trust_resolver()
                    )
                except (TokenError, CryptoError, httpx.HTTPError, ValueError) as exc:
                    return (
                        403,
                        {
                            "error": "INVALID_GATEWAY_ROOT_TOKEN",
                            "detail": f"Invalid or unverifiable compact_token: {exc}",
                        },
                        {},
                    )
                if (
                    parsed.hops
                    or parsed.root.issuer_trust_domain != self.trust_domain
                    or parsed.sub != canonical_sub
                    or parsed.root.sender_jkt != self.identity.jkt
                    or parsed.root.exp <= (time.time() - 2.0)
                ):
                    return (
                        403,
                        {
                            "error": "INVALID_GATEWAY_ROOT_TOKEN",
                            "detail": "Supplied compact_token is not an active Hop-0 token bound to this gateway and principal",
                        },
                        {},
                    )
                target_spiffe = parsed.holder_spiffe_id
            else:
                st_m, out_m = self._mint_root_via_local_ca(
                    body=body,
                    canonical_sub=canonical_sub,
                    raw_oidc=raw_oidc,
                    sender_jkt=self.identity.jkt,
                )
                if st_m != 200:
                    return st_m, out_m, {}
                compact_tok = str(out_m["compact_token"])
                mint_meta = redact_sensitive(
                    {k: v for k, v in out_m.items() if k != "compact_token"}
                )
                target_spiffe = str(body["first_hop_spiffe_id"])

            full_url = f"{target_endpoint}{target_path}"
            dpop = create_dpop_proof(self.identity, "POST", full_url, compact_tok)
            verify_kw: Any = (
                self.mtls_bundle.verify_for_target(
                    target_url=full_url, expected_spiffe_id=target_spiffe
                )
                if self.mtls_bundle is not None
                else True
            )
            req_timeout = min(max(float(body.get("timeout", 90.0)), 1.0), 180.0)
            with httpx.Client(
                verify=verify_kw,
                timeout=req_timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                r_up = client.post(
                    full_url,
                    json=dict(body.get("payload") or {}),
                    headers={
                        "Authorization": f"DPoP {compact_tok}",
                        "DPoP": dpop,
                    },
                )
            try:
                up_json = r_up.json()
            except Exception:
                up_json = {"raw_text": r_up.text[:500]}
            return (
                r_up.status_code,
                {
                    "gateway_spiffe_id": self.identity.spiffe_id,
                    "gateway_trust_domain": self.trust_domain,
                    "principal_sub": canonical_sub,
                    "mint_metadata": mint_meta,
                    "upstream_status": r_up.status_code,
                    "upstream_body": up_json,
                },
                {},
            )

        return 404, {"error": "route_not_found"}, {}
