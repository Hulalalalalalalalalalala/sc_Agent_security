"""Zero-Secret Kubernetes Container Bootstrap & Multi-Domain Federation Authority.

Security Architecture:
1. Every workload generates its own `ES256` private key strictly in container RAM
   (never written to disk, environment variables, ConfigMaps, Secrets, or logs).
2. `FederationCAService` (`lineage-ctrl`) cryptographically verifies each caller's
   Kubernetes API-Server-signed `RS256` ServiceAccount JWT directly against
   `https://kubernetes.default.svc/openid/v1/jwks` (using `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`),
   enforcing a strict `(k8s_namespace, k8s_service_account) -> (trust_domain, spiffe_path)` binding
   with zero cluster-scoped RBAC objects required.
3. In every 2/2 Agent & MCP Pod:
   - `lct-sidecar` generates a fresh 256-bit random loopback secret into an in-memory
     shared volume (`/var/run/lct-loopback/secret`, `emptyDir: {medium: Memory}`),
     binds `0.0.0.0:8080` (Pod network) and `127.0.0.1:8081` (loopback outbound proxy);
   - `app` binds strictly `127.0.0.1:9001` (loopback only), holds zero private keys,
     and rejects any request lacking constant-time `X-LCT-Loopback-Auth` match.
"""

from __future__ import annotations

import argparse
import hmac
import os
import secrets
import signal
import socket
import ssl
import sys
import threading
import time
import uuid
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

import httpx

from lineage.agents import (
    FlightSpecialistApp,
    HotelSpecialistApp,
    OrchestratorAlphaApp,
    PaymentVaultMCPApp,
    SettlementConvergerApp,
    TravelOpsMCPApp,
)
from lineage.audit import (
    AuditCollectorClient,
    AuditCollectorService,
    AuditEventType,
    AuditStreamEmitter,
)
from lineage.common.crypto import (
    CryptoError,
    KeyPair,
    compute_jwk_thumbprint,
    jws_parse_unverified,
    jws_sign_compact,
    jws_verify_compact,
    require_finite_timestamp,
    sha256_b64url,
)
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.identity import (
    IdentityError,
    TrustBundleResolver,
    TrustDomainCA,
    WorkloadIdentity,
)
from lineage.protocol import (
    DPoPError,
    JTIReplayCache,
    LatticeError,
    PermissionLattice,
    TokenError,
    mint_root_token,
)
from lineage.registry import AgentCard, AgentDirectoryClient, AgentDirectoryService
from lineage.revocation import (
    RevocationError,
    RevocationEvent,
    RevocationReplicaClient,
    RevocationService,
)
from lineage.sidecar import LineageSidecar
from lineage.verifier import VerificationMode
from lineage.workspace_agents import WorkspaceAssistantPeerApp, WorkspaceVaultMCPApp

PROJECTED_SA_TOKEN_PATH = "/var/run/lct-sa/token"
PROJECTED_CA_CERT_PATH = "/var/run/lct-sa/ca.crt"
PROJECTED_K8S_API_TOKEN_PATH = "/var/run/lct-sa/k8s-api-token"
LEGACY_K8S_SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
LEGACY_K8S_CA_CERT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

K8S_SA_TOKEN_PATH = PROJECTED_SA_TOKEN_PATH
K8S_CA_CERT_PATH = PROJECTED_CA_CERT_PATH
LOOPBACK_SECRET_FILE = "/var/run/lct-loopback/secret"


def resolve_sa_token_path(preferred: str = K8S_SA_TOKEN_PATH) -> str:
    if os.path.exists(preferred):
        return preferred
    if os.path.exists(LEGACY_K8S_SA_TOKEN_PATH):
        return LEGACY_K8S_SA_TOKEN_PATH
    return preferred


def _resolve_ca_cert_path(preferred: str = K8S_CA_CERT_PATH) -> str:
    if os.path.exists(preferred):
        return preferred
    if os.path.exists(LEGACY_K8S_CA_CERT_PATH):
        return LEGACY_K8S_CA_CERT_PATH
    return preferred


def create_ca_pop_jws(keypair: KeyPair, sa_jwt: str) -> str:
    """Create a short-lived Proof-of-Possession JWS binding `public_jwk` to `sa_jwt`."""
    return jws_sign_compact(
        payload={
            "jti": f"capop-{uuid.uuid4().hex}",
            "iat": time.time(),
            "jkt": keypair.jkt,
            "sa_jwt_sha256": sha256_b64url(sa_jwt.encode("ascii")),
        },
        keypair=keypair,
        typ="lct-ca-pop+jwt",
    )


def _extract_bearer(hdr: Optional[str]) -> str:
    if not hdr or not isinstance(hdr, str):
        raise ValueError("Missing Authorization Bearer header")
    parts = hdr.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise ValueError("Malformed Authorization Bearer header")
    return parts[1].strip()


class K8sServiceAccountVerifier:
    """Verifies Kubernetes projected ServiceAccount JWTs via real K8s OIDC RS256 JWKS."""

    def __init__(
        self,
        jwks_url: str = "https://kubernetes.default.svc/openid/v1/jwks",
        ca_cert_path: str = K8S_CA_CERT_PATH,
        self_sa_token_path: str = PROJECTED_K8S_API_TOKEN_PATH,
        expected_issuer: str = "https://kubernetes.default.svc.cluster.local",
        allowed_audiences: Iterable[str] = ("lct-federation-ca",),
    ) -> None:
        self.jwks_url = jwks_url
        self.ca_cert_path = ca_cert_path
        self.self_sa_token_path = self_sa_token_path
        self.expected_issuer = expected_issuer
        self.allowed_audiences: FrozenSet[str] = frozenset(
            str(a) for a in allowed_audiences if a
        )
        self._lock = threading.Lock()
        self._keys_by_kid: Dict[str, Dict[str, Any]] = {}
        self._last_refresh = 0.0

    def _refresh_jwks(self) -> None:
        tok_path = resolve_sa_token_path(self.self_sa_token_path)
        ca_path = _resolve_ca_cert_path(self.ca_cert_path)
        with open(tok_path, "r", encoding="utf-8") as fh:
            bearer = fh.read().strip()
        ssl_ctx = ssl.create_default_context(cafile=ca_path)
        resp = httpx.get(
            self.jwks_url,
            headers={"Authorization": f"Bearer {bearer}"},
            verify=ssl_ctx,
            timeout=5.0,
        )
        resp.raise_for_status()
        keys = resp.json().get("keys") or []
        mapping: Dict[str, Dict[str, Any]] = {}
        for k in keys:
            if isinstance(k, dict) and k.get("kid"):
                mapping[str(k["kid"])] = k
        if not mapping:
            raise CryptoError("Kubernetes OIDC JWKS returned zero signing keys")
        with self._lock:
            self._keys_by_kid = mapping
            self._last_refresh = time.time()

    def verify_sa_jwt(
        self, sa_jwt: str, now: Optional[float] = None
    ) -> Tuple[str, str, float]:
        """Cryptographically verify K8s SA JWT (`iss`, `aud`, `exp`, `iat`, `nbf`, `sub`)."""
        hdr, _, _, _ = jws_parse_unverified(sa_jwt)
        kid = str(hdr.get("kid") or "")
        with self._lock:
            jwk = self._keys_by_kid.get(kid)
            stale = (time.time() - self._last_refresh) > 300.0
        if jwk is None or stale:
            self._refresh_jwks()
            with self._lock:
                jwk = self._keys_by_kid.get(kid)
        if jwk is None:
            raise CryptoError(f"Unknown Kubernetes signing kid: {kid!r}")

        _, claims = jws_verify_compact(sa_jwt, jwk, expected_typ=None)
        now_ts = require_finite_timestamp(
            time.time() if now is None else now, "now"
        )

        # 1. Strict OIDC Issuer validation (`[HIGH-M2-02]`)
        iss = claims.get("iss")
        if not isinstance(iss, str) or iss != self.expected_issuer:
            raise CryptoError(
                f"Invalid Kubernetes SA JWT issuer {iss!r} (expected {self.expected_issuer!r})"
            )

        # 2. Strict Projected Token Audience validation (`lct-federation-ca`)
        raw_aud = claims.get("aud")
        if isinstance(raw_aud, str):
            aud_list = [raw_aud]
        elif isinstance(raw_aud, list) and all(isinstance(x, str) for x in raw_aud):
            aud_list = list(raw_aud)
        else:
            raise CryptoError("Kubernetes SA JWT missing or malformed aud claim")
        if not any(a in self.allowed_audiences for a in aud_list):
            raise CryptoError(
                f"Kubernetes SA JWT audience {aud_list!r} not in allowed {sorted(self.allowed_audiences)!r}"
            )

        # 3. Mandatory finite `exp` + optional finite `iat` / `nbf` validation
        if "exp" not in claims or claims.get("exp") is None:
            raise CryptoError("Kubernetes SA JWT missing mandatory exp claim")
        exp_ts = require_finite_timestamp(claims.get("exp"), "sa_jwt.exp")
        if exp_ts <= now_ts - 5.0:
            raise CryptoError("Kubernetes ServiceAccount token has expired")

        if "iat" in claims and claims.get("iat") is not None:
            iat_ts = require_finite_timestamp(claims.get("iat"), "sa_jwt.iat")
            if iat_ts > now_ts + 30.0:
                raise CryptoError("Kubernetes SA JWT iat is in the future")

        if "nbf" in claims and claims.get("nbf") is not None:
            nbf_ts = require_finite_timestamp(claims.get("nbf"), "sa_jwt.nbf")
            if nbf_ts > now_ts + 30.0:
                raise CryptoError("Kubernetes SA JWT is not yet valid (nbf in future)")

        sub = str(claims.get("sub") or "")
        # Standard Kubernetes SA subject: `system:serviceaccount:<namespace>:<sa_name>`
        parts = sub.split(":")
        if (
            len(parts) != 4
            or parts[0] != "system"
            or parts[1] != "serviceaccount"
            or not parts[2]
            or not parts[3]
        ):
            raise CryptoError(f"Invalid Kubernetes ServiceAccount subject: {sub!r}")
        return parts[2], parts[3], exp_ts


class FederationCAService:
    """Multi-Domain Trust Authority (`org-alpha.io`, `org-beta.io`, `org-payment.io`)."""

    # Strict namespace -> trust_domain isolation table
    _CTRL_SA_MAP: Dict[str, Tuple[str, str]] = {
        "revocation-svc": ("org-alpha.io", "/ns/sys/sa/revocation"),
        "directory-svc": ("org-alpha.io", "/ns/sys/sa/directory"),
        "audit-collector": ("org-alpha.io", "/ns/sys/sa/audit-collector"),
        "federation-ca": ("org-alpha.io", "/ns/sys/sa/federation-ca"),
    }
    _NS_DOMAIN_MAP: Dict[str, str] = {
        "lineage-alpha": "org-alpha.io",
        "lineage-beta": "org-beta.io",
        "lineage-pay": "org-payment.io",
    }

    def __init__(
        self,
        audit_collector_url: str,
        host: str = "0.0.0.0",
        port: int = 8090,
    ) -> None:
        self.cas: Dict[str, TrustDomainCA] = {
            "org-alpha.io": TrustDomainCA("org-alpha.io", alg="ES256"),
            "org-beta.io": TrustDomainCA("org-beta.io", alg="ES256"),
            "org-payment.io": TrustDomainCA("org-payment.io", alg="ES256"),
        }
        self.resolver = TrustBundleResolver()
        for ca in self.cas.values():
            self.resolver.register_domain_ca(ca)

        self.k8s_verifier = K8sServiceAccountVerifier()
        self._pop_replay_cache = JTIReplayCache(ttl_seconds=300.0)
        self.audit_collector_url = audit_collector_url
        self._audit_emitters: Dict[str, AuditStreamEmitter] = {
            td: AuditStreamEmitter(
                ca,
                collector_client=AuditCollectorClient(audit_collector_url),
                stream_id=f"spiffe://{td}/authority/root",
            )
            for td, ca in self.cas.items()
        }
        self.http = ManagedHTTPService(
            service_name="federation-ca",
            dispatcher=self._dispatch,
            host=host,
            port=port,
        )

    def _resolve_authorized_spiffe(self, k8s_ns: str, k8s_sa: str) -> Tuple[str, str]:
        if k8s_ns == "lineage-ctrl":
            mapped = self._CTRL_SA_MAP.get(k8s_sa)
            if mapped is None:
                raise PermissionError(f"Unauthorized control-plane SA {k8s_ns}/{k8s_sa}")
            return mapped
        td = self._NS_DOMAIN_MAP.get(k8s_ns)
        if td is None:
            raise PermissionError(
                f"Namespace {k8s_ns!r} is outside LCT federation trust domains"
            )
        return td, f"/ns/{k8s_ns}/sa/{k8s_sa}"

    def _dispatch(self, req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return (
                200,
                {"status": "ok", "domains": sorted(self.cas.keys())},
                {},
            )

        if req.method == "GET" and req.path == "/v1/ca/bundles":
            return (
                200,
                {"bundles": self.resolver.export_federation_bundles()},
                {},
            )

        # All mutating CA routes require a cryptographically verified K8s SA JWT!
        try:
            sa_jwt = _extract_bearer(req.header("Authorization"))
            k8s_ns, k8s_sa, sa_exp = self.k8s_verifier.verify_sa_jwt(sa_jwt)
            trust_domain, workload_path = self._resolve_authorized_spiffe(k8s_ns, k8s_sa)
        except Exception as exc:
            return 403, {"error": "k8s_sa_attestation_failed", "detail": str(exc)}, {}

        if req.method == "POST" and req.path == "/v1/ca/issue-workload":
            body = req.json()
            public_jwk = body.get("public_jwk")
            pop_jws = body.get("pop_jws")
            if not isinstance(public_jwk, Mapping):
                return 400, {"error": "missing_public_jwk"}, {}
            if not isinstance(pop_jws, str) or not pop_jws.strip():
                return (
                    400,
                    {
                        "error": "missing_pop_jws",
                        "detail": "Proof-of-Possession JWS (lct-ca-pop+jwt) is mandatory",
                    },
                    {},
                )
            now_ts = time.time()
            try:
                jwk_dict = dict(public_jwk)
                expected_jkt = compute_jwk_thumbprint(jwk_dict)
                _, pop_claims = jws_verify_compact(
                    pop_jws.strip(), jwk_dict, expected_typ="lct-ca-pop+jwt"
                )
                if pop_claims.get("jkt") != expected_jkt:
                    raise CryptoError("PoP jkt mismatch with public_jwk")
                expected_sa_hash = sha256_b64url(sa_jwt.encode("ascii"))
                if pop_claims.get("sa_jwt_sha256") != expected_sa_hash:
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

                raw_ttl = body.get("ttl_seconds", 1800.0)
                req_ttl = require_finite_timestamp(raw_ttl, "ttl_seconds")
                if req_ttl < 1.0 or req_ttl > 7200.0:
                    return (
                        400,
                        {
                            "error": "invalid_ttl_seconds",
                            "detail": "ttl_seconds must be finite within [1.0, 7200.0]",
                        },
                        {},
                    )
                effective_ttl = min(req_ttl, 7200.0, max(1.0, sa_exp - now_ts + 30.0))
                ca = self.cas[trust_domain]
                spiffe_id, svid, iat, exp = ca.sign_svid_for_public_jwk(
                    workload_path=workload_path,
                    public_jwk=jwk_dict,
                    ttl_seconds=effective_ttl,
                )
            except (CryptoError, DPoPError, IdentityError, ValueError, TypeError) as exc:
                return 400, {"error": "invalid_workload_csr", "detail": str(exc)}, {}

            return (
                200,
                {
                    "trust_domain": trust_domain,
                    "spiffe_id": spiffe_id,
                    "workload_svid": svid,
                    "issued_at": iat,
                    "expires_at": exp,
                    "bundles": self.resolver.export_federation_bundles(),
                },
                {},
            )

        # Root user-token minting & domain-CA audit logging strictly gated to `e2e-user-gateway` in `lineage-alpha`
        if (k8s_ns, k8s_sa) != ("lineage-alpha", "e2e-user-gateway"):
            return (
                403,
                {"error": "gateway_only_endpoint", "caller": f"{k8s_ns}/{k8s_sa}"},
                {},
            )

        if req.method == "POST" and req.path == "/v1/ca/mint-root-token":
            body = req.json()
            req_td = str(body.get("trust_domain", trust_domain))
            if req_td not in self.cas:
                return 400, {"error": "unknown_trust_domain", "detail": req_td}, {}
            if req_td != trust_domain:
                return (
                    403,
                    {
                        "error": "cross_domain_root_mint_forbidden",
                        "detail": f"Caller in {trust_domain!r} cannot mint root tokens for {req_td!r}",
                    },
                    {},
                )
            try:
                raw_ttl = body.get("ttl_seconds", 900.0)
                mint_ttl = require_finite_timestamp(raw_ttl, "ttl_seconds")
                if mint_ttl < 1.0 or mint_ttl > 7200.0:
                    raise ValueError("ttl_seconds must be within [1.0, 7200.0]")
                max_depth_raw = body.get("max_depth", 6)
                if isinstance(max_depth_raw, bool) or not isinstance(max_depth_raw, int):
                    raise ValueError("max_depth must be an integer")
                if max_depth_raw < 1 or max_depth_raw > 16:
                    raise ValueError("max_depth must be within [1, 16]")
                ca = self.cas[req_td]
                perms = PermissionLattice.from_dict(body["permissions"])
                tok = mint_root_token(
                    ca,
                    task_id=str(body["task_id"]),
                    sub=str(body["sub"]),
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

            # Automatically anchor `ROOT_MINT` in AuditCollectorService!
            self._audit_emitters[req_td].emit(
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
            )
            return (
                200,
                {
                    "compact_token": tok.encode_compact(),
                    "task_id": tok.task_id,
                    "lineage_path": tok.lineage_path,
                    "root_block_hash": tok.root_block_hash,
                },
                {},
            )

        if req.method == "POST" and req.path == "/v1/ca/emit-revocation-audit":
            body = req.json()
            req_td = str(body.get("trust_domain", trust_domain))
            if req_td not in self.cas:
                return 400, {"error": "unknown_trust_domain", "detail": req_td}, {}
            if req_td != trust_domain:
                return (
                    403,
                    {
                        "error": "cross_domain_audit_forbidden",
                        "detail": f"Caller in {trust_domain!r} cannot emit revocation audits for {req_td!r}",
                    },
                    {},
                )
            raw_rev = body.get("revocation_event")
            if not isinstance(raw_rev, Mapping):
                return (
                    400,
                    {
                        "error": "missing_revocation_event",
                        "detail": "Signed RevocationEvent proof is mandatory",
                    },
                    {},
                )
            try:
                rev_ev = RevocationEvent.from_dict(dict(raw_rev))
                if not rev_ev.service_svid or not rev_ev.service_signature:
                    raise RevocationError("RevocationEvent missing service_svid or signature")
                svid_claims = self.resolver.verify_workload_svid(
                    rev_ev.service_svid,
                    expected_spiffe_id="spiffe://org-alpha.io/ns/sys/sa/revocation",
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
                    rev_ev.trust_domain != req_td
                    or rev_ev.target != target_prefix_str
                    or not target_prefix_str.startswith(f"/{task_id_str}/")
                ):
                    raise RevocationError(
                        "RevocationEvent target or trust_domain does not match audit request"
                    )
                self._audit_emitters[req_td].emit(
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
                        "trust_domain": req_td,
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


def bootstrap_k8s_workload_identity(
    ca_url: str,
    sa_token_path: str = K8S_SA_TOKEN_PATH,
    max_wait_sec: float = 45.0,
) -> Tuple[WorkloadIdentity, TrustBundleResolver]:
    """Generate ephemeral in-memory ES256 keypair and obtain CA-signed SVID via K8s SA JWT + PoP."""
    resolved_tok_path = resolve_sa_token_path(sa_token_path)
    keypair = KeyPair.generate("ES256")
    deadline = time.time() + max_wait_sec
    last_err: Optional[Exception] = None
    while time.time() < deadline:
        try:
            with open(resolved_tok_path, "r", encoding="utf-8") as fh:
                sa_jwt = fh.read().strip()
            pop_jws = create_ca_pop_jws(keypair, sa_jwt)
            resp = httpx.post(
                f"{ca_url.rstrip('/')}/v1/ca/issue-workload",
                json={
                    "public_jwk": keypair.public_jwk(),
                    "pop_jws": pop_jws,
                    "ttl_seconds": 1800.0,
                },
                headers={"Authorization": f"Bearer {sa_jwt}"},
                timeout=5.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                resolver = TrustBundleResolver()
                resolver.register_federation(data["bundles"])
                identity = WorkloadIdentity(
                    spiffe_id=data["spiffe_id"],
                    trust_domain=data["trust_domain"],
                    keypair=keypair,
                    workload_svid=data["workload_svid"],
                    issued_at=float(data["issued_at"]),
                    expires_at=float(data["expires_at"]),
                )
                return identity, resolver
            last_err = RuntimeError(f"CA HTTP {resp.status_code}: {resp.text}")
        except Exception as exc:
            last_err = exc
        time.sleep(0.5)
    raise RuntimeError(f"Failed to bootstrap workload identity from {ca_url}: {last_err}")


def _wait_for_http_ok(url: str, max_wait_sec: float = 45.0) -> None:
    deadline = time.time() + max_wait_sec
    while time.time() < deadline:
        try:
            r = httpx.get(url, timeout=2.0)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.3)
    raise RuntimeError(f"Timed out waiting for {url}")


def _write_shared_loopback_secret(secret_path: str = LOOPBACK_SECRET_FILE) -> str:
    os.makedirs(os.path.dirname(secret_path), exist_ok=True)
    secret_val = secrets.token_urlsafe(32)
    tmp_path = f"{secret_path}.tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(secret_val)
    os.replace(tmp_path, secret_path)
    return secret_val


def _read_shared_loopback_secret(
    secret_path: str = LOOPBACK_SECRET_FILE, max_wait_sec: float = 45.0
) -> str:
    deadline = time.time() + max_wait_sec
    while time.time() < deadline:
        if os.path.exists(secret_path):
            with open(secret_path, "r", encoding="utf-8") as fh:
                val = fh.read().strip()
            if len(val) >= 24:
                return val
        time.sleep(0.15)
    raise RuntimeError(f"Timed out waiting for shared loopback secret at {secret_path}")


def _read_optional_pem(dir_path: str, filename: str) -> Optional[str]:
    if not dir_path:
        return None
    full = os.path.join(dir_path, filename)
    if not os.path.isfile(full):
        return None
    with open(full, "r", encoding="utf-8") as fh:
        val = fh.read().strip()
    return val or None


def _build_env_anchor_store() -> Tuple[Optional[Any], bool]:
    from lineage.federation.anchors import TrustAnchorPinStore

    anchors_dir = os.environ.get("LCT_TRUST_ANCHORS_DIR", "").strip() or None
    require_pins = (
        os.environ.get("LCT_REQUIRE_PINNED_ANCHORS", "false").strip().lower() == "true"
    )
    raw_env_pins = os.environ.get("LCT_TRUST_ANCHORS", "").strip()
    if anchors_dir or require_pins or raw_env_pins:
        return TrustAnchorPinStore(anchors_dir=anchors_dir), require_pins
    return None, False


def _is_identity_addressing_enabled() -> bool:
    return (
        os.environ.get("LCT_IDENTITY_ADDRESSING", "false").strip().lower() == "true"
        or bool(os.environ.get("LCT_NODE_LOCATOR_FILE", "").strip())
    )


def _build_env_seed_store() -> Optional[Any]:
    from lineage.common.locators import SeedEndpointStore

    seeds_dir = os.environ.get("LCT_SEEDS_DIR", "").strip() or None
    raw_seeds = os.environ.get("LCT_BOOTSTRAP_SEEDS", "").strip()
    if _is_identity_addressing_enabled() or seeds_dir or raw_seeds:
        return SeedEndpointStore(seeds_dir=seeds_dir)
    return None


def _build_env_descriptor_store(
    anchor_store: Optional[Any],
    require_pins: bool,
    local_trust_domain: Optional[str] = None,
    local_trust_anchor: Optional[str] = None,
) -> Optional[Any]:
    from lineage.common.locators import allowed_cidrs_from_env
    from lineage.federation.locators import DomainDescriptorStore

    if not _is_identity_addressing_enabled() and not os.environ.get(
        "LCT_PERSISTED_DESCRIPTORS_FILE", ""
    ).strip():
        return None
    return DomainDescriptorStore(
        anchor_store=anchor_store,
        require_pinned_anchors=require_pins,
        allowed_cidrs=allowed_cidrs_from_env(),
        local_trust_domain=local_trust_domain,
        local_trust_anchor=local_trust_anchor,
    )


def _build_env_node_locator_watcher(
    on_change: Optional[Any] = None,
) -> Optional[Any]:
    from lineage.common.locators import NodeLocatorWatcher, allowed_cidrs_from_env

    loc_file = os.environ.get("LCT_NODE_LOCATOR_FILE", "").strip()
    if not loc_file:
        return None
    return NodeLocatorWatcher(
        locator_file=loc_file,
        poll_interval_sec=1.0,
        allowed_cidrs=allowed_cidrs_from_env(),
        on_change=on_change,
    )


class MinimalAuditTLSCAService:
    """Minimal X.509-only CA (`org-audit.io`) issuing leaf TLS certs to `audit-collector`.

    Holds ZERO ES256 JWKS signing keys (`keys: []`), so it can NEVER mint or attest
    any LCT `WorkloadIdentity` JWT-SVID or `RootBlock`.
    """

    def __init__(
        self,
        csr_token_file: str,
        x509_private_key_pem: Optional[str] = None,
        x509_root_cert_pem: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 8090,
        federation_port: Optional[int] = None,
        descriptor_store: Optional[Any] = None,
        on_descriptor_learned: Optional[Any] = None,
    ) -> None:
        from lineage.common.mtls import X509DomainAuthority
        from lineage.federation.anchors import compute_bundle_trust_anchor

        self.trust_domain = "org-audit.io"
        self.csr_token_file = csr_token_file
        self.descriptor_store = descriptor_store
        self.on_descriptor_learned = on_descriptor_learned
        self._desc_lock = threading.Lock()
        self._own_desc_version = 0
        self.x509_ca = X509DomainAuthority(
            self.trust_domain,
            allowed_dns_suffixes=(
                ".lineage-audit.svc.cluster.local",
                ".lineage-audit.svc",
                ".org-audit.io",
                "org-audit.io",
                "localhost",
            ),
            private_key_pem=x509_private_key_pem,
            root_cert_pem=x509_root_cert_pem,
        )
        self._compute_anchor = compute_bundle_trust_anchor
        self._pop_replay = JTIReplayCache(ttl_seconds=300.0)
        if self.descriptor_store is not None:
            b = self.export_public_bundle()
            self.descriptor_store.set_local_trust_domain(
                self.trust_domain, str(b["trust_anchor"])
            )
        self.http = ManagedHTTPService(
            service_name="audit-tls-ca",
            dispatcher=self._dispatch,
            host=host,
            port=port,
        )
        self.federation_http: Optional[ManagedHTTPService] = None
        if federation_port is not None:
            self.federation_http = ManagedHTTPService(
                service_name="audit-tls-ca-federation",
                dispatcher=self._dispatch_federation_ro,
                host=host,
                port=int(federation_port),
            )

    def start(self) -> None:
        self.http.start()
        if self.federation_http is not None:
            self.federation_http.start()

    def stop(self) -> None:
        if self.federation_http is not None:
            self.federation_http.stop()
        self.http.stop()

    def export_public_bundle(self) -> Dict[str, Any]:
        root_pem = self.x509_ca.export_root_pem()
        bundle: Dict[str, Any] = {
            "trust_domain": self.trust_domain,
            "keys": [],
            "x509_root_pem": root_pem,
        }
        bundle["trust_anchor"] = self._compute_anchor(bundle, allow_keyless_jwks=True)
        return bundle

    def publish_audit_locators(
        self, snapshot: Any, ttl_seconds: float = 3600.0
    ) -> Optional[Any]:
        from lineage.federation.locators import SignedDomainDescriptor

        if self.descriptor_store is None or snapshot is None:
            return None
        ca_locs = snapshot.build_service_locators("ca_federation", transport="http-ro")
        collector_locs = snapshot.build_service_locators(
            "audit_collector",
            transport="tls-tcp",
            spiffe_id="spiffe://org-audit.io/ns/lineage-audit/sa/audit-collector",
        )
        if not ca_locs and not collector_locs:
            return None
        loc_map: Dict[str, Any] = {}
        if ca_locs:
            loc_map["ca_bundle"] = ca_locs
        if collector_locs:
            loc_map["audit_collector"] = collector_locs
        with self._desc_lock:
            next_ver = max(self._own_desc_version + 1, int(time.time() * 1000))
            desc = SignedDomainDescriptor.sign_with_x509_root(
                x509_ca=self.x509_ca,
                bundle=self.export_public_bundle(),
                locators=loc_map,
                version=next_ver,
                ttl_seconds=ttl_seconds,
            )
            self._own_desc_version = next_ver
            self.descriptor_store.set_own_descriptor(desc)
            return desc

    def _export_descriptors_payload(self) -> Dict[str, Any]:
        if self.descriptor_store is None:
            return {"trust_domain": self.trust_domain, "descriptors": []}
        payload = dict(self.descriptor_store.export_gossip_payload())
        payload.setdefault("trust_domain", self.trust_domain)
        return payload

    def _read_csr_secret(self) -> str:
        with open(self.csr_token_file, "r", encoding="utf-8") as fh:
            val = fh.read().strip()
        if len(val) < 24:
            raise PermissionError("Invalid CSR bootstrap secret length")
        return val

    def _dispatch_federation_ro(
        self, req: HTTPRequestContext
    ) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            b = self.export_public_bundle()
            return (
                200,
                {
                    "status": "ok",
                    "trust_domain": self.trust_domain,
                    "trust_anchor": b["trust_anchor"],
                },
                {},
            )
        if req.method == "GET" and req.path == "/v1/federation/bundle":
            return 200, self.export_public_bundle(), {}
        if req.method == "GET" and req.path == "/v1/federation/descriptors":
            return 200, self._export_descriptors_payload(), {}
        if req.method == "POST" and req.path == "/v1/federation/descriptors":
            from lineage.federation.locators import ingest_descriptor_http_request

            return ingest_descriptor_http_request(
                req,
                self.descriptor_store,
                on_descriptor_learned=self.on_descriptor_learned,
            )
        return 404, {"error": "route_not_found"}, {}

    def _dispatch(self, req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            b = self.export_public_bundle()
            return (
                200,
                {
                    "status": "ok",
                    "trust_domain": self.trust_domain,
                    "trust_anchor": b["trust_anchor"],
                },
                {},
            )
        if req.method == "GET" and req.path == "/v1/federation/bundle":
            return 200, self.export_public_bundle(), {}
        if req.method == "GET" and req.path == "/v1/federation/descriptors":
            return 200, self._export_descriptors_payload(), {}
        if req.method == "POST" and req.path == "/v1/ca/learn-descriptors":
            try:
                bearer = _extract_bearer(req.header("Authorization"))
                expected_sec = self._read_csr_secret()
            except Exception as exc:
                return 401, {"error": "unauthorized_caller", "detail": str(exc)}, {}
            if not bearer or not hmac.compare_digest(
                bearer.encode("utf-8"), expected_sec.encode("utf-8")
            ):
                return 401, {"error": "unauthorized_caller"}, {}
            from lineage.federation.locators import ingest_descriptor_http_request

            status_code, out_body, hdrs = ingest_descriptor_http_request(
                req,
                self.descriptor_store,
                on_descriptor_learned=self.on_descriptor_learned,
            )
            return status_code, out_body, hdrs
        if req.method == "POST" and req.path == "/v1/ca/issue-audit-tls":
            bearer = _extract_bearer(req.header("Authorization"))
            try:
                expected_sec = self._read_csr_secret()
            except Exception as exc:
                return 500, {"error": "csr_secret_unavailable", "detail": str(exc)}, {}
            if not bearer or not hmac.compare_digest(bearer.encode("utf-8"), expected_sec.encode("utf-8")):
                return 401, {"error": "unauthorized_csr_caller"}, {}
            body = req.json()
            try:
                pub_jwk = body["public_jwk"]
                pop_jws = str(body["pop_jws"])
                raw_ttl = body.get("ttl_seconds", 1800.0)
                ttl_s = max(10.0, min(86400.0, require_finite_timestamp(raw_ttl, "ttl_seconds")))
                _, pop_claims = jws_verify_compact(
                    pop_jws, pub_jwk, expected_typ="lct-ca-pop+jwt"
                )
                now_ts = time.time()
                iat_val = require_finite_timestamp(pop_claims.get("iat"), "pop.iat")
                if abs(now_ts - iat_val) > 30.0:
                    return 403, {"error": "stale_pop_jws"}, {}
                expected_hash = sha256_b64url(bearer.encode("utf-8"))
                if pop_claims.get("sa_jwt_sha256") != expected_hash:
                    return 403, {"error": "pop_secret_binding_mismatch"}, {}
                pop_jti = str(pop_claims.get("jti") or "")
                if not pop_jti or not self._pop_replay.check_and_record(pop_jti, now=now_ts):
                    return 403, {"error": "replayed_pop_jws"}, {}
                spiffe_uri = "spiffe://org-audit.io/ns/lineage-audit/sa/audit-collector"
                leaf_pem = self.x509_ca.issue_x509_svid(
                    spiffe_id=spiffe_uri,
                    public_jwk=pub_jwk,
                    ttl_seconds=ttl_s,
                    dns_names=(
                        "audit-collector.org-audit.io",
                        "audit-collector.lineage-audit.svc.cluster.local",
                        "audit-collector.lineage-audit.svc",
                        "localhost",
                    ),
                )
            except Exception as exc:
                return 400, {"error": "invalid_audit_csr", "detail": str(exc)}, {}
            now_out = time.time()
            return (
                200,
                {
                    "trust_domain": self.trust_domain,
                    "spiffe_id": spiffe_uri,
                    "x509_leaf_pem": leaf_pem,
                    "issued_at": now_out,
                    "expires_at": now_out + ttl_s,
                    "bundle": self.export_public_bundle(),
                },
                {},
            )
        return 404, {"error": "route_not_found"}, {}


def main() -> None:
    parser = argparse.ArgumentParser(description="LCT Kubernetes Role Runner")
    parser.add_argument("--role", required=True)
    args = parser.parse_args()

    role = args.role
    identity_addressing = _is_identity_addressing_enabled()
    ca_url = os.environ.get(
        "FEDERATION_CA_URL", "http://federation-ca.lineage-ctrl.svc.cluster.local:8090"
    )
    dir_url = os.environ.get(
        "DIRECTORY_URL", "http://directory-svc.lineage-ctrl.svc.cluster.local:8091"
    )
    rev_url = os.environ.get(
        "REVOCATION_URL", "http://revocation-svc.lineage-ctrl.svc.cluster.local:8092"
    )
    raw_audit_env = os.environ.get("AUDIT_COLLECTOR_URL", "").strip()
    audit_url = raw_audit_env or (
        "" if identity_addressing else "http://audit-collector.lineage-ctrl.svc.cluster.local:8093"
    )
    raw_travel_mcp = os.environ.get("TRAVEL_MCP_URL", "").strip()
    travel_mcp_url = raw_travel_mcp or (
        "" if identity_addressing else "https://travel-ops-mcp.lineage-pay.svc.cluster.local:8443/mcp"
    )
    raw_payment_mcp = os.environ.get("PAYMENT_MCP_URL", "").strip()
    payment_mcp_url = raw_payment_mcp or (
        "" if identity_addressing else "https://payment-vault-mcp.lineage-pay.svc.cluster.local:8443/mcp"
    )
    persisted_desc_file = (
        os.environ.get("LCT_PERSISTED_DESCRIPTORS_FILE", "").strip() or None
    )

    stop_event = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())

    wait_for_peers_on_boot = (
        os.environ.get("LCT_WAIT_FOR_PEERS_ON_BOOT", "true").strip().lower() != "false"
    )
    svid_ttl = max(
        6.0, float(os.environ.get("LCT_SVID_TTL_SECONDS", "1800.0").strip() or "1800.0")
    )
    anchor_store, require_pins = _build_env_anchor_store()

    if role == "oauth-sts":
        import json as _json

        from lineage.federation import FederationBundleSyncer
        from lineage.oauth_sts import DEFAULT_REALM_NAME, OAuthSTSService

        trust_domain = os.environ.get("TRUST_DOMAIN", "org-alpha.io").strip()
        oauth_realm = os.environ.get("OAUTH_REALM", DEFAULT_REALM_NAME).strip() or DEFAULT_REALM_NAME
        sts_port = int(os.environ.get("STS_PORT", "8095"))
        local_ca_url_sts = os.environ.get("LOCAL_CA_URL", "").strip()
        creds_path = os.environ.get("OAUTH_CREDENTIALS_FILE", "").strip()

        user_pws: Dict[str, str] = {}
        client_secs: Dict[str, str] = {}
        if creds_path and os.path.isfile(creds_path):
            try:
                with open(creds_path, "r", encoding="utf-8") as fh:
                    creds_doc = _json.load(fh)
                user_pws = dict(creds_doc.get("users") or {})
                client_secs = dict(creds_doc.get("clients") or {})
            except Exception as exc:
                print(
                    f"[oauth-sts:{trust_domain}] Warning reading OAuth credentials metadata: {type(exc).__name__}",
                    flush=True,
                )

        seed_store_sts = _build_env_seed_store() if identity_addressing else None
        desc_store_sts = (
            _build_env_descriptor_store(
                anchor_store, require_pins, local_trust_domain=trust_domain
            )
            if identity_addressing
            else None
        )
        sts_syncer: Optional[FederationBundleSyncer] = None
        if local_ca_url_sts and identity_addressing:
            _wait_for_http_ok(f"{local_ca_url_sts}/healthz")
            sts_syncer = FederationBundleSyncer(
                peer_ca_urls={},
                local_ca_url=local_ca_url_sts,
                anchor_store=anchor_store,
                require_pinned_anchors=require_pins,
                local_trust_domain=trust_domain,
                seed_store=seed_store_sts,
                descriptor_store=desc_store_sts,
                persisted_descriptors_file=persisted_desc_file,
            )
            try:
                loc_b = httpx.get(
                    f"{local_ca_url_sts}/v1/federation/bundle",
                    timeout=3.0,
                    trust_env=False,
                ).json()
                sts_syncer.trust_resolver.register_bundle(loc_b)
                if desc_store_sts is not None and loc_b.get("trust_anchor"):
                    desc_store_sts.set_local_trust_domain(
                        trust_domain, str(loc_b["trust_anchor"])
                    )
            except Exception:
                pass
            sts_syncer.start_background_refresh(interval_sec=2.0)

        def _peer_sts_jwks_urls() -> List[str]:
            if desc_store_sts is None:
                return []
            urls: List[str] = []
            for td_name, desc_obj in desc_store_sts.all_descriptors().items():
                if td_name == trust_domain:
                    continue
                for loc in desc_obj.locators.get("oauth_sts", ()):
                    u = f"{loc.origin_url.rstrip('/')}/realms/{oauth_realm}/protocol/openid-connect/certs"
                    if u not in urls:
                        urls.append(u)
            return urls

        def _peer_sts_issuer_aliases() -> Dict[str, List[str]]:
            if desc_store_sts is None:
                return {}
            amap: Dict[str, List[str]] = {}
            for td_name, desc_obj in desc_store_sts.all_descriptors().items():
                if td_name == trust_domain:
                    continue
                td_short = td_name.strip().lower().removeprefix("org-").split(".", 1)[0]
                canon = f"http://{td_short}-oidc.lct.local/realms/{oauth_realm}"
                lst = amap.setdefault(canon, [])
                for loc in desc_obj.locators.get("oauth_sts", ()):
                    src_u = f"{loc.origin_url.rstrip('/')}/realms/{oauth_realm}"
                    if src_u not in lst:
                        lst.append(src_u)
            return amap

        oauth_issuer_origin = os.environ.get("OAUTH_ISSUER_ORIGIN", "").strip().rstrip("/") or None
        sts_svc = OAuthSTSService(
            trust_domain=trust_domain,
            realm=oauth_realm,
            user_passwords=user_pws,
            client_secrets=client_secs,
            spiffe_trust_resolver=(
                sts_syncer.trust_resolver if sts_syncer is not None else None
            ),
            peer_sts_jwks_Urls_provider=_peer_sts_jwks_urls,
            peer_issuer_aliases_provider=_peer_sts_issuer_aliases,
            issuer_override=oauth_issuer_origin,
            host="0.0.0.0",
            port=sts_port,
            credentials_file=(creds_path if creds_path else None),
        )
        sts_svc.start()
        print(
            f"[oauth-sts:{trust_domain}] RFC 8693 / OIDC STS active on 0.0.0.0:{sts_port} realm={oauth_realm}",
            flush=True,
        )
        try:
            stop_event.wait()
        finally:
            if sts_syncer is not None:
                sts_syncer.stop_background_refresh()
            sts_svc.stop()
        return

    if role == "audit-tls-ca":
        from lineage.federation import FederationBundleSyncer

        key_dir = os.environ.get("CA_KEY_MATERIAL_DIR", "").strip()
        csr_tok_file = os.environ["AUDIT_CSR_TOKEN_FILE"]
        fed_port_raw = os.environ.get("CA_FEDERATION_PORT", "").strip()
        fed_port = int(fed_port_raw) if fed_port_raw else None
        seed_store = _build_env_seed_store() if identity_addressing else None
        desc_store = _build_env_descriptor_store(
            anchor_store, require_pins, local_trust_domain="org-audit.io"
        )
        audit_ca_syncer: Optional[FederationBundleSyncer] = (
            FederationBundleSyncer(
                peer_ca_urls={},
                anchor_store=anchor_store,
                require_pinned_anchors=require_pins,
                local_trust_domain="org-audit.io",
                seed_store=seed_store,
                descriptor_store=desc_store,
                persisted_descriptors_file=persisted_desc_file,
            )
            if identity_addressing
            else None
        )
        svc_audit_ca = MinimalAuditTLSCAService(
            csr_token_file=csr_tok_file,
            x509_private_key_pem=_read_optional_pem(key_dir, "x509_private_key.pem"),
            x509_root_cert_pem=_read_optional_pem(key_dir, "x509_root_cert.pem"),
            host="0.0.0.0",
            port=8090,
            federation_port=fed_port,
            descriptor_store=desc_store,
            on_descriptor_learned=(
                audit_ca_syncer.apply_verified_descriptor
                if audit_ca_syncer is not None
                else None
            ),
        )
        svc_audit_ca.start()
        loc_watcher = _build_env_node_locator_watcher(
            on_change=lambda snap: svc_audit_ca.publish_audit_locators(snap)
        )
        if loc_watcher is not None:
            init_snap = loc_watcher.wait_for_locators(max_wait_sec=12.0)
            if init_snap is not None:
                svc_audit_ca.publish_audit_locators(init_snap)
            loc_watcher.start()
        if audit_ca_syncer is not None:
            audit_ca_syncer.start_background_refresh(interval_sec=2.0)
        print(
            f"[audit-tls-ca:org-audit.io] Minimal X.509-only CA ready on 0.0.0.0:8090 (fed_port={fed_port}) anchor={svc_audit_ca.export_public_bundle()['trust_anchor']}",
            flush=True,
        )
        try:
            while not stop_event.wait(timeout=600.0):
                if loc_watcher is not None:
                    cur_s = loc_watcher.current_snapshot()
                    if cur_s is not None:
                        svc_audit_ca.publish_audit_locators(cur_s)
        finally:
            if loc_watcher is not None:
                loc_watcher.stop()
            if audit_ca_syncer is not None:
                audit_ca_syncer.stop_background_refresh()
            svc_audit_ca.stop()
        return

    if role == "domain-ca":
        from lineage.federation import AutonomousDomainCAService, FederationBundleSyncer

        trust_domain = os.environ["TRUST_DOMAIN"]
        allowed_ns = os.environ["ALLOWED_K8S_NAMESPACE"]
        auth_gw_sa = os.environ.get("AUTHORIZED_GATEWAY_SA", "").strip() or None
        auth_gw_sas = [
            s.strip()
            for s in os.environ.get("AUTHORIZED_GATEWAY_SAS", "").split(",")
            if s.strip()
        ]
        auth_auditors = [
            s.strip()
            for s in os.environ.get("AUTHORIZED_AUDITORS", "").split(",")
            if s.strip()
        ]
        registry_mode_ca = os.environ.get("REGISTRY_MODE", "federated").strip().lower() or "federated"
        audit_mode_ca = os.environ.get("AUDIT_MODE", "").strip().lower()
        fed_port_raw = os.environ.get("CA_FEDERATION_PORT", "").strip()
        fed_port = int(fed_port_raw) if fed_port_raw else None
        key_dir = os.environ.get("CA_KEY_MATERIAL_DIR", "").strip()
        seed_store = _build_env_seed_store() if identity_addressing else None
        desc_store = (
            _build_env_descriptor_store(
                anchor_store, require_pins, local_trust_domain=trust_domain
            )
            if identity_addressing
            else None
        )
        ca_audit_syncer: Optional[FederationBundleSyncer] = None
        if identity_addressing:
            ca_audit_syncer = FederationBundleSyncer(
                peer_ca_urls={},
                anchor_store=anchor_store,
                require_pinned_anchors=require_pins,
                local_trust_domain=trust_domain,
                seed_store=seed_store,
                descriptor_store=desc_store,
                persisted_descriptors_file=persisted_desc_file,
            )
        elif audit_url and audit_url.startswith("https://"):
            ca_audit_syncer = FederationBundleSyncer(
                peer_ca_urls={},
                anchor_store=anchor_store,
                require_pinned_anchors=require_pins,
                audit_ca_url=audit_url,
            )

        oidc_jwks_url = os.environ.get("OIDC_JWKS_URL", "").strip()
        local_sts_url_ca = os.environ.get("LOCAL_STS_URL", "").strip().rstrip("/")
        oauth_realm_ca = os.environ.get("OAUTH_REALM", "lct").strip() or "lct"
        ca_oidc_verifier: Optional[Any] = None
        if oidc_jwks_url:
            from lineage.oauth_sts import OIDCTokenVerifier

            def _ca_oidc_jwks_urls() -> List[str]:
                out = [oidc_jwks_url]
                if desc_store is not None:
                    d_obj = desc_store.get_descriptor(trust_domain)
                    if d_obj is not None:
                        for loc in d_obj.locators.get("oauth_sts", ()):
                            u = f"{loc.origin_url.rstrip('/')}/realms/{oauth_realm_ca}/protocol/openid-connect/certs"
                            if u not in out:
                                out.append(u)
                return out

            def _ca_allowed_issuers() -> List[str]:
                dom_short = trust_domain.strip().lower().removeprefix("org-").split(".", 1)[0]
                iss_list: List[str] = [
                    f"http://{dom_short}-oidc.lct.local/realms/{oauth_realm_ca}",
                ]
                if local_sts_url_ca:
                    iss_list.append(f"{local_sts_url_ca}/realms/{oauth_realm_ca}")
                if desc_store is not None:
                    d_obj = desc_store.get_descriptor(trust_domain)
                    if d_obj is not None:
                        for loc in d_obj.locators.get("oauth_sts", ()):
                            iss_list.append(
                                f"{loc.origin_url.rstrip('/')}/realms/{oauth_realm_ca}"
                            )
                return iss_list

            ca_oidc_verifier = OIDCTokenVerifier(
                jwks_urls=[oidc_jwks_url],
                jwks_urls_provider=_ca_oidc_jwks_urls,
                allowed_issuers_provider=_ca_allowed_issuers,
                default_user_domain=trust_domain,
                allowed_user_domains=(trust_domain,),
                single_entity_issuers=True,
            )

        svc = AutonomousDomainCAService(
            trust_domain=trust_domain,
            allowed_k8s_namespace=allowed_ns,
            audit_collector_url=audit_url,
            authorized_gateway_sa=auth_gw_sa,
            authorized_gateway_sas=auth_gw_sas or None,
            host="0.0.0.0",
            port=8090,
            federation_port=fed_port,
            ca_private_key_pem=_read_optional_pem(key_dir, "ca_private_key.pem"),
            x509_private_key_pem=_read_optional_pem(key_dir, "x509_private_key.pem"),
            x509_root_cert_pem=_read_optional_pem(key_dir, "x509_root_cert.pem"),
            audit_ssl_context_provider=(
                ca_audit_syncer.audit_ssl_context
                if (ca_audit_syncer is not None and not identity_addressing and audit_mode_ca != "decentralized")
                else None
            ),
            audit_locator_provider=(
                ca_audit_syncer.audit_locators
                if (ca_audit_syncer is not None and identity_addressing and audit_mode_ca != "decentralized")
                else None
            ),
            audit_ssl_for_locator=(
                ca_audit_syncer.audit_ssl_context_for_locator
                if (ca_audit_syncer is not None and identity_addressing and audit_mode_ca != "decentralized")
                else None
            ),
            best_effort_audit=(
                (not wait_for_peers_on_boot)
                or identity_addressing
                or audit_url.startswith("https://")
                or audit_mode_ca == "decentralized"
            ),
            descriptor_store=desc_store,
            on_descriptor_learned=(
                ca_audit_syncer.apply_verified_descriptor
                if ca_audit_syncer is not None
                else None
            ),
            oidc_verifier=ca_oidc_verifier,
            federation_trust_resolver=(
                ca_audit_syncer.trust_resolver if ca_audit_syncer is not None else None
            ),
            authorized_auditors=auth_auditors or None,
            consent_issuer_policy=os.environ.get("CONSENT_ISSUER_POLICY", "").strip() or None,
        )
        if ca_audit_syncer is not None:
            ca_audit_syncer.trust_resolver.register_domain_ca(svc.ca)
        if desc_store is not None:
            desc_store.set_local_trust_domain(trust_domain, svc.trust_anchor)

        def _publish_ca_snapshot(snap: Any) -> None:
            if snap is None:
                return
            ca_locs = snap.build_service_locators("ca_federation", transport="http-ro")
            dir_locs = snap.build_service_locators(
                "directory_federation",
                transport="mtls-tcp",
                spiffe_id=f"spiffe://{trust_domain}/ns/sys/sa/directory",
            )
            yp_locs = snap.build_service_locators(
                "yellow_pages",
                transport="mtls-tcp",
                spiffe_id=f"spiffe://{trust_domain}/ns/sys/sa/directory",
            )
            rev_locs = snap.build_service_locators(
                "revocation_federation",
                transport="mtls-tcp",
                spiffe_id=f"spiffe://{trust_domain}/ns/sys/sa/revocation",
            )
            sts_locs = snap.build_service_locators("oauth_sts", transport="http-ro")
            ugw_locs = (
                snap.build_service_locators(
                    auth_gw_sa,
                    transport="mtls-tcp",
                    spiffe_id=f"spiffe://{trust_domain}/ns/{allowed_ns}/sa/{auth_gw_sa}",
                )
                if auth_gw_sa and auth_gw_sa != "e2e-user-gateway"
                else ()
            )
            yp_dom_ca = os.environ.get("YELLOW_PAGES_DOMAIN", "org-alpha.io").strip().lower() or "org-alpha.io"
            loc_map: Dict[str, Any] = {}
            if ca_locs:
                loc_map["ca_bundle"] = ca_locs
            if dir_locs and (registry_mode_ca != "centralized" or trust_domain == yp_dom_ca):
                loc_map["directory_federation"] = dir_locs
            if registry_mode_ca == "centralized" and trust_domain == yp_dom_ca and (yp_locs or dir_locs):
                loc_map["yellow_pages"] = yp_locs or dir_locs
            if rev_locs:
                loc_map["revocation_federation"] = rev_locs
            if sts_locs:
                loc_map["oauth_sts"] = sts_locs
            if ugw_locs:
                loc_map["user_gateway"] = ugw_locs
            if loc_map:
                desc = svc.publish_domain_locators(loc_map)
                print(
                    f"[domain-ca:{trust_domain}] Signed domain descriptor v{desc.version} locators={ {k: [l.origin_url for l in v] for k, v in desc.locators.items()} }",
                    flush=True,
                )

        svc.start()
        loc_watcher = _build_env_node_locator_watcher(on_change=_publish_ca_snapshot)
        if loc_watcher is not None:
            init_snap = loc_watcher.wait_for_locators(max_wait_sec=12.0)
            if init_snap is not None:
                _publish_ca_snapshot(init_snap)
            loc_watcher.start()

        if ca_audit_syncer is not None:
            ca_audit_syncer.sync_all(require_all=False)
            ca_audit_syncer.start_background_refresh(interval_sec=2.0)
        print(
            f"[domain-ca:{trust_domain}] Autonomous CA ready on 0.0.0.0:8090 (fed_port={fed_port}, allowed_ns={allowed_ns}, anchor={svc.trust_anchor})",
            flush=True,
        )
        try:
            while not stop_event.wait(timeout=600.0):
                if loc_watcher is not None:
                    cur_s = loc_watcher.current_snapshot()
                    if cur_s is not None:
                        _publish_ca_snapshot(cur_s)
        finally:
            if loc_watcher is not None:
                loc_watcher.stop()
            if ca_audit_syncer is not None:
                ca_audit_syncer.stop_background_refresh()
            svc.stop()
        return

    if role == "federated-audit-collector":
        from lineage.common.mtls import WorkloadMTLSBundle, X509FederationTrustStore
        from lineage.federation import FederationBundleSyncer, parse_domain_url_map

        peer_ca_raw = os.environ.get("PEER_CA_URLS", "").strip()
        peer_ca_map = parse_domain_url_map(peer_ca_raw) if peer_ca_raw else {}
        use_id_addr = identity_addressing or not peer_ca_map

        audit_tls_ca_url = os.environ.get("AUDIT_TLS_CA_URL", "").strip()
        audit_csr_token_file = os.environ.get("AUDIT_CSR_TOKEN_FILE", "").strip()
        audit_mtls_bundle: Optional[WorkloadMTLSBundle] = None
        audit_public_bundle_box: Dict[str, Any] = {}
        tls_renew_stop = threading.Event()
        tls_renew_thread: Optional[threading.Thread] = None

        if audit_tls_ca_url and audit_csr_token_file:
            tls_kp = KeyPair.generate("ES256")
            audit_x509_store = X509FederationTrustStore()

            def _issue_or_renew_audit_tls() -> Tuple[str, float, float, Dict[str, Any]]:
                with open(audit_csr_token_file, "r", encoding="utf-8") as fh:
                    csr_tok = fh.read().strip()
                pop_jws = create_ca_pop_jws(tls_kp, csr_tok)
                resp_tls = httpx.post(
                    f"{audit_tls_ca_url.rstrip('/')}/v1/ca/issue-audit-tls",
                    json={
                        "public_jwk": tls_kp.public_jwk(),
                        "pop_jws": pop_jws,
                        "ttl_seconds": svid_ttl,
                    },
                    headers={"Authorization": f"Bearer {csr_tok}"},
                    timeout=5.0,
                )
                resp_tls.raise_for_status()
                d_tls = resp_tls.json()
                return (
                    str(d_tls["x509_leaf_pem"]),
                    float(d_tls["issued_at"]),
                    float(d_tls["expires_at"]),
                    dict(d_tls["bundle"]),
                )

            deadline_tls = time.time() + 45.0
            last_tls_err: Optional[Exception] = None
            init_leaf: Optional[str] = None
            init_iat = 0.0
            init_exp = 0.0
            while time.time() < deadline_tls:
                try:
                    init_leaf, init_iat, init_exp, pub_b = _issue_or_renew_audit_tls()
                    audit_public_bundle_box.clear()
                    audit_public_bundle_box.update(pub_b)
                    audit_x509_store.register_domain_root_pem(
                        "org-audit.io", str(pub_b["x509_root_pem"])
                    )
                    break
                except Exception as exc:
                    last_tls_err = exc
                    time.sleep(0.4)
            if init_leaf is None:
                raise RuntimeError(
                    f"Failed to obtain TLS leaf cert from {audit_tls_ca_url}: {last_tls_err}"
                )

            audit_mtls_bundle = WorkloadMTLSBundle(
                spiffe_id="spiffe://org-audit.io/ns/lineage-audit/sa/audit-collector",
                keypair=tls_kp,
                leaf_cert_pem=init_leaf,
                trust_store=audit_x509_store,
            )

            def _audit_tls_renew_loop() -> None:
                cur_iat = init_iat
                cur_exp = init_exp
                check_s = max(0.5, min(10.0, svid_ttl * 0.15))
                while not tls_renew_stop.is_set():
                    if (cur_exp - time.time()) <= 0.5 * max(1.0, cur_exp - cur_iat):
                        try:
                            new_leaf, n_iat, n_exp, new_b = _issue_or_renew_audit_tls()
                            audit_public_bundle_box.update(new_b)
                            audit_x509_store.register_domain_root_pem(
                                "org-audit.io", str(new_b["x509_root_pem"])
                            )
                            if audit_mtls_bundle is not None:
                                audit_mtls_bundle.update_svid(leaf_cert_pem=new_leaf)
                            cur_iat, cur_exp = n_iat, n_exp
                        except Exception:
                            pass
                    tls_renew_stop.wait(check_s)

            tls_renew_thread = threading.Thread(
                target=_audit_tls_renew_loop, name="audit-tls-renew", daemon=True
            )
            tls_renew_thread.start()

        own_audit_anchor = (
            str(audit_public_bundle_box.get("trust_anchor") or "") or None
        )
        seed_store = _build_env_seed_store() if use_id_addr else None
        desc_store = (
            _build_env_descriptor_store(
                anchor_store,
                require_pins,
                local_trust_domain="org-audit.io",
                local_trust_anchor=own_audit_anchor,
            )
            if use_id_addr
            else None
        )
        syncer = FederationBundleSyncer(
            peer_ca_urls=peer_ca_map,
            anchor_store=anchor_store,
            require_pinned_anchors=require_pins,
            local_trust_domain=("org-audit.io" if use_id_addr else None),
            seed_store=seed_store,
            descriptor_store=desc_store,
            local_ca_url=(audit_tls_ca_url if use_id_addr and audit_tls_ca_url else None),
            sa_token_path=(audit_csr_token_file if use_id_addr and audit_csr_token_file else None),
            persisted_descriptors_file=(persisted_desc_file if use_id_addr else None),
        )
        if wait_for_peers_on_boot and peer_ca_map:
            syncer.sync_all(require_all=True, max_wait_sec=60.0)
        elif use_id_addr:
            syncer.sync_all(require_all=False)
        syncer.start_background_refresh(interval_sec=2.0)

        svc = AuditCollectorService(
            trust_resolver=syncer.trust_resolver,
            host="0.0.0.0",
            port=8093,
            ssl_context_provider=(
                audit_mtls_bundle.server_ssl_context_provider(require_client_cert=False)
                if audit_mtls_bundle is not None
                else None
            ),
            public_bundle_provider=(
                (lambda: dict(audit_public_bundle_box))
                if audit_mtls_bundle is not None
                else None
            ),
            descriptors_provider=(
                desc_store.export_gossip_payload if desc_store is not None else None
            ),
            readiness_check=syncer.is_ready,
        )
        try:
            svc.start()
            mode_lbl = "TLS-1.3" if audit_mtls_bundle is not None else "HTTP"
            print(
                f"[federated-audit-collector:{mode_lbl}] Keyless verifier listening on 0.0.0.0:8093 (id_addressing={use_id_addr})",
                flush=True,
            )
            stop_event.wait()
        finally:
            tls_renew_stop.set()
            if tls_renew_thread is not None:
                tls_renew_thread.join(timeout=2.0)
            syncer.stop_background_refresh()
            svc.stop()
            if audit_mtls_bundle is not None:
                audit_mtls_bundle.cleanup()
        return

    if role == "domain-revocation":
        from lineage.federation import bootstrap_autonomous_workload, parse_domain_url_map

        local_ca_url = os.environ["LOCAL_CA_URL"]
        peer_ca_raw = os.environ.get("PEER_CA_URLS", "").strip()
        peer_ca_map = parse_domain_url_map(peer_ca_raw) if peer_ca_raw else {}
        peer_rev_map = parse_domain_url_map(os.environ.get("PEER_REVOCATION_URLS", ""))
        use_id_addr = identity_addressing or not peer_ca_map
        rev_fed_raw = os.environ.get("REVOCATION_FEDERATION_PORT", "").strip()
        rev_fed_port = int(rev_fed_raw) if rev_fed_raw else None
        seed_store = _build_env_seed_store() if use_id_addr else None
        desc_store = (
            _build_env_descriptor_store(anchor_store, require_pins)
            if use_id_addr
            else None
        )
        identity, resolver, mtls_bundle, syncer = bootstrap_autonomous_workload(
            local_ca_url,
            peer_ca_map,
            require_all_peers=wait_for_peers_on_boot and bool(peer_ca_map),
            svid_ttl_seconds=svid_ttl,
            anchor_store=anchor_store,
            require_pinned_anchors=require_pins,
            enable_auto_renewal=True,
            seed_store=seed_store,
            descriptor_store=desc_store,
            persisted_descriptors_file=(persisted_desc_file if use_id_addr else None),
        )
        svc = RevocationService(
            identity,
            resolver,
            strict_domain_isolation=True,
            peer_revocation_urls=peer_rev_map,
            host="0.0.0.0",
            port=8092,
            federation_port=rev_fed_port,
            mtls_bundle=mtls_bundle,
            readiness_check=syncer.is_ready,
            descriptor_store=desc_store,
        )
        try:
            svc.start()
            print(
                f"[domain-revocation:{identity.trust_domain}] Listening as {identity.spiffe_id} on :8092 (mTLS fed_port={rev_fed_port}, id_addressing={use_id_addr})",
                flush=True,
            )
            stop_event.wait()
        finally:
            syncer.stop_background_refresh()
            svc.stop()
            if mtls_bundle is not None:
                mtls_bundle.cleanup()
        return

    if role == "domain-directory":
        from lineage.federation import bootstrap_autonomous_workload, parse_domain_url_map

        local_ca_url = os.environ["LOCAL_CA_URL"]
        peer_ca_raw = os.environ.get("PEER_CA_URLS", "").strip()
        peer_ca_map = parse_domain_url_map(peer_ca_raw) if peer_ca_raw else {}
        peer_dir_map = parse_domain_url_map(os.environ.get("PEER_DIRECTORY_URLS", ""))
        use_id_addr = identity_addressing or not peer_ca_map
        dir_fed_raw = os.environ.get("DIRECTORY_FEDERATION_PORT", "").strip()
        dir_fed_port = int(dir_fed_raw) if dir_fed_raw else None
        seed_store = _build_env_seed_store() if use_id_addr else None
        desc_store = (
            _build_env_descriptor_store(anchor_store, require_pins)
            if use_id_addr
            else None
        )
        identity, resolver, mtls_bundle, syncer = bootstrap_autonomous_workload(
            local_ca_url,
            peer_ca_map,
            require_all_peers=wait_for_peers_on_boot and bool(peer_ca_map),
            svid_ttl_seconds=svid_ttl,
            anchor_store=anchor_store,
            require_pinned_anchors=require_pins,
            enable_auto_renewal=True,
            seed_store=seed_store,
            descriptor_store=desc_store,
            persisted_descriptors_file=(persisted_desc_file if use_id_addr else None),
        )
        _wait_for_http_ok(f"{rev_url}/healthz")
        rev_replica = RevocationReplicaClient(rev_url, resolver)
        rev_replica.start_background_sync(wait_ms=800)
        registry_mode_dir = os.environ.get("REGISTRY_MODE", "federated").strip().lower() or "federated"
        svc = AgentDirectoryService(
            resolver,
            revocation_replica=rev_replica,
            local_trust_domain=identity.trust_domain,
            peer_directory_urls=peer_dir_map,
            host="0.0.0.0",
            port=8091,
            federation_port=dir_fed_port,
            mtls_bundle=mtls_bundle,
            readiness_check=syncer.is_ready,
            descriptor_store=desc_store,
            on_descriptor_learned=syncer.apply_verified_descriptor,
            registry_mode=registry_mode_dir,
        )
        try:
            svc.start()
            print(
                f"[domain-directory:{identity.trust_domain}] Listening as {identity.spiffe_id} on :8091 (mTLS fed_port={dir_fed_port}, id_addressing={use_id_addr})",
                flush=True,
            )
            stop_event.wait()
        finally:
            rev_replica.stop_background_sync()
            syncer.stop_background_refresh()
            svc.stop()
            if mtls_bundle is not None:
                mtls_bundle.cleanup()
        return

    if role == "federation-ca":
        svc = FederationCAService(audit_collector_url=audit_url, host="0.0.0.0", port=8090)
        svc.http.start()
        print("[federation-ca] Ready on 0.0.0.0:8090", flush=True)
        stop_event.wait()
        svc.http.stop()
        return

    if role == "revocation-svc":
        identity, resolver = bootstrap_k8s_workload_identity(ca_url)
        svc = RevocationService(identity, resolver, host="0.0.0.0", port=8092)
        svc.start()
        print(f"[revocation-svc] Ready as {identity.spiffe_id} on 0.0.0.0:8092", flush=True)
        stop_event.wait()
        svc.stop()
        return

    if role == "directory-svc":
        identity, resolver = bootstrap_k8s_workload_identity(ca_url)
        _wait_for_http_ok(f"{rev_url}/healthz")
        rev_replica = RevocationReplicaClient(rev_url, resolver)
        rev_replica.start_background_sync(wait_ms=1000)
        svc = AgentDirectoryService(
            resolver, revocation_replica=rev_replica, host="0.0.0.0", port=8091
        )
        svc.start()
        print(f"[directory-svc] Ready as {identity.spiffe_id} on 0.0.0.0:8091", flush=True)
        stop_event.wait()
        rev_replica.stop_background_sync()
        svc.stop()
        return

    if role == "audit-collector":
        identity, resolver = bootstrap_k8s_workload_identity(ca_url)
        svc = AuditCollectorService(trust_resolver=resolver, host="0.0.0.0", port=8093)
        svc.start()
        print(f"[audit-collector] Ready as {identity.spiffe_id} on 0.0.0.0:8093", flush=True)
        stop_event.wait()
        svc.stop()
        return

    if role == "sidecar":
        loopback_secret = _write_shared_loopback_secret()
        local_ca_url = os.environ.get("LOCAL_CA_URL", "").strip()
        peer_ca_spec = os.environ.get("PEER_CA_URLS", "").strip()
        use_id_addr = bool(local_ca_url) and (identity_addressing or not peer_ca_spec)
        mtls_bundle = None
        syncer = None
        desc_store = None
        if local_ca_url and (peer_ca_spec or use_id_addr):
            from lineage.federation import (
                bootstrap_autonomous_workload,
                parse_domain_url_map,
            )

            seed_store = _build_env_seed_store() if use_id_addr else None
            desc_store = (
                _build_env_descriptor_store(anchor_store, require_pins)
                if use_id_addr
                else None
            )
            peer_ca_map = parse_domain_url_map(peer_ca_spec) if peer_ca_spec else {}
            identity, resolver, mtls_bundle, syncer = bootstrap_autonomous_workload(
                local_ca_url,
                peer_ca_map,
                require_all_peers=wait_for_peers_on_boot and bool(peer_ca_map),
                svid_ttl_seconds=svid_ttl,
                anchor_store=anchor_store,
                require_pinned_anchors=require_pins,
                audit_ca_url=(
                    audit_url
                    if (not use_id_addr and audit_url.startswith("https://"))
                    else None
                ),
                enable_auto_renewal=True,
                seed_store=seed_store,
                descriptor_store=desc_store,
                persisted_descriptors_file=(persisted_desc_file if use_id_addr else None),
            )
            default_in_port = "8443"
        else:
            identity, resolver = bootstrap_k8s_workload_identity(ca_url)
            default_in_port = "8080"

        _wait_for_http_ok(f"{rev_url}/healthz")
        if (
            wait_for_peers_on_boot
            and audit_url
            and not audit_url.startswith("https://")
        ):
            _wait_for_http_ok(f"{audit_url}/healthz")
        app_port = int(os.environ.get("APP_PORT", "9001"))
        inbound_port = int(os.environ.get("SIDECAR_INBOUND_PORT", default_in_port))
        outbound_port = int(os.environ.get("SIDECAR_OUTBOUND_PORT", "8081"))
        is_tool = os.environ.get("IS_TOOL_SERVER", "false").lower() == "true"
        v_mode = VerificationMode(
            os.environ.get("VERIFICATION_MODE", VerificationMode.ADAPTIVE_RISK_ANCHORED.value)
        )
        loc_slot = os.environ.get("LCT_LOCATOR_SLOT", "").strip()
        explicit_public_origin = os.environ.get("PUBLIC_ORIGIN", "").strip()
        loc_transport = "mtls-tcp" if mtls_bundle is not None else "http-ro"

        _wait_for_http_ok(f"http://127.0.0.1:{app_port}/healthz")

        rev_replica = RevocationReplicaClient(rev_url, resolver)
        rev_replica.start_background_sync(wait_ms=800)

        registry_mode_sc = os.environ.get("REGISTRY_MODE", "federated").strip().lower() or "federated"
        yp_domain_sc = os.environ.get("YELLOW_PAGES_DOMAIN", "org-alpha.io").strip().lower() or "org-alpha.io"
        audit_mode_sc = os.environ.get("AUDIT_MODE", "").strip().lower()
        auth_auditors_sc = [
            s.strip()
            for s in os.environ.get("AUTHORIZED_AUDITORS", "").split(",")
            if s.strip()
        ]
        res_owner_sub_sc = os.environ.get("RESOURCE_OWNER_SUB", "").strip() or None
        owner_prot_tools_sc = [
            s.strip()
            for s in os.environ.get("OWNER_PROTECTED_TOOLS", "").split(",")
            if s.strip()
        ]
        allowed_coauth_tools_sc = [
            s.strip()
            for s in os.environ.get("ALLOWED_CO_AUTH_TOOLS", "").split(",")
            if s.strip()
        ]

        def _yellow_pages_locators() -> List[Any]:
            if desc_store is None:
                return []
            yp_desc = desc_store.get_descriptor(yp_domain_sc)
            if yp_desc is None:
                return []
            locs = list(yp_desc.locators.get("yellow_pages", ()))
            if not locs:
                locs = list(yp_desc.locators.get("directory_federation", ()))
            return locs

        dir_client = AgentDirectoryClient(
            dir_url,
            resolver,
            locator_provider=(
                _yellow_pages_locators
                if (not dir_url and registry_mode_sc == "centralized")
                else None
            ),
            mtls_bundle=(
                mtls_bundle
                if (not dir_url and registry_mode_sc == "centralized")
                else None
            ),
        )
        pod_stream_id = f"{identity.spiffe_id}#{socket.gethostname()}"
        audit_collector_cli = (
            None
            if (audit_mode_sc == "decentralized" and not audit_url)
            else AuditCollectorClient(
                audit_url,
                ssl_context_provider=(
                    syncer.audit_ssl_context
                    if (syncer is not None and not use_id_addr and audit_url.startswith("https://"))
                    else None
                ),
                locator_provider=(
                    syncer.audit_locators
                    if (syncer is not None and use_id_addr and not audit_url)
                    else None
                ),
                ssl_context_for_locator=(
                    syncer.audit_ssl_context_for_locator
                    if (syncer is not None and use_id_addr and not audit_url)
                    else None
                ),
            )
        )
        audit_emitter = AuditStreamEmitter(
            signer=identity,
            collector_client=audit_collector_cli,
            stream_id=pod_stream_id,
            best_effort_remote=(
                (not wait_for_peers_on_boot)
                or use_id_addr
                or audit_url.startswith("https://")
                or audit_mode_sc == "decentralized"
            ),
            authorized_auditors=auth_auditors_sc or None,
        )

        card_lock = threading.Lock()
        card_state: Dict[str, Any] = {
            "card": None,
            "version": int(time.time() * 1000),
            "locators": (),
        }
        raw_skills_env = os.environ.get("AGENT_SKILLS", "").strip()
        skills = [
            s.strip()
            for s in (raw_skills_env or "agent.generic").split(",")
            if s.strip()
        ]
        supported_tools = [
            t.strip()
            for t in os.environ.get("SUPPORTED_TOOLS", "").split(",")
            if t.strip()
        ]
        should_register_card = (not is_tool) or bool(raw_skills_env)
        priority = int(os.environ.get("AGENT_PRIORITY", "50"))
        agent_name = os.environ.get("AGENT_DISPLAY_NAME", identity.spiffe_id)

        loc_watcher = _build_env_node_locator_watcher() if loc_slot else None
        if loc_watcher is not None:
            init_snap = loc_watcher.wait_for_locators(max_wait_sec=12.0)
            if init_snap is not None:
                card_state["locators"] = init_snap.build_service_locators(
                    loc_slot,
                    transport=loc_transport,
                    spiffe_id=identity.spiffe_id,
                )

        def _current_primary_and_extras() -> Tuple[str, List[str]]:
            locs = card_state["locators"]
            if locs:
                return locs[0].origin_url, [loc.origin_url for loc in locs[1:]]
            if explicit_public_origin:
                return explicit_public_origin, []
            scheme = "https" if mtls_bundle is not None else "http"
            return f"{scheme}://127.0.0.1:{inbound_port}", []

        init_primary_origin, init_extra_origins = _current_primary_and_extras()

        def _mint_and_register_card(sidecar_ref: Optional[LineageSidecar] = None) -> Optional[AgentCard]:
            if stop_event.is_set():
                return None
            with card_lock:
                if stop_event.is_set():
                    return None
                cur_locs = tuple(card_state["locators"])
                prim_origin, extra_origins = _current_primary_and_extras()
                next_ver = max(int(card_state["version"]) + 1, int(time.time() * 1000))
                rem_svid_ttl = max(
                    5.0, min(float(svid_ttl), float(identity.expires_at - time.time()))
                )
                card_obj = AgentCard.sign_and_create(
                    identity=identity,
                    name=agent_name,
                    endpoint=(None if cur_locs else prim_origin),
                    return_endpoint=(None if cur_locs else prim_origin),
                    skills=skills,
                    supported_tools=supported_tools,
                    priority=priority,
                    streaming_supported=(not is_tool),
                    ttl_seconds=rem_svid_ttl,
                    version=next_ver,
                    locators=(cur_locs if cur_locs else None),
                )
                card_state["version"] = next_ver
                if sidecar_ref is not None:
                    sidecar_ref.set_public_origins(prim_origin, extra_origins)
                    sidecar_ref.set_agent_card(card_obj)
                dir_client.register(card_obj)
                card_state["card"] = card_obj
                return card_obj

        registered_card: Optional[AgentCard] = None
        if should_register_card:
            if dir_url:
                _wait_for_http_ok(f"{dir_url}/healthz")
            for attempt in range(12):
                try:
                    registered_card = _mint_and_register_card()
                    break
                except Exception:
                    if attempt == 11 and wait_for_peers_on_boot:
                        raise
                    time.sleep(0.5)

        def _sidecar_readiness() -> Tuple[bool, Dict[str, Any]]:
            if syncer is None:
                return True, {}
            peers_ok, diag = syncer.is_ready()
            card_ok = (not should_register_card) or (card_state["card"] is not None)
            diag["agent_card_registered"] = card_ok
            return (peers_ok and card_ok), diag

        delegation_mode_env = os.environ.get("DELEGATION_MODE", "lct").strip().lower() or "lct"
        local_sts_url_sc = os.environ.get("LOCAL_STS_URL", "").strip().rstrip("/")
        oauth_realm_sc = os.environ.get("OAUTH_REALM", "lct").strip() or "lct"
        oauth_creds_file = os.environ.get("OAUTH_CREDENTIALS_FILE", "").strip()

        oauth_central_ver: Optional[Any] = None
        oauth_local_ver: Optional[Any] = None
        oauth_ex_cli: Optional[Any] = None
        central_origins_fn = None
        domain_origins_fn = None
        if delegation_mode_env in ("dual", "oauth_centralized", "oauth_federated"):
            import json as _json_sc

            from lineage.oauth_sts import OAuthTokenExchangeClient, OIDCTokenVerifier

            sc_client_secrets: Dict[str, str] = {}
            if oauth_creds_file and os.path.isfile(oauth_creds_file):
                try:
                    with open(oauth_creds_file, "r", encoding="utf-8") as fh:
                        sc_client_secrets = dict((_json_sc.load(fh) or {}).get("clients") or {})
                except Exception:
                    sc_client_secrets = {}

            def _central_sts_origins() -> List[str]:
                ext_locs = (
                    [
                        loc
                        for loc in (desc_store.get_descriptor("org-alpha.io").locators.get("oauth_sts", ()) if (desc_store is not None and desc_store.get_descriptor("org-alpha.io") is not None) else ())
                    ]
                )
                origins: List[str] = []
                if identity.trust_domain == "org-alpha.io" and local_sts_url_sc:
                    if ext_locs:
                        origins.append(f"{local_sts_url_sc}#host={ext_locs[0].host}:{ext_locs[0].port}")
                    else:
                        origins.append(local_sts_url_sc)
                for loc in ext_locs:
                    u = loc.origin_url.rstrip("/")
                    if u not in origins:
                        origins.append(u)
                return origins

            def _domain_sts_origins(target_td: str) -> List[str]:
                td_clean = (target_td or identity.trust_domain).strip().lower()
                d_obj = desc_store.get_descriptor(td_clean) if desc_store is not None else None
                ext_locs = list(d_obj.locators.get("oauth_sts", ())) if d_obj is not None else []
                origins: List[str] = []
                if td_clean == identity.trust_domain and local_sts_url_sc:
                    if ext_locs:
                        origins.append(f"{local_sts_url_sc}#host={ext_locs[0].host}:{ext_locs[0].port}")
                    else:
                        origins.append(local_sts_url_sc)
                for loc in ext_locs:
                    u = loc.origin_url.rstrip("/")
                    if u not in origins:
                        origins.append(u)
                return origins

            central_origins_fn = _central_sts_origins
            domain_origins_fn = _domain_sts_origins
            own_short = identity.trust_domain.strip().lower().removeprefix("org-").split(".", 1)[0]

            oauth_central_ver = OIDCTokenVerifier(
                jwks_urls_provider=lambda: [
                    f"{o.split('#host=', 1)[0]}/realms/{oauth_realm_sc}/protocol/openid-connect/certs"
                    for o in _central_sts_origins()
                ],
                allowed_issuers_provider=lambda: [
                    f"http://alpha-oidc.lct.local/realms/{oauth_realm_sc}",
                    f"http://alpha-sts.lineage-alpha.svc.cluster.local:8095/realms/{oauth_realm_sc}",
                    *[
                        f"http://{o.split('#host=', 1)[1]}/realms/{oauth_realm_sc}"
                        if "#host=" in o
                        else f"{o}/realms/{oauth_realm_sc}"
                        for o in _central_sts_origins()
                    ],
                ],
                default_user_domain="org-alpha.io",
                single_entity_issuers=True,
            )

            def _federated_sts_jwks_urls() -> List[str]:
                urls: List[str] = [
                    f"{o.split('#host=', 1)[0]}/realms/{oauth_realm_sc}/protocol/openid-connect/certs"
                    for o in _domain_sts_origins(identity.trust_domain)
                ]
                if desc_store is not None:
                    for td_k, d_obj in desc_store.all_descriptors().items():
                        for loc in d_obj.locators.get("oauth_sts", ()):
                            u = f"{loc.origin_url.rstrip('/')}/realms/{oauth_realm_sc}/protocol/openid-connect/certs"
                            if u not in urls:
                                urls.append(u)
                return urls

            def _federated_allowed_issuers() -> List[str]:
                iss_out: List[str] = [
                    f"http://{own_short}-oidc.lct.local/realms/{oauth_realm_sc}",
                    *[
                        f"http://{o.split('#host=', 1)[1]}/realms/{oauth_realm_sc}"
                        if "#host=" in o
                        else f"{o}/realms/{oauth_realm_sc}"
                        for o in _domain_sts_origins(identity.trust_domain)
                    ],
                ]
                if desc_store is not None:
                    for td_k, d_obj in desc_store.all_descriptors().items():
                        td_short = td_k.strip().lower().removeprefix("org-").split(".", 1)[0]
                        iss_out.append(f"http://{td_short}-oidc.lct.local/realms/{oauth_realm_sc}")
                        for loc in d_obj.locators.get("oauth_sts", ()):
                            iss_out.append(f"{loc.origin_url.rstrip('/')}/realms/{oauth_realm_sc}")
                return list(dict.fromkeys(iss_out))

            def _federated_issuer_aliases() -> Dict[str, List[str]]:
                alias_map: Dict[str, List[str]] = {}
                own_canon = f"http://{own_short}-oidc.lct.local/realms/{oauth_realm_sc}"
                alias_map[own_canon] = [
                    f"{o.split('#host=', 1)[0]}/realms/{oauth_realm_sc}"
                    for o in _domain_sts_origins(identity.trust_domain)
                ]
                if desc_store is not None:
                    for td_k, d_obj in desc_store.all_descriptors().items():
                        td_short = td_k.strip().lower().removeprefix("org-").split(".", 1)[0]
                        canon_iss = f"http://{td_short}-oidc.lct.local/realms/{oauth_realm_sc}"
                        lst = alias_map.setdefault(canon_iss, [])
                        for loc in d_obj.locators.get("oauth_sts", ()):
                            src_i = f"{loc.origin_url.rstrip('/')}/realms/{oauth_realm_sc}"
                            if src_i not in lst:
                                lst.append(src_i)
                return alias_map

            oauth_local_ver = OIDCTokenVerifier(
                jwks_urls_provider=_federated_sts_jwks_urls,
                allowed_issuers_provider=_federated_allowed_issuers,
                issuer_aliases_provider=_federated_issuer_aliases,
                default_user_domain=identity.trust_domain,
                single_entity_issuers=False,
            )
            oauth_ex_cli = OAuthTokenExchangeClient(
                realm=oauth_realm_sc,
                client_secrets=sc_client_secrets,
            )

        raw_scanner_spiffes_sc = [
            s.strip()
            for s in os.environ.get("ALLOWED_SCANNER_SPIFFE_IDS", "").split(",")
            if s.strip()
        ]
        sidecar = LineageSidecar(
            identity=identity,
            trust_resolver=resolver,
            app_upstream_url=f"http://127.0.0.1:{app_port}",
            loopback_secret=loopback_secret,
            mode=v_mode,
            revocation_replica=rev_replica,
            directory_client=dir_client,
            audit_emitter=audit_emitter,
            agent_card=registered_card,
            is_tool_server=is_tool,
            inbound_host="0.0.0.0",
            inbound_port=inbound_port,
            outbound_port=outbound_port,
            public_origin=init_primary_origin,
            mtls_bundle=mtls_bundle,
            readiness_check=_sidecar_readiness,
            delegation_mode=delegation_mode_env,
            oauth_central_verifier=oauth_central_ver,
            oauth_local_verifier=oauth_local_ver,
            oauth_exchange_client=oauth_ex_cli,
            oauth_central_sts_origins_provider=central_origins_fn,
            oauth_domain_sts_origins_provider=domain_origins_fn,
            resource_owner_sub=res_owner_sub_sc,
            owner_protected_tools=owner_prot_tools_sc or None,
            allowed_co_auth_tools=allowed_coauth_tools_sc or None,
            allowed_scanner_spiffe_ids=(raw_scanner_spiffes_sc if raw_scanner_spiffes_sc else None),
            local_ca_url=local_ca_url or None,
            sa_token_path=resolve_sa_token_path(),
        )
        sidecar.set_public_origins(init_primary_origin, init_extra_origins)
        if registered_card is not None:
            sidecar.set_agent_card(registered_card)

        if loc_watcher is not None:
            def _on_node_locator_changed(new_snap: Any) -> None:
                if new_snap is None or stop_event.is_set():
                    return
                new_locs = new_snap.build_service_locators(
                    loc_slot,
                    transport=loc_transport,
                    spiffe_id=identity.spiffe_id,
                )
                if not new_locs:
                    return
                with card_lock:
                    prev_dicts = [loc.to_dict() for loc in card_state["locators"]]
                    next_dicts = [loc.to_dict() for loc in new_locs]
                    if prev_dicts == next_dicts:
                        return
                    card_state["locators"] = new_locs
                sidecar.set_public_origins(
                    new_locs[0].origin_url,
                    [loc.origin_url for loc in new_locs[1:]],
                )
                if should_register_card:
                    try:
                        updated = _mint_and_register_card(sidecar_ref=sidecar)
                        if updated is not None:
                            print(
                                f"[lct-sidecar:locator] Re-signed AgentCard {identity.spiffe_id} v{updated.version} -> {[loc.origin_url for loc in new_locs]}",
                                flush=True,
                            )
                    except Exception as exc:
                        print(
                            f"[lct-sidecar:locator-warn] Deferred AgentCard update on IP change: {exc}",
                            flush=True,
                        )

            loc_watcher.add_callback(_on_node_locator_changed)
            loc_watcher.start()

        if syncer is not None and syncer.identity_renewer is not None:
            def _on_svid_renewed(
                _id: WorkloadIdentity, _mb: Optional[Any]
            ) -> None:
                sidecar.on_identity_renewed()
                if should_register_card:
                    try:
                        refreshed = _mint_and_register_card(sidecar_ref=sidecar)
                        if refreshed is not None:
                            print(
                                f"[lct-sidecar:renew] Refreshed SVID & AgentCard gen={identity.renewal_generation} ver={refreshed.version}",
                                flush=True,
                            )
                    except Exception as exc:
                        print(
                            f"[lct-sidecar:renew-warn] AgentCard re-registration deferred: {exc}",
                            flush=True,
                        )
                else:
                    print(
                        f"[lct-sidecar:renew] Refreshed tool SVID gen={identity.renewal_generation}",
                        flush=True,
                    )

            syncer.identity_renewer.add_callback(_on_svid_renewed)

        sidecar.start()

        card_keeper_stop = threading.Event()
        card_keeper_thread: Optional[threading.Thread] = None
        if should_register_card:
            def _card_keeper_loop() -> None:
                from lineage.registry.agent_card import AgentCardError

                while not card_keeper_stop.is_set() and not stop_event.is_set():
                    card_keeper_stop.wait(3.0)
                    if card_keeper_stop.is_set() or stop_event.is_set():
                        break
                    try:
                        try:
                            existing = dir_client.get_agent(identity.spiffe_id)
                        except AgentCardError:
                            existing = None
                        cur_loc_dicts = [loc.to_dict() for loc in card_state["locators"]]
                        existing_loc_dicts = (
                            [loc.to_dict() for loc in existing.locators]
                            if existing is not None
                            else []
                        )
                        if (
                            existing is None
                            or existing.jkt != identity.jkt
                            or existing.workload_svid != identity.workload_svid
                            or existing.expires_at <= (time.time() + 25.0)
                            or (cur_loc_dicts and existing_loc_dicts != cur_loc_dicts)
                        ):
                            _mint_and_register_card(sidecar_ref=sidecar)
                    except Exception:
                        pass

            card_keeper_thread = threading.Thread(
                target=_card_keeper_loop, name="sidecar-card-keeper", daemon=True
            )
            card_keeper_thread.start()

        proto_tag = "mTLS-1.3" if mtls_bundle is not None else "HTTP"
        if registered_card is not None:
            print(
                f"[lct-sidecar:{proto_tag}] Registered signed AgentCard {identity.spiffe_id} -> {registered_card.endpoint} skills={list(registered_card.skills)} prio={registered_card.priority} ver={registered_card.version}",
                flush=True,
            )
        else:
            print(
                f"[lct-sidecar:{proto_tag}] Sidecar active for {identity.spiffe_id} -> {init_primary_origin} mode={v_mode.value}",
                flush=True,
            )

        try:
            stop_event.wait()
        finally:
            if loc_watcher is not None:
                loc_watcher.stop()
            card_keeper_stop.set()
            if card_keeper_thread is not None:
                card_keeper_thread.join(timeout=1.5)
            audit_emitter.stop()
            rev_replica.stop_background_sync()
            if syncer is not None:
                syncer.stop_background_refresh()
            sidecar.stop()
            if mtls_bundle is not None:
                mtls_bundle.cleanup()
        return

    if role == "user-gateway":
        from lineage.federation import DomainUserGatewayService, bootstrap_autonomous_workload
        from lineage.oauth_sts import OIDCTokenVerifier

        local_ca_url = os.environ["LOCAL_CA_URL"]
        sa_tok_path = os.environ.get("K8S_SA_TOKEN_PATH", "/var/run/lct-sa/token")
        seed_store = _build_env_seed_store()
        desc_store = _build_env_descriptor_store(anchor_store, require_pins)
        identity, resolver, mtls_bundle, syncer = bootstrap_autonomous_workload(
            local_ca_url,
            {},
            require_all_peers=False,
            svid_ttl_seconds=svid_ttl,
            anchor_store=anchor_store,
            require_pinned_anchors=require_pins,
            enable_auto_renewal=True,
            seed_store=seed_store,
            descriptor_store=desc_store,
            persisted_descriptors_file=persisted_desc_file,
        )
        trust_domain_gw = identity.trust_domain
        oidc_jwks_gw = os.environ.get("OIDC_JWKS_URL", "").strip()
        local_sts_gw = os.environ.get("LOCAL_STS_URL", "").strip().rstrip("/")
        oauth_realm_gw = os.environ.get("OAUTH_REALM", "lct").strip() or "lct"

        def _gw_jwks_urls() -> List[str]:
            out: List[str] = [oidc_jwks_gw] if oidc_jwks_gw else []
            if desc_store is not None:
                d_obj = desc_store.get_descriptor(trust_domain_gw)
                if d_obj is not None:
                    for loc in d_obj.locators.get("oauth_sts", ()):
                        u = f"{loc.origin_url.rstrip('/')}/realms/{oauth_realm_gw}/protocol/openid-connect/certs"
                        if u not in out:
                            out.append(u)
            return out

        def _gw_allowed_issuers() -> List[str]:
            dom_s = trust_domain_gw.strip().lower().removeprefix("org-").split(".", 1)[0]
            iss_l: List[str] = [
                f"http://{dom_s}-oidc.lct.local/realms/{oauth_realm_gw}",
            ]
            if local_sts_gw:
                iss_l.append(f"{local_sts_gw}/realms/{oauth_realm_gw}")
            if desc_store is not None:
                d_obj = desc_store.get_descriptor(trust_domain_gw)
                if d_obj is not None:
                    for loc in d_obj.locators.get("oauth_sts", ()):
                        iss_l.append(f"{loc.origin_url.rstrip('/')}/realms/{oauth_realm_gw}")
            return iss_l

        gw_oidc_verifier = OIDCTokenVerifier(
            jwks_urls=([oidc_jwks_gw] if oidc_jwks_gw else ()),
            jwks_urls_provider=_gw_jwks_urls,
            allowed_issuers_provider=_gw_allowed_issuers,
            default_user_domain=trust_domain_gw,
            allowed_user_domains=(trust_domain_gw,),
            single_entity_issuers=True,
        )
        raw_callers = [
            s.strip()
            for s in os.environ.get("AUTHORIZED_CALLER_SPIFFE_IDS", "").split(",")
            if s.strip()
        ]

        def _fresh_sa_jwt_gw() -> str:
            with open(sa_tok_path, "r", encoding="utf-8") as fh:
                return fh.read().strip()

        ugw_svc = DomainUserGatewayService(
            identity=identity,
            local_ca_url=local_ca_url,
            sa_jwt_provider=_fresh_sa_jwt_gw,
            oidc_verifier=gw_oidc_verifier,
            mtls_bundle=mtls_bundle,
            authorized_caller_spiffe_ids=(raw_callers or None),
            readiness_check=syncer.is_ready if syncer is not None else None,
            inbound_host="0.0.0.0",
            inbound_port=int(os.environ.get("SIDECAR_INBOUND_PORT", "8443")),
            health_host="127.0.0.1",
            health_port=int(os.environ.get("SIDECAR_OUTBOUND_PORT", "8081")),
        )
        try:
            ugw_svc.start()
            print(
                f"[user-gateway:{trust_domain_gw}] mTLS + OIDC entry gateway active on 0.0.0.0:8443 spiffe={identity.spiffe_id}",
                flush=True,
            )
            stop_event.wait()
        finally:
            ugw_svc.stop()
            if syncer is not None:
                syncer.stop_background_refresh()
            if mtls_bundle is not None:
                mtls_bundle.cleanup()
        return

    # Co-located `app` containers (strictly bound to `127.0.0.1:9001`, zero private keys!)
    loopback_secret = _read_shared_loopback_secret()
    app_port = int(os.environ.get("APP_PORT", "9001"))
    sidecar_out_url = f"http://127.0.0.1:{int(os.environ.get('SIDECAR_OUTBOUND_PORT', '8081'))}"

    app_obj: Any
    if role == "app-orchestrator":
        app_obj = OrchestratorAlphaApp(loopback_secret, sidecar_out_url, port=app_port)
    elif role == "app-flight":
        app_obj = FlightSpecialistApp(
            loopback_secret, sidecar_out_url, travel_mcp_url, port=app_port
        )
    elif role == "app-hotel":
        app_obj = HotelSpecialistApp(
            loopback_secret,
            sidecar_out_url,
            travel_mcp_url,
            instance_label=os.environ.get("SPECIALIST_INSTANCE", "primary"),
            port=app_port,
        )
    elif role == "app-converger":
        app_obj = SettlementConvergerApp(
            loopback_secret, sidecar_out_url, payment_mcp_url, port=app_port
        )
    elif role == "app-travel-mcp":
        app_obj = TravelOpsMCPApp(loopback_secret, port=app_port)
    elif role == "app-payment-mcp":
        app_obj = PaymentVaultMCPApp(loopback_secret, port=app_port)
    elif role == "app-peer-assistant":
        from lineage.agents import OllamaClient

        use_llm_peer = os.environ.get("ENABLE_PEER_LLM", "true").strip().lower() != "false"
        app_obj = WorkspaceAssistantPeerApp(
            peer_name=os.environ.get("PEER_NAME", "alice"),
            owner_sub=os.environ.get("PEER_OWNER_SUB", "user:alice@org-alpha.io"),
            outbound_proxy_url=sidecar_out_url,
            loopback_secret=loopback_secret,
            ollama=(OllamaClient() if use_llm_peer else None),
            instance_label=os.environ.get("SPECIALIST_INSTANCE", "primary"),
            vault_mcp_target=os.environ.get("VAULT_MCP_TARGET", "skill://mcp.workspace-vault"),
            port=app_port,
        )
    elif role == "app-workspace-vault":
        from lineage.agents import OllamaClient

        use_llm_vault = os.environ.get("ENABLE_PEER_LLM", "true").strip().lower() != "false"
        app_obj = WorkspaceVaultMCPApp(
            loopback_secret=loopback_secret,
            outbound_proxy_url=sidecar_out_url,
            ollama=(OllamaClient() if use_llm_vault else None),
            vault_mcp_target=os.environ.get("VAULT_MCP_TARGET", "skill://mcp.workspace-vault"),
            port=app_port,
        )
    else:
        print(f"Unknown role: {role!r}", file=sys.stderr)
        sys.exit(2)

    url = app_obj.start()
    print(f"[{role}] Loopback-isolated business container listening strictly on {url}", flush=True)
    stop_event.wait()
    app_obj.stop()


if __name__ == "__main__":
    main()
