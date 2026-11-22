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


def main() -> None:
    parser = argparse.ArgumentParser(description="LCT Milestone 4 Kubernetes Role Runner")
    parser.add_argument("--role", required=True)
    args = parser.parse_args()

    role = args.role
    ca_url = os.environ.get(
        "FEDERATION_CA_URL", "http://federation-ca.lineage-ctrl.svc.cluster.local:8090"
    )
    dir_url = os.environ.get(
        "DIRECTORY_URL", "http://directory-svc.lineage-ctrl.svc.cluster.local:8091"
    )
    rev_url = os.environ.get(
        "REVOCATION_URL", "http://revocation-svc.lineage-ctrl.svc.cluster.local:8092"
    )
    audit_url = os.environ.get(
        "AUDIT_COLLECTOR_URL", "http://audit-collector.lineage-ctrl.svc.cluster.local:8093"
    )
    travel_mcp_url = os.environ.get(
        "TRAVEL_MCP_URL", "https://travel-ops-mcp.lineage-pay.svc.cluster.local:8443/mcp"
    )
    payment_mcp_url = os.environ.get(
        "PAYMENT_MCP_URL", "https://payment-vault-mcp.lineage-pay.svc.cluster.local:8443/mcp"
    )

    stop_event = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())

    if role == "domain-ca":
        from lineage.federation import AutonomousDomainCAService

        trust_domain = os.environ["TRUST_DOMAIN"]
        allowed_ns = os.environ["ALLOWED_K8S_NAMESPACE"]
        auth_gw_sa = os.environ.get("AUTHORIZED_GATEWAY_SA", "").strip() or None
        fed_port_raw = os.environ.get("CA_FEDERATION_PORT", "").strip()
        fed_port = int(fed_port_raw) if fed_port_raw else None
        svc = AutonomousDomainCAService(
            trust_domain=trust_domain,
            allowed_k8s_namespace=allowed_ns,
            audit_collector_url=audit_url,
            authorized_gateway_sa=auth_gw_sa,
            host="0.0.0.0",
            port=8090,
            federation_port=fed_port,
        )
        svc.start()
        print(
            f"[domain-ca:{trust_domain}] Autonomous CA ready on 0.0.0.0:8090 (fed_port={fed_port}, allowed_ns={allowed_ns})",
            flush=True,
        )
        stop_event.wait()
        svc.stop()
        return

    if role == "federated-audit-collector":
        from lineage.federation import FederationBundleSyncer, parse_domain_url_map

        peer_ca_map = parse_domain_url_map(os.environ["PEER_CA_URLS"])
        syncer = FederationBundleSyncer(peer_ca_urls=peer_ca_map)
        syncer.sync_all(require_all=True, max_wait_sec=60.0)
        syncer.start_background_refresh(interval_sec=10.0)
        svc = AuditCollectorService(
            trust_resolver=syncer.trust_resolver, host="0.0.0.0", port=8093
        )
        svc.start()
        print(
            f"[federated-audit-collector] Keyless verifier ready on 0.0.0.0:8093 (domains={sorted(peer_ca_map.keys())})",
            flush=True,
        )
        stop_event.wait()
        syncer.stop_background_refresh()
        svc.stop()
        return

    if role == "domain-revocation":
        from lineage.federation import bootstrap_autonomous_workload, parse_domain_url_map

        local_ca_url = os.environ["LOCAL_CA_URL"]
        peer_ca_map = parse_domain_url_map(os.environ["PEER_CA_URLS"])
        peer_rev_map = parse_domain_url_map(os.environ.get("PEER_REVOCATION_URLS", ""))
        rev_fed_raw = os.environ.get("REVOCATION_FEDERATION_PORT", "").strip()
        rev_fed_port = int(rev_fed_raw) if rev_fed_raw else None
        identity, resolver, mtls_bundle, syncer = bootstrap_autonomous_workload(
            local_ca_url, peer_ca_map
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
        )
        try:
            svc.start()
            print(
                f"[domain-revocation:{identity.trust_domain}] Ready as {identity.spiffe_id} on :8092 (mTLS fed_port={rev_fed_port})",
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
        peer_ca_map = parse_domain_url_map(os.environ["PEER_CA_URLS"])
        peer_dir_map = parse_domain_url_map(os.environ.get("PEER_DIRECTORY_URLS", ""))
        dir_fed_raw = os.environ.get("DIRECTORY_FEDERATION_PORT", "").strip()
        dir_fed_port = int(dir_fed_raw) if dir_fed_raw else None
        identity, resolver, mtls_bundle, syncer = bootstrap_autonomous_workload(
            local_ca_url, peer_ca_map
        )
        _wait_for_http_ok(f"{rev_url}/healthz")
        rev_replica = RevocationReplicaClient(rev_url, resolver)
        rev_replica.start_background_sync(wait_ms=800)
        svc = AgentDirectoryService(
            resolver,
            revocation_replica=rev_replica,
            local_trust_domain=identity.trust_domain,
            peer_directory_urls=peer_dir_map,
            host="0.0.0.0",
            port=8091,
            federation_port=dir_fed_port,
            mtls_bundle=mtls_bundle,
        )
        try:
            svc.start()
            print(
                f"[domain-directory:{identity.trust_domain}] Ready as {identity.spiffe_id} on :8091 (mTLS fed_port={dir_fed_port})",
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
        mtls_bundle = None
        syncer = None
        if local_ca_url and peer_ca_spec:
            from lineage.federation import (
                bootstrap_autonomous_workload,
                parse_domain_url_map,
            )

            identity, resolver, mtls_bundle, syncer = bootstrap_autonomous_workload(
                local_ca_url, parse_domain_url_map(peer_ca_spec)
            )
            default_in_port = "8443"
        else:
            identity, resolver = bootstrap_k8s_workload_identity(ca_url)
            default_in_port = "8080"

        _wait_for_http_ok(f"{rev_url}/healthz")
        _wait_for_http_ok(f"{audit_url}/healthz")
        app_port = int(os.environ.get("APP_PORT", "9001"))
        inbound_port = int(os.environ.get("SIDECAR_INBOUND_PORT", default_in_port))
        outbound_port = int(os.environ.get("SIDECAR_OUTBOUND_PORT", "8081"))
        public_origin = os.environ["PUBLIC_ORIGIN"]
        is_tool = os.environ.get("IS_TOOL_SERVER", "false").lower() == "true"
        v_mode = VerificationMode(
            os.environ.get("VERIFICATION_MODE", VerificationMode.ADAPTIVE_RISK_ANCHORED.value)
        )

        _wait_for_http_ok(f"http://127.0.0.1:{app_port}/healthz")

        rev_replica = RevocationReplicaClient(rev_url, resolver)
        rev_replica.start_background_sync(wait_ms=800)
        dir_client = AgentDirectoryClient(dir_url, resolver)
        pod_stream_id = f"{identity.spiffe_id}#{socket.gethostname()}"
        audit_emitter = AuditStreamEmitter(
            signer=identity,
            collector_client=AuditCollectorClient(audit_url),
            stream_id=pod_stream_id,
        )

        registered_card: Optional[AgentCard] = None
        if not is_tool:
            _wait_for_http_ok(f"{dir_url}/healthz")
            skills = [
                s.strip()
                for s in os.environ.get("AGENT_SKILLS", "agent.generic").split(",")
                if s.strip()
            ]
            priority = int(os.environ.get("AGENT_PRIORITY", "50"))
            agent_name = os.environ.get("AGENT_DISPLAY_NAME", identity.spiffe_id)
            for attempt in range(8):
                card = AgentCard.sign_and_create(
                    identity=identity,
                    name=agent_name,
                    endpoint=public_origin,
                    return_endpoint=public_origin,
                    skills=skills,
                    priority=priority,
                    version=int(time.time() * 1000) + attempt,
                )
                try:
                    dir_client.register(card)
                    registered_card = card
                    break
                except Exception:
                    if attempt == 7:
                        raise
                    time.sleep(0.5)

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
            public_origin=public_origin,
            mtls_bundle=mtls_bundle,
        )
        sidecar.start()

        proto_tag = "mTLS-1.3" if mtls_bundle is not None else "HTTP"
        if registered_card is not None:
            print(
                f"[lct-sidecar:{proto_tag}] Registered A2A v1.0 AgentCard {identity.spiffe_id} -> {public_origin} skills={list(registered_card.skills)} prio={registered_card.priority}",
                flush=True,
            )
        else:
            print(
                f"[lct-sidecar:{proto_tag}] Tool sidecar active for {identity.spiffe_id} -> {public_origin} mode={v_mode.value}",
                flush=True,
            )

        try:
            stop_event.wait()
        finally:
            rev_replica.stop_background_sync()
            if syncer is not None:
                syncer.stop_background_refresh()
            sidecar.stop()
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
    else:
        print(f"Unknown role: {role!r}", file=sys.stderr)
        sys.exit(2)

    url = app_obj.start()
    print(f"[{role}] Loopback-isolated business container listening strictly on {url}", flush=True)
    stop_event.wait()
    app_obj.stop()


if __name__ == "__main__":
    main()
