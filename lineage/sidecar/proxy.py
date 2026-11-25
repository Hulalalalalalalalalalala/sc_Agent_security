"""Real HTTP Inbound & Outbound `LineageSidecar` Proxy + Agent/MCP Node Wrappers.

Architecture per node:
- `inbound_http` (`127.0.0.1:<inbound_port>`): Public A2A / MCP ingress enforcing
  strict `Host` authority validation, authoritative `htu` DPoP binding, full LCT chain
  verification, endpoint-specific recipient/child role checks, monotonic risk-anchored
  revocation, active liveness probing on skip-level returns, and signed audit logging.
- `outbound_http` (`127.0.0.1:<outbound_port>`): Localhost-only egress proxy accepting
  constant-time authenticated loopback requests (`X-LCT-Loopback-Auth` + `X-LCT-Request-Id`).
- `app_http` (`127.0.0.1:<app_port>`): Business logic server rejecting any request
  failing constant-time `X-LCT-Loopback-Auth` verification.
"""

from __future__ import annotations

import hmac
import math
import os
import secrets
import socket
import ssl
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import unquote, urlsplit

import httpx

from lineage.audit.logger import (
    AuditCollectorClient,
    AuditEventType,
    AuditStreamEmitter,
)
from lineage.common.crypto import (
    compute_jwk_thumbprint,
    redact_sensitive,
    sha256_canonical_b64url,
    strict_json_loads,
)
from lineage.common.http_utils import (
    HTTPRequestContext,
    ManagedHTTPService,
    SSEResponse,
    validate_origin_form_target,
)
from lineage.common.mtls import WorkloadMTLSBundle
from lineage.identity.spiffe import SpiffeId, WorkloadIdentity
from lineage.identity.trust_bundle import TrustBundleResolver
from lineage.protocol.dpop import JTIReplayCache, create_dpop_proof
from lineage.protocol.lattice import PermissionLattice
from lineage.protocol.token import (
    CoAuthorizedToken,
    LineageToken,
    MultiParentToken,
    TaskCheckpoint,
    TokenError,
    TokenExpiredError,
    compute_branch_idempotency_key,
    decode_token,
    validate_clean_endpoint_url,
    verify_root_block_signature_ignoring_expiry,
)
from lineage.registry.agent_card import AgentCard
from lineage.registry.directory import AgentDirectoryClient
from lineage.resilience.coordinator import (
    ResilientDelegationCoordinator,
    verify_and_accept_skip_level_request,
)
from lineage.resilience.detector import ThreeLayerFaultDetector
from lineage.resilience.receipts import ResilienceError
from lineage.revocation.service import RevocationReplicaClient
from lineage.sidecar.context import (
    ActiveRequestStore,
    MultiParentConvergenceInbox,
    OAuthActiveRequestStore,
    OAuthConvergenceInbox,
    OAuthRequestContext,
    lineage_context_scope,
)
from lineage.verifier.policy_verifier import (
    LeafVerifier,
    RiskClassifier,
    VerificationMode,
)


def _extract_dpop_token(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header or not isinstance(auth_header, str):
        return None
    parts = auth_header.strip().split(None, 1)
    if len(parts) != 2:
        return None
    scheme, token = parts[0], parts[1].strip()
    if scheme.upper() != "DPOP":
        return None
    return token if token else None


def _extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header or not isinstance(auth_header, str):
        return None
    parts = auth_header.strip().split(None, 1)
    if len(parts) != 2:
        return None
    scheme, token = parts[0], parts[1].strip()
    if scheme.upper() != "BEARER":
        return None
    return token if token else None


def _constant_time_secret_match(provided: Optional[str], expected: str) -> bool:
    if not provided or not isinstance(provided, str):
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def _require_finite_timeout(
    raw_val: Any, default_val: float, min_val: float = 0.05, max_val: float = 120.0
) -> float:
    if raw_val is None:
        return default_val
    if isinstance(raw_val, bool) or not isinstance(raw_val, (int, float)):
        raise ValueError(f"invalid_timeout: expected finite number, got {raw_val!r}")
    val = float(raw_val)
    if not math.isfinite(val) or val < min_val or val > max_val:
        raise ValueError(
            f"invalid_timeout: {val!r} outside allowed range [{min_val}, {max_val}]"
        )
    return val


def _validate_outbound_target_url(
    raw_url: Any, expected_origin: Optional[str] = None
) -> str:
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("invalid_target_url: target_url must be a non-empty string")
    candidate = raw_url.strip()
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in candidate):
        raise ValueError("invalid_target_url: control/whitespace characters forbidden")
    sp = urlsplit(candidate)
    if (
        sp.scheme not in ("http", "https")
        or not sp.netloc
        or not sp.hostname
        or "@" in sp.netloc
        or sp.username is not None
        or sp.password is not None
        or sp.fragment
    ):
        raise ValueError(f"invalid_target_url: malformed or unsafe URL {candidate!r}")
    origin_form = (sp.path or "/") + (f"?{sp.query}" if sp.query else "")
    validate_origin_form_target(origin_form)
    hx = httpx.URL(candidate)
    if (
        bool(hx.username)
        or bool(hx.password)
        or hx.raw_path.startswith(b"//")
        or (hx.scheme, hx.host, hx.port) != (sp.scheme.lower(), sp.hostname.lower(), sp.port)
    ):
        raise ValueError(f"invalid_target_url: authority mismatch in {candidate!r}")
    if expected_origin is not None:
        eb = urlsplit(expected_origin)
        if (sp.scheme.lower(), sp.hostname.lower(), sp.port) != (
            eb.scheme.lower(),
            (eb.hostname or "").lower(),
            eb.port,
        ):
            raise ValueError(
                f"invalid_target_url: origin smuggling blocked ({candidate!r} != {expected_origin!r})"
            )
    return candidate


class _BoundedTaskListStore:
    """Thread-safe bounded TTL/LRU store mapping `task_id -> List[(sub, Dict)]`."""

    def __init__(self, ttl_seconds: float = 1800.0, max_tasks: int = 10_000) -> None:
        self.ttl_seconds = float(ttl_seconds)
        self.max_tasks = int(max_tasks)
        self._lock = threading.Lock()
        self._data: "OrderedDict[str, Tuple[List[Tuple[str, Dict[str, Any]]], float]]" = (
            OrderedDict()
        )

    def _evict_locked(self, now_ts: float) -> None:
        while self._data:
            _, (_, exp_at) = next(iter(self._data.items()))
            if exp_at <= now_ts:
                self._data.popitem(last=False)
            else:
                break

    def append(self, task_id: str, item: Dict[str, Any], sub: str = "") -> None:
        now_ts = time.time()
        with self._lock:
            self._evict_locked(now_ts)
            if task_id in self._data:
                items, _ = self._data.pop(task_id)
            else:
                if len(self._data) >= self.max_tasks:
                    self._data.popitem(last=False)
                items = []
            items.append((str(sub), item))
            self._data[task_id] = (items, now_ts + self.ttl_seconds)

    def get(
        self, task_id: str, expected_sub: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        now_ts = time.time()
        with self._lock:
            self._evict_locked(now_ts)
            entry = self._data.get(task_id)
            if entry is None:
                return []
            if expected_sub is None:
                return [dict(it) for _, it in entry[0]]
            return [dict(it) for item_sub, it in entry[0] if item_sub == expected_sub]


def _resolve_target_peer_ip(target_url: str) -> Optional[str]:
    """Resolve target URL hostname via OS/CoreDNS resolver for cross-host audit telemetry."""
    try:
        sp = urlsplit(target_url)
        host = sp.hostname
        if not host:
            return None
        infos = socket.getaddrinfo(host, sp.port or (443 if sp.scheme == "https" else 80), socket.AF_INET)
        if infos:
            return str(infos[0][4][0])
    except Exception:
        pass
    return None


class LineageSidecar:
    """Dual-listener HTTP Sidecar enforcing LCT governance on inbound & outbound traffic."""

    def __init__(
        self,
        identity: WorkloadIdentity,
        trust_resolver: TrustBundleResolver,
        app_upstream_url: str,
        loopback_secret: str,
        mode: VerificationMode = VerificationMode.ADAPTIVE_RISK_ANCHORED,
        revocation_replica: Optional[RevocationReplicaClient] = None,
        directory_client: Optional[AgentDirectoryClient] = None,
        audit_emitter: Optional[AuditStreamEmitter] = None,
        risk_classifier: Optional[RiskClassifier] = None,
        agent_card: Optional[AgentCard] = None,
        is_tool_server: bool = False,
        fail_closed_on_high_risk: bool = True,
        inbound_host: str = "127.0.0.1",
        inbound_port: int = 0,
        outbound_port: int = 0,
        public_origin: Optional[str] = None,
        allowed_hosts: Iterable[str] = (),
        upstream_timeout: float = 90.0,
        mtls_bundle: Optional[WorkloadMTLSBundle] = None,
        readiness_check: Optional[Callable[[], Tuple[bool, Dict[str, Any]]]] = None,
        delegation_mode: str = "lct",
        oauth_central_verifier: Optional[Any] = None,
        oauth_local_verifier: Optional[Any] = None,
        oauth_exchange_client: Optional[Any] = None,
        oauth_central_sts_origins_provider: Optional[Callable[[], Sequence[str]]] = None,
        oauth_domain_sts_origins_provider: Optional[Callable[[str], Sequence[str]]] = None,
        resource_owner_sub: Optional[str] = None,
        owner_protected_tools: Optional[Iterable[str]] = None,
        allowed_co_auth_tools: Optional[Iterable[str]] = None,
        authorized_auditors: Iterable[str] = (),
        local_ca_url: Optional[str] = None,
        sa_token_path: Optional[str] = None,
    ) -> None:
        norm_dm = (delegation_mode or "lct").strip().lower()
        if norm_dm not in ("lct", "dual", "oauth_centralized", "oauth_federated"):
            raise ValueError(f"Unsupported delegation_mode {delegation_mode!r}")
        self.delegation_mode = norm_dm
        self.oauth_central_verifier = oauth_central_verifier
        self.oauth_local_verifier = oauth_local_verifier
        self.oauth_exchange_client = oauth_exchange_client
        self._oauth_central_sts_origins_provider = oauth_central_sts_origins_provider
        self._oauth_domain_sts_origins_provider = oauth_domain_sts_origins_provider
        self.resource_owner_sub = (
            str(resource_owner_sub).strip() if resource_owner_sub and str(resource_owner_sub).strip() else None
        )
        self._owner_protected_tools: Optional[frozenset[str]] = (
            frozenset(str(t).strip() for t in owner_protected_tools if str(t).strip())
            if owner_protected_tools is not None
            else None
        )
        self._allowed_co_auth_tools: Optional[frozenset[str]] = (
            frozenset(str(t).strip() for t in allowed_co_auth_tools if str(t).strip())
            if allowed_co_auth_tools is not None
            else None
        )
        self._local_ca_url = (local_ca_url or "").strip().rstrip("/") or None
        self._sa_token_path = (sa_token_path or "").strip() or None
        self.identity = identity
        self.trust_resolver = trust_resolver
        self.app_upstream_url = app_upstream_url.rstrip("/")
        self.loopback_secret = loopback_secret
        self.revocation_replica = revocation_replica
        self.directory_client = directory_client
        self.audit_emitter: AuditStreamEmitter = (
            audit_emitter
            if audit_emitter is not None
            else AuditStreamEmitter(
                signer=identity,
                stream_id=identity.spiffe_id,
                authorized_auditors=authorized_auditors,
            )
        )
        self.agent_card = agent_card
        self.is_tool_server = is_tool_server
        self.upstream_timeout = float(upstream_timeout)
        self._mtls_bundle = mtls_bundle
        self._readiness_check = readiness_check
        self._server_ssl_ctx: Optional[ssl.SSLContext] = (
            mtls_bundle.build_server_ssl_context(require_client_cert=True)
            if mtls_bundle is not None
            else None
        )
        self._client_ssl_ctx: Optional[ssl.SSLContext] = (
            mtls_bundle.build_client_ssl_context(check_hostname=True)
            if mtls_bundle is not None
            else None
        )
        self.public_origin = (
            validate_clean_endpoint_url(public_origin, "public_origin")
            if public_origin is not None
            else None
        )

        self.verifier = LeafVerifier(
            self_spiffe_id=identity.spiffe_id,
            self_jkt=identity.jkt,
            trust_resolver=trust_resolver,
            mode=mode,
            revocation_replica=revocation_replica,
            risk_classifier=risk_classifier,
            fail_closed_on_high_risk=fail_closed_on_high_risk,
        )
        self.active_requests = ActiveRequestStore()
        self.convergence_inbox = MultiParentConvergenceInbox()
        self.oauth_active_requests = OAuthActiveRequestStore()
        self.oauth_convergence_inbox = OAuthConvergenceInbox()
        self.detector = ThreeLayerFaultDetector()
        self._skip_receipt_replay_cache = JTIReplayCache(ttl_seconds=600.0)
        self._skip_level_results = _BoundedTaskListStore()
        self._direct_results = _BoundedTaskListStore()
        self._task_checkpoints = _BoundedTaskListStore()

        self._inbound_http = ManagedHTTPService(
            service_name=f"sidecar-in-{identity.parsed_spiffe.default_hop_segment}",
            dispatcher=self._dispatch_inbound,
            host=inbound_host,
            port=inbound_port,
            public_origin=self.public_origin,
            allowed_hosts=allowed_hosts,
            ssl_context=self._server_ssl_ctx if mtls_bundle is None else None,
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
        # Outbound proxy ALWAYS binds strictly to 127.0.0.1 loopback (Pod-local only)
        self._outbound_http = ManagedHTTPService(
            service_name=f"sidecar-out-{identity.parsed_spiffe.default_hop_segment}",
            dispatcher=self._dispatch_outbound,
            host="127.0.0.1",
            port=outbound_port,
        )

    def start(self) -> Tuple[str, str]:
        self._inbound_http.start()
        out_url = self._outbound_http.start()
        return self.inbound_url, out_url

    def stop(self) -> None:
        if self.revocation_replica is not None:
            self.revocation_replica.stop_background_sync()
        self._inbound_http.stop()
        self._outbound_http.stop()

    @property
    def inbound_url(self) -> str:
        return self.public_origin or self._inbound_http.base_url

    @property
    def outbound_url(self) -> str:
        return self._outbound_http.base_url

    def set_public_origins(
        self,
        primary_origin: Optional[str],
        extra_origins: Iterable[str] = (),
    ) -> None:
        """Atomically update signed public origin(s) in RAM on live host IP change."""
        clean_primary = (
            validate_clean_endpoint_url(primary_origin, "public_origin")
            if primary_origin is not None
            else None
        )
        clean_extras = tuple(
            validate_clean_endpoint_url(o, "extra_origin")
            for o in extra_origins
            if o
        )
        self.public_origin = clean_primary
        self._inbound_http.set_public_origins(clean_primary, clean_extras)

    def set_agent_card(self, card: AgentCard) -> None:
        self.agent_card = card
        if card.locators:
            self.set_public_origins(
                card.locators[0].origin_url,
                [loc.origin_url for loc in card.locators[1:]],
            )

    def on_identity_renewed(self) -> None:
        """Synchronize `LeafVerifier.self_jkt` and cached `SSLContext` refs after SVID renewal."""
        self.verifier.self_jkt = self.identity.jkt
        if self._mtls_bundle is not None:
            try:
                self._server_ssl_ctx = self._mtls_bundle.build_server_ssl_context(
                    require_client_cert=True
                )
                self._client_ssl_ctx = self._mtls_bundle.build_client_ssl_context(
                    check_hostname=True
                )
            except Exception:
                pass

    def get_skip_level_results(
        self, task_id: str, expected_sub: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        return self._skip_level_results.get(task_id, expected_sub=expected_sub)

    def get_direct_results(
        self, task_id: str, expected_sub: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        return self._direct_results.get(task_id, expected_sub=expected_sub)

    def _outbound_verify_kwarg(
        self,
        target_url: Optional[str] = None,
        expected_trust_domain: Optional[str] = None,
        expected_spiffe_id: Optional[str] = None,
    ) -> Any:
        if self._mtls_bundle is not None:
            return self._mtls_bundle.verify_for_target(
                target_url=target_url,
                expected_trust_domain=expected_trust_domain,
                expected_spiffe_id=expected_spiffe_id,
            )
        return self._client_ssl_ctx if self._client_ssl_ctx is not None else True

    def _verify_mtls_channel_binding(
        self,
        req: HTTPRequestContext,
        parsed_token: LineageToken | MultiParentToken | CoAuthorizedToken,
    ) -> Tuple[bool, str]:
        """Cross-verify mTLS X.509 peer certificate (`spiffe://` + `jkt`) against LCT sender."""
        if self._mtls_bundle is None:
            return True, "mtls_not_configured"
        peer_spiffe = req.peer_spiffe_id
        peer_jkt = req.peer_jkt
        if not peer_spiffe or not peer_jkt:
            return False, "Missing authenticated mTLS peer X.509-SVID certificate"

        if isinstance(parsed_token, LineageToken):
            if parsed_token.holder_spiffe_id == self.identity.spiffe_id:
                if not parsed_token.hops:
                    # RootBlock from entry gateway: must belong to root issuer trust domain & match sender_jkt
                    peer_td = SpiffeId.parse(peer_spiffe).trust_domain
                    if peer_td != parsed_token.root.issuer_trust_domain:
                        return (
                            False,
                            f"mTLS peer domain {peer_td!r} != RootBlock domain {parsed_token.root.issuer_trust_domain!r}",
                        )
                    if peer_jkt != parsed_token.root.sender_jkt:
                        return (
                            False,
                            "mTLS peer certificate public key jkt != RootBlock sender_jkt",
                        )
                    return True, "ok"
                last_hop = parsed_token.hops[-1]
                expected_jkt = compute_jwk_thumbprint(last_hop.issuer_jwk)
                if peer_spiffe != last_hop.issuer_spiffe_id or peer_jkt != expected_jkt:
                    return (
                        False,
                        f"mTLS peer {peer_spiffe!r} != upstream hop issuer {last_hop.issuer_spiffe_id!r}",
                    )
                return True, "ok"
            # MCP tool call or direct upward task-result
            if (
                peer_spiffe != parsed_token.holder_spiffe_id
                or peer_jkt != parsed_token.holder_cnf_jkt
            ):
                return (
                    False,
                    f"mTLS peer {peer_spiffe!r} != token holder {parsed_token.holder_spiffe_id!r}",
                )
            return True, "ok"

        # MultiParentToken
        if (
            parsed_token.holder_spiffe_id == self.identity.spiffe_id
            and parsed_token.signer_spiffe_id != self.identity.spiffe_id
        ):
            expected_spiffe = parsed_token.signer_spiffe_id
            expected_jkt = compute_jwk_thumbprint(parsed_token.signer_jwk)
        else:
            expected_spiffe = parsed_token.holder_spiffe_id
            expected_jkt = parsed_token.holder_cnf_jkt

        if peer_spiffe != expected_spiffe or peer_jkt != expected_jkt:
            return (
                False,
                f"mTLS peer {peer_spiffe!r} != MultiParentToken sender {expected_spiffe!r}",
            )
        return True, "ok"

    # -------------------------------------------------------------------------
    # Inbound Reverse Proxy Dispatcher
    # -------------------------------------------------------------------------
    def _dispatch_inbound(
        self, req: HTTPRequestContext
    ) -> Tuple[int, Any, Dict[str, str]]:
        # 1. Iteratively decode percent-encoding & normalize trailing slash (`[LOW-02]`, `[HIGH-R3-01]`)
        decoded_path = req.path
        for _ in range(4):
            nxt_p = unquote(decoded_path)
            if nxt_p == decoded_path:
                break
            decoded_path = nxt_p
        norm_path = decoded_path.rstrip("/") or "/"

        # Unauthenticated read-only Kubelet/liveness probe (`GET /healthz`) checks Host syntax
        # (allowing Kubelet `Host: <PodIP>:8080`), while ALL other routes enforce strict authority match!
        if req.method == "GET" and norm_path == "/healthz":
            syn_ok, syn_err = req.validate_host_syntax_only()
            if not syn_ok:
                return 400, {"error": "invalid_or_spoofed_host_header", "detail": syn_err}, {}
            return (
                200,
                {
                    "status": "ok",
                    "spiffe_id": self.identity.spiffe_id,
                    "mode": self.verifier.mode.value,
                },
                {},
            )

        # 2. Strict HTTP `Host` header syntax & authority validation (`[CRITICAL-02]`)
        host_ok, host_err = req.validate_host_header()
        if not host_ok:
            return (
                400,
                {"error": "invalid_or_spoofed_host_header", "detail": host_err},
                {},
            )

        auth_htu = req.authoritative_url

        if req.method == "GET" and norm_path in (
            "/.well-known/agent-card.json",
            "/.well-known/agent.json",
        ):
            if self.agent_card is None:
                return 404, {"error": "no_agent_card"}, {}
            return 200, self.agent_card.to_dict(), {"A2A-Version": "1.0"}

        if req.method == "GET" and norm_path == "/v1/audit/local":
            return self.audit_emitter.local_store.serve_http_query(
                req,
                self.trust_resolver,
                node_spiffe_id=self.identity.spiffe_id,
                require_task_id=True,
            )

        # Dedicated endpoint: Upward Authenticated Skip-Level Return (`[HIGH-01]`)
        if req.method == "POST" and norm_path == "/v1/skip-level-return":
            body = req.json()
            raw_receipt = body.get("skip_level_receipt", body)
            dpop_hdr = req.header("DPoP")
            try:
                receipt, child_tok = verify_and_accept_skip_level_request(
                    ancestor_identity=self.identity,
                    ancestor_verifier=self.verifier,
                    raw_receipt=raw_receipt,
                    dpop_proof=dpop_hdr,
                    htm=req.method,
                    htu=auth_htu,
                    audit_emitter=self.audit_emitter,
                    revocation_replica=self.revocation_replica,
                    directory_client=self.directory_client,
                    receipt_replay_cache=self._skip_receipt_replay_cache,
                    prune_dead_intermediate=True,
                    client_ssl_context=self._client_ssl_ctx,
                    mtls_bundle=self._mtls_bundle,
                )
            except ResilienceError as exc:
                err_str = str(exc)
                child_id = (
                    str(raw_receipt.get("child_spiffe_id", ""))
                    if isinstance(raw_receipt, Mapping)
                    else ""
                )
                if child_id:
                    self.detector.record_policy_violation(
                        spiffe_id=child_id,
                        endpoint=auth_htu,
                        detail=err_str,
                    )
                err_code = (
                    "INTERMEDIATE_ANCESTOR_ALIVE"
                    if "INTERMEDIATE_ANCESTOR_ALIVE" in err_str
                    else "skip_level_rejected"
                )
                return 403, {"error": err_code, "detail": err_str}, {}

            if self._mtls_bundle is not None:
                if (
                    req.peer_spiffe_id != receipt.child_spiffe_id
                    or req.peer_jkt != child_tok.holder_cnf_jkt
                ):
                    return (
                        403,
                        {
                            "error": "MTLS_CHANNEL_BINDING_MISMATCH",
                            "detail": (
                                f"mTLS peer {req.peer_spiffe_id!r} != SkipLevelReceipt child {receipt.child_spiffe_id!r}"
                            ),
                        },
                        {},
                    )

            self._skip_level_results.append(
                receipt.task_id, receipt.to_dict(), sub=child_tok.sub
            )
            return (
                200,
                {
                    "accepted": True,
                    "merge_type": "SKIP_LEVEL_MERGE",
                    "receipt_id": receipt.receipt_id,
                    "task_id": receipt.task_id,
                    "result_sha256": receipt.result_sha256,
                },
                {},
            )

        # Standard protected routes (/mcp, /a2a/task, /a2a/converge, /v1/task-result, etc.)
        compact_token = _extract_dpop_token(req.header("Authorization"))
        if compact_token is None and self.delegation_mode in (
            "dual",
            "oauth_centralized",
            "oauth_federated",
        ):
            bearer_jwt = _extract_bearer_token(req.header("Authorization"))
            if bearer_jwt is not None:
                return self._handle_inbound_oauth_request(
                    req=req,
                    norm_path=norm_path,
                    bearer_jwt=bearer_jwt,
                )
        if self.delegation_mode in ("oauth_centralized", "oauth_federated"):
            return (
                401,
                {
                    "error": "missing_or_invalid_authorization_scheme",
                    "detail": f"Sidecar configured strictly for {self.delegation_mode}; expected 'Authorization: Bearer <jwt>'",
                },
                {},
            )
        dpop_proof = req.header("DPoP")
        if compact_token is None:
            return (
                401,
                {
                    "error": "missing_or_invalid_authorization_scheme",
                    "detail": "Expected 'Authorization: DPoP <lct_token>'",
                },
                {},
            )

        body_json = req.json() if req.body else {}

        # Determine endpoint role & monotonic escalation-only risk hint (`[CRITICAL-01]`, `[CRITICAL-04]`)
        is_mcp_route = self.is_tool_server or norm_path == "/mcp"
        is_direct_result_route = (not is_mcp_route) and norm_path == "/v1/task-result"
        is_agent_delegation_route = (not is_mcp_route) and (not is_direct_result_route)

        if is_mcp_route:
            mcp_method = str(body_json.get("method", "tools/call"))
            params = body_json.get("params") or {}
            tool_name = params.get("name") if isinstance(params, Mapping) else None
            tool_args = params.get("arguments") if isinstance(params, Mapping) else None
            ext_hint = req.header("X-LCT-Risk-Hint")
            # External caller may ONLY escalate risk (`HIGH`); `LOW` hints are ignored!
            risk_hint = (
                "HIGH"
                if (ext_hint and ext_hint.strip().upper() == "HIGH")
                else None
            )
            check_lattice = True
        else:
            mcp_method = "a2a/send"
            tool_name = None
            tool_args = None
            risk_hint = None
            check_lattice = False
            if isinstance(body_json, Mapping):
                cand_priv = body_json.get("private_tool") or body_json.get("tool")
                if not cand_priv and isinstance(body_json.get("params"), Mapping):
                    msg_obj = (body_json.get("params") or {}).get("message")
                    if isinstance(msg_obj, Mapping):
                        for pt in msg_obj.get("parts") or ():
                            if isinstance(pt, Mapping) and isinstance(pt.get("data"), Mapping):
                                cand_priv = pt["data"].get("private_tool") or pt["data"].get("tool")
                                if cand_priv:
                                    break
                if (
                    cand_priv
                    and self.resource_owner_sub
                    and (
                        self._owner_protected_tools is None
                        or str(cand_priv) in self._owner_protected_tools
                    )
                ):
                    tool_name = str(cand_priv)
                    check_lattice = True

        eff_owner_sub: Optional[str] = None
        if self.resource_owner_sub:
            if self._owner_protected_tools is None:
                eff_owner_sub = self.resource_owner_sub
            elif tool_name and str(tool_name) in self._owner_protected_tools:
                eff_owner_sub = self.resource_owner_sub

        vres = self.verifier.verify_request(
            compact_token=compact_token,
            dpop_proof=dpop_proof,
            htm=req.method,
            htu=auth_htu,
            method=mcp_method,
            tool=str(tool_name) if tool_name else None,
            arguments=tool_args if isinstance(tool_args, Mapping) else None,
            explicit_risk_hint=risk_hint,
            require_dpop=True,
            check_invocation_lattice=check_lattice,
            require_recipient_self=is_agent_delegation_route,
            require_direct_child_issuer=is_direct_result_route,
            resource_owner_sub=eff_owner_sub,
            allowed_co_auth_tools=self._allowed_co_auth_tools,
        )

        if not vres.allowed:
            if (
                vres.holder_spiffe_id
                and vres.status_code in (401, 403)
                and vres.reason_code != "TASK_AUTH_EXPIRED"
            ):
                self.detector.record_policy_violation(
                    spiffe_id=vres.holder_spiffe_id,
                    endpoint=auth_htu,
                    detail=f"{vres.reason_code}: {vres.detail}",
                )

            if (
                self.audit_emitter is not None
                and vres.task_id
                and vres.root_block_hash
                and vres.leaf_block_hash
            ):
                self.audit_emitter.emit(
                    event_type=AuditEventType.AUTHZ_DENIED,
                    task_id=vres.task_id,
                    sub=vres.sub or "unknown",
                    lineage_path=vres.lineage_path or f"/{vres.task_id}/unknown",
                    hop_index=vres.hop_index,
                    epoch=vres.epoch,
                    root_block_hash=vres.root_block_hash,
                    parent_block_hash=vres.parent_block_hash,
                    current_block_hash=vres.leaf_block_hash,
                    multi_parent_hashes=vres.multi_parent_hashes,
                    dpop_jti=vres.dpop_jti,
                    action_detail={
                        "path": norm_path,
                        "method": mcp_method,
                        "tool": tool_name,
                        "reason_code": vres.reason_code,
                        "detail": vres.detail,
                    },
                    decision="DENY",
                )
            deny_payload: Dict[str, Any] = {
                "error": vres.reason_code,
                "detail": vres.detail,
                "decision": vres.decision,
                "pruned_revoked_paths": list(vres.pruned_revoked_paths),
            }
            if vres.reason_code == "TASK_AUTH_EXPIRED" and vres.task_id:
                saved_ckpts = self._task_checkpoints.get(vres.task_id, expected_sub=vres.sub)
                if saved_ckpts:
                    deny_payload["checkpoint"] = saved_ckpts[-1]
            return vres.status_code, deny_payload, {}

        parsed_token = decode_token(compact_token)
        ch_ok, ch_err = self._verify_mtls_channel_binding(req, parsed_token)
        if not ch_ok:
            return (
                403,
                {"error": "MTLS_CHANNEL_BINDING_MISMATCH", "detail": ch_err},
                {},
            )
        if (
            isinstance(parsed_token, (MultiParentToken, CoAuthorizedToken))
            and parsed_token.holder_spiffe_id == self.identity.spiffe_id
            and parsed_token.signer_spiffe_id != self.identity.spiffe_id
        ):
            parsed_token = parsed_token.rebind_as_holder(self.identity)
            compact_token = parsed_token.encode_compact()

        if self.audit_emitter is not None:
            in_action_detail: Dict[str, Any] = {
                "path": norm_path,
                "decision": vres.decision,
                "active_paths": list(vres.active_paths),
                "pruned_revoked_paths": list(vres.pruned_revoked_paths),
                "peer_spiffe_id": req.peer_spiffe_id,
                "peer_issuer_domain": (
                    SpiffeId.parse(req.peer_spiffe_id).trust_domain
                    if req.peer_spiffe_id
                    else None
                ),
                "tls_version": req.tls_version,
                "tls_cipher": req.tls_cipher,
                "client_ip": req.client_ip,
            }
            if vres.co_authorized_principals:
                in_action_detail["co_authorized_principals"] = list(vres.co_authorized_principals)
            if vres.resumes_checkpoint_id:
                in_action_detail["resumes_checkpoint_id"] = vres.resumes_checkpoint_id
            in_idem = req.header("X-LCT-Idempotency-Key")
            if in_idem:
                in_action_detail["branch_idempotency_key"] = in_idem

            self.audit_emitter.emit(
                event_type=AuditEventType.INBOUND_AUTHZ,
                task_id=parsed_token.task_id,
                sub=parsed_token.sub,
                lineage_path=vres.lineage_path or "",
                hop_index=vres.hop_index,
                epoch=vres.epoch,
                root_block_hash=vres.root_block_hash or "",
                parent_block_hash=vres.parent_block_hash,
                current_block_hash=vres.leaf_block_hash or "",
                multi_parent_hashes=vres.multi_parent_hashes,
                dpop_jti=vres.dpop_jti,
                permissions_summary=vres.effective_permissions,
                action_detail=in_action_detail,
                decision=vres.decision,
            )

        # Built-in N-to-1 convergence collection endpoint (`[CRITICAL-04]`)
        if req.method == "POST" and norm_path == "/a2a/converge":
            try:
                branch_count = self.convergence_inbox.add_verified_branch(
                    token=parsed_token,
                    branch_payload=body_json.get("branch_data", body_json),
                    expected_holder_spiffe_id=self.identity.spiffe_id,
                    expected_holder_jkt=self.identity.jkt,
                )
            except TokenError as exc:
                return 403, {"error": "CONVERGENCE_BRANCH_REJECTED", "detail": str(exc)}, {}

            return (
                200,
                {
                    "converged_branch_recorded": True,
                    "task_id": parsed_token.task_id,
                    "sub": parsed_token.sub,
                    "total_branches_for_task": branch_count,
                },
                {},
            )

        # Built-in direct upward result callback endpoint (`[CRITICAL-04]`)
        if req.method == "POST" and norm_path == "/v1/task-result":
            self._direct_results.append(
                parsed_token.task_id, dict(body_json), sub=parsed_token.sub
            )
            return 200, {"accepted": True, "delivery_mode": "DIRECT_PARENT"}, {}

        # Register isolated per-request context & forward to local business server
        req_ctx = self.active_requests.register(
            compact_token=compact_token,
            parsed_token=parsed_token,
            verification=vres,
        )
        fwd_path = "/mcp" if norm_path == "/mcp" else req.path
        fwd_url = f"{self.app_upstream_url}{fwd_path}" + (
            f"?{req.query_raw}" if req.query_raw else ""
        )
        up_base = urlsplit(self.app_upstream_url)
        up_target = urlsplit(fwd_url)
        httpx_target = httpx.URL(fwd_url)
        if (
            (up_target.scheme, up_target.hostname, up_target.port)
            != (up_base.scheme, up_base.hostname, up_base.port)
            or (httpx_target.scheme, httpx_target.host, httpx_target.port)
            != (up_base.scheme, up_base.hostname, up_base.port)
            or up_target.username is not None
            or up_target.password is not None
            or bool(httpx_target.username)
            or bool(httpx_target.password)
            or httpx_target.raw_path.startswith(b"//")
        ):
            self.active_requests.release(req_ctx.request_id)
            return (
                400,
                {"error": "invalid_upstream_target", "detail": "Origin mismatch blocked"},
                {},
            )

        up_headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "X-LCT-Loopback-Auth": self.loopback_secret,
            "X-LCT-Request-Id": req_ctx.request_id,
            "X-LCT-Task-Id": req_ctx.task_id,
            "X-LCT-Sub": req_ctx.sub,
            "X-LCT-Lineage-Path": vres.lineage_path or "",
            "X-LCT-Decision": vres.decision,
            "X-LCT-Root-Block-Hash": vres.root_block_hash or "",
        }
        if vres.co_authorized_principals:
            up_headers["X-LCT-Co-Authorized-Principals"] = ",".join(
                vres.co_authorized_principals
            )
        in_idem_hdr = req.header("X-LCT-Idempotency-Key")
        if in_idem_hdr:
            up_headers["X-LCT-Idempotency-Key"] = in_idem_hdr
        a2a_ver = req.header("A2A-Version")
        if a2a_ver:
            up_headers["A2A-Version"] = a2a_ver
        accept_hdr = req.header("Accept")
        if accept_hdr:
            up_headers["Accept"] = accept_hdr

        wants_sse = (
            not is_mcp_route
            and (
                (accept_hdr is not None and "text/event-stream" in accept_hdr.lower())
                or body_json.get("method") in ("SendStreamingMessage", "message/stream")
            )
        )
        if wants_sse:
            stream_client = httpx.Client(
                timeout=self.upstream_timeout, follow_redirects=False
            )
            try:
                stream_ctx = stream_client.stream(
                    method=req.method,
                    url=fwd_url,
                    content=req.body,
                    headers=up_headers,
                )
                up_resp = stream_ctx.__enter__()
                up_ct = up_resp.headers.get("content-type", "")
                out_extra = {}
                if up_resp.headers.get("a2a-version"):
                    out_extra["A2A-Version"] = up_resp.headers["a2a-version"]
                if "text/event-stream" not in up_ct.lower():
                    raw_b = up_resp.read()
                    st_code = up_resp.status_code
                    stream_ctx.__exit__(None, None, None)
                    stream_client.close()
                    self.active_requests.release(req_ctx.request_id)
                    try:
                        parsed_err_body = strict_json_loads(raw_b)
                    except Exception:
                        parsed_err_body = {
                            "error": "upstream_non_json_response",
                            "status_code": st_code,
                        }
                    return st_code, parsed_err_body, out_extra

                def _relay_sse_frames() -> Iterator[str]:
                    try:
                        for line in up_resp.iter_lines():
                            s = line.strip()
                            if s.startswith("data:"):
                                yield f"{s}\n\n"
                    finally:
                        try:
                            stream_ctx.__exit__(None, None, None)
                        finally:
                            stream_client.close()
                            self.active_requests.release(req_ctx.request_id)

                return up_resp.status_code, SSEResponse(frames=_relay_sse_frames()), out_extra
            except Exception:
                stream_client.close()
                self.active_requests.release(req_ctx.request_id)
                raise

        try:
            fwd_resp = httpx.request(
                method=req.method,
                url=fwd_url,
                content=req.body,
                headers=up_headers,
                timeout=self.upstream_timeout,
                follow_redirects=False,
            )
            resp_json = fwd_resp.json()
            out_extra_headers: Dict[str, str] = {}
            if fwd_resp.headers.get("a2a-version"):
                out_extra_headers["A2A-Version"] = fwd_resp.headers["a2a-version"]

            if (
                is_mcp_route
                and 200 <= fwd_resp.status_code < 300
                and self.audit_emitter is not None
            ):
                self.audit_emitter.emit(
                    event_type=AuditEventType.TOOL_INVOCATION,
                    task_id=parsed_token.task_id,
                    sub=parsed_token.sub,
                    lineage_path=vres.lineage_path or "",
                    hop_index=vres.hop_index,
                    epoch=vres.epoch,
                    root_block_hash=vres.root_block_hash or "",
                    parent_block_hash=vres.parent_block_hash,
                    current_block_hash=vres.leaf_block_hash or "",
                    multi_parent_hashes=vres.multi_parent_hashes,
                    dpop_jti=vres.dpop_jti,
                    permissions_summary=vres.effective_permissions,
                    action_detail={
                        "method": mcp_method,
                        "tool": tool_name,
                        "arguments": tool_args,
                        "result_sha256": sha256_canonical_b64url(resp_json),
                        "active_paths": list(vres.active_paths),
                        "pruned_revoked_paths": list(vres.pruned_revoked_paths),
                        "co_authorized_principals": list(vres.co_authorized_principals)
                        if vres.co_authorized_principals
                        else [],
                        "peer_spiffe_id": req.peer_spiffe_id,
                        "peer_issuer_domain": (
                            SpiffeId.parse(req.peer_spiffe_id).trust_domain
                            if req.peer_spiffe_id
                            else None
                        ),
                        "tls_version": req.tls_version,
                        "tls_cipher": req.tls_cipher,
                        "client_ip": req.client_ip,
                    },
                    decision=vres.decision,
                )

            return fwd_resp.status_code, resp_json, out_extra_headers
        finally:
            self.active_requests.release(req_ctx.request_id)

    def _resolve_oauth_sts_origins(
        self, delegation_mode: str, target_trust_domain: Optional[str] = None
    ) -> List[str]:
        if delegation_mode == "oauth_centralized":
            if self._oauth_central_sts_origins_provider is not None:
                return [str(x) for x in self._oauth_central_sts_origins_provider() if str(x).strip()]
            return []
        eff_td = (target_trust_domain or self.identity.trust_domain).strip().lower()
        if self._oauth_domain_sts_origins_provider is not None:
            return [str(x) for x in self._oauth_domain_sts_origins_provider(eff_td) if str(x).strip()]
        if self._oauth_central_sts_origins_provider is not None and eff_td == "org-alpha.io":
            return [str(x) for x in self._oauth_central_sts_origins_provider() if str(x).strip()]
        return []

    def _handle_inbound_oauth_request(
        self,
        *,
        req: HTTPRequestContext,
        norm_path: str,
        bearer_jwt: str,
    ) -> Tuple[int, Any, Dict[str, str]]:
        """Inbound RFC 8693 OAuth 2.0 Bearer verification (flat scope + audience check)."""
        from lineage.oauth_sts.keycloak_realm import spiffe_id_to_oauth_client_id

        hdr_mode = (req.header("X-LCT-Delegation-Mode") or "").strip().lower()
        if self.delegation_mode in ("oauth_centralized", "oauth_federated"):
            eff_mode = self.delegation_mode
        elif hdr_mode in ("oauth_centralized", "oauth_federated"):
            eff_mode = hdr_mode
        else:
            eff_mode = "oauth_centralized"

        verifier = (
            self.oauth_central_verifier
            if eff_mode == "oauth_centralized"
            else (self.oauth_local_verifier or self.oauth_central_verifier)
        )
        if verifier is None:
            return (
                503,
                {
                    "error": "oauth_verifier_not_configured",
                    "detail": f"No OIDC/OAuth JWKS verifier configured for mode {eff_mode!r}",
                },
                {},
            )

        if self._mtls_bundle is not None and not req.peer_spiffe_id:
            return (
                403,
                {
                    "error": "unauthenticated_mtls_peer",
                    "detail": "Missing authenticated mTLS peer X.509-SVID certificate",
                },
                {},
            )

        body_json = req.json() if req.body else {}
        is_mcp_route = self.is_tool_server or norm_path == "/mcp"
        oauth_tool_name = ""
        required_scopes: List[str] = []
        if is_mcp_route:
            params = body_json.get("params") or {}
            tool_name = str(params.get("name") or "") if isinstance(params, Mapping) else ""
            oauth_tool_name = tool_name
            if tool_name == "execute_settlement":
                required_scopes = ["travel:pay"]
            elif tool_name in (
                "search_flight",
                "search_flights",
                "book_flight",
                "search_hotel",
                "search_hotels",
                "reserve_hotel",
                "record_itinerary_audit",
            ):
                required_scopes = ["travel:book"]
        elif isinstance(body_json, Mapping) and body_json.get("private_tool"):
            oauth_tool_name = str(body_json["private_tool"]).strip()

        own_cid = spiffe_id_to_oauth_client_id(self.identity.spiffe_id)
        try:
            verified_jwt = verifier.verify_jwt(
                bearer_jwt,
                expected_audience=(self.identity.spiffe_id, own_cid),
                required_scopes=required_scopes,
            )
        except Exception as exc:
            err_msg = str(exc)
            st_err = 403 if "insufficient_oauth_scope" in err_msg else 401
            return st_err, {"error": "oauth_verification_failed", "detail": err_msg}, {}

        if self.resource_owner_sub:
            is_owner_gated = (
                self._owner_protected_tools is None
                or (bool(oauth_tool_name) and oauth_tool_name in self._owner_protected_tools)
            )
            if is_owner_gated and verified_jwt.canonical_lct_sub != self.resource_owner_sub:
                return (
                    403,
                    {
                        "error": "CROSS_PRINCIPAL_DENIED",
                        "detail": (
                            f"OAuth principal {verified_jwt.canonical_lct_sub!r} is forbidden from "
                            f"accessing owner-protected resource of {self.resource_owner_sub!r}"
                        ),
                    },
                    {},
                )

        # Extract task_id from header or JSON-RPC message if present
        task_id = (req.header("X-LCT-Task-Id") or "").strip()
        if not task_id and isinstance(body_json, Mapping):
            task_id = str(body_json.get("task_id") or "").strip()
            if not task_id and isinstance(body_json.get("params"), Mapping):
                p_msg = body_json["params"].get("message")
                if isinstance(p_msg, Mapping):
                    task_id = str(p_msg.get("taskId") or "").strip()
        if not task_id:
            task_id = f"task-oauth-{secrets.token_hex(5)}"

        if req.method == "POST" and norm_path == "/a2a/converge":
            branch_key = f"/oauth/{eff_mode}/{verified_jwt.azp or 'branch'}-{secrets.token_hex(2)}"
            cnt = self.oauth_convergence_inbox.add_branch(
                task_id=task_id,
                sub=verified_jwt.canonical_lct_sub,
                delegation_mode=eff_mode,
                access_token=bearer_jwt,
                branch_key=branch_key,
                branch_payload=body_json.get("branch_data", body_json),
            )
            return (
                200,
                {
                    "converged_branch_recorded": True,
                    "delegation_mode": eff_mode,
                    "task_id": task_id,
                    "sub": verified_jwt.canonical_lct_sub,
                    "total_branches_for_task": cnt,
                },
                {},
            )

        oauth_ctx = self.oauth_active_requests.register(
            delegation_mode=eff_mode,
            task_id=task_id,
            sub=verified_jwt.canonical_lct_sub,
            access_token=bearer_jwt,
            issuer=verified_jwt.issuer,
            scopes=verified_jwt.scopes,
            azp=verified_jwt.azp,
            act=verified_jwt.act,
            jti=verified_jwt.jti,
        )
        fwd_path = "/mcp" if norm_path == "/mcp" else req.path
        fwd_url = f"{self.app_upstream_url}{fwd_path}" + (
            f"?{req.query_raw}" if req.query_raw else ""
        )
        up_headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "X-LCT-Loopback-Auth": self.loopback_secret,
            "X-LCT-Request-Id": oauth_ctx.request_id,
            "X-LCT-Task-Id": oauth_ctx.task_id,
            "X-LCT-Sub": oauth_ctx.sub,
            "X-LCT-Lineage-Path": f"/{oauth_ctx.task_id}/oauth/{eff_mode}/{own_cid}",
            "X-LCT-Decision": "ALLOW_OAUTH_FLAT_SCOPE",
        }
        a2a_ver = req.header("A2A-Version")
        if a2a_ver:
            up_headers["A2A-Version"] = a2a_ver
        accept_hdr = req.header("Accept")
        if accept_hdr:
            up_headers["Accept"] = accept_hdr

        wants_sse = (
            not is_mcp_route
            and (
                (accept_hdr is not None and "text/event-stream" in accept_hdr.lower())
                or body_json.get("method") in ("SendStreamingMessage", "message/stream")
            )
        )
        if wants_sse:
            stream_client = httpx.Client(timeout=self.upstream_timeout, follow_redirects=False)
            try:
                stream_ctx = stream_client.stream(
                    method=req.method,
                    url=fwd_url,
                    content=req.body,
                    headers=up_headers,
                )
                up_resp = stream_ctx.__enter__()
                up_ct = up_resp.headers.get("content-type", "")
                out_extra = {}
                if up_resp.headers.get("a2a-version"):
                    out_extra["A2A-Version"] = up_resp.headers["a2a-version"]
                if "text/event-stream" not in up_ct.lower():
                    raw_b = up_resp.read()
                    st_code = up_resp.status_code
                    stream_ctx.__exit__(None, None, None)
                    stream_client.close()
                    self.oauth_active_requests.release(oauth_ctx.request_id)
                    return st_code, strict_json_loads(raw_b), out_extra

                def _relay_oauth_sse() -> Iterator[str]:
                    try:
                        for line in up_resp.iter_lines():
                            s = line.strip()
                            if s.startswith("data:"):
                                yield f"{s}\n\n"
                    finally:
                        try:
                            stream_ctx.__exit__(None, None, None)
                        finally:
                            stream_client.close()
                            self.oauth_active_requests.release(oauth_ctx.request_id)

                return up_resp.status_code, SSEResponse(frames=_relay_oauth_sse()), out_extra
            except Exception:
                stream_client.close()
                self.oauth_active_requests.release(oauth_ctx.request_id)
                raise

        try:
            fwd_resp = httpx.request(
                method=req.method,
                url=fwd_url,
                content=req.body,
                headers=up_headers,
                timeout=self.upstream_timeout,
                follow_redirects=False,
            )
            out_hdrs: Dict[str, str] = {}
            if fwd_resp.headers.get("a2a-version"):
                out_hdrs["A2A-Version"] = fwd_resp.headers["a2a-version"]
            return fwd_resp.status_code, fwd_resp.json(), out_hdrs
        finally:
            self.oauth_active_requests.release(oauth_ctx.request_id)

    def _handle_outbound_oauth_proxy_call(
        self,
        *,
        action: str,
        body: Mapping[str, Any],
        delegation_mode: str,
        subject_token: str,
        task_id: str,
        converged_payloads: Dict[str, dict],
    ) -> Tuple[int, Any, Dict[str, str]]:
        """Execute outbound RFC 8693 Token Exchange (`oauth_centralized` or `oauth_federated`)."""
        if self.oauth_exchange_client is None:
            return 503, {"error": "oauth_exchange_client_not_configured"}, {}

        if action == "call_tool":
            raw_target_url = str(body.get("target_url") or "").strip()
            req_skill = str(body.get("required_skill") or "").strip()
            eff_spiffe_id: Optional[str] = (
                str(body["target_spiffe_id"]).strip() if body.get("target_spiffe_id") else None
            )
            eff_trust_domain: Optional[str] = (
                str(body["target_trust_domain"]).strip() if body.get("target_trust_domain") else None
            )
            candidate_urls: List[str] = []
            if raw_target_url:
                candidate_urls = [_validate_outbound_target_url(raw_target_url)]
            elif self.directory_client is not None and (req_skill or eff_spiffe_id):
                mcp_path = str(body.get("mcp_path") or "/mcp").strip() or "/mcp"
                tool_card: Optional[AgentCard] = None
                if eff_spiffe_id:
                    tool_card = self.directory_client.get_agent(eff_spiffe_id)
                if tool_card is None and req_skill:
                    found_tools = self.directory_client.discover(
                        skill=req_skill, trust_domain=eff_trust_domain, only_healthy=True
                    )
                    if found_tools:
                        tool_card = found_tools[0]
                if tool_card is None:
                    return 404, {"error": "mcp_tool_server_not_found", "required_skill": req_skill}, {}
                eff_spiffe_id = tool_card.spiffe_id
                eff_trust_domain = tool_card.trust_domain
                for orig in tool_card.candidate_origins():
                    candidate_urls.append(
                        _validate_outbound_target_url(f"{orig.rstrip('/')}{mcp_path}", expected_origin=orig)
                    )
            else:
                return 400, {"error": "missing_target_url_or_skill"}, {}

            sts_origins = self._resolve_oauth_sts_origins(delegation_mode, eff_trust_domain)
            ex_out: Optional[Any] = None
            out_bearer = subject_token
            if eff_spiffe_id != self.identity.spiffe_id:
                try:
                    ex_out = self.oauth_exchange_client.exchange_token(
                        sts_origins=sts_origins,
                        subject_token=subject_token,
                        target_audience=eff_spiffe_id or req_skill or "mcp-tool",
                        caller_spiffe_id=self.identity.spiffe_id,
                        caller_workload_svid=self.identity.workload_svid,
                    )
                    out_bearer = ex_out.access_token
                except Exception as exc:
                    return 502, {"error": "oauth_sts_exchange_failed", "detail": str(exc)}, {}

            timeout_val = _require_finite_timeout(body.get("timeout"), 60.0)
            payload = body.get("payload") or {}
            resp: Optional[httpx.Response] = None
            last_exc: Optional[Exception] = None
            for target_url in candidate_urls:
                try:
                    with httpx.Client(
                        verify=self._outbound_verify_kwarg(
                            target_url=target_url,
                            expected_trust_domain=eff_trust_domain,
                            expected_spiffe_id=eff_spiffe_id,
                        ),
                        timeout=timeout_val,
                        follow_redirects=False,
                        trust_env=False,
                    ) as client:
                        resp = client.post(
                            target_url,
                            json=payload,
                            headers={
                                "Authorization": f"Bearer {out_bearer}",
                                "X-LCT-Delegation-Mode": delegation_mode,
                                "X-LCT-Task-Id": task_id,
                            },
                        )
                    break
                except httpx.HTTPError as exc:
                    last_exc = exc
                    continue

            if resp is None:
                return 502, {"error": "upstream_transport_error", "detail": str(last_exc)}, {}
            return (
                resp.status_code,
                {
                    "upstream_status": resp.status_code,
                    "upstream_body": resp.json(),
                    "converged_branch_payloads": converged_payloads,
                    "target_spiffe_id": eff_spiffe_id,
                    "resolved_locator": str(resp.request.url),
                    "oauth_telemetry": (
                        {
                            "delegation_mode": delegation_mode,
                            "sts_endpoint": ex_out.sts_endpoint,
                            "sts_rtt_ms": ex_out.rtt_ms,
                            "sts_exchanges": 1,
                            "exchanged_scope": ex_out.scope,
                        }
                        if ex_out is not None
                        else None
                    ),
                },
                {},
            )

        if action == "delegate_agent":
            payload = body.get("payload") or {}
            raw_task_path = str(body.get("task_path", "/a2a/task"))
            norm_tp_path, norm_tp_query = validate_origin_form_target(raw_task_path)
            task_path = norm_tp_path + (f"?{norm_tp_query}" if norm_tp_query else "")
            extra_del_headers: Dict[str, str] = {}
            if norm_tp_path in ("/", "/a2a") or body.get("a2a_v1"):
                extra_del_headers["A2A-Version"] = "1.0"

            timeout_del = _require_finite_timeout(body.get("timeout"), 60.0)
            del_candidate_urls: List[str] = []
            delegate_spiffe_id: Optional[str] = None
            delegate_td: Optional[str] = None
            if "delegate_spiffe_id" in body and "target_url" in body:
                delegate_spiffe_id = str(body["delegate_spiffe_id"])
                delegate_td = SpiffeId.parse(delegate_spiffe_id).trust_domain
                del_candidate_urls = [_validate_outbound_target_url(body["target_url"])]
            elif "required_skill" in body and self.directory_client is not None:
                cards = self.directory_client.discover(
                    skill=str(body["required_skill"]),
                    only_healthy=True,
                )
                if not cards:
                    return 404, {"error": "no_candidate_for_skill"}, {}
                chosen = cards[0]
                delegate_spiffe_id = chosen.spiffe_id
                delegate_td = chosen.trust_domain
                for orig in chosen.candidate_origins():
                    del_candidate_urls.append(
                        _validate_outbound_target_url(f"{orig.rstrip('/')}{task_path}", expected_origin=orig)
                    )
            else:
                return 400, {"error": "missing_delegate_target_or_skill"}, {}

            # Note: In `oauth_federated`, if crossing domain boundary, we first ensure we hold a
            # local domain token (if incoming token was from upstream), then exchange at `delegate_td`'s STS!
            sts_origins = self._resolve_oauth_sts_origins(delegation_mode, delegate_td)
            try:
                ex_out = self.oauth_exchange_client.exchange_token(
                    sts_origins=sts_origins,
                    subject_token=subject_token,
                    target_audience=delegate_spiffe_id or "agent",
                    caller_spiffe_id=self.identity.spiffe_id,
                    caller_workload_svid=self.identity.workload_svid,
                )
            except Exception as exc:
                return 502, {"error": "oauth_sts_exchange_failed", "detail": str(exc)}, {}

            resp_del: Optional[httpx.Response] = None
            last_del_exc: Optional[Exception] = None
            # Support failover to secondary card in OAuth mode (WITHOUT Prune-and-Graft revocation —
            # empirically demonstrating why zombie T_1 remains valid in OAuth!)
            all_cards = (
                self.directory_client.discover(skill=str(body["required_skill"]), only_healthy=True)
                if ("required_skill" in body and self.directory_client is not None and body.get("use_prune_and_graft"))
                else []
            )
            attempt_targets: List[Tuple[str, Optional[str], str, float]] = [
                (u, delegate_spiffe_id, ex_out.access_token, timeout_del) for u in del_candidate_urls
            ]
            total_sts_exchanges = 1
            total_sts_rtt_ms = ex_out.rtt_ms

            idx = 0
            while idx < len(attempt_targets):
                target_url, exp_spiffe, tok_to_send, req_to = attempt_targets[idx]
                try:
                    with httpx.Client(
                        verify=self._outbound_verify_kwarg(
                            target_url=target_url,
                            expected_spiffe_id=exp_spiffe,
                        ),
                        timeout=req_to,
                        follow_redirects=False,
                        trust_env=False,
                    ) as client:
                        resp_del = client.post(
                            target_url,
                            json=payload,
                            headers={
                                "Authorization": f"Bearer {tok_to_send}",
                                "X-LCT-Delegation-Mode": delegation_mode,
                                "X-LCT-Task-Id": task_id,
                                **extra_del_headers,
                            },
                        )
                    break
                except httpx.HTTPError as exc:
                    last_del_exc = exc
                    if not isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout)):
                        while (
                            idx + 1 < len(attempt_targets)
                            and attempt_targets[idx + 1][1] == exp_spiffe
                        ):
                            idx += 1
                    # If primary timed out and backup card exists, perform a second STS exchange to backup!
                    if idx == len(attempt_targets) - 1 and len(all_cards) > 1:
                        b_card = all_cards[1]
                        if b_card.spiffe_id != delegate_spiffe_id:
                            b_sts = self._resolve_oauth_sts_origins(delegation_mode, b_card.trust_domain)
                            ex_b = self.oauth_exchange_client.exchange_token(
                                sts_origins=b_sts,
                                subject_token=subject_token,
                                target_audience=b_card.spiffe_id,
                                caller_spiffe_id=self.identity.spiffe_id,
                                caller_workload_svid=self.identity.workload_svid,
                            )
                            total_sts_exchanges += 1
                            total_sts_rtt_ms = round(total_sts_rtt_ms + ex_b.rtt_ms, 2)
                            backup_to = max(timeout_del * 20.0, 35.0)
                            for b_orig in b_card.candidate_origins():
                                attempt_targets.append(
                                    (
                                        _validate_outbound_target_url(f"{b_orig.rstrip('/')}{task_path}", expected_origin=b_orig),
                                        b_card.spiffe_id,
                                        ex_b.access_token,
                                        backup_to,
                                    )
                                )
                            delegate_spiffe_id = b_card.spiffe_id
                    idx += 1

            if resp_del is None:
                return 502, {"error": "upstream_transport_error", "detail": str(last_del_exc)}, {}
            return (
                resp_del.status_code,
                {
                    "upstream_status": resp_del.status_code,
                    "upstream_body": resp_del.json(),
                    "delegate_spiffe_id": delegate_spiffe_id,
                    "resolved_locator": str(resp_del.request.url),
                    "oauth_telemetry": {
                        "delegation_mode": delegation_mode,
                        "sts_endpoint": ex_out.sts_endpoint,
                        "sts_rtt_ms": total_sts_rtt_ms,
                        "sts_exchanges": total_sts_exchanges,
                        "exchanged_scope": ex_out.scope,
                    },
                },
                {},
            )

        return 400, {"error": f"unsupported_oauth_proxy_action:{action}"}, {}

    # -------------------------------------------------------------------------
    # Outbound Delegation & Tool Call Proxy Dispatcher (Localhost Only)
    # -------------------------------------------------------------------------
    def _dispatch_outbound(
        self, req: HTTPRequestContext
    ) -> Tuple[int, Any, Dict[str, str]]:
        norm_path = unquote(req.path).rstrip("/") or "/"
        if req.method == "GET" and norm_path == "/healthz":
            return (
                200,
                {
                    "status": "ok",
                    "spiffe_id": self.identity.spiffe_id,
                    "mtls_enabled": self._mtls_bundle is not None,
                    "svid_generation": self.identity.renewal_generation,
                },
                {},
            )

        if req.method == "GET" and norm_path == "/readyz":
            if self._readiness_check is not None:
                ok, detail = self._readiness_check()
                if not ok:
                    return (
                        503,
                        {
                            "status": "not_ready",
                            "spiffe_id": self.identity.spiffe_id,
                            **detail,
                        },
                        {},
                    )
                return (
                    200,
                    {
                        "status": "ready",
                        "spiffe_id": self.identity.spiffe_id,
                        "svid_generation": self.identity.renewal_generation,
                        **detail,
                    },
                    {},
                )
            return (
                200,
                {
                    "status": "ready",
                    "spiffe_id": self.identity.spiffe_id,
                    "svid_generation": self.identity.renewal_generation,
                },
                {},
            )

        if not _constant_time_secret_match(
            req.header("X-LCT-Loopback-Auth"), self.loopback_secret
        ):
            return 403, {"error": "unauthorized_loopback_caller"}, {}

        if req.method != "POST" or norm_path != "/v1/proxy/call":
            return 404, {"error": "route_not_found"}, {}

        body = req.json()
        action = str(body.get("action", "call_tool"))
        fault_injection_enabled = (
            os.environ.get("LCT_ENABLE_FAULT_INJECTION", "false").lower() == "true"
        )
        if action == "inspect_inbox":
            tid = str(body.get("task_id", "")).strip()
            sub_val = str(body.get("sub", "")).strip()
            caller_tid = str(body.get("caller_task_id", tid)).strip()
            if not tid or not sub_val:
                return (
                    400,
                    {
                        "error": "missing_task_or_sub",
                        "detail": "inspect_inbox requires non-empty task_id and sub",
                    },
                    {},
                )
            if caller_tid != tid and not fault_injection_enabled:
                return (
                    403,
                    {
                        "error": "cross_task_inbox_inspection_forbidden",
                        "detail": "Cross-task inbox inspection requires explicit LCT_ENABLE_FAULT_INJECTION=true",
                    },
                    {},
                )
            conv_payloads = self.convergence_inbox.peek_branch_payloads(tid, sub_val)
            if not conv_payloads:
                conv_payloads = self.oauth_convergence_inbox.peek_branch_payloads(tid, sub_val)
            scrubbed_skip = [
                redact_sensitive(r)
                for r in self.get_skip_level_results(tid, expected_sub=sub_val)
            ]
            scrubbed_direct = [
                redact_sensitive(r)
                for r in self.get_direct_results(tid, expected_sub=sub_val)
            ]
            scrubbed_ckpts = [
                redact_sensitive(r)
                for r in self._task_checkpoints.get(tid, expected_sub=sub_val)
            ]
            return (
                200,
                {
                    "task_id": tid,
                    "skip_level_results": scrubbed_skip,
                    "direct_results": scrubbed_direct,
                    "checkpoints": scrubbed_ckpts,
                    "converged_branch_payloads": conv_payloads,
                    "spiffe_id": self.identity.spiffe_id,
                },
                {},
            )

        if action == "get_request_permissions":
            req_id_q = str(body.get("request_id") or "").strip()
            active_q = self.active_requests.get(req_id_q) if req_id_q else None
            eff_dict: Optional[Dict[str, Any]] = None
            if active_q is not None:
                if active_q.verification.effective_permissions is not None:
                    eff_dict = dict(active_q.verification.effective_permissions)
                elif isinstance(active_q.parsed_token, LineageToken):
                    eff_dict = active_q.parsed_token.leaf_permissions.to_dict()
                elif isinstance(active_q.parsed_token, CoAuthorizedToken):
                    eff_dict = active_q.parsed_token.effective_permissions.to_dict()
            return (
                200,
                {
                    "has_lct_permissions": eff_dict is not None,
                    "effective_permissions": eff_dict,
                },
                {},
            )

        if action == "sign_checkpoint":
            prior_tok_obj: Optional[LineageToken] = None
            raw_pt = str(body.get("prior_token") or body.get("compact_token") or "").strip()
            if raw_pt:
                try:
                    dec_pt = decode_token(raw_pt)
                except TokenError as exc:
                    return 403, {"error": "INVALID_PRIOR_TOKEN", "detail": str(exc)}, {}
                if not isinstance(dec_pt, LineageToken):
                    return 403, {"error": "INVALID_PRIOR_TOKEN", "detail": "prior_token must be LineageToken"}, {}
                prior_tok_obj = dec_pt
            elif body.get("request_id"):
                act_ck = self.active_requests.get(str(body["request_id"]).strip())
                if act_ck is not None and isinstance(act_ck.parsed_token, LineageToken):
                    prior_tok_obj = act_ck.parsed_token

            if prior_tok_obj is None:
                return (
                    403,
                    {
                        "error": "PRIOR_TOKEN_REQUIRED_FOR_CHECKPOINT",
                        "detail": "sign_checkpoint requires verified prior_token or active LCT request_id",
                    },
                    {},
                )
            try:
                verify_root_block_signature_ignoring_expiry(
                    prior_tok_obj.root, self.trust_resolver
                )
            except TokenError as exc:
                return 403, {"error": "INVALID_PRIOR_TOKEN_SIGNATURE", "detail": str(exc)}, {}

            if prior_tok_obj.root.delegate_spiffe_id != self.identity.spiffe_id:
                return (
                    403,
                    {
                        "error": "CHECKPOINT_SIGNER_NOT_ENTRY_DELEGATE",
                        "detail": (
                            f"Sidecar {self.identity.spiffe_id!r} != prior RootBlock entry delegate "
                            f"{prior_tok_obj.root.delegate_spiffe_id!r}"
                        ),
                    },
                    {},
                )
            if body.get("task_id") and str(body["task_id"]) != prior_tok_obj.task_id:
                return 403, {"error": "CHECKPOINT_TASK_MISMATCH"}, {}
            if body.get("sub") and str(body["sub"]) != prior_tok_obj.sub:
                return 403, {"error": "CHECKPOINT_SUB_MISMATCH"}, {}
            if (
                body.get("prior_root_block_hash")
                and str(body["prior_root_block_hash"]) != prior_tok_obj.root_block_hash
            ):
                return 403, {"error": "CHECKPOINT_PRIOR_ROOT_MISMATCH"}, {}

            try:
                ckpt = TaskCheckpoint.create_and_sign(
                    signer_identity=self.identity,
                    task_id=prior_tok_obj.task_id,
                    sub=prior_tok_obj.sub,
                    prior_root_block_hash=prior_tok_obj.root_block_hash,
                    original_max_amount=prior_tok_obj.root.permissions.max_amount,
                    original_max_calls=int(prior_tok_obj.root.permissions.max_calls),
                    completed_branches=body.get("completed_branches") or (),
                    remaining_branches=body.get("remaining_branches") or (),
                    consumed_amount=float(body.get("consumed_amount", 0.0)),
                    consumed_calls=int(body.get("consumed_calls", 0)),
                    checkpoint_id=body.get("checkpoint_id"),
                )
            except (KeyError, ValueError, TypeError, TokenError) as exc:
                return 400, {"error": "invalid_checkpoint_request", "detail": str(exc)}, {}
            self._task_checkpoints.append(ckpt.task_id, ckpt.to_dict(), sub=ckpt.sub)
            return 200, {"checkpoint": ckpt.to_dict()}, {}

        if action == "request_local_ca_consent":
            if not self._local_ca_url or not self._sa_token_path or not self.resource_owner_sub:
                return 503, {"error": "local_ca_consent_not_configured"}, {}
            if not self._allowed_co_auth_tools:
                return 403, {"error": "COAUTH_TOOL_NOT_PERMITTED", "detail": "No co-authorizable tools configured"}, {}
            req_tools = [str(t).strip() for t in (body.get("tools") or ()) if str(t).strip()]
            if not req_tools or not set(req_tools).issubset(self._allowed_co_auth_tools):
                return (
                    403,
                    {
                        "error": "COAUTH_TOOL_NOT_PERMITTED",
                        "detail": f"Requested consent tools {req_tools!r} exceed allowed {sorted(self._allowed_co_auth_tools)!r}",
                    },
                    {},
                )
            user_oidc = str(body.get("user_oidc_token") or "").strip()
            if not user_oidc:
                return (
                    401,
                    {
                        "error": "OWNER_CONSENT_PROOF_REQUIRED",
                        "detail": "Cryptographic owner user_oidc_token is mandatory to mint consent",
                    },
                    {},
                )
            try:
                with open(self._sa_token_path, "r", encoding="utf-8") as fh:
                    sa_jwt = fh.read().strip()
                ca_hdrs: Dict[str, str] = {"Authorization": f"Bearer {sa_jwt}"}
                perms = PermissionLattice.create(
                    tools=req_tools,
                    max_calls=max(1, min(int(body.get("max_calls", 2)), 4)),
                )
                ca_req_json: Dict[str, Any] = {
                    "trust_domain": self.identity.trust_domain,
                    "sub": self.resource_owner_sub,
                    "task_id": str(body["task_id"]),
                    "sender_jkt": self.identity.jkt,
                    "first_hop_spiffe_id": str(body["delegate_spiffe_id"]),
                    "first_hop_jkt": str(body["delegate_jkt"]),
                    "hop_segment": "OwnerConsent",
                    "permissions": perms.to_dict(),
                    "ttl_seconds": min(float(body.get("ttl_seconds", 120.0)), 300.0),
                    "co_auth_consent": True,
                    "requester_sub": str(body.get("requester_sub") or ""),
                    "user_oidc_token": user_oidc,
                }
                r_ca = httpx.post(
                    f"{self._local_ca_url}/v1/ca/mint-consent-token",
                    json=ca_req_json,
                    headers=ca_hdrs,
                    timeout=10.0,
                    trust_env=False,
                )
                return r_ca.status_code, r_ca.json(), {}
            except Exception as exc:
                return 502, {"error": "local_ca_consent_failed", "detail": str(exc)}, {}

        if action == "resolve_card":
            if self.directory_client is None:
                return 500, {"error": "directory_client_not_configured"}, {}
            sp_query = str(body.get("spiffe_id") or "").strip()
            sk_query = str(body.get("required_skill") or "").strip()
            td_query = str(body.get("trust_domain") or "").strip() or None
            resolved_card: Optional[AgentCard] = None
            if sp_query:
                resolved_card = self.directory_client.get_agent(sp_query)
            elif sk_query:
                found = self.directory_client.discover(
                    skill=sk_query, trust_domain=td_query, only_healthy=True
                )
                if found:
                    resolved_card = found[0]
            if resolved_card is None:
                return 404, {"error": "card_not_found"}, {}
            return (
                200,
                {
                    "agent_card": resolved_card.to_dict(),
                    "spiffe_id": resolved_card.spiffe_id,
                    "candidate_origins": resolved_card.candidate_origins(),
                },
                {},
            )

        if action == "list_skills":
            if self.directory_client is None:
                return 500, {"error": "directory_client_not_configured"}, {}
            cards = self.directory_client.discover(only_healthy=True)
            catalog: List[Dict[str, Any]] = [
                {
                    "spiffe_id": c.spiffe_id,
                    "trust_domain": c.trust_domain,
                    "name": c.name,
                    "skills": sorted(c.skills),
                    "priority": c.priority,
                }
                for c in cards
            ]
            return 200, {"peers": catalog}, {}

        request_id = body.get("request_id")
        use_converged = bool(body.get("use_converged_multiparent", False))

        # Check OAuth 2.0 active request / converged inbox first when request_id is req-oauth-* or LCT inbox empty
        if not use_converged and isinstance(request_id, str) and request_id.startswith("req-oauth-"):
            oauth_ctx = self.oauth_active_requests.get(request_id)
            if oauth_ctx is None:
                return 404, {"error": "unknown_or_expired_request_id"}, {}
            return self._handle_outbound_oauth_proxy_call(
                action=action,
                body=body,
                delegation_mode=oauth_ctx.delegation_mode,
                subject_token=oauth_ctx.access_token,
                task_id=oauth_ctx.task_id,
                converged_payloads={},
            )

        active_tok: LineageToken | MultiParentToken | CoAuthorizedToken
        converged_payloads: Dict[str, dict] = {}
        if use_converged:
            task_id = str(body["task_id"])
            sub = str(body["sub"])
            try:
                active_tok, converged_payloads = (
                    self.convergence_inbox.assemble_multiparent_token(
                        holder_identity=self.identity,
                        task_id=task_id,
                        sub=sub,
                    )
                )
            except (KeyError, TokenError) as exc:
                oauth_conv = self.oauth_convergence_inbox.get_latest_token_and_payloads(
                    task_id, sub
                )
                if oauth_conv is not None:
                    o_mode, o_tok, o_payloads = oauth_conv
                    return self._handle_outbound_oauth_proxy_call(
                        action=action,
                        body=body,
                        delegation_mode=o_mode,
                        subject_token=o_tok,
                        task_id=task_id,
                        converged_payloads=o_payloads,
                    )
                return (
                    400,
                    {"error": "convergence_assembly_failed", "detail": str(exc)},
                    {},
                )
        else:
            if not request_id:
                return 400, {"error": "missing_request_id"}, {}
            ctx = self.active_requests.get(str(request_id))
            if ctx is None:
                return 404, {"error": "unknown_or_expired_request_id"}, {}
            active_tok = ctx.parsed_token

        raw_owner_consent = str(body.get("owner_consent_token") or "").strip()
        if raw_owner_consent:
            if not isinstance(active_tok, LineageToken):
                return 400, {"error": "co_authorization_requires_single_chain_requester"}, {}
            try:
                parsed_consent = decode_token(raw_owner_consent)
                if not isinstance(parsed_consent, LineageToken):
                    raise TokenError("owner_consent_token must be a single-chain LineageToken")
                self.verifier.verify_single_chain_full(parsed_consent, check_revocation=True)
                active_tok = CoAuthorizedToken.assemble_and_sign(
                    holder_identity=self.identity,
                    requester_chain=active_tok,
                    owner_consent_chain=parsed_consent,
                )
            except TokenExpiredError as exc:
                return 401, {"error": "TASK_AUTH_EXPIRED", "detail": str(exc)}, {}
            except Exception as exc:
                return 403, {"error": "co_authorization_assembly_failed", "detail": str(exc)}, {}

        # Action 1: Direct Tool Invocation (or Converged MultiParent Tool Invocation)
        if action == "call_tool":
            raw_target_url = str(body.get("target_url") or "").strip()
            req_skill = str(body.get("required_skill") or "").strip()
            eff_spiffe_id: Optional[str] = (
                str(body["target_spiffe_id"]).strip()
                if body.get("target_spiffe_id")
                else None
            )
            eff_trust_domain: Optional[str] = (
                str(body["target_trust_domain"]).strip()
                if body.get("target_trust_domain")
                else None
            )
            candidate_urls: List[str] = []
            if raw_target_url:
                candidate_urls = [_validate_outbound_target_url(raw_target_url)]
            elif self.directory_client is not None and (req_skill or eff_spiffe_id):
                mcp_path = str(body.get("mcp_path") or "/mcp").strip() or "/mcp"
                tool_card: Optional[AgentCard] = None
                if eff_spiffe_id:
                    tool_card = self.directory_client.get_agent(eff_spiffe_id)
                if tool_card is None and req_skill:
                    found_tools = self.directory_client.discover(
                        skill=req_skill,
                        trust_domain=eff_trust_domain,
                        only_healthy=True,
                    )
                    if found_tools:
                        tool_card = found_tools[0]
                if tool_card is None:
                    return (
                        404,
                        {
                            "error": "mcp_tool_server_not_found",
                            "required_skill": req_skill,
                            "target_spiffe_id": eff_spiffe_id,
                        },
                        {},
                    )
                eff_spiffe_id = tool_card.spiffe_id
                eff_trust_domain = tool_card.trust_domain
                for orig in tool_card.candidate_origins():
                    candidate_urls.append(
                        _validate_outbound_target_url(
                            f"{orig.rstrip('/')}{mcp_path}",
                            expected_origin=orig,
                        )
                    )
            else:
                return 400, {"error": "missing_target_url_or_skill"}, {}

            timeout_val = _require_finite_timeout(body.get("timeout"), 60.0)
            payload = body.get("payload") or {}
            compact_out = active_tok.encode_compact()
            primary_tool_url = candidate_urls[0]
            tool_idem_key = str(body.get("idempotency_key") or "").strip()
            if not tool_idem_key and body.get("logical_branch_id"):
                tool_idem_key = compute_branch_idempotency_key(
                    active_tok.task_id, str(body["logical_branch_id"])
                )

            resolved_tool_ip = _resolve_target_peer_ip(primary_tool_url)
            if self.audit_emitter is not None:
                if isinstance(active_tok, LineageToken):
                    self.audit_emitter.emit(
                        event_type=AuditEventType.OUTBOUND_DELEGATE,
                        task_id=active_tok.task_id,
                        sub=active_tok.sub,
                        lineage_path=active_tok.lineage_path,
                        hop_index=active_tok.depth,
                        epoch=active_tok.current_epoch,
                        root_block_hash=active_tok.root_block_hash,
                        parent_block_hash=active_tok.parent_block_hash,
                        current_block_hash=active_tok.leaf_block_hash,
                        permissions_summary=active_tok.leaf_permissions.to_dict(),
                        action_detail={
                            "action": "call_tool",
                            "target_spiffe_id": eff_spiffe_id,
                            "target_url": primary_tool_url,
                            "resolved_peer_ip": resolved_tool_ip,
                            **({"branch_idempotency_key": tool_idem_key} if tool_idem_key else {}),
                        },
                        decision="ALLOW",
                    )
                else:
                    mp_action_detail: Dict[str, Any] = {
                        "action": (
                            "call_tool_coauthorized"
                            if isinstance(active_tok, CoAuthorizedToken)
                            else "call_tool_multiparent"
                        ),
                        "target_spiffe_id": eff_spiffe_id,
                        "target_url": primary_tool_url,
                        "branch_count": len(active_tok.parent_chains),
                        "resolved_peer_ip": resolved_tool_ip,
                    }
                    if isinstance(active_tok, CoAuthorizedToken):
                        mp_action_detail["co_authorized_principals"] = list(
                            active_tok.co_authorized_principals
                        )
                    if tool_idem_key:
                        mp_action_detail["branch_idempotency_key"] = tool_idem_key
                    self.audit_emitter.emit(
                        event_type=AuditEventType.OUTBOUND_DELEGATE,
                        task_id=active_tok.task_id,
                        sub=active_tok.sub,
                        lineage_path="|".join(active_tok.lineage_paths),
                        hop_index=max(c.depth for c in active_tok.parent_chains),
                        epoch=max(c.current_epoch for c in active_tok.parent_chains),
                        root_block_hash=active_tok.parent_chains[0].root_block_hash,
                        parent_block_hash=None,
                        current_block_hash=active_tok.envelope_hash,
                        multi_parent_hashes=tuple(
                            c.leaf_block_hash for c in active_tok.parent_chains
                        ),
                        action_detail=mp_action_detail,
                        decision="ALLOW",
                    )

            resp: Optional[httpx.Response] = None
            last_tool_exc: Optional[Exception] = None
            for idx, target_url in enumerate(candidate_urls):
                dpop = create_dpop_proof(
                    signer=self.identity,
                    htm="POST",
                    htu=target_url,
                    access_token=compact_out,
                )
                eff_to = (
                    httpx.Timeout(connect=2.5, read=timeout_val, write=10.0, pool=5.0)
                    if idx + 1 < len(candidate_urls)
                    else timeout_val
                )
                tool_hdrs = {
                    "Authorization": f"DPoP {compact_out}",
                    "DPoP": dpop,
                }
                if tool_idem_key:
                    tool_hdrs["X-LCT-Idempotency-Key"] = tool_idem_key
                try:
                    with httpx.Client(
                        verify=self._outbound_verify_kwarg(
                            target_url=target_url,
                            expected_trust_domain=eff_trust_domain,
                            expected_spiffe_id=eff_spiffe_id,
                        ),
                        timeout=eff_to,
                        follow_redirects=False,
                        trust_env=False,
                    ) as client:
                        resp = client.post(
                            target_url,
                            json=payload,
                            headers=tool_hdrs,
                        )
                    break
                except httpx.HTTPError as exc:
                    last_tool_exc = exc
                    continue

            if resp is None:
                return (
                    502,
                    {"error": "upstream_transport_error", "detail": str(last_tool_exc)},
                    {},
                )
            try:
                parsed_up_body = resp.json()
            except Exception:
                parsed_up_body = {
                    "error": "upstream_non_json_response",
                    "status_code": resp.status_code,
                    "detail": (resp.text or "")[:256],
                }
            return (
                resp.status_code,
                {
                    "upstream_status": resp.status_code,
                    "upstream_body": parsed_up_body,
                    "converged_branch_payloads": converged_payloads,
                    "target_spiffe_id": eff_spiffe_id,
                    "resolved_locator": str(resp.request.url),
                },
                {},
            )

        # Action 2: Attenuated Agent-to-Agent Delegation (`[MEDIUM-03]`, `[MEDIUM-M2-02]`)
        if action == "delegate_agent":
            perms_raw = body.get("permissions")
            explicit_perms = (
                PermissionLattice.from_dict(perms_raw)
                if isinstance(perms_raw, Mapping)
                else None
            )
            payload = body.get("payload") or {}
            raw_task_path = str(body.get("task_path", "/a2a/task"))
            norm_tp_path, norm_tp_query = validate_origin_form_target(raw_task_path)
            task_path = norm_tp_path + (f"?{norm_tp_query}" if norm_tp_query else "")
            extra_del_headers: Dict[str, str] = {}
            if norm_tp_path in ("/", "/a2a") or body.get("a2a_v1"):
                extra_del_headers["A2A-Version"] = "1.0"

            if body.get("use_prune_and_graft") and isinstance(active_tok, LineageToken):
                if self.directory_client is None or self.revocation_replica is None:
                    return 500, {"error": "resilience_clients_not_configured"}, {}
                timeout_pg = _require_finite_timeout(body.get("timeout"), 1.5)
                coord = ResilientDelegationCoordinator(
                    identity=self.identity,
                    trust_resolver=self.trust_resolver,
                    directory_client=self.directory_client,
                    revocation_replica=self.revocation_replica,
                    audit_emitter=self.audit_emitter,
                    detector=self.detector,
                    return_endpoint=self.inbound_url,
                    client_ssl_context=self._client_ssl_ctx,
                    mtls_bundle=self._mtls_bundle,
                )
                primary_card = (
                    AgentCard.from_dict_and_verify(
                        body["primary_card"], self.trust_resolver
                    )
                    if "primary_card" in body and body["primary_card"]
                    else None
                )
                logical_br = str(
                    body.get("logical_branch_id")
                    or body.get("hop_segment")
                    or body.get("required_skill")
                ).strip()
                explicit_idem = str(body.get("idempotency_key") or "").strip() or None
                try:
                    res_json, final_tok, receipts = coord.invoke_with_prune_and_graft(
                        parent_token=active_tok,
                        required_skill=str(body["required_skill"]),
                        attenuated_permissions=explicit_perms
                        or active_tok.leaf_permissions,
                        task_payload=payload,
                        primary_card=primary_card,
                        task_path=task_path,
                        timeout_seconds=timeout_pg,
                        max_failovers=int(body.get("max_failovers", 2)),
                        extra_headers=extra_del_headers,
                        logical_branch_id=logical_br,
                        branch_idempotency_key=explicit_idem,
                    )
                except TokenExpiredError as exc:
                    exp_out: Dict[str, Any] = {
                        "error": "TASK_AUTH_EXPIRED",
                        "detail": str(exc),
                    }
                    saved_ck = self._task_checkpoints.get(
                        active_tok.task_id, expected_sub=active_tok.sub
                    )
                    if saved_ck:
                        exp_out["checkpoint"] = saved_ck[-1]
                    return 401, exp_out, {}
                except (ResilienceError, TokenError) as exc:
                    if isinstance(exc, TokenExpiredError) or "expired" in str(exc).lower():
                        exp_out_fallback: Dict[str, Any] = {
                            "error": "TASK_AUTH_EXPIRED",
                            "detail": str(exc),
                        }
                        saved_ck_f = self._task_checkpoints.get(
                            active_tok.task_id, expected_sub=active_tok.sub
                        )
                        if saved_ck_f:
                            exp_out_fallback["checkpoint"] = saved_ck_f[-1]
                        return 401, exp_out_fallback, {}
                    return (
                        502,
                        {"error": "prune_and_graft_failed", "detail": str(exc)},
                        {},
                    )

                eff_out_idem = explicit_idem or compute_branch_idempotency_key(
                    active_tok.task_id, logical_br
                )
                return (
                    200,
                    {
                        "upstream_status": 200,
                        "upstream_body": res_json,
                        "delegated_lineage_path": final_tok.lineage_path,
                        "epoch": final_tok.current_epoch,
                        "failover_occurred": len(receipts) > 0,
                        "branch_idempotency_key": eff_out_idem,
                        "failover_receipts": [r.to_dict() for r in receipts],
                    },
                    {},
                )

            timeout_del = _require_finite_timeout(body.get("timeout"), 60.0)
            del_candidate_urls: List[str] = []
            if (
                "delegate_spiffe_id" in body
                and "delegate_jkt" in body
                and "target_url" in body
            ):
                delegate_spiffe_id = str(body["delegate_spiffe_id"])
                delegate_jkt = str(body["delegate_jkt"])
                del_candidate_urls = [_validate_outbound_target_url(body["target_url"])]
            elif "required_skill" in body and self.directory_client is not None:
                excluded_visited: Set[str] = set()
                if isinstance(active_tok, LineageToken):
                    excluded_visited = set(active_tok.visited_subjects)
                else:
                    for ch in active_tok.parent_chains:
                        excluded_visited.update(ch.visited_subjects)
                cards = self.directory_client.discover(
                    skill=str(body["required_skill"]),
                    exclude_spiffe_ids=excluded_visited,
                    only_healthy=True,
                )
                if not cards:
                    return 404, {"error": "no_candidate_for_skill"}, {}
                chosen = cards[0]
                delegate_spiffe_id = chosen.spiffe_id
                delegate_jkt = chosen.jkt
                for orig in chosen.candidate_origins():
                    del_candidate_urls.append(
                        _validate_outbound_target_url(
                            f"{orig.rstrip('/')}{task_path}",
                            expected_origin=orig,
                        )
                    )
            else:
                return 400, {"error": "missing_delegate_target_or_skill"}, {}

            hop_seg = body.get("hop_segment")
            del_idem_key = str(body.get("idempotency_key") or "").strip()
            if not del_idem_key and (body.get("logical_branch_id") or hop_seg or body.get("required_skill")):
                del_idem_key = compute_branch_idempotency_key(
                    active_tok.task_id,
                    str(body.get("logical_branch_id") or hop_seg or body.get("required_skill")),
                )
            if del_idem_key:
                extra_del_headers["X-LCT-Idempotency-Key"] = del_idem_key
            try:
                if isinstance(active_tok, LineageToken):
                    out_tok: LineageToken | MultiParentToken | CoAuthorizedToken = active_tok.attenuate(
                        issuer_identity=self.identity,
                        delegate_spiffe_id=delegate_spiffe_id,
                        delegate_jkt=delegate_jkt,
                        permissions=explicit_perms or active_tok.leaf_permissions,
                        hop_segment=str(hop_seg) if hop_seg else None,
                        issuer_return_endpoint=self.inbound_url,
                    )
                else:
                    out_tok = active_tok.attenuate_to_delegate(
                        issuer_identity=self.identity,
                        delegate_spiffe_id=delegate_spiffe_id,
                        delegate_jkt=delegate_jkt,
                        requested_permissions=explicit_perms,
                        hop_segment=str(hop_seg) if hop_seg else None,
                        issuer_return_endpoint=self.inbound_url,
                    )
            except TokenExpiredError as exc:
                exp_out2: Dict[str, Any] = {"error": "TASK_AUTH_EXPIRED", "detail": str(exc)}
                saved_ck2 = self._task_checkpoints.get(
                    active_tok.task_id, expected_sub=active_tok.sub
                )
                if saved_ck2:
                    exp_out2["checkpoint"] = saved_ck2[-1]
                return 401, exp_out2, {}
            except TokenError as exc:
                return 403, {"error": "attenuation_rejected", "detail": str(exc)}, {}

            compact_out = out_tok.encode_compact()
            primary_del_url = del_candidate_urls[0]

            resolved_del_ip = _resolve_target_peer_ip(primary_del_url)
            if self.audit_emitter is not None:
                if isinstance(out_tok, LineageToken):
                    self.audit_emitter.emit(
                        event_type=AuditEventType.OUTBOUND_DELEGATE,
                        task_id=out_tok.task_id,
                        sub=out_tok.sub,
                        lineage_path=out_tok.lineage_path,
                        hop_index=out_tok.depth,
                        epoch=out_tok.current_epoch,
                        root_block_hash=out_tok.root_block_hash,
                        parent_block_hash=out_tok.parent_block_hash,
                        current_block_hash=out_tok.leaf_block_hash,
                        permissions_summary=out_tok.leaf_permissions.to_dict(),
                        action_detail={
                            "delegate_spiffe_id": delegate_spiffe_id,
                            "target_url": primary_del_url,
                            "resolved_peer_ip": resolved_del_ip,
                            **({"branch_idempotency_key": del_idem_key} if del_idem_key else {}),
                        },
                        decision="ALLOW",
                    )
                else:
                    co_principals_meta = (
                        list(out_tok.co_authorized_principals)
                        if isinstance(out_tok, CoAuthorizedToken)
                        else []
                    )
                    for ch in out_tok.parent_chains:
                        ch_detail: Dict[str, Any] = {
                            "delegate_spiffe_id": delegate_spiffe_id,
                            "target_url": primary_del_url,
                            "resolved_peer_ip": resolved_del_ip,
                        }
                        if co_principals_meta:
                            ch_detail["co_authorized_principals"] = co_principals_meta
                        if del_idem_key:
                            ch_detail["branch_idempotency_key"] = del_idem_key
                        self.audit_emitter.emit(
                            event_type=AuditEventType.OUTBOUND_DELEGATE,
                            task_id=ch.task_id,
                            sub=ch.sub,
                            lineage_path=ch.lineage_path,
                            hop_index=ch.depth,
                            epoch=ch.current_epoch,
                            root_block_hash=ch.root_block_hash,
                            parent_block_hash=ch.parent_block_hash,
                            current_block_hash=ch.leaf_block_hash,
                            permissions_summary=ch.leaf_permissions.to_dict(),
                            action_detail=ch_detail,
                            decision="ALLOW",
                        )

            resp_del: Optional[httpx.Response] = None
            last_del_exc: Optional[Exception] = None
            for idx, target_url in enumerate(del_candidate_urls):
                dpop = create_dpop_proof(
                    signer=self.identity,
                    htm="POST",
                    htu=target_url,
                    access_token=compact_out,
                )
                del_headers = {
                    "Authorization": f"DPoP {compact_out}",
                    "DPoP": dpop,
                    **extra_del_headers,
                }
                eff_to = (
                    httpx.Timeout(connect=2.5, read=timeout_del, write=10.0, pool=5.0)
                    if idx + 1 < len(del_candidate_urls)
                    else timeout_del
                )
                try:
                    with httpx.Client(
                        verify=self._outbound_verify_kwarg(
                            target_url=target_url,
                            expected_spiffe_id=delegate_spiffe_id,
                        ),
                        timeout=eff_to,
                        follow_redirects=False,
                        trust_env=False,
                    ) as client:
                        resp_del = client.post(
                            target_url,
                            json=payload,
                            headers=del_headers,
                        )
                    break
                except httpx.HTTPError as exc:
                    last_del_exc = exc
                    continue

            if resp_del is None:
                return (
                    502,
                    {"error": "upstream_transport_error", "detail": str(last_del_exc)},
                    {},
                )
            return (
                resp_del.status_code,
                {
                    "upstream_status": resp_del.status_code,
                    "upstream_body": resp_del.json(),
                    "delegate_spiffe_id": delegate_spiffe_id,
                    "resolved_locator": str(resp_del.request.url),
                },
                {},
            )

        # Action 3: Upward Return with Automatic Skip-Level Fallback
        if action == "return_result":
            if not isinstance(active_tok, LineageToken):
                return 400, {"error": "skip_level_requires_single_chain"}, {}
            if self.directory_client is None or self.revocation_replica is None:
                return 500, {"error": "resilience_clients_not_configured"}, {}
            timeout_ret = _require_finite_timeout(
                body.get("timeout"), 1.2, max_val=30.0
            )
            sim_unreach = bool(body.get("simulate_direct_parent_unreachable", False))
            if sim_unreach and not fault_injection_enabled:
                return (
                    403,
                    {
                        "error": "fault_injection_disabled",
                        "detail": "simulate_direct_parent_unreachable requires LCT_ENABLE_FAULT_INJECTION=true",
                    },
                    {},
                )
            coord = ResilientDelegationCoordinator(
                identity=self.identity,
                trust_resolver=self.trust_resolver,
                directory_client=self.directory_client,
                revocation_replica=self.revocation_replica,
                audit_emitter=self.audit_emitter,
                detector=self.detector,
                return_endpoint=self.inbound_url,
                client_ssl_context=self._client_ssl_ctx,
                mtls_bundle=self._mtls_bundle,
            )
            try:
                outcome = coord.return_result_with_skip_level_fallback(
                    child_token=active_tok,
                    result_payload=body.get("result_payload") or {},
                    direct_parent_return_url=body.get("direct_parent_return_url"),
                    timeout_seconds=timeout_ret,
                    simulate_direct_parent_unreachable=sim_unreach,
                )
            except ResilienceError as exc:
                return 502, {"error": "upward_return_failed", "detail": str(exc)}, {}
            return 200, outcome, {}

        # Action 4: Cascading Subtree/Full-Chain Revocation (used by A2A v1.0 `CancelTask`)
        if action == "revoke_subtree":
            if not isinstance(active_tok, LineageToken):
                return 400, {"error": "revoke_subtree_requires_single_chain"}, {}
            if self.revocation_replica is None:
                return 500, {"error": "revocation_replica_not_configured"}, {}
            target_prefix = str(body.get("prefix") or active_tok.lineage_path).strip()
            reason = str(body.get("reason") or "a2a_cancel_task")
            try:
                rev_ev = self.revocation_replica.revoke_prefix(
                    caller=self.identity,
                    prefix=target_prefix,
                    reason=reason,
                    authority_token=active_tok.encode_compact(),
                )
            except Exception as exc:
                return 403, {"error": "cascade_revocation_failed", "detail": str(exc)}, {}

            if self.audit_emitter is not None:
                self.audit_emitter.emit(
                    event_type=AuditEventType.REVOCATION_ISSUED,
                    task_id=active_tok.task_id,
                    sub=active_tok.sub,
                    lineage_path=target_prefix,
                    hop_index=active_tok.depth,
                    epoch=active_tok.current_epoch,
                    root_block_hash=active_tok.root_block_hash,
                    parent_block_hash=active_tok.parent_block_hash,
                    current_block_hash=active_tok.leaf_block_hash,
                    action_detail={
                        "target": rev_ev.target,
                        "revocation_version": (
                            rev_ev.origin_version
                            if rev_ev.origin_version is not None
                            else rev_ev.version
                        ),
                        "reason": reason,
                        "trust_domain": rev_ev.trust_domain,
                    },
                    decision="REVOKED",
                )
            return 200, {"revoked": True, "event": rev_ev.to_dict()}, {}

        return 400, {"error": f"unsupported_proxy_action:{action}"}, {}


class MCPToolSidecarNode:
    """Complete MCP Tool HTTP Server + Paired `LineageSidecar` (loopback isolated)."""

    def __init__(
        self,
        identity: WorkloadIdentity,
        trust_resolver: TrustBundleResolver,
        tools: Mapping[
            str, Callable[[Mapping[str, Any], HTTPRequestContext], Dict[str, Any]]
        ],
        mode: VerificationMode = VerificationMode.ADAPTIVE_RISK_ANCHORED,
        revocation_url: Optional[str] = None,
        audit_collector_url: Optional[str] = None,
        risk_classifier: Optional[RiskClassifier] = None,
        inbound_port: int = 0,
        delegation_mode: str = "lct",
        oauth_central_verifier: Optional[Any] = None,
        oauth_local_verifier: Optional[Any] = None,
    ) -> None:
        self.identity = identity
        self.tools = dict(tools)
        self._loopback_secret = secrets.token_urlsafe(32)

        self.app_http = ManagedHTTPService(
            service_name=f"mcp-app-{identity.parsed_spiffe.default_hop_segment}",
            dispatcher=self._dispatch_mcp_app,
            host="127.0.0.1",
            port=0,
        )
        app_url = self.app_http.start()

        rev_replica = (
            RevocationReplicaClient(revocation_url, trust_resolver)
            if revocation_url
            else None
        )
        audit_client = (
            AuditCollectorClient(audit_collector_url) if audit_collector_url else None
        )
        self.audit_emitter = AuditStreamEmitter(
            signer=identity, collector_client=audit_client
        )

        self.sidecar = LineageSidecar(
            identity=identity,
            trust_resolver=trust_resolver,
            app_upstream_url=app_url,
            loopback_secret=self._loopback_secret,
            mode=mode,
            revocation_replica=rev_replica,
            audit_emitter=self.audit_emitter,
            risk_classifier=risk_classifier,
            is_tool_server=True,
            inbound_port=inbound_port,
            delegation_mode=delegation_mode,
            oauth_central_verifier=oauth_central_verifier,
            oauth_local_verifier=oauth_local_verifier,
        )

    def start(self) -> str:
        in_url, _ = self.sidecar.start()
        return in_url

    def stop(self) -> None:
        self.sidecar.stop()
        self.app_http.stop()

    @property
    def mcp_url(self) -> str:
        return f"{self.sidecar.inbound_url}/mcp"

    @property
    def direct_app_url(self) -> str:
        return f"{self.app_http.base_url}/mcp"

    def _dispatch_mcp_app(
        self, req: HTTPRequestContext
    ) -> Tuple[int, Any, Dict[str, str]]:
        if not _constant_time_secret_match(
            req.header("X-LCT-Loopback-Auth"), self._loopback_secret
        ):
            return (
                403,
                {
                    "error": "direct_bypass_blocked",
                    "detail": "Direct access to local MCP app port is forbidden",
                },
                {},
            )

        body = req.json()
        method = str(body.get("method", "tools/call"))
        req_id = body.get("id", 1)

        if method == "initialize":
            return (
                200,
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "serverInfo": {"name": self.identity.spiffe_id},
                    },
                },
                {},
            )

        if method == "tools/list":
            return (
                200,
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": [{"name": k} for k in sorted(self.tools.keys())]
                    },
                },
                {},
            )

        if method == "tools/call":
            params = body.get("params") or {}
            tname = str(params.get("name", ""))
            targs = params.get("arguments") or {}
            fn = self.tools.get(tname)
            if fn is None:
                return (
                    404,
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": f"Unknown tool {tname!r}",
                    },
                    {},
                )
            output = fn(targs, req)
            return (
                200,
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": False,
                        "task_id": req.header("X-LCT-Task-Id"),
                        "sub": req.header("X-LCT-Sub"),
                        "lineage_path": req.header("X-LCT-Lineage-Path"),
                        "decision": req.header("X-LCT-Decision"),
                        "data": output,
                    },
                },
                {},
            )

        return 400, {"error": f"Unsupported MCP method {method!r}"}, {}


class AgentSidecarNode:
    """Complete Business Agent HTTP Server + Paired `LineageSidecar` + Signed Registration."""

    def __init__(
        self,
        identity: WorkloadIdentity,
        trust_resolver: TrustBundleResolver,
        name: str,
        skills: Iterable[str],
        handler: Callable[
            ["AgentSidecarNode", HTTPRequestContext, Dict[str, Any]],
            Tuple[int, Dict[str, Any]],
        ],
        directory_url: Optional[str] = None,
        revocation_url: Optional[str] = None,
        audit_collector_url: Optional[str] = None,
        mode: VerificationMode = VerificationMode.ADAPTIVE_RISK_ANCHORED,
        priority: int = 100,
        inbound_port: int = 0,
        delegation_mode: str = "lct",
        oauth_central_verifier: Optional[Any] = None,
        oauth_local_verifier: Optional[Any] = None,
        oauth_exchange_client: Optional[Any] = None,
        oauth_central_sts_origins_provider: Optional[Callable[[], Sequence[str]]] = None,
        oauth_domain_sts_origins_provider: Optional[Callable[[str], Sequence[str]]] = None,
    ) -> None:
        self.identity = identity
        self.name = name
        self.skills = tuple(skills)
        self._handler = handler
        self.priority = priority
        self._loopback_secret = secrets.token_urlsafe(32)

        self.app_http = ManagedHTTPService(
            service_name=f"agent-app-{identity.parsed_spiffe.default_hop_segment}",
            dispatcher=self._dispatch_agent_app,
            host="127.0.0.1",
            port=0,
        )
        app_url = self.app_http.start()

        self.revocation_replica = (
            RevocationReplicaClient(revocation_url, trust_resolver)
            if revocation_url
            else None
        )
        self.directory_client = (
            AgentDirectoryClient(directory_url, trust_resolver)
            if directory_url
            else None
        )
        audit_client = (
            AuditCollectorClient(audit_collector_url) if audit_collector_url else None
        )
        self.audit_emitter = AuditStreamEmitter(
            signer=identity, collector_client=audit_client
        )

        self.sidecar = LineageSidecar(
            identity=identity,
            trust_resolver=trust_resolver,
            app_upstream_url=app_url,
            loopback_secret=self._loopback_secret,
            mode=mode,
            revocation_replica=self.revocation_replica,
            directory_client=self.directory_client,
            audit_emitter=self.audit_emitter,
            is_tool_server=False,
            inbound_port=inbound_port,
            delegation_mode=delegation_mode,
            oauth_central_verifier=oauth_central_verifier,
            oauth_local_verifier=oauth_local_verifier,
            oauth_exchange_client=oauth_exchange_client,
            oauth_central_sts_origins_provider=oauth_central_sts_origins_provider,
            oauth_domain_sts_origins_provider=oauth_domain_sts_origins_provider,
        )

    def start(self, register_in_directory: bool = True) -> AgentCard:
        in_url, _ = self.sidecar.start()
        card = AgentCard.sign_and_create(
            identity=self.identity,
            name=self.name,
            endpoint=in_url,
            return_endpoint=in_url,
            skills=self.skills,
            priority=self.priority,
        )
        self.sidecar.set_agent_card(card)
        if register_in_directory and self.directory_client is not None:
            self.directory_client.register(card)
        return card

    def stop(self) -> None:
        self.sidecar.stop()
        self.app_http.stop()

    @property
    def endpoint(self) -> str:
        return self.sidecar.inbound_url

    def sidecar_call_tool(
        self,
        request_id: str,
        target_mcp_url: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        method: str = "tools/call",
        target_spiffe_id: Optional[str] = None,
        target_trust_domain: Optional[str] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        """Invoke an MCP tool strictly through the local outbound `LineageSidecar`."""
        call_json: Dict[str, Any] = {
            "action": "call_tool",
            "request_id": request_id,
            "target_url": target_mcp_url,
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": {"name": tool_name, "arguments": dict(arguments)},
            },
        }
        if target_spiffe_id:
            call_json["target_spiffe_id"] = target_spiffe_id
        if target_trust_domain:
            call_json["target_trust_domain"] = target_trust_domain
        resp = httpx.post(
            f"{self.sidecar.outbound_url}/v1/proxy/call",
            headers={"X-LCT-Loopback-Auth": self._loopback_secret},
            json=call_json,
            timeout=10.0,
        )
        return resp.status_code, resp.json()

    def sidecar_call_tool_converged(
        self,
        task_id: str,
        sub: str,
        target_mcp_url: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        method: str = "tools/call",
    ) -> Tuple[int, Dict[str, Any]]:
        """Invoke an MCP tool using the assembled N-to-1 `MultiParentToken` for `(task_id, sub)`."""
        resp = httpx.post(
            f"{self.sidecar.outbound_url}/v1/proxy/call",
            headers={"X-LCT-Loopback-Auth": self._loopback_secret},
            json={
                "action": "call_tool",
                "use_converged_multiparent": True,
                "task_id": task_id,
                "sub": sub,
                "target_url": target_mcp_url,
                "payload": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": method,
                    "params": {"name": tool_name, "arguments": dict(arguments)},
                },
            },
            timeout=10.0,
        )
        return resp.status_code, resp.json()

    def sidecar_delegate(
        self,
        request_id: str,
        permissions: Optional[PermissionLattice],
        payload: Mapping[str, Any],
        target_card: Optional[AgentCard] = None,
        required_skill: Optional[str] = None,
        task_path: str = "/a2a/task",
        hop_segment: Optional[str] = None,
        use_prune_and_graft: bool = False,
        timeout: float = 3.0,
    ) -> Tuple[int, Dict[str, Any]]:
        """Delegate an attenuated sub-task to another Agent through local outbound Sidecar."""
        req_body: Dict[str, Any] = {
            "action": "delegate_agent",
            "request_id": request_id,
            "payload": dict(payload),
            "task_path": task_path,
            "use_prune_and_graft": use_prune_and_graft,
            "timeout": timeout,
        }
        if permissions is not None:
            req_body["permissions"] = permissions.to_dict()
        if hop_segment:
            req_body["hop_segment"] = hop_segment
        if required_skill:
            req_body["required_skill"] = required_skill
        if target_card is not None:
            if use_prune_and_graft:
                req_body["primary_card"] = target_card.to_dict()
            else:
                req_body["delegate_spiffe_id"] = target_card.spiffe_id
                req_body["delegate_jkt"] = target_card.jkt
                req_body["target_url"] = (
                    f"{target_card.endpoint.rstrip('/')}{task_path}"
                )

        resp = httpx.post(
            f"{self.sidecar.outbound_url}/v1/proxy/call",
            headers={"X-LCT-Loopback-Auth": self._loopback_secret},
            json=req_body,
            timeout=max(10.0, timeout * 4.0),
        )
        return resp.status_code, resp.json()

    def sidecar_return_result(
        self,
        request_id: str,
        result_payload: Mapping[str, Any],
        direct_parent_return_url: Optional[str] = None,
        timeout: float = 1.2,
    ) -> Tuple[int, Dict[str, Any]]:
        """Return sub-task result upward with automatic Authenticated Skip-Level fallback."""
        resp = httpx.post(
            f"{self.sidecar.outbound_url}/v1/proxy/call",
            headers={"X-LCT-Loopback-Auth": self._loopback_secret},
            json={
                "action": "return_result",
                "request_id": request_id,
                "result_payload": dict(result_payload),
                "direct_parent_return_url": direct_parent_return_url,
                "timeout": timeout,
            },
            timeout=10.0,
        )
        return resp.status_code, resp.json()

    def _dispatch_agent_app(
        self, req: HTTPRequestContext
    ) -> Tuple[int, Any, Dict[str, str]]:
        if not _constant_time_secret_match(
            req.header("X-LCT-Loopback-Auth"), self._loopback_secret
        ):
            return 403, {"error": "direct_bypass_blocked"}, {}
        req_id = str(req.header("X-LCT-Request-Id", ""))
        ctx = self.sidecar.active_requests.get(req_id)
        body = req.json() if req.body else {}
        if ctx is not None:
            with lineage_context_scope(ctx):
                status, out = self._handler(self, req, body)
        else:
            status, out = self._handler(self, req, body)
        return status, out, {}
