"""Milestone 3 In-Cluster Kubernetes + Host Ollama (`qwen2.5:3b`) E2E Verification Driver.

Executes inside `e2e-user-gateway` (`lineage-alpha`), validating:
1. Physically Autonomous 3-Domain Control Plane (`alpha-ca`, `beta-ca`, `payment-ca` +
   per-domain `*-directory` & `*-revocation` + keyless `audit-collector` in `lineage-ctrl`).
2. Full-Chain Bidirectional SPIFFE X.509-SVID mTLS 1.3 (`https://...:8443`, `ssl.CERT_REQUIRED`
   + Channel-Token Dual Binding).
3. Official A2A v1.0 Protocol Stack (`/.well-known/agent-card.json` + `/.well-known/agent.json`,
   `A2A-Version: 1.0`, JSON-RPC 2.0 `SendMessage`, `SendStreamingMessage` real-time SSE,
   `GetTask` tenant isolation, and `CancelTask` cross-3-domain cascading revocation).
4. Real `qwen2.5:3b` LLM multi-agent workflows, Downward Atomic Prune-and-Graft (2A & 2B),
   Upward Authenticated Skip-Level Return (3A & 3B), Online Fagin Multi-Parent DAG Smooth
   Degradation + Multi-User Concurrency (4), and 100% `CausalChainAuditor` Reconstruction (5).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hmac
import json
import os
import secrets
import socket
import ssl
import sys
import threading
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

import httpx

from lineage.a2a import A2AClient, Message, TaskState
from lineage.audit import AuditCollectorClient, CausalChainAuditor
from lineage.common.crypto import KeyPair, redact_sensitive, sha256_hex
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.common.mtls import WorkloadMTLSBundle, X509DomainAuthority
from lineage.federation import bootstrap_autonomous_workload, parse_domain_url_map
from lineage.k8s.bootstrap_services import (
    K8S_SA_TOKEN_PATH,
    _build_env_anchor_store,
    create_ca_pop_jws,
    resolve_sa_token_path,
)
from lineage.protocol import PermissionLattice, create_dpop_proof, decode_token
from lineage.registry import AgentCard, AgentDirectoryClient
from lineage.revocation import RevocationEvent, RevocationReplicaClient

ALPHA_CA_URL = os.environ.get(
    "ALPHA_CA_URL", "http://alpha-ca.lineage-alpha.svc.cluster.local:8090"
)
BETA_CA_URL = os.environ.get(
    "BETA_CA_URL", "http://beta-ca.lineage-beta.svc.cluster.local:8090"
)
PAYMENT_CA_URL = os.environ.get(
    "PAYMENT_CA_URL", "http://payment-ca.lineage-pay.svc.cluster.local:8090"
)
PEER_CA_SPEC = os.environ.get(
    "PEER_CA_URLS", f"org-beta.io={BETA_CA_URL},org-payment.io={PAYMENT_CA_URL}"
)

ALPHA_DIR_URL = os.environ.get(
    "ALPHA_DIR_URL", "http://alpha-directory.lineage-alpha.svc.cluster.local:8091"
)
ALPHA_REV_URL = os.environ.get(
    "ALPHA_REV_URL", "http://alpha-revocation.lineage-alpha.svc.cluster.local:8092"
)
BETA_REV_URL = os.environ.get(
    "BETA_REV_FED_URL", "http://beta-revocation.lineage-beta.svc.cluster.local:8092"
)
PAYMENT_REV_URL = os.environ.get(
    "PAYMENT_REV_FED_URL", "http://payment-revocation.lineage-pay.svc.cluster.local:8092"
)
AUDIT_URL = os.environ.get(
    "AUDIT_COLLECTOR_URL", "http://audit-collector.lineage-ctrl.svc.cluster.local:8093"
)

ORCH_URL = os.environ.get(
    "ORCH_URL", "https://orchestrator-alpha.lineage-alpha.svc.cluster.local:8443"
)
_orch_sp = urlsplit(ORCH_URL)
ORCH_HOST = _orch_sp.hostname or "orchestrator-alpha.lineage-alpha.svc.cluster.local"
ORCH_PORT = _orch_sp.port or 8443

FLIGHT_URL = os.environ.get(
    "FLIGHT_URL", "https://flight-specialist.lineage-beta.svc.cluster.local:8443"
)
HOTEL_PRIMARY_URL = os.environ.get(
    "HOTEL_PRIMARY_URL",
    "https://hotel-specialist-primary.lineage-beta.svc.cluster.local:8443",
)
HOTEL_BACKUP_URL = os.environ.get(
    "HOTEL_BACKUP_URL",
    "https://hotel-specialist-backup.lineage-beta.svc.cluster.local:8443",
)
CONVERGER_URL = os.environ.get(
    "CONVERGER_URL", "https://settlement-converger.lineage-pay.svc.cluster.local:8443"
)
TRAVEL_MCP_SVC_URL = os.environ.get(
    "TRAVEL_MCP_SVC_URL",
    "https://travel-ops-mcp.lineage-pay.svc.cluster.local:8443/mcp",
)
PAYMENT_MCP_SVC_URL = os.environ.get(
    "PAYMENT_MCP_SVC_URL",
    "https://payment-vault-mcp.lineage-pay.svc.cluster.local:8443/mcp",
)
SYNC_HOOK_URL = os.environ.get("SYNC_HOOK_URL", "")
OLLAMA_URL = os.environ.get("OLLAMA_BASE_URL", "http://host.docker.internal:11434/v1")


def _scrub_for_disk(obj: Any) -> Any:
    base = redact_sensitive(obj)
    if isinstance(base, dict):
        return {k: _scrub_for_disk(v) for k, v in base.items()}
    if isinstance(base, list):
        return [_scrub_for_disk(x) for x in base]
    if isinstance(base, str):
        if base.startswith(("lct1.", "lctmp1.", "lctm1.")):
            return f"[REDACTED_LCT_TOKEN_SHA256:{sha256_hex(base.encode('ascii'))[:12]}]"
        if base.startswith("eyJhbG") and base.count(".") == 2:
            return f"[REDACTED_JWS_SHA256:{sha256_hex(base.encode('ascii'))[:12]}]"
    return base


def _extract_a2a_task_data(rpc_body: Dict[str, Any]) -> Dict[str, Any]:
    if rpc_body.get("jsonrpc") != "2.0" or "result" not in rpc_body:
        raise AssertionError(f"Expected JSON-RPC 2.0 result, got: {rpc_body}")
    task = rpc_body["result"]["task"]
    msg = task.get("status", {}).get("message") or {}
    for p in msg.get("parts") or []:
        if isinstance(p, dict) and isinstance(p.get("data"), dict):
            return p["data"]
    for art in task.get("artifacts") or []:
        for p in art.get("parts") or []:
            if isinstance(p, dict) and isinstance(p.get("data"), dict):
                return p["data"]
    raise AssertionError(f"No structured DataPart found in A2A Task: {task}")


class GatewaySession:
    """Authenticated user-entry gateway inside `lineage-alpha` (`org-alpha.io`)."""

    def __init__(
        self,
        require_all_peers: bool = True,
        seed_bundles: Optional[Sequence[Mapping[str, Any]]] = None,
        peer_timeout: float = 3.0,
        max_wait_sec: float = 45.0,
    ) -> None:
        self._sa_token_file = resolve_sa_token_path(K8S_SA_TOKEN_PATH)
        with open(self._sa_token_file, "r", encoding="utf-8") as fh:
            self.sa_jwt = fh.read().strip()
        anchor_store, require_pins = _build_env_anchor_store()
        svid_ttl = max(
            6.0, float(os.environ.get("LCT_SVID_TTL_SECONDS", "1800.0").strip() or "1800.0")
        )
        (
            self.identity,
            self.resolver,
            self.mtls_bundle,
            self.syncer,
        ) = bootstrap_autonomous_workload(
            ALPHA_CA_URL,
            parse_domain_url_map(PEER_CA_SPEC),
            max_wait_sec=max_wait_sec,
            require_all_peers=require_all_peers,
            seed_bundles=seed_bundles,
            peer_timeout=peer_timeout,
            svid_ttl_seconds=svid_ttl,
            anchor_store=anchor_store,
            require_pinned_anchors=require_pins,
            audit_ca_url=(AUDIT_URL if AUDIT_URL.startswith("https://") else None),
            enable_auto_renewal=True,
        )
        self.ssl_ctx = self.mtls_bundle.build_client_ssl_context(check_hostname=True)
        self.dir_client = AgentDirectoryClient(ALPHA_DIR_URL, self.resolver)
        self.rev_client = RevocationReplicaClient(ALPHA_REV_URL, self.resolver)
        self.audit_client = AuditCollectorClient(
            AUDIT_URL,
            signer=self.identity,
            ssl_context_provider=(
                self.syncer.audit_ssl_context if AUDIT_URL.startswith("https://") else None
            ),
        )
        self.a2a_orch = A2AClient(
            agent_base_url=ORCH_URL,
            signer=self.identity,
            mtls_bundle=self.mtls_bundle,
            expected_trust_domain="org-alpha.io",
            rpc_path="/a2a",
            timeout=95.0,
        )

    def _fresh_sa_jwt(self) -> str:
        with open(self._sa_token_file, "r", encoding="utf-8") as fh:
            self.sa_jwt = fh.read().strip()
        return self.sa_jwt

    def a2a_client_for(self, base_url: str, rpc_path: str = "/a2a", timeout: float = 90.0) -> A2AClient:
        return A2AClient(
            agent_base_url=base_url,
            signer=self.identity,
            mtls_bundle=self.mtls_bundle,
            rpc_path=rpc_path,
            timeout=timeout,
        )

    def get_orchestrator_card(self) -> AgentCard:
        cards = self.dir_client.discover(skill="travel.orchestrate", only_healthy=True)
        if not cards:
            raise RuntimeError("No healthy orchestrator-alpha card registered in alpha-directory")
        return cards[0]

    def mint_root_for_user(
        self,
        task_id: str,
        sub: str,
        permissions: PermissionLattice,
        target_card: Optional[AgentCard] = None,
        hop_segment: str = "OrchestratorAlpha",
        max_depth: int = 6,
    ) -> Tuple[str, Dict[str, Any]]:
        card = target_card or self.get_orchestrator_card()
        resp = httpx.post(
            f"{ALPHA_CA_URL}/v1/ca/mint-root-token",
            json={
                "trust_domain": "org-alpha.io",
                "task_id": task_id,
                "sub": sub,
                "sender_jkt": self.identity.jkt,
                "first_hop_spiffe_id": card.spiffe_id,
                "first_hop_jkt": card.jkt,
                "first_hop_public_jwk": card.public_jwk,
                "first_hop_return_endpoint": card.return_endpoint,
                "permissions": permissions.to_dict(),
                "hop_segment": hop_segment,
                "max_depth": max_depth,
            },
            headers={"Authorization": f"Bearer {self._fresh_sa_jwt()}"},
            timeout=10.0,
        )
        resp.raise_for_status()
        meta = resp.json()
        return str(meta["compact_token"]), meta

    def emit_revocation_audit(
        self,
        task_id: str,
        sub: str,
        revocation_event: RevocationEvent,
        root_block_hash: str,
        current_block_hash: str,
    ) -> None:
        resp = httpx.post(
            f"{ALPHA_CA_URL}/v1/ca/emit-revocation-audit",
            json={
                "trust_domain": "org-alpha.io",
                "task_id": task_id,
                "sub": sub,
                "target_prefix": revocation_event.target,
                "root_block_hash": root_block_hash,
                "current_block_hash": current_block_hash,
                "revocation_version": (
                    revocation_event.origin_version
                    if revocation_event.origin_version is not None
                    else revocation_event.version
                ),
                "revocation_event": revocation_event.to_dict(),
            },
            headers={"Authorization": f"Bearer {self._fresh_sa_jwt()}"},
            timeout=10.0,
        )
        resp.raise_for_status()

    def get_mtls(self, url: str, timeout: float = 5.0) -> httpx.Response:
        with httpx.Client(
            verify=self.mtls_bundle.verify_for_target(target_url=url),
            timeout=timeout,
        ) as client:
            return client.get(url)

    def post_lct_mtls(
        self,
        endpoint_base: str,
        compact_token: str,
        payload: Dict[str, Any],
        path: str = "/a2a/task",
        timeout: float = 90.0,
    ) -> httpx.Response:
        url = f"{endpoint_base.rstrip('/')}{path}"
        dpop = create_dpop_proof(self.identity, "POST", url, compact_token)
        with httpx.Client(
            verify=self.mtls_bundle.verify_for_target(target_url=url),
            timeout=timeout,
        ) as client:
            return client.post(
                url,
                json=payload,
                headers={
                    "Authorization": f"DPoP {compact_token}",
                    "DPoP": dpop,
                },
            )


def _full_travel_root_permissions(cities: List[str], max_amount: float = 1000.0) -> PermissionLattice:
    return PermissionLattice.create(
        tools=[
            "search_flight",
            "book_flight",
            "search_hotel",
            "reserve_hotel",
            "execute_settlement",
            "record_itinerary_audit",
        ],
        max_amount=max_amount,
        allowed_targets=["airline-escrow", "hotel-escrow", "audit-ledger"],
        param_whitelist={"city": cities},
        max_calls=12,
    )


# =============================================================================
# Scenario Implementations
# =============================================================================


def run_scenario_1(gw: GatewaySession, run_id: str) -> Dict[str, Any]:
    # 0. Wait for kube-proxy ClusterIP DNAT rules across all `:8443` mTLS data-plane Services
    for svc_health in (
        f"{ORCH_URL}/healthz",
        f"{FLIGHT_URL}/healthz",
        f"{HOTEL_PRIMARY_URL}/healthz",
        f"{HOTEL_BACKUP_URL}/healthz",
        f"{CONVERGER_URL}/healthz",
        f"{TRAVEL_MCP_SVC_URL.rsplit('/mcp', 1)[0]}/healthz",
        f"{PAYMENT_MCP_SVC_URL.rsplit('/mcp', 1)[0]}/healthz",
    ):
        for _ in range(35):
            try:
                if gw.get_mtls(svc_health, timeout=2.0).status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(0.3)

    # 1. Verify Autonomous 3-Domain CA Physical Namespace Isolation:
    #    `e2e-user-gateway` (`lineage-alpha` SA JWT) MUST be rejected (`403`) by both `beta-ca` and `payment-ca`!
    sa_jwt = gw._fresh_sa_jwt()
    test_kp = KeyPair.generate("ES256")
    cross_ca_proofs: Dict[str, Any] = {}
    for foreign_name, foreign_url in (("beta-ca", BETA_CA_URL), ("payment-ca", PAYMENT_CA_URL)):
        r_for = httpx.post(
            f"{foreign_url}/v1/ca/issue-workload",
            json={
                "public_jwk": test_kp.public_jwk(),
                "pop_jws": create_ca_pop_jws(test_kp, sa_jwt),
            },
            headers={"Authorization": f"Bearer {sa_jwt}"},
            timeout=5.0,
        )
        if r_for.status_code != 403:
            raise AssertionError(
                f"Autonomous {foreign_name} failed to reject lineage-alpha SA JWT: {r_for.status_code} {r_for.text}"
            )
        cross_ca_proofs[foreign_name] = {
            "http_status": r_for.status_code,
            "error": r_for.json().get("error"),
            "detail": r_for.json().get("detail"),
        }

    # 2. Verify Bidirectional X.509 mTLS 1.3 Enforcement on `:8443`:
    #    (a) Client WITHOUT client X.509 certificate -> rejected at TLS handshake!
    no_client_cert_ctx = ssl.create_default_context(
        cadata=gw.mtls_bundle.trust_store.combined_ca_pem()
    )
    unauth_blocked = False
    unauth_err = ""
    try:
        with httpx.Client(verify=no_client_cert_ctx, timeout=3.0) as bad_cli:
            bad_cli.get(f"{ORCH_URL}/healthz")
    except Exception as exc:
        unauth_blocked = True
        unauth_err = f"{type(exc).__name__}: {exc}"
    if not unauth_blocked:
        raise AssertionError("Unauthenticated TLS client without X.509-SVID was not rejected on :8443!")

    #    (b) Client WITH rogue unfederated X.509 CA (`org-rogue.io`) -> rejected at TLS handshake!
    rogue_ca = X509DomainAuthority("org-rogue.io")
    rogue_kp = KeyPair.generate("ES256")
    rogue_leaf = rogue_ca.issue_x509_svid(
        "spiffe://org-rogue.io/ns/rogue/sa/intruder",
        rogue_kp.public_jwk(),
        dns_names=("intruder.org-rogue.io",),
    )
    rogue_bundle = WorkloadMTLSBundle(
        "spiffe://org-rogue.io/ns/rogue/sa/intruder",
        rogue_kp,
        rogue_leaf,
        gw.mtls_bundle.trust_store,
    )
    rogue_blocked = False
    rogue_err = ""
    try:
        with httpx.Client(verify=rogue_bundle.build_client_ssl_context(), timeout=3.0) as r_cli:
            r_cli.get(f"{ORCH_URL}/healthz")
    except Exception as exc:
        rogue_blocked = True
        rogue_err = f"{type(exc).__name__}: {exc}"
    if not rogue_blocked:
        raise AssertionError("Rogue unfederated X.509 client was not rejected on :8443!")

    #    (c) Authenticated TLS socket inspection -> confirm negotiated protocol == `TLSv1.3`!
    orch_pinned_ssl = gw.mtls_bundle.verify_for_target(
        target_url=ORCH_URL, expected_trust_domain="org-alpha.io"
    )
    with socket.create_connection((ORCH_HOST, ORCH_PORT), timeout=5.0) as raw_sock:
        with orch_pinned_ssl.wrap_socket(raw_sock, server_hostname=ORCH_HOST) as tls_sock:
            negotiated_tls_version = tls_sock.version()
            negotiated_cipher = tls_sock.cipher()
    if negotiated_tls_version != "TLSv1.3":
        raise AssertionError(f"Expected TLSv1.3, negotiated {negotiated_tls_version!r}")

    # 3. Verify Official A2A v1.0 Dual Discovery (`/.well-known/agent-card.json` & `/.well-known/agent.json`)
    card_v1, raw_card_v1 = gw.a2a_orch.fetch_agent_card(
        gw.resolver, "/.well-known/agent-card.json"
    )
    card_compat, raw_card_compat = gw.a2a_orch.fetch_agent_card(
        gw.resolver, "/.well-known/agent.json"
    )
    assert card_v1.spiffe_id == card_compat.spiffe_id
    assert raw_card_v1["protocolVersion"] == "1.0"
    assert raw_card_v1["url"] == ORCH_URL
    assert raw_card_v1["capabilities"]["streaming"] is True
    assert "lct_dpop" in raw_card_v1["securitySchemes"]
    assert isinstance(raw_card_v1["skills"][0], dict)
    assert raw_card_compat["protocolVersion"] == "1.0"

    # 4. Verify Ollama `qwen2.5:3b` model endpoint inside Pod
    models_resp = httpx.get(f"{OLLAMA_URL}/models", timeout=10.0)
    models_resp.raise_for_status()
    model_ids = [m.get("id") for m in models_resp.json().get("data", [])]
    if "qwen2.5:3b" not in model_ids:
        raise AssertionError(f"qwen2.5:3b not found in Ollama models: {model_ids}")

    # 5. Verify all 5 cross-domain signed AgentCards converged in `alpha-directory` via federation peering!
    registered_spiffes: List[str] = []
    for _ in range(20):
        all_cards = gw.dir_client.discover(only_healthy=True)
        registered_spiffes = sorted(c.spiffe_id for c in all_cards)
        if len(registered_spiffes) >= 5:
            break
        time.sleep(0.4)
    if len(registered_spiffes) < 5:
        raise AssertionError(
            f"Expected >=5 federated cross-domain AgentCards in alpha-directory, got {registered_spiffes}"
        )

    # 6. Execute Official A2A v1.0 `SendStreamingMessage` (Real SSE `text/event-stream`)!
    task_id = f"task-k8s-s1-{run_id}"
    perms = _full_travel_root_permissions(["Tokyo"], max_amount=800.0)
    tok, _ = gw.mint_root_for_user(task_id, "user:alice@org-alpha.io", perms)

    sse_status, sse_ct, sse_events = gw.a2a_orch.send_streaming_message(
        message=Message.create_user(
            text=(
                "Book business travel to Tokyo for Alice with a flight budget up to 650 USD "
                "and a hotel budget up to 420 USD, then complete split escrow settlement."
            ),
            data={"op": "plan_and_execute_trip"},
            task_id=task_id,
        ),
        compact_token=tok,
    )
    if sse_status != 200 or "text/event-stream" not in sse_ct.lower():
        raise AssertionError(
            f"A2A SendStreamingMessage failed ({sse_status}, ct={sse_ct}): {sse_events}"
        )

    observed_states = [
        ev["result"]["statusUpdate"]["status"]["state"]
        for ev in sse_events
        if "result" in ev and "statusUpdate" in ev["result"]
    ]
    artifact_updates = [
        ev["result"]["artifactUpdate"]
        for ev in sse_events
        if "result" in ev and "artifactUpdate" in ev["result"]
    ]
    assert TaskState.SUBMITTED.value in observed_states, observed_states
    assert TaskState.WORKING.value in observed_states, observed_states
    assert observed_states[-1] == TaskState.COMPLETED.value, observed_states
    assert sse_events[-1]["result"]["statusUpdate"]["final"] is True
    assert len(artifact_updates) >= 1, sse_events

    # 7. Official A2A v1.0 `GetTask` owner query (`200`) + Cross-Tenant Snooping Block (`403` `-32003`)!
    st_get, get_body = gw.a2a_orch.get_task(task_id, compact_token=tok)
    assert st_get == 200, get_body
    assert get_body["result"]["task"]["status"]["state"] == TaskState.COMPLETED.value
    assert len(get_body["result"]["task"]["artifacts"]) >= 1

    tok_snoop, _ = gw.mint_root_for_user(
        f"task-k8s-s1-snoop-{run_id}", "user:carol@org-alpha.io", perms
    )
    st_snoop, snoop_body = gw.a2a_orch.get_task(task_id, compact_token=tok_snoop)
    assert st_snoop == 403, snoop_body
    assert snoop_body["error"]["code"] == -32003, snoop_body

    # Also verify `POST /` standard root A2A JSON-RPC path works identically!
    root_path_cli = gw.a2a_client_for(ORCH_URL, rpc_path="/")
    st_root_get, root_get_body = root_path_cli.get_task(task_id, compact_token=tok)
    assert st_root_get == 200, root_get_body
    assert root_get_body["result"]["task"]["id"] == task_id

    data = _extract_a2a_task_data(get_body)
    flight_b = data["flight_branch"]["upstream_body"]["flight_booking"]
    hotel_r = data["hotel_branch"]["upstream_body"]["hotel_reservation"]
    conv_body = data["settlement_convergence"]["upstream_body"]
    completed_stl = conv_body["completed_settlements"]
    final_answer = str(conv_body["final_answer"])

    # Strict Grounding Verification: MCP JSON values <-> LLM answer & settlement amounts
    assert flight_b["flight_no"] == "NH-108", flight_b
    assert float(flight_b["charged_usd"]) == 580.0, flight_b
    assert hotel_r["hotel_id"] == "HTL-TYO-09", hotel_r
    assert float(hotel_r["charged_usd"]) == 360.0, hotel_r
    assert float(completed_stl["airline-escrow"]["settled_usd"]) == 580.0, completed_stl
    assert float(completed_stl["hotel-escrow"]["settled_usd"]) == 360.0, completed_stl
    assert completed_stl["airline-escrow"]["lineage_decision"] == "ALLOW"
    assert completed_stl["hotel-escrow"]["lineage_decision"] == "ALLOW"

    for expected_token in ("NH-108", "580", "360"):
        if expected_token not in final_answer:
            raise AssertionError(
                f"LLM final_answer missing grounded MCP value {expected_token!r}: {final_answer!r}"
            )

    return {
        "scenario": "1_a2a_v1_sse_autonomous_3domain_mtls13_and_llm_mcp_grounding",
        "status": "PASS",
        "task_id": task_id,
        "autonomous_ca_cross_namespace_rejections": cross_ca_proofs,
        "mtls_1_3_security_proofs": {
            "negotiated_protocol": negotiated_tls_version,
            "negotiated_cipher": list(negotiated_cipher) if negotiated_cipher else None,
            "no_client_cert_rejected": unauth_blocked,
            "no_client_cert_error": unauth_err,
            "rogue_unfederated_ca_rejected": rogue_blocked,
            "rogue_unfederated_ca_error": rogue_err,
        },
        "a2a_v1_agent_card_discovery": {
            "well_known_agent_card_url": f"{ORCH_URL}/.well-known/agent-card.json",
            "protocol_version": raw_card_v1["protocolVersion"],
            "capabilities": raw_card_v1["capabilities"],
            "security_schemes": list(raw_card_v1["securitySchemes"].keys()),
            "skills": raw_card_v1["skills"],
        },
        "a2a_v1_sse_streaming": {
            "content_type": sse_ct,
            "sse_frame_count": len(sse_events),
            "state_transitions_observed": observed_states,
            "artifact_update_count": len(artifact_updates),
            "cross_tenant_get_task_blocked_http": st_snoop,
            "cross_tenant_get_task_rpc_code": snoop_body["error"]["code"],
        },
        "ollama_models_seen": model_ids,
        "federated_registered_agents": registered_spiffes,
        "orchestrator_plan": data["orchestrator_plan"],
        "orchestrator_llm_trace": data["orchestrator_llm_trace"],
        "flight_llm_traces": data["flight_branch"]["upstream_body"]["llm_traces"],
        "hotel_llm_traces": data["hotel_branch"]["upstream_body"]["llm_traces"],
        "converger_llm_trace": conv_body["llm_trace"],
        "flight_booking_mcp": flight_b,
        "hotel_reservation_mcp": hotel_r,
        "completed_settlements_mcp": completed_stl,
        "final_answer": final_answer,
    }


def run_scenario_2a(gw: GatewaySession, run_id: str) -> Dict[str, Any]:
    task_id = f"task-k8s-s2a-{run_id}"
    perms = _full_travel_root_permissions(["Paris"], max_amount=800.0)
    tok, _ = gw.mint_root_for_user(task_id, "user:alice@org-alpha.io", perms)

    # Official A2A v1.0 `SendMessage`: Primary B2 stalls 10.0s (> hotel_timeout_sec=8.5s);
    # Orchestrator (`org-alpha.io`) prunes B2 at `alpha-revocation` (federated to `payment-revocation`!)
    # and grafts `hotel-specialist-backup` (`epoch=1`) over mTLS 1.3!
    st_rpc, rpc_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text=(
                "Book business travel to Paris for Alice with flight budget up to 600 USD "
                "and hotel budget up to 400 USD."
            ),
            data={
                "op": "plan_and_execute_trip",
                "hotel_timeout_sec": 8.5,
                "simulate_primary_zombie_delay_sec": 10.0,
            },
            task_id=task_id,
        ),
        compact_token=tok,
    )
    if st_rpc != 200:
        raise AssertionError(f"Scenario 2A A2A SendMessage failover failed ({st_rpc}): {rpc_body}")
    assert rpc_body["result"]["task"]["status"]["state"] == TaskState.COMPLETED.value

    data = _extract_a2a_task_data(rpc_body)
    hotel_out = data["hotel_branch"]
    assert hotel_out["epoch"] == 1, hotel_out
    assert len(hotel_out["failover_receipts"]) == 1, hotel_out
    assert hotel_out["upstream_body"]["instance_label"] == "backup", hotel_out

    # Query `hotel-specialist-primary` over mTLS 1.3 via A2A `SendMessage` to confirm its delayed
    # zombie call to `travel-ops-mcp` (`org-payment.io`) hit federated `403 LINEAGE_REVOKED`!
    primary_cards = [
        c
        for c in gw.dir_client.discover(skill="travel.hotel", only_healthy=False)
        if "primary" in c.spiffe_id
    ]
    assert primary_cards, "Primary hotel card not found"
    p_card = primary_cards[0]
    diag_tok, _ = gw.mint_root_for_user(
        f"task-k8s-s2a-diag-{run_id}",
        "user:alice@org-alpha.io",
        perms,
        target_card=p_card,
        hop_segment="DiagPrimary",
    )
    a2a_primary = gw.a2a_client_for(HOTEL_PRIMARY_URL)
    zombie_rec = None
    for _ in range(25):
        st_d, d_body = a2a_primary.send_message(
            message=Message.create_user(
                text="Inspect zombie telemetry",
                data={"op": "inspect_zombie_telemetry", "inspect_task_id": task_id},
            ),
            compact_token=diag_tok,
        )
        if st_d == 200:
            d_data = _extract_a2a_task_data(d_body)
            zombie_rec = d_data.get("zombie_telemetry")
            if zombie_rec is not None:
                break
        time.sleep(0.4)

    if zombie_rec is None:
        raise AssertionError("Primary zombie wakeup telemetry was not recorded")
    assert zombie_rec["zombie_mcp_http_status"] == 403, zombie_rec
    assert zombie_rec["zombie_mcp_body"].get("error") == "LINEAGE_REVOKED", zombie_rec

    return {
        "scenario": "2a_a2a_v1_atomic_prune_and_graft_plus_cross_domain_zombie_403_proof",
        "status": "PASS",
        "task_id": task_id,
        "a2a_task_state": rpc_body["result"]["task"]["status"]["state"],
        "grafted_epoch": hotel_out["epoch"],
        "grafted_lineage_path": hotel_out["delegated_lineage_path"],
        "handled_by_instance": hotel_out["upstream_body"]["instance_label"],
        "failover_receipt": hotel_out["failover_receipts"][0],
        "zombie_revocation_proof": zombie_rec,
        "final_answer": data["settlement_convergence"]["upstream_body"]["final_answer"],
    }


def run_scenario_2b(gw: GatewaySession, run_id: str) -> Dict[str, Any]:
    # Executed while `deployment/hotel-specialist-primary` is scaled to 0 replicas in K8s!
    task_id = f"task-k8s-s2b-{run_id}"
    perms = _full_travel_root_permissions(["Singapore"], max_amount=850.0)
    tok, _ = gw.mint_root_for_user(task_id, "user:alice@org-alpha.io", perms)

    st_rpc, rpc_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text=(
                "Book business travel to Singapore for Alice with flight budget up to 700 USD "
                "and hotel budget up to 450 USD."
            ),
            data={"op": "plan_and_execute_trip", "hotel_timeout_sec": 20.0},
            task_id=task_id,
        ),
        compact_token=tok,
    )
    if st_rpc != 200:
        raise AssertionError(
            f"Scenario 2B K8s pod-down failover failed ({st_rpc}): {rpc_body}"
        )
    assert rpc_body["result"]["task"]["status"]["state"] == TaskState.COMPLETED.value

    data = _extract_a2a_task_data(rpc_body)
    hotel_out = data["hotel_branch"]
    assert hotel_out["epoch"] == 1, hotel_out
    assert hotel_out["upstream_body"]["instance_label"] == "backup", hotel_out
    return {
        "scenario": "2b_a2a_v1_k8s_replicas_zero_crash_prune_and_graft",
        "status": "PASS",
        "task_id": task_id,
        "a2a_task_state": rpc_body["result"]["task"]["status"]["state"],
        "grafted_epoch": hotel_out["epoch"],
        "grafted_lineage_path": hotel_out["delegated_lineage_path"],
        "failover_fault_type": hotel_out["failover_receipts"][0]["failure_evidence"]["fault_type"],
        "final_answer": data["settlement_convergence"]["upstream_body"]["final_answer"],
    }


def run_scenario_3a(gw: GatewaySession, run_id: str) -> Dict[str, Any]:
    # Intermediate `hotel-specialist-primary` IS HEALTHY (`2/2 Running` on `:8443` mTLS).
    # Leaf `settlement-converger` (`org-payment.io`) attempts Skip-Level Return to
    # `orchestrator-alpha` (`org-alpha.io`) -> MUST BE REJECTED (`INTERMEDIATE_ANCESTOR_ALIVE`)
    # by `orchestrator-alpha`'s live mTLS `/healthz` probe!
    h_check = gw.get_mtls(f"{HOTEL_PRIMARY_URL}/healthz", timeout=3.0)
    assert h_check.status_code == 200, "hotel-specialist-primary must be healthy for Scenario 3A"

    task_id = f"task-k8s-s3a-{run_id}"
    perms = _full_travel_root_permissions(["Tokyo"], max_amount=500.0)
    tok, _ = gw.mint_root_for_user(task_id, "user:alice@org-alpha.io", perms)

    st_rpc, rpc_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text="Execute 3-tier chain with simulated direct-parent unreachable",
            data={
                "op": "delegate_upward_return_chain",
                "city": "Tokyo",
                "simulate_direct_parent_unreachable": True,
                "return_timeout_sec": 1.0,
            },
            task_id=task_id,
        ),
        compact_token=tok,
    )
    assert st_rpc == 200, rpc_body
    chain_out = _extract_a2a_task_data(rpc_body)
    leaf_status = chain_out["downstream"]["upstream_body"]["downstream_status"]
    assert leaf_status == 502, chain_out

    tok_insp, _ = gw.mint_root_for_user(
        f"task-k8s-s3a-insp-{run_id}", "user:alice@org-alpha.io", perms
    )
    st_in, in_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text="Inspect inbox",
            data={"op": "inspect_inbox", "inspect_task_id": task_id},
        ),
        compact_token=tok_insp,
    )
    assert st_in == 200, in_body
    skip_list = _extract_a2a_task_data(in_body).get("skip_level_results", [])
    assert skip_list == [], f"Healthy intermediate bypass was wrongly accepted: {skip_list}"

    return {
        "scenario": "3a_false_skip_level_rejected_by_mtls_healthz_probe",
        "status": "PASS",
        "task_id": task_id,
        "intermediate_mtls_healthz_http": h_check.status_code,
        "rogue_leaf_return_status": leaf_status,
        "accepted_skip_level_results": len(skip_list),
    }


def run_scenario_3b(
    gw: GatewaySession, run_id: str, self_pod_ip: str, sync_marker_file: str
) -> Dict[str, Any]:
    leaf_arrived = threading.Event()
    sync_token = secrets.token_urlsafe(24)

    def _sync_handler(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method != "POST" or req.path != "/sync":
            return 404, {"error": "route_not_found"}, {}
        provided_tok = str(req.header("X-LCT-Sync-Token") or "")
        if not provided_tok or not hmac.compare_digest(provided_tok, sync_token):
            return 403, {"error": "invalid_or_missing_sync_token"}, {}
        with open(sync_marker_file, "w", encoding="utf-8") as fh:
            fh.write("READY_TO_KILL_INTERMEDIATE\n")
        leaf_arrived.set()
        deadline = time.time() + 18.0
        while time.time() < deadline:
            try:
                r = gw.get_mtls(f"{HOTEL_PRIMARY_URL}/healthz", timeout=0.6)
                if r.status_code >= 500:
                    break
            except Exception:
                break
            time.sleep(0.3)
        return 200, {"intermediate_offline": True}, {}

    hook_srv = ManagedHTTPService("s3b-sync-hook", _sync_handler, host="0.0.0.0", port=19090)
    hook_srv.start()
    try:
        task_id = f"task-k8s-s3b-{run_id}"
        perms = _full_travel_root_permissions(["Tokyo"], max_amount=500.0)
        tok, _ = gw.mint_root_for_user(task_id, "user:alice@org-alpha.io", perms)

        eff_hook_url = SYNC_HOOK_URL or f"http://{self_pod_ip}:19090/sync"
        a2a_short = gw.a2a_client_for(ORCH_URL, timeout=45.0)
        a2a_short.send_message(
            message=Message.create_user(
                text="Execute 3-tier chain with mid-flight intermediate Pod termination",
                data={
                    "op": "delegate_upward_return_chain",
                    "city": "Tokyo",
                    "sync_hook_url": eff_hook_url,
                    "sync_hook_token": sync_token,
                    "return_timeout_sec": 1.2,
                },
                task_id=task_id,
            ),
            compact_token=tok,
        )

        tok_inspect, _ = gw.mint_root_for_user(
            f"task-k8s-s3b-insp-{run_id}", "user:alice@org-alpha.io", perms
        )
        accepted_skip: List[Dict[str, Any]] = []
        for _ in range(22):
            st_in, in_body = gw.a2a_orch.send_message(
                message=Message.create_user(
                    text="Inspect inbox",
                    data={"op": "inspect_inbox", "inspect_task_id": task_id},
                ),
                compact_token=tok_inspect,
            )
            if st_in == 200:
                accepted_skip = _extract_a2a_task_data(in_body).get(
                    "skip_level_results", []
                )
                if len(accepted_skip) == 1:
                    break
            time.sleep(0.3)

        if len(accepted_skip) != 1:
            raise AssertionError(f"Expected 1 verified SkipLevelReceipt, got {accepted_skip}")

        sr = accepted_skip[0]
        return {
            "scenario": "3b_authenticated_skip_level_return_over_mtls_on_real_k8s_pod_kill",
            "status": "PASS",
            "task_id": task_id,
            "receipt_id": sr["receipt_id"],
            "child_spiffe_id": sr["child_spiffe_id"],
            "skipped_ancestors": sr["skipped_ancestors"],
            "target_ancestor_spiffe_id": sr["target_ancestor_spiffe_id"],
            "result_sha256": sr["result_sha256"],
            "leaf_result_payload": sr["result_payload"],
        }
    finally:
        hook_srv.stop()


def _probe_tcp_closed(ip: str, port: int, timeout: float = 1.0) -> Tuple[bool, str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return False, f"UNEXPECTED_OPEN:{ip}:{port}"
    except Exception as exc:
        return True, f"{type(exc).__name__}: {exc}"


def run_scenario_4(
    gw: GatewaySession, run_id: str, pod_ips_json: str
) -> Dict[str, Any]:
    pod_ips: Dict[str, str] = json.loads(pod_ips_json)

    # 1. Cross-Pod Loopback Bypass Guard Verification across real K8s CNI Pod IPs!
    bypass_checks: Dict[str, Any] = {}
    for name, ip in pod_ips.items():
        if not ip:
            continue
        ok_app, det_app = _probe_tcp_closed(ip, 9001)
        ok_out, det_out = _probe_tcp_closed(ip, 8081)
        if not ok_app or not ok_out:
            raise AssertionError(f"Loopback port exposed across Pod network on {name} ({ip})!")
        bypass_checks[name] = {
            "pod_ip": ip,
            "app_port_9001_blocked": ok_app,
            "app_port_detail": det_app,
            "sidecar_outbound_8081_blocked": ok_out,
            "sidecar_outbound_detail": det_out,
        }

    # Forged `X-LCT-Loopback-Auth` header sent over mTLS to `:8443/mcp` -> MUST return 401!
    with httpx.Client(verify=gw.ssl_ctx, timeout=5.0) as m_cli:
        forged_in = m_cli.post(
            PAYMENT_MCP_SVC_URL,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "execute_settlement",
                    "arguments": {"target": "hotel-escrow", "amount": 50},
                },
            },
            headers={"X-LCT-Loopback-Auth": "forged-secret-attempt"},
        )
    assert forged_in.status_code == 401, forged_in.text
    bypass_checks["inbound_8443_forged_loopback_header_status"] = forged_in.status_code

    # 2. Official A2A v1.0 `CancelTask` Cross-3-Domain Cascading Revocation Proof (`user:bob@org-alpha.io`):
    #    - Stage Bob's trip across `org-alpha.io` -> `org-beta.io` -> `org-payment.io`
    #    - Verify Carol CANNOT cancel Bob's task (`403` `-32003`)
    #    - Bob invokes `CancelTask(task_bob)` -> atomically sets `TASK_STATE_CANCELED` AND
    #      revokes `/task_bob/OrchestratorAlpha` in `alpha-revocation`, federating immediately to
    #      `beta-revocation` & `payment-revocation`!
    task_bob = f"task-k8s-s4-bob-cancel-{run_id}"
    tok_bob, _ = gw.mint_root_for_user(
        task_bob,
        "user:bob@org-alpha.io",
        _full_travel_root_permissions(["Tokyo"], max_amount=800.0),
    )
    st_bob_stage, bob_stage_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text=(
                "Book business travel to Tokyo for Bob with flight budget up to 650 USD "
                "and hotel budget up to 420 USD."
            ),
            data={"op": "plan_and_execute_trip", "pause_before_settlement": True},
            task_id=task_bob,
        ),
        compact_token=tok_bob,
    )
    assert st_bob_stage == 200, bob_stage_body

    # Cross-user `CancelTask` attempt by Carol -> MUST fail `403` (`-32003`)!
    tok_carol_probe, _ = gw.mint_root_for_user(
        f"task-k8s-s4-carol-probe-{run_id}",
        "user:carol@org-alpha.io",
        _full_travel_root_permissions(["London"], max_amount=800.0),
    )
    st_unauth_cancel, unauth_cancel_body = gw.a2a_orch.cancel_task(
        task_bob, compact_token=tok_carol_probe
    )
    assert st_unauth_cancel == 403, unauth_cancel_body
    assert unauth_cancel_body["error"]["code"] == -32003, unauth_cancel_body

    # Authorized `CancelTask` by Bob -> `TASK_STATE_CANCELED` + cascading lineage revocation!
    st_bob_cancel, bob_cancel_body = gw.a2a_orch.cancel_task(
        task_bob, compact_token=tok_bob
    )
    assert st_bob_cancel == 200, bob_cancel_body
    assert (
        bob_cancel_body["result"]["task"]["status"]["state"]
        == TaskState.CANCELED.value
    ), bob_cancel_body
    bob_rev_meta = bob_cancel_body["result"]["revocation"]
    assert bob_rev_meta["target"] == f"/{task_bob}/OrchestratorAlpha", bob_rev_meta

    # Verify federated propagation to BOTH `beta-revocation` and `payment-revocation`!
    for peer_rev_name, peer_rev_url in (
        ("beta-revocation", BETA_REV_URL),
        ("payment-revocation", PAYMENT_REV_URL),
    ):
        found_fed = False
        for _ in range(15):
            if peer_rev_url.startswith("https://"):
                r_rh = gw.get_mtls(f"{peer_rev_url}/healthz", timeout=3.0)
                if r_rh.status_code == 200 and int(r_rh.json().get("version", 0)) >= 1:
                    found_fed = True
                    break
            else:
                evs = httpx.get(f"{peer_rev_url}/v1/events", timeout=3.0).json().get("events", [])
                if any(
                    e.get("target") == f"/{task_bob}/OrchestratorAlpha"
                    and e.get("trust_domain") == "org-alpha.io"
                    for e in evs
                ):
                    found_fed = True
                    break
            time.sleep(0.2)
        if not found_fed:
            raise AssertionError(
                f"CancelTask revocation for {task_bob} did not federate to {peer_rev_name}!"
            )

    # Replay of `tok_bob` after `CancelTask` -> immediately blocked at Sidecar (`403 LINEAGE_REVOKED`)!
    r_bob_replay = gw.post_lct_mtls(
        ORCH_URL,
        tok_bob,
        {"op": "trigger_converged_settlement", "city": "Tokyo"},
    )
    assert r_bob_replay.status_code == 403, r_bob_replay.text
    assert r_bob_replay.json().get("error") == "LINEAGE_REVOKED", r_bob_replay.text

    # 3. Multi-User Concurrent Execution (`alice@org-alpha.io` staged + `carol@org-alpha.io` full)
    #    + Branch-Scoped A2A `CancelTask` triggering Fagin Multi-Parent DAG Smooth Degradation!
    task_alice = f"task-k8s-s4-alice-{run_id}"
    task_carol = f"task-k8s-s4-carol-{run_id}"

    tok_alice, _ = gw.mint_root_for_user(
        task_alice,
        "user:alice@org-alpha.io",
        _full_travel_root_permissions(["Tokyo"], max_amount=800.0),
    )
    tok_carol, _ = gw.mint_root_for_user(
        task_carol,
        "user:carol@org-alpha.io",
        _full_travel_root_permissions(["London"], max_amount=800.0),
    )

    def _stage_alice() -> Tuple[int, Dict[str, Any]]:
        return gw.a2a_orch.send_message(
            message=Message.create_user(
                text=(
                    "Book business travel to Tokyo for Alice with flight budget up to 650 USD "
                    "and hotel budget up to 420 USD."
                ),
                data={"op": "plan_and_execute_trip", "pause_before_settlement": True},
                task_id=task_alice,
            ),
            compact_token=tok_alice,
        )

    def _run_carol_full() -> Tuple[int, Dict[str, Any]]:
        return gw.a2a_orch.send_message(
            message=Message.create_user(
                text=(
                    "Book business travel to London for Carol with flight budget up to 600 USD "
                    "and hotel budget up to 400 USD."
                ),
                data={"op": "plan_and_execute_trip"},
                task_id=task_carol,
            ),
            compact_token=tok_carol,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_alice = pool.submit(_stage_alice)
        f_carol = pool.submit(_run_carol_full)
        st_alice_stage, alice_stage_body = f_alice.result()
        st_carol, carol_body = f_carol.result()

    assert st_alice_stage == 200, alice_stage_body
    assert st_carol == 200, carol_body

    alice_staged = _extract_a2a_task_data(alice_stage_body)
    flight_branch_path = str(
        alice_staged["flight_branch"]["upstream_body"]["lineage_path"]
    )

    # Online Subtree Revocation of Alice's Flight Branch (`/<task_alice>/OrchestratorAlpha/FlightB1`)
    # at `alpha-revocation`, which federates to `payment-revocation` (`org-payment.io`)!
    rev_ev = gw.rev_client.revoke_prefix(
        caller=gw.identity,
        prefix=flight_branch_path,
        reason="online_cancel_flight_branch",
        authority_token=tok_alice,
    )
    parsed_alice_root = decode_token(tok_alice)
    gw.emit_revocation_audit(
        task_id=task_alice,
        sub="user:alice@org-alpha.io",
        revocation_event=rev_ev,
        root_block_hash=parsed_alice_root.root_block_hash,
        current_block_hash=parsed_alice_root.leaf_block_hash,
    )

    # 4A. Trigger Alice's Hotel Escrow Settlement -> SMOOTH FAGIN DEGRADATION (`200 ALLOW_DEGRADED_DAG`)!
    st_hotel_ok, hotel_ok_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text="Settle surviving Tokyo hotel escrow",
            data={
                "op": "trigger_converged_settlement",
                "city": "Tokyo",
                "requested_targets": ["hotel-escrow"],
                "trigger_hop_segment": "SettleHotelSurviving",
            },
            task_id=task_alice,
        ),
        compact_token=tok_alice,
    )
    assert st_hotel_ok == 200, hotel_ok_body
    hotel_deg_body = _extract_a2a_task_data(hotel_ok_body)["upstream_body"]
    hotel_stl = hotel_deg_body["completed_settlements"]["hotel-escrow"]
    assert hotel_stl["lineage_decision"] == "ALLOW_DEGRADED_DAG", hotel_stl
    assert float(hotel_stl["settled_usd"]) == 360.0, hotel_stl
    assert "360" in hotel_deg_body["final_answer"], hotel_deg_body["final_answer"]
    assert "580" not in hotel_deg_body["final_answer"], (
        f"Degraded answer must not hallucinate revoked 580 USD flight settlement: {hotel_deg_body['final_answer']!r}"
    )

    # 4B. Trigger Alice's Airline Escrow Settlement (depended on revoked `FlightB1`) -> `403` (`FAILED` task)!
    st_air_deny, air_deny_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text="Attempt settlement of revoked Tokyo airline escrow",
            data={
                "op": "trigger_converged_settlement",
                "city": "Tokyo",
                "requested_targets": ["airline-escrow"],
                "trigger_hop_segment": "SettleAirlineRevoked",
            },
            task_id=task_alice,
        ),
        compact_token=tok_alice,
    )
    assert st_air_deny == 403, air_deny_body
    air_err_data = air_deny_body["error"]["data"]
    assert air_err_data["task"]["status"]["state"] == TaskState.FAILED.value, air_deny_body
    air_err = air_err_data["upstream_body"]["denied_settlements"]["airline-escrow"]
    assert air_err["error"] == "REVOKED_DEPENDENCY_INSUFFICIENT_SURVIVING_PATHS", air_err

    # 4C. Verify Carol's concurrent London trip completed 100% cleanly (`ALLOW`) with zero cross-user bleed!
    carol_conv = _extract_a2a_task_data(carol_body)["settlement_convergence"]["upstream_body"]
    assert carol_conv["sub"] == "user:carol@org-alpha.io"
    assert carol_conv["city"] == "London"
    assert carol_conv["flight_booking"]["flight_no"] == "BA-284"
    assert float(carol_conv["completed_settlements"]["airline-escrow"]["settled_usd"]) == 510.0
    assert float(carol_conv["completed_settlements"]["hotel-escrow"]["settled_usd"]) == 340.0
    assert carol_conv["completed_settlements"]["airline-escrow"]["lineage_decision"] == "ALLOW"

    return {
        "scenario": "4_a2a_v1_canceltask_cross_domain_cascade_fagin_dag_concurrency_and_loopback_isolation",
        "status": "PASS",
        "cross_pod_loopback_isolation": bypass_checks,
        "a2a_canceltask_cross_3domain_proof": {
            "task_id": task_bob,
            "unauthorized_carol_cancel_http": st_unauth_cancel,
            "unauthorized_carol_cancel_rpc_code": unauth_cancel_body["error"]["code"],
            "bob_canceled_state": bob_cancel_body["result"]["task"]["status"]["state"],
            "cascaded_revocation_target": bob_rev_meta["target"],
            "federated_to_beta_and_payment_revocation": True,
            "post_cancel_token_replay_http": r_bob_replay.status_code,
            "post_cancel_token_replay_error": r_bob_replay.json().get("error"),
        },
        "alice_revoked_branch": rev_ev.target,
        "alice_revocation_version": rev_ev.version,
        "alice_surviving_hotel_settlement": hotel_stl,
        "alice_degraded_llm_answer": hotel_deg_body["final_answer"],
        "alice_revoked_airline_rejection": air_err,
        "carol_concurrent_london_settlements": carol_conv["completed_settlements"],
        "carol_final_answer": carol_conv["final_answer"],
    }


def run_scenario_5(gw: GatewaySession) -> Dict[str, Any]:
    entries = gw.audit_client.fetch_entries()
    auditor = CausalChainAuditor(
        gw.resolver,
        trusted_revocation_spiffe_ids=[
            "spiffe://org-alpha.io/ns/sys/sa/revocation",
            "spiffe://org-beta.io/ns/sys/sa/revocation",
            "spiffe://org-payment.io/ns/sys/sa/revocation",
        ],
    )
    report = auditor.audit(entries)
    ok_num, total_den = report.reconstruction_rate

    all_resilience_tags: List[str] = []
    per_task_summary: Dict[str, Any] = {}
    for tid, trec in sorted(report.tasks.items()):
        all_resilience_tags.extend(trec.resilience_classifications)
        per_task_summary[tid] = {
            "sub": trec.sub,
            "reconstructed_complete": trec.reconstructed_complete,
            "lineage_paths_count": len(trec.lineage_paths_observed),
            "lineage_paths_observed": trec.lineage_paths_observed,
            "verified_hops": trec.verified_hops,
            "tool_invocations_verified": trec.tool_invocations_verified,
            "resilience_classifications": trec.resilience_classifications,
            "anomalies": [a.__dict__ for a in trec.anomalies],
        }

    if not report.stream_integrity_ok or not report.clean or ok_num != total_den or total_den == 0:
        raise AssertionError(
            f"Cluster audit reconstruction not 100% clean: ok={ok_num}/{total_den}, "
            f"stream_ok={report.stream_integrity_ok}, anomalies={report.anomalies}"
        )
    if "VERIFIED_FAILOVER_GRAFT" not in all_resilience_tags:
        raise AssertionError(f"Expected VERIFIED_FAILOVER_GRAFT in {all_resilience_tags}")
    if "VERIFIED_SKIP_LEVEL_MERGE" not in all_resilience_tags:
        raise AssertionError(f"Expected VERIFIED_SKIP_LEVEL_MERGE in {all_resilience_tags}")

    return {
        "scenario": "5_keyless_audit_collector_export_and_100pct_3domain_causal_reconstruction",
        "status": "PASS",
        "total_signed_entries": report.total_entries,
        "distinct_streams_verified": report.streams_checked,
        "stream_hash_chain_integrity_ok": report.stream_integrity_ok,
        "clean": report.clean,
        "reconstructed_tasks_numerator": ok_num,
        "total_tasks_denominator": total_den,
        "reconstruction_rate_pct": round(100.0 * ok_num / total_den, 2),
        "resilience_classifications_verified": sorted(set(all_resilience_tags)),
        "tasks": per_task_summary,
        "redacted_audit_sample_count": len(entries),
    }


def run_multicluster_isolation_proofs(
    gw: GatewaySession, foreign_pod_ips_json: str
) -> Dict[str, Any]:
    """Verify physical L3 CIDR unroutability, private cluster.local DNS isolation,
    public organization FQDN purity, and hardened external control-plane ports.
    """
    foreign_ips: Dict[str, str] = json.loads(foreign_pod_ips_json)

    # 1. Private `.svc.cluster.local` DNS names of foreign clusters MUST fail resolution!
    dns_isolation: Dict[str, Any] = {}
    for foreign_dns in (
        "flight-specialist.lineage-beta.svc.cluster.local",
        "payment-vault-mcp.lineage-pay.svc.cluster.local",
        "audit-collector.lineage-ctrl.svc.cluster.local",
    ):
        failed = False
        err_msg = ""
        try:
            socket.getaddrinfo(foreign_dns, 8443)
        except socket.gaierror as exc:
            failed = True
            err_msg = f"gaierror: {exc}"
        if not failed:
            raise AssertionError(
                f"Foreign cluster private DNS {foreign_dns!r} unexpectedly resolved inside lct-org-alpha!"
            )
        dns_isolation[foreign_dns] = {"nxdomain_isolated": True, "detail": err_msg}

    # 2. Disjoint internal Pod CIDRs (`10.242.0.0/16` in Beta, `10.243.0.0/16` in Pay)
    #    MUST be physically unroutable from `lct-org-alpha` (`10.241.0.0/16`)!
    l3_isolation: Dict[str, Any] = {}
    for label, pod_ip in foreign_ips.items():
        if not pod_ip:
            continue
        ok_unreach, detail = _probe_tcp_closed(pod_ip, 8443, timeout=1.2)
        if not ok_unreach:
            raise AssertionError(
                f"Foreign cluster internal Pod IP {pod_ip}:8443 ({label}) was unexpectedly reachable!"
            )
        l3_isolation[label] = {
            "foreign_pod_ip": pod_ip,
            "port_8443_unroutable": True,
            "detail": detail,
        }

    # 3. Verify all 5 federated `AgentCard`s advertise ONLY public `*.org-*.io:<nodeport>` FQDNs
    #    (ZERO `.svc.cluster.local` leakage!)
    cards = gw.dir_client.discover(only_healthy=True)
    if len(cards) < 5:
        raise AssertionError(f"Expected >=5 federated AgentCards, got {len(cards)}")
    card_endpoints: Dict[str, str] = {}
    for c in cards:
        if ".svc.cluster.local" in c.endpoint or ".svc.cluster.local" in (
            c.return_endpoint or ""
        ):
            raise AssertionError(
                f"AgentCard {c.spiffe_id} leaked internal .svc.cluster.local URL: {c.endpoint}"
            )
        if not c.endpoint.startswith("https://"):
            raise AssertionError(f"AgentCard {c.spiffe_id} endpoint must be https://: {c.endpoint}")
        card_endpoints[c.spiffe_id] = c.endpoint

    # 4. External Control-Plane Boundary Hardening Checks
    sa_jwt = gw._fresh_sa_jwt()
    kp = KeyPair.generate("ES256")
    pop = create_ca_pop_jws(kp, sa_jwt)
    ext_ca_checks: Dict[str, Any] = {}
    for name, url in (("beta-ca-fed", BETA_CA_URL), ("payment-ca-fed", PAYMENT_CA_URL)):
        r = httpx.post(
            f"{url}/v1/ca/issue-workload",
            json={"public_jwk": kp.public_jwk(), "pop_jws": pop},
            headers={"Authorization": f"Bearer {sa_jwt}"},
            timeout=5.0,
        )
        assert r.status_code == 403, f"{name} returned {r.status_code}: {r.text}"
        assert r.json().get("error") == "federation_endpoint_read_only", r.text
        ext_ca_checks[name] = {"status": r.status_code, "error": r.json().get("error")}

    # Unauthenticated TLS client rejected on external `:31491` directory & `:32492` revocation ports;
    # Authenticated mTLS client rejected (`403 federation_port_restricted`) on mutating admin routes!
    server_only_ctx = ssl.create_default_context(
        cadata=gw.mtls_bundle.trust_store.combined_ca_pem()
    )
    beta_dir_fed = "https://beta-directory.org-beta.io:31491"
    pay_rev_fed = PAYMENT_REV_URL
    for target_u in (f"{beta_dir_fed}/v1/federation/cards", f"{pay_rev_fed}/v1/federation/events"):
        blocked = False
        try:
            with httpx.Client(verify=server_only_ctx, timeout=3.0) as bad_c:
                bad_c.get(target_u)
        except Exception:
            blocked = True
        if not blocked:
            raise AssertionError(f"Certless TLS client was not rejected at {target_u}!")

    with httpx.Client(
        verify=gw.mtls_bundle.verify_for_target(target_url=beta_dir_fed), timeout=5.0
    ) as b_cli:
        r_reg_block = b_cli.post(f"{beta_dir_fed}/v1/agents/register", json={})
        assert r_reg_block.status_code == 403
        assert r_reg_block.json().get("error") == "federation_port_restricted"

    with httpx.Client(
        verify=gw.mtls_bundle.verify_for_target(target_url=pay_rev_fed), timeout=5.0
    ) as p_cli:
        r_qw_block = p_cli.post(f"{pay_rev_fed}/v1/revoke/workload", json={})
        assert r_qw_block.status_code == 403
        assert r_qw_block.json().get("error") == "federation_port_restricted"

    return {
        "check": "multicluster_physical_l3_dns_and_boundary_isolation",
        "status": "PASS",
        "private_cluster_local_dns_isolation": dns_isolation,
        "disjoint_pod_cidr_l3_isolation": l3_isolation,
        "public_fqdn_agent_cards": card_endpoints,
        "external_ca_readonly_enforcement": ext_ca_checks,
        "external_directory_register_status": r_reg_block.status_code,
        "external_revocation_workload_status": r_qw_block.status_code,
    }


def _wait_for_marker(path: str, timeout_sec: float = 45.0) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.25)
    raise TimeoutError(f"Timed out waiting for synchronization marker {path!r}")


def run_scenario_6_whole_cluster_partition(
    gw: GatewaySession,
    run_id: str,
    ready_disconnect_file: str = "/tmp/s6_ready_disconnect",
    ack_disconnected_file: str = "/tmp/s6_ack_disconnected",
    ready_reconnect_file: str = "/tmp/s6_ready_reconnect",
    ack_reconnected_file: str = "/tmp/s6_ack_reconnected",
) -> Dict[str, Any]:
    """Scenario 6: End-to-end Whole-Cluster Network Partition, Fail-Closed `503`, and Autonomous Recovery
    within a single persistent in-memory `GatewaySession` (zero serialized keys or tokens!).
    """
    for mf in (
        ready_disconnect_file,
        ack_disconnected_file,
        ready_reconnect_file,
        ack_reconnected_file,
    ):
        try:
            os.remove(mf)
        except FileNotFoundError:
            pass

    # 1. Stage cross-3-cluster travel workflow (`org-alpha.io -> org-beta.io -> org-payment.io`)
    task_id = f"task-k8s-s6-part-{run_id}"
    perms = _full_travel_root_permissions(["Tokyo"], max_amount=800.0)
    tok, _ = gw.mint_root_for_user(task_id, "user:alice@org-alpha.io", perms)

    st, body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text=(
                "Book business travel to Tokyo for Alice with flight budget up to 650 USD "
                "and hotel budget up to 420 USD."
            ),
            data={"op": "plan_and_execute_trip", "pause_before_settlement": True},
            task_id=task_id,
        ),
        compact_token=tok,
    )
    if st != 200:
        raise AssertionError(f"Scenario 6 staging failed ({st}): {body}")

    # Signal host runner to execute `docker network disconnect kind lct-org-beta-control-plane`
    with open(ready_disconnect_file, "w", encoding="utf-8") as fh:
        fh.write("READY\n")
    _wait_for_marker(ack_disconnected_file, timeout_sec=45.0)

    # 2. Verify autonomous survivability of Clusters Alpha, Pay, and Audit while Cluster Beta is severed!
    survivability: Dict[str, int] = {
        "alpha_ca_healthz": httpx.get(f"{ALPHA_CA_URL}/healthz", timeout=3.0).status_code,
        "alpha_dir_healthz": httpx.get(f"{ALPHA_DIR_URL}/healthz", timeout=3.0).status_code,
        "alpha_rev_healthz": httpx.get(f"{ALPHA_REV_URL}/healthz", timeout=3.0).status_code,
        "orchestrator_alpha_mtls_healthz": gw.get_mtls(f"{ORCH_URL}/healthz", timeout=3.0).status_code,
        "payment_ca_fed_healthz": httpx.get(f"{PAYMENT_CA_URL}/healthz", timeout=3.0).status_code,
        "settlement_converger_mtls_healthz": gw.get_mtls(f"{CONVERGER_URL}/healthz", timeout=3.0).status_code,
        "payment_vault_mcp_mtls_healthz": gw.get_mtls(
            f"{PAYMENT_MCP_SVC_URL.rsplit('/mcp', 1)[0]}/healthz", timeout=3.0
        ).status_code,
        "audit_collector_healthz": gw.audit_client.healthz().status_code,
    }
    for k, code in survivability.items():
        if code != 200:
            raise AssertionError(f"Surviving cluster service {k} unhealthy during Beta outage: {code}")

    # Confirm Cluster Beta is genuinely unreachable from Cluster Alpha!
    beta_unreachable = False
    try:
        gw.get_mtls(f"{FLIGHT_URL}/healthz", timeout=1.2)
    except Exception:
        beta_unreachable = True
    if not beta_unreachable:
        raise AssertionError("Expected Cluster Beta to be unreachable during network disconnect!")

    # 3. Attempt HIGH_RISK settlement traversing `org-beta.io` -> MUST fail closed (`503`)!
    st_settle, settle_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text="Attempt HIGH_RISK Tokyo escrow settlement while Cluster Beta is partitioned",
            data={
                "op": "trigger_converged_settlement",
                "city": "Tokyo",
                "requested_targets": ["airline-escrow"],
                "trigger_hop_segment": "SettleDuringBetaOutage",
            },
            task_id=task_id,
        ),
        compact_token=tok,
    )
    assert st_settle == 503, f"Expected 503 fail-closed, got {st_settle}: {settle_body}"
    err_data = settle_body["error"]["data"]
    assert err_data["task"]["status"]["state"] == TaskState.FAILED.value
    vault_deny = err_data["upstream_body"]["denied_settlements"]["airline-escrow"]
    assert vault_deny["error"] == "REVOCATION_ANCHOR_UNAVAILABLE", vault_deny

    # Signal host runner to execute `docker network connect kind lct-org-beta-control-plane`
    with open(ready_reconnect_file, "w", encoding="utf-8") as fh:
        fh.write("READY\n")
    _wait_for_marker(ack_reconnected_file, timeout_sec=45.0)

    # 4. Wait for Cluster Beta mTLS endpoints to recover autonomously and execute full workflow
    for svc_u in (f"{FLIGHT_URL}/healthz", f"{HOTEL_PRIMARY_URL}/healthz"):
        recovered = False
        for _ in range(35):
            try:
                if gw.get_mtls(svc_u, timeout=1.5).status_code == 200:
                    recovered = True
                    break
            except Exception:
                pass
            time.sleep(0.4)
        if not recovered:
            raise AssertionError(f"Cluster Beta endpoint {svc_u} did not recover after reconnect!")

    recov_task_id = f"task-k8s-s6-recov-{run_id}"
    tok_recov, _ = gw.mint_root_for_user(recov_task_id, "user:alice@org-alpha.io", perms)

    st_ok, ok_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text=(
                "Book business travel to Tokyo for Alice with flight budget up to 650 USD "
                "and hotel budget up to 420 USD after Cluster Beta network recovery."
            ),
            data={"op": "plan_and_execute_trip"},
            task_id=recov_task_id,
        ),
        compact_token=tok_recov,
    )
    if st_ok != 200:
        raise AssertionError(f"Post-recovery trip failed ({st_ok}): {ok_body}")
    assert ok_body["result"]["task"]["status"]["state"] == TaskState.COMPLETED.value
    recov_data = _extract_a2a_task_data(ok_body)
    stl = recov_data["settlement_convergence"]["upstream_body"]["completed_settlements"]
    assert stl["airline-escrow"]["lineage_decision"] == "ALLOW"
    assert stl["hotel-escrow"]["lineage_decision"] == "ALLOW"

    for mf in (
        ready_disconnect_file,
        ack_disconnected_file,
        ready_reconnect_file,
        ack_reconnected_file,
    ):
        try:
            os.remove(mf)
        except FileNotFoundError:
            pass

    return {
        "scenario": "6_whole_cluster_network_partition_fail_closed_and_autonomous_recovery",
        "status": "PASS",
        "during_whole_cluster_partition": {
            "partitioned_task_id": task_id,
            "beta_cluster_confirmed_unreachable": beta_unreachable,
            "surviving_clusters_health": survivability,
            "high_risk_fail_closed_http_status": st_settle,
            "high_risk_fail_closed_error": vault_deny,
        },
        "after_autonomous_recovery": {
            "recovered_task_id": recov_task_id,
            "a2a_task_state": ok_body["result"]["task"]["status"]["state"],
            "completed_settlements": stl,
            "final_answer": recov_data["settlement_convergence"]["upstream_body"]["final_answer"],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True)
    parser.add_argument("--run-id", default="m3")
    parser.add_argument("--self-pod-ip", default="127.0.0.1")
    parser.add_argument("--sync-marker-file", default="/tmp/s3b_ready")
    parser.add_argument("--pod-ips-json", default="{}")
    parser.add_argument("--foreign-pod-ips-json", default="{}")
    args = parser.parse_args()

    gw = GatewaySession()
    phase = args.phase
    try:
        if phase == "multicluster_isolation_proofs":
            out = run_multicluster_isolation_proofs(gw, args.foreign_pod_ips_json)
        elif phase == "scenario1_normal_dag":
            out = run_scenario_1(gw, args.run_id)
        elif phase == "scenario2a_zombie_prune_and_graft":
            out = run_scenario_2a(gw, args.run_id)
        elif phase == "scenario2b_pod_down_prune_and_graft":
            out = run_scenario_2b(gw, args.run_id)
        elif phase == "scenario3a_forged_skip_blocked_while_alive":
            out = run_scenario_3a(gw, args.run_id)
        elif phase == "scenario3b_genuine_skip_level_when_pod_killed":
            out = run_scenario_3b(gw, args.run_id, args.self_pod_ip, args.sync_marker_file)
        elif phase == "scenario4_fagin_degradation_concurrency_and_bypass_guard":
            out = run_scenario_4(gw, args.run_id, args.pod_ips_json)
        elif phase == "scenario6_whole_cluster_partition":
            out = run_scenario_6_whole_cluster_partition(gw, args.run_id)
        elif phase == "scenario5_cluster_audit_reconstruction":
            out = run_scenario_5(gw)
        elif phase == "export_redacted_audit_entries":
            entries = [e.to_dict() for e in gw.audit_client.fetch_entries()]
            out = {"count": len(entries), "entries": _scrub_for_disk(entries)}
        else:
            print(f"Unknown phase: {phase!r}", file=sys.stderr)
            sys.exit(2)
    finally:
        gw.syncer.stop_background_refresh()
        gw.mtls_bundle.cleanup()

    print(json.dumps(_scrub_for_disk(out), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
