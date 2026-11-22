"""Permanent Adversarial Security Regression Suite Covering All 21 QA Findings (Rounds 1, 2 & 3).

Verifies root-cause protocol & implementation fixes for:
- Round 1 (`CRITICAL-01..04`, `HIGH-01..04`, `MEDIUM-01..03`, `LOW-01..02`)
- Round 2 Second-Order Findings (`CRITICAL-R2-01`, `HIGH-R2-01..03`, `MEDIUM-R2-01`)
- Round 3 Third-Order Boundary Findings:
  - `HIGH-R3-01`: Single-dot (`/./mcp`, `/mcp/.`), mid-path `//`, & single/double percent-encoded `/%6d%63%70` normalization
  - `HIGH-R3-02`: `FailoverReceipt` & `CausalChainAuditor` `RevocationEvent.trust_domain` / `SUBTREE` & same-domain SVID binding
  - `MEDIUM-R3-01`: Quarantined caller, expired `B_0`, bare 0-hop `B_0`, & revoked Hop-0 root coordinate checks on global quarantine
"""

from __future__ import annotations

import concurrent.futures
import json
import socket
import sys
import threading
import time
import unittest

import httpx

from lineage.audit import (
    AuditCollectorService,
    AuditEventType,
    AuditStreamEmitter,
    CausalChainAuditor,
)
from lineage.common.crypto import (
    KeyPair,
    b64url_decode,
    b64url_encode,
    canonical_json_bytes,
    jws_sign_compact,
    sha256_b64url,
)
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.protocol import (
    DPoPError,
    DPoPVerifier,
    MultiParentToken,
    PermissionLattice,
    TokenError,
    create_dpop_proof,
    mint_root_token,
)
from lineage.registry import (
    AgentCard,
    AgentCardError,
    AgentDirectoryClient,
    AgentDirectoryService,
)
from lineage.resilience import (
    FailoverReceipt,
    FailureEvidence,
    FaultType,
    ResilienceError,
    ResilientDelegationCoordinator,
    SkipLevelReceipt,
    ThreeLayerFaultDetector,
)
from lineage.revocation import (
    RevocationError,
    RevocationEvent,
    RevocationKind,
    RevocationReplicaClient,
    RevocationService,
)
from lineage.sidecar import AgentSidecarNode, LineageSidecar, MCPToolSidecarNode
from lineage.verifier import LeafVerifier, VerificationMode


def _sign_raw_jws_unrestricted(
    payload_raw_json: str,
    keypair: KeyPair,
    typ: str,
    extra_headers: dict | None = None,
) -> str:
    header = {"alg": keypair.alg, "typ": typ, "kid": keypair.kid}
    if extra_headers:
        header.update(extra_headers)
    h_b64 = b64url_encode(canonical_json_bytes(header))
    p_b64 = b64url_encode(payload_raw_json.encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    s_b64 = b64url_encode(keypair.sign_bytes(signing_input))
    return f"{h_b64}.{p_b64}.{s_b64}"


class TestSecurityRegressions(unittest.TestCase):
    def test_critical_01_risk_hint_cannot_downgrade_high_risk_or_fail_closed(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_drv = ca.issue_workload("/ns/entry/sa/drv")
        w_agent = ca.issue_workload("/ns/work/sa/agent-b")
        w_tool = ca.issue_workload("/ns/tool/sa/pay-mcp")
        w_rev = ca.issue_workload("/ns/sys/sa/rev")

        rev_svc = RevocationService(w_rev, resolver)
        rev_url = rev_svc.start()
        tool_node = MCPToolSidecarNode(
            identity=w_tool,
            trust_resolver=resolver,
            tools={
                "execute_payment": lambda args, _: {"paid": args.get("amount")},
                "get_weather": lambda args, _: {"temp": 70},
            },
            mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
            revocation_url=rev_url,
        )
        tool_node.start()
        try:
            perms = PermissionLattice.create(
                tools=["execute_payment", "get_weather"], max_amount=5000.0
            )
            tok = mint_root_token(
                ca,
                "task-risk-downgrade",
                "user:alice",
                w_drv.jkt,
                w_agent.spiffe_id,
                w_agent.jkt,
                perms,
                hop_segment="B",
            ).encode_compact()

            rev_svc.revoke_prefix_direct(
                "/task-risk-downgrade", requested_by="user:alice", reason="compromised"
            )
            self.assertEqual(tool_node.sidecar.verifier.trie.version, 0)

            # Attack A: `X-LCT-Risk-Hint: LOW` MUST NOT bypass sync revocation check on `execute_payment`!
            resp_revoked = httpx.post(
                tool_node.mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "execute_payment", "arguments": {"amount": 1000.0}},
                },
                headers={
                    "Authorization": f"DPoP {tok}",
                    "DPoP": create_dpop_proof(w_agent, "POST", tool_node.mcp_url, tok),
                    "X-LCT-Risk-Hint": "LOW",
                },
                timeout=5.0,
            )
            self.assertEqual(resp_revoked.status_code, 403)
            self.assertEqual(resp_revoked.json()["error"], "LINEAGE_REVOKED")

            # Attack B: Stop RevocationService -> `X-LCT-Risk-Hint: LOW` MUST still fail-closed (503)!
            tok2 = mint_root_token(
                ca,
                "task-anchor-down",
                "user:alice",
                w_drv.jkt,
                w_agent.spiffe_id,
                w_agent.jkt,
                perms,
                hop_segment="B",
            ).encode_compact()
            rev_svc.stop()

            resp_fail_closed = httpx.post(
                tool_node.mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "execute_payment", "arguments": {"amount": 2500.0}},
                },
                headers={
                    "Authorization": f"DPoP {tok2}",
                    "DPoP": create_dpop_proof(w_agent, "POST", tool_node.mcp_url, tok2),
                    "X-LCT-Risk-Hint": "LOW",
                },
                timeout=5.0,
            )
            self.assertEqual(resp_fail_closed.status_code, 503)
            self.assertEqual(
                resp_fail_closed.json()["error"], "REVOCATION_ANCHOR_UNAVAILABLE"
            )

            # Upward escalation (`X-LCT-Risk-Hint: HIGH` on `get_weather`) IS honored -> 503 when anchor offline!
            resp_escalate = httpx.post(
                tool_node.mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "get_weather", "arguments": {}},
                },
                headers={
                    "Authorization": f"DPoP {tok2}",
                    "DPoP": create_dpop_proof(w_agent, "POST", tool_node.mcp_url, tok2),
                    "X-LCT-Risk-Hint": "HIGH",
                },
                timeout=5.0,
            )
            self.assertEqual(resp_escalate.status_code, 503)
        finally:
            tool_node.stop()
            rev_svc.stop()

    def test_critical_02_dpop_host_header_spoofing_and_path_smuggling_blocked(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_drv = ca.issue_workload("/ns/entry/sa/drv")
        w_c = ca.issue_workload("/ns/work/sa/agent-c")
        w_tool1 = ca.issue_workload("/ns/tool/sa/weather-mcp")
        w_tool2 = ca.issue_workload("/ns/tool/sa/payment-mcp")

        tool1 = MCPToolSidecarNode(
            w_tool1, resolver, tools={"get_weather": lambda args, _: {"temp": 72}}
        )
        tool2 = MCPToolSidecarNode(
            w_tool2,
            resolver,
            tools={"execute_payment": lambda args, _: {"paid": args.get("amount")}},
        )
        tool1.start()
        tool2.start()
        try:
            perms = PermissionLattice.create(
                tools=["get_weather", "execute_payment"], max_amount=500.0
            )
            tok = mint_root_token(
                ca, "task-host", "user:alice", w_drv.jkt, w_c.spiffe_id, w_c.jkt, perms, hop_segment="C"
            ).encode_compact()

            dpop_for_tool1 = create_dpop_proof(w_c, "POST", tool1.mcp_url, tok)
            self.assertEqual(
                httpx.post(
                    tool1.mcp_url,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "get_weather", "arguments": {}},
                    },
                    headers={"Authorization": f"DPoP {tok}", "DPoP": dpop_for_tool1},
                    timeout=5.0,
                ).status_code,
                200,
            )

            # Attack A: Cross-Sidecar replay with spoofed Host header + body swap -> 400!
            tool1_authority = tool1.sidecar.inbound_url.replace("http://", "")
            replay_spoof_host = httpx.post(
                tool2.mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "execute_payment", "arguments": {"amount": 450.0}},
                },
                headers={
                    "Host": tool1_authority,
                    "Authorization": f"DPoP {tok}",
                    "DPoP": dpop_for_tool1,
                },
                timeout=5.0,
            )
            self.assertEqual(replay_spoof_host.status_code, 400)
            self.assertEqual(
                replay_spoof_host.json()["error"], "invalid_or_spoofed_host_header"
            )

            # Even without spoofing Host, replaying tool1's DPoP to tool2 fails authoritative htu check (401)!
            replay_real_host = httpx.post(
                tool2.mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "execute_payment", "arguments": {"amount": 450.0}},
                },
                headers={
                    "Authorization": f"DPoP {tok}",
                    "DPoP": dpop_for_tool1,
                },
                timeout=5.0,
            )
            self.assertEqual(replay_real_host.status_code, 401)
            self.assertEqual(replay_real_host.json()["error"], "DPOP_FAILED")

            # Attack B: Query/path smuggling via `Host: <authority>/a2a/task?swallow=` -> 400!
            tool2_authority = tool2.sidecar.inbound_url.replace("http://", "")
            dpop_other_path = create_dpop_proof(
                w_c, "POST", f"{tool2.sidecar.inbound_url}/a2a/task", tok
            )
            smuggle_resp = httpx.post(
                tool2.mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "execute_payment", "arguments": {"amount": 100.0}},
                },
                headers={
                    "Host": f"{tool2_authority}/a2a/task?swallow=",
                    "Authorization": f"DPoP {tok}",
                    "DPoP": dpop_other_path,
                },
                timeout=5.0,
            )
            self.assertEqual(smuggle_resp.status_code, 400)
        finally:
            tool1.stop()
            tool2.stop()

    def test_critical_03_revocation_and_directory_jurisdiction_and_cmd_anti_replay(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        w_drv = ca_alpha.issue_workload("/ns/entry/sa/drv")
        w_coord_alpha = ca_alpha.issue_workload("/ns/coord/sa/coord-a")
        w_b1 = ca_alpha.issue_workload("/ns/work/sa/b1")
        w_b2 = ca_alpha.issue_workload("/ns/work/sa/b2")
        w_untrusted_beta = ca_beta.issue_workload("/ns/sandbox/sa/untrusted-leaf")
        w_rev = ca_alpha.issue_workload("/ns/sys/sa/rev")

        rev_svc = RevocationService(w_rev, resolver)
        dir_svc = AgentDirectoryService(resolver)
        rev_url = rev_svc.start()
        dir_url = dir_svc.start()
        try:
            dir_client = AgentDirectoryClient(dir_url, resolver)
            rev_client = RevocationReplicaClient(rev_url, resolver)

            coord_card = AgentCard.sign_and_create(
                w_coord_alpha, "Alpha Coord", "http://127.0.0.1:19500", ["coord.root"]
            )
            dir_client.register(coord_card)

            # 1. Foreign leaf cannot revoke Alpha's prefix!
            with self.assertRaises(RevocationError):
                rev_client.revoke_prefix(
                    w_untrusted_beta, "/task-alpha-secret", reason="sabotage"
                )
            self.assertIsNone(
                rev_svc.trie.check_lineage_path("/task-alpha-secret/CoordA")
            )

            # 2. Child hop B2 cannot revoke its root `/task-j`, its parent `/task-j/A`, or sibling `/task-j/A/B1`!
            p = PermissionLattice.create(tools=["t1"])
            t_root = mint_root_token(
                ca_alpha, "task-j", "user:alice", w_drv.jkt, w_coord_alpha.spiffe_id, w_coord_alpha.jkt, p, hop_segment="A"
            )
            t_b2 = t_root.attenuate(
                w_coord_alpha, w_b2.spiffe_id, w_b2.jkt, p, hop_segment="B2"
            ).encode_compact()

            for forbidden_prefix in ("/task-j", "/task-j/A", "/task-j/A/B1"):
                with self.assertRaises(RevocationError):
                    rev_client.revoke_prefix(
                        w_b2, forbidden_prefix, reason="upward_or_sibling_sabotage", authority_token=t_b2
                    )

            # Legitimate parent `w_coord_alpha` revoking child `/task-j/A/B2` SUCCEEDS!
            ev_ok = rev_client.revoke_prefix(
                w_coord_alpha, "/task-j/A/B2", reason="legit_parent_prune", authority_token=t_b2
            )
            self.assertEqual(ev_ok.target, "/task-j/A/B2")

            # 3. Foreign leaf (and non-delegator same-domain leaf `w_b1`) cannot quarantine `w_coord_alpha`!
            with self.assertRaises(RevocationError):
                rev_client.quarantine_workload(
                    w_untrusted_beta, w_coord_alpha.spiffe_id, reason="lateral_dos"
                )
            with self.assertRaises(AgentCardError):
                dir_client.quarantine(
                    w_untrusted_beta, w_coord_alpha.spiffe_id, reason="lateral_dos"
                )
            with self.assertRaises(AgentCardError):
                dir_client.quarantine(
                    w_b1, w_coord_alpha.spiffe_id, reason="child_mutiny", authority_token=t_b2
                )

            # Alpha Coordinator remains 100% discoverable and can update to version=2!
            self.assertEqual(len(dir_client.discover(skill="coord.root")), 1)
            coord_card_v2 = AgentCard.sign_and_create(
                w_coord_alpha, "Alpha Coord", "http://127.0.0.1:19500", ["coord.root"], version=2
            )
            dir_client.register(coord_card_v2)

            # 4. Command JWS replay blocked!
            replay_jws = jws_sign_compact(
                {
                    "jti": "fixed-cmd-jti-1",
                    "prefix": "/task-replay-cmd",
                    "reason": "cancel",
                    "iat": time.time(),
                },
                ca_alpha.active_keypair,
                typ="lct-revoke-cmd+jwt",
            )
            r_first = httpx.post(
                f"{rev_url}/v1/revoke/prefix",
                json={
                    "auth_mode": "domain_authority",
                    "trust_domain": "org-alpha.io",
                    "command_jws": replay_jws,
                },
                timeout=3.0,
            )
            self.assertEqual(r_first.status_code, 200)
            r_second = httpx.post(
                f"{rev_url}/v1/revoke/prefix",
                json={
                    "auth_mode": "domain_authority",
                    "trust_domain": "org-alpha.io",
                    "command_jws": replay_jws,
                },
                timeout=3.0,
            )
            self.assertEqual(r_second.status_code, 403)
        finally:
            rev_svc.stop()
            dir_svc.stop()

    def test_critical_04_inbound_recipient_holder_and_direct_child_result_enforcement(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_drv = ca.issue_workload("/ns/entry/sa/drv")
        w_a = ca.issue_workload("/ns/coord/sa/a")
        w_b1 = ca.issue_workload("/ns/mid/sa/b1")
        w_c = ca.issue_workload("/ns/dag/sa/aggregator-c")
        w_rogue_m = ca.issue_workload("/ns/other/sa/branch-m")
        w_tool = ca.issue_workload("/ns/tool/sa/ledger-tool")

        invoked_on_c: list[str] = []

        def _c_handler(node: AgentSidecarNode, req: HTTPRequestContext, body: dict):
            if body.get("op") == "run_converged":
                return node.sidecar_call_tool_converged(
                    task_id=str(req.header("X-LCT-Task-Id")),
                    sub=str(req.header("X-LCT-Sub")),
                    target_mcp_url=tool_node.mcp_url,
                    tool_name="read_ledger",
                    arguments={},
                )
            invoked_on_c.append(str(req.header("X-LCT-Lineage-Path")))
            return 200, {"executed_on_c": True}

        a_node = AgentSidecarNode(w_a, resolver, "A", ["coord"], lambda *_: (200, {}))
        c_node = AgentSidecarNode(w_c, resolver, "C", ["converge"], _c_handler)
        tool_node = MCPToolSidecarNode(
            w_tool,
            resolver,
            tools={"read_ledger": lambda args, _: {"ok": True}},
            mode=VerificationMode.LOCAL_FULL_CHAIN,
        )
        a_node.start(register_in_directory=False)
        c_node.start(register_in_directory=False)
        tool_node.start()
        try:
            perms = PermissionLattice.create(tools=["read_ledger"])
            t_root = mint_root_token(
                ca, "task-dag-clean", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, perms, hop_segment="A"
            )
            t_b1 = t_root.attenuate(w_a, w_b1.spiffe_id, w_b1.jkt, perms, hop_segment="B1")
            t_b1_to_c = t_b1.attenuate(w_b1, w_c.spiffe_id, w_c.jkt, perms, hop_segment="C")
            t_m = t_root.attenuate(w_a, w_rogue_m.spiffe_id, w_rogue_m.jkt, perms, hop_segment="M")
            compact_m = t_m.encode_compact()

            # Subtest A: M (`holder = M != C`) calling C's `/a2a/task` -> 403 RECIPIENT_HOLDER_MISMATCH!
            task_url_c = f"{c_node.endpoint}/a2a/task"
            r_task = httpx.post(
                task_url_c,
                json={"op": "ping"},
                headers={
                    "Authorization": f"DPoP {compact_m}",
                    "DPoP": create_dpop_proof(w_rogue_m, "POST", task_url_c, compact_m),
                },
                timeout=5.0,
            )
            self.assertEqual(r_task.status_code, 403)
            self.assertEqual(r_task.json()["error"], "RECIPIENT_HOLDER_MISMATCH")
            self.assertEqual(invoked_on_c, [])

            # Subtest B: Legitimate B1 -> C converges (200); M's poison attempt gets 403; C executes cleanly (200)!
            conv_url_c = f"{c_node.endpoint}/a2a/converge"
            compact_b1_c = t_b1_to_c.encode_compact()
            self.assertEqual(
                httpx.post(
                    conv_url_c,
                    json={"branch_data": {"from": "B1"}},
                    headers={
                        "Authorization": f"DPoP {compact_b1_c}",
                        "DPoP": create_dpop_proof(w_b1, "POST", conv_url_c, compact_b1_c),
                    },
                    timeout=5.0,
                ).status_code,
                200,
            )
            r_poison = httpx.post(
                conv_url_c,
                json={"branch_data": {"from": "M_poison"}},
                headers={
                    "Authorization": f"DPoP {compact_m}",
                    "DPoP": create_dpop_proof(w_rogue_m, "POST", conv_url_c, compact_m),
                },
                timeout=5.0,
            )
            self.assertEqual(r_poison.status_code, 403)

            r_run = httpx.post(
                task_url_c,
                json={"op": "run_converged"},
                headers={
                    "Authorization": f"DPoP {compact_b1_c}",
                    "DPoP": create_dpop_proof(w_b1, "POST", task_url_c, compact_b1_c),
                },
                timeout=5.0,
            )
            self.assertEqual(r_run.status_code, 200)
            self.assertEqual(r_run.json()["upstream_status"], 200)

            # Subtest C: Grandchild C (`A -> B1 -> C`) POSTing directly to A's `/v1/task-result` -> 403!
            res_url_a = f"{a_node.endpoint}/v1/task-result"
            r_grandchild_bypass = httpx.post(
                res_url_a,
                json={"task_id": "task-dag-clean", "result": {"bypass": True}},
                headers={
                    "Authorization": f"DPoP {compact_b1_c}",
                    "DPoP": create_dpop_proof(w_c, "POST", res_url_a, compact_b1_c),
                },
                timeout=5.0,
            )
            self.assertEqual(r_grandchild_bypass.status_code, 403)
            self.assertEqual(
                r_grandchild_bypass.json()["error"], "NOT_DIRECT_CHILD_DELEGATE"
            )
            self.assertEqual(a_node.sidecar.get_direct_results("task-dag-clean"), [])

            # Direct child B1 (`A -> B1`) POSTing to A's `/v1/task-result` -> 200 OK!
            compact_b1 = t_b1.encode_compact()
            r_direct_ok = httpx.post(
                res_url_a,
                json={"task_id": "task-dag-clean", "result": {"reviewed_by_b1": True}},
                headers={
                    "Authorization": f"DPoP {compact_b1}",
                    "DPoP": create_dpop_proof(w_b1, "POST", res_url_a, compact_b1),
                },
                timeout=5.0,
            )
            self.assertEqual(r_direct_ok.status_code, 200)
            self.assertEqual(len(a_node.sidecar.get_direct_results("task-dag-clean")), 1)
        finally:
            a_node.stop()
            c_node.stop()
            tool_node.stop()

    def test_high_01_skip_level_active_liveness_probe_freshness_and_anti_replay(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        dir_svc = AgentDirectoryService(resolver)
        rev_svc = RevocationService(ca.issue_workload("/ns/sys/sa/rev"), resolver)
        dir_url = dir_svc.start()
        rev_url = rev_svc.start()

        w_drv = ca.issue_workload("/ns/entry/sa/drv")
        w_a = ca.issue_workload("/ns/coord/sa/a")
        w_b1 = ca.issue_workload("/ns/mid/sa/healthy-b1")
        w_c = ca.issue_workload("/ns/leaf/sa/c")

        a_node = AgentSidecarNode(
            w_a, resolver, "A", ["coord"], lambda *_: (200, {}), directory_url=dir_url, revocation_url=rev_url
        )
        b1_node = AgentSidecarNode(
            w_b1, resolver, "B1", ["mid"], lambda *_: (200, {}), directory_url=dir_url, revocation_url=rev_url
        )
        a_card = a_node.start()
        b1_card = b1_node.start()
        try:
            perms = PermissionLattice.create(tools=["calc"])
            t0 = mint_root_token(
                ca,
                "task-false-skip",
                "user:alice",
                w_drv.jkt,
                w_a.spiffe_id,
                w_a.jkt,
                perms,
                hop_segment="A",
                first_hop_public_jwk=w_a.public_jwk(),
                first_hop_return_endpoint=a_card.return_endpoint,
            )
            t_b1 = t0.attenuate(
                w_a, w_b1.spiffe_id, w_b1.jkt, perms, hop_segment="B1", issuer_return_endpoint=a_card.return_endpoint
            )
            t_c = t_b1.attenuate(
                w_b1, w_c.spiffe_id, w_c.jkt, perms, hop_segment="C", issuer_return_endpoint=b1_card.return_endpoint
            )
            compact_tc = t_c.encode_compact()
            skip_url = f"{a_node.endpoint}/v1/skip-level-return"

            # Subtest A: Even if C lies and puts dead `127.0.0.1:9` in `failed_endpoint`,
            # A probes B1's signed `issuer_return_endpoint/healthz`, sees B1 is ALIVE, and rejects with 403!
            fake_ev = FailureEvidence(
                failed_spiffe_id=w_b1.spiffe_id,
                failed_endpoint="http://127.0.0.1:9",
                fault_type=FaultType.CRASH,
                error_detail="Forged crash while B1 is alive",
                attempt_count=1,
                observed_at=time.time(),
            )
            forged_skip = SkipLevelReceipt.create_and_sign(
                w_c, t_c, [w_b1.spiffe_id], w_a.spiffe_id, fake_ev, {"unreviewed": True}
            )
            r_alive = httpx.post(
                skip_url,
                json={"skip_level_receipt": forged_skip.to_dict()},
                headers={"DPoP": create_dpop_proof(w_c, "POST", skip_url, compact_tc)},
                timeout=5.0,
            )
            self.assertEqual(r_alive.status_code, 403)
            self.assertEqual(r_alive.json()["error"], "INTERMEDIATE_ANCESTOR_ALIVE")
            # Healthy B1 MUST NOT be revoked!
            self.assertIsNone(rev_svc.trie.check_lineage_path("/task-false-skip/A/B1"))

            # Subtest B: Stop B1 genuinely -> fresh SkipLevelReceipt succeeds (200),
            # replaying same receipt (with fresh DPoP) is 403, and stale receipt is 403!
            b1_node.stop()
            valid_skip = SkipLevelReceipt.create_and_sign(
                w_c, t_c, [w_b1.spiffe_id], w_a.spiffe_id, fake_ev, {"legit": 42}
            )
            r_ok = httpx.post(
                skip_url,
                json={"skip_level_receipt": valid_skip.to_dict()},
                headers={"DPoP": create_dpop_proof(w_c, "POST", skip_url, compact_tc)},
                timeout=5.0,
            )
            self.assertEqual(r_ok.status_code, 200)

            r_replay = httpx.post(
                skip_url,
                json={"skip_level_receipt": valid_skip.to_dict()},
                headers={"DPoP": create_dpop_proof(w_c, "POST", skip_url, compact_tc)},
                timeout=5.0,
            )
            self.assertEqual(r_replay.status_code, 403)

            stale_skip = SkipLevelReceipt.create_and_sign(
                w_c,
                t_c,
                [w_b1.spiffe_id],
                w_a.spiffe_id,
                fake_ev,
                {"stale": 1},
                now=time.time() - 600.0,
            )
            r_stale = httpx.post(
                skip_url,
                json={"skip_level_receipt": stale_skip.to_dict()},
                headers={"DPoP": create_dpop_proof(w_c, "POST", skip_url, compact_tc)},
                timeout=5.0,
            )
            self.assertEqual(r_stale.status_code, 403)
        finally:
            a_node.stop()
            b1_node.stop()
            dir_svc.stop()
            rev_svc.stop()

    def test_high_02_atomic_per_block_chain_quota_prevents_race_reattenuation_and_dag_sum(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_a = ca.issue_workload("/ns/c/sa/a")
        w_b1 = ca.issue_workload("/ns/c/sa/b1")
        w_b2 = ca.issue_workload("/ns/c/sa/b2")
        w_c = ca.issue_workload("/ns/c/sa/c")
        w_tool = ca.issue_workload("/ns/t/sa/tool")

        htu = "http://127.0.0.1:19876/mcp"
        verifier = LeafVerifier(
            w_tool.spiffe_id, resolver, self_jkt=w_tool.jkt, mode=VerificationMode.LOCAL_FULL_CHAIN
        )

        # Subtest A: 16-thread TOCTOU stress race on `max_calls=1` -> strictly 1 ALLOW!
        p_one = PermissionLattice.create(
            tools=["pay"],
            allowed_scopes=["s"],
            param_whitelist={f"p{k}": ["v"] for k in range(10)},
            max_calls=1,
        )
        race_args = {"scopes": ["s"] * 500, **{f"p{k}": ["v"] * 100 for k in range(10)}}
        tok_race = mint_root_token(
            ca, "task-quota-race", "user:alice", w_drv.jkt, w_c.spiffe_id, w_c.jkt, p_one, hop_segment="C"
        ).encode_compact()
        proofs = [create_dpop_proof(w_c, "POST", htu, tok_race) for _ in range(16)]
        barrier = threading.Barrier(16)

        def _fire(idx: int) -> bool:
            barrier.wait()
            return verifier.verify_request(
                tok_race, proofs[idx], "POST", htu, tool="pay", arguments=race_args
            ).allowed

        orig_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                allowed_count = sum(1 for ok in pool.map(_fire, range(16)) if ok)
        finally:
            sys.setswitchinterval(orig_interval)
        self.assertEqual(allowed_count, 1)

        # Subtest B: 5 offline re-attenuated sibling tokens under RootBlock `max_calls=1` -> strictly 1 ALLOW!
        t0_strict = mint_root_token(
            ca, "task-quota-amp", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p_one, hop_segment="A"
        )
        amp_allowed = 0
        for i in range(5):
            child_tok = t0_strict.attenuate(
                w_a, w_c.spiffe_id, w_c.jkt, p_one, hop_segment=f"C-{i}"
            ).encode_compact()
            if verifier.verify_request(
                child_tok,
                create_dpop_proof(w_c, "POST", htu, child_tok),
                "POST",
                htu,
                tool="pay",
                arguments={},
            ).allowed:
                amp_allowed += 1
        self.assertEqual(amp_allowed, 1)

        # Subtest C: MultiParentToken sharing RootBlock `max_calls=1` -> strictly 1 ALLOW!
        t0_dag = mint_root_token(
            ca, "task-quota-dag", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p_one, hop_segment="A"
        )
        ch1 = t0_dag.attenuate(w_a, w_b1.spiffe_id, w_b1.jkt, p_one, hop_segment="B1").attenuate(
            w_b1, w_c.spiffe_id, w_c.jkt, p_one, hop_segment="C"
        )
        ch2 = t0_dag.attenuate(w_a, w_b2.spiffe_id, w_b2.jkt, p_one, hop_segment="B2").attenuate(
            w_b2, w_c.spiffe_id, w_c.jkt, p_one, hop_segment="C"
        )
        mpt = MultiParentToken.assemble_and_sign(w_c, [ch1, ch2]).encode_compact()
        dag_allowed = sum(
            1
            for _ in range(3)
            if verifier.verify_request(
                mpt, create_dpop_proof(w_c, "POST", htu, mpt), "POST", htu, tool="pay", arguments={}
            ).allowed
        )
        self.assertEqual(dag_allowed, 1)

    def test_high_03_nan_and_infinity_rejected_across_jws_dpop_services_and_verifier(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)
        w_c = ca.issue_workload("/ns/c/sa/c")
        w_rev = ca.issue_workload("/ns/sys/sa/rev")

        tok_str = "lct1.dummy"
        ath = sha256_b64url(tok_str.encode("ascii"))
        htu = "http://127.0.0.1:18080/mcp"

        # 1. DPoP with NaN / Infinity rejected
        for bad_const in ("NaN", "Infinity", "-Infinity"):
            raw_dpop = f'{{"ath":"{ath}","htm":"POST","htu":"{htu}","iat":{bad_const},"jti":"id-{bad_const}"}}'
            bad_proof = _sign_raw_jws_unrestricted(
                raw_dpop, w_c.keypair, "dpop+jwt", {"jwk": w_c.public_jwk()}
            )
            with self.assertRaises(DPoPError):
                DPoPVerifier().verify_proof(bad_proof, "POST", htu, tok_str, w_c.jkt)

        # 2 & 3. AgentDirectoryService & RevocationService reject `"iat": "nan"` and raw `NaN`
        dir_svc = AgentDirectoryService(resolver, authorized_admins=[w_c.spiffe_id])
        rev_svc = RevocationService(w_rev, resolver, authorized_admins=[w_c.spiffe_id])
        dir_url = dir_svc.start()
        rev_url = rev_svc.start()
        try:
            q_cmd = jws_sign_compact(
                {"target_spiffe_id": "spiffe://org-alpha.io/ns/x/sa/v", "iat": "nan"},
                w_c.keypair,
                typ="lct-quarantine+jwt",
            )
            r_dir = httpx.post(
                f"{dir_url}/v1/agents/quarantine",
                json={"reporter_svid": w_c.workload_svid, "command_jws": q_cmd},
                timeout=3.0,
            )
            self.assertEqual(r_dir.status_code, 403)

            rev_cmd = _sign_raw_jws_unrestricted(
                '{"prefix":"/task-nan","reason":"immortal","iat":NaN}',
                w_c.keypair,
                typ="lct-revoke-cmd+jwt",
            )
            r_rev = httpx.post(
                f"{rev_url}/v1/revoke/prefix",
                json={"auth_mode": "workload", "caller_svid": w_c.workload_svid, "command_jws": rev_cmd},
                timeout=3.0,
            )
            self.assertEqual(r_rev.status_code, 403)
        finally:
            dir_svc.stop()
            rev_svc.stop()

        # 4. LeafVerifier returns clean 401 MALFORMED_TOKEN (never uncaught 500 CryptoError!) on NaN in token
        valid_tok = mint_root_token(
            ca, "task-nan", "user:alice", w_c.jkt, w_c.spiffe_id, w_c.jkt, PermissionLattice.create(tools=["t1"]), hop_segment="C"
        )
        obj = json.loads(b64url_decode(valid_tok.encode_compact()[5:]).decode("utf-8"))
        obj["root"]["iat"] = float("nan")
        nan_wire = "lct1." + b64url_encode(json.dumps(obj, allow_nan=True).encode("utf-8"))
        lv = LeafVerifier("spiffe://org-alpha.io/ns/t/sa/tool", resolver)
        res = lv.verify_request(
            nan_wire,
            create_dpop_proof(w_c, "POST", htu, nan_wire),
            "POST",
            htu,
            tool="t1",
        )
        self.assertFalse(res.allowed)
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.reason_code, "MALFORMED_TOKEN")

    def test_high_04_auditor_hardened_failover_skip_level_multiparent_bfs_and_collector_auth(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        w_drv = ca_alpha.issue_workload("/ns/e/sa/drv")
        w_a = ca_alpha.issue_workload("/ns/c/sa/a")
        w_b1 = ca_alpha.issue_workload("/ns/c/sa/b1")
        w_b2 = ca_alpha.issue_workload("/ns/c/sa/b2")
        w_c = ca_alpha.issue_workload("/ns/c/sa/c")
        w_tool = ca_alpha.issue_workload("/ns/t/sa/tool")
        w_rogue = ca_alpha.issue_workload("/ns/evil/sa/rogue")

        p0 = PermissionLattice.create(tools=["pay"])
        t0 = mint_root_token(
            ca_alpha,
            "task-aud-01",
            "user:alice",
            w_drv.jkt,
            w_a.spiffe_id,
            w_a.jkt,
            p0,
            hop_segment="A",
            first_hop_public_jwk=w_a.public_jwk(),
        )

        # 1. Forged FailoverReceipt (fake revocation_event_sig + rogue issuer) -> ILLEGAL_FAILOVER_SPOOF!
        em_root = AuditStreamEmitter(ca_alpha)
        em_rogue = AuditStreamEmitter(w_rogue)
        em_root.emit(
            AuditEventType.ROOT_MINT,
            "task-aud-01",
            "user:alice",
            t0.lineage_path,
            0,
            0,
            t0.root_block_hash,
            t0.leaf_block_hash,
            "ALLOW",
            permissions_summary=p0.to_dict(),
        )
        fake_fr = FailoverReceipt.create_and_sign(
            parent_identity=w_rogue,
            task_id="task-aud-01",
            pruned_lineage_path="/task-aud-01/A/B1",
            revocation_version=999,
            revocation_event_sig="NOT_A_REAL_REVOCATION_SERVICE_SIGNATURE",
            failed_delegate_spiffe_id=w_a.spiffe_id,
            substitute_delegate_spiffe_id=w_rogue.spiffe_id,
            new_lineage_path="/task-aud-01/A/Rogue-e1",
            old_epoch=0,
            new_epoch=1,
            failure_evidence=FailureEvidence(
                failed_spiffe_id=w_a.spiffe_id,
                failed_endpoint="http://127.0.0.1:9",
                fault_type=FaultType.CRASH,
                error_detail="fake",
                attempt_count=1,
                observed_at=time.time(),
            ),
        )
        em_rogue.emit(
            AuditEventType.FAILOVER_PRUNE_GRAFT,
            "task-aud-01",
            "user:alice",
            "/task-aud-01/A/Rogue-e1",
            1,
            1,
            t0.root_block_hash,
            "forged-block-hash",
            "RECOVERED",
            receipt_payload=fake_fr.to_dict(),
            timestamp=100.0,
        )
        auditor = CausalChainAuditor(resolver)
        rep_spoof = auditor.audit(em_root.local_entries() + em_rogue.local_entries())
        self.assertFalse(rep_spoof.clean)
        self.assertIn(
            "ILLEGAL_FAILOVER_SPOOF",
            {a.code for a in rep_spoof.tasks["task-aud-01"].anomalies},
        )

        # 2. Unauthenticated AuditCollectorService poisoning rejected (403), preserving clean task!
        collector = AuditCollectorService(trust_resolver=resolver)
        col_url = collector.start()
        try:
            for e in em_root.local_entries():
                collector.append_direct(e)
            bogus = em_root.local_entries()[0].to_dict()
            bogus["stream_id"] = "anon-attacker"
            bogus["node_signature"] = "invalid"
            r_inject = httpx.post(
                f"{col_url}/v1/audit/append", json={"entry": bogus}, timeout=3.0
            )
            self.assertEqual(r_inject.status_code, 403)
            self.assertTrue(auditor.audit(collector.get_all_entries()).clean)
        finally:
            collector.stop()

        # 3. Full DFS over `multi_parent_hashes` catches unanchored cycle on 2nd branch!
        t_b1 = t0.attenuate(w_a, w_b1.spiffe_id, w_b1.jkt, p0, hop_segment="B1")
        t_b1_c = t_b1.attenuate(w_b1, w_c.spiffe_id, w_c.jkt, p0, hop_segment="C")
        em_r3 = AuditStreamEmitter(ca_alpha, stream_id="r3")
        em_a3 = AuditStreamEmitter(w_a, stream_id="a3")
        em_b1_3 = AuditStreamEmitter(w_b1, stream_id="b1_3")
        em_b2_3 = AuditStreamEmitter(w_b2, stream_id="b2_3")
        em_c3 = AuditStreamEmitter(w_c, stream_id="c3")
        em_t3 = AuditStreamEmitter(w_tool, stream_id="t3")

        em_r3.emit(
            AuditEventType.ROOT_MINT,
            "task-aud-01",
            "user:alice",
            t0.lineage_path,
            0,
            0,
            t0.root_block_hash,
            t0.leaf_block_hash,
            "ALLOW",
        )
        em_a3.emit(
            AuditEventType.OUTBOUND_DELEGATE,
            "task-aud-01",
            "user:alice",
            t_b1.lineage_path,
            1,
            0,
            t0.root_block_hash,
            t_b1.leaf_block_hash,
            "ALLOW",
            parent_block_hash=t_b1.parent_block_hash,
        )
        em_b1_3.emit(
            AuditEventType.OUTBOUND_DELEGATE,
            "task-aud-01",
            "user:alice",
            t_b1_c.lineage_path,
            2,
            0,
            t0.root_block_hash,
            t_b1_c.leaf_block_hash,
            "ALLOW",
            parent_block_hash=t_b1_c.parent_block_hash,
        )
        em_b2_3.emit(
            AuditEventType.OUTBOUND_DELEGATE,
            "task-aud-01",
            "user:alice",
            "/task-aud-01/A/B2/Cycle1",
            2,
            0,
            t0.root_block_hash,
            "cycle-h1",
            "ALLOW",
            multi_parent_hashes=("cycle-h2",),
        )
        em_b2_3.emit(
            AuditEventType.OUTBOUND_DELEGATE,
            "task-aud-01",
            "user:alice",
            "/task-aud-01/A/B2/Cycle2",
            2,
            0,
            t0.root_block_hash,
            "cycle-h2",
            "ALLOW",
            multi_parent_hashes=("cycle-h1",),
        )
        em_c3.emit(
            AuditEventType.OUTBOUND_DELEGATE,
            "task-aud-01",
            "user:alice",
            "/task-aud-01/A/B1/C|/task-aud-01/A/B2/Cycle1",
            2,
            0,
            t0.root_block_hash,
            "mp-env-h",
            "ALLOW",
            multi_parent_hashes=(t_b1_c.leaf_block_hash, "cycle-h1"),
        )
        em_t3.emit(
            AuditEventType.TOOL_INVOCATION,
            "task-aud-01",
            "user:alice",
            "/task-aud-01/A/B1/C|/task-aud-01/A/B2/Cycle1",
            2,
            0,
            t0.root_block_hash,
            "mp-env-h",
            "ALLOW",
            multi_parent_hashes=(t_b1_c.leaf_block_hash, "cycle-h1"),
        )
        rep_cycle = auditor.audit(
            em_r3.local_entries()
            + em_a3.local_entries()
            + em_b1_3.local_entries()
            + em_b2_3.local_entries()
            + em_c3.local_entries()
            + em_t3.local_entries()
        )
        self.assertFalse(rep_cycle.clean)
        self.assertIn(
            "CAUSAL_CYCLE", {a.code for a in rep_cycle.tasks["task-aud-01"].anomalies}
        )

        # 4. SkipLevelReceipt foreign-root mismatch caught, AND historical post-TTL valid log passes!
        t_foreign = (
            mint_root_token(
                ca_beta,
                "task-aud-01",
                "user:mallory",
                w_drv.jkt,
                w_a.spiffe_id,
                w_a.jkt,
                p0,
                hop_segment="A",
                first_hop_public_jwk=w_a.public_jwk(),
            )
            .attenuate(w_a, w_b2.spiffe_id, w_b2.jkt, p0, hop_segment="B2")
            .attenuate(w_b2, w_c.spiffe_id, w_c.jkt, p0, hop_segment="C")
        )
        foreign_sr = SkipLevelReceipt.create_and_sign(
            w_c,
            t_foreign,
            [w_b2.spiffe_id],
            w_a.spiffe_id,
            FailureEvidence(w_b2.spiffe_id, "http://127.0.0.1:9", FaultType.CRASH, "down", 1, time.time()),
            {"spoofed": True},
        )
        em_r4 = AuditStreamEmitter(ca_alpha, stream_id="r4")
        em_a4 = AuditStreamEmitter(w_a, stream_id="a4")
        em_r4.emit(
            AuditEventType.ROOT_MINT,
            "task-aud-01",
            "user:alice",
            t0.lineage_path,
            0,
            0,
            t0.root_block_hash,
            t0.leaf_block_hash,
            "ALLOW",
        )
        em_a4.emit(
            AuditEventType.SKIP_LEVEL_ACCEPT,
            "task-aud-01",
            "user:alice",
            t_foreign.lineage_path,
            2,
            0,
            t0.root_block_hash,
            t_foreign.leaf_block_hash,
            "ALLOW",
            receipt_payload=foreign_sr.to_dict(),
        )
        rep_sr_mismatch = auditor.audit(em_r4.local_entries() + em_a4.local_entries())
        self.assertFalse(rep_sr_mismatch.clean)
        self.assertIn(
            "ILLEGAL_SKIP_LEVEL_SPOOF",
            {a.code for a in rep_sr_mismatch.tasks["task-aud-01"].anomalies},
        )

        # Historical SkipLevelReceipt with short 0.05s TTL audited AFTER token expiration still verifies cleanly!
        hist_ts = time.time() - 500.0
        w_a_hist = ca_alpha.issue_workload("/ns/c/sa/a-hist", now=hist_ts)
        w_b2_hist = ca_alpha.issue_workload("/ns/c/sa/b2-hist", now=hist_ts)
        w_c_hist = ca_alpha.issue_workload("/ns/c/sa/c-hist", now=hist_ts)
        t_hist = (
            mint_root_token(
                ca_alpha,
                "task-hist",
                "user:alice",
                w_drv.jkt,
                w_a_hist.spiffe_id,
                w_a_hist.jkt,
                p0,
                hop_segment="A",
                first_hop_public_jwk=w_a_hist.public_jwk(),
                ttl_seconds=1.0,
                now=hist_ts,
            )
            .attenuate(w_a_hist, w_b2_hist.spiffe_id, w_b2_hist.jkt, p0, hop_segment="B2", now=hist_ts)
            .attenuate(w_b2_hist, w_c_hist.spiffe_id, w_c_hist.jkt, p0, hop_segment="C", now=hist_ts)
        )
        hist_sr = SkipLevelReceipt.create_and_sign(
            w_c_hist,
            t_hist,
            [w_b2_hist.spiffe_id],
            w_a_hist.spiffe_id,
            FailureEvidence(w_b2_hist.spiffe_id, "http://127.0.0.1:9", FaultType.CRASH, "down", 1, hist_ts + 0.1),
            {"ok": True},
            now=hist_ts + 0.2,
        )
        em_rh = AuditStreamEmitter(ca_alpha, stream_id="rh")
        em_ah = AuditStreamEmitter(w_a_hist, stream_id="ah")
        em_rh.emit(
            AuditEventType.ROOT_MINT,
            "task-hist",
            "user:alice",
            t_hist.root.lineage_path,
            0,
            0,
            t_hist.root_block_hash,
            t_hist.root_block_hash,
            "ALLOW",
            timestamp=hist_ts,
        )
        em_ah.emit(
            AuditEventType.SKIP_LEVEL_ACCEPT,
            "task-hist",
            "user:alice",
            t_hist.lineage_path,
            2,
            0,
            t_hist.root_block_hash,
            t_hist.leaf_block_hash,
            "ALLOW",
            receipt_payload=hist_sr.to_dict(),
            timestamp=hist_ts + 0.3,
        )
        rep_hist = auditor.audit(em_rh.local_entries() + em_ah.local_entries())
        self.assertTrue(rep_hist.clean, f"Historical audit failed: {rep_hist.anomalies}")
        self.assertIn(
            "VERIFIED_SKIP_LEVEL_MERGE",
            rep_hist.tasks["task-hist"].resilience_classifications,
        )

    def test_medium_01_02_03_and_low_01_02_regressions(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        w_drv = ca_alpha.issue_workload("/ns/e/sa/drv")
        w_a = ca_alpha.issue_workload("/ns/c/sa/a")
        w_b1 = ca_alpha.issue_workload("/ns/c/sa/b1")
        w_b2 = ca_alpha.issue_workload("/ns/c/sa/b2")
        w_c = ca_alpha.issue_workload("/ns/c/sa/c")
        w_d = ca_alpha.issue_workload("/ns/c/sa/d")
        w_tool = ca_alpha.issue_workload("/ns/t/sa/tool")

        htu = "http://127.0.0.1:19877/mcp"
        lv = LeafVerifier(
            w_tool.spiffe_id,
            resolver,
            self_jkt=w_tool.jkt,
            mode=VerificationMode.LOCAL_FULL_CHAIN,
            clock_skew_seconds=0.0,
        )

        # --- MEDIUM-01 (A): Single expired branch degrades smoothly to surviving branch ---
        now = time.time()
        p_root = PermissionLattice.create(tools=["book_flight", "book_hotel"], max_amount=1000.0)
        t0 = mint_root_token(
            ca_alpha, "task-exp-dag", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p_root, hop_segment="A", now=now
        )
        ch_b1_short = t0.attenuate(
            w_a,
            w_b1.spiffe_id,
            w_b1.jkt,
            PermissionLattice.create(tools=["book_flight"], max_amount=500.0),
            hop_segment="B1",
            ttl_seconds=1.0,
            now=now,
        ).attenuate(
            w_b1,
            w_c.spiffe_id,
            w_c.jkt,
            PermissionLattice.create(tools=["book_flight"], max_amount=500.0),
            hop_segment="C",
            now=now,
        )
        ch_b2_long = t0.attenuate(
            w_a,
            w_b2.spiffe_id,
            w_b2.jkt,
            PermissionLattice.create(tools=["book_hotel"], max_amount=500.0),
            hop_segment="B2",
            ttl_seconds=600.0,
            now=now,
        ).attenuate(
            w_b2,
            w_c.spiffe_id,
            w_c.jkt,
            PermissionLattice.create(tools=["book_hotel"], max_amount=500.0),
            hop_segment="C",
            now=now,
        )
        mpt_Obj = MultiParentToken.assemble_and_sign(w_c, [ch_b1_short, ch_b2_long], now=now)
        mpt_exp = mpt_Obj.encode_compact()

        res_degraded = lv.verify_request(
            mpt_exp,
            create_dpop_proof(w_c, "POST", htu, mpt_exp, now=now + 10.0),
            "POST",
            htu,
            tool="book_hotel",
            arguments={"amount": 200.0},
            now=now + 10.0,
        )
        self.assertTrue(res_degraded.allowed)
        self.assertEqual(res_degraded.decision, "ALLOW_DEGRADED_DAG")
        self.assertEqual(res_degraded.pruned_revoked_paths, ("/task-exp-dag/A/B1/C",))

        # --- MEDIUM-03: Non-truncating downstream MultiParentToken delegation (`requested_permissions=None`) ---
        mpt_to_d = mpt_Obj.attenuate_to_delegate(
            issuer_identity=w_c,
            delegate_spiffe_id=w_d.spiffe_id,
            delegate_jkt=w_d.jkt,
            requested_permissions=None,
            hop_segment="D",
            now=now,
        ).rebind_as_holder(w_d, now=now)
        compact_d = mpt_to_d.encode_compact()
        # Verify D retains BOTH `book_flight` (from branch 0) AND `book_hotel` (from branch 1)!
        for tname in ("book_flight", "book_hotel"):
            r_d = lv.verify_request(
                compact_d,
                create_dpop_proof(w_d, "POST", htu, compact_d, now=now),
                "POST",
                htu,
                tool=tname,
                arguments={"amount": 200.0},
                now=now,
            )
            self.assertTrue(r_d.allowed, f"Branch capability {tname} was truncated!")

        # --- MEDIUM-01 (B): Principal `@domain` home-domain check & cross-root MultiParentToken block ---
        with self.assertRaises(TokenError):
            mint_root_token(
                ca_beta,
                "task-cross-root",
                "user:alice@org-alpha.io",
                w_drv.jkt,
                w_c.spiffe_id,
                w_c.jkt,
                p_root,
            )

        t_root_1 = mint_root_token(
            ca_alpha, "task-two-roots", "user:alice", w_drv.jkt, w_c.spiffe_id, w_c.jkt, p_root, hop_segment="R1"
        )
        t_root_2 = mint_root_token(
            ca_alpha, "task-two-roots", "user:alice", w_drv.jkt, w_c.spiffe_id, w_c.jkt, p_root, hop_segment="R2"
        )
        with self.assertRaises(TokenError):
            MultiParentToken.assemble_and_sign(w_c, [t_root_1, t_root_2])

        # --- MEDIUM-02: Single 403 does NOT prematurely trip `policy_breaker_threshold=3` ---
        dir_svc = AgentDirectoryService(resolver)
        rev_svc = RevocationService(ca_alpha.issue_workload("/ns/sys/sa/rev"), resolver)
        dir_url = dir_svc.start()
        rev_url = rev_svc.start()

        b1_node = AgentSidecarNode(
            w_b1, resolver, "B1", ["work"], lambda *_: (403, {"error": "transient"}), directory_url=dir_url, priority=10
        )
        b2_node = AgentSidecarNode(
            w_b2, resolver, "B2", ["work"], lambda *_: (200, {"ok": True}), directory_url=dir_url, priority=20
        )
        b1_node.start()
        b2_node.start()
        try:
            detector = ThreeLayerFaultDetector(policy_breaker_threshold=3)
            coord = ResilientDelegationCoordinator(
                w_a,
                resolver,
                AgentDirectoryClient(dir_url, resolver),
                RevocationReplicaClient(rev_url, resolver),
                detector=detector,
            )
            p_work = PermissionLattice.create(tools=["t1"])

            # 1st 403: prunes task branch and fails over to B2, WITHOUT globally quarantining B1!
            t_403_1 = mint_root_token(
                ca_alpha, "task-403-1", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p_work, hop_segment="A"
            )
            coord.invoke_with_prune_and_graft(t_403_1, "work", p_work, {})
            self.assertIsNone(rev_svc.trie.check_workloads([w_b1.spiffe_id]))

            # 2nd 403: still below threshold=3 -> NOT globally quarantined yet
            t_403_2 = mint_root_token(
                ca_alpha, "task-403-2", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p_work, hop_segment="A"
            )
            coord.invoke_with_prune_and_graft(t_403_2, "work", p_work, {})
            self.assertIsNone(rev_svc.trie.check_workloads([w_b1.spiffe_id]))

            # 3rd genuine 403: reaches `policy_breaker_threshold=3` -> trips breaker & quarantines B1!
            t_403_3 = mint_root_token(
                ca_alpha, "task-403-3", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p_work, hop_segment="A"
            )
            coord.invoke_with_prune_and_graft(t_403_3, "work", p_work, {})
            self.assertIsNotNone(rev_svc.trie.check_workloads([w_b1.spiffe_id]))
        finally:
            b1_node.stop()
            b2_node.stop()
            dir_svc.stop()
            rev_svc.stop()

        # --- LOW-01 & LOW-02: Trailing-slash `/mcp/` lattice check on standalone Sidecar (`is_tool_server=False`) ---
        dummy_app = ManagedHTTPService("dummy-app", lambda _: (200, {"reached_app": True}, {}))
        app_url = dummy_app.start()
        sc = LineageSidecar(
            identity=w_tool,
            trust_resolver=resolver,
            app_upstream_url=app_url,
            loopback_secret="top-secret-loopback",
            mode=VerificationMode.LOCAL_FULL_CHAIN,
            is_tool_server=False,
        )
        sc.start()
        try:
            tok_weather_only = mint_root_token(
                ca_alpha,
                "task-slash",
                "user:alice",
                w_drv.jkt,
                w_c.spiffe_id,
                w_c.jkt,
                PermissionLattice.create(tools=["get_weather"]),
                hop_segment="C",
            ).encode_compact()
            slash_url = f"{sc.inbound_url}/mcp/"
            r_slash = httpx.post(
                slash_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "execute_payment", "arguments": {"amount": 100}},
                },
                headers={
                    "Authorization": f"DPoP {tok_weather_only}",
                    "DPoP": create_dpop_proof(w_c, "POST", slash_url, tok_weather_only),
                },
                timeout=3.0,
            )
            self.assertEqual(r_slash.status_code, 403)
            self.assertEqual(r_slash.json()["error"], "LATTICE_PERMISSION_DENIED")
        finally:
            sc.stop()
            dummy_app.stop()

    def test_r2_critical_01_origin_form_blocks_at_userinfo_and_double_slash_ssrf(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)
        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_c = ca.issue_workload("/ns/c/sa/c")
        w_tool = ca.issue_workload("/ns/t/sa/pay-mcp")

        tool_node = MCPToolSidecarNode(
            w_tool,
            resolver,
            tools={"execute_payment": lambda args, _: {"paid": args.get("amount")}},
        )
        tool_node.start()

        ssrf_captured: list[dict] = []
        evil_srv = ManagedHTTPService(
            "evil-ssrf-listener",
            lambda req: (
                ssrf_captured.append({"path": req.path, "headers": dict(req.headers)}) or 200,
                {"hijacked": True},
                {},
            ),
        )
        evil_srv.start()
        try:
            tok = mint_root_token(
                ca,
                "task-r2-01",
                "user:alice",
                w_drv.jkt,
                w_c.spiffe_id,
                w_c.jkt,
                PermissionLattice.create(tools=["execute_payment"], max_amount=500.0),
                hop_segment="C",
            ).encode_compact()
            body_bytes = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_payment","arguments":{"amount":10}}}'

            smuggled_targets = [
                f"@127.0.0.1:{evil_srv.port}/mcp",
                f"//127.0.0.1:{evil_srv.port}/mcp",
                f"http://127.0.0.1:{evil_srv.port}/mcp",
                f"/mcp/@127.0.0.1:{evil_srv.port}",
                "/../mcp",
                "/mcp\\evil",
            ]
            sc_port = int(tool_node.sidecar.inbound_url.rsplit(":", 1)[1])
            for bad_target in smuggled_targets:
                dpop = create_dpop_proof(
                    w_c, "POST", f"{tool_node.sidecar.inbound_url}/mcp", tok
                )
                raw_http = (
                    f"POST {bad_target} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{sc_port}\r\n"
                    f"Authorization: DPoP {tok}\r\n"
                    f"DPoP: {dpop}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body_bytes)}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii") + body_bytes

                with socket.create_connection(
                    ("127.0.0.1", sc_port), timeout=3.0
                ) as s:
                    s.sendall(raw_http)
                    chunks: list[bytes] = []
                    while True:
                        buf = s.recv(4096)
                        if not buf:
                            break
                        chunks.append(buf)
                resp_text = b"".join(chunks).decode("utf-8", errors="replace")
                self.assertIn("400", resp_text.splitlines()[0], f"Target not rejected: {bad_target!r}")
                self.assertIn("invalid_request_target", resp_text)

            # Zero SSRF hits and zero leaked `X-LCT-Loopback-Auth`!
            self.assertEqual(ssrf_captured, [])
        finally:
            evil_srv.stop()
            tool_node.stop()

    def test_r2_high_01_hop1_unilateral_attenuation_cannot_globally_quarantine_peers(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)

        w_drv = ca_alpha.issue_workload("/ns/entry/sa/drv")
        w_root_coord = ca_alpha.issue_workload("/ns/coord/sa/root-coord")
        w_hop1_work = ca_alpha.issue_workload("/ns/work/sa/hop1-worker")
        w_hop1_sandbox = ca_alpha.issue_workload("/ns/sandbox/sa/hop1-leaf")
        w_pay_tool = ca_alpha.issue_workload("/ns/tool/sa/payment-mcp")
        w_rev = ca_alpha.issue_workload("/ns/sys/sa/rev")

        rev_svc = RevocationService(w_rev, resolver)
        dir_svc = AgentDirectoryService(resolver)
        rev_url = rev_svc.start()
        dir_url = dir_svc.start()
        try:
            rev_client = RevocationReplicaClient(rev_url, resolver)
            dir_client = AgentDirectoryClient(dir_url, resolver)
            dir_client.register(
                AgentCard.sign_and_create(
                    w_pay_tool, "Payment MCP", "http://127.0.0.1:19610", ["payment.exec"]
                )
            )

            p_low = PermissionLattice.create(tools=["get_weather"])
            t0 = mint_root_token(
                ca_alpha,
                "task-r2-02",
                "user:bob",
                w_drv.jkt,
                w_root_coord.spiffe_id,
                w_root_coord.jkt,
                p_low,
                hop_segment="Coord",
            )

            # Both sandbox AND standard `/ns/work/` hop-1 leaves unilaterally mint dummy child blocks
            for rogue_hop1 in (w_hop1_sandbox, w_hop1_work):
                t_hop1 = t0.attenuate(
                    w_root_coord, rogue_hop1.spiffe_id, rogue_hop1.jkt, p_low, hop_segment="H1"
                )
                self_forged_auth = t_hop1.attenuate(
                    rogue_hop1, w_pay_tool.spiffe_id, w_pay_tool.jkt, p_low, hop_segment="Victim"
                ).encode_compact()

                with self.assertRaises(RevocationError):
                    rev_client.quarantine_workload(
                        rogue_hop1,
                        w_pay_tool.spiffe_id,
                        reason="unilateral_dos",
                        authority_token=self_forged_auth,
                    )
                with self.assertRaises(AgentCardError):
                    dir_client.quarantine(
                        rogue_hop1,
                        w_pay_tool.spiffe_id,
                        reason="unilateral_dos",
                        authority_token=self_forged_auth,
                    )

            # Even Hop-0 Root Coordinator cannot globally quarantine `/ns/sys/` infrastructure (`w_rev`)!
            t0_sys = t0.attenuate(
                w_root_coord, w_rev.spiffe_id, w_rev.jkt, p_low, hop_segment="Sys"
            ).encode_compact()
            with self.assertRaises(RevocationError):
                rev_client.quarantine_workload(
                    w_root_coord, w_rev.spiffe_id, reason="infra_dos", authority_token=t0_sys
                )

            # `w_pay_tool` remains 100% healthy and unquarantined!
            self.assertIsNone(rev_svc.trie.check_workloads([w_pay_tool.spiffe_id]))
            self.assertEqual(len(dir_client.discover(skill="payment.exec")), 1)
        finally:
            rev_svc.stop()
            dir_svc.stop()

    def test_r2_high_02_trust_domain_isolated_prefix_revocation_prevents_hijack_and_collision(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        w_rev = ca_alpha.issue_workload("/ns/sys/sa/rev")
        w_drv_a = ca_alpha.issue_workload("/ns/e/sa/drv")
        w_coord_a = ca_alpha.issue_workload("/ns/c/sa/coord-a")
        w_tool_a = ca_alpha.issue_workload("/ns/t/sa/tool-a")
        w_beta = ca_beta.issue_workload("/ns/c/sa/coord-b")

        rev_svc = RevocationService(w_rev, resolver)
        rev_url = rev_svc.start()
        try:
            rev_client = RevocationReplicaClient(rev_url, resolver)
            htu = "http://127.0.0.1:19890/mcp"
            lv = LeafVerifier(
                w_tool_a.spiffe_id,
                resolver,
                revocation_replica=rev_client,
                self_jkt=w_tool_a.jkt,
                mode=VerificationMode.LOCAL_FULL_CHAIN,
            )

            # Subtest A: Foreign `ca_beta` preemptively revokes `/task-alpha-live-01` -> scoped to `org-beta.io` ONLY!
            rev_client.revoke_prefix(
                ca_beta, "/task-alpha-live-01", reason="foreign_preemptive_sabotage"
            )
            rev_client.sync_now()

            tok_alpha_1 = mint_root_token(
                ca_alpha,
                "task-alpha-live-01",
                "user:alice",
                w_drv_a.jkt,
                w_coord_a.spiffe_id,
                w_coord_a.jkt,
                PermissionLattice.create(tools=["pay"]),
                hop_segment="CoordA",
            ).encode_compact()
            res_ok = lv.verify_request(
                tok_alpha_1,
                create_dpop_proof(w_coord_a, "POST", htu, tok_alpha_1),
                "POST",
                htu,
                tool="pay",
            )
            self.assertTrue(res_ok.allowed, f"Foreign CA sabotaged Alpha task: {res_ok.detail}")

            # And `ca_alpha` is NOT locked out of revoking its own `/task-alpha-live-01`!
            rev_client.revoke_prefix(ca_alpha, "/task-alpha-live-01", reason="legit_owner_cancel")
            rev_client.sync_now()
            res_revoked = lv.verify_request(
                tok_alpha_1,
                create_dpop_proof(w_coord_a, "POST", htu, tok_alpha_1),
                "POST",
                htu,
                tool="pay",
            )
            self.assertFalse(res_revoked.allowed)
            self.assertEqual(res_revoked.reason_code, "LINEAGE_REVOKED")

            # Subtest B: Cross-domain colliding `task_id="task-shared-02"` via `authority_token` -> isolated!
            tok_alpha_2 = mint_root_token(
                ca_alpha,
                "task-shared-02",
                "user:alice",
                w_drv_a.jkt,
                w_coord_a.spiffe_id,
                w_coord_a.jkt,
                PermissionLattice.create(tools=["pay"]),
                hop_segment="CoordA",
            ).encode_compact()
            tok_beta_collide = mint_root_token(
                ca_beta,
                "task-shared-02",
                "user:bob",
                w_beta.jkt,
                w_beta.spiffe_id,
                w_beta.jkt,
                PermissionLattice.create(tools=["pay"]),
                hop_segment="CoordB",
            ).encode_compact()
            rev_client.revoke_prefix(
                w_beta,
                "/task-shared-02",
                reason="beta_collision_revoke",
                authority_token=tok_beta_collide,
            )
            rev_client.sync_now()

            res_alpha_2 = lv.verify_request(
                tok_alpha_2,
                create_dpop_proof(w_coord_a, "POST", htu, tok_alpha_2),
                "POST",
                htu,
                tool="pay",
            )
            self.assertTrue(res_alpha_2.allowed)
        finally:
            rev_svc.stop()

    def test_r2_high_03_failover_receipt_rejects_self_or_peer_svid_and_collector_requires_resolver(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_parent = ca.issue_workload("/ns/c/sa/compromised-coord")
        w_b1 = ca.issue_workload("/ns/w/sa/b1")
        w_b2 = ca.issue_workload("/ns/w/sa/b2")
        w_colluding_peer = ca.issue_workload("/ns/w/sa/colluding-helper")

        # Subtest B: AuditCollectorService without TrustBundleResolver is strictly forbidden!
        with self.assertRaises(TypeError):
            AuditCollectorService()  # type: ignore[call-arg]

        # Subtest A: Self-signed (`w_parent`) AND colluding non-system peer (`w_colluding_peer`)
        # `RevocationEvent` signatures inside `FailoverReceipt` are rejected!
        p0 = PermissionLattice.create(tools=["pay"])
        t0 = mint_root_token(
            ca, "task-r2-04", "user:alice", w_drv.jkt, w_parent.spiffe_id, w_parent.jkt, p0, hop_segment="A"
        )
        t_b1 = t0.attenuate(w_parent, w_b1.spiffe_id, w_b1.jkt, p0, hop_segment="B1")

        for fake_signer in (w_parent, w_colluding_peer):
            provisional_ev = RevocationEvent(
                version=1,
                kind=RevocationKind.SUBTREE,
                target=t_b1.lineage_path,
                reason="fake_prune",
                requested_by=w_parent.spiffe_id,
                timestamp=time.time() - 1.0,
                service_signature="",
                service_svid=fake_signer.workload_svid,
                trust_domain="org-alpha.io",
            )
            fake_sig = jws_sign_compact(
                provisional_ev.core_claims(),
                fake_signer.keypair,
                typ="lct-revocation-event+jwt",
            )
            forged_ev = RevocationEvent(
                **{**provisional_ev.__dict__, "service_signature": fake_sig}
            )
            forged_fr = FailoverReceipt.create_and_sign(
                parent_identity=w_parent,
                task_id="task-r2-04",
                pruned_lineage_path=t_b1.lineage_path,
                revocation_version=1,
                revocation_event_sig=fake_sig,
                failed_delegate_spiffe_id=w_b1.spiffe_id,
                substitute_delegate_spiffe_id=w_b2.spiffe_id,
                new_lineage_path="/task-r2-04/A/B2-e1",
                old_epoch=0,
                new_epoch=1,
                failure_evidence=FailureEvidence(
                    w_b1.spiffe_id, "http://127.0.0.1:9", FaultType.CRASH, "fake", 1, time.time() - 1.0
                ),
                revocation_event=forged_ev.to_dict(),
                revocation_service_svid=fake_signer.workload_svid,
            )
            with self.assertRaises(ResilienceError):
                FailoverReceipt.from_dict_and_verify(forged_fr.to_dict(), resolver)

            em_r = AuditStreamEmitter(ca, stream_id=f"r-{fake_signer.keypair.kid[:6]}")
            em_p = AuditStreamEmitter(w_parent, stream_id=f"p-{fake_signer.keypair.kid[:6]}")
            now_ts = time.time()
            em_r.emit(
                AuditEventType.ROOT_MINT,
                "task-r2-04",
                "user:alice",
                t0.lineage_path,
                0,
                0,
                t0.root_block_hash,
                t0.leaf_block_hash,
                "ALLOW",
                timestamp=now_ts - 2.0,
            )
            em_p.emit(
                AuditEventType.REVOCATION_ISSUED,
                "task-r2-04",
                "user:alice",
                t_b1.lineage_path,
                1,
                0,
                t0.root_block_hash,
                t_b1.leaf_block_hash,
                "REVOKED",
                action_detail={"target": t_b1.lineage_path, "revocation_version": 1},
                timestamp=now_ts - 1.0,
            )
            em_p.emit(
                AuditEventType.FAILOVER_PRUNE_GRAFT,
                "task-r2-04",
                "user:alice",
                "/task-r2-04/A/B2-e1",
                1,
                1,
                t0.root_block_hash,
                t_b1.leaf_block_hash,
                "RECOVERED",
                parent_block_hash=t0.leaf_block_hash,
                receipt_payload=forged_fr.to_dict(),
                timestamp=now_ts,
            )
            rep = CausalChainAuditor(resolver).audit(em_r.local_entries() + em_p.local_entries())
            self.assertFalse(rep.clean)
            self.assertIn(
                "ILLEGAL_FAILOVER_SPOOF",
                {a.code for a in rep.tasks["task-r2-04"].anomalies},
            )

    def test_r2_medium_01_clean_return_endpoint_blocks_ssrf_and_empty_probe_fails_closed(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_a = ca.issue_workload("/ns/c/sa/a")
        w_b1 = ca.issue_workload("/ns/m/sa/b1")
        w_c = ca.issue_workload("/ns/l/sa/c")

        ssrf_hits: list[str] = []
        trap_srv = ManagedHTTPService(
            "ssrf-trap",
            lambda req: (ssrf_hits.append(req.raw_path) or 500, {"trap": True}, {}),
        )
        trap_url = trap_srv.start()

        a_node = AgentSidecarNode(
            w_a, resolver, "Ancestor A", ["coord"], lambda *_: (200, {}), directory_url=None
        )
        b1_node = AgentSidecarNode(
            w_b1, resolver, "Healthy B1", ["mid"], lambda *_: (200, {}), directory_url=None
        )
        a_card = a_node.start()
        b1_node.start()
        try:
            perms = PermissionLattice.create(tools=["calc"])
            t0 = mint_root_token(
                ca,
                "task-r2-05",
                "user:alice",
                w_drv.jkt,
                w_a.spiffe_id,
                w_a.jkt,
                perms,
                hop_segment="A",
                first_hop_public_jwk=w_a.public_jwk(),
                first_hop_return_endpoint=a_card.return_endpoint,
            )
            t_b1 = t0.attenuate(
                w_a,
                w_b1.spiffe_id,
                w_b1.jkt,
                perms,
                hop_segment="B1",
                issuer_return_endpoint=a_card.return_endpoint,
            )

            # Subtest A1: Query/path/userinfo smuggling rejected in `attenuate` and `AgentCard`
            for bad_ep in (
                f"{trap_url}/admin/wipe?swallow=",
                f"http://evil@127.0.0.1:{trap_srv.port}",
                f"{trap_url}/extra-path",
                f"{trap_url}#frag",
            ):
                with self.assertRaises(TokenError):
                    t_b1.attenuate(
                        w_b1,
                        w_c.spiffe_id,
                        w_c.jkt,
                        perms,
                        hop_segment="C",
                        issuer_return_endpoint=bad_ep,
                    )
                with self.assertRaises(AgentCardError):
                    AgentCard.sign_and_create(w_b1, "BadCard", bad_ep, ["mid"])

            # Subtest B: Empty probe URL list (`issuer_return_endpoint=None` & `directory_url=None`)
            # MUST fail closed (`403 SKIP_LEVEL_UNVERIFIABLE_LIVENESS`) while B1 is alive!
            t_c_no_ep = t_b1.attenuate(
                w_b1,
                w_c.spiffe_id,
                w_c.jkt,
                perms,
                hop_segment="C",
                issuer_return_endpoint=None,
            )
            fake_ev = FailureEvidence(
                w_b1.spiffe_id, "http://127.0.0.1:9", FaultType.CRASH, "lie", 1, time.time()
            )
            sr_no_ep = SkipLevelReceipt.create_and_sign(
                w_c, t_c_no_ep, [w_b1.spiffe_id], w_a.spiffe_id, fake_ev, {"bypass": True}
            )
            skip_url = f"{a_node.endpoint}/v1/skip-level-return"
            compact_no_ep = t_c_no_ep.encode_compact()
            r_fail_closed = httpx.post(
                skip_url,
                json={"skip_level_receipt": sr_no_ep.to_dict()},
                headers={"DPoP": create_dpop_proof(w_c, "POST", skip_url, compact_no_ep)},
                timeout=5.0,
            )
            self.assertEqual(r_fail_closed.status_code, 403)
            self.assertIn("SKIP_LEVEL_UNVERIFIABLE_LIVENESS", r_fail_closed.text)
            self.assertEqual(a_node.sidecar.get_skip_level_results("task-r2-05"), [])
            self.assertEqual(ssrf_hits, [])
        finally:
            a_node.stop()
            b1_node.stop()
            trap_srv.stop()

    def test_r3_high_01_dot_segment_and_percent_encoded_mcp_lattice_enforced(self) -> None:
        from urllib.parse import unquote

        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)
        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_c = ca.issue_workload("/ns/c/sa/c")
        w_tool = ca.issue_workload("/ns/t/sa/hybrid-mcp")

        executed_calls: list[dict] = []

        def _upstream_app(req: HTTPRequestContext):
            if unquote(req.path) == "/mcp":
                body = req.json()
                params = body.get("params", {})
                executed_calls.append({"tool": params.get("name")})
                return 200, {"executed": True}, {}
            return 404, {"error": "not_found"}, {}

        upstream = ManagedHTTPService("upstream-r3-mcp", _upstream_app)
        app_url = upstream.start()
        sc = LineageSidecar(
            identity=w_tool,
            trust_resolver=resolver,
            app_upstream_url=app_url,
            loopback_secret="secret-loopback-r3",
            mode=VerificationMode.LOCAL_FULL_CHAIN,
            is_tool_server=False,
        )
        sc.start()
        try:
            tok_weather = mint_root_token(
                ca,
                "task-r3-01",
                "user:alice",
                w_drv.jkt,
                w_c.spiffe_id,
                w_c.jkt,
                PermissionLattice.create(tools=["get_weather"], max_calls=1),
                hop_segment="C",
            )
            tok_deleg = tok_weather.attenuate(
                w_c,
                w_tool.spiffe_id,
                w_tool.jkt,
                PermissionLattice.create(tools=["get_weather"], max_calls=1),
                hop_segment="Tool",
            ).encode_compact()

            sc_port = int(sc.inbound_url.rsplit(":", 1)[1])
            forbidden_body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "execute_payment", "arguments": {"amount": 999999}},
                }
            ).encode("utf-8")

            def _send_raw(target_path: str) -> tuple[int, str]:
                htu_p = f"{sc.inbound_url}{target_path}"
                dpop = create_dpop_proof(w_c, "POST", htu_p, tok_deleg)
                raw_req = (
                    f"POST {target_path} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{sc_port}\r\n"
                    f"Authorization: DPoP {tok_deleg}\r\n"
                    f"DPoP: {dpop}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(forbidden_body)}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii") + forbidden_body
                with socket.create_connection(("127.0.0.1", sc_port), timeout=3.0) as sock:
                    sock.sendall(raw_req)
                    chunks: list[bytes] = []
                    while True:
                        buf = sock.recv(4096)
                        if not buf:
                            break
                        chunks.append(buf)
                text = b"".join(chunks).decode("utf-8", errors="replace")
                return int(text.splitlines()[0].split()[1]), text

            # 1. Dot segments & mid-path double slashes -> 400 invalid_request_target
            for bad_dot_path in (
                "/./mcp",
                "/mcp/.",
                "/.//127.0.0.1:9999/mcp",
                "/%2e/mcp",
                "/mcp/%2e",
                "/%252e/mcp",
            ):
                st, txt = _send_raw(bad_dot_path)
                self.assertEqual(st, 400, f"Expected 400 for {bad_dot_path!r}, got {st}: {txt}")
                self.assertIn("invalid_request_target", txt)

            # 2. Single & double percent-encoded `/mcp` (`/%6d%63%70`, `/%256d%2563%2570`) -> 403 LATTICE_PERMISSION_DENIED!
            for encoded_mcp in ("/%6d%63%70", "/%6D%63%70/", "/%256d%2563%2570"):
                st_enc, txt_enc = _send_raw(encoded_mcp)
                self.assertEqual(st_enc, 403, f"Bypassed lattice on {encoded_mcp!r}: {txt_enc}")
                self.assertIn("LATTICE_PERMISSION_DENIED", txt_enc)

            self.assertEqual(executed_calls, [])
        finally:
            sc.stop()
            upstream.stop()

    def test_r3_high_02_failover_receipt_enforces_revocation_trust_domain_and_same_domain_svid(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        w_rev_alpha = ca_alpha.issue_workload("/ns/sys/sa/rev")
        w_drv_a = ca_alpha.issue_workload("/ns/e/sa/drv")
        w_parent_a = ca_alpha.issue_workload("/ns/c/sa/parent-a")
        w_b1_a = ca_alpha.issue_workload("/ns/w/sa/b1")
        w_b2_a = ca_alpha.issue_workload("/ns/w/sa/b2")
        w_beta_helper = ca_beta.issue_workload("/ns/c/sa/helper-b")
        w_beta_rev = ca_beta.issue_workload("/ns/sys/sa/rev")

        rev_svc = RevocationService(w_rev_alpha, resolver)
        rev_url = rev_svc.start()
        try:
            rev_client = RevocationReplicaClient(rev_url, resolver)
            p_pay = PermissionLattice.create(tools=["execute_payment"], max_amount=500.0)
            t0_alpha = mint_root_token(
                ca_alpha,
                "task-r3-split",
                "user:alice",
                w_drv_a.jkt,
                w_parent_a.spiffe_id,
                w_parent_a.jkt,
                p_pay,
                hop_segment="A",
            )
            t_b1_alpha = t0_alpha.attenuate(
                w_parent_a, w_b1_a.spiffe_id, w_b1_a.jkt, p_pay, hop_segment="B1"
            )

            # Subtest A: Colliding `org-beta.io` RevocationEvent signed by real `w_rev_alpha` -> REJECTED!
            t_b1_beta = mint_root_token(
                ca_beta,
                "task-r3-split",
                "user:bob",
                w_beta_helper.jkt,
                w_beta_helper.spiffe_id,
                w_beta_helper.jkt,
                p_pay,
                hop_segment="A",
            ).attenuate(w_beta_helper, w_b1_a.spiffe_id, w_b1_a.jkt, p_pay, hop_segment="B1")
            beta_rev_ev = rev_client.revoke_prefix(
                w_beta_helper,
                "/task-r3-split/A/B1",
                reason="decoy_beta_prune",
                authority_token=t_b1_beta.encode_compact(),
            )

            split_fr = FailoverReceipt.create_and_sign(
                parent_identity=w_parent_a,
                task_id="task-r3-split",
                pruned_lineage_path="/task-r3-split/A/B1",
                revocation_version=beta_rev_ev.version,
                revocation_event_sig=beta_rev_ev.service_signature,
                failed_delegate_spiffe_id=w_b1_a.spiffe_id,
                substitute_delegate_spiffe_id=w_b2_a.spiffe_id,
                new_lineage_path="/task-r3-split/A/B2-e1",
                old_epoch=0,
                new_epoch=1,
                failure_evidence=FailureEvidence(
                    w_b1_a.spiffe_id, "http://127.0.0.1:9", FaultType.CRASH, "split", 1, time.time()
                ),
                revocation_event=beta_rev_ev.to_dict(),
                revocation_service_svid=w_rev_alpha.workload_svid,
            )
            with self.assertRaises(ResilienceError):
                FailoverReceipt.from_dict_and_verify(
                    split_fr.to_dict(),
                    resolver,
                    trusted_revocation_spiffe_ids=[w_rev_alpha.spiffe_id],
                )

            now_ts = time.time()
            em_ca = AuditStreamEmitter(ca_alpha, stream_id="ca-r3")
            em_pa = AuditStreamEmitter(w_parent_a, stream_id="pa-r3")
            em_ca.emit(
                AuditEventType.ROOT_MINT,
                "task-r3-split",
                "user:alice",
                t0_alpha.lineage_path,
                0,
                0,
                t0_alpha.root_block_hash,
                t0_alpha.leaf_block_hash,
                "ALLOW",
                timestamp=now_ts - 2.0,
            )
            em_pa.emit(
                AuditEventType.REVOCATION_ISSUED,
                "task-r3-split",
                "user:alice",
                "/task-r3-split/A/B1",
                1,
                0,
                t0_alpha.root_block_hash,
                t_b1_alpha.leaf_block_hash,
                "REVOKED",
                action_detail={"target": "/task-r3-split/A/B1", "revocation_version": beta_rev_ev.version},
                timestamp=now_ts - 1.0,
            )
            em_pa.emit(
                AuditEventType.FAILOVER_PRUNE_GRAFT,
                "task-r3-split",
                "user:alice",
                "/task-r3-split/A/B2-e1",
                1,
                1,
                t0_alpha.root_block_hash,
                t_b1_alpha.leaf_block_hash,
                "RECOVERED",
                parent_block_hash=t0_alpha.leaf_block_hash,
                receipt_payload=split_fr.to_dict(),
                timestamp=now_ts,
            )
            auditor = CausalChainAuditor(resolver, trusted_revocation_spiffe_ids=[w_rev_alpha.spiffe_id])
            rep = auditor.audit(em_ca.local_entries() + em_pa.local_entries())
            self.assertFalse(rep.clean)
            self.assertIn(
                "ILLEGAL_FAILOVER_SPOOF",
                {a.code for a in rep.tasks["task-r3-split"].anomalies},
            )

            # Subtest B: Foreign `spiffe://org-beta.io/ns/sys/sa/rev` signing fake event for `org-alpha.io` -> REJECTED!
            fake_prov = RevocationEvent(
                99,
                RevocationKind.SUBTREE,
                "/task-r3-split/A/B1",
                "foreign_rev_spoof",
                w_parent_a.spiffe_id,
                time.time() - 1.0,
                "",
                w_beta_rev.workload_svid,
                "org-alpha.io",
            )
            foreign_sig = jws_sign_compact(
                fake_prov.core_claims(), w_beta_rev.keypair, typ="lct-revocation-event+jwt"
            )
            foreign_ev = RevocationEvent(**{**fake_prov.__dict__, "service_signature": foreign_sig})
            foreign_fr = FailoverReceipt.create_and_sign(
                parent_identity=w_parent_a,
                task_id="task-r3-split",
                pruned_lineage_path="/task-r3-split/A/B1",
                revocation_version=99,
                revocation_event_sig=foreign_sig,
                failed_delegate_spiffe_id=w_b1_a.spiffe_id,
                substitute_delegate_spiffe_id=w_b2_a.spiffe_id,
                new_lineage_path="/task-r3-split/A/B2-e1",
                old_epoch=0,
                new_epoch=1,
                failure_evidence=FailureEvidence(
                    w_b1_a.spiffe_id, "http://127.0.0.1:9", FaultType.CRASH, "foreign", 1, time.time()
                ),
                revocation_event=foreign_ev.to_dict(),
                revocation_service_svid=w_beta_rev.workload_svid,
            )
            with self.assertRaises(ResilienceError):
                FailoverReceipt.from_dict_and_verify(foreign_fr.to_dict(), resolver)
        finally:
            rev_svc.stop()

    def test_r3_medium_01_quarantined_revoked_expired_or_bare_hop0_cannot_quarantine_peers(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_rev = ca.issue_workload("/ns/sys/sa/rev")
        w_drv = ca.issue_workload("/ns/entry/sa/drv")
        w_coord_exp = ca.issue_workload("/ns/coord/sa/coord-exp")
        w_coord_rev = ca.issue_workload("/ns/coord/sa/coord-rev")
        w_coord_quar = ca.issue_workload("/ns/coord/sa/coord-quar")
        w_healthy_tool = ca.issue_workload("/ns/tool/sa/payment-mcp")
        w_healthy_peer = ca.issue_workload("/ns/work/sa/healthy-worker")

        rev_svc = RevocationService(w_rev, resolver)
        dir_svc = AgentDirectoryService(resolver, revocation_trie=rev_svc.trie)
        rev_url = rev_svc.start()
        dir_url = dir_svc.start()
        try:
            rev_client = RevocationReplicaClient(rev_url, resolver)
            dir_client = AgentDirectoryClient(dir_url, resolver)
            dir_client.register(
                AgentCard.sign_and_create(w_healthy_peer, "HealthyWorker", "http://127.0.0.1:19799", ["work"])
            )
            p_low = PermissionLattice.create(tools=["get_weather"])

            # 1. Unexpired bare 0-hop `B_0` (`len(hops) == 0`) -> REJECTED on both services!
            bare_t0 = mint_root_token(
                ca,
                "task-r3-bare",
                "user:alice",
                w_drv.jkt,
                w_coord_exp.spiffe_id,
                w_coord_exp.jkt,
                p_low,
                hop_segment="Coord",
            ).encode_compact()
            with self.assertRaises(RevocationError):
                rev_client.quarantine_workload(w_coord_exp, w_healthy_tool.spiffe_id, authority_token=bare_t0)
            with self.assertRaises(AgentCardError):
                dir_client.quarantine(w_coord_exp, w_healthy_peer.spiffe_id, "bare", authority_token=bare_t0)

            # 2. Expired 1-hop `authority_token` (`now - 7200`, `ttl=10`) -> REJECTED on both services!
            past = time.time() - 7200.0
            exp_1hop = (
                mint_root_token(
                    ca,
                    "task-r3-expired",
                    "user:alice",
                    w_drv.jkt,
                    w_coord_exp.spiffe_id,
                    w_coord_exp.jkt,
                    p_low,
                    hop_segment="Coord",
                    ttl_seconds=10.0,
                    now=past,
                )
                .attenuate(
                    w_coord_exp,
                    w_healthy_tool.spiffe_id,
                    w_healthy_tool.jkt,
                    p_low,
                    hop_segment="Tool",
                    now=past,
                )
                .encode_compact()
            )
            with self.assertRaises(RevocationError):
                rev_client.quarantine_workload(w_coord_exp, w_healthy_tool.spiffe_id, authority_token=exp_1hop)
            with self.assertRaises(AgentCardError):
                dir_client.quarantine(w_coord_exp, w_healthy_tool.spiffe_id, "exp", authority_token=exp_1hop)

            # 3. Unexpired 1-hop token whose Hop-0 root task was ALREADY revoked by CA -> REJECTED!
            rev_1hop = (
                mint_root_token(
                    ca,
                    "task-r3-ca-revoked",
                    "user:alice",
                    w_drv.jkt,
                    w_coord_rev.spiffe_id,
                    w_coord_rev.jkt,
                    p_low,
                    hop_segment="Coord",
                )
                .attenuate(
                    w_coord_rev,
                    w_healthy_peer.spiffe_id,
                    w_healthy_peer.jkt,
                    p_low,
                    hop_segment="Peer",
                )
                .encode_compact()
            )
            rev_client.revoke_prefix(ca, "/task-r3-ca-revoked", reason="ca_cancelled")
            with self.assertRaises(RevocationError):
                rev_client.quarantine_workload(w_coord_rev, w_healthy_peer.spiffe_id, authority_token=rev_1hop)
            with self.assertRaises(AgentCardError):
                dir_client.quarantine(w_coord_rev, w_healthy_peer.spiffe_id, "rev", authority_token=rev_1hop)

            # 4. Quarantined Hop-0 coordinator with fresh unrevoked 1-hop token -> REJECTED on both services!
            live_1hop = (
                mint_root_token(
                    ca,
                    "task-r3-quar-retaliate",
                    "user:alice",
                    w_drv.jkt,
                    w_coord_quar.spiffe_id,
                    w_coord_quar.jkt,
                    p_low,
                    hop_segment="Coord",
                )
                .attenuate(
                    w_coord_quar,
                    w_healthy_peer.spiffe_id,
                    w_healthy_peer.jkt,
                    p_low,
                    hop_segment="Peer",
                )
                .encode_compact()
            )
            rev_client.quarantine_workload(ca, w_coord_quar.spiffe_id, reason="compromised")
            dir_client.quarantine(ca, w_coord_quar.spiffe_id, reason="compromised")
            with self.assertRaises(RevocationError):
                rev_client.quarantine_workload(w_coord_quar, w_healthy_peer.spiffe_id, authority_token=live_1hop)
            with self.assertRaises(AgentCardError):
                dir_client.quarantine(w_coord_quar, w_healthy_peer.spiffe_id, "retaliate", authority_token=live_1hop)

            # Healthy victims remain 100% unquarantined and discoverable!
            self.assertIsNone(rev_svc.trie.check_workloads([w_healthy_tool.spiffe_id, w_healthy_peer.spiffe_id]))
            self.assertEqual(len(dir_client.discover(skill="work")), 1)
        finally:
            rev_svc.stop()
            dir_svc.stop()

    def test_r4_high_01_unquote_delimiter_fixed_point_and_encoded_slash_preservation(self) -> None:
        from urllib.parse import unquote

        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)
        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_c = ca.issue_workload("/ns/c/sa/c")
        w_tool = ca.issue_workload("/ns/t/sa/hybrid-mcp")

        executed_mcp: list[dict] = []
        captured_a2a: list[dict] = []

        def _upstream_app(req: HTTPRequestContext):
            if unquote(req.path) == "/mcp":
                executed_mcp.append({"wire_path": req.path, "query": req.query_raw})
                return 200, {"executed": True}, {}
            captured_a2a.append({"wire_path": req.path, "query": req.query_raw})
            return 200, {"a2a_ok": True, "wire_path": req.path, "query": req.query_raw}, {}

        upstream = ManagedHTTPService("upstream-r4-reg", _upstream_app)
        app_url = upstream.start()
        sc = LineageSidecar(
            w_tool,
            resolver,
            app_url,
            loopback_secret="sec-r4-reg",
            mode=VerificationMode.LOCAL_FULL_CHAIN,
            is_tool_server=False,
        )
        sc.start()
        try:
            tok_deleg = (
                mint_root_token(
                    ca,
                    "task-r4-reg",
                    "user:alice",
                    w_drv.jkt,
                    w_c.spiffe_id,
                    w_c.jkt,
                    PermissionLattice.create(tools=["get_weather"], max_calls=1),
                    hop_segment="C",
                )
                .attenuate(
                    w_c,
                    w_tool.spiffe_id,
                    w_tool.jkt,
                    PermissionLattice.create(tools=["get_weather"], max_calls=1),
                    hop_segment="Tool",
                )
                .encode_compact()
            )
            sc_port = int(sc.inbound_url.rsplit(":", 1)[1])
            forbidden_body = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_payment","arguments":{"amount":999999}}}'

            def _send(target_p: str, htu_path: str, payload: bytes) -> tuple[int, str]:
                htu_full = f"{sc.inbound_url}{htu_path}"
                dpop = create_dpop_proof(w_c, "POST", htu_full, tok_deleg)
                raw = (
                    f"POST {target_p} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{sc_port}\r\n"
                    f"Authorization: DPoP {tok_deleg}\r\n"
                    f"DPoP: {dpop}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii") + payload
                with socket.create_connection(("127.0.0.1", sc_port), timeout=3.0) as sock:
                    sock.sendall(raw)
                    chunks: list[bytes] = []
                    while True:
                        buf = sock.recv(4096)
                        if not buf:
                            break
                        chunks.append(buf)
                txt = b"".join(chunks).decode("utf-8", errors="replace")
                return int(txt.splitlines()[0].split()[1]), txt

            # 1. `%23` (# fragment), `%3f` (? query), `%20` (space), and >=5x nested `%25` -> 400 invalid_request_target!
            for r4_vec in (
                "/mcp%23bypass",
                "/mcp%3fbypass=1",
                "/mcp%20bypass",
                "/%252525256d%2525252563%2525252570",
            ):
                st, txt = _send(r4_vec, r4_vec, forbidden_body)
                self.assertEqual(st, 400, f"Expected 400 on {r4_vec!r}, got {st}: {txt}")
                self.assertIn("invalid_request_target", txt)

            self.assertEqual(executed_mcp, [])

            # 2. Legitimate `/a2a/items/ns%2fname?filter=active&limit=5` preserves BOTH query AND `%2f` segment!
            st_ok, txt_ok = _send(
                "/a2a/items/ns%2fname?filter=active&limit=5",
                "/a2a/items/ns%2fname",
                b'{"task":"ping"}',
            )
            self.assertEqual(st_ok, 200, txt_ok)
            self.assertEqual(len(captured_a2a), 1)
            self.assertEqual(captured_a2a[0]["wire_path"], "/a2a/items/ns%2fname")
            self.assertEqual(captured_a2a[0]["query"], "filter=active&limit=5")
        finally:
            sc.stop()
            upstream.stop()


if __name__ == "__main__":
    unittest.main()
