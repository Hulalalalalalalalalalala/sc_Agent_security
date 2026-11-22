"""Tests for Three-Layer Fault Detection, Atomic Prune-and-Graft, and Authenticated Skip-Level Return."""

from __future__ import annotations

import time
import unittest

import httpx

from lineage.audit import (
    AuditCollectorClient,
    AuditCollectorService,
    AuditEventType,
    AuditStreamEmitter,
    CausalChainAuditor,
)
from lineage.common.http_utils import HTTPRequestContext
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.protocol import PermissionLattice, create_dpop_proof, mint_root_token
from lineage.registry import AgentCard, AgentDirectoryService
from lineage.resilience import FaultType, SkipLevelReceipt, ThreeLayerFaultDetector
from lineage.revocation import RevocationService
from lineage.sidecar import AgentSidecarNode, MCPToolSidecarNode


class TestResilienceProtocols(unittest.TestCase):
    def test_three_layer_fault_detector_classifications(self) -> None:
        det = ThreeLayerFaultDetector(policy_breaker_threshold=2)

        # Layer 1: Crash
        ev_crash = det.classify_exception(
            "spiffe://org-alpha.io/ns/a/sa/n1",
            "http://127.0.0.1:9999",
            httpx.ConnectError("Connection refused"),
        )
        self.assertEqual(ev_crash.fault_type, FaultType.CRASH)

        # Layer 2: Timeout
        ev_timeout = det.classify_exception(
            "spiffe://org-alpha.io/ns/a/sa/n2",
            "http://127.0.0.1:9999",
            httpx.ReadTimeout("Deadline exceeded"),
        )
        self.assertEqual(ev_timeout.fault_type, FaultType.TIMEOUT)

        # Layer 3: Policy/Byzantine Circuit Breaker (trips on 2nd consecutive 403)
        rogue_id = "spiffe://org-beta.io/ns/b/sa/rogue"
        self.assertIsNone(
            det.classify_http_failure(rogue_id, "http://127.0.0.1:9999", 403, "denied-1")
        )
        self.assertFalse(det.is_circuit_open(rogue_id))
        ev_byz = det.classify_http_failure(
            rogue_id, "http://127.0.0.1:9999", 403, "denied-2"
        )
        self.assertIsNotNone(ev_byz)
        assert ev_byz is not None
        self.assertEqual(ev_byz.fault_type, FaultType.POLICY_BYZANTINE)
        self.assertTrue(det.is_circuit_open(rogue_id))

    def test_downward_atomic_prune_and_graft_blocks_zombie_and_audits_cleanly(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        directory = AgentDirectoryService(resolver)
        dir_url = directory.start()
        rev_svc = RevocationService(ca_alpha.issue_workload("/ns/sys/sa/rev"), resolver)
        rev_url = rev_svc.start()
        collector = AuditCollectorService(resolver)
        col_url = collector.start()

        w_drv = ca_alpha.issue_workload("/ns/entry/sa/drv")
        w_coord = ca_alpha.issue_workload("/ns/coord/sa/coord-a")
        w_b1_dead = ca_alpha.issue_workload("/ns/work/sa/worker-b1")
        w_b1_sub = ca_beta.issue_workload("/ns/work/sa/worker-b1-sub")
        w_tool = ca_beta.issue_workload("/ns/tool/sa/analytics-tool")

        tool_node = MCPToolSidecarNode(
            w_tool,
            resolver,
            tools={"run_query": lambda args, _: {"rows": 42, "region": args.get("region")}},
            revocation_url=rev_url,
            audit_collector_url=col_url,
        )
        tool_node.start()

        captured_zombie_tokens: list[str] = []

        # Primary B1 simulates a timeout/crash right AFTER receiving the token (capturing zombie token!)
        def _b1_faulty_handler(
            node: AgentSidecarNode, req: HTTPRequestContext, body: dict
        ):
            req_id = str(req.header("X-LCT-Request-Id"))
            ctx = node.sidecar.active_requests.get(req_id)
            if ctx is not None:
                captured_zombie_tokens.append(ctx.compact_token)
            return 503, {"error": "simulated_worker_crash"}

        # Healthy substitute B1' in org-beta.io calls the MCP tool and succeeds!
        def _b1_sub_handler(
            node: AgentSidecarNode, req: HTTPRequestContext, body: dict
        ):
            req_id = str(req.header("X-LCT-Request-Id"))
            st, res = node.sidecar_call_tool(
                req_id,
                tool_node.mcp_url,
                "run_query",
                {"region": body["region"]},
            )
            return st, {"handled_by": node.identity.spiffe_id, "mcp": res}

        def _coord_handler(
            node: AgentSidecarNode, req: HTTPRequestContext, body: dict
        ):
            req_id = str(req.header("X-LCT-Request-Id"))
            sub_perms = PermissionLattice.create(
                tools=["run_query"],
                param_whitelist={"region": ["us-east"]},
                max_calls=3,
            )
            return node.sidecar_delegate(
                request_id=req_id,
                permissions=sub_perms,
                payload={"region": body["region"]},
                required_skill="analytics.query",
                use_prune_and_graft=True,
                timeout=1.5,
            )

        b1_node = AgentSidecarNode(
            w_b1_dead,
            resolver,
            "B1 Primary",
            ["analytics.query"],
            _b1_faulty_handler,
            directory_url=dir_url,
            revocation_url=rev_url,
            audit_collector_url=col_url,
            priority=10,
        )
        b1_sub_node = AgentSidecarNode(
            w_b1_sub,
            resolver,
            "B1 Substitute",
            ["analytics.query"],
            _b1_sub_handler,
            directory_url=dir_url,
            revocation_url=rev_url,
            audit_collector_url=col_url,
            priority=20,
        )
        coord_node = AgentSidecarNode(
            w_coord,
            resolver,
            "Coordinator A",
            ["coord.main"],
            _coord_handler,
            directory_url=dir_url,
            revocation_url=rev_url,
            audit_collector_url=col_url,
        )

        try:
            b1_node.start()
            b1_sub_node.start()
            coord_card = coord_node.start()

            root_em = AuditStreamEmitter(ca_alpha, AuditCollectorClient(col_url))
            p0 = PermissionLattice.create(
                tools=["run_query"], param_whitelist={"region": ["us-east", "eu-west"]}
            )
            t0 = mint_root_token(
                ca_alpha,
                "task-failover-01",
                "user:alice",
                w_drv.jkt,
                w_coord.spiffe_id,
                w_coord.jkt,
                p0,
                hop_segment="A",
                first_hop_public_jwk=w_coord.public_jwk(),
                first_hop_return_endpoint=coord_card.return_endpoint,
            )
            root_em.emit(
                AuditEventType.ROOT_MINT,
                t0.task_id,
                t0.sub,
                t0.lineage_path,
                0,
                0,
                t0.root_block_hash,
                t0.leaf_block_hash,
                "ALLOW",
                permissions_summary=p0.to_dict(),
            )

            compact_t0 = t0.encode_compact()
            target = f"{coord_node.endpoint}/a2a/task"
            resp = httpx.post(
                target,
                json={"region": "us-east"},
                headers={
                    "Authorization": f"DPoP {compact_t0}",
                    "DPoP": create_dpop_proof(w_drv, "POST", target, compact_t0),
                },
                timeout=10.0,
            )
            self.assertEqual(resp.status_code, 200)
            res_body = resp.json()
            self.assertEqual(res_body["epoch"], 1)
            self.assertEqual(len(res_body["failover_receipts"]), 1)
            self.assertEqual(
                res_body["upstream_body"]["handled_by"], w_b1_sub.spiffe_id
            )

            # Verify Zombie B1's captured token is 100% DEAD if B1 wakes up and calls the tool!
            self.assertEqual(len(captured_zombie_tokens), 1)
            zombie_tok = captured_zombie_tokens[0]
            # Force tool's revocation replica to sync (or pass HIGH risk hint)
            zombie_resp = httpx.post(
                tool_node.mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "tools/call",
                    "params": {"name": "run_query", "arguments": {"region": "us-east"}},
                },
                headers={
                    "Authorization": f"DPoP {zombie_tok}",
                    "DPoP": create_dpop_proof(w_b1_dead, "POST", tool_node.mcp_url, zombie_tok),
                    "X-LCT-Risk-Hint": "HIGH",
                },
                timeout=5.0,
            )
            self.assertEqual(zombie_resp.status_code, 403)
            self.assertEqual(zombie_resp.json()["error"], "LINEAGE_REVOKED")

            # Verify CausalChainAuditor reconstructs 100% and verifies VERIFIED_FAILOVER_GRAFT!
            auditor = CausalChainAuditor(resolver)
            audit_rep = auditor.audit(collector.get_all_entries())
            self.assertTrue(audit_rep.clean, f"Anomalies: {audit_rep.anomalies}")
            self.assertIn(
                "VERIFIED_FAILOVER_GRAFT",
                audit_rep.tasks["task-failover-01"].resilience_classifications,
            )
        finally:
            coord_node.stop()
            b1_node.stop()
            b1_sub_node.stop()
            tool_node.stop()
            collector.stop()
            rev_svc.stop()
            directory.stop()

    def test_upward_authenticated_skip_level_return_and_spoof_rejection(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        directory = AgentDirectoryService(resolver)
        dir_url = directory.start()
        rev_svc = RevocationService(ca_alpha.issue_workload("/ns/sys/sa/rev"), resolver)
        rev_url = rev_svc.start()
        collector = AuditCollectorService(resolver)
        col_url = collector.start()

        w_drv = ca_alpha.issue_workload("/ns/entry/sa/drv")
        w_a = ca_alpha.issue_workload("/ns/coord/sa/ancestor-a")
        w_b1 = ca_beta.issue_workload("/ns/mid/sa/mid-b1")
        w_c = ca_beta.issue_workload("/ns/leaf/sa/leaf-c")
        w_rogue = ca_beta.issue_workload("/ns/evil/sa/rogue-z")

        b1_node_ref: list[AgentSidecarNode] = []

        def _c_handler(node: AgentSidecarNode, req: HTTPRequestContext, body: dict):
            req_id = str(req.header("X-LCT-Request-Id"))
            # Simulate intermediate parent B1 crashing WHILE C is computing its result!
            b1_node_ref[0].stop()
            ret_status, ret_outcome = node.sidecar_return_result(
                request_id=req_id,
                result_payload={"computed_answer": 314159, "status": "completed_by_c"},
                timeout=0.8,
            )
            return ret_status, ret_outcome

        def _b1_handler(node: AgentSidecarNode, req: HTTPRequestContext, body: dict):
            req_id = str(req.header("X-LCT-Request-Id"))
            p_c = PermissionLattice.create(tools=["calc"])
            return node.sidecar_delegate(
                request_id=req_id,
                permissions=p_c,
                payload=body,
                required_skill="leaf.compute",
            )

        def _a_handler(node: AgentSidecarNode, req: HTTPRequestContext, body: dict):
            req_id = str(req.header("X-LCT-Request-Id"))
            p_b1 = PermissionLattice.create(tools=["calc"])
            st, out = node.sidecar_delegate(
                request_id=req_id,
                permissions=p_b1,
                payload=body,
                required_skill="mid.relay",
            )
            return 200, {"downstream_http": st, "downstream": out}

        a_node = AgentSidecarNode(
            w_a,
            resolver,
            "Ancestor A",
            ["coord.root"],
            _a_handler,
            directory_url=dir_url,
            revocation_url=rev_url,
            audit_collector_url=col_url,
        )
        b1_node = AgentSidecarNode(
            w_b1,
            resolver,
            "Middle B1",
            ["mid.relay"],
            _b1_handler,
            directory_url=dir_url,
            revocation_url=rev_url,
            audit_collector_url=col_url,
        )
        b1_node_ref.append(b1_node)
        c_node = AgentSidecarNode(
            w_c,
            resolver,
            "Leaf C",
            ["leaf.compute"],
            _c_handler,
            directory_url=dir_url,
            revocation_url=rev_url,
            audit_collector_url=col_url,
        )

        try:
            a_card = a_node.start()
            b1_node.start()
            c_node.start()

            root_em = AuditStreamEmitter(ca_alpha, AuditCollectorClient(col_url))
            p0 = PermissionLattice.create(tools=["calc"])
            t0 = mint_root_token(
                ca_alpha,
                "task-skip-01",
                "user:alice",
                w_drv.jkt,
                w_a.spiffe_id,
                w_a.jkt,
                p0,
                hop_segment="A",
                first_hop_public_jwk=w_a.public_jwk(),
                first_hop_return_endpoint=a_card.return_endpoint,
            )
            root_em.emit(
                AuditEventType.ROOT_MINT,
                t0.task_id,
                t0.sub,
                t0.lineage_path,
                0,
                0,
                t0.root_block_hash,
                t0.leaf_block_hash,
                "ALLOW",
                permissions_summary=p0.to_dict(),
            )

            # Dispatch A -> B1 -> C; B1 stops mid-flight, so C executes Skip-Level Return directly to A!
            compact_t0 = t0.encode_compact()
            target_a = f"{a_node.endpoint}/a2a/task"
            httpx.post(
                target_a,
                json={"job": "pi"},
                headers={
                    "Authorization": f"DPoP {compact_t0}",
                    "DPoP": create_dpop_proof(w_drv, "POST", target_a, compact_t0),
                },
                timeout=10.0,
            )

            # Verify Ancestor A cryptographically accepted C's Skip-Level Return!
            accepted = a_node.sidecar.get_skip_level_results("task-skip-01")
            self.assertEqual(len(accepted), 1)
            self.assertEqual(accepted[0]["result_payload"]["computed_answer"], 314159)
            self.assertEqual(accepted[0]["skipped_ancestors"], [w_b1.spiffe_id])

            # Adversarial Attack: Rogue Agent Z (not on A's delegation chain!) tries to POST
            # a forged skip-level result to A!
            t_unrelated = mint_root_token(
                ca_alpha,
                "task-rogue",
                "user:mallory",
                w_drv.jkt,
                w_b1.spiffe_id,
                w_b1.jkt,
                p0,
                hop_segment="B1",
            ).attenuate(w_b1, w_rogue.spiffe_id, w_rogue.jkt, p0, hop_segment="Z")

            with self.assertRaises( Exception ):
                # Even trying to construct SkipLevelReceipt targeting A when A is not in t_unrelated fails!
                SkipLevelReceipt.create_and_sign(
                    child_identity=w_rogue,
                    lineage_token=t_unrelated,
                    skipped_ancestors=[w_b1.spiffe_id],
                    target_ancestor_spiffe_id=w_a.spiffe_id,
                    failure_evidence=accepted[0]["failure_evidence"],
                    result_payload={"evil": True},
                )

            # Attack 2: Tamper `result_payload` of C's valid SkipLevelReceipt and replay to A -> 403!
            tampered_receipt = dict(accepted[0])
            tampered_receipt["result_payload"] = {"computed_answer": 999999}
            skip_url = f"{a_node.endpoint}/v1/skip-level-return"
            spoof_resp = httpx.post(
                skip_url,
                json={"skip_level_receipt": tampered_receipt},
                headers={
                    "Authorization": f"DPoP {accepted[0]['compact_lineage_token']}",
                    "DPoP": create_dpop_proof(
                        w_c, "POST", skip_url, accepted[0]["compact_lineage_token"]
                    ),
                },
                timeout=3.0,
            )
            self.assertEqual(spoof_resp.status_code, 403)

            # Verify CausalChainAuditor recognizes legitimate `VERIFIED_SKIP_LEVEL_MERGE`!
            auditor = CausalChainAuditor(resolver)
            rep = auditor.audit(collector.get_all_entries())
            self.assertTrue(rep.clean, f"Anomalies: {rep.anomalies}")
            self.assertIn(
                "VERIFIED_SKIP_LEVEL_MERGE",
                rep.tasks["task-skip-01"].resilience_classifications,
            )
        finally:
            a_node.stop()
            b1_node.stop()
            c_node.stop()
            collector.stop()
            rev_svc.stop()
            directory.stop()


if __name__ == "__main__":
    unittest.main()
