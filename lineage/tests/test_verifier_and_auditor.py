"""Tests for 3 Verifier Modes (`LEAF_ONLY` vs `LOCAL_FULL_CHAIN` vs `ADAPTIVE_RISK_ANCHORED`)
and Adversarial Tamper Detection in `CausalChainAuditor` (`delete_hop`, `modify_parent`,
`mix_record`, `modify_correlation`, hash recomputation, DPoP replay).
"""

from __future__ import annotations

import copy
import time
import unittest

from lineage.audit import (
    AuditEntry,
    AuditEventType,
    AuditStreamEmitter,
    CausalChainAuditor,
)
from lineage.common.crypto import jws_sign_compact
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.protocol import (
    AttenuationBlock,
    LineageToken,
    PermissionLattice,
    create_dpop_proof,
    mint_root_token,
)
from lineage.revocation import RevocationReplicaClient, RevocationService
from lineage.verifier import LeafVerifier, VerificationMode


class TestVerifierAndAuditor(unittest.TestCase):
    def test_three_verification_modes_and_fail_closed_anchoring(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_a = ca.issue_workload("/ns/c/sa/a")
        w_b = ca.issue_workload("/ns/c/sa/b")
        w_c = ca.issue_workload("/ns/c/sa/c")
        w_tool = ca.issue_workload("/ns/t/sa/pay-tool")
        w_rev = ca.issue_workload("/ns/sys/sa/rev")

        # 1. Construct a compromised intermediate escalation:
        # Root grants max_amount=100 to A -> A grants max_amount=100 to B ->
        # Compromised B bypasses SDK and signs B_2 granting max_amount=5000 to C!
        p_small = PermissionLattice.create(tools=["execute_payment"], max_amount=100.0, max_calls=2)
        p_escalated = PermissionLattice.create(tools=["execute_payment"], max_amount=5000.0, max_calls=2)

        t0 = mint_root_token(
            ca, "task-esc", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p_small, hop_segment="A"
        )
        t1 = t0.attenuate(w_a, w_b.spiffe_id, w_b.jkt, p_small, hop_segment="B")

        # Hand-craft malicious B_2 signed with B's real private key!
        ts = time.time()
        malicious_prov = AttenuationBlock(
            block_type="ATTENUATION",
            jti="hop-evil",
            hop_index=2,
            task_id="task-esc",
            parent_hash=t1.leaf_block_hash,
            hop_segment="C",
            lineage_path="/task-esc/A/B/C",
            epoch=0,
            issuer_spiffe_id=w_b.spiffe_id,
            issuer_jwk=w_b.public_jwk(),
            issuer_svid=w_b.workload_svid,
            issuer_return_endpoint=None,
            delegate_spiffe_id=w_c.spiffe_id,
            cnf_jkt=w_c.jkt,
            target_audience=w_tool.spiffe_id,
            permissions=p_escalated,
            iat=ts,
            exp=ts + 600,
            jws_signature="",
        )
        evil_sig = jws_sign_compact(
            malicious_prov.core_claims(), w_b.keypair, typ="lct-hop+jwt"
        )
        evil_hop = AttenuationBlock(**{**malicious_prov.__dict__, "jws_signature": evil_sig})
        forged_tok = LineageToken(root=t1.root, hops=t1.hops + (evil_hop,)).encode_compact()
        htu = "http://127.0.0.1:18888/mcp"

        # Fragile baseline `LEAF_ONLY` only checks last hop -> FOOLED (allows amount=2500!)
        v_leaf = LeafVerifier(
            w_tool.spiffe_id, resolver, self_jkt=w_tool.jkt, mode=VerificationMode.LEAF_ONLY
        )
        res_leaf = v_leaf.verify_request(
            forged_tok,
            create_dpop_proof(w_c, "POST", htu, forged_tok),
            "POST",
            htu,
            tool="execute_payment",
            arguments={"amount": 2500.0},
        )
        self.assertTrue(res_leaf.allowed)

        # `LOCAL_FULL_CHAIN` catches intermediate privilege escalation in microseconds -> 403!
        v_full = LeafVerifier(
            w_tool.spiffe_id, resolver, self_jkt=w_tool.jkt, mode=VerificationMode.LOCAL_FULL_CHAIN
        )
        res_full = v_full.verify_request(
            forged_tok,
            create_dpop_proof(w_c, "POST", htu, forged_tok),
            "POST",
            htu,
            tool="execute_payment",
            arguments={"amount": 2500.0},
        )
        self.assertFalse(res_full.allowed)
        self.assertEqual(res_full.status_code, 403)
        self.assertIn("Privilege escalation", res_full.detail)

        # 2. Test `ADAPTIVE_RISK_ANCHORED` + `max_calls` quota + fail-closed when anchor offline
        rev_svc = RevocationService(w_rev, resolver)
        rev_url = rev_svc.start()
        try:
            replica = RevocationReplicaClient(rev_url, resolver)
            v_adaptive = LeafVerifier(
                w_tool.spiffe_id,
                resolver,
                self_jkt=w_tool.jkt,
                mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
                revocation_replica=replica,
                fail_closed_on_high_risk=True,
            )

            valid_tok = t1.attenuate(
                w_b, w_c.spiffe_id, w_c.jkt, p_small, hop_segment="C"
            ).encode_compact()

            # Call 1 & Call 2 succeed (`max_calls=2`)
            for _ in range(2):
                r_ok = v_adaptive.verify_request(
                    valid_tok,
                    create_dpop_proof(w_c, "POST", htu, valid_tok),
                    "POST",
                    htu,
                    tool="execute_payment",
                    arguments={"amount": 50.0},
                )
                self.assertTrue(r_ok.allowed)

            # Call 3 exceeds max_calls=2 -> 403 QUOTA_EXCEEDED!
            r_quota = v_adaptive.verify_request(
                valid_tok,
                create_dpop_proof(w_c, "POST", htu, valid_tok),
                "POST",
                htu,
                tool="execute_payment",
                arguments={"amount": 50.0},
            )
            self.assertFalse(r_quota.allowed)
            self.assertEqual(r_quota.reason_code, "QUOTA_EXCEEDED")

            # Mint fresh valid token `t_fresh`, revoke on remote server WITHOUT syncing local replica:
            # HIGH_RISK call must synchronously anchor against RevocationService and block!
            t_fresh = mint_root_token(
                ca,
                "task-anchor",
                "user:bob",
                w_drv.jkt,
                w_c.spiffe_id,
                w_c.jkt,
                PermissionLattice.create(tools=["execute_payment", "get_weather"], max_amount=500.0),
                hop_segment="C",
            ).encode_compact()
            rev_svc.revoke_prefix_direct("/task-anchor", requested_by="user:bob", reason="cancel")
            self.assertEqual(replica.trie.version, 0)  # Local cache is still stale at v0!

            r_anchored = v_adaptive.verify_request(
                t_fresh,
                create_dpop_proof(w_c, "POST", htu, valid_tok if False else t_fresh),
                "POST",
                htu,
                tool="execute_payment",
                arguments={"amount": 200.0},
            )
            self.assertFalse(r_anchored.allowed)
            self.assertEqual(r_anchored.reason_code, "LINEAGE_REVOKED")
            self.assertEqual(replica.trie.version, 1)  # Pulled v1 synchronously!

            # Now stop RevocationService -> HIGH_RISK fails closed (503), LOW_RISK fast path works!
            t_unrevoked = mint_root_token(
                ca,
                "task-offline",
                "user:carol",
                w_drv.jkt,
                w_c.spiffe_id,
                w_c.jkt,
                PermissionLattice.create(tools=["execute_payment", "get_weather"], max_amount=500.0),
                hop_segment="C",
            ).encode_compact()
        finally:
            rev_svc.stop()

        # RevocationService is now stopped!
        r_low = v_adaptive.verify_request(
            t_unrevoked,
            create_dpop_proof(w_c, "POST", htu, t_unrevoked),
            "POST",
            htu,
            method="tools/call",
            tool="get_weather",
            arguments={"city": "Boston"},
        )
        self.assertTrue(r_low.allowed)

        r_high_fail_closed = v_adaptive.verify_request(
            t_unrevoked,
            create_dpop_proof(w_c, "POST", htu, t_unrevoked),
            "POST",
            htu,
            method="tools/call",
            tool="execute_payment",
            arguments={"amount": 300.0},
        )
        self.assertFalse(r_high_fail_closed.allowed)
        self.assertEqual(r_high_fail_closed.status_code, 503)
        self.assertEqual(
            r_high_fail_closed.reason_code, "REVOCATION_ANCHOR_UNAVAILABLE"
        )

    def test_causal_chain_auditor_concurrent_reconstruction_and_tamper_detection(self) -> None:
        """Verify 100% causal reconstruction under interleaved concurrency & 100% tamper recall."""
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        w_drv = ca_alpha.issue_workload("/ns/e/sa/drv")
        w_a = ca_alpha.issue_workload("/ns/coord/sa/coord-a")
        w_b = ca_beta.issue_workload("/ns/work/sa/worker-b")
        w_tool = ca_beta.issue_workload("/ns/tool/sa/weather-tool")

        em_root = AuditStreamEmitter(ca_alpha)
        em_a = AuditStreamEmitter(w_a)
        em_b = AuditStreamEmitter(w_b)
        em_tool = AuditStreamEmitter(w_tool)

        # Simulate 8 concurrent tasks from alternating users interleaved in the log
        for i in range(8):
            tid = f"conc-task-{i:02d}"
            user = f"user:{'alice' if i % 2 == 0 else 'bob'}"
            p0 = PermissionLattice.create(tools=["get_weather"], max_calls=5)
            p1 = PermissionLattice.create(
                tools=["get_weather"],
                param_whitelist={"city": ["New York" if i % 2 == 0 else "London"]},
                max_calls=2,
            )

            tok_a = mint_root_token(
                ca_alpha, tid, user, w_drv.jkt, w_a.spiffe_id, w_a.jkt, p0, hop_segment="A"
            )
            em_root.emit(
                AuditEventType.ROOT_MINT,
                tid,
                user,
                tok_a.lineage_path,
                0,
                0,
                tok_a.root_block_hash,
                tok_a.leaf_block_hash,
                "ALLOW",
                permissions_summary=p0.to_dict(),
            )
            em_a.emit(
                AuditEventType.INBOUND_AUTHZ,
                tid,
                user,
                tok_a.lineage_path,
                0,
                0,
                tok_a.root_block_hash,
                tok_a.leaf_block_hash,
                "ALLOW",
                dpop_jti=f"jti-in-a-{i}",
            )

            tok_b = tok_a.attenuate(w_a, w_b.spiffe_id, w_b.jkt, p1, hop_segment="B")
            em_a.emit(
                AuditEventType.OUTBOUND_DELEGATE,
                tid,
                user,
                tok_b.lineage_path,
                1,
                0,
                tok_b.root_block_hash,
                tok_b.leaf_block_hash,
                "ALLOW",
                parent_block_hash=tok_b.parent_block_hash,
                permissions_summary=p1.to_dict(),
            )
            em_b.emit(
                AuditEventType.INBOUND_AUTHZ,
                tid,
                user,
                tok_b.lineage_path,
                1,
                0,
                tok_b.root_block_hash,
                tok_b.leaf_block_hash,
                "ALLOW",
                parent_block_hash=tok_b.parent_block_hash,
                dpop_jti=f"jti-in-b-{i}",
            )
            em_tool.emit(
                AuditEventType.INBOUND_AUTHZ,
                tid,
                user,
                tok_b.lineage_path,
                1,
                0,
                tok_b.root_block_hash,
                tok_b.leaf_block_hash,
                "ALLOW",
                parent_block_hash=tok_b.parent_block_hash,
                dpop_jti=f"jti-tool-{i}",
            )
            em_tool.emit(
                AuditEventType.TOOL_INVOCATION,
                tid,
                user,
                tok_b.lineage_path,
                1,
                0,
                tok_b.root_block_hash,
                tok_b.leaf_block_hash,
                "ALLOW",
                parent_block_hash=tok_b.parent_block_hash,
                action_detail={"tool": "get_weather"},
            )

        clean_logs = (
            em_root.local_entries()
            + em_a.local_entries()
            + em_b.local_entries()
            + em_tool.local_entries()
        )
        # Shuffle / interleave by timestamp
        clean_logs.sort(key=lambda e: (e.stream_seq, e.stream_id))

        auditor = CausalChainAuditor(resolver)
        report = auditor.audit(clean_logs)
        self.assertTrue(report.clean)
        self.assertEqual(report.reconstruction_rate, (8, 8))

        # --- Tamper 1: `delete_hop` (remove Coordinator A's OUTBOUND_DELEGATE for conc-task-00) ---
        del_hop_logs = [
            e
            for e in clean_logs
            if not (
                e.task_id == "conc-task-00"
                and e.event_type == AuditEventType.OUTBOUND_DELEGATE
            )
        ]
        # Even if stream continuity check is bypassed, causal graph MUST still catch missing hop!
        rep_del = auditor.audit(del_hop_logs, check_stream_continuity=False)
        self.assertFalse(rep_del.tasks["conc-task-00"].reconstructed_complete)
        self.assertIn(
            "MISSING_OR_MODIFIED_PARENT_HOP",
            {a.code for a in rep_del.tasks["conc-task-00"].anomalies},
        )
        # Other 7 tasks remain 100% cleanly reconstructed!
        self.assertEqual(rep_del.reconstruction_rate, (7, 8))

        # --- Tamper 2: `modify_parent` (Experiment 03 attack: alter A's outbound block hash
        # so B -> Tool is orphaned; verify B -> Tool does NOT look like a valid short path!) ---
        mod_parent_logs = []
        for e in clean_logs:
            if (
                e.task_id == "conc-task-01"
                and e.event_type == AuditEventType.OUTBOUND_DELEGATE
            ):
                d = copy.deepcopy(e.to_dict())
                d["current_block_hash"] = "forged_unrelated_block_hash"
                mod_parent_logs.append(AuditEntry.from_dict(d))
            else:
                mod_parent_logs.append(e)

        rep_mod_parent = auditor.audit(mod_parent_logs, check_stream_continuity=False)
        self.assertFalse(rep_mod_parent.tasks["conc-task-01"].reconstructed_complete)
        codes_mp = {a.code for a in rep_mod_parent.tasks["conc-task-01"].anomalies}
        self.assertIn("ENTRY_HASH_TAMPERED", codes_mp)
        self.assertIn("MISSING_OR_MODIFIED_PARENT_HOP", codes_mp)

        # --- Tamper 3: `mix_record` / `modify_correlation` (re-label task_id AND recompute entry_hash!) ---
        mix_logs = []
        for e in clean_logs:
            if (
                e.task_id == "conc-task-02"
                and e.event_type == AuditEventType.TOOL_INVOCATION
            ):
                d = copy.deepcopy(e.to_dict())
                d["task_id"] = "conc-task-03"  # Mix into another user's task!
                temp_entry = AuditEntry.from_dict(d)
                # Attacker even recomputes SHA-256 entry_hash!
                d["entry_hash"] = temp_entry.compute_expected_hash()
                mix_logs.append(AuditEntry.from_dict(d))
            else:
                mix_logs.append(e)

        rep_mix = auditor.audit(mix_logs, check_stream_continuity=False)
        codes_mix = {a.code for a in rep_mix.tasks["conc-task-03"].anomalies}
        self.assertIn("NODE_SIGNATURE_INVALID", codes_mix)
        self.assertIn("CORRELATION_MISMATCH", codes_mix)


if __name__ == "__main__":
    unittest.main()
