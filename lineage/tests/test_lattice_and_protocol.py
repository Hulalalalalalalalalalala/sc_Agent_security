"""Unit & Adversarial Tests for PermissionLattice, LCT Chains, MultiParentToken, and DPoP."""

from __future__ import annotations

import concurrent.futures
import time
import unittest

from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.protocol import (
    CompositePermission,
    CycleDetectedError,
    DPoPError,
    DPoPVerifier,
    LatticeAttenuationError,
    MaxDepthExceededError,
    MultiParentToken,
    PermissionLattice,
    TokenError,
    create_dpop_proof,
    decode_token,
    mint_root_token,
)


class TestLatticeAndProtocol(unittest.TestCase):
    def test_permission_lattice_partial_order_and_meet_axioms(self) -> None:
        root_p = PermissionLattice.create(
            tools=["*"],
            methods=["initialize", "tools/list", "tools/call"],
            max_amount=1000.0,
            numeric_bounds={"days": 14.0},
            allowed_scopes=["weather:read", "flight:book", "pay:exec"],
            allowed_targets=["vendor-a", "vendor-b"],
            param_whitelist={"city": ["New York", "London", "Tokyo"]},
            max_calls=20,
        )
        child_p = PermissionLattice.create(
            tools=["get_weather", "book_flight"],
            methods=["tools/call"],
            max_amount=400.0,
            numeric_bounds={"days": 7.0, "passengers": 2.0},  # Adding new bound shrinks space!
            allowed_scopes=["flight:book"],
            allowed_targets=["vendor-a"],
            param_whitelist={"city": ["New York"]},
            max_calls=5,
        )
        grandchild_p = PermissionLattice.create(
            tools=["book_flight"],
            methods=["tools/call"],
            max_amount=250.0,
            numeric_bounds={"days": 3.0, "passengers": 1.0},
            allowed_scopes=["flight:book"],
            allowed_targets=["vendor-a"],
            param_whitelist={"city": ["New York"]},
            max_calls=2,
        )

        # Reflexivity, Antisymmetry, Transitivity
        self.assertTrue(root_p.is_subset_of(root_p))
        self.assertTrue(child_p.is_subset_of(root_p))
        self.assertFalse(root_p.is_subset_of(child_p))
        self.assertTrue(grandchild_p.is_subset_of(child_p))
        self.assertTrue(grandchild_p.is_subset_of(root_p))

        # Meet (intersect) is greatest lower bound
        m = root_p.intersect(child_p)
        self.assertTrue(m.is_subset_of(root_p))
        self.assertTrue(m.is_subset_of(child_p))
        self.assertEqual(m, child_p)

    def test_constraint_dropping_and_type_confusion_attacks_blocked(self) -> None:
        parent = PermissionLattice.create(
            tools=["pay"],
            max_amount=500.0,
            allowed_scopes=["pay:small"],
            allowed_targets=["acct-1"],
            param_whitelist={"currency": ["USD"]},
            max_calls=5,
        )

        # Attack 1: Child drops max_amount (trying to become unbounded!)
        drop_amt = PermissionLattice.create(
            tools=["pay"],
            max_amount=None,
            allowed_scopes=["pay:small"],
            allowed_targets=["acct-1"],
            param_whitelist={"currency": ["USD"]},
            max_calls=5,
        )
        self.assertFalse(drop_amt.is_subset_of(parent))

        # Attack 2: Child drops param_whitelist["currency"]
        drop_pw = PermissionLattice.create(
            tools=["pay"],
            max_amount=100.0,
            allowed_scopes=["pay:small"],
            allowed_targets=["acct-1"],
            param_whitelist={},
            max_calls=5,
        )
        self.assertFalse(drop_pw.is_subset_of(parent))

        # Attack 3: Invocation type confusion (`bool` as int, negative amount, string amount)
        self.assertFalse(
            parent.check_invocation("tools/call", "pay", {"amount": True})[0]
        )
        self.assertFalse(
            parent.check_invocation("tools/call", "pay", {"amount": -10})[0]
        )
        self.assertFalse(
            parent.check_invocation("tools/call", "pay", {"amount": "100"})[0]
        )
        self.assertFalse(
            parent.check_invocation("tools/call", "pay", {"amount": 500.01})[0]
        )
        self.assertTrue(
            parent.check_invocation(
                "tools/call",
                "pay",
                {"amount": 500.0, "scope": "pay:small", "target": "acct-1", "currency": "USD"},
                call_index=5,
            )[0]
        )
        # Quota overflow on call 6
        self.assertFalse(
            parent.check_invocation("tools/call", "pay", {"amount": 10.0}, call_index=6)[0]
        )

    def test_composite_permission_blocks_cross_branch_cartesian_amplification(self) -> None:
        """Verify Branch 1 (vendor-a, <=100) + Branch 2 (vendor-b, <=1000) NEVER allows (vendor-a, 500)."""
        b1 = PermissionLattice.create(
            tools=["pay"], allowed_targets=["vendor-a"], max_amount=100.0
        )
        b2 = PermissionLattice.create(
            tools=["pay"], allowed_targets=["vendor-b"], max_amount=1000.0
        )
        comp = CompositePermission(
            surviving_branches=(("/t/A/B1/C", b1), ("/t/A/B2/C", b2))
        )

        # Valid via B1
        ok1, paths1, _ = comp.evaluate(
            "tools/call", "pay", {"target": "vendor-a", "amount": 80.0}
        )
        self.assertTrue(ok1)
        self.assertEqual(paths1, ["/t/A/B1/C"])

        # Valid via B2
        ok2, paths2, _ = comp.evaluate(
            "tools/call", "pay", {"target": "vendor-b", "amount": 800.0}
        )
        self.assertTrue(ok2)
        self.assertEqual(paths2, ["/t/A/B2/C"])

        # Cross-branch Cartesian attack: vendor-a with amount 500 -> MUST BE DENIED!
        ok_cross, _, _ = comp.evaluate(
            "tools/call", "pay", {"target": "vendor-a", "amount": 500.0}
        )
        self.assertFalse(ok_cross)

    def test_lct_chain_cycle_detection_max_depth_and_path_injection(self) -> None:
        ca_a = TrustDomainCA("org-alpha.io")
        ca_b = TrustDomainCA("org-beta.io")
        w_driver = ca_a.issue_workload("/ns/entry/sa/driver")
        w_a = ca_a.issue_workload("/ns/coord/sa/agent-a")
        w_b = ca_b.issue_workload("/ns/work/sa/agent-b")
        w_c = ca_b.issue_workload("/ns/work/sa/agent-c")
        w_d = ca_a.issue_workload("/ns/work/sa/agent-d")

        p0 = PermissionLattice.create(tools=["t1", "t2"], max_amount=500.0)

        # Path injection in task_id or hop_segment must be blocked
        with self.assertRaises(TokenError):
            mint_root_token(
                authority_ca=ca_a,
                task_id="task/injected",
                sub="user:alice",
                sender_jkt=w_driver.jkt,
                first_hop_spiffe_id=w_a.spiffe_id,
                first_hop_jkt=w_a.jkt,
                permissions=p0,
            )

        tok0 = mint_root_token(
            authority_ca=ca_a,
            task_id="task-m2n-01",
            sub="user:alice",
            sender_jkt=w_driver.jkt,
            first_hop_spiffe_id=w_a.spiffe_id,
            first_hop_jkt=w_a.jkt,
            permissions=p0,
            max_depth=2,
            hop_segment="A",
        )

        tok1 = tok0.attenuate(
            issuer_identity=w_a,
            delegate_spiffe_id=w_b.spiffe_id,
            delegate_jkt=w_b.jkt,
            permissions=PermissionLattice.create(tools=["t1"], max_amount=200.0),
            hop_segment="B",
        )
        self.assertEqual(tok1.lineage_path, "/task-m2n-01/A/B")

        # Attack 1:Privilege escalation at hop 2 (t2 not in tok1, max_amount 300 > 200)
        with self.assertRaises(LatticeAttenuationError):
            tok1.attenuate(
                issuer_identity=w_b,
                delegate_spiffe_id=w_c.spiffe_id,
                delegate_jkt=w_c.jkt,
                permissions=PermissionLattice.create(tools=["t1", "t2"], max_amount=200.0),
            )

        # Attack 2: Cycle detection (B -> A revisits A!)
        with self.assertRaises(CycleDetectedError):
            tok1.attenuate(
                issuer_identity=w_b,
                delegate_spiffe_id=w_a.spiffe_id,
                delegate_jkt=w_a.jkt,
                permissions=PermissionLattice.create(tools=["t1"], max_amount=100.0),
            )

        # Valid hop 2 (B -> C) reaches max_depth=2
        tok2 = tok1.attenuate(
            issuer_identity=w_b,
            delegate_spiffe_id=w_c.spiffe_id,
            delegate_jkt=w_c.jkt,
            permissions=PermissionLattice.create(tools=["t1"], max_amount=100.0),
            hop_segment="C",
        )
        self.assertEqual(tok2.lineage_path, "/task-m2n-01/A/B/C")

        # Attack 3: Exceed max_depth=2 (C -> D is hop 3 > 2)
        with self.assertRaises(MaxDepthExceededError):
            tok2.attenuate(
                issuer_identity=w_c,
                delegate_spiffe_id=w_d.spiffe_id,
                delegate_jkt=w_d.jkt,
                permissions=PermissionLattice.create(tools=["t1"], max_amount=50.0),
            )

        # Roundtrip wire encode/decode
        decoded = decode_token(tok2.encode_compact())
        self.assertEqual(decoded, tok2)

    def test_multiparent_token_blocks_cross_user_and_cross_task_splicing(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_a = ca.issue_workload("/ns/c/sa/a")
        w_c = ca.issue_workload("/ns/c/sa/c")
        p = PermissionLattice.create(tools=["ledger"])

        t_alice = mint_root_token(
            ca, "task-1", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p, hop_segment="A1"
        ).attenuate(w_a, w_c.spiffe_id, w_c.jkt, p, hop_segment="C")

        t_bob_same_task_diff_sub = mint_root_token(
            ca, "task-1", "user:bob", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p, hop_segment="A2"
        ).attenuate(w_a, w_c.spiffe_id, w_c.jkt, p, hop_segment="C")

        t_alice_diff_task = mint_root_token(
            ca, "task-2", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p, hop_segment="A1"
        ).attenuate(w_a, w_c.spiffe_id, w_c.jkt, p, hop_segment="C")

        with self.assertRaises(TokenError):
            MultiParentToken.assemble_and_sign(w_c, [t_alice, t_bob_same_task_diff_sub])

        with self.assertRaises(TokenError):
            MultiParentToken.assemble_and_sign(w_c, [t_alice, t_alice_diff_task])

    def test_dpop_sender_binding_and_concurrent_jti_anti_replay(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        w_legit = ca.issue_workload("/ns/team1/sa/weather-agent")
        w_thief = ca.issue_workload("/ns/team2/sa/rogue-pod")

        access_tok = "lct1.dummy_token_payload_for_ath_binding"
        htu = "http://127.0.0.1:18080/mcp?ignored_query=1"
        proof = create_dpop_proof(w_legit, "POST", htu, access_tok)

        verifier = DPoPVerifier()
        # First verification succeeds
        info = verifier.verify_proof(
            proof, "POST", "http://127.0.0.1:18080/mcp", access_tok, w_legit.jkt
        )
        self.assertEqual(info["jkt"], w_legit.jkt)

        # Replay of exact same proof -> REJECTED
        with self.assertRaises(DPoPError):
            verifier.verify_proof(
                proof, "POST", "http://127.0.0.1:18080/mcp", access_tok, w_legit.jkt
            )

        # Stolen token used with thief's own DPoP proof -> REJECTED (jkt mismatch!)
        thief_proof = create_dpop_proof(w_thief, "POST", htu, access_tok)
        with self.assertRaises(DPoPError):
            verifier.verify_proof(
                thief_proof, "POST", "http://127.0.0.1:18080/mcp", access_tok, w_legit.jkt
            )

        # Wrong HTTP method or target URL -> REJECTED
        p2 = create_dpop_proof(w_legit, "GET", htu, access_tok)
        with self.assertRaises(DPoPError):
            verifier.verify_proof(
                p2, "POST", "http://127.0.0.1:18080/mcp", access_tok, w_legit.jkt
            )

        # Stale iat -> REJECTED
        stale_proof = create_dpop_proof(
            w_legit, "POST", htu, access_tok, now=time.time() - 500.0
        )
        with self.assertRaises(DPoPError):
            verifier.verify_proof(
                stale_proof, "POST", "http://127.0.0.1:18080/mcp", access_tok, w_legit.jkt
            )

        # Concurrent race test: 16 threads simultaneously submitting the SAME fresh DPoP proof ->
        # EXACTLY 1 thread must succeed and 15 must fail!
        race_proof = create_dpop_proof(w_legit, "POST", htu, access_tok)

        def _try_verify(_: int) -> bool:
            try:
                verifier.verify_proof(
                    race_proof,
                    "POST",
                    "http://127.0.0.1:18080/mcp",
                    access_tok,
                    w_legit.jkt,
                )
                return True
            except DPoPError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(_try_verify, range(16)))
        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count(False), 15)


if __name__ == "__main__":
    unittest.main()
