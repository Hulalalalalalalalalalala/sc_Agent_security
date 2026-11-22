"""Unit & Integration Tests for LineagePrefixTrie, HTTP RevocationService, and Fagin DAG Revocation."""

from __future__ import annotations

import threading
import time
import unittest

from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.protocol import (
    MultiParentToken,
    PermissionLattice,
    create_dpop_proof,
    mint_root_token,
)
from lineage.revocation import (
    LineagePrefixTrie,
    RevocationKind,
    RevocationReplicaClient,
    RevocationService,
)
from lineage.verifier import LeafVerifier, VerificationMode


class TestRevocationAndFaginDAG(unittest.TestCase):
    def test_segment_exact_prefix_trie_no_false_sibling_collision(self) -> None:
        trie = LineagePrefixTrie()
        ev = trie.revoke_prefix("/task-1/A/B1", requested_by="admin", reason="compromised")
        self.assertEqual(ev.kind, RevocationKind.SUBTREE)

        # Revoked node & offline-derived grandchildren MUST match
        self.assertIsNotNone(trie.check_lineage_path("/task-1/A/B1"))
        self.assertIsNotNone(trie.check_lineage_path("/task-1/A/B1/C"))
        self.assertIsNotNone(trie.check_lineage_path("/task-1/A/B1/C/D"))

        # Sibling `/task-1/A/B10` (string prefix trap!) and `/task-1/A/B2` and `/task-10/...` MUST NOT match!
        self.assertIsNone(trie.check_lineage_path("/task-1/A/B10"))
        self.assertIsNone(trie.check_lineage_path("/task-1/A/B10/C"))
        self.assertIsNone(trie.check_lineage_path("/task-1/A/B2"))
        self.assertIsNone(trie.check_lineage_path("/task-10/A/B1"))

        # Full-chain teardown `/task-1` kills all remaining branches of task-1, leaving task-10 intact
        ev_full = trie.revoke_prefix("/task-1", requested_by="user:alice", reason="user_cancel")
        self.assertEqual(ev_full.kind, RevocationKind.FULL_CHAIN)
        self.assertIsNotNone(trie.check_lineage_path("/task-1/A/B2"))
        self.assertIsNotNone(trie.check_lineage_path("/task-1/A/B10/C"))
        self.assertIsNone(trie.check_lineage_path("/task-10/A/B1"))

    def test_http_revocation_service_long_polling_and_signature_verification(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_svc = ca.issue_workload("/ns/sys/sa/revocation-svc")
        w_coord = ca.issue_workload("/ns/coord/sa/agent-a")

        svc = RevocationService(w_svc, resolver)
        url = svc.start()
        try:
            replica = RevocationReplicaClient(url, resolver)
            self.assertEqual(replica.trie.version, 0)

            # Test real-time wakeup of long-polling `sync_now(wait_ms=2000)`
            wakeup_elapsed: list[float] = []

            def _waiter() -> None:
                t0 = time.perf_counter()
                replica.sync_now(wait_ms=2000)
                wakeup_elapsed.append(time.perf_counter() - t0)

            th = threading.Thread(target=_waiter)
            th.start()
            time.sleep(0.08)

            # Issue revocation from another client using verified lineage authority
            auth_tok = mint_root_token(
                ca,
                "task-live",
                "user:alice",
                w_coord.jkt,
                w_coord.spiffe_id,
                w_coord.jkt,
                PermissionLattice.create(tools=["t"]),
                hop_segment="A",
            ).encode_compact()
            issuer_client = RevocationReplicaClient(url, resolver)
            issuer_client.revoke_prefix(
                w_coord, "/task-live/A/B1", reason="timeout", authority_token=auth_tok
            )
            th.join(timeout=2.0)

            self.assertEqual(replica.trie.version, 1)
            self.assertTrue(len(wakeup_elapsed) == 1 and wakeup_elapsed[0] < 1.0)
            self.assertIsNotNone(replica.trie.check_lineage_path("/task-live/A/B1/C"))
        finally:
            svc.stop()

    def test_fagin_multipath_dag_revocation_exact_degradation_semantics(self) -> None:
        """Verify Fagin Multi-Path DAG Revocation on diamond A -> {B1, B2} -> C -> Tool."""
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        ca_pay = TrustDomainCA("org-payment.io")

        resolver = TrustBundleResolver()
        for ca in (ca_alpha, ca_beta, ca_pay):
            resolver.register_domain_ca(ca)

        w_drv = ca_alpha.issue_workload("/ns/entry/sa/driver")
        w_a = ca_alpha.issue_workload("/ns/coord/sa/coord-a")
        w_b1 = ca_beta.issue_workload("/ns/travel/sa/flight-b1")
        w_b2 = ca_beta.issue_workload("/ns/travel/sa/hotel-b2")
        w_c = ca_pay.issue_workload("/ns/settle/sa/aggregator-c")
        w_tool = ca_pay.issue_workload("/ns/tools/sa/travel-gateway")
        w_rev = ca_alpha.issue_workload("/ns/sys/sa/revocation")

        rev_svc = RevocationService(w_rev, resolver)
        rev_url = rev_svc.start()
        try:
            replica = RevocationReplicaClient(rev_url, resolver)
            verifier = LeafVerifier(
                self_spiffe_id=w_tool.spiffe_id,
                self_jkt=w_tool.jkt,
                trust_resolver=resolver,
                mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
                revocation_replica=replica,
            )

            p0 = PermissionLattice.create(
                tools=["book_flight", "book_hotel", "write_ledger"],
                max_amount=2000.0,
                allowed_scopes=["flight:book", "hotel:book", "ledger:write"],
            )
            t_root = mint_root_token(
                ca_alpha,
                "task-dag-fagin",
                "user:alice",
                w_drv.jkt,
                w_a.spiffe_id,
                w_a.jkt,
                p0,
                hop_segment="A",
            )

            # Branch 1 (A -> B1 -> C): grants `book_flight` & `write_ledger` up to 1200
            p_b1 = PermissionLattice.create(
                tools=["book_flight", "write_ledger"],
                max_amount=1200.0,
                allowed_scopes=["flight:book", "ledger:write"],
            )
            chain_b1 = t_root.attenuate(
                w_a, w_b1.spiffe_id, w_b1.jkt, p_b1, hop_segment="B1"
            ).attenuate(w_b1, w_c.spiffe_id, w_c.jkt, p_b1, hop_segment="C")

            # Branch 2 (A -> B2 -> C): grants `book_hotel` & `write_ledger` up to 700
            p_b2 = PermissionLattice.create(
                tools=["book_hotel", "write_ledger"],
                max_amount=700.0,
                allowed_scopes=["hotel:book", "ledger:write"],
            )
            chain_b2 = t_root.attenuate(
                w_a, w_b2.spiffe_id, w_b2.jkt, p_b2, hop_segment="B2"
            ).attenuate(w_b2, w_c.spiffe_id, w_c.jkt, p_b2, hop_segment="C")

            # Aggregator C assembles MultiParentToken(chain_b1, chain_b2)
            mpt = MultiParentToken.assemble_and_sign(w_c, [chain_b1, chain_b2])
            compact_mp = mpt.encode_compact()
            htu = "http://127.0.0.1:19900/mcp"

            def _call(tool_name: str, args: dict):
                dpop = create_dpop_proof(w_c, "POST", htu, compact_mp)
                return verifier.verify_request(
                    compact_token=compact_mp,
                    dpop_proof=dpop,
                    htm="POST",
                    htu=htu,
                    method="tools/call",
                    tool=tool_name,
                    arguments=args,
                )

            # Phase 1: Both B1 and B2 alive -> flight (900), hotel (500), ledger (1000) ALL SUCCEED!
            r1 = _call("book_flight", {"amount": 900, "scope": "flight:book"})
            self.assertTrue(r1.allowed)
            self.assertEqual(r1.decision, "ALLOW")

            r2 = _call("book_hotel", {"amount": 500, "scope": "hotel:book"})
            self.assertTrue(r2.allowed)
            self.assertEqual(r2.decision, "ALLOW")

            r3 = _call("write_ledger", {"amount": 1000, "scope": "ledger:write"})
            self.assertTrue(r3.allowed)

            # Phase 2: Revoke ONLY `/task-dag-fagin/A/B1` at RevocationService!
            # Notice we do NOT manually sync replica; ADAPTIVE_RISK_ANCHORED auto-syncs on HIGH_RISK tools!
            rev_svc.revoke_prefix_direct(
                "/task-dag-fagin/A/B1", requested_by=w_a.spiffe_id, reason="b1_fault"
            )

            # Now C uses the EXACT SAME MultiParentToken:
            # 2a) `book_hotel(500)` -> B2 satisfies it -> SMOOTH DEGRADATION 200!
            r_hotel_after = _call("book_hotel", {"amount": 500, "scope": "hotel:book"})
            self.assertTrue(r_hotel_after.allowed)
            self.assertEqual(r_hotel_after.decision, "ALLOW_DEGRADED_DAG")
            self.assertEqual(
                r_hotel_after.pruned_revoked_paths, ("/task-dag-fagin/A/B1/C",)
            )
            self.assertEqual(
                r_hotel_after.active_paths, ("/task-dag-fagin/A/B2/C",)
            )

            # 2b) `write_ledger(600)` -> B2 (max_amount=700) still satisfies 600 -> SMOOTH DEGRADATION 200!
            r_ledger_600 = _call("write_ledger", {"amount": 600, "scope": "ledger:write"})
            self.assertTrue(r_ledger_600.allowed)
            self.assertEqual(r_ledger_600.decision, "ALLOW_DEGRADED_DAG")

            # 2c) `write_ledger(1000)` -> depended on B1's 1200 limit (B2 only allows <=700) -> 403!
            r_ledger_1000 = _call(
                "write_ledger", {"amount": 1000, "scope": "ledger:write"}
            )
            self.assertFalse(r_ledger_1000.allowed)
            self.assertEqual(r_ledger_1000.status_code, 403)
            self.assertEqual(
                r_ledger_1000.reason_code,
                "REVOKED_DEPENDENCY_INSUFFICIENT_SURVIVING_PATHS",
            )

            # 2d) `book_flight(900)` -> depended exclusively on B1 -> 403!
            r_flight_after = _call("book_flight", {"amount": 900, "scope": "flight:book"})
            self.assertFalse(r_flight_after.allowed)
            self.assertEqual(r_flight_after.status_code, 403)
            self.assertEqual(
                r_flight_after.reason_code,
                "REVOKED_DEPENDENCY_INSUFFICIENT_SURVIVING_PATHS",
            )

            # Phase 3: Also revoke `/task-dag-fagin/A/B2` -> ALL branches dead -> 403!
            rev_svc.revoke_prefix_direct(
                "/task-dag-fagin/A/B2", requested_by=w_a.spiffe_id, reason="b2_fault"
            )
            r_all_dead = _call("book_hotel", {"amount": 200, "scope": "hotel:book"})
            self.assertFalse(r_all_dead.allowed)
            self.assertEqual(r_all_dead.status_code, 403)
            self.assertEqual(r_all_dead.reason_code, "ALL_DAG_PARENT_CHAINS_REVOKED")
        finally:
            rev_svc.stop()


if __name__ == "__main__":
    unittest.main()
