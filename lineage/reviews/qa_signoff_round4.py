"""Round-4 Positive Security-Invariant & Full Regression Sign-Off Suite (`lineage/`).

Authored by: qa-inspector (strictly read-only on business/baseline files; standalone in `lineage/reviews/`).

All assertions in this suite express POSITIVE SECURITY INVARIANTS (every historical & fourth-order
attack vector MUST be rejected with 4xx/exception, and every legitimate positive workflow MUST pass):
- `test_01_round1_13_invariants_and_positive_dag_flow`: All 13 Round-1 vectors rejected + positive DAG flow OK.
- `test_02_round2_5_invariants_and_positive_skip_level_flow`: All 5 Round-2 vectors rejected + positive dead-B1 skip-level OK.
- `test_03_round3_failover_and_quarantine_invariants_and_positive_graft`: `HIGH-R3-02` & `MEDIUM-R3-01` rejected + positive Prune-and-Graft & CausalChainAuditor OK.
- `test_04_round3_dot_segment_and_basic_percent_encoding_invariants`: `HIGH-R3-01` direct vectors (`/./mcp`, `/mcp/.`, `/%6d%63%70`, `/%256d%2563%2570`) rejected.
- `test_05_fourth_order_unquote_delimiter_depth_and_query_preservation_invariants`:
  Verifies that iterative `unquote` in `validate_origin_form_target` + `LineageSidecar`:
  (A) Blocks `%23` (`#` fragment truncation `/mcp%23bypass`), `%3f` (`?` query injection `/mcp%3fbypass=1`),
      and `>=5x` nested `%25` encoding (`/%252525256d%2525252563%2525252570`) from bypassing `/mcp` lattice checks;
  (B) Preserves legitimate query strings and `%2f`-encoded path segments on `/a2a/...` routes without
      query loss or unintended `%2f` path-segment splitting.
"""

from __future__ import annotations

import json
import socket
import time
import unittest
from urllib.parse import unquote

import httpx

from lineage.audit import (
    AuditCollectorService,
    AuditEventType,
    AuditStreamEmitter,
    CausalChainAuditor,
)
from lineage.common.crypto import jws_sign_compact
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.protocol import (
    LatticeError,
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


def _raw_http_post(port: int, target: str, headers: dict[str, str], body: bytes) -> tuple[int, str]:
    hdr_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    req_bytes = (
        f"POST {target} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"{hdr_lines}"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii") + body
    with socket.create_connection(("127.0.0.1", port), timeout=3.0) as sock:
        sock.sendall(req_bytes)
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    raw_resp = b"".join(chunks).decode("utf-8", errors="replace")
    status_code = int(raw_resp.splitlines()[0].split()[1])
    return status_code, raw_resp


class Milestone1Round4SignOffSuite(unittest.TestCase):
    """Positive Security-Invariant Verification across R1 (13) + R2 (5) + R3 (3) + R4 Boundaries."""

    def test_01_round1_13_invariants_and_positive_dag_flow(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        w_drv = ca_alpha.issue_workload("/ns/entry/sa/drv")
        w_a = ca_alpha.issue_workload("/ns/coord/sa/a")
        w_b1 = ca_alpha.issue_workload("/ns/mid/sa/b1")
        w_b2 = ca_alpha.issue_workload("/ns/mid/sa/b2")
        w_c = ca_alpha.issue_workload("/ns/leaf/sa/c")
        w_d = ca_alpha.issue_workload("/ns/leaf/sa/d")
        w_tool = ca_alpha.issue_workload("/ns/tool/sa/pay-mcp")
        w_rev = ca_alpha.issue_workload("/ns/sys/sa/rev")

        # NaN / Inf / bool blocked
        for bad in (float("nan"), float("inf"), -float("inf"), True):
            with self.assertRaises((LatticeError, TypeError, ValueError)):
                PermissionLattice.create(tools=["pay"], max_amount=bad)  # type: ignore[arg-type]

        # Cross-domain principal `@domain` spoofing blocked
        p_root = PermissionLattice.create(tools=["book_flight", "book_hotel"], max_amount=1000.0, max_calls=3)
        with self.assertRaises(TokenError):
            mint_root_token(ca_beta, "task-spoof", "user:alice@org-alpha.io", w_drv.jkt, w_c.spiffe_id, w_c.jkt, p_root)

        # Positive + adversarial Fagin Multi-Path DAG flow
        now = time.time()
        t0 = mint_root_token(
            ca_alpha, "task-r4-dag", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p_root, hop_segment="A", now=now
        )
        ch_d = t0.attenuate(
            w_a, w_d.spiffe_id, w_d.jkt, PermissionLattice.create(tools=["book_flight"], max_amount=400.0, max_calls=1), hop_segment="D", now=now
        )
        ch_b1_c = t0.attenuate(
            w_a, w_b1.spiffe_id, w_b1.jkt, PermissionLattice.create(tools=["book_flight"], max_amount=300.0, max_calls=1), hop_segment="B1", now=now
        ).attenuate(
            w_b1, w_c.spiffe_id, w_c.jkt, PermissionLattice.create(tools=["book_flight"], max_amount=300.0, max_calls=1), hop_segment="C", now=now
        )
        ch_b2_c = t0.attenuate(
            w_a, w_b2.spiffe_id, w_b2.jkt, PermissionLattice.create(tools=["book_hotel"], max_amount=700.0, max_calls=2), hop_segment="B2", now=now
        ).attenuate(
            w_b2, w_c.spiffe_id, w_c.jkt, PermissionLattice.create(tools=["book_hotel"], max_amount=700.0, max_calls=2), hop_segment="C", now=now
        )

        with self.assertRaises(TokenError):
            MultiParentToken.assemble_and_sign(w_c, [ch_b1_c, ch_d], now=now)

        rev_svc = RevocationService(w_rev, resolver)
        rev_url = rev_svc.start()
        try:
            rev_client = RevocationReplicaClient(rev_url, resolver)
            lv = LeafVerifier(
                w_tool.spiffe_id,
                resolver,
                revocation_replica=rev_client,
                self_jkt=w_tool.jkt,
                mode=VerificationMode.LOCAL_FULL_CHAIN,
                clock_skew_seconds=0.0,
            )
            htu = "http://127.0.0.1:19941/mcp"
            mpt = MultiParentToken.assemble_and_sign(w_c, [ch_b1_c, ch_b2_c], now=now)
            tok_mpt = mpt.encode_compact()

            # Chimera cross-branch parameter mixing blocked
            r_mix = lv.verify_request(
                tok_mpt,
                create_dpop_proof(w_c, "POST", htu, tok_mpt, now=now),
                "POST",
                htu,
                tool="book_flight",
                arguments={"amount": 500.0},
                now=now,
            )
            self.assertFalse(r_mix.allowed)

            # Positive: prune B1 -> book_flight denied, book_hotel degrades smoothly to ALLOW_DEGRADED_DAG!
            rev_client.revoke_prefix(
                w_a, "/task-r4-dag/A/B1", reason="prune_b1", authority_token=ch_b1_c.encode_compact()
            )
            rev_client.sync_now()

            r_flight = lv.verify_request(
                tok_mpt,
                create_dpop_proof(w_c, "POST", htu, tok_mpt, now=now),
                "POST",
                htu,
                tool="book_flight",
                arguments={"amount": 200.0},
                now=now,
            )
            self.assertFalse(r_flight.allowed)

            r_hotel = lv.verify_request(
                tok_mpt,
                create_dpop_proof(w_c, "POST", htu, tok_mpt, now=now),
                "POST",
                htu,
                tool="book_hotel",
                arguments={"amount": 600.0},
                now=now,
            )
            self.assertTrue(r_hotel.allowed)
            self.assertEqual(r_hotel.decision, "ALLOW_DEGRADED_DAG")
        finally:
            rev_svc.stop()

    def test_02_round2_5_invariants_and_positive_skip_level_flow(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        w_drv = ca_alpha.issue_workload("/ns/entry/sa/drv")
        w_a = ca_alpha.issue_workload("/ns/coord/sa/a")
        w_b1 = ca_alpha.issue_workload("/ns/mid/sa/b1")
        w_c = ca_alpha.issue_workload("/ns/leaf/sa/c")
        w_tool = ca_alpha.issue_workload("/ns/tool/sa/pay-mcp")
        w_rev = ca_alpha.issue_workload("/ns/sys/sa/rev")

        with self.assertRaises(TypeError):
            AuditCollectorService(None)  # type: ignore[arg-type]

        rev_svc = RevocationService(w_rev, resolver)
        rev_url = rev_svc.start()
        tool_node = MCPToolSidecarNode(
            w_tool, resolver, tools={"execute_payment": lambda args, _: {"paid": args.get("amount")}}, revocation_url=rev_url
        )
        a_node = AgentSidecarNode(
            w_a, resolver, "CoordA", ["coord"], lambda *_: (200, {}), revocation_url=rev_url, directory_url=None
        )
        b1_node = AgentSidecarNode(
            w_b1, resolver, "MidB1", ["mid"], lambda *_: (200, {}), revocation_url=rev_url, directory_url=None
        )
        tool_node.start()
        a_card = a_node.start()
        b1_card = b1_node.start()
        try:
            p_pay = PermissionLattice.create(tools=["execute_payment"], max_amount=500.0)
            sc_port = int(tool_node.sidecar.inbound_url.rsplit(":", 1)[1])
            tok_c0 = mint_root_token(
                ca_alpha, "task-r4-ssrf", "user:alice", w_drv.jkt, w_c.spiffe_id, w_c.jkt, p_pay, hop_segment="C"
            ).encode_compact()
            body = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_payment","arguments":{"amount":10}}}'

            for bad_target in ("@127.0.0.1:9999/mcp", "//127.0.0.1:9999/mcp", "http://127.0.0.1:9999/mcp"):
                st, _ = _raw_http_post(
                    sc_port,
                    bad_target,
                    {
                        "Authorization": f"DPoP {tok_c0}",
                        "DPoP": create_dpop_proof(w_c, "POST", f"{tool_node.sidecar.inbound_url}/mcp", tok_c0),
                        "Content-Type": "application/json",
                    },
                    body,
                )
                self.assertEqual(st, 400)

            # Skip-level return: rejected while B1 is alive; ACCEPTED once B1 crashes!
            t0 = mint_root_token(
                ca_alpha,
                "task-r4-skip",
                "user:alice",
                w_drv.jkt,
                w_a.spiffe_id,
                w_a.jkt,
                p_pay,
                hop_segment="A",
                first_hop_public_jwk=w_a.public_jwk(),
                first_hop_return_endpoint=a_card.return_endpoint,
            )
            t_b1 = t0.attenuate(
                w_a, w_b1.spiffe_id, w_b1.jkt, p_pay, hop_segment="B1", issuer_return_endpoint=a_card.return_endpoint
            )
            t_c = t_b1.attenuate(
                w_b1, w_c.spiffe_id, w_c.jkt, p_pay, hop_segment="C", issuer_return_endpoint=b1_card.return_endpoint
            )
            compact_c = t_c.encode_compact()
            skip_url = f"{a_node.endpoint}/v1/skip-level-return"

            sr_lie = SkipLevelReceipt.create_and_sign(
                w_c,
                t_c,
                [w_b1.spiffe_id],
                w_a.spiffe_id,
                FailureEvidence(w_b1.spiffe_id, b1_card.endpoint, FaultType.CRASH, "lie", 1, time.time()),
                {"answer": 42},
            )
            r_alive = httpx.post(
                skip_url,
                json={"skip_level_receipt": sr_lie.to_dict()},
                headers={"DPoP": create_dpop_proof(w_c, "POST", skip_url, compact_c)},
                timeout=3.0,
            )
            self.assertEqual(r_alive.status_code, 403)

            # Now stop B1 -> genuine skip-level return succeeds!
            b1_node.stop()
            sr_real = SkipLevelReceipt.create_and_sign(
                w_c,
                t_c,
                [w_b1.spiffe_id],
                w_a.spiffe_id,
                FailureEvidence(w_b1.spiffe_id, b1_card.endpoint, FaultType.CRASH, "conn_refused", 1, time.time()),
                {"answer": 42},
            )
            r_dead = httpx.post(
                skip_url,
                json={"skip_level_receipt": sr_real.to_dict()},
                headers={"DPoP": create_dpop_proof(w_c, "POST", skip_url, compact_c)},
                timeout=3.0,
            )
            self.assertEqual(r_dead.status_code, 200)
            self.assertEqual(len(a_node.sidecar.get_skip_level_results("task-r4-skip")), 1)
        finally:
            b1_node.stop()
            a_node.stop()
            tool_node.stop()
            rev_svc.stop()

    def test_03_round3_failover_and_quarantine_invariants_and_positive_graft(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        w_rev = ca_alpha.issue_workload("/ns/sys/sa/rev")
        w_drv = ca_alpha.issue_workload("/ns/entry/sa/drv")
        w_a = ca_alpha.issue_workload("/ns/coord/sa/a")
        w_b1 = ca_alpha.issue_workload("/ns/work/sa/b1")
        w_b2 = ca_alpha.issue_workload("/ns/work/sa/b2")
        w_beta = ca_beta.issue_workload("/ns/coord/sa/b")
        w_beta_rev = ca_beta.issue_workload("/ns/sys/sa/rev")

        rev_svc = RevocationService(w_rev, resolver)
        dir_svc = AgentDirectoryService(resolver, revocation_trie=rev_svc.trie)
        rev_url = rev_svc.start()
        dir_url = dir_svc.start()
        b1_node = AgentSidecarNode(
            w_b1, resolver, "ByzantineB1", ["work"], lambda *_: (403, {"error": "byzantine"}), directory_url=dir_url, priority=10
        )
        b2_node = AgentSidecarNode(
            w_b2, resolver, "HealthyB2", ["work"], lambda *_: (200, {"done": True}), directory_url=dir_url, priority=20
        )
        b1_node.start()
        b2_node.start()
        try:
            rev_client = RevocationReplicaClient(rev_url, resolver)
            dir_client = AgentDirectoryClient(dir_url, resolver)
            p_work = PermissionLattice.create(tools=["work_tool"])

            # 1. Cross-domain `RevocationEvent.trust_domain` & foreign `/ns/sys/sa/rev` blocked (`HIGH-R3-02`)
            t0_a = mint_root_token(
                ca_alpha, "task-r4-graft", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p_work, hop_segment="A"
            )
            t_b1_beta = mint_root_token(
                ca_beta, "task-r4-graft", "user:bob", w_beta.jkt, w_beta.spiffe_id, w_beta.jkt, p_work, hop_segment="A"
            ).attenuate(w_beta, w_b1.spiffe_id, w_b1.jkt, p_work, hop_segment="B1")
            beta_ev = rev_client.revoke_prefix(
                w_beta, "/task-r4-graft/A/B1", reason="decoy", authority_token=t_b1_beta.encode_compact()
            )
            bad_split_fr = FailoverReceipt.create_and_sign(
                w_a,
                "task-r4-graft",
                "/task-r4-graft/A/B1",
                beta_ev.version,
                beta_ev.service_signature,
                w_b1.spiffe_id,
                w_b2.spiffe_id,
                "/task-r4-graft/A/B2-e1",
                0,
                1,
                FailureEvidence(w_b1.spiffe_id, "http://127.0.0.1:9", FaultType.CRASH, "x", 1, time.time()),
                revocation_event=beta_ev.to_dict(),
                revocation_service_svid=w_rev.workload_svid,
            )
            with self.assertRaises(ResilienceError):
                FailoverReceipt.from_dict_and_verify(bad_split_fr.to_dict(), resolver)

            fake_prov = RevocationEvent(
                88, RevocationKind.SUBTREE, "/task-r4-graft/A/B1", "x", w_a.spiffe_id, time.time(), "", w_beta_rev.workload_svid, "org-alpha.io"
            )
            f_sig = jws_sign_compact(fake_prov.core_claims(), w_beta_rev.keypair, typ="lct-revocation-event+jwt")
            f_ev = RevocationEvent(**{**fake_prov.__dict__, "service_signature": f_sig})
            bad_foreign_fr = FailoverReceipt.create_and_sign(
                w_a,
                "task-r4-graft",
                "/task-r4-graft/A/B1",
                88,
                f_sig,
                w_b1.spiffe_id,
                w_b2.spiffe_id,
                "/task-r4-graft/A/B2-e1",
                0,
                1,
                FailureEvidence(w_b1.spiffe_id, "http://127.0.0.1:9", FaultType.CRASH, "x", 1, time.time()),
                revocation_event=f_ev.to_dict(),
                revocation_service_svid=w_beta_rev.workload_svid,
            )
            with self.assertRaises(ResilienceError):
                FailoverReceipt.from_dict_and_verify(bad_foreign_fr.to_dict(), resolver)

            # 2. Bare 0-hop `B_0`, expired `B_0`, revoked `B_0`, and quarantined caller blocked (`MEDIUM-R3-01`)
            with self.assertRaises(RevocationError):
                rev_client.quarantine_workload(w_a, w_b2.spiffe_id, authority_token=t0_a.encode_compact())

            # 3. Positive Prune-and-Graft + Circuit-Breaker Quarantine (threshold=1) + CausalChainAuditor PASS!
            em_ca = AuditStreamEmitter(ca_alpha, stream_id="ca-pos")
            em_a = AuditStreamEmitter(w_a, stream_id="a-pos")
            em_ca.emit(
                AuditEventType.ROOT_MINT,
                "task-r4-graft",
                "user:alice",
                t0_a.lineage_path,
                0,
                0,
                t0_a.root_block_hash,
                t0_a.leaf_block_hash,
                "ALLOW",
            )
            coord = ResilientDelegationCoordinator(
                w_a,
                resolver,
                dir_client,
                rev_client,
                detector=ThreeLayerFaultDetector(policy_breaker_threshold=1),
                audit_emitter=em_a,
            )
            resp_graft, _, graft_receipts = coord.invoke_with_prune_and_graft(
                t0_a, "work", p_work, {"job": 1}
            )
            self.assertEqual(resp_graft["done"], True)
            self.assertEqual(len(graft_receipts), 1)
            self.assertIsNotNone(rev_svc.trie.check_workloads([w_b1.spiffe_id]))

            # Quarantined `w_b1` CANNOT retaliate even if it held a Hop-0 token!
            t0_b1 = mint_root_token(
                ca_alpha, "task-b1-retal", "user:alice", w_drv.jkt, w_b1.spiffe_id, w_b1.jkt, p_work, hop_segment="B1"
            ).attenuate(w_b1, w_b2.spiffe_id, w_b2.jkt, p_work, hop_segment="B2")
            with self.assertRaises(RevocationError):
                rev_client.quarantine_workload(w_b1, w_b2.spiffe_id, authority_token=t0_b1.encode_compact())

            rep = CausalChainAuditor(resolver).audit(em_ca.local_entries() + em_a.local_entries())
            self.assertTrue(rep.clean, f"Expected clean audit on genuine failover: {rep.anomalies}")
            self.assertIn("VERIFIED_FAILOVER_GRAFT", rep.tasks["task-r4-graft"].resilience_classifications)
        finally:
            b1_node.stop()
            b2_node.stop()
            rev_svc.stop()
            dir_svc.stop()

    def test_04_round3_dot_segment_and_basic_percent_encoding_invariants(self) -> None:
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)
        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_c = ca.issue_workload("/ns/c/sa/c")
        w_tool = ca.issue_workload("/ns/t/sa/hybrid-mcp")

        executed: list[str] = []
        upstream = ManagedHTTPService(
            "upstream-r4-04",
            lambda req: (
                (executed.append(req.path) or 200, {"ok": True}, {})
                if unquote(req.path) == "/mcp"
                else (404, {"error": "not_found"}, {})
            ),
        )
        app_url = upstream.start()
        sc = LineageSidecar(
            w_tool,
            resolver,
            app_url,
            loopback_secret="sec-r4-04",
            mode=VerificationMode.LOCAL_FULL_CHAIN,
            is_tool_server=False,
        )
        sc.start()
        try:
            tok = (
                mint_root_token(
                    ca,
                    "task-r4-04",
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
            bad_body = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_payment","arguments":{"amount":9999}}}'

            for vec in ("/./mcp", "/mcp/.", "/.//127.0.0.1:9999/mcp", "/%2e/mcp", "/%6d%63%70", "/%256d%2563%2570"):
                htu_v = f"{sc.inbound_url}{vec}"
                st, _ = _raw_http_post(
                    sc_port,
                    vec,
                    {
                        "Authorization": f"DPoP {tok}",
                        "DPoP": create_dpop_proof(w_c, "POST", htu_v, tok),
                        "Content-Type": "application/json",
                    },
                    bad_body,
                )
                self.assertIn(st, (400, 403), f"Vector {vec!r} was not blocked (got {st})")
            self.assertEqual(executed, [])
        finally:
            sc.stop()
            upstream.stop()

    def test_05_fourth_order_unquote_delimiter_depth_and_query_preservation_invariants(self) -> None:
        """[HIGH-R4-01 INVARIANT] `%23` (`#`), `%3f` (`?`), and `5x` `%25` MUST NOT bypass `/mcp` lattice or drop queries."""
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)
        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_c = ca.issue_workload("/ns/c/sa/c")
        w_tool = ca.issue_workload("/ns/t/sa/hybrid-mcp")

        executed_mcp_calls: list[dict] = []
        captured_a2a_requests: list[dict] = []

        def _upstream_app(req: HTTPRequestContext):
            if unquote(req.path) == "/mcp":
                body = req.json()
                executed_mcp_calls.append(
                    {"wire_path": req.path, "query": req.query_raw, "params": body.get("params")}
                )
                return 200, {"executed": True}, {}
            captured_a2a_requests.append({"wire_path": req.path, "query": req.query_raw})
            return 200, {"a2a_ok": True, "wire_path": req.path, "query": req.query_raw}, {}

        upstream = ManagedHTTPService("upstream-r4-05", _upstream_app)
        app_url = upstream.start()
        sc = LineageSidecar(
            w_tool,
            resolver,
            app_url,
            loopback_secret="sec-r4-05",
            mode=VerificationMode.LOCAL_FULL_CHAIN,
            is_tool_server=False,
        )
        sc.start()
        try:
            tok_deleg = (
                mint_root_token(
                    ca,
                    "task-r4-05",
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

            # 1. Adversarial 4th-order bypass vectors:
            #    - `/mcp%23bypass`: `%23` decodes to `#` in `norm_path`, skipping `is_mcp_route` while `httpx` strips `#bypass` -> `POST /mcp`!
            #    - `/mcp%3fbypass=1`: `%3f` decodes to `?` in `norm_path`, skipping `is_mcp_route` while `httpx`/upstream sees `req.path == "/mcp"`!
            #    - `/%252525256d%2525252563%2525252570`: 5x-encoded `/mcp` exceeds `range(4)` -> `norm_path == "/%6d%63%70"`, upstream unquotes 5th layer -> `"/mcp"`!
            for r4_vec in (
                "/mcp%23bypass",
                "/mcp%3fbypass=1",
                "/%252525256d%2525252563%2525252570",
            ):
                with self.subTest(vector=r4_vec):
                    htu_v = f"{sc.inbound_url}{r4_vec}"
                    st, resp_txt = _raw_http_post(
                        sc_port,
                        r4_vec,
                        {
                            "Authorization": f"DPoP {tok_deleg}",
                            "DPoP": create_dpop_proof(w_c, "POST", htu_v, tok_deleg),
                            "Content-Type": "application/json",
                        },
                        forbidden_body,
                    )
                    self.assertIn(
                        st,
                        (400, 403),
                        f"[HIGH-R4-01] 4th-order vector {r4_vec!r} bypassed Sidecar `/mcp` lattice (got HTTP {st}: {resp_txt.splitlines()[-1]})",
                    )

            with self.subTest(check="zero_forbidden_mcp_executions"):
                self.assertEqual(executed_mcp_calls, [], f"Forbidden MCP calls executed: {executed_mcp_calls}")

            # 2. Positive invariant: legitimate `/a2a/items/ns%2fname?filter=active&limit=5` preserves
            #    query parameters AND does NOT split `ns%2fname` into two path segments!
            with self.subTest(check="preserve_query_and_encoded_slash_segment"):
                legit_target = "/a2a/items/ns%2fname?filter=active&limit=5"
                legit_htu = f"{sc.inbound_url}/a2a/items/ns%2fname"
                st_ok, resp_ok = _raw_http_post(
                    sc_port,
                    legit_target,
                    {
                        "Authorization": f"DPoP {tok_deleg}",
                        "DPoP": create_dpop_proof(w_c, "POST", legit_htu, tok_deleg),
                        "Content-Type": "application/json",
                    },
                    b'{"task":"ping"}',
                )
                self.assertEqual(st_ok, 200, f"Legitimate A2A request failed: {resp_ok}")
                self.assertEqual(len(captured_a2a_requests), 1)
                self.assertEqual(captured_a2a_requests[0]["query"], "filter=active&limit=5")
                self.assertEqual(captured_a2a_requests[0]["wire_path"], "/a2a/items/ns%2fname")
        finally:
            sc.stop()
            upstream.stop()


if __name__ == "__main__":
    unittest.main()
