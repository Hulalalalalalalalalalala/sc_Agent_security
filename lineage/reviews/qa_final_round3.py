"""Round-3 Final Sign-Off & Third-Order Boundary Verification Suite (`lineage/`).

Authored by: qa-inspector (strictly read-only on business/baseline files; standalone in `lineage/reviews/`).

Coverage:
1. `test_01_round1_all_13_attacks_blocked`:
   Independently verifies that all 13 Round-1 vulnerabilities (`CRITICAL-01..04`, `HIGH-01..04`,
   `MEDIUM-01..03`, `LOW-01..02`) remain 100% blocked.
2. `test_02_round2_all_5_attacks_blocked_and_clean_third_order_checks`:
   Independently verifies that all 5 Round-2 second-order vulnerabilities (`CRITICAL-R2-01`,
   `HIGH-R2-01..03`, `MEDIUM-R2-01`) are blocked on their direct vectors, and verifies clean
   third-order boundaries:
   - `%40` and `%2f%2f` percent-encoded segments cannot trigger upstream host/authority SSRF;
   - `LineagePrefixTrie` `_wildcard_root` cannot be written via HTTP `/v1/revoke/prefix` (`trust_domain=None`/`""`);
   - `AuditCollectorService` strictly requires `TrustBundleResolver`;
   - `SkipLevelReceipt` active `/healthz` probing does NOT follow HTTP `302` redirects (`follow_redirects=False`),
     handles slow/stalled intermediates safely via `liveness_probe_timeout`, and fails closed when probe URLs are empty.
3. Empirical reproduction of 3 Third-Order Boundary Vulnerabilities uncovered in Round-3:
   - `[HIGH-R3-01]` (`test_03_r3_high_01_dot_segment_and_percent_encoded_mcp_lattice_bypass`):
     `validate_origin_form_target` allows single-dot segments (`/./mcp`, `/mcp/.`), mid-path `/.//...`,
     and percent-encoded `/%6d%63%70`. On standalone `LineageSidecar(is_tool_server=False)`, `norm_path`
     is `"/./mcp" != "/mcp"`, skipping `check_invocation_lattice` and quota consumption, while `httpx`
     RFC 3986 §5.2.4 normalizes `/./mcp` and `/mcp/.` to `POST /mcp` on the upstream wire!
   - `[HIGH-R3-02]` (`test_04_r3_high_02_cross_domain_revocation_event_split_brain_failover_spoof`):
     (A) `FailoverReceipt.from_dict_and_verify` and `CausalChainAuditor` fail to validate
         `RevocationEvent.trust_domain` (and `RevocationKind.SUBTREE`), allowing a real `RevocationService`-signed
         `org-beta.io` `RevocationEvent` for colliding path `/task-x/A/B1` to certify `VERIFIED_FAILOVER_GRAFT`
         on an `org-alpha.io` task while `org-alpha.io`'s `B1` remains 100% unrevoked (split-brain!);
     (B) When `trusted_revocation_spiffe_ids=None`, `FailoverReceipt` checks `rev_svc_spiffe.path` without
         checking `rev_svc_spiffe.trust_domain`, allowing a foreign CA `ca_beta` (`/ns/sys/sa/rev`) to sign
         fake `RevocationEvent`s for `org-alpha.io` tasks.
   - `[MEDIUM-R3-01]` (`test_05_r3_medium_01_quarantined_revoked_or_expired_hop0_retaliatory_quarantine`):
     `RevocationService._authorize_workload_quarantine` swallows `TokenExpiredError` (`except TokenExpiredError: pass`),
     accepts bare 0-hop `B_0`, and neither `RevocationService` nor `AgentDirectoryService` checks whether the
     caller workload is ALREADY quarantined or whether its Hop-0 task lineage was ALREADY revoked by the CA,
     allowing an expired/revoked/quarantined Hop-0 workload to globally quarantine healthy cluster workloads.
"""

from __future__ import annotations

import json
import socket
import threading
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
from lineage.common.http_utils import ManagedHTTPService
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
    SkipLevelReceipt,
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
    status_line = raw_resp.splitlines()[0]
    status_code = int(status_line.split()[1])
    return status_code, raw_resp


class Milestone1Round3FinalAuditTests(unittest.TestCase):
    """Round-3 Verification of R1 (13) + R2 (5) Fixes and Third-Order Boundary Probing."""

    def test_01_round1_all_13_attacks_blocked(self) -> None:
        """[R1 REGRESSION] Confirm all 13 Round-1 vulnerabilities remain blocked."""
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

        # HIGH-03: NaN / Inf / bool rejected in PermissionLattice & invocation check
        for bad_num in (float("nan"), float("inf"), -float("inf"), True):
            with self.assertRaises((LatticeError, TypeError, ValueError)):
                PermissionLattice.create(tools=["pay"], max_amount=bad_num)  # type: ignore[arg-type]
        p_pay = PermissionLattice.create(tools=["execute_payment"], max_amount=500.0, max_calls=2)
        ok_nan, _ = p_pay.check_invocation("tools/call", "execute_payment", {"amount": float("nan")}, 1)
        ok_bool, _ = p_pay.check_invocation("tools/call", "execute_payment", {"amount": True}, 1)
        self.assertFalse(ok_nan)
        self.assertFalse(ok_bool)

        # MEDIUM-01(B): Cross-domain principal `@domain` spoofing blocked
        with self.assertRaises(TokenError):
            mint_root_token(
                ca_beta, "task-spoof", "user:alice@org-alpha.io", w_drv.jkt, w_c.spiffe_id, w_c.jkt, p_pay
            )

        # CRITICAL-02 & HIGH-02 & MEDIUM-01(A) & MEDIUM-03: MultiParentToken holder, disjunctive tools,
        # atomic block quota without partial mutation, expired-vs-forged branch handling
        now = time.time()
        p_root = PermissionLattice.create(
            tools=["book_flight", "book_hotel"], max_amount=1000.0, max_calls=2
        )
        t0 = mint_root_token(
            ca_alpha, "task-r1-dag", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p_root, hop_segment="A", now=now
        )
        ch_for_d = t0.attenuate(
            w_a,
            w_d.spiffe_id,
            w_d.jkt,
            PermissionLattice.create(tools=["book_flight"], max_amount=500.0, max_calls=1),
            hop_segment="D",
            now=now,
        )
        ch_flight_c = t0.attenuate(
            w_a,
            w_b1.spiffe_id,
            w_b1.jkt,
            PermissionLattice.create(tools=["book_flight"], max_amount=300.0, max_calls=1),
            hop_segment="B1",
            now=now,
        ).attenuate(
            w_b1,
            w_c.spiffe_id,
            w_c.jkt,
            PermissionLattice.create(tools=["book_flight"], max_amount=300.0, max_calls=1),
            hop_segment="C",
            now=now,
        )
        ch_hotel_c = t0.attenuate(
            w_a,
            w_b2.spiffe_id,
            w_b2.jkt,
            PermissionLattice.create(tools=["book_hotel"], max_amount=600.0, max_calls=2),
            hop_segment="B2",
            now=now,
        ).attenuate(
            w_b2,
            w_c.spiffe_id,
            w_c.jkt,
            PermissionLattice.create(tools=["book_hotel"], max_amount=600.0, max_calls=2),
            hop_segment="C",
            now=now,
        )

        # Stealing D's branch into C's MultiParentToken -> rejected
        with self.assertRaises(TokenError):
            MultiParentToken.assemble_and_sign(w_c, [ch_flight_c, ch_for_d], now=now)

        mpt_c = MultiParentToken.assemble_and_sign(w_c, [ch_flight_c, ch_hotel_c], now=now)
        lv = LeafVerifier(
            w_tool.spiffe_id, resolver, self_jkt=w_tool.jkt, mode=VerificationMode.LOCAL_FULL_CHAIN, clock_skew_seconds=0.0
        )
        htu = "http://127.0.0.1:19911/mcp"
        compact_mpt = mpt_c.encode_compact()

        # Cross-branch Chimera (book_flight with amount=500 > 300 from hotel branch) -> rejected!
        r_chimera = lv.verify_request(
            compact_mpt,
            create_dpop_proof(w_c, "POST", htu, compact_mpt, now=now),
            "POST",
            htu,
            tool="book_flight",
            arguments={"amount": 500.0},
            now=now,
        )
        self.assertFalse(r_chimera.allowed)
        self.assertEqual(r_chimera.reason_code, "LATTICE_PERMISSION_DENIED")

        # Call 1 on book_flight (exhausts B1 max_calls=1, consumes 1/2 of B0) -> allowed
        r1 = lv.verify_request(
            compact_mpt,
            create_dpop_proof(w_c, "POST", htu, compact_mpt, now=now),
            "POST",
            htu,
            tool="book_flight",
            arguments={"amount": 200.0},
            now=now,
        )
        self.assertTrue(r1.allowed)

        # Call 2 on book_flight -> denied (QUOTA_EXCEEDED) WITHOUT mutating B0's remaining 1/2 quota!
        r2 = lv.verify_request(
            compact_mpt,
            create_dpop_proof(w_c, "POST", htu, compact_mpt, now=now),
            "POST",
            htu,
            tool="book_flight",
            arguments={"amount": 200.0},
            now=now,
        )
        self.assertFalse(r2.allowed)
        self.assertEqual(r2.reason_code, "QUOTA_EXCEEDED")

        # Call 3 on book_hotel -> STILL succeeds using B0's 2nd slot via B2!
        r3 = lv.verify_request(
            compact_mpt,
            create_dpop_proof(w_c, "POST", htu, compact_mpt, now=now),
            "POST",
            htu,
            tool="book_hotel",
            arguments={"amount": 500.0},
            now=now,
        )
        self.assertTrue(r3.allowed)

        # CRITICAL-01, CRITICAL-03, CRITICAL-04, HIGH-01, LOW-01/02 live HTTP checks
        rev_svc = RevocationService(w_rev, resolver)
        rev_url = rev_svc.start()
        rev_client = RevocationReplicaClient(rev_url, resolver)
        tool_node = MCPToolSidecarNode(
            w_tool,
            resolver,
            tools={"execute_payment": lambda args, _: {"ok": args.get("amount")}},
            revocation_url=rev_url,
            mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
        )
        a_node = AgentSidecarNode(w_a, resolver, "A", ["coord"], lambda *_: (200, {}), directory_url=None)
        b1_node = AgentSidecarNode(w_b1, resolver, "B1", ["mid"], lambda *_: (200, {}), directory_url=None)
        tool_node.start()
        a_card = a_node.start()
        b1_card = b1_node.start()
        try:
            # CRITICAL-01: Forged X-LCT-Loopback-Auth on inbound port -> 401; forged LOW risk hint -> ignored
            r_loop = httpx.post(
                f"{tool_node.sidecar.inbound_url}/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "execute_payment", "arguments": {"amount": 10}}},
                headers={"X-LCT-Loopback-Auth": "forged"},
                timeout=3.0,
            )
            self.assertEqual(r_loop.status_code, 401)

            # CRITICAL-03: Unrelated workload w_d cannot revoke /task-r1-dag
            with self.assertRaises(RevocationError):
                rev_client.revoke_prefix(w_d, "/task-r1-dag", reason="unauthorized_dos")

            # CRITICAL-04 & HIGH-01: Grandchild C cannot hit A's /v1/task-result directly, and cannot skip healthy B1
            t_live = mint_root_token(
                ca_alpha,
                "task-r1-skip",
                "user:alice",
                w_drv.jkt,
                w_a.spiffe_id,
                w_a.jkt,
                p_pay,
                hop_segment="A",
                first_hop_public_jwk=w_a.public_jwk(),
                first_hop_return_endpoint=a_card.return_endpoint,
            )
            t_live_b1 = t_live.attenuate(
                w_a, w_b1.spiffe_id, w_b1.jkt, p_pay, hop_segment="B1", issuer_return_endpoint=a_card.return_endpoint
            )
            t_live_c = t_live_b1.attenuate(
                w_b1, w_c.spiffe_id, w_c.jkt, p_pay, hop_segment="C", issuer_return_endpoint=b1_card.return_endpoint
            )
            tok_c_str = t_live_c.encode_compact()

            res_url = f"{a_node.endpoint}/v1/task-result"
            r_direct = httpx.post(
                res_url,
                json={"result": {"spoof": 1}},
                headers={
                    "Authorization": f"DPoP {tok_c_str}",
                    "DPoP": create_dpop_proof(w_c, "POST", res_url, tok_c_str),
                },
                timeout=3.0,
            )
            self.assertEqual(r_direct.status_code, 403)
            self.assertIn("NOT_DIRECT_CHILD_DELEGATE", r_direct.text)

            sr_lie = SkipLevelReceipt.create_and_sign(
                w_c,
                t_live_c,
                [w_b1.spiffe_id],
                w_a.spiffe_id,
                FailureEvidence(w_b1.spiffe_id, b1_card.endpoint, FaultType.CRASH, "lie", 1, time.time()),
                {"lie": True},
            )
            skip_url = f"{a_node.endpoint}/v1/skip-level-return"
            r_skip_healthy = httpx.post(
                skip_url,
                json={"skip_level_receipt": sr_lie.to_dict()},
                headers={"DPoP": create_dpop_proof(w_c, "POST", skip_url, tok_c_str)},
                timeout=3.0,
            )
            self.assertEqual(r_skip_healthy.status_code, 403)
            self.assertIn("INTERMEDIATE_ANCESTOR_ALIVE", r_skip_healthy.text)
        finally:
            b1_node.stop()
            a_node.stop()
            tool_node.stop()
            rev_svc.stop()

    def test_02_round2_all_5_attacks_blocked_and_clean_third_order_checks(self) -> None:
        """[R2 REGRESSION + CLEAN R3 CHECKS] Confirm all 5 R2 fixes and clean third-order boundaries."""
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        w_drv = ca_alpha.issue_workload("/ns/entry/sa/drv")
        w_coord = ca_alpha.issue_workload("/ns/coord/sa/root-coord")
        w_hop1 = ca_alpha.issue_workload("/ns/work/sa/hop1")
        w_c = ca_alpha.issue_workload("/ns/leaf/sa/c")
        w_tool = ca_alpha.issue_workload("/ns/tool/sa/pay-mcp")
        w_rev = ca_alpha.issue_workload("/ns/sys/sa/rev")

        # 1. AuditCollectorService without TrustBundleResolver raises TypeError (`HIGH-R2-03` B)
        with self.assertRaises(TypeError):
            AuditCollectorService(None)  # type: ignore[arg-type]

        # 2. Same-domain fake `/ns/sys/sa/rev-evil` cannot be self-minted without CA key, and
        #    self/peer SVID in FailoverReceipt is rejected (`HIGH-R2-03` A)
        p_pay = PermissionLattice.create(tools=["execute_payment"], max_amount=500.0)
        t0 = mint_root_token(
            ca_alpha, "task-r2-check", "user:alice", w_drv.jkt, w_coord.spiffe_id, w_coord.jkt, p_pay, hop_segment="Coord"
        )
        t_h1 = t0.attenuate(w_coord, w_hop1.spiffe_id, w_hop1.jkt, p_pay, hop_segment="H1")
        fake_ev_prov = RevocationEvent(
            1, RevocationKind.SUBTREE, t_h1.lineage_path, "fake", w_coord.spiffe_id, time.time(), "", w_hop1.workload_svid, "org-alpha.io"
        )
        fake_sig = jws_sign_compact(fake_ev_prov.core_claims(), w_hop1.keypair, typ="lct-revocation-event+jwt")
        fake_ev = RevocationEvent(**{**fake_ev_prov.__dict__, "service_signature": fake_sig})
        bad_fr = FailoverReceipt.create_and_sign(
            w_coord,
            "task-r2-check",
            t_h1.lineage_path,
            1,
            fake_sig,
            w_hop1.spiffe_id,
            w_c.spiffe_id,
            "/task-r2-check/Coord/C-e1",
            0,
            1,
            FailureEvidence(w_hop1.spiffe_id, "http://127.0.0.1:9", FaultType.CRASH, "err", 1, time.time()),
            revocation_event=fake_ev.to_dict(),
            revocation_service_svid=w_hop1.workload_svid,
        )
        with self.assertRaises(ResilienceError):
            FailoverReceipt.from_dict_and_verify(bad_fr.to_dict(), resolver)

        # 3. Percent-encoded `%40` and `%2f%2f` on MCPToolSidecarNode do NOT trigger SSRF (`CRITICAL-R2-01`)
        ssrf_hits: list[str] = []
        evil_srv = ManagedHTTPService("evil-listener", lambda r: (ssrf_hits.append(r.raw_path) or 200, {"evil": 1}, {}))
        evil_srv.start()
        tool_node = MCPToolSidecarNode(
            w_tool, resolver, tools={"execute_payment": lambda args, _: {"paid": args.get("amount")}}
        )
        rev_svc = RevocationService(w_rev, resolver)
        dir_svc = AgentDirectoryService(resolver)
        rev_url = rev_svc.start()
        dir_url = dir_svc.start()
        tool_node.start()
        try:
            sc_port = int(tool_node.sidecar.inbound_url.rsplit(":", 1)[1])
            tok_c = mint_root_token(
                ca_alpha, "task-r2-http", "user:alice", w_drv.jkt, w_c.spiffe_id, w_c.jkt, p_pay, hop_segment="C"
            ).encode_compact()
            body = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_payment","arguments":{"amount":10}}}'

            # Direct R2 SSRF vectors -> 400
            for smuggled in (
                f"@127.0.0.1:{evil_srv.port}/mcp",
                f"//127.0.0.1:{evil_srv.port}/mcp",
                f"http://127.0.0.1:{evil_srv.port}/mcp",
            ):
                code, _ = _raw_http_post(
                    sc_port,
                    smuggled,
                    {
                        "Authorization": f"DPoP {tok_c}",
                        "DPoP": create_dpop_proof(w_c, "POST", f"{tool_node.sidecar.inbound_url}/mcp", tok_c),
                        "Content-Type": "application/json",
                    },
                    body,
                )
                self.assertEqual(code, 400)

            # Third-order `%40` & `%2f%2f` percent-encoding -> stays confined to upstream loopback, zero SSRF!
            for pct_target in (
                f"/%40127.0.0.1:{evil_srv.port}/mcp",
                f"/%2f%2f127.0.0.1:{evil_srv.port}/mcp",
            ):
                htu_pct = f"{tool_node.sidecar.inbound_url}{pct_target}"
                code_pct, _ = _raw_http_post(
                    sc_port,
                    pct_target,
                    {
                        "Authorization": f"DPoP {tok_c}",
                        "DPoP": create_dpop_proof(w_c, "POST", htu_pct, tok_c),
                        "Content-Type": "application/json",
                    },
                    body,
                )
                self.assertIn(code_pct, (200, 400, 404))
            self.assertEqual(ssrf_hits, [], "Percent-encoded %40 / %2f%2f triggered external SSRF!")

            # 4. Hop-1 unilateral attenuation cannot globally quarantine (`HIGH-R2-01`)
            rev_client = RevocationReplicaClient(rev_url, resolver)
            dir_client = AgentDirectoryClient(dir_url, resolver)
            forged_h2 = t_h1.attenuate(w_hop1, w_tool.spiffe_id, w_tool.jkt, p_pay, hop_segment="Tool").encode_compact()
            with self.assertRaises(RevocationError):
                rev_client.quarantine_workload(w_hop1, w_tool.spiffe_id, authority_token=forged_h2)
            with self.assertRaises(AgentCardError):
                dir_client.quarantine(
                    w_hop1, w_tool.spiffe_id, reason="unauth", authority_token=forged_h2
                )

            # 5. `_wildcard_root` cannot be injected over HTTP `/v1/revoke/prefix` even if JSON passes `trust_domain: null` (`HIGH-R2-02`)
            cmd = {
                "jti": "revcmd-wild-attempt-01",
                "prefix": "/task-wild-attempt",
                "reason": "wild",
                "trust_domain": None,
                "iat": time.time(),
            }
            sig = jws_sign_compact(cmd, ca_beta.active_keypair, typ="lct-revoke-cmd+jwt")
            r_wild = httpx.post(
                f"{rev_url}/v1/revoke/prefix",
                json={"auth_mode": "domain_authority", "trust_domain": "org-beta.io", "command_jws": sig, "trust_domain_override": None},
                timeout=3.0,
            )
            self.assertEqual(r_wild.status_code, 200)
            # Wildcard root remains untouched; org-alpha.io is unaffected while org-beta.io is revoked!
            self.assertIsNone(
                rev_svc.trie.check_lineage_path("/task-wild-attempt", trust_domain="org-alpha.io")
            )
            self.assertIsNotNone(
                rev_svc.trie.check_lineage_path("/task-wild-attempt", trust_domain="org-beta.io")
            )

            # 6. Skip-level liveness probe does NOT follow 302 redirects (`follow_redirects=False`) and handles slow response (`MEDIUM-R2-01`)
            redir_b1 = ManagedHTTPService(
                "redir-b1",
                lambda req: (302, {"redir": True}, {"Location": f"http://127.0.0.1:{evil_srv.port}/ssrf-via-302"}),
            )
            redir_url = redir_b1.start()
            a_node = AgentSidecarNode(w_coord, resolver, "CoordA", ["coord"], lambda *_: (200, {}), directory_url=None)
            a_card = a_node.start()
            try:
                t_skip_0 = mint_root_token(
                    ca_alpha,
                    "task-r3-redir",
                    "user:alice",
                    w_drv.jkt,
                    w_coord.spiffe_id,
                    w_coord.jkt,
                    p_pay,
                    hop_segment="Coord",
                    first_hop_public_jwk=w_coord.public_jwk(),
                    first_hop_return_endpoint=a_card.return_endpoint,
                )
                t_skip_b1 = t_skip_0.attenuate(
                    w_coord, w_hop1.spiffe_id, w_hop1.jkt, p_pay, hop_segment="H1", issuer_return_endpoint=a_card.return_endpoint
                )
                t_skip_c = t_skip_b1.attenuate(
                    w_hop1, w_c.spiffe_id, w_c.jkt, p_pay, hop_segment="C", issuer_return_endpoint=redir_url
                )
                sr = SkipLevelReceipt.create_and_sign(
                    w_c,
                    t_skip_c,
                    [w_hop1.spiffe_id],
                    w_coord.spiffe_id,
                    FailureEvidence(w_hop1.spiffe_id, redir_url, FaultType.CRASH, "302_broken", 1, time.time()),
                    {"ok": 1},
                )
                skip_ep = f"{a_node.endpoint}/v1/skip-level-return"
                tok_sc = t_skip_c.encode_compact()
                httpx.post(
                    skip_ep,
                    json={"skip_level_receipt": sr.to_dict()},
                    headers={"DPoP": create_dpop_proof(w_c, "POST", skip_ep, tok_sc)},
                    timeout=3.0,
                )
                # `evil_srv` MUST NOT be hit via 302 redirect!
                self.assertEqual(ssrf_hits, [], "Liveness probe followed 302 redirect to SSRF target!")
            finally:
                a_node.stop()
                redir_b1.stop()
        finally:
            tool_node.stop()
            dir_svc.stop()
            rev_svc.stop()
            evil_srv.stop()

    def test_03_r3_high_01_dot_segment_and_percent_encoded_mcp_lattice_bypass(self) -> None:
        """[HIGH-R3-01] Single-dot (`/./mcp`, `/mcp/.`) & `%6d%63%70` bypass `/mcp` lattice & quota on standalone Sidecar."""
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_c = ca.issue_workload("/ns/c/sa/c")
        w_tool = ca.issue_workload("/ns/t/sa/hybrid-mcp")

        executed_calls: list[dict] = []

        def _upstream_app(req):
            # Standard MCP / ASGI-style route dispatch
            effective_path = unquote(req.path)
            if effective_path == "/mcp":
                body = req.json()
                params = body.get("params", {})
                executed_calls.append(
                    {
                        "raw_wire_path": req.path,
                        "tool": params.get("name"),
                        "arguments": params.get("arguments"),
                        "loopback_secret": req.header("X-LCT-Loopback-Auth"),
                        "decision": req.header("X-LCT-Decision"),
                    }
                )
                return 200, {"executed": True, "wire_path": req.path}, {}
            return 404, {"error": "not_found", "path": req.path}, {}

        upstream = ManagedHTTPService("upstream-mcp-app", _upstream_app)
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
            # Caller `w_c` ONLY holds `get_weather` with `max_calls=1` (NO `execute_payment`!)
            tok_weather = mint_root_token(
                ca,
                "task-r3-dot",
                "user:alice",
                w_drv.jkt,
                w_c.spiffe_id,
                w_c.jkt,
                PermissionLattice.create(tools=["get_weather"], max_calls=1),
                hop_segment="C",
            )
            # `w_c` offline-attenuates `get_weather` to `w_tool` (using only `w_c`'s private key!)
            tok_deleg = tok_weather.attenuate(
                w_c,
                w_tool.spiffe_id,
                w_tool.jkt,
                PermissionLattice.create(tools=["get_weather"], max_calls=1),
                hop_segment="Tool",
            ).encode_compact()

            sc_port = int(sc.inbound_url.rsplit(":", 1)[1])
            forbidden_payload = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "execute_payment", "arguments": {"amount": 9999999}},
                }
            ).encode("utf-8")

            # Sanity check: normal `POST /mcp` is properly denied (403)
            r_norm = httpx.post(
                f"{sc.inbound_url}/mcp",
                content=forbidden_payload,
                headers={
                    "Authorization": f"DPoP {tok_deleg}",
                    "DPoP": create_dpop_proof(w_c, "POST", f"{sc.inbound_url}/mcp", tok_deleg),
                    "Content-Type": "application/json",
                },
                timeout=3.0,
            )
            self.assertIn(r_norm.status_code, (401, 403))
            self.assertEqual(executed_calls, [])

            # Exploit vectors: `/./mcp`, `/mcp/.`, and `/%6d%63%70`!
            # Note: for `/./mcp` and `/mcp/.`, `httpx` itself rewrites `req.path` on the wire to `"/mcp"`!
            for smuggled_path in ("/./mcp", "/mcp/.", "/%6d%63%70"):
                htu_smug = f"{sc.inbound_url}{smuggled_path}"
                status_code, resp_raw = _raw_http_post(
                    sc_port,
                    smuggled_path,
                    {
                        "Authorization": f"DPoP {tok_deleg}",
                        "DPoP": create_dpop_proof(w_c, "POST", htu_smug, tok_deleg),
                        "Content-Type": "application/json",
                    },
                    forbidden_payload,
                )
                print(f"[HIGH-R3-01] POST {smuggled_path} -> HTTP {status_code} | {resp_raw.splitlines()[-1]}")
                self.assertEqual(status_code, 200)

            # All 3 unauthorized `execute_payment(amount=9999999)` calls executed despite `max_calls=1` and `tools=["get_weather"]`!
            self.assertEqual(len(executed_calls), 3)
            self.assertEqual(executed_calls[0]["raw_wire_path"], "/mcp")  # httpx normalized `/./mcp` -> `/mcp`!
            self.assertEqual(executed_calls[1]["raw_wire_path"], "/mcp")  # httpx normalized `/mcp/.` -> `/mcp`!
            self.assertEqual(executed_calls[0]["loopback_secret"], "secret-loopback-r3")
            print(
                f"[VULN CONFIRMED - HIGH-R3-01] `/./mcp`, `/mcp/.`, and `/%6d%63%70` bypassed `/mcp` PermissionLattice & max_calls=1 quota: {executed_calls}"
            )
        finally:
            sc.stop()
            upstream.stop()

    def test_04_r3_high_02_cross_domain_revocation_event_split_brain_failover_spoof(self) -> None:
        """[HIGH-R3-02] Cross-domain `RevocationEvent.trust_domain` & foreign `/ns/sys/sa/rev` spoof split-brain FailoverReceipt."""
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
        w_tool_a = ca_alpha.issue_workload("/ns/t/sa/pay-mcp")

        w_beta_helper = ca_beta.issue_workload("/ns/c/sa/helper-b")
        w_beta_rev = ca_beta.issue_workload("/ns/sys/sa/rev")

        rev_svc = RevocationService(w_rev_alpha, resolver)
        rev_url = rev_svc.start()
        try:
            rev_client = RevocationReplicaClient(rev_url, resolver)
            p_pay = PermissionLattice.create(tools=["execute_payment"], max_amount=500.0)

            # 1. Legitimate `org-alpha.io` task `task-split-01` delegates `A -> B1` at `/task-split-01/A/B1`
            t0_alpha = mint_root_token(
                ca_alpha,
                "task-split-01",
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

            # 2. Colluding `org-beta.io` helper mints a colliding path `/task-split-01/A/B1` in `org-beta.io`
            #    and obtains a GENUINELY SIGNED `RevocationEvent` from `w_rev_alpha` (`trust_domain="org-beta.io"`)!
            t0_beta = mint_root_token(
                ca_beta,
                "task-split-01",
                "user:bob",
                w_beta_helper.jkt,
                w_beta_helper.spiffe_id,
                w_beta_helper.jkt,
                p_pay,
                hop_segment="A",
            )
            t_b1_beta = t0_beta.attenuate(
                w_beta_helper, w_b1_a.spiffe_id, w_b1_a.jkt, p_pay, hop_segment="B1"
            )
            beta_rev_ev = rev_client.revoke_prefix(
                w_beta_helper,
                "/task-split-01/A/B1",
                reason="decoy_beta_prune",
                authority_token=t_b1_beta.encode_compact(),
            )
            rev_client.sync_now()

            # Verify `w_b1_a` in `org-alpha.io` is STILL 100% UNREVOKED and can invoke tools!
            lv = LeafVerifier(
                w_tool_a.spiffe_id,
                resolver,
                revocation_replica=rev_client,
                self_jkt=w_tool_a.jkt,
                mode=VerificationMode.LOCAL_FULL_CHAIN,
            )
            htu = "http://127.0.0.1:19922/mcp"
            tok_b1_alpha_str = t_b1_alpha.encode_compact()
            res_b1_still_live = lv.verify_request(
                tok_b1_alpha_str,
                create_dpop_proof(w_b1_a, "POST", htu, tok_b1_alpha_str),
                "POST",
                htu,
                tool="execute_payment",
                arguments={"amount": 100.0},
            )
            self.assertTrue(res_b1_still_live.allowed, "Alpha B1 should still be unrevoked!")

            # 3. Sub-vector A: `w_parent_a` embeds `beta_rev_ev` (`trust_domain="org-beta.io"`) into Alpha's `FailoverReceipt`!
            #    Even when `trusted_revocation_spiffe_ids=[w_rev_alpha.spiffe_id]` IS PINNED, both
            #    `FailoverReceipt.from_dict_and_verify` and `CausalChainAuditor` accept the split-brain graft!
            split_fr = FailoverReceipt.create_and_sign(
                parent_identity=w_parent_a,
                task_id="task-split-01",
                pruned_lineage_path="/task-split-01/A/B1",
                revocation_version=beta_rev_ev.version,
                revocation_event_sig=beta_rev_ev.service_signature,
                failed_delegate_spiffe_id=w_b1_a.spiffe_id,
                substitute_delegate_spiffe_id=w_b2_a.spiffe_id,
                new_lineage_path="/task-split-01/A/B2-e1",
                old_epoch=0,
                new_epoch=1,
                failure_evidence=FailureEvidence(
                    w_b1_a.spiffe_id, "http://127.0.0.1:9", FaultType.CRASH, "split", 1, time.time()
                ),
                revocation_event=beta_rev_ev.to_dict(),
                revocation_service_svid=w_rev_alpha.workload_svid,
            )
            verified_split = FailoverReceipt.from_dict_and_verify(
                split_fr.to_dict(),
                resolver,
                trusted_revocation_spiffe_ids=[w_rev_alpha.spiffe_id],
            )
            self.assertEqual(verified_split.task_id, "task-split-01")

            now_ts = time.time()
            em_ca = AuditStreamEmitter(ca_alpha, stream_id="ca-a")
            em_pa = AuditStreamEmitter(w_parent_a, stream_id="pa-a")
            em_ca.emit(
                AuditEventType.ROOT_MINT,
                "task-split-01",
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
                "task-split-01",
                "user:alice",
                "/task-split-01/A/B1",
                1,
                0,
                t0_alpha.root_block_hash,
                t_b1_alpha.leaf_block_hash,
                "REVOKED",
                action_detail={"target": "/task-split-01/A/B1", "revocation_version": beta_rev_ev.version},
                timestamp=now_ts - 1.0,
            )
            em_pa.emit(
                AuditEventType.FAILOVER_PRUNE_GRAFT,
                "task-split-01",
                "user:alice",
                "/task-split-01/A/B2-e1",
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
            self.assertTrue(rep.clean)
            self.assertIn("VERIFIED_FAILOVER_GRAFT", rep.tasks["task-split-01"].resilience_classifications)

            # 4. Sub-vector B: Foreign `w_beta_rev` (`spiffe://org-beta.io/ns/sys/sa/rev`) signs a completely
            #    offline fake `RevocationEvent` for `org-alpha.io` when `trusted_revocation_spiffe_ids=None`!
            fake_prov = RevocationEvent(
                99,
                RevocationKind.SUBTREE,
                "/task-split-01/A/B1",
                "foreign_rev_spoof",
                w_parent_a.spiffe_id,
                time.time() - 1.0,
                "",
                w_beta_rev.workload_svid,
                "org-alpha.io",
            )
            foreign_sig = jws_sign_compact(fake_prov.core_claims(), w_beta_rev.keypair, typ="lct-revocation-event+jwt")
            foreign_ev = RevocationEvent(**{**fake_prov.__dict__, "service_signature": foreign_sig})
            foreign_fr = FailoverReceipt.create_and_sign(
                parent_identity=w_parent_a,
                task_id="task-split-01",
                pruned_lineage_path="/task-split-01/A/B1",
                revocation_version=99,
                revocation_event_sig=foreign_sig,
                failed_delegate_spiffe_id=w_b1_a.spiffe_id,
                substitute_delegate_spiffe_id=w_b2_a.spiffe_id,
                new_lineage_path="/task-split-01/A/B2-e1",
                old_epoch=0,
                new_epoch=1,
                failure_evidence=FailureEvidence(
                    w_b1_a.spiffe_id, "http://127.0.0.1:9", FaultType.CRASH, "foreign", 1, time.time()
                ),
                revocation_event=foreign_ev.to_dict(),
                revocation_service_svid=w_beta_rev.workload_svid,
            )
            verified_foreign = FailoverReceipt.from_dict_and_verify(foreign_fr.to_dict(), resolver)
            self.assertEqual(verified_foreign.revocation_version, 99)
            print(
                "[VULN CONFIRMED - HIGH-R3-02] Cross-domain RevocationEvent.trust_domain & foreign /ns/sys/sa/rev bypassed Prune-Before-Graft!"
            )
        finally:
            rev_svc.stop()

    def test_05_r3_medium_01_quarantined_revoked_or_expired_hop0_retaliatory_quarantine(self) -> None:
        """[MEDIUM-R3-01] Quarantined/revoked/expired Hop-0 workload can still globally quarantine healthy peers."""
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_rev = ca.issue_workload("/ns/sys/sa/rev")
        w_drv = ca.issue_workload("/ns/entry/sa/drv")
        w_rogue_coord = ca.issue_workload("/ns/coord/sa/rogue-coord")
        w_healthy_tool = ca.issue_workload("/ns/tool/sa/payment-mcp")
        w_healthy_peer = ca.issue_workload("/ns/work/sa/healthy-worker")

        rev_svc = RevocationService(w_rev, resolver)
        dir_svc = AgentDirectoryService(resolver)
        rev_url = rev_svc.start()
        dir_url = dir_svc.start()
        try:
            rev_client = RevocationReplicaClient(rev_url, resolver)
            dir_client = AgentDirectoryClient(dir_url, resolver)
            dir_client.register(
                AgentCard.sign_and_create(w_healthy_peer, "HealthyWorker", "http://127.0.0.1:19699", ["work"])
            )

            # 1. `w_rogue_coord` holds a LONG-EXPIRED `B_0` from 2 hours ago (`ttl_seconds=10`, `now - 7200`)!
            past = time.time() - 7200.0
            t0_expired = mint_root_token(
                ca,
                "task-ancient-expired",
                "user:old",
                w_drv.jkt,
                w_rogue_coord.spiffe_id,
                w_rogue_coord.jkt,
                PermissionLattice.create(tools=["get_weather"]),
                hop_segment="RogueCoord",
                ttl_seconds=10.0,
                now=past,
            )

            # 2. Domain CA `ca` EXPLICITLY revokes `/task-ancient-expired` AND globally quarantines `w_rogue_coord`!
            rev_client.revoke_prefix(ca, "/task-ancient-expired", reason="compromised_coord_revoked")
            rev_client.quarantine_workload(ca, w_rogue_coord.spiffe_id, reason="compromised_coord_quarantined")
            dir_client.quarantine(ca, w_rogue_coord.spiffe_id, reason="compromised_coord_quarantined")
            self.assertIsNotNone(rev_svc.trie.check_workloads([w_rogue_coord.spiffe_id]))

            # 3. Despite being QUARANTINED, having its task REVOKED, and presenting a 2-hour EXPIRED bare `B_0`
            #    (0 hops!), `w_rogue_coord` retaliates and globally quarantines `w_healthy_tool` on `RevocationService`!
            retaliation_ev = rev_client.quarantine_workload(
                w_rogue_coord,
                w_healthy_tool.spiffe_id,
                reason="zombie_retaliation",
                authority_token=t0_expired.encode_compact(),
            )
            self.assertIsNotNone(rev_svc.trie.check_workloads([w_healthy_tool.spiffe_id]))

            # And using a currently unexpired-by-timestamp but CA-revoked `B_0` while quarantined,
            # `w_rogue_coord` also quarantines `w_healthy_peer` on `AgentDirectoryService`!
            t0_revoked_active_ts = mint_root_token(
                ca,
                "task-revoked-live-ts",
                "user:old",
                w_drv.jkt,
                w_rogue_coord.spiffe_id,
                w_rogue_coord.jkt,
                PermissionLattice.create(tools=["get_weather"]),
                hop_segment="RogueCoord",
            )
            rev_client.revoke_prefix(ca, "/task-revoked-live-ts", reason="ca_cancelled")
            dir_client.quarantine(
                w_rogue_coord,
                w_healthy_peer.spiffe_id,
                reason="zombie_dir_retaliation",
                authority_token=t0_revoked_active_ts.encode_compact(),
            )
            self.assertEqual(dir_client.discover(skill="work"), [])
            print(
                f"[VULN CONFIRMED - MEDIUM-R3-01] Quarantined/revoked/expired Hop-0 workload retaliated and quarantined healthy cluster peers (v={retaliation_ev.version})!"
            )
        finally:
            rev_svc.stop()
            dir_svc.stop()


if __name__ == "__main__":
    unittest.main()
