"""Milestone 6 Final Independent QA Sign-Off Suite (`k8s-qa-reviewer`).

Verifies all 7 remediations (`[HIGH-M6-01]`, `[HIGH-M6-02]`, `[MEDIUM-M6-01..03]`,
`[LOW-M6-01..02]`), the `bootstrap_services.py` AgentCard TTL / stale-SVID keeper
hardening, the live rehearsal evidence bundle (`20261123T183128Z-multihost-rehearsal`),
documentation alignment (`ARCHITECTURE.md` & `MULTIHOST_GUIDE.md`), and strict
zero-secret / zero-token workspace hygiene.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import re
import subprocess
import time
from typing import Any, Callable, Dict, List, Tuple
import unittest
from unittest import mock

import httpx
import yaml

from lineage.a2a import A2AClient, A2AInvocationContext, A2AServerEngine, Artifact, Message, TaskState
from lineage.a2a.rpc import A2ARPCExecutionError
from lineage.audit import (
    AuditCollectorClient,
    AuditCollectorService,
    AuditEventType,
    AuditIngestError,
    AuditStreamEmitter,
    CausalChainAuditor,
)
from lineage.common.crypto import KeyPair, jws_sign_compact
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.common.mtls import WorkloadMTLSBundle, X509DomainAuthority, X509FederationTrustStore
from lineage.federation import (
    FederationBundleSyncer,
    FederationSecurityError,
    TrustAnchorPinError,
    TrustAnchorPinStore,
    compute_bundle_trust_anchor,
)
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.multihost import (
    FORBIDDEN_HOST_PORTS,
    ROLE_ORDER,
    render_kind_cluster_config,
    render_role_k8s_manifests,
)
from lineage.multihost.config_gen import render_e2e_sync_service_manifest
from lineage.multihost.lct_multihost_cli import main as cli_main, stream_and_summarize_a2a_sse
from lineage.protocol import PermissionLattice, mint_root_token
from lineage.registry import AgentCard
from lineage.revocation import RevocationError, RevocationReplicaClient, RevocationService

REPO_ROOT = Path("/Users/hulalala/Desktop/A")
LINEAGE_ROOT = REPO_ROOT / "lineage"
REHEARSAL_R2 = LINEAGE_ROOT / "k8s" / "runs" / "20261123T183128Z-multihost-rehearsal"


class Milestone6FinalQASignOffTests(unittest.TestCase):
    # -------------------------------------------------------------------------
    # 1. [HIGH-M6-01] Spoof Resilience, Local-Pin Eviction, & Single-Root Rules
    # -------------------------------------------------------------------------
    def test_01_high_m6_01_spoof_resilience_local_pin_eviction_and_canonical_root(
        self,
    ) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io", alg="ES256")
        x509_alpha = X509DomainAuthority("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io", alg="ES256")
        x509_beta = X509DomainAuthority("org-beta.io")
        ca_rogue = TrustDomainCA("org-beta.io", alg="ES256")
        x509_rogue = X509DomainAuthority("org-beta.io")

        genuine_bundle: Dict[str, Any] = ca_beta.export_public_bundle()
        genuine_bundle["x509_root_pem"] = x509_beta.export_root_pem()
        genuine_pin = compute_bundle_trust_anchor(genuine_bundle)

        extra_key_bundle = dict(genuine_bundle)
        extra_key_bundle["keys"] = [
            *genuine_bundle["keys"],
            ca_rogue.active_keypair.public_jwk(include_kid=True),
        ]
        dup_key_bundle = dict(genuine_bundle)
        dup_key_bundle["keys"] = [genuine_bundle["keys"][0], genuine_bundle["keys"][0]]

        # Extra JWKS keys or duplicate JWKS keys MUST produce a different digest!
        self.assertNotEqual(compute_bundle_trust_anchor(extra_key_bundle), genuine_pin)
        self.assertNotEqual(compute_bundle_trust_anchor(dup_key_bundle), genuine_pin)

        # Multi-root lists, empty root lists, and mismatched x509_root_pem vs x509_roots_pem MUST fail closed!
        for bad_bundle in (
            {**genuine_bundle, "x509_roots_pem": []},
            {
                **genuine_bundle,
                "x509_roots_pem": [x509_beta.export_root_pem(), x509_rogue.export_root_pem()],
            },
            {**genuine_bundle, "x509_roots_pem": [x509_rogue.export_root_pem()]},
        ):
            with self.assertRaises(TrustAnchorPinError):
                compute_bundle_trust_anchor(bad_bundle)

        state = {"payload": genuine_bundle}
        peer_srv = ManagedHTTPService(
            "qa-beta-bundle-srv",
            lambda r: (200, state["payload"], {}) if r.path == "/v1/federation/bundle" else (404, {}, {}),
            host="127.0.0.1",
            port=0,
        )
        peer_url = peer_srv.start()

        # Stand up real mTLS 1.3 Beta endpoint to verify active traffic survives LAN spoofing
        kp_b = KeyPair.generate("ES256")
        leaf_b = x509_beta.issue_x509_svid(
            "spiffe://org-beta.io/ns/lineage-beta/sa/flight-specialist",
            kp_b.public_jwk(),
            dns_names=("localhost",),
        )
        store_b = X509FederationTrustStore()
        store_b.register_domain_root_pem("org-alpha.io", x509_alpha.export_root_pem())
        store_b.register_domain_root_pem("org-beta.io", x509_beta.export_root_pem())
        mtls_b = WorkloadMTLSBundle(
            "spiffe://org-beta.io/ns/lineage-beta/sa/flight-specialist", kp_b, leaf_b, store_b
        )
        beta_https_srv = ManagedHTTPService(
            "qa-beta-mtls",
            lambda r: (200, {"peer": r.peer_spiffe_id}, {}),
            host="127.0.0.1",
            port=0,
            ssl_context_provider=mtls_b.server_ssl_context_provider(require_client_cert=True),
            peer_cert_verifier=store_b.verify_peer_der_cert,
        )
        beta_https_srv.start()
        beta_https_url = f"https://localhost:{beta_https_srv.port}"

        pins = TrustAnchorPinStore(initial_pins={"org-beta.io": genuine_pin})
        syncer = FederationBundleSyncer(
            peer_ca_urls={"org-beta.io": peer_url},
            anchor_store=pins,
            require_pinned_anchors=True,
        )
        syncer.x509_trust_store.register_domain_root_pem("org-alpha.io", x509_alpha.export_root_pem())
        kp_a = KeyPair.generate("ES256")
        leaf_a = x509_alpha.issue_x509_svid(
            "spiffe://org-alpha.io/ns/lineage-alpha/sa/orchestrator-alpha",
            kp_a.public_jwk(),
            dns_names=("localhost",),
        )
        mtls_a = WorkloadMTLSBundle(
            "spiffe://org-alpha.io/ns/lineage-alpha/sa/orchestrator-alpha",
            kp_a,
            leaf_a,
            syncer.x509_trust_store,
        )
        try:
            syncer.sync_all(require_all=True, max_wait_sec=2.0)
            self.assertTrue(syncer.is_ready()[0])

            spoof_candidates: List[Any] = [
                {**ca_rogue.export_public_bundle(), "x509_root_pem": x509_rogue.export_root_pem()},
                {**genuine_bundle, "trust_domain": "org-attacker.io"},
                extra_key_bundle,
                dup_key_bundle,
                {**genuine_bundle, "x509_root_pem": "-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"},
                {
                    **genuine_bundle,
                    "x509_roots_pem": [x509_beta.export_root_pem(), x509_rogue.export_root_pem()],
                },
                ["not-a-json-object"],
            ]
            for idx, spoof_obj in enumerate(spoof_candidates, start=1):
                state["payload"] = spoof_obj
                syncer.sync_all(require_all=False, max_wait_sec=0.15)
                ready_ok, diag = syncer.is_ready()
                self.assertTrue(ready_ok, f"Spoof payload #{idx} wrongly evicted verified peer!")
                self.assertIn("org-beta.io", syncer.trust_resolver.trusted_domains())
                self.assertTrue(syncer.x509_trust_store.has_domain("org-beta.io"))
                self.assertEqual(diag["rejected_bundle_counts"].get("org-beta.io"), idx)

                with httpx.Client(
                    verify=mtls_a.verify_for_target(
                        target_url=beta_https_url, expected_trust_domain="org-beta.io"
                    ),
                    timeout=3.0,
                    trust_env=False,
                ) as cli:
                    r_ok = cli.get(f"{beta_https_url}/healthz")
                    self.assertEqual(r_ok.status_code, 200)

            # Altering the LOCAL pin evicts immediately!
            pins.set_pin("org-beta.io", f"sha256:{'1' * 64}:{'2' * 64}")
            self.assertTrue(syncer.reconcile_anchor_evictions())
            self.assertFalse(syncer.is_ready()[0])
            self.assertNotIn("org-beta.io", syncer.trust_resolver.trusted_domains())
            self.assertFalse(syncer.x509_trust_store.has_domain("org-beta.io"))

            # Restoring genuine bundle + pin re-verifies, and removing local pin evicts immediately!
            state["payload"] = genuine_bundle
            pins.set_pin("org-beta.io", genuine_pin)
            syncer.sync_all(require_all=True, max_wait_sec=2.0)
            self.assertTrue(syncer.is_ready()[0])

            pins.remove_pin("org-beta.io")
            self.assertTrue(syncer.reconcile_anchor_evictions())
            self.assertFalse(syncer.is_ready()[0])
            self.assertFalse(syncer.x509_trust_store.has_domain("org-beta.io"))
        finally:
            mtls_a.cleanup()
            mtls_b.cleanup()
            beta_https_srv.stop()
            peer_srv.stop()

    # -------------------------------------------------------------------------
    # 2. [HIGH-M6-02] Audit Bounds/Capacity Integrity & Revocation JKT Replay
    # -------------------------------------------------------------------------
    def test_02_high_m6_02_audit_safe_capacity_and_revocation_jkt_replay_guard(
        self,
    ) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io", alg="ES256")
        ca_pay = TrustDomainCA("org-payment.io", alg="ES256")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_pay)

        now = time.time()
        expired_id = ca_alpha.issue_workload(
            "/ns/lineage-alpha/sa/orchestrator-alpha",
            ttl_seconds=60.0,
            now=now - 7200.0,
        )
        orch_id = ca_alpha.issue_workload(
            "/ns/lineage-alpha/sa/orchestrator-alpha", ttl_seconds=1800.0
        )

        # Start real HTTP AuditCollectorService with tight max_entries=2 to verify fail-closed chain integrity
        collector = AuditCollectorService(
            trust_resolver=resolver,
            host="127.0.0.1",
            port=0,
            max_ingest_age_seconds=3600.0,
            max_future_skew_seconds=30.0,
            max_entries=2,
            max_streams=2,
        )
        col_url = collector.start()
        try:
            # 1. Back-dated (>1h) and future-dated (>30s) entries rejected
            em_expired = AuditStreamEmitter(signer=expired_id, stream_id="s-expired")
            with mock.patch("lineage.audit.logger.time.time", return_value=now - 7190.0):
                e_old = em_expired.emit(
                    AuditEventType.INBOUND_AUTHZ, "t-old", "user:a", "/t-old/O", 0, 0, "r", "c", "ALLOW"
                )
            with self.assertRaises(AuditIngestError):
                collector.append_direct(e_old)

            em_fut = AuditStreamEmitter(signer=orch_id, stream_id="s-fut")
            with mock.patch("lineage.audit.logger.time.time", return_value=now + 120.0):
                e_fut = em_fut.emit(
                    AuditEventType.INBOUND_AUTHZ, "t-fut", "user:a", "/t-fut/O", 0, 0, "r", "c", "ALLOW"
                )
            with self.assertRaises(AuditIngestError):
                collector.append_direct(e_fut)

            # 2. Emit a valid 2-entry task chain + 3rd overflow entry via best-effort AuditStreamEmitter
            tok = mint_root_token(
                ca_alpha,
                task_id="task-cap-safe",
                sub="user:alice@org-alpha.io",
                sender_jkt=orch_id.jkt,
                first_hop_spiffe_id=orch_id.spiffe_id,
                first_hop_jkt=orch_id.jkt,
                permissions=PermissionLattice.create(tools=["noop"], max_calls=2),
            )
            ca_emitter = AuditStreamEmitter(
                signer=ca_alpha,
                collector_client=AuditCollectorClient(col_url),
                stream_id="ca-stream",
            )
            orch_emitter = AuditStreamEmitter(
                signer=orch_id,
                collector_client=AuditCollectorClient(col_url),
                stream_id="orch-stream",
                best_effort_remote=True,
            )
            try:
                ca_emitter.emit(
                    AuditEventType.ROOT_MINT,
                    "task-cap-safe",
                    "user:alice@org-alpha.io",
                    "/task-cap-safe/OrchestratorAlpha",
                    0,
                    0,
                    tok.root_block_hash,
                    tok.leaf_block_hash,
                    "ALLOW",
                )
                orch_emitter.emit(
                    AuditEventType.INBOUND_AUTHZ,
                    "task-cap-safe",
                    "user:alice@org-alpha.io",
                    "/task-cap-safe/OrchestratorAlpha",
                    0,
                    0,
                    tok.root_block_hash,
                    tok.leaf_block_hash,
                    "ALLOW",
                    parent_block_hash=tok.root_block_hash,
                )
                self.assertEqual(len(collector.get_all_entries()), 2)

                # 3rd entry hits max_entries=2: collector rejects (403) WITHOUT dropping seq 0,
                # and emitter retains the unshipped entry in `_pending_remote`!
                orch_emitter.emit(
                    AuditEventType.TOOL_INVOCATION,
                    "task-cap-safe",
                    "user:alice@org-alpha.io",
                    "/task-cap-safe/OrchestratorAlpha",
                    0,
                    0,
                    tok.root_block_hash,
                    tok.leaf_block_hash,
                    "ALLOW",
                    parent_block_hash=tok.root_block_hash,
                    action_detail={"tool": "noop"},
                )
                self.assertEqual(len(collector.get_all_entries()), 2)
                self.assertEqual(len(orch_emitter._pending_remote), 1)

                # CausalChainAuditor verifies existing 2 entries have 100% intact hash-chain integrity!
                auditor = CausalChainAuditor(resolver)
                rep = auditor.audit(collector.get_all_entries())
                self.assertTrue(rep.stream_integrity_ok)
                self.assertTrue(rep.clean)
                self.assertTrue(rep.tasks["task-cap-safe"].reconstructed_complete)
            finally:
                orch_emitter.stop()
        finally:
            collector.stop()

        # 3. Revocation `(trust_domain, origin_instance_jkt, orig_ver)` replay & equivocation checks
        rev_a1 = ca_alpha.issue_workload("/ns/sys/sa/revocation", ttl_seconds=600.0)
        rev_a2 = ca_alpha.issue_workload("/ns/sys/sa/revocation", ttl_seconds=600.0)
        non_rev = ca_alpha.issue_workload("/ns/lineage-alpha/sa/rogue-pod", ttl_seconds=600.0)
        rev_pay = ca_pay.issue_workload("/ns/sys/sa/revocation", ttl_seconds=600.0)

        svc_a1 = RevocationService(rev_a1, resolver, host="127.0.0.1", port=0)
        ev1 = svc_a1.revoke_prefix_direct("/task-1/O", requested_by="ca", trust_domain="org-alpha.io")
        svc_a2 = RevocationService(rev_a2, resolver, host="127.0.0.1", port=0)
        ev_r1 = svc_a2.revoke_prefix_direct("/task-r1/O", requested_by="ca", trust_domain="org-alpha.io")

        fed_box: Dict[str, Any] = {
            "svid": rev_a1.workload_svid,
            "version": 1,
            "events": [ev1.to_dict()],
        }
        peer_fed = ManagedHTTPService(
            "qa-rev-peer",
            lambda req: (
                200,
                {
                    "trust_domain": "org-alpha.io",
                    "version": fed_box["version"],
                    "service_svid": fed_box["svid"],
                    "events": [
                        e
                        for e in fed_box["events"]
                        if int(e["version"]) > int(req.query.get("since_version", 0))
                    ],
                },
                {},
            ),
            host="127.0.0.1",
            port=0,
        )
        peer_fed_url = peer_fed.start()
        pay_svc = RevocationService(
            rev_pay,
            resolver,
            strict_domain_isolation=True,
            peer_revocation_urls={"org-alpha.io": peer_fed_url},
            host="127.0.0.1",
            port=0,
        )
        try:
            self.assertEqual(pay_svc.sync_from_federation_peers(["org-alpha.io"]), 1)
            self.assertEqual(pay_svc.trie.version, 1)

            # Non-revocation workload JKT attempting to forge an event -> REJECTED!
            forged_claims = ev1.core_claims()
            forged_sig = jws_sign_compact(forged_claims, non_rev.keypair, typ="lct-revocation-event+jwt")
            with self.assertRaises(RevocationError):
                pay_svc.ingest_federated_event(
                    {**forged_claims, "service_signature": forged_sig, "service_svid": non_rev.workload_svid},
                    expected_peer_domain="org-alpha.io",
                )

            # Peer restarts (`rev_a2`) and replays old `(rev_a1, v1)` + new `(rev_a2, v2)`:
            # `ev1` is deduplicated (no duplicate trie entry), while `ev_r2` is imported cleanly!
            ev_r2 = svc_a2.revoke_prefix_direct("/task-r2/O", requested_by="ca", trust_domain="org-alpha.io")
            fed_box["svid"] = rev_a2.workload_svid
            fed_box["version"] = 2
            fed_box["events"] = [ev1.to_dict(), ev_r2.to_dict()]
            pay_svc.sync_from_federation_peers(["org-alpha.io"])
            # Trie version advanced by ONLY 1 (`ev_r2`), NOT 2 (`ev1` was idempotently deduplicated)!
            self.assertEqual(pay_svc.trie.version, 2)
            self.assertIsNotNone(pay_svc.trie.check_lineage_path("/task-1/O", trust_domain="org-alpha.io"))
            self.assertIsNotNone(pay_svc.trie.check_lineage_path("/task-r2/O", trust_domain="org-alpha.io"))

            # Replaying a tampered event at `(rev_a1, v1)` even after restart -> Equivocation REJECTED!
            tampered_v1 = {**ev1.core_claims(), "target": "/task-tampered/O"}
            tampered_sig = jws_sign_compact(tampered_v1, rev_a1.keypair, typ="lct-revocation-event+jwt")
            with self.assertRaises(RevocationError):
                pay_svc.ingest_federated_event(
                    {**tampered_v1, "service_signature": tampered_sig, "service_svid": rev_a1.workload_svid},
                    expected_peer_domain="org-alpha.io",
                )
            _ = ev_r1
        finally:
            pay_svc.stop()
            peer_fed.stop()

    # -------------------------------------------------------------------------
    # 3. [MEDIUM-M6-01..03], [LOW-M6-01..02], & `bootstrap_services.py` Review
    # -------------------------------------------------------------------------
    def test_03_medium_low_fixes_and_bootstrap_card_ttl_hardening(self) -> None:
        # [MEDIUM-M6-01]: No permanent 30990 NodePort Service in alpha manifest; transient helper works
        alpha_docs = list(yaml.safe_load_all(render_role_k8s_manifests("alpha")))
        self.assertNotIn(
            "e2e-user-gateway-sync",
            {d["metadata"]["name"] for d in alpha_docs if d["kind"] == "Service"},
        )
        sync_svc = render_e2e_sync_service_manifest("lineage-alpha")
        self.assertEqual(sync_svc["spec"]["ports"][0]["nodePort"], 30990)

        e2e_src = (LINEAGE_ROOT / "k8s" / "e2e_driver.py").read_text(encoding="utf-8")
        self.assertIn("X-LCT-Sync-Token", e2e_src)
        self.assertIn("hmac.compare_digest(provided_tok, sync_token)", e2e_src)

        # [MEDIUM-M6-02]: `MULTIHOST_GUIDE.md` runbook uses `trust add` / `trust fetch --expect` (never `--yes`)
        guide_txt = (LINEAGE_ROOT / "multihost" / "MULTIHOST_GUIDE.md").read_text(encoding="utf-8")
        self.assertIn("trust add", guide_txt)
        self.assertIn("trust fetch \\\n  --domain org-beta.io \\\n  --ip 192.168.1.12 \\\n  --expect", guide_txt)
        self.assertNotIn("trust fetch --domain", guide_txt)

        # [MEDIUM-M6-03]: SSE terminal state enforcement
        def _work(
            _ctx: A2AInvocationContext, msg: Message, emit: Callable[[Artifact], None]
        ) -> Tuple[Message, Dict[str, Any]]:
            if "BOOM" in msg.extract_text():
                raise A2ARPCExecutionError(-32005, "boom")
            emit(Artifact.create(name="art-1", description="ok", data={"k": 1}))
            return Message.create_agent(text="done"), {}

        eng = A2AServerEngine(agent_name="qa-sse", work_handler=_work)
        srv = ManagedHTTPService(
            "qa-sse-http",
            lambda r: eng.dispatch(
                HTTPRequestContext(
                    method=r.method,
                    raw_path=r.raw_path,
                    headers={
                        **dict(r.headers),
                        "x-lct-request-id": "r1",
                        "x-lct-task-id": "t1",
                        "x-lct-sub": "user:alice@org-alpha.io",
                        "x-lct-lineage-path": "/t1/O",
                    },
                    body=r.body,
                    server_host=r.server_host,
                    server_port=r.server_port,
                )
            ),
            host="127.0.0.1",
            port=0,
        )
        u = srv.start()
        try:
            cli = A2AClient(agent_base_url=u, rpc_path="/a2a", timeout=5.0)
            rc_ok, sum_ok = stream_and_summarize_a2a_sse(
                cli, Message.create_user(text="hi", task_id="t1"), event_sink=io.StringIO()
            )
            self.assertEqual(rc_ok, 0)
            self.assertEqual(sum_ok["terminal_state"], TaskState.COMPLETED.value)
            self.assertEqual(sum_ok["artifact_names"], ["art-1"])

            rc_err, sum_err = stream_and_summarize_a2a_sse(
                cli, Message.create_user(text="BOOM", task_id="t2"), event_sink=io.StringIO()
            )
            self.assertEqual(rc_err, 1)
            self.assertEqual(sum_err["terminal_state"], TaskState.FAILED.value)
        finally:
            srv.stop()

        # [LOW-M6-01] & [LOW-M6-02] + `bootstrap_services.py` unrequested hardening check
        arch_txt = (LINEAGE_ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
        self.assertIn("defaultMode: 0440", arch_txt)
        self.assertIn("fsGroup: 2000", arch_txt)
        self.assertNotIn("`0400`", arch_txt)

        preflight_txt = (LINEAGE_ROOT / "multihost" / "preflight.sh").read_text(encoding="utf-8")
        self.assertIn("httpx.Client(timeout=4.0, trust_env=False)", preflight_txt)

        bad_fault = subprocess.run(
            ["bash", str(LINEAGE_ROOT / "multihost" / "fault.sh"), "--partition", "--role", "badrole"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(bad_fault.returncode, 2)

        boot_txt = (LINEAGE_ROOT / "k8s" / "bootstrap_services.py").read_text(encoding="utf-8")
        self.assertIn("min(float(svid_ttl), float(identity.expires_at - time.time()))", boot_txt)
        self.assertIn("existing.workload_svid != identity.workload_svid", boot_txt)

        # Verify AgentCard.sign_and_create strictly caps card.expires_at <= identity.expires_at
        ca = TrustDomainCA("org-alpha.io", alg="ES256")
        wl = ca.issue_workload("/ns/lineage-alpha/sa/orchestrator-alpha", ttl_seconds=30.0)
        card = AgentCard.sign_and_create(
            identity=wl,
            name="Orch",
            endpoint="https://orchestrator-alpha.org-alpha.io:30441",
            skills=["travel.orchestrate"],
            ttl_seconds=1800.0,
        )
        self.assertLessEqual(card.expires_at, wl.expires_at)

    # -------------------------------------------------------------------------
    # 4. Live Rehearsal `20261123T183128Z-multihost-rehearsal` & Secret Hygiene
    # -------------------------------------------------------------------------
    def test_04_rehearsal_evidence_and_secret_hygiene(self) -> None:
        self.assertTrue(REHEARSAL_R2.is_dir())
        summary = json.loads((REHEARSAL_R2 / "e2e_multihost_summary.json").read_text())
        self.assertEqual(summary["overall_status"], "PASS")
        self.assertEqual(set(summary["scenarios"].keys()), {"1", "2A", "2B", "3A", "3B", "4", "5", "6"})
        for k, v in summary["scenarios"].items():
            self.assertEqual(v["status"], "PASS", k)

        # 30990 closed outside Scenario 3B + deleted after Scenario 3B
        p30990_txt = (REHEARSAL_R2 / "02_port_30990_closed_outside_s3b.txt").read_text()
        self.assertIn('services "e2e-user-gateway-sync" not found', p30990_txt)
        e2e_log = (REHEARSAL_R2 / "06_e2e_console.log").read_text()
        self.assertIn("post-S3B get svc e2e-user-gateway-sync exit_code=1", e2e_log)

        # Wrong `--expect` leaves all 4 ConfigMaps empty (`{}`)
        expect_txt = (REHEARSAL_R2 / "03_trust_fetch_expect_good_and_bad.txt").read_text()
        self.assertIn("wrong --expect exit_code=1", expect_txt)
        self.assertIn('"lctmh-alpha": {}', expect_txt)

        # Live spoofed bundle rejected while staying 200 Ready
        spoof_txt = (REHEARSAL_R2 / "04_live_spoofed_bundle_stays_ready.txt").read_text()
        self.assertIn("orchestrator-alpha /readyz status= 200", spoof_txt)
        self.assertIn('"org-beta.io": 5', spoof_txt)

        # SSE states & final_event populated in `05_cli_send_stream.json`
        sse_json = json.loads((REHEARSAL_R2 / "05_cli_send_stream.json").read_text())
        self.assertEqual(
            sse_json["a2a_result"]["sse_states"],
            ["TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_COMPLETED"],
        )
        self.assertEqual(sse_json["a2a_result"]["terminal_state"], "TASK_STATE_COMPLETED")
        self.assertIsNotNone(sse_json["a2a_result"]["final_event"])
        self.assertEqual(sse_json["a2a_result"]["artifact_update_count"], 4)

        # Zero private keys / raw JWTs / raw LCT wire tokens across rehearsal & reviews
        priv_hdr = "-----BEGIN " + "PRIVATE KEY-----"
        ec_hdr = "-----BEGIN EC " + "PRIVATE KEY-----"
        jwt_pfx = "ey" + "J"
        jwt_re = re.compile(rf"\b{jwt_pfx}[A-Za-z0-9_-]{{10,}}\.[A-Za-z0-9_-]{{10,}}\.[A-Za-z0-9_-]{{10,}}\b")
        lct_re = re.compile(r"\blct(?:mp)?1\.[A-Za-z0-9_.-]{16,}\b")

        for scan_dir in (
            REHEARSAL_R2,
            LINEAGE_ROOT / "k8s" / "runs" / "20261123T155355Z-multihost-rehearsal",
        ):
            for p in scan_dir.rglob("*"):
                if not p.is_file():
                    continue
                txt = p.read_text(encoding="utf-8", errors="ignore")
                self.assertNotIn(priv_hdr, txt, p.name)
                self.assertNotIn(ec_hdr, txt, p.name)
                self.assertIsNone(jwt_re.search(txt), p.name)
                self.assertIsNone(lct_re.search(txt), p.name)

        # Verify all roles enforce FORBIDDEN_HOST_PORTS exclusion & zero RBAC Secret grants
        for role in ROLE_ORDER:
            cfg = yaml.safe_load(render_kind_cluster_config(role))
            for m in cfg["nodes"][0]["extraPortMappings"]:
                self.assertNotIn(int(m["containerPort"]), FORBIDDEN_HOST_PORTS)


if __name__ == "__main__":
    unittest.main()
