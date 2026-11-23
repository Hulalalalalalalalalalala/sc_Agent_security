"""Milestone 6 Independent QA Review & Reproduction Suite (`k8s-qa-reviewer`).

Strictly read-only against `lineage/` implementation code, baseline files, and
host Docker/Kind containers. Verifies Milestone 6 compliance invariants AND
deterministically reproduces the issues documented in `MILESTONE6_QA_REPORT.md`:

- `[HIGH-M6-01]`:
  (A) Unauthenticated plain-HTTP bundle spoofing evicts an already pin-verified
      peer domain from `TrustBundleResolver` & `X509FederationTrustStore` (LAN DoS).
  (B) `x509_roots_pem` hashes only `roots_list[0]` in `compute_bundle_trust_anchor`
      and crashes with `AttributeError: 'X509FederationTrustStore' object has no
      attribute 'register_domain_roots_pem'` in `FederationBundleSyncer`.
- `[HIGH-M6-02]`:
  `AuditCollectorService` accepts arbitrarily back-dated and future-dated
  `AuditEntry` records signed under retired/expired workload SVIDs over
  server-only TLS (`:30893`) without ingest-age or per-stream timestamp bounds.
- `[MEDIUM-M6-01]`:
  `ROLE_SPECS['alpha'].host_ports` permanently exposes plain-HTTP port `30990`
  (`e2e-user-gateway-sync`), and `s3b-sync-hook` accepts unauthenticated requests.
- `[MEDIUM-M6-02]`:
  `lct_multihost_cli.py trust fetch` lacks `--expect <sha256:...>` and `--yes`
  emits no `UNVERIFIED TOFU` security warning on `stderr`.
- `[MEDIUM-M6-03]`:
  `lct_multihost_cli.py send --stream` parses `result.status` instead of official
  A2A v1.0 `result.statusUpdate.status`, producing `sse_states: []` and
  `final_event: null` (confirmed in `12_cli_send_stream.json`).
- `[LOW-M6-01]`:
  `ARCHITECTURE.md` states `0400` CA Secret mount mode whereas `config_gen.py`
  renders `defaultMode: 0o440` (`288`) with `fsGroup: 2000`.
- `[LOW-M6-02]`:
  `preflight.sh` calls `httpx.get(url)` without `trust_env=False`, and `fault.sh`
  does not validate `--role` values against `alpha|beta|pay|audit|all`.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import re
import subprocess
import time
import unittest
from typing import Any, Dict, Tuple
from unittest import mock

import yaml

from lineage.audit import AuditCollectorService, AuditEventType, AuditStreamEmitter
from lineage.common.crypto import KeyPair
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.common.mtls import X509DomainAuthority, X509FederationTrustStore
from lineage.federation import (
    FederationBundleSyncer,
    FederationSecurityError,
    TrustAnchorPinStore,
    compute_bundle_trust_anchor,
)
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.multihost import (
    FORBIDDEN_HOST_PORTS,
    ROLE_ORDER,
    ROLE_SPECS,
    render_kind_cluster_config,
    render_role_k8s_manifests,
)
from lineage.multihost.lct_multihost_cli import build_cli_parser, main as cli_main

REPO_ROOT = Path("/Users/hulalala/Desktop/A")
LINEAGE_ROOT = REPO_ROOT / "lineage"
REHEARSAL_DIR = LINEAGE_ROOT / "k8s" / "runs" / "20261123T155355Z-multihost-rehearsal"


class Milestone6IndependentQAReviewTests(unittest.TestCase):
    # -------------------------------------------------------------------------
    # 1. Positive Compliance & Rehearsal Hygiene Verification
    # -------------------------------------------------------------------------
    def test_01_rehearsal_evidence_hygiene_and_port_rbac_invariants(self) -> None:
        self.assertTrue(REHEARSAL_DIR.is_dir(), "Missing M6 rehearsal directory")

        summary = json.loads((REHEARSAL_DIR / "e2e_multihost_summary.json").read_text())
        self.assertEqual(summary["overall_status"], "PASS")
        self.assertEqual(
            set(summary["scenarios"].keys()),
            {"1", "2A", "2B", "3A", "3B", "4", "5", "6"},
        )
        for sc_id, sc_payload in summary["scenarios"].items():
            self.assertEqual(sc_payload.get("status"), "PASS", f"Scenario {sc_id} failed")

        # Verify zero private keys, zero raw 3-part JWS/JWTs, and zero raw wire LCT tokens in rehearsal run
        priv_marker = "-----BEGIN " + "PRIVATE KEY-----"
        ec_priv_marker = "-----BEGIN EC " + "PRIVATE KEY-----"
        jwt_prefix = "ey" + "J"
        jwt_re = re.compile(rf"\b{jwt_prefix}[A-Za-z0-9_-]{{10,}}\.[A-Za-z0-9_-]{{10,}}\.[A-Za-z0-9_-]{{10,}}\b")
        lct_re = re.compile(r"\blct(?:mp)?1\.[A-Za-z0-9_.-]{16,}\b")

        for fpath in REHEARSAL_DIR.rglob("*"):
            if not fpath.is_file():
                continue
            text = fpath.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn(priv_marker, text, f"Private key leaked in {fpath.name}")
            self.assertNotIn(ec_priv_marker, text, f"EC private key leaked in {fpath.name}")
            self.assertIsNone(jwt_re.search(text), f"Raw JWT leaked in {fpath.name}")
            self.assertIsNone(lct_re.search(text), f"Raw LCT token leaked in {fpath.name}")

        # Verify zero RBAC Role/ClusterRole/RoleBinding granting Secret access, and readinessProbes use /readyz
        for role in ROLE_ORDER:
            cfg = yaml.safe_load(render_kind_cluster_config(role))
            for m in cfg["nodes"][0]["extraPortMappings"]:
                self.assertNotIn(int(m["containerPort"]), FORBIDDEN_HOST_PORTS)

            docs = list(yaml.safe_load_all(render_role_k8s_manifests(role)))
            for doc in docs:
                self.assertNotIn(
                    doc["kind"],
                    {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"},
                    f"Unexpected RBAC manifest in {role}: {doc}",
                )
                if doc["kind"] == "Deployment":
                    dep_name = doc["metadata"]["name"]
                    for c in doc["spec"]["template"]["spec"]["containers"]:
                        if "readinessProbe" in c and not dep_name.endswith("-ca"):
                            probe_str = json.dumps(c["readinessProbe"])
                            self.assertIn("/readyz", probe_str, f"{dep_name} readinessProbe must use /readyz")

    # -------------------------------------------------------------------------
    # 2. Reproduce [HIGH-M6-01]: LAN Spoof Eviction DoS + x509_roots_pem Bug
    # -------------------------------------------------------------------------
    def test_02_reproduce_high_m6_01_lan_spoof_evicts_verified_peer_and_roots_list_bug(
        self,
    ) -> None:
        ca_beta = TrustDomainCA("org-beta.io", alg="ES256")
        x509_beta = X509DomainAuthority("org-beta.io")
        genuine_bundle: Dict[str, Any] = ca_beta.export_public_bundle()
        genuine_bundle["x509_root_pem"] = x509_beta.export_root_pem()
        genuine_pin = compute_bundle_trust_anchor(genuine_bundle)

        serve_spoof = {"active": False}
        ca_rogue = TrustDomainCA("org-beta.io", alg="ES256")
        x509_rogue = X509DomainAuthority("org-beta.io")
        spoofed_bundle: Dict[str, Any] = ca_rogue.export_public_bundle()
        spoofed_bundle["x509_root_pem"] = x509_rogue.export_root_pem()

        def _bundle_handler(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
            if req.path == "/v1/federation/bundle":
                return 200, (spoofed_bundle if serve_spoof["active"] else genuine_bundle), {}
            return 404, {"error": "not_found"}, {}

        peer_http = ManagedHTTPService("peer-beta-bundle", _bundle_handler, host="127.0.0.1", port=0)
        peer_url = peer_http.start()
        try:
            pins = TrustAnchorPinStore(initial_pins={"org-beta.io": genuine_pin})
            syncer = FederationBundleSyncer(
                peer_ca_urls={"org-beta.io": peer_url},
                anchor_store=pins,
                require_pinned_anchors=True,
            )
            syncer.sync_all(require_all=True, max_wait_sec=2.0)
            self.assertIn("org-beta.io", syncer.trust_resolver.trusted_domains())
            self.assertTrue(syncer.is_ready()[0])

            # Simulate a single spoofed plain-HTTP response on the LAN during background refresh
            # (`sync_all(require_all=False, max_wait_sec=0.2)`) while local ConfigMap pin is unchanged!
            serve_spoof["active"] = True
            syncer.sync_all(require_all=False, max_wait_sec=0.2)

            # BUG [HIGH-M6-01A]: The already pin-verified `org-beta.io` trust material is EVICTED from RAM!
            evicted_from_resolver = "org-beta.io" not in syncer.trust_resolver.trusted_domains()
            evicted_from_x509 = not syncer.x509_trust_store.has_domain("org-beta.io")
            not_ready_now = not syncer.is_ready()[0]
            self.assertTrue(
                evicted_from_resolver and evicted_from_x509 and not_ready_now,
                "Expected reproduction of [HIGH-M6-01A]: spoofed HTTP response evicted verified peer domain",
            )

            # BUG [HIGH-M6-01B]: `x509_roots_pem` hashes ONLY `roots_list[0]` (ignoring appended rogue cert)
            # AND crashes `FederationBundleSyncer` with `AttributeError: register_domain_roots_pem`!
            multi_root_bundle = dict(genuine_bundle)
            multi_root_bundle["x509_roots_pem"] = [
                x509_beta.export_root_pem(),
                x509_rogue.export_root_pem(),
            ]
            # Anchor matches genuine_pin despite second unpinned CA cert in x509_roots_pem!
            self.assertEqual(compute_bundle_trust_anchor(multi_root_bundle), genuine_pin)
            self.assertFalse(hasattr(X509FederationTrustStore, "register_domain_roots_pem"))
            with self.assertRaises(AttributeError):
                syncer._verify_and_apply_bundle("org-beta.io", multi_root_bundle)
        finally:
            peer_http.stop()

    # -------------------------------------------------------------------------
    # 3. Reproduce [HIGH-M6-02]: Back-Dated & Future-Dated AuditEntry Acceptance
    # -------------------------------------------------------------------------
    def test_03_reproduce_high_m6_02_unbounded_historical_and_future_audit_timestamps(
        self,
    ) -> None:
        ca = TrustDomainCA("org-alpha.io", alg="ES256")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca)

        now = time.time()
        # Mint a workload identity whose SVID expired 24 hours ago!
        expired_ts = now - 86400.0
        expired_id = ca.issue_workload(
            "/ns/lineage-alpha/sa/orchestrator-alpha",
            ttl_seconds=60.0,
            now=expired_ts,
        )
        # Confirm SVID is genuinely expired at current wall clock
        with self.assertRaises(Exception):
            resolver.verify_workload_svid(expired_id.workload_svid)

        collector = AuditCollectorService(trust_resolver=resolver, host="127.0.0.1", port=0)
        emitter_old = AuditStreamEmitter(signer=expired_id, stream_id="forged-backdated-stream")
        with mock.patch("lineage.audit.logger.time.time", return_value=expired_ts + 10.0):
            backdated_entry = emitter_old.emit(
                event_type=AuditEventType.TOOL_INVOCATION,
                task_id="task-ancient-forged",
                sub="user:alice@org-alpha.io",
                lineage_path="/task-ancient-forged/OrchestratorAlpha",
                hop_index=0,
                epoch=0,
                root_block_hash="rbh",
                current_block_hash="cbh",
                decision="ALLOW",
            )
        # BUG [HIGH-M6-02]: Collector accepts a 24-hour-expired SVID via back-dated entry.timestamp!
        count_after_backdate = collector.append_direct(backdated_entry)
        self.assertEqual(count_after_backdate, 1)

        # Also accepts a 20-minute future-dated entry under a live 30-min SVID!
        live_id = ca.issue_workload(
            "/ns/lineage-alpha/sa/orchestrator-alpha",
            ttl_seconds=1800.0,
        )
        emitter_future = AuditStreamEmitter(signer=live_id, stream_id="future-dated-stream")
        with mock.patch("lineage.audit.logger.time.time", return_value=now + 1200.0):
            future_entry = emitter_future.emit(
                event_type=AuditEventType.TOOL_INVOCATION,
                task_id="task-future-forged",
                sub="user:alice@org-alpha.io",
                lineage_path="/task-future-forged/OrchestratorAlpha",
                hop_index=0,
                epoch=0,
                root_block_hash="rbh2",
                current_block_hash="cbh2",
                decision="ALLOW",
            )
        self.assertEqual(collector.append_direct(future_entry), 2)

    # -------------------------------------------------------------------------
    # 4. Reproduce [MEDIUM-M6-01..03] & [LOW-M6-01..02]
    # -------------------------------------------------------------------------
    def test_04_reproduce_medium_and_low_m6_findings(self) -> None:
        # [MEDIUM-M6-01]: Port 30990 permanently published in alpha host_ports
        self.assertIn(30990, ROLE_SPECS["alpha"].host_ports)

        # [MEDIUM-M6-02]: `trust fetch` parser lacks `--expect`
        parser = build_cli_parser()
        with mock.patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "trust",
                    "fetch",
                    "--domain",
                    "org-beta.io",
                    "--ip",
                    "192.168.1.7",
                    "--expect",
                    f"sha256:{'a' * 64}:{'b' * 64}",
                ]
            )

        # [MEDIUM-M6-03]: Live rehearsal artifact `12_cli_send_stream.json` has empty `sse_states` & null `final_event`
        cli_sse = json.loads((REHEARSAL_DIR / "12_cli_send_stream.json").read_text())
        self.assertEqual(cli_sse["a2a_result"]["sse_frame_count"], 7)
        self.assertEqual(cli_sse["a2a_result"]["sse_states"], [])
        self.assertIsNone(cli_sse["a2a_result"]["final_event"])

        # [LOW-M6-01]: `ARCHITECTURE.md` claims `0400` while `config_gen.py` sets `0o440` (`288`)
        arch_md = (LINEAGE_ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
        self.assertIn("`0400`", arch_md)
        alpha_docs = list(yaml.safe_load_all(render_role_k8s_manifests("alpha")))
        ca_dep = next(
            d for d in alpha_docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "alpha-ca"
        )
        ca_vol = next(
            v for v in ca_dep["spec"]["template"]["spec"]["volumes"] if v["name"] == "ca-root-keys"
        )
        self.assertEqual(ca_vol["secret"]["defaultMode"], 0o440)

        # [LOW-M6-02]: `preflight.sh` uses bare `httpx.get(url, timeout=4.0)` without `trust_env=False`,
        # and `fault.sh` does not validate `--role` before running `docker exec`
        preflight_txt = (LINEAGE_ROOT / "multihost" / "preflight.sh").read_text(encoding="utf-8")
        self.assertIn("httpx.get(url, timeout=4.0)", preflight_txt)

        res_bad_role = subprocess.run(
            ["bash", str(LINEAGE_ROOT / "multihost" / "fault.sh"), "--heal", "--role", "invalid_role_xyz"],
            capture_output=True,
            text=True,
        )
        # Fails inside `docker exec lctmh-invalid_role_xyz-control-plane` (exit 1) instead of argument error (exit 2)
        self.assertNotEqual(res_bad_role.returncode, 2)
        self.assertIn("lctmh-invalid_role_xyz-control-plane", res_bad_role.stderr)


if __name__ == "__main__":
    unittest.main()
