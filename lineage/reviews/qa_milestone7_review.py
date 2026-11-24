"""Milestone 7 Independent QA Review & Vulnerability Reproduction Suite.

Deterministic, non-destructive verification and PoC reproduction suite for Milestone 7:
1. Reproduces `[HIGH-M7-01]`: Following the 4-machine runbook (`MULTIHOST_GUIDE.md:117-129`)
   where Machine 1 (`alpha`) deploys with NO `--seed` and Machines 2–4 (`beta`, `pay`, `audit`)
   deploy with `--seed <alpha_ip:alpha_ca_port>`, pull-only gossip deadlocks: `alpha` learns 0
   peers, `beta`/`pay`/`audit` never learn each other, and all 4 domains stay `NotReady`.
   Also reproduces `POST /v1/federation/descriptors` returning `403`/`404` on CA federation ports.
2. Reproduces `[HIGH-M7-02]`: Localized Chinese Windows 10/11 WSL2 host LAN IP detection bug:
   `decode("utf-8", errors="ignore")` on CP936/GBK `ipconfig.exe` bytes silently strips `"默认网关"`,
   preventing the `gbk` fallback (`if not raw_out.strip():` is False) and causing a host-only
   adapter (`192.168.207.1`) listed before `"WLAN"` (`10.29.101.203`) to be selected. Also verifies
   QuickQ (`30.233.233.233`) and public `183.175.x.x` addresses are rejected.
3. Reproduces `[MEDIUM-M7-01]`: Unbounded memory growth in `DomainDescriptorStore`
   (`_ignored_unpinned`, `_rejected_counts`, `_last_errors`) and `SeedEndpointStore` dynamic seeds.
4. Reproduces `[MEDIUM-M7-02]`: `ConfigMap/lct-bootstrap-seeds` key mismatch between `config_gen.py`
   / `lct_multihost_cli.py` (`"seeds"`) and `locator_agent.py:append_seed_to_local_clusters`
   (`"seeds.txt"`), wiping operator-configured `--seed` entries when mDNS discovers a seed.
5. Reproduces `[LOW-M7-01]`: Stale M6 documentation in `lineage/README.md` (`--alpha-ip`,
   `Tailscale`, `update-peer-ips`, 3-machine title) and `typ` string typo in `ARCHITECTURE.md`.
6. Verifies M7 positive cryptographic & TLS invariants (pin-first verification, `check_hostname=False`
   without `expected_spiffe_id` blocked, RFC1918-only CIDR allowlist, rehearsal secret hygiene).
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
import unittest
from typing import Any, Dict, List
from unittest import mock

import httpx

from lineage.common.crypto import KeyPair
from lineage.common.http_utils import find_free_port
from lineage.common.locators import (
    LocatorValidationError,
    SeedEndpointStore,
    ServiceLocator,
    validate_locator_host,
)
from lineage.common.mtls import (
    MTLSError,
    WorkloadMTLSBundle,
    X509DomainAuthority,
    X509FederationTrustStore,
)
from lineage.federation import (
    AutonomousDomainCAService,
    DomainDescriptorStore,
    FederationBundleSyncer,
    SignedDomainDescriptor,
    TrustAnchorPinStore,
)
from lineage.k8s.bootstrap_services import K8sServiceAccountVerifier, MinimalAuditTLSCAService
from lineage.multihost import config_gen, locator_agent

REPO_ROOT = Path(__file__).resolve().parents[2]
LINEAGE_ROOT = REPO_ROOT / "lineage"


class Milestone7IndependentQAReviewTests(unittest.TestCase):
    def _make_k8s_verifier(self, oidc_kp: KeyPair) -> K8sServiceAccountVerifier:
        jwk = oidc_kp.public_jwk()
        verifier = K8sServiceAccountVerifier(allowed_audiences=("lct-federation-ca",))
        verifier._keys_by_kid = {jwk["kid"]: jwk}
        verifier._last_refresh = time.time() + 3600.0
        return verifier

    def test_01_reproduce_high_m7_01_seedless_first_node_star_topology_deadlock(self) -> None:
        """Reproduce [HIGH-M7-01]: 4-machine star topology (`alpha` seedless; others `--seed alpha`) fails to converge."""
        oidc_kp = KeyPair.generate("RS256")
        with tempfile.TemporaryDirectory() as tmpdir:
            csr_f = Path(tmpdir) / "csr"
            csr_f.write_text(secrets.token_urlsafe(32), encoding="utf-8")

            ca_alpha = AutonomousDomainCAService(
                trust_domain="org-alpha.io",
                allowed_k8s_namespace="lineage-alpha",
                k8s_verifier=self._make_k8s_verifier(oidc_kp),
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=DomainDescriptorStore(require_pinned_anchors=False),
            )
            ca_beta = AutonomousDomainCAService(
                trust_domain="org-beta.io",
                allowed_k8s_namespace="lineage-beta",
                k8s_verifier=self._make_k8s_verifier(oidc_kp),
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=DomainDescriptorStore(require_pinned_anchors=False),
            )
            ca_pay = AutonomousDomainCAService(
                trust_domain="org-payment.io",
                allowed_k8s_namespace="lineage-pay",
                k8s_verifier=self._make_k8s_verifier(oidc_kp),
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=DomainDescriptorStore(require_pinned_anchors=False),
            )
            ca_audit = MinimalAuditTLSCAService(
                csr_token_file=str(csr_f),
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=DomainDescriptorStore(require_pinned_anchors=False),
            )
            ca_alpha.start()
            ca_beta.start()
            ca_pay.start()
            ca_audit.start()
            try:
                assert ca_alpha.federation_http is not None
                assert ca_beta.federation_http is not None
                assert ca_pay.federation_http is not None
                assert ca_audit.federation_http is not None

                ca_alpha.publish_domain_locators(
                    {"ca_bundle": [ServiceLocator("http-ro", "10.29.77.23", ca_alpha.federation_http.port)]}
                )
                ca_beta.publish_domain_locators(
                    {"ca_bundle": [ServiceLocator("http-ro", "10.29.101.203", ca_beta.federation_http.port)]}
                )
                ca_pay.publish_domain_locators(
                    {"ca_bundle": [ServiceLocator("http-ro", "10.29.49.219", ca_pay.federation_http.port)]}
                )
                desc_audit = SignedDomainDescriptor.sign_with_x509_root(
                    x509_ca=ca_audit.x509_ca,
                    bundle=ca_audit.export_public_bundle(),
                    locators={
                        "ca_bundle": [ServiceLocator("http-ro", "10.29.88.10", ca_audit.federation_http.port)],
                        "audit_collector": [
                            ServiceLocator(
                                "tls-tcp",
                                "10.29.88.10",
                                30801,
                                spiffe_id="spiffe://org-audit.io/ns/lineage-audit/sa/audit-collector",
                            )
                        ],
                    },
                    version=1,
                )
                assert ca_audit.descriptor_store is not None
                ca_audit.descriptor_store.set_own_descriptor(desc_audit)

                all_pins = {
                    "org-alpha.io": ca_alpha.trust_anchor,
                    "org-beta.io": ca_beta.trust_anchor,
                    "org-payment.io": ca_pay.trust_anchor,
                    "org-audit.io": ca_audit.export_public_bundle()["trust_anchor"],
                }

                def _wire_syncer(own_td: str, ds: DomainDescriptorStore, own_anchor: str, seeds: List[str]) -> FederationBundleSyncer:
                    ps = TrustAnchorPinStore(static_pins={k: v for k, v in all_pins.items() if k != own_td})
                    ds.anchor_store = ps
                    ds.require_pinned_anchors = True
                    ds.set_local_trust_domain(own_td, own_anchor)
                    return FederationBundleSyncer(
                        anchor_store=ps,
                        require_pinned_anchors=True,
                        local_trust_domain=own_td,
                        seed_store=SeedEndpointStore(static_seeds=seeds),
                        descriptor_store=ds,
                    )

                alpha_seed = f"10.29.77.23:{ca_alpha.federation_http.port}"
                assert ca_alpha.descriptor_store is not None
                assert ca_beta.descriptor_store is not None
                assert ca_pay.descriptor_store is not None
                # Exact MULTIHOST_GUIDE.md:117-129 topology:
                # Machine 1 (alpha): NO seed; Machines 2, 3, 4: `--seed <alpha_seed>`
                sync_alpha = _wire_syncer("org-alpha.io", ca_alpha.descriptor_store, ca_alpha.trust_anchor, [])
                sync_beta = _wire_syncer("org-beta.io", ca_beta.descriptor_store, ca_beta.trust_anchor, [alpha_seed])
                sync_pay = _wire_syncer("org-payment.io", ca_pay.descriptor_store, ca_pay.trust_anchor, [alpha_seed])
                sync_audit = _wire_syncer(
                    "org-audit.io",
                    ca_audit.descriptor_store,
                    all_pins["org-audit.io"],
                    [alpha_seed],
                )

                real_client = httpx.Client

                def _loopback_rewriter(*args: Any, **kwargs: Any) -> httpx.Client:
                    cli = real_client(*args, **kwargs)
                    orig_req = cli.request

                    def _req(method: str, url: str, *ra: Any, **rk: Any) -> Any:
                        patched = url
                        for ip in ("10.29.77.23", "10.29.101.203", "10.29.49.219", "10.29.88.10"):
                            patched = patched.replace(ip, "127.0.0.1")
                        return orig_req(method, patched, *ra, **rk)

                    cli.request = _req  # type: ignore[method-assign]
                    return cli

                with mock.patch("lineage.federation.sync.httpx.Client", side_effect=_loopback_rewriter):
                    for _ in range(3):
                        sync_alpha.sync_descriptors_from_seeds_and_peers()
                        sync_beta.sync_descriptors_from_seeds_and_peers()
                        sync_pay.sync_descriptors_from_seeds_and_peers()
                        sync_audit.sync_descriptors_from_seeds_and_peers()

                # Reproduce deadlock: NONE of the 4 domains reach Ready!
                self.assertFalse(sync_alpha.is_ready()[0], "Expected seedless alpha to stay NotReady under pull-only gossip")
                self.assertFalse(sync_beta.is_ready()[0], "Expected beta to miss pay & audit when hub alpha never learned them")
                self.assertFalse(sync_pay.is_ready()[0], "Expected pay to miss beta & audit when hub alpha never learned them")
                self.assertFalse(sync_audit.is_ready()[0], "Expected audit to miss beta & pay when hub alpha never learned them")
                self.assertEqual(set(ca_alpha.descriptor_store.all_descriptors().keys()), {"org-alpha.io"})

                # Confirm CA federation ports currently reject POST /v1/federation/descriptors with 403 / 404
                r_post_alpha = httpx.post(
                    f"http://127.0.0.1:{ca_alpha.federation_http.port}/v1/federation/descriptors",
                    json=ca_beta.descriptor_store.export_gossip_payload(),
                    trust_env=False,
                )
                r_post_audit = httpx.post(
                    f"http://127.0.0.1:{ca_audit.federation_http.port}/v1/federation/descriptors",
                    json=ca_beta.descriptor_store.export_gossip_payload(),
                    trust_env=False,
                )
                self.assertEqual(r_post_alpha.status_code, 403)
                self.assertEqual(r_post_audit.status_code, 404)
            finally:
                ca_alpha.stop()
                ca_beta.stop()
                ca_pay.stop()
                ca_audit.stop()

    def test_02_reproduce_high_m7_02_chinese_windows_wsl2_encoding_and_adapter_filtering(self) -> None:
        """Reproduce [HIGH-M7-02]: GBK `ipconfig.exe` decoded via `utf-8, ignore` loses `'默认网关'` and picks `.1` virtual IP."""
        # Simulated Chinese Windows 11 `ipconfig.exe` CP936/GBK stdout:
        # Adapter 1: VMware/Host-Only localized alias "以太网适配器 以太网 2" (192.168.207.1, NO default gateway)
        # Adapter 2: QuickQ VPN/accelerator (30.233.233.233) + public multi-IP adapter (183.175.12.34)
        # Adapter 3: Physical Wi-Fi "无线局域网适配器 WLAN" (10.29.101.203, WITH 默认网关 10.29.64.1)
        cn_ipconfig_text = (
            "Windows IP 配置\r\n\r\n"
            "以太网适配器 以太网 2:\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 192.168.207.1\r\n"
            "   子网掩码  . . . . . . . . . . . . : 255.255.255.0\r\n"
            "   默认网关. . . . . . . . . . . . . : \r\n\r\n"
            "未知适配器 QuickQ:\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 30.233.233.233\r\n"
            "   默认网关. . . . . . . . . . . . . : 30.233.233.1\r\n\r\n"
            "以太网适配器 以太网 4:\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 183.175.12.34\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 183.175.12.35\r\n"
            "   默认网关. . . . . . . . . . . . . : \r\n\r\n"
            "无线局域网适配器 WLAN:\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 10.29.101.203\r\n"
            "   子网掩码  . . . . . . . . . . . . : 255.255.192.0\r\n"
            "   默认网关. . . . . . . . . . . . . : 10.29.64.1\r\n"
        )
        gbk_bytes = cn_ipconfig_text.encode("gbk")

        # 1. Verify QuickQ (30.233.233.233) & 183.175.x.x are ALWAYS rejected by RFC1918 CIDR validator
        for non_lan_ip in ("30.233.233.233", "183.175.12.34"):
            with self.assertRaises(LocatorValidationError):
                validate_locator_host(non_lan_ip)

        # 2. When decoded properly as GBK, `parse_windows_ipconfig_lan_ips` sees `"默认网关"` and picks ONLY `10.29.101.203`
        self.assertEqual(
            locator_agent.parse_windows_ipconfig_lan_ips(gbk_bytes.decode("gbk")),
            ["10.29.101.203"],
        )

        # 3. Reproduce bug in `_detect_wsl2_windows_host_ips` (`locator_agent.py:253-278`):
        #    (a) `powershell.exe` with `text=True` raises `UnicodeDecodeError` on GBK Chinese adapter aliases;
        #    (b) `ipconfig.exe` runs `gbk_bytes.decode("utf-8", errors="ignore")`, which is non-empty (so `gbk`
        #        fallback never runs!), strips `"默认网关"`, and picks `"192.168.207.1"` first!
        def _fake_run(cmd: List[str], *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
            exe = str(cmd[0]).lower()
            if "powershell" in exe:
                if kwargs.get("text"):
                    raise UnicodeDecodeError("utf-8", b"\xd2\xd4\xcc\xab\xcd\xf8", 0, 1, "invalid start byte")
                return subprocess.CompletedProcess(cmd, 1, b"", b"")
            return subprocess.CompletedProcess(cmd, 0, gbk_bytes, b"")

        with mock.patch("lineage.multihost.locator_agent.subprocess.run", side_effect=_fake_run):
            detected = locator_agent._detect_wsl2_windows_host_ips()
        self.assertEqual(
            detected[0][0],
            "192.168.207.1",
            f"Expected reproduction of [HIGH-M7-02] picking 192.168.207.1 before 10.29.101.203, got {detected}",
        )

    def test_03_reproduce_medium_m7_01_and_02_unbounded_maps_and_seeds_key_conflict(self) -> None:
        """Reproduce [MEDIUM-M7-01] unbounded untrusted tracking sets & [MEDIUM-M7-02] `seeds` vs `seeds.txt` wipe."""
        # [MEDIUM-M7-01]: Unbounded `_ignored_unpinned` & `SeedEndpointStore._dynamic_seeds`
        pin_store = TrustAnchorPinStore(static_pins={"org-beta.io": f"sha256:{'a' * 64}:{'b' * 64}"})
        d_store = DomainDescriptorStore(anchor_store=pin_store, require_pinned_anchors=True)
        for idx in range(200):
            with self.assertRaises(Exception):
                d_store.ingest_raw_descriptor({"trust_domain": f"unpinned-{idx}.evil.io"})
        diag = d_store.diagnostics()
        self.assertEqual(len(diag["ignored_unpinned_domains"]), 200)

        s_store = SeedEndpointStore()
        for idx in range(1, 201):
            s_store.add_dynamic_seed(f"10.29.1.{idx}:30100")
        self.assertEqual(len(s_store.list_seeds()), 200)

        # [MEDIUM-M7-02]: `render_role_k8s_manifests` writes key `"seeds"`, whereas
        # `append_seed_to_local_clusters` reads ONLY `"seeds.txt"` and overwrites ConfigMap with `{"seeds.txt": ...}`!
        applied_cm_data: List[Dict[str, str]] = []
        existing_cm = {
            "data": {"seeds": "10.29.77.23:30100"}  # exact key written by `deploy` & `seeds add`
        }
        with (
            mock.patch(
                "lineage.multihost.locator_agent.discover_local_active_roles",
                return_value=["beta"],
            ),
            mock.patch(
                "lineage.multihost.locator_agent._kubectl_json",
                return_value=existing_cm,
            ),
            mock.patch(
                "lineage.multihost.locator_agent._apply_configmap",
                side_effect=lambda _ctx, _ns, _name, data, **_kw: applied_cm_data.append(dict(data)),
            ),
        ):
            locator_agent.append_seed_to_local_clusters("10.29.49.219:32100", roles=["beta"])

        self.assertEqual(len(applied_cm_data), 1)
        # Reproduces clobbering: operator's `10.29.77.23:30100` under key `"seeds"` is lost!
        self.assertNotIn("10.29.77.23:30100", "\n".join(applied_cm_data[0].values()))

    def test_04_reproduce_low_m7_01_stale_lineage_readme_and_arch_typo(self) -> None:
        """Reproduce [LOW-M7-01]: `lineage/README.md` still has `--alpha-ip`, `Tailscale`, and `update-peer-ips`."""
        readme_txt = (LINEAGE_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("--alpha-ip", readme_txt)
        self.assertIn("tailscale", readme_txt.lower())
        self.assertIn("update-peer-ips", readme_txt)

        # Confirm `deploy-role.sh` rejects `--alpha-ip` with exit code 2
        proc = subprocess.run(
            ["bash", str(LINEAGE_ROOT / "multihost" / "deploy-role.sh"), "--roles", "alpha", "--alpha-ip", "10.29.77.23"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 2)

        arch_txt = (LINEAGE_ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
        self.assertIn('typ="lct-agent-card+jwt"', arch_txt)

    def test_05_verify_m7_positive_security_invariants_and_rehearsal_hygiene(self) -> None:
        """Verify M7 positive cryptographic & hygiene invariants that passed review."""
        # 1. Hard TLS invariant: `check_hostname=False` without `expected_spiffe_id` is forbidden
        x509_ca = X509DomainAuthority("org-beta.io")
        trust = X509FederationTrustStore()
        trust.register_domain_root_pem("org-beta.io", x509_ca.export_root_pem())
        kp = KeyPair.generate("ES256")
        spiffe = "spiffe://org-beta.io/ns/lineage-beta/sa/flight-specialist"
        leaf = x509_ca.issue_x509_svid(spiffe, kp.public_jwk(), dns_names=("localhost",))
        bundle = WorkloadMTLSBundle(spiffe, kp, leaf, trust)
        try:
            with self.assertRaises(MTLSError):
                bundle.build_client_ssl_context(check_hostname=False, expected_spiffe_id=None)
            with self.assertRaises(MTLSError):
                bundle.verify_for_target("https://10.29.101.203:31103/a2a", expected_spiffe_id=None)
        finally:
            bundle.cleanup()

        # 2. Dynamic port allocation stays strictly within [30000, 32767] and excludes internal ports
        for role in config_gen.ROLE_ORDER:
            ports = config_gen.allocate_role_ports(role)
            for p in ports.values():
                self.assertGreaterEqual(p, 30000)
                self.assertLessEqual(p, 32767)
                self.assertNotIn(p, config_gen.FORBIDDEN_HOST_PORTS)

        # 3. Rehearsal evidence bundle contains 0 private keys, 0 raw JWTs, 0 raw LCT tokens, and 8/8 E2E PASS
        rehearsal_dir = LINEAGE_ROOT / "k8s" / "runs" / "20261124-131005-identity-addressing-rehearsal"
        self.assertTrue(rehearsal_dir.is_dir())
        priv_marker = "BEGIN " + "PRIVATE KEY"
        ec_priv_marker = "BEGIN EC " + "PRIVATE KEY"
        jwt_pat = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
        lct_pat = re.compile(r"\blct(?:mp|m)?1\.[A-Za-z0-9_.-]{12,}")
        for fpath in rehearsal_dir.rglob("*"):
            if not fpath.is_file():
                continue
            txt = fpath.read_text(encoding="utf-8", errors="replace")
            self.assertNotIn(priv_marker, txt, f"Private key leaked in {fpath.name}")
            self.assertNotIn(ec_priv_marker, txt, f"EC private key leaked in {fpath.name}")
            self.assertIsNone(jwt_pat.search(txt), f"Raw JWT leaked in {fpath.name}")
            self.assertIsNone(lct_pat.search(txt), f"Raw LCT token leaked in {fpath.name}")

        e2e_summary = json.loads((rehearsal_dir / "e2e" / "e2e_multihost_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(e2e_summary["overall_status"], "PASS")
        self.assertEqual(sorted(e2e_summary["scenarios"].keys()), ["1", "2A", "2B", "3A", "3B", "4", "5", "6"])


if __name__ == "__main__":
    unittest.main()
