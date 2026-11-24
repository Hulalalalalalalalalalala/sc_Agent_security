"""Independent QA Sign-Off Suite for Combined Milestone 7 Remediations & Milestone 8
(`lineage/reviews/qa_milestone7_8_signoff.py`).

Validates:
1. [HIGH-M7-01] Star-topology seedless-`alpha` 4-domain descriptor convergence via
   `POST /v1/federation/descriptors` on real `AutonomousDomainCAService` &
   `MinimalAuditTLSCAService` + zero-seed-edit `audit` role migration.
2. [HIGH-M7-02], [MEDIUM-M7-01], [MEDIUM-M7-02], [LOW-M7-01] Chinese Windows 10/11
   GBK/UTF-8 WSL2 LAN IP detection, bounded gossip/anomaly/seed caps, and canonical
   `"seeds"` ConfigMap key handling.
3. Milestone 8 `quay.io/keycloak/keycloak:26.5.2` realm generation (zero hardcoded
   secrets) and Kubernetes Secret/RBAC/host-port isolation across all 4 roles.
4. Milestone 8 JWS algorithm-confusion defenses (`alg:none`, `HS256`, `ES256`/`RS256`
   mismatch) and Hop-0 OIDC -> LCT `RootBlock` `B_0` bridge adversarial matrix.
5. Milestone 8 RFC 8693 `OAuthSTSService` + `OAuthTokenExchangeClient` (`oauth_centralized`
   & `oauth_federated` SPIFFE `JWT-SVID` assertions, `act` nesting, scope subsetting,
   RFC 7662 introspection & RFC 7009 revocation).
6. Milestone 8 `LineageSidecar` strict `DELEGATION_MODE=lct` isolation (`Bearer` /
   `X-LCT-Delegation-Mode: oauth_*` blocked with `401`) and `dual`-mode empirical contrast.
7. Zero business-app OAuth protocol branching (`specialist_apps.py`, `mcp_servers.py`)
   and documentation hygiene (`README.md`, `ARCHITECTURE.md`, `MULTIHOST_GUIDE.md`).
8. Live 4-cluster star-topology + Keycloak 26.5.2 + `qwen2.5:3b` rehearsal bundle
   (`20261124-164141-m7m8-star-oauth-compare-rehearsal`) completeness & secret scrubbing.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
from typing import Any, Dict, List
from unittest import mock
import unittest

import httpx
import yaml

from lineage.common.crypto import KeyPair, jws_sign_compact
from lineage.common.http_utils import HTTPRequestContext, find_free_port
from lineage.common.locators import (
    MAX_BOOTSTRAP_SEEDS,
    SeedEndpointStore,
    ServiceLocator,
)
from lineage.federation.anchors import TrustAnchorPinStore
from lineage.federation.domain_ca import (
    AutonomousDomainCAService,
    K8sServiceAccountVerifier,
)
from lineage.federation.locators import (
    MAX_DESCRIPTORS_PER_MESSAGE,
    MAX_TRACKED_DESCRIPTOR_ANOMALIES,
    DomainDescriptorStore,
    SignedDomainDescriptor,
    ingest_descriptor_http_request,
)
from lineage.federation.sync import FederationBundleSyncer
from lineage.identity.spiffe import TrustDomainCA
from lineage.identity.trust_bundle import TrustBundleResolver
from lineage.k8s.bootstrap_services import MinimalAuditTLSCAService
from lineage.multihost.config_gen import (
    FORBIDDEN_HOST_PORTS,
    render_kind_cluster_config,
    render_role_k8s_manifests,
)
from lineage.multihost.locator_agent import (
    _detect_wsl2_windows_host_ips,
    append_seed_to_local_clusters,
)
from lineage.oauth_sts import (
    CLIENT_ASSERTION_JWT_SPIFFE,
    DEFAULT_REALM_NAME,
    GRANT_TOKEN_EXCHANGE,
    KEYCLOAK_IMAGE,
    OAuthSTSError,
    OAuthSTSService,
    OAuthTokenExchangeClient,
    OIDCTokenVerifier,
    TOKEN_TYPE_ACCESS,
    generate_keycloak_realm_bundle,
)
from lineage.protocol.dpop import create_dpop_proof
from lineage.protocol.lattice import PermissionLattice
from lineage.protocol.token import decode_token, mint_root_token
from lineage.sidecar.proxy import AgentSidecarNode, MCPToolSidecarNode

REPO_ROOT = Path(__file__).resolve().parents[2]
LINEAGE_DIR = REPO_ROOT / "lineage"
REHEARSAL_DIR = (
    LINEAGE_DIR
    / "k8s"
    / "runs"
    / "20261124-164141-m7m8-star-oauth-compare-rehearsal"
)


class _MockK8sSAVerifier(K8sServiceAccountVerifier):
    """Deterministic RS256 K8s ServiceAccount JWT signer/verifier for QA tests."""

    def __init__(self) -> None:
        self.kp = KeyPair.generate("RS256")
        jwk = self.kp.public_jwk()
        super().__init__(allowed_audiences=("lct-federation-ca",))
        self._keys_by_kid = {jwk["kid"]: jwk}
        self._last_refresh = time.time()

    def _refresh_jwks(self) -> None:
        jwk = self.kp.public_jwk()
        with self._lock:
            self._keys_by_kid = {jwk["kid"]: jwk}
            self._last_refresh = time.time()

    def sign(self, namespace: str, sa_name: str, ttl_sec: float = 600.0) -> str:
        now = time.time()
        return jws_sign_compact(
            {
                "iss": "https://kubernetes.default.svc.cluster.local",
                "sub": f"system:serviceaccount:{namespace}:{sa_name}",
                "aud": ["lct-federation-ca"],
                "iat": now,
                "exp": now + ttl_sec,
                "kubernetes.io": {
                    "namespace": namespace,
                    "serviceaccount": {"name": sa_name, "uid": "qa-uid"},
                },
            },
            self.kp,
            typ="JWT",
        )


class Milestone7And8QASignoffTests(unittest.TestCase):
    # -------------------------------------------------------------------------
    # 1. [HIGH-M7-01] Star-Topology Seedless-Alpha Convergence & Migration
    # -------------------------------------------------------------------------
    def test_01_m7_star_topology_seedless_alpha_convergence_and_zero_seed_edit_migration(
        self,
    ) -> None:
        k8s_ver = _MockK8sSAVerifier()
        with tempfile.TemporaryDirectory() as tmpdir:
            csr1 = Path(tmpdir) / "csr1"
            csr2 = Path(tmpdir) / "csr2"
            csr1.write_text(secrets.token_urlsafe(32), encoding="utf-8")
            csr2.write_text(secrets.token_urlsafe(32), encoding="utf-8")

            ca_alpha = AutonomousDomainCAService(
                trust_domain="org-alpha.io",
                allowed_k8s_namespace="lineage-alpha",
                k8s_verifier=k8s_ver,
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=DomainDescriptorStore(require_pinned_anchors=False),
            )
            ca_beta = AutonomousDomainCAService(
                trust_domain="org-beta.io",
                allowed_k8s_namespace="lineage-beta",
                k8s_verifier=k8s_ver,
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=DomainDescriptorStore(require_pinned_anchors=False),
            )
            ca_pay = AutonomousDomainCAService(
                trust_domain="org-payment.io",
                allowed_k8s_namespace="lineage-pay",
                k8s_verifier=k8s_ver,
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=DomainDescriptorStore(require_pinned_anchors=False),
            )
            ca_audit1 = MinimalAuditTLSCAService(
                csr_token_file=str(csr1),
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=DomainDescriptorStore(require_pinned_anchors=False),
            )
            for svc in (ca_alpha, ca_beta, ca_pay, ca_audit1):
                svc.start()

            try:
                assert ca_alpha.federation_http is not None
                assert ca_beta.federation_http is not None
                assert ca_pay.federation_http is not None
                assert ca_audit1.federation_http is not None
                assert ca_alpha.descriptor_store is not None
                assert ca_beta.descriptor_store is not None
                assert ca_pay.descriptor_store is not None
                assert ca_audit1.descriptor_store is not None

                ca_alpha.publish_domain_locators(
                    {"ca_bundle": [ServiceLocator("http-ro", "10.29.77.23", ca_alpha.federation_http.port)]}
                )
                ca_beta.publish_domain_locators(
                    {"ca_bundle": [ServiceLocator("http-ro", "10.29.101.203", ca_beta.federation_http.port)]}
                )
                ca_pay.publish_domain_locators(
                    {"ca_bundle": [ServiceLocator("http-ro", "10.29.49.219", ca_pay.federation_http.port)]}
                )
                desc_audit1 = SignedDomainDescriptor.sign_with_x509_root(
                    x509_ca=ca_audit1.x509_ca,
                    bundle=ca_audit1.export_public_bundle(),
                    locators={
                        "ca_bundle": [ServiceLocator("http-ro", "10.29.88.10", ca_audit1.federation_http.port)],
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
                ca_audit1.descriptor_store.set_own_descriptor(desc_audit1)

                all_pins = {
                    "org-alpha.io": ca_alpha.trust_anchor,
                    "org-beta.io": ca_beta.trust_anchor,
                    "org-payment.io": ca_pay.trust_anchor,
                    "org-audit.io": ca_audit1.export_public_bundle()["trust_anchor"],
                }

                def _wire_syncer(
                    own_td: str,
                    ds: DomainDescriptorStore,
                    own_anchor: str,
                    seeds: List[str],
                    local_ca_url: str,
                ) -> Tuple[FederationBundleSyncer, TrustAnchorPinStore]:
                    ps = TrustAnchorPinStore(
                        static_pins={k: v for k, v in all_pins.items() if k != own_td}
                    )
                    ds.anchor_store = ps
                    ds.require_pinned_anchors = True
                    ds.set_local_trust_domain(own_td, own_anchor)
                    syn = FederationBundleSyncer(
                        anchor_store=ps,
                        require_pinned_anchors=True,
                        local_trust_domain=own_td,
                        seed_store=SeedEndpointStore(static_seeds=seeds),
                        descriptor_store=ds,
                        local_ca_url=local_ca_url,
                    )
                    return syn, ps

                alpha_seed = f"10.29.77.23:{ca_alpha.federation_http.port}"
                sync_alpha, ps_alpha = _wire_syncer(
                    "org-alpha.io", ca_alpha.descriptor_store, ca_alpha.trust_anchor, [], ca_alpha.base_url
                )
                sync_beta, ps_beta = _wire_syncer(
                    "org-beta.io", ca_beta.descriptor_store, ca_beta.trust_anchor, [alpha_seed], ca_beta.base_url
                )
                sync_pay, ps_pay = _wire_syncer(
                    "org-payment.io", ca_pay.descriptor_store, ca_pay.trust_anchor, [alpha_seed], ca_pay.base_url
                )
                sync_audit1, _ = _wire_syncer(
                    "org-audit.io",
                    ca_audit1.descriptor_store,
                    all_pins["org-audit.io"],
                    [alpha_seed],
                    ca_audit1.http.base_url,
                )

                real_client = httpx.Client

                def _loopback_rewriter(*args: Any, **kwargs: Any) -> httpx.Client:
                    cli = real_client(*args, **kwargs)
                    orig_req = cli.request

                    def _req(method: str, url: str, *ra: Any, **rk: Any) -> Any:
                        patched = url
                        for ip in (
                            "10.29.77.23",
                            "10.29.101.203",
                            "10.29.49.219",
                            "10.29.88.10",
                            "10.29.99.55",
                        ):
                            patched = patched.replace(ip, "127.0.0.1")
                        return orig_req(method, patched, *ra, **rk)

                    cli.request = _req  # type: ignore[method-assign]
                    return cli

                with mock.patch(
                    "lineage.federation.sync.httpx.Client", side_effect=_loopback_rewriter
                ):
                    for _ in range(3):
                        for syn in (sync_beta, sync_pay, sync_audit1, sync_alpha):
                            syn.sync_descriptors_from_seeds_and_peers()

                # Seedless `alpha` AND all 3 spokes converge to Ready!
                self.assertEqual(sync_alpha.seed_store.list_seeds(), [])
                for name, syn in (
                    ("alpha", sync_alpha),
                    ("beta", sync_beta),
                    ("pay", sync_pay),
                    ("audit1", sync_audit1),
                ):
                    ok, detail = syn.is_ready()
                    self.assertTrue(ok, f"{name} failed star convergence: {detail}")

                # Migrate `audit` to a brand-new `MinimalAuditTLSCAService` (`10.29.99.55:30851`)
                # with ZERO seed edits on `alpha` (`alpha` seeds stay `[]`)!
                ca_audit1.stop()
                ca_audit2 = MinimalAuditTLSCAService(
                    csr_token_file=str(csr2),
                    host="127.0.0.1",
                    port=0,
                    federation_port=find_free_port(),
                    descriptor_store=DomainDescriptorStore(require_pinned_anchors=False),
                )
                ca_audit2.start()
                try:
                    assert ca_audit2.federation_http is not None
                    assert ca_audit2.descriptor_store is not None
                    new_audit_anc = ca_audit2.export_public_bundle()["trust_anchor"]
                    desc_audit2 = SignedDomainDescriptor.sign_with_x509_root(
                        x509_ca=ca_audit2.x509_ca,
                        bundle=ca_audit2.export_public_bundle(),
                        locators={
                            "ca_bundle": [
                                ServiceLocator("http-ro", "10.29.99.55", ca_audit2.federation_http.port)
                            ],
                            "audit_collector": [
                                ServiceLocator(
                                    "tls-tcp",
                                    "10.29.99.55",
                                    30851,
                                    spiffe_id="spiffe://org-audit.io/ns/lineage-audit/sa/audit-collector",
                                )
                            ],
                        },
                        version=2,
                    )
                    ca_audit2.descriptor_store.set_own_descriptor(desc_audit2)
                    all_pins["org-audit.io"] = new_audit_anc

                    for ps_surv in (ps_alpha, ps_beta, ps_pay):
                        ps_surv.set_pin("org-audit.io", new_audit_anc)

                    sync_audit2, _ = _wire_syncer(
                        "org-audit.io",
                        ca_audit2.descriptor_store,
                        new_audit_anc,
                        [alpha_seed],
                        ca_audit2.http.base_url,
                    )
                    with mock.patch(
                        "lineage.federation.sync.httpx.Client", side_effect=_loopback_rewriter
                    ):
                        for _ in range(3):
                            for syn in (sync_audit2, sync_alpha, sync_beta, sync_pay):
                                syn.sync_descriptors_from_seeds_and_peers()

                    self.assertEqual(sync_alpha.seed_store.list_seeds(), [])
                    aud_locs = ca_alpha.descriptor_store.get_locators(
                        "org-audit.io", "audit_collector"
                    )
                    self.assertEqual(len(aud_locs), 1)
                    self.assertEqual(aud_locs[0].host, "10.29.99.55")
                    self.assertEqual(aud_locs[0].port, 30851)
                finally:
                    ca_audit2.stop()
            finally:
                ca_alpha.stop()
                ca_beta.stop()
                ca_pay.stop()
                ca_audit1.stop()

    # -------------------------------------------------------------------------
    # 2. [HIGH-M7-02], [MEDIUM-M7-01..02] Chinese Windows WSL2 & Bounded Maps
    # -------------------------------------------------------------------------
    def test_02_m7_chinese_windows_gbk_utf8_wsl2_and_bounded_gossip_defenses(
        self,
    ) -> None:
        zh_ipconfig = (
            "\r\nWindows IP 配置\r\n\r\n"
            "以太网适配器 VMware Network Adapter VMnet8:\r\n"
            "   描述. . . . . . . . . . . . . . . : VMware Virtual Ethernet Adapter for VMnet8\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 192.168.207.1(首选)\r\n\r\n"
            "未知适配器 QuickQ TUN:\r\n"
            "   描述. . . . . . . . . . . . . . . : WireGuard Wintun Tunnel\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 10.8.0.1(首选)\r\n\r\n"
            "无线局域网适配器 WLAN:\r\n"
            "   描述. . . . . . . . . . . . . . . : Intel(R) Wi-Fi 6 AX201 160MHz\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 10.29.101.203(首选)\r\n"
            "   默认网关. . . . . . . . . . . . . : 10.29.0.1\r\n"
        ).encode("gbk")

        def _fake_run(cmd: Any, **_kw: Any) -> subprocess.CompletedProcess[bytes]:
            exe = cmd[0] if isinstance(cmd, list) else str(cmd)
            if "powershell" in exe:
                return subprocess.CompletedProcess(cmd, 1, stdout=b"", stderr=b"blocked")
            return subprocess.CompletedProcess(cmd, 0, stdout=zh_ipconfig, stderr=b"")

        with mock.patch("subprocess.run", side_effect=_fake_run):
            locs = _detect_wsl2_windows_host_ips()
        self.assertGreaterEqual(len(locs), 1)
        self.assertEqual(locs[0][0], "10.29.101.203")

        # Bounded HTTP descriptor ingestion & anomaly map caps
        pin_store = TrustAnchorPinStore()
        store = DomainDescriptorStore(
            anchor_store=pin_store,
            require_pinned_anchors=True,
        )
        req_413 = HTTPRequestContext(
            "POST", "/v1/federation/descriptors", {}, b"x" * 1_048_577, "127.0.0.1", 8094
        )
        st_413, body_413, _ = ingest_descriptor_http_request(req_413, store)
        self.assertEqual(st_413, 413)
        self.assertEqual(body_413["error"], "descriptor_payload_too_large")

        req_400 = HTTPRequestContext(
            "POST",
            "/v1/federation/descriptors",
            {},
            json.dumps(
                {"descriptors": [{} for _ in range(MAX_DESCRIPTORS_PER_MESSAGE + 1)]}
            ).encode("utf-8"),
            "127.0.0.1",
            8094,
        )
        st_400, body_400, _ = ingest_descriptor_http_request(req_400, store)
        self.assertEqual(st_400, 400)
        self.assertEqual(body_400["error"], "too_many_descriptors")

        for idx in range(220):
            try:
                store.ingest_raw_descriptor(
                    {"trust_domain": f"org-flood-{idx}.io", "descriptor_jws": "bad"}
                )
            except Exception:
                pass
        self.assertEqual(
            len(store.diagnostics()["ignored_unpinned_domains"]),
            MAX_TRACKED_DESCRIPTOR_ANOMALIES,
        )

        # Bounded seed store cap (`<= 32`)
        seed_store = SeedEndpointStore()
        for idx in range(1, 80):
            seed_store.add_dynamic_seed(f"10.29.1.{idx}:30100")
        self.assertEqual(len(seed_store.list_seeds()), MAX_BOOTSTRAP_SEEDS)

        # Canonical `"seeds"` ConfigMap key merge in `append_seed_to_local_clusters`
        applied_docs: List[Dict[str, Any]] = []

        def _fake_kubectl(cmd: List[str], **kw: Any) -> subprocess.CompletedProcess[str]:
            if cmd[:2] == ["kind", "get"]:
                return subprocess.CompletedProcess(cmd, 0, stdout="lctmh-beta\n", stderr="")
            if "get" in cmd and "configmap" in cmd:
                cm = {"data": {"seeds": "10.29.77.23:30100\n"}}
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(cm), stderr="")
            if "apply" in cmd:
                applied_docs.append(yaml.safe_load(kw["input"]))
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=_fake_kubectl):
            append_seed_to_local_clusters("10.29.88.44:31100")
        self.assertEqual(len(applied_docs), 1)
        self.assertEqual(list(applied_docs[0]["data"].keys()), ["seeds"])
        self.assertIn("10.29.77.23:30100", applied_docs[0]["data"]["seeds"])
        self.assertIn("10.29.88.44:31100", applied_docs[0]["data"]["seeds"])

    # -------------------------------------------------------------------------
    # 3. Milestone 8 Keycloak 26.5.2 Realm & K8s Manifest Security Isolation
    # -------------------------------------------------------------------------
    def test_03_m8_keycloak_realm_zero_hardcoded_secrets_and_k8s_manifest_isolation(
        self,
    ) -> None:
        b1 = generate_keycloak_realm_bundle()
        b2 = generate_keycloak_realm_bundle()
        self.assertNotEqual(b1.admin_password, b2.admin_password)
        for u in ("alice", "bob", "carol"):
            self.assertNotEqual(b1.user_passwords[u], b2.user_passwords[u])
            self.assertGreaterEqual(len(b1.user_passwords[u]), 20)
        for cid in b1.client_secrets:
            self.assertNotEqual(b1.client_secrets[cid], b2.client_secrets[cid])
            self.assertGreaterEqual(len(b1.client_secrets[cid]), 24)

        kc_realm_mounts: List[str] = []
        for role_name, eng in (
            ("alpha", "keycloak"),
            ("beta", "lightweight"),
            ("pay", "lightweight"),
            ("audit", "none"),
        ):
            kind_cfg = yaml.safe_load(render_kind_cluster_config(role_name))
            for pm in kind_cfg["nodes"][0].get("extraPortMappings") or []:
                self.assertEqual(pm["containerPort"], pm["hostPort"])
                self.assertNotIn(int(pm["hostPort"]), FORBIDDEN_HOST_PORTS)

            docs = list(
                yaml.safe_load_all(
                    render_role_k8s_manifests(role_name, sts_engine=eng)
                )
            )
            for doc in docs:
                kind = doc["kind"]
                if kind in ("Role", "ClusterRole"):
                    for rule in doc.get("rules") or []:
                        self.assertNotIn("secrets", rule.get("resources") or [])

                if kind == "Service" and doc["spec"].get("type") == "NodePort":
                    for p_entry in doc["spec"]["ports"]:
                        self.assertNotIn(
                            int(p_entry["targetPort"]),
                            (8080, 8081, 8090, 8091, 8092, 9001),
                        )

                if kind == "Deployment":
                    dep_name = doc["metadata"]["name"]
                    pspec = doc["spec"]["template"]["spec"]
                    self.assertIs(pspec.get("automountServiceAccountToken"), False)

                    sec_vols = {
                        v["name"]: v["secret"]
                        for v in (pspec.get("volumes") or [])
                        if "secret" in v
                    }
                    for s_vol in sec_vols.values():
                        self.assertEqual(s_vol.get("defaultMode"), 0o440)
                        self.assertEqual(
                            (pspec.get("securityContext") or {}).get("fsGroup"), 2000
                        )
                        if s_vol["secretName"] == "lct-keycloak-realm":
                            kc_realm_mounts.append(f"{role_name}/{dep_name}")
                        if role_name == "audit":
                            self.assertNotIn(
                                s_vol["secretName"],
                                ("lct-oauth-credentials", "lct-keycloak-realm"),
                            )

                    for c_doc in pspec["containers"]:
                        c_mounts = {
                            m["name"]: m for m in (c_doc.get("volumeMounts") or [])
                        }
                        if c_doc["name"] == "app":
                            self.assertNotIn("lct-oauth-credentials", c_mounts)
                            self.assertNotIn("lct-keycloak-realm", c_mounts)
                            self.assertNotIn("lct-sa-token", c_mounts)
                        for v_name in sec_vols:
                            if v_name in c_mounts:
                                self.assertIs(c_mounts[v_name].get("readOnly"), True)

                        if dep_name == "alpha-sts":
                            self.assertEqual(c_doc["image"], KEYCLOAK_IMAGE)
                            self.assertIn(
                                "--features=token-exchange,token-exchange-standard:v2",
                                c_doc["args"],
                            )

        self.assertEqual(kc_realm_mounts, ["alpha/alpha-sts"])

    # -------------------------------------------------------------------------
    # 4. Milestone 8 JWS `alg` Confusion & Hop-0 OIDC Bridge Adversarial Matrix
    # -------------------------------------------------------------------------
    def test_04_m8_jws_alg_confusion_and_hop0_oidc_bridge_adversarial_matrix(
        self,
    ) -> None:
        bundle = generate_keycloak_realm_bundle()
        sts = OAuthSTSService(
            trust_domain="org-alpha.io",
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
        )
        sts_url = sts.start()
        k8s_ver = _MockK8sSAVerifier()
        oidc_ver = OIDCTokenVerifier(
            jwks_urls=[f"{sts_url}/realms/{DEFAULT_REALM_NAME}/protocol/openid-connect/certs"],
            allowed_issuers=[f"{sts_url}/realms/{DEFAULT_REALM_NAME}"],
            default_user_domain="org-alpha.io",
        )
        ca_svc = AutonomousDomainCAService(
            trust_domain="org-alpha.io",
            allowed_k8s_namespace="lineage-alpha",
            authorized_gateway_sa="e2e-user-gateway",
            k8s_verifier=k8s_ver,
            oidc_verifier=oidc_ver,
            require_oidc_user_token=True,
            host="127.0.0.1",
            port=0,
            federation_port=find_free_port(),
        )
        ca_url = ca_svc.start()
        ca_fed_url = ca_svc.federation_base_url
        assert ca_fed_url is not None
        try:
            gw_sa = k8s_ver.sign("lineage-alpha", "e2e-user-gateway")
            other_sa = k8s_ver.sign("lineage-alpha", "orchestrator-alpha")
            gw_kp = KeyPair.generate("ES256")
            orch_kp = KeyPair.generate("ES256")
            perms = PermissionLattice.create(tools=["search_flight"], max_calls=2)

            cli = OAuthTokenExchangeClient(client_secrets=bundle.client_secrets)
            login_alice = cli.login_user_password(
                sts_origins=sts_url,
                username="alice",
                password=bundle.user_passwords["alice"],
                client_id="lct-gateway",
            )

            def _post_mint(
                extra: Dict[str, Any],
                sa_jwt: str = gw_sa,
                base: str = ca_url,
            ) -> httpx.Response:
                req = {
                    "trust_domain": "org-alpha.io",
                    "task_id": f"task-qa-m8-{int(time.time() * 1000000)}",
                    "sender_jkt": gw_kp.jkt,
                    "first_hop_spiffe_id": "spiffe://org-alpha.io/ns/lineage-alpha/sa/orchestrator-alpha",
                    "first_hop_jkt": orch_kp.jkt,
                    "permissions": perms.to_dict(),
                    **extra,
                }
                return httpx.post(
                    f"{base}/v1/ca/mint-root-token",
                    json=req,
                    headers={"Authorization": f"Bearer {sa_jwt}"},
                    timeout=5.0,
                )

            # 1) Missing `user_oidc_token` when `require_oidc_user_token=True` -> 401
            self.assertEqual(_post_mint({"sub": "user:alice@org-alpha.io"}).status_code, 401)

            # 2) Valid RS256 OIDC token -> 200 & `RootBlock` `B_0` bound to `user:alice@org-alpha.io`
            r_ok = _post_mint({"user_oidc_token": login_alice["id_token"]})
            self.assertEqual(r_ok.status_code, 200, r_ok.text)
            self.assertEqual(decode_token(r_ok.json()["compact_token"]).sub, "user:alice@org-alpha.io")

            # 3) `alg: none` unsigned token -> 401
            b64u = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
            now_i = int(time.time())
            claims_alice = {
                "iss": f"{sts_url}/realms/lct",
                "sub": "alice",
                "preferred_username": "alice",
                "iat": now_i,
                "exp": now_i + 600,
            }
            tok_none = f"{b64u({'alg': 'none', 'typ': 'JWT'})}.{b64u(claims_alice)}."
            self.assertEqual(_post_mint({"user_oidc_token": tok_none}).status_code, 401)

            # 4) `alg: HS256` symmetric algorithm confusion -> 401
            tok_hs256 = (
                f"{b64u({'alg': 'HS256', 'typ': 'JWT', 'kid': sts.keypair.kid})}"
                f".{b64u(claims_alice)}.AAAA"
            )
            self.assertEqual(_post_mint({"user_oidc_token": tok_hs256}).status_code, 401)

            # 5) `ES256` token masquerading under `RS256` `kid` -> 401
            ec_rogue = KeyPair.generate("ES256", kid=sts.keypair.kid)
            tok_ec_mismatch = jws_sign_compact(claims_alice, ec_rogue, typ="JWT")
            self.assertEqual(_post_mint({"user_oidc_token": tok_ec_mismatch}).status_code, 401)

            # 6) Future `nbf` token -> 401
            tok_future_nbf = jws_sign_compact(
                {**claims_alice, "nbf": now_i + 3600}, sts.keypair, typ="JWT"
            )
            self.assertEqual(_post_mint({"user_oidc_token": tok_future_nbf}).status_code, 401)

            # 7) Subject spoofing (`user:bob@org-alpha.io` + Alice's OIDC token) -> 403
            r_spoof = _post_mint(
                {"sub": "user:bob@org-alpha.io", "user_oidc_token": login_alice["id_token"]}
            )
            self.assertEqual(r_spoof.status_code, 403)
            self.assertEqual(r_spoof.json()["error"], "oidc_sub_mismatch")

            # 8) Unauthorized K8s SA (`orchestrator-alpha`) -> 403
            self.assertEqual(
                _post_mint({"user_oidc_token": login_alice["id_token"]}, sa_jwt=other_sa).status_code,
                403,
            )

            # 9) External read-only federation port `:8094` -> 403 `federation_endpoint_read_only`
            r_ext = _post_mint(
                {"user_oidc_token": login_alice["id_token"]}, base=ca_fed_url
            )
            self.assertEqual(r_ext.status_code, 403)
            self.assertEqual(r_ext.json()["error"], "federation_endpoint_read_only")
        finally:
            ca_svc.stop()
            sts.stop()

    # -------------------------------------------------------------------------
    # 5. Milestone 8 RFC 8693 STS Centralized & Federated Security Invariants
    # -------------------------------------------------------------------------
    def test_05_m8_rfc8693_centralized_and_federated_sts_security_invariants(
        self,
    ) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        ca_evil = TrustDomainCA("org-evil.io")
        resolver = TrustBundleResolver()
        resolver.register_bundle(ca_alpha.export_public_bundle())
        resolver.register_bundle(ca_beta.export_public_bundle())

        bundle = generate_keycloak_realm_bundle()
        peer_jwks: List[str] = []
        sts_alpha = OAuthSTSService(
            trust_domain="org-alpha.io",
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
            spiffe_trust_resolver=resolver,
        )
        sts_beta = OAuthSTSService(
            trust_domain="org-beta.io",
            spiffe_trust_resolver=resolver,
            peer_sts_jwks_Urls_provider=lambda: peer_jwks,
        )
        u_alpha = sts_alpha.start()
        u_beta = sts_beta.start()
        try:
            cli_central = OAuthTokenExchangeClient(client_secrets=bundle.client_secrets)
            cli_fed = OAuthTokenExchangeClient()  # Zero shared secrets: SPIFFE SVID assertion only
            peer_jwks.append(cli_central.jwks_endpoint(u_alpha))

            login_res = cli_central.login_user_password(
                sts_origins=u_alpha,
                username="alice",
                password=bundle.user_passwords["alice"],
                client_id="lct-gateway",
            )
            t0 = login_res["access_token"]

            # Wrong client_secret rejected (`401`)
            r_bad_sec = httpx.post(
                cli_central.token_endpoint(u_alpha),
                data={
                    "grant_type": GRANT_TOKEN_EXCHANGE,
                    "client_id": "lct-gateway",
                    "client_secret": "wrong-secret",
                    "subject_token": t0,
                    "subject_token_type": TOKEN_TYPE_ACCESS,
                },
                timeout=5.0,
            )
            self.assertEqual(r_bad_sec.status_code, 401)

            # Narrow to `travel:book`, then attempt cross-domain federated escalation to `travel:pay` -> fails!
            ex_narrow = cli_central.exchange_token(
                sts_origins=u_alpha,
                subject_token=t0,
                target_audience="orchestrator-alpha",
                client_id="lct-gateway",
                requested_scope="travel:book",
            )
            orch_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/orchestrator-alpha")
            with self.assertRaises(OAuthSTSError) as ctx_esc:
                cli_fed.exchange_token(
                    sts_origins=u_beta,
                    subject_token=ex_narrow.access_token,
                    target_audience="flight-specialist",
                    caller_spiffe_id=orch_id.spiffe_id,
                    caller_workload_svid=orch_id.workload_svid,
                    requested_scope="travel:book travel:pay",
                )
            self.assertIn("invalid_scope", str(ctx_esc.exception))

            # Unpinned `org-evil.io` SPIFFE SVID client_assertion rejected (`401`)
            evil_id = ca_evil.issue_workload("/ns/evil/sa/intruder")
            r_evil = httpx.post(
                cli_fed.token_endpoint(u_beta),
                data={
                    "grant_type": GRANT_TOKEN_EXCHANGE,
                    "subject_token": t0,
                    "subject_token_type": TOKEN_TYPE_ACCESS,
                    "audience": "flight-specialist",
                    "client_assertion_type": CLIENT_ASSERTION_JWT_SPIFFE,
                    "client_assertion": evil_id.workload_svid,
                },
                timeout=5.0,
            )
            self.assertEqual(r_evil.status_code, 401)
        finally:
            sts_alpha.stop()
            sts_beta.stop()

    # -------------------------------------------------------------------------
    # 6. Sidecar `DELEGATION_MODE=lct` Isolation & `dual` Scope/Lattice Contrast
    # -------------------------------------------------------------------------
    def test_06_m8_sidecar_delegation_mode_lct_strict_isolation_and_dual_mode_contrast(
        self,
    ) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_pay = TrustDomainCA("org-payment.io")
        resolver = TrustBundleResolver()
        resolver.register_bundle(ca_alpha.export_public_bundle())
        resolver.register_bundle(ca_pay.export_public_bundle())

        bundle = generate_keycloak_realm_bundle()
        sts = OAuthSTSService(
            trust_domain="org-alpha.io",
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
        )
        sts_url = sts.start()
        cli = OAuthTokenExchangeClient(client_secrets=bundle.client_secrets)
        ver = OIDCTokenVerifier(
            jwks_urls=[cli.jwks_endpoint(sts_url)],
            allowed_issuers=[f"{sts_url}/realms/lct"],
        )

        gw_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
        lct_only_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/orchestrator-alpha")
        vault_id = ca_pay.issue_workload("/ns/lineage-pay/sa/payment-vault-mcp")

        # (A) Default `delegation_mode="lct"` MUST block valid Bearer tokens with 401!
        lct_only_node = AgentSidecarNode(
            identity=lct_only_id,
            trust_resolver=resolver,
            name="LCT-Only Agent",
            skills=["travel.orchestrate"],
            handler=lambda _n, _r, _b: (200, {"ok": True}),
            delegation_mode="lct",
            oauth_central_verifier=ver,
        )
        lct_card = lct_only_node.start(register_in_directory=False)

        # (B) `dual`-mode `payment-vault-mcp` requires `travel:pay` for `execute_settlement`
        vault_node = MCPToolSidecarNode(
            identity=vault_id,
            trust_resolver=resolver,
            tools={
                "execute_settlement": lambda args, _r: {
                    "settled": True,
                    "amount": args["amount"],
                }
            },
            delegation_mode="dual",
            oauth_central_verifier=ver,
            oauth_local_verifier=ver,
        )
        vault_url = vault_node.start()
        try:
            login_res = cli.login_user_password(
                sts_origins=sts_url,
                username="alice",
                password=bundle.user_passwords["alice"],
                client_id="lct-gateway",
            )
            ex_orch = cli.exchange_token(
                sts_origins=sts_url,
                subject_token=login_res["access_token"],
                target_audience=lct_only_id.spiffe_id,
                client_id="lct-gateway",
            )
            for hdr_mode in ("oauth_centralized", "oauth_federated"):
                r_downgrade = httpx.post(
                    f"{lct_card.endpoint}/a2a/task",
                    json={"op": "ping"},
                    headers={
                        "Authorization": f"Bearer {ex_orch.access_token}",
                        "X-LCT-Delegation-Mode": hdr_mode,
                    },
                    timeout=5.0,
                )
                self.assertEqual(r_downgrade.status_code, 401)
                self.assertEqual(
                    r_downgrade.json()["error"],
                    "missing_or_invalid_authorization_scheme",
                )
                self.assertIn("DPoP", r_downgrade.json()["detail"])
            self.assertEqual(len(lct_only_node.sidecar.oauth_active_requests._active), 0)

            # Insufficient OAuth scope (`travel:book` only) calling `execute_settlement` -> 403 `insufficient_scope`
            ex_book_only = cli.exchange_token(
                sts_origins=sts_url,
                subject_token=login_res["access_token"],
                target_audience=vault_id.spiffe_id,
                client_id="lct-gateway",
                requested_scope="travel:book",
            )
            r_insuff = httpx.post(
                f"{vault_url}/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "execute_settlement",
                        "arguments": {"target": "airline-escrow", "amount": 500.0},
                    },
                },
                headers={
                    "Authorization": f"Bearer {ex_book_only.access_token}",
                    "X-LCT-Delegation-Mode": "oauth_centralized",
                },
                timeout=5.0,
            )
            self.assertEqual(r_insuff.status_code, 403)
            self.assertIn("insufficient_oauth_scope", r_insuff.json()["detail"])

            # Valid LCT DPoP call on `lct_only_node` succeeds cleanly
            lct_tok = mint_root_token(
                ca_alpha,
                task_id="task-lct-isolated-ok",
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=lct_only_id.spiffe_id,
                first_hop_jkt=lct_only_id.jkt,
                permissions=PermissionLattice.create(tools=["search_flight"], max_calls=2),
            ).encode_compact()
            u_task = f"{lct_card.endpoint}/a2a/task"
            r_lct = httpx.post(
                u_task,
                json={"op": "ping"},
                headers={
                    "Authorization": f"DPoP {lct_tok}",
                    "DPoP": create_dpop_proof(gw_id, "POST", u_task, lct_tok),
                },
                timeout=5.0,
            )
            self.assertEqual(r_lct.status_code, 200)
        finally:
            lct_only_node.stop()
            vault_node.stop()
            sts.stop()

    # -------------------------------------------------------------------------
    # 7. Zero Business-App Protocol Branching & Documentation Hygiene
    # -------------------------------------------------------------------------
    def test_07_m8_business_apps_zero_protocol_branching_and_doc_hygiene(self) -> None:
        for app_path in (
            LINEAGE_DIR / "agents" / "specialist_apps.py",
            LINEAGE_DIR / "agents" / "mcp_servers.py",
        ):
            src = app_path.read_text(encoding="utf-8")
            self.assertNotIn("oauth_sts", src)
            self.assertNotIn("OIDCTokenVerifier", src)
            self.assertNotIn("GRANT_TOKEN_EXCHANGE", src)
            self.assertNotIn("Authorization", src)

        for doc_path in (
            LINEAGE_DIR / "README.md",
            LINEAGE_DIR / "ARCHITECTURE.md",
            LINEAGE_DIR / "multihost" / "MULTIHOST_GUIDE.md",
        ):
            txt = doc_path.read_text(encoding="utf-8")
            self.assertNotIn("--alpha-ip", txt)
            self.assertNotIn("Tailscale", txt)
            self.assertNotIn("tailscale", txt)

    # -------------------------------------------------------------------------
    # 8. Live Star-Topology + Keycloak 26.5.2 Rehearsal Evidence & Scrubbing
    # -------------------------------------------------------------------------
    def test_08_rehearsal_evidence_and_secret_redaction_integrity(self) -> None:
        self.assertTrue(REHEARSAL_DIR.is_dir(), f"Missing rehearsal dir: {REHEARSAL_DIR}")

        seeds_before = json.loads(
            (REHEARSAL_DIR / "01_seeds_list_star_topology.json").read_text("utf-8")
        )
        seeds_after = json.loads(
            (REHEARSAL_DIR / "07_seeds_list_after_migration.json").read_text("utf-8")
        )
        self.assertEqual(seeds_before["lctmh-alpha"], [])
        self.assertEqual(seeds_after["lctmh-alpha"], [])
        for spoke in ("lctmh-beta", "lctmh-pay", "lctmh-audit"):
            self.assertEqual(len(seeds_before[spoke]), 1)
            self.assertEqual(seeds_before[spoke], seeds_after[spoke])

        st_before = json.loads((REHEARSAL_DIR / "04_star_status.json").read_text("utf-8"))
        st_after = json.loads(
            (REHEARSAL_DIR / "08_post_migration_status.json").read_text("utf-8")
        )
        self.assertTrue(st_before["federation_ready"])
        self.assertTrue(st_after["federation_ready"])
        self.assertNotEqual(
            st_before["domain_descriptor_resolution"]["org-audit.io"]["trust_anchor"],
            st_after["domain_descriptor_resolution"]["org-audit.io"]["trust_anchor"],
        )
        for item in st_after["identity_to_locator_resolution"]:
            self.assertEqual(item["tls_version"], "TLSv1.3")
            self.assertEqual(item["healthz_status"], 200)

        cmp_doc = json.loads(
            (REHEARSAL_DIR / "m8_protocol_comparison.json").read_text("utf-8")
        )
        self.assertEqual(cmp_doc["status"], "PASS")
        self.assertEqual(cmp_doc["alpha_sts_engine"], "keycloak-26.5.2")
        dims = cmp_doc["dimensions"]
        self.assertEqual(
            dims["1_latency_and_sts_rpcs"]["oauth_centralized"]["online_sts_exchange_rpcs"],
            12,
        )
        self.assertEqual(
            dims["1_latency_and_sts_rpcs"]["oauth_federated"]["online_sts_exchange_rpcs"],
            12,
        )
        self.assertEqual(
            dims["1_latency_and_sts_rpcs"]["lct"]["online_sts_exchange_rpcs"],
            0,
        )
        self.assertTrue(dims["1_latency_and_sts_rpcs"]["lct"]["hop0_oidc_bridged"])
        self.assertEqual(
            dims["2_fine_grained_overprivilege"]["oauth_centralized"]["http_status"],
            200,
        )
        self.assertEqual(
            dims["2_fine_grained_overprivilege"]["lct"]["http_status"],
            403,
        )
        self.assertEqual(
            dims["3_multiparent_convergence_and_branch_cancel"]["lct"][
                "airline_escrow_status_after_flight_cancel"
            ],
            403,
        )
        self.assertEqual(
            dims["3_multiparent_convergence_and_branch_cancel"]["lct"][
                "hotel_lineage_decision"
            ],
            "ALLOW_DEGRADED_DAG",
        )
        self.assertFalse(
            dims["4_zombie_primary_failover_double_spend"]["oauth_centralized"][
                "double_spend_prevented"
            ]
        )
        self.assertTrue(
            dims["4_zombie_primary_failover_double_spend"]["lct"][
                "double_spend_prevented"
            ]
        )
        self.assertEqual(
            dims["5_central_sts_partition_impact"]["oauth_centralized"][
                "http_status_during_alpha_sts_outage"
            ],
            502,
        )
        self.assertEqual(
            dims["5_central_sts_partition_impact"]["lct"][
                "alpha_to_beta_to_pay_http_status_during_alpha_sts_outage"
            ],
            200,
        )
        self.assertEqual(
            dims["6_causal_audit_reconstruction"]["lct"][
                "hash_linked_causal_coverage_pct"
            ],
            100.0,
        )

        # Build patterns dynamically so this file never triggers static regex scanners
        priv_pat = re.compile("BEGIN " + r"[A-Z0-9 ]*PRIVATE KEY")
        jwt_pat = re.compile(
            r"\bey" + r"J[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
        )
        lct_pat = re.compile(r"\blct(?:mp|m)?" + r"1\.[A-Za-z0-9_.-]{12,}")
        files = sorted(p for p in REHEARSAL_DIR.rglob("*") if p.is_file())
        self.assertGreaterEqual(len(files), 20)
        for p in files:
            txt = p.read_text(encoding="utf-8", errors="replace")
            self.assertIsNone(priv_pat.search(txt), f"Private key leaked in {p.name}")
            self.assertIsNone(jwt_pat.search(txt), f"Raw JWT leaked in {p.name}")
            self.assertIsNone(lct_pat.search(txt), f"Raw LCT token leaked in {p.name}")


if __name__ == "__main__":
    unittest.main()
