"""Milestone 6 Unit & Integration Tests: Multi-Host Physical Interconnection.

Covers:
1. Kind multi-host config generation (`extraPortMappings`, `listenAddress: 0.0.0.0`,
   disjoint port sets & CIDRs, zero internal `:8090/:8091/:8092/:8081/:9001` ports published)
   and multi-host K8s manifest key-custody invariants.
2. CoreDNS `hosts` block generation from `--alpha-ip/--beta-ip/--pay-ip/--audit-ip`,
   strict IPv4 validation, `host.docker.internal` preservation, and idempotent `update-peer-ips`.
3. SSH-style SHA-256 trust anchor pinning (pin match, mismatch fail-closed, missing pin
   fail-closed, persisted CA root stability, and keyless TLS 1.3 `audit-collector`).
4. Zero-restart trust hot-reload across BOTH client and server mTLS 1.3 `SSLContext`s
   (including immediate eviction when a pinned anchor mismatches).
5. Startup-order independence: booting with absent peers (`0` exceptions, `/healthz` 200,
   `/readyz` 503) and automatic transition to Ready (`200`) once peers come online.
6. Automatic background SVID & X.509 leaf certificate renewal across `>= 2` full cycles
   with kubelet-rotated SA token re-reading, live mTLS traffic, signed `AuditEntry`
   verification, and monotonic `AgentCard` re-registration.
7. RFC 9110 HTTP `Date` clock-skew preflight logic (`warn > 10s`, `fail > 25s`) and
   `lct_multihost_cli.py` argument validation.
"""

from __future__ import annotations

import datetime as dt
import email.utils
import hmac
import io
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import unittest
from typing import Any, Callable, Dict, List, Set, Tuple
from unittest import mock

import httpx
import yaml

from lineage.a2a import (
    A2AClient,
    A2AInvocationContext,
    A2AServerEngine,
    Artifact,
    Message,
    TaskState,
)
from lineage.audit import (
    AuditCollectorClient,
    AuditCollectorService,
    AuditEventType,
    AuditIngestError,
    AuditStreamEmitter,
)
from lineage.common.crypto import KeyPair, jws_sign_compact
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService, find_free_port
from lineage.common.mtls import WorkloadMTLSBundle, X509DomainAuthority, X509FederationTrustStore
from lineage.federation import (
    AutonomousDomainCAService,
    FederationBundleSyncer,
    FederationSecurityError,
    TrustAnchorPinError,
    TrustAnchorPinStore,
    bootstrap_autonomous_workload,
    compute_bundle_trust_anchor,
)
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.k8s.bootstrap_services import (
    K8sServiceAccountVerifier,
    MinimalAuditTLSCAService,
    create_ca_pop_jws,
)
from lineage.multihost import (
    FORBIDDEN_HOST_PORTS,
    ROLE_ORDER,
    ROLE_SPECS,
    allocate_role_ports,
    evaluate_http_date_clock_skew,
    generate_domain_ca_secret_bundle,
    parse_roles_csv,
    render_e2e_sync_service_manifest,
    render_kind_cluster_config,
    render_role_k8s_manifests,
    sanitize_coredns_corefile,
    validate_ipv4_address,
)
from lineage.multihost.lct_multihost_cli import (
    build_cli_parser,
    main as cli_main,
    stream_and_summarize_a2a_sse,
)
from lineage.protocol import PermissionLattice, create_dpop_proof, mint_root_token
from lineage.registry import AgentCard, AgentDirectoryClient, AgentDirectoryService
from lineage.revocation import RevocationError, RevocationReplicaClient, RevocationService
from lineage.sidecar import LineageSidecar
from lineage.verifier import VerificationMode


class Milestone6MultiHostTests(unittest.TestCase):
    def _make_k8s_verifier(self, oidc_kp: KeyPair) -> K8sServiceAccountVerifier:
        jwk = oidc_kp.public_jwk()
        v = K8sServiceAccountVerifier(
            allowed_audiences=(
                "lct-federation-ca",
                "lct-ca-org-alpha.io",
                "lct-ca-org-beta.io",
                "lct-ca-org-payment.io",
            )
        )
        v._keys_by_kid = {jwk["kid"]: jwk}
        v._last_refresh = time.time() + 3600.0
        return v

    def _mint_sa_jwt(
        self, oidc_kp: KeyPair, ns: str, sa: str, aud: str = "lct-federation-ca"
    ) -> str:
        now = time.time()
        return jws_sign_compact(
            {
                "iss": "https://kubernetes.default.svc.cluster.local",
                "aud": [aud],
                "sub": f"system:serviceaccount:{ns}:{sa}",
                "iat": now,
                "nbf": now,
                "exp": now + 1800.0,
            },
            oidc_kp,
        )

    # -------------------------------------------------------------------------
    # 1. Kind Multi-Host Configs & Rendered K8s Manifests Security Invariants
    # -------------------------------------------------------------------------
    def test_01_kind_multihost_configs_disjoint_ports_and_cidrs(self) -> None:
        self.assertEqual(parse_roles_csv("alpha,audit"), ("alpha", "audit"))
        self.assertEqual(parse_roles_csv("all"), ROLE_ORDER)
        with self.assertRaises(ValueError):
            parse_roles_csv("alpha,unknown")

        seen_ports: Set[int] = set()
        seen_pod_cidrs: Set[str] = set()
        seen_svc_cidrs: Set[str] = set()

        expected_ports = {
            role: set(allocate_role_ports(role).values())
            for role in ROLE_ORDER
        }

        for role in ROLE_ORDER:
            cfg_yaml = render_kind_cluster_config(role)
            cfg = yaml.safe_load(cfg_yaml)
            self.assertEqual(cfg["kind"], "Cluster")
            pod_cidr = cfg["networking"]["podSubnet"]
            svc_cidr = cfg["networking"]["serviceSubnet"]
            self.assertNotIn(pod_cidr, seen_pod_cidrs)
            self.assertNotIn(svc_cidr, seen_svc_cidrs)
            seen_pod_cidrs.add(pod_cidr)
            seen_svc_cidrs.add(svc_cidr)

            mappings = cfg["nodes"][0]["extraPortMappings"]
            role_ports: Set[int] = set()
            for m in mappings:
                c_port = int(m["containerPort"])
                h_port = int(m["hostPort"])
                self.assertEqual(c_port, h_port)
                self.assertEqual(m["listenAddress"], "0.0.0.0")
                self.assertEqual(m["protocol"], "TCP")
                self.assertNotIn(c_port, FORBIDDEN_HOST_PORTS)
                self.assertNotIn(c_port, seen_ports)
                seen_ports.add(c_port)
                role_ports.add(c_port)
            self.assertEqual(role_ports, expected_ports[role])

            # Verify rendered manifests for each role preserve strict key & port isolation
            docs = list(yaml.safe_load_all(render_role_k8s_manifests(role)))
            for doc in docs:
                if doc["kind"] == "Service":
                    ports_spec = doc["spec"]["ports"]
                    for ps in ports_spec:
                        if ps["port"] in (8090, 8091, 8092):
                            self.assertEqual(
                                doc["spec"]["type"],
                                "ClusterIP",
                                f"Internal service {doc['metadata']['name']} must remain ClusterIP!",
                            )
                        if doc["spec"]["type"] == "NodePort":
                            self.assertIn(int(ps["nodePort"]), expected_ports[role])
                if doc["kind"] == "Deployment":
                    dep_name = doc["metadata"]["name"]
                    pod_spec = doc["spec"]["template"]["spec"]
                    self.assertFalse(pod_spec.get("automountServiceAccountToken", True))
                    vols = pod_spec.get("volumes") or []
                    secret_names = [
                        v["secret"]["secretName"] for v in vols if "secret" in v
                    ]
                    if dep_name == "audit-collector":
                        # `audit-collector` holds ZERO domain CA keys and ZERO K8s SA tokens!
                        for s_name in secret_names:
                            self.assertNotIn("ca-keys", s_name)
                        for v in vols:
                            self.assertNotIn("projected", v)
                    elif not dep_name.endswith("-ca"):
                        for s_name in secret_names:
                            self.assertNotIn("ca-keys", s_name)
                    if dep_name in (
                        "orchestrator-alpha",
                        "hotel-specialist-primary",
                        "hotel-specialist-backup",
                        "settlement-converger",
                    ):
                        app_env_names = {
                            e["name"]: e.get("value")
                            for e in pod_spec["containers"][0].get("env", [])
                        }
                        self.assertEqual(app_env_names.get("LCT_ENABLE_FAULT_INJECTION"), "true")

    # -------------------------------------------------------------------------
    # 2. CoreDNS Sanitization (`host.docker.internal` Preserved) & IPv4 Validation
    # -------------------------------------------------------------------------
    def test_02_coredns_hosts_patching_idempotency_and_ipv4_validation(self) -> None:
        self.assertEqual(validate_ipv4_address("10.29.77.23", "--ip"), "10.29.77.23")
        self.assertEqual(validate_ipv4_address("192.168.1.6", "--ip"), "192.168.1.6")
        for bad_ip in (
            "",
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.5",
            "::1",
            "10.29.77.23/24",
            "010.29.77.23",
            "999.1.2.3",
            "alpha.local",
        ):
            with self.assertRaises(ValueError, msg=f"Expected rejection for {bad_ip!r}"):
                validate_ipv4_address(bad_ip, "--ip")

        legacy_corefile = (
            ".:53 {\n"
            "    errors\n"
            "    health {\n"
            "       lameduck 5s\n"
            "    }\n"
            "    ready\n"
            "    hosts {\n"
            "        192.168.65.254 host.docker.internal\n"
            "        10.29.77.24 beta-ca.org-beta.io\n"
            "        10.29.77.23 audit-collector.org-audit.io\n"
            "        fallthrough\n"
            "    }\n"
            "    kubernetes cluster.local in-addr.arpa ip6.arpa {\n"
            "       pods insecure\n"
            "       fallthrough in-addr.arpa ip6.arpa\n"
            "    }\n"
            "    forward . /etc/resolv.conf\n"
            "}\n"
        )
        sanitized_1 = sanitize_coredns_corefile(legacy_corefile)
        # Exactly ONE `hosts {` stanza, `host.docker.internal` preserved, zero cross-domain FQDNs!
        self.assertEqual(sanitized_1.count("hosts {"), 1)
        self.assertIn("192.168.65.254 host.docker.internal", sanitized_1)
        self.assertNotIn("org-beta.io", sanitized_1)
        self.assertNotIn("org-audit.io", sanitized_1)
        self.assertIn("kubernetes cluster.local", sanitized_1)

        # Idempotent re-sanitization
        self.assertEqual(sanitized_1, sanitize_coredns_corefile(sanitized_1))

    # -------------------------------------------------------------------------
    # 3. Trust Anchor Pinning, Stable CA Roots, & Keyless TLS 1.3 Audit Collector
    # -------------------------------------------------------------------------
    def test_03_trust_anchor_pinning_fail_closed_and_tls13_audit_collector(self) -> None:
        oidc_kp = KeyPair.generate("RS256")
        sec_list, td_beta, anchor_line_beta = generate_domain_ca_secret_bundle("beta")
        self.assertEqual(td_beta, "org-beta.io")
        sec_data = sec_list[0]["stringData"]

        # Restarting AutonomousDomainCAService from same K8s Secret produces identical anchor!
        ca_b1 = AutonomousDomainCAService(
            trust_domain="org-beta.io",
            allowed_k8s_namespace="lineage-beta",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
            ca_private_key_pem=sec_data["ca_private_key.pem"],
            x509_private_key_pem=sec_data["x509_private_key.pem"],
            x509_root_cert_pem=sec_data["x509_root_cert.pem"],
        )
        u_b1 = ca_b1.start()
        expected_beta_anchor = anchor_line_beta.split()[1]
        self.assertEqual(ca_b1.trust_anchor, expected_beta_anchor)
        ca_b1.stop()

        ca_b2 = AutonomousDomainCAService(
            trust_domain="org-beta.io",
            allowed_k8s_namespace="lineage-beta",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
            ca_private_key_pem=sec_data["ca_private_key.pem"],
            x509_private_key_pem=sec_data["x509_private_key.pem"],
            x509_root_cert_pem=sec_data["x509_root_cert.pem"],
        )
        u_b2 = ca_b2.start()

        # Keyless TLS 1.3 `audit-collector` backed by `MinimalAuditTLSCAService` (`org-audit.io`)
        with tempfile.TemporaryDirectory() as tmpdir:
            csr_file = Path(tmpdir) / "csr_token"
            csr_secret = secrets.token_urlsafe(36)
            csr_file.write_text(csr_secret, encoding="utf-8")

            audit_ca = MinimalAuditTLSCAService(
                csr_token_file=str(csr_file), host="127.0.0.1", port=0
            )
            u_audit_ca = audit_ca.http.start()

            tls_kp = KeyPair.generate("ES256")
            r_csr = httpx.post(
                f"{u_audit_ca}/v1/ca/issue-audit-tls",
                json={
                    "public_jwk": tls_kp.public_jwk(),
                    "pop_jws": create_ca_pop_jws(tls_kp, csr_secret),
                    "ttl_seconds": 300.0,
                },
                headers={"Authorization": f"Bearer {csr_secret}"},
            )
            self.assertEqual(r_csr.status_code, 200)
            csr_json = r_csr.json()
            audit_pub_bundle = csr_json["bundle"]
            audit_anchor = audit_pub_bundle["trust_anchor"]
            self.assertTrue(audit_anchor.endswith(":keyless"))

            local_aud_store = X509FederationTrustStore()
            local_aud_store.register_domain_root_pem(
                "org-audit.io", audit_pub_bundle["x509_root_pem"]
            )
            aud_mtls = WorkloadMTLSBundle(
                spiffe_id="spiffe://org-audit.io/ns/lineage-audit/sa/audit-collector",
                keypair=tls_kp,
                leaf_cert_pem=csr_json["x509_leaf_pem"],
                trust_store=local_aud_store,
            )

            pin_store = TrustAnchorPinStore()
            syncer = FederationBundleSyncer(
                peer_ca_urls={"org-beta.io": u_b2},
                anchor_store=pin_store,
                require_pinned_anchors=True,
            )

            audit_collector = AuditCollectorService(
                trust_resolver=syncer.trust_resolver,
                host="localhost",
                port=0,
                ssl_context_provider=aud_mtls.server_ssl_context_provider(
                    require_client_cert=False
                ),
                public_bundle_provider=lambda: dict(audit_pub_bundle),
            )
            u_audit_https = audit_collector.start()
            syncer.audit_ca_url = u_audit_https

            try:
                # 1) Unpinned peer MUST fail closed immediately!
                with self.assertRaises(FederationSecurityError) as ctx_unpinned:
                    syncer.sync_all(require_all=True, max_wait_sec=2.0)
                self.assertIn("Missing required trust anchor pin", str(ctx_unpinned.exception))
                self.assertEqual(syncer.trust_resolver.trusted_domains(), [])

                # 2) Deliberately wrong pin MUST fail closed and NOT import root!
                bad_anchor = f"sha256:{'0' * 64}:{'1' * 64}"
                pin_store.set_pin("org-beta.io", bad_anchor)
                pin_store.set_pin("org-audit.io", audit_anchor)
                with self.assertRaises(FederationSecurityError) as ctx_mismatch:
                    syncer.sync_all(require_all=True, max_wait_sec=2.0)
                self.assertIn("MISMATCH", str(ctx_mismatch.exception))
                self.assertIn("trust add", str(ctx_mismatch.exception))
                self.assertEqual(syncer.trust_resolver.trusted_domains(), [])

                # 3) Exact verified pins pass and enable TLS 1.3 audit shipping & authenticated reads!
                pin_store.set_pin("org-beta.io", expected_beta_anchor)
                syncer.sync_all(require_all=True, max_wait_sec=3.0)
                ready_ok, _ = syncer.is_ready()
                self.assertTrue(ready_ok)

                aud_client = AuditCollectorClient(
                    u_audit_https,
                    signer=ca_b2.ca,
                    ssl_context_provider=syncer.audit_ssl_context,
                )
                emitter = AuditStreamEmitter(ca_b2.ca, collector_client=aud_client)
                emitter.emit(
                    event_type=AuditEventType.ROOT_MINT,
                    task_id="task-m6-tls-audit",
                    sub="user:bob@org-beta.io",
                    lineage_path="/task-m6-tls-audit/BetaRoot",
                    hop_index=0,
                    epoch=0,
                    root_block_hash="rbh-1",
                    current_block_hash="rbh-1",
                    decision="ALLOW",
                )
                fetched = aud_client.fetch_entries(task_id="task-m6-tls-audit")
                self.assertEqual(len(fetched), 1)
                self.assertEqual(fetched[0].task_id, "task-m6-tls-audit")
            finally:
                audit_collector.stop()
                aud_mtls.cleanup()
                audit_ca.http.stop()
                ca_b2.stop()

    # -------------------------------------------------------------------------
    # 4. Trust Hot-Reload (Client AND Server mTLS 1.3 Contexts, Zero Restart)
    # -------------------------------------------------------------------------
    def test_04_trust_hot_reload_client_and_server_mtls_without_restart(self) -> None:
        oidc_kp = KeyPair.generate("RS256")
        ca_alpha = AutonomousDomainCAService(
            trust_domain="org-alpha.io",
            allowed_k8s_namespace="lineage-alpha",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
        )
        ca_beta = AutonomousDomainCAService(
            trust_domain="org-beta.io",
            allowed_k8s_namespace="lineage-beta",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
        )
        u_alpha = ca_alpha.start()
        u_beta = ca_beta.start()

        with tempfile.TemporaryDirectory() as tmpdir:
            pins_dir = Path(tmpdir) / "anchors"
            pins_dir.mkdir()
            sa_alpha_file = Path(tmpdir) / "sa_alpha"
            sa_beta_file = Path(tmpdir) / "sa_beta"
            sa_alpha_file.write_text(
                self._mint_sa_jwt(oidc_kp, "lineage-alpha", "orchestrator-alpha"),
                encoding="utf-8",
            )
            sa_beta_file.write_text(
                self._mint_sa_jwt(oidc_kp, "lineage-beta", "flight-specialist"),
                encoding="utf-8",
            )

            # Alpha starts WITHOUT `org-beta.io` pinned in ConfigMap dir -> `org-beta.io` NOT trusted yet!
            alpha_pins = TrustAnchorPinStore(anchors_dir=str(pins_dir))
            id_a, res_a, mtls_a, sync_a = bootstrap_autonomous_workload(
                u_alpha,
                {"org-beta.io": u_beta},
                sa_token_path=str(sa_alpha_file),
                require_all_peers=False,
                anchor_store=alpha_pins,
                require_pinned_anchors=True,
                enable_auto_renewal=False,
            )

            # Beta already trusts Alpha
            beta_pins = TrustAnchorPinStore(
                initial_pins={"org-alpha.io": ca_alpha.trust_anchor}
            )
            id_b, res_b, mtls_b, sync_b = bootstrap_autonomous_workload(
                u_beta,
                {"org-alpha.io": u_alpha},
                sa_token_path=str(sa_beta_file),
                require_all_peers=True,
                anchor_store=beta_pins,
                require_pinned_anchors=True,
                enable_auto_renewal=False,
            )

            loopback_sec = "m6-hotreload-loopback-secret-0123456789"
            app_srv = ManagedHTTPService(
                "dummy-app",
                lambda _r: (200, {"ok": True}, {}),
                host="127.0.0.1",
                port=0,
            )
            app_url = app_srv.start()

            alpha_port = find_free_port("127.0.0.1")
            alpha_origin = f"https://localhost:{alpha_port}"
            sidecar_a = LineageSidecar(
                identity=id_a,
                trust_resolver=res_a,
                app_upstream_url=app_url,
                loopback_secret=loopback_sec,
                is_tool_server=True,
                mode=VerificationMode.LOCAL_FULL_CHAIN,
                inbound_host="127.0.0.1",
                inbound_port=alpha_port,
                public_origin=alpha_origin,
                mtls_bundle=mtls_a,
                readiness_check=sync_a.is_ready,
            )
            sidecar_a.start()

            beta_srv = ManagedHTTPService(
                "beta-mtls-srv",
                lambda r: (200, {"peer": r.peer_spiffe_id, "tls": r.tls_version}, {}),
                host="127.0.0.1",
                port=0,
                ssl_context_provider=mtls_b.server_ssl_context_provider(
                    require_client_cert=True
                ),
                peer_cert_verifier=mtls_b.trust_store.verify_peer_der_cert,
            )
            beta_srv.start()
            beta_https = f"https://localhost:{beta_srv.port}"

            try:
                # Before pinning `org-beta.io`:
                # (1) Alpha readiness is 503
                r_ready_before = httpx.get(f"{sidecar_a.outbound_url}/readyz")
                self.assertEqual(r_ready_before.status_code, 503)

                # (2) Beta client connecting to Alpha server mTLS is REJECTED (server trust store lacks Beta root)
                with self.assertRaises(Exception):
                    with httpx.Client(
                        verify=mtls_b.verify_for_target(
                            target_url=alpha_origin, expected_trust_domain="org-alpha.io"
                        ),
                        timeout=2.0,
                    ) as cli_b:
                        cli_b.get(f"{alpha_origin}/healthz")

                # (3) Alpha client connecting to Beta server mTLS is REJECTED (client trust store lacks Beta root)
                with self.assertRaises(Exception):
                    with httpx.Client(
                        verify=mtls_a.verify_for_target(
                            target_url=beta_https, expected_trust_domain="org-beta.io"
                        ),
                        timeout=2.0,
                    ) as cli_a:
                        cli_a.get(f"{beta_https}/healthz")

                # Write `org-beta.io` pin into ConfigMap directory & sync — ZERO service restart!
                (pins_dir / "org-beta.io").write_text(
                    f"org-beta.io {ca_beta.trust_anchor}\n", encoding="utf-8"
                )
                sync_a.sync_all(require_all=True, max_wait_sec=3.0)

                r_ready_after = httpx.get(f"{sidecar_a.outbound_url}/readyz")
                self.assertEqual(r_ready_after.status_code, 200)

                # BOTH server mTLS (Beta -> Alpha) AND client mTLS (Alpha -> Beta) now succeed without restart!
                with httpx.Client(
                    verify=mtls_b.verify_for_target(
                        target_url=alpha_origin, expected_trust_domain="org-alpha.io"
                    ),
                    timeout=3.0,
                ) as cli_b2:
                    rh = cli_b2.get(f"{alpha_origin}/healthz")
                    self.assertEqual(rh.status_code, 200)

                with httpx.Client(
                    verify=mtls_a.verify_for_target(
                        target_url=beta_https, expected_trust_domain="org-beta.io"
                    ),
                    timeout=3.0,
                ) as cli_a2:
                    rb = cli_a2.get(f"{beta_https}/healthz")
                    self.assertEqual(rb.status_code, 200)
                    self.assertEqual(rb.json()["tls"], "TLSv1.3")

                # Corrupting the pin in ConfigMap immediately evicts `org-beta.io` on BOTH server & client!
                (pins_dir / "org-beta.io").write_text(
                    f"org-beta.io sha256:{'a' * 64}:{'b' * 64}\n", encoding="utf-8"
                )
                sync_a.reconcile_anchor_evictions()
                self.assertEqual(
                    httpx.get(f"{sidecar_a.outbound_url}/readyz").status_code, 503
                )
                with self.assertRaises(Exception):
                    with httpx.Client(
                        verify=mtls_b.verify_for_target(
                            target_url=alpha_origin, expected_trust_domain="org-alpha.io"
                        ),
                        timeout=2.0,
                    ) as cli_b3:
                        cli_b3.get(f"{alpha_origin}/healthz")
            finally:
                sync_a.stop_background_refresh()
                sync_b.stop_background_refresh()
                sidecar_a.stop()
                beta_srv.stop()
                app_srv.stop()
                mtls_a.cleanup()
                mtls_b.cleanup()
                ca_alpha.stop()
                ca_beta.stop()

    # -------------------------------------------------------------------------
    # 5. Startup-Order Independence (Absent Peers -> Auto-Ready Later)
    # -------------------------------------------------------------------------
    def test_05_startup_with_absent_peers_and_auto_readiness(self) -> None:
        oidc_kp = KeyPair.generate("RS256")
        ca_beta = AutonomousDomainCAService(
            trust_domain="org-beta.io",
            allowed_k8s_namespace="lineage-beta",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
        )
        u_beta = ca_beta.start()
        future_alpha_port = find_free_port("127.0.0.1")
        future_alpha_url = f"http://127.0.0.1:{future_alpha_port}"

        with tempfile.TemporaryDirectory() as tmpdir:
            sa_beta_file = Path(tmpdir) / "sa_beta_rev"
            sa_beta_file.write_text(
                self._mint_sa_jwt(oidc_kp, "lineage-beta", "beta-revocation"),
                encoding="utf-8",
            )
            pin_store = TrustAnchorPinStore()
            # Peer `org-alpha.io` is NOT running yet (`ConnectionRefusedError`)!
            id_rev, res_rev, mtls_rev, sync_rev = bootstrap_autonomous_workload(
                u_beta,
                {"org-alpha.io": future_alpha_url},
                sa_token_path=str(sa_beta_file),
                require_all_peers=False,
                anchor_store=pin_store,
                require_pinned_anchors=True,
                enable_auto_renewal=False,
                refresh_interval_sec=0.35,
            )
            rev_svc = RevocationService(
                id_rev,
                res_rev,
                strict_domain_isolation=True,
                host="127.0.0.1",
                port=0,
                mtls_bundle=mtls_rev,
                readiness_check=sync_rev.is_ready,
            )
            rev_url = rev_svc.start()
            ca_alpha: AutonomousDomainCAService | None = None
            try:
                # Liveness `/healthz` is 200 immediately; Readiness `/readyz` is 503
                self.assertEqual(httpx.get(f"{rev_url}/healthz").status_code, 200)
                r_not_ready = httpx.get(f"{rev_url}/readyz")
                self.assertEqual(r_not_ready.status_code, 503)
                self.assertEqual(
                    r_not_ready.json()["missing_domains"], ["org-alpha.io"]
                )

                # Now start `org-alpha.io` CA on that exact port and pin its anchor!
                ca_alpha = AutonomousDomainCAService(
                    trust_domain="org-alpha.io",
                    allowed_k8s_namespace="lineage-alpha",
                    k8s_verifier=self._make_k8s_verifier(oidc_kp),
                    host="127.0.0.1",
                    port=future_alpha_port,
                )
                ca_alpha.start()
                pin_store.set_pin("org-alpha.io", ca_alpha.trust_anchor)

                became_ready = False
                for _ in range(25):
                    if httpx.get(f"{rev_url}/readyz").status_code == 200:
                        became_ready = True
                        break
                    time.sleep(0.2)
                self.assertTrue(became_ready, "Workload did not auto-transition to Ready!")
            finally:
                sync_rev.stop_background_refresh()
                rev_svc.stop()
                mtls_rev.cleanup()
                if ca_alpha is not None:
                    ca_alpha.stop()
                ca_beta.stop()

    # -------------------------------------------------------------------------
    # 6. Automatic SVID / X.509 Renewal Across >= 2 Cycles With Live Traffic
    # -------------------------------------------------------------------------
    def test_06_automatic_svid_and_x509_renewal_across_multiple_cycles_with_live_traffic(
        self,
    ) -> None:
        oidc_kp = KeyPair.generate("RS256")
        ca_alpha = AutonomousDomainCAService(
            trust_domain="org-alpha.io",
            allowed_k8s_namespace="lineage-alpha",
            authorized_gateway_sa="e2e-user-gateway",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
        )
        u_alpha = ca_alpha.start()

        with tempfile.TemporaryDirectory() as tmpdir:
            sa_agent_file = Path(tmpdir) / "sa_orch"
            sa_gw_file = Path(tmpdir) / "sa_gw"
            sa_rev_file = Path(tmpdir) / "sa_rev"
            sa_agent_file.write_text(
                self._mint_sa_jwt(oidc_kp, "lineage-alpha", "orchestrator-alpha"),
                encoding="utf-8",
            )
            sa_gw_file.write_text(
                self._mint_sa_jwt(oidc_kp, "lineage-alpha", "e2e-user-gateway"),
                encoding="utf-8",
            )
            sa_rev_file.write_text(
                self._mint_sa_jwt(oidc_kp, "lineage-alpha", "alpha-revocation"),
                encoding="utf-8",
            )

            id_rev, res_shared, mtls_rev, sync_rev = bootstrap_autonomous_workload(
                u_alpha,
                {},
                sa_token_path=str(sa_rev_file),
                svid_ttl_seconds=4.0,
                enable_auto_renewal=True,
            )
            rev_svc = RevocationService(id_rev, res_shared, host="127.0.0.1", port=0)
            rev_url = rev_svc.start()
            rev_rep = RevocationReplicaClient(rev_url, res_shared)
            dir_svc = AgentDirectoryService(
                res_shared, local_trust_domain="org-alpha.io", host="127.0.0.1", port=0
            )
            dir_url = dir_svc.start()
            dir_cli = AgentDirectoryClient(dir_url, res_shared)

            audit_svc = AuditCollectorService(res_shared, host="127.0.0.1", port=0)
            audit_url = audit_svc.start()

            # Short 4.0s SVID TTL -> automatic background renewal every ~2.0s!
            id_orch, res_orch, mtls_orch, sync_orch = bootstrap_autonomous_workload(
                u_alpha,
                {},
                sa_token_path=str(sa_agent_file),
                svid_ttl_seconds=4.0,
                enable_auto_renewal=True,
                rotate_keypair_on_renewal=True,
            )
            id_gw, _, mtls_gw, sync_gw = bootstrap_autonomous_workload(
                u_alpha,
                {},
                sa_token_path=str(sa_gw_file),
                svid_ttl_seconds=4.0,
                enable_auto_renewal=True,
            )

            orch_port = find_free_port("127.0.0.1")
            orch_origin = f"https://localhost:{orch_port}"
            loopback_sec = "m6-renewal-loopback-secret-9876543210"
            app_srv = ManagedHTTPService(
                "mcp-tool-app",
                lambda r: (
                    (200, {"status": "ok", "tool_out": "renewed-ok"}, {})
                    if hmac.compare_digest(
                        r.header("X-LCT-Loopback-Auth") or "", loopback_sec
                    )
                    else (403, {"error": "forbidden"}, {})
                ),
                host="127.0.0.1",
                port=0,
            )
            app_url = app_srv.start()

            init_card = AgentCard.sign_and_create(
                identity=id_orch,
                name="Orchestrator Alpha",
                endpoint=orch_origin,
                return_endpoint=orch_origin,
                skills=["travel.orchestrate"],
                priority=10,
                ttl_seconds=4.0,
                version=100,
            )
            dir_cli.register(init_card)

            aud_emitter = AuditStreamEmitter(
                signer=id_orch,
                collector_client=AuditCollectorClient(audit_url),
            )
            sidecar_orch = LineageSidecar(
                identity=id_orch,
                trust_resolver=res_orch,
                app_upstream_url=app_url,
                loopback_secret=loopback_sec,
                mode=VerificationMode.LOCAL_FULL_CHAIN,
                revocation_replica=rev_rep,
                directory_client=dir_cli,
                audit_emitter=aud_emitter,
                agent_card=init_card,
                is_tool_server=True,
                inbound_host="127.0.0.1",
                inbound_port=orch_port,
                public_origin=orch_origin,
                mtls_bundle=mtls_orch,
            )

            card_ver_box = {"ver": 100}

            def _on_renew(_ident: Any, _mb: Any) -> None:
                sidecar_orch.on_identity_renewed()
                card_ver_box["ver"] += 1
                refreshed = AgentCard.sign_and_create(
                    identity=id_orch,
                    name="Orchestrator Alpha",
                    endpoint=orch_origin,
                    return_endpoint=orch_origin,
                    skills=["travel.orchestrate"],
                    priority=10,
                    ttl_seconds=4.0,
                    version=card_ver_box["ver"],
                )
                dir_cli.register(refreshed)
                sidecar_orch.set_agent_card(refreshed)

            assert sync_orch.identity_renewer is not None
            sync_orch.identity_renewer.add_callback(_on_renew)
            sidecar_orch.start()

            try:
                initial_svid = id_orch.workload_svid
                initial_jkt = id_orch.jkt

                # Helper sending a full mTLS 1.3 + DPoP + LCT tool call using latest AgentCard from directory
                def _send_live_tool_call(seq_idx: int) -> int:
                    cards = dir_cli.discover(skill="travel.orchestrate", only_healthy=True)
                    self.assertEqual(len(cards), 1, "Renewed AgentCard must remain discoverable!")
                    live_card = cards[0]
                    tok = mint_root_token(
                        ca_alpha.ca,
                        task_id=f"task-m6-renew-{seq_idx}",
                        sub="user:alice@org-alpha.io",
                        sender_jkt=id_gw.jkt,
                        first_hop_spiffe_id=live_card.spiffe_id,
                        first_hop_jkt=live_card.jkt,
                        permissions=PermissionLattice.create(
                            tools=["search_flight"], max_amount=200.0, max_calls=4
                        ),
                    )
                    compact = tok.encode_compact()
                    mcp_url = f"{orch_origin}/mcp"
                    dpop = create_dpop_proof(id_gw, "POST", mcp_url, compact)
                    with httpx.Client(
                        verify=mtls_gw.verify_for_target(
                            target_url=orch_origin,
                            expected_spiffe_id=live_card.spiffe_id,
                        ),
                        timeout=3.0,
                    ) as cli:
                        resp = cli.post(
                            mcp_url,
                            json={
                                "jsonrpc": "2.0",
                                "id": seq_idx,
                                "method": "tools/call",
                                "params": {"name": "search_flight", "arguments": {}},
                            },
                            headers={"Authorization": f"DPoP {compact}", "DPoP": dpop},
                        )
                    return resp.status_code

                self.assertEqual(_send_live_tool_call(1), 200)
                rev_rep.revoke_prefix(
                    caller=ca_alpha.ca,
                    prefix="/task-m6-historical-before-svid-rot",
                    reason="test_historical_svid_eval_ts",
                )

                # Simulate kubelet rotating the projected SA token file on disk mid-flight!
                time.sleep(1.2)
                sa_agent_file.write_text(
                    self._mint_sa_jwt(oidc_kp, "lineage-alpha", "orchestrator-alpha"),
                    encoding="utf-8",
                )

                # Wait across >= 2 full renewal cycles (total > 4.6s, exceeding original 4.0s TTL!)
                deadline = time.time() + 6.5
                while time.time() < deadline:
                    if (
                        sync_orch.identity_renewer.renewal_count >= 2
                        and sync_gw.identity_renewer is not None
                        and sync_gw.identity_renewer.renewal_count >= 2
                    ):
                        break
                    time.sleep(0.3)

                # Wait slightly more so we are strictly past the initial 4.0s SVID expiry timestamp!
                time.sleep(0.9)
                self.assertGreaterEqual(sync_orch.identity_renewer.renewal_count, 2)
                self.assertGreaterEqual(id_orch.renewal_generation, 2)
                self.assertGreaterEqual(mtls_orch.generation, 2)
                self.assertNotEqual(id_orch.workload_svid, initial_svid)
                self.assertNotEqual(id_orch.jkt, initial_jkt)
                self.assertGreaterEqual(card_ver_box["ver"], 102)

                # Live mTLS + LCT + AuditCollector ingest MUST still succeed after original TTL expired!
                self.assertEqual(_send_live_tool_call(2), 200)
                # Brand-new replica syncing historical events from v0 after revocation SVID rotated MUST succeed!
                late_rep = RevocationReplicaClient(rev_url, res_shared)
                self.assertGreaterEqual(late_rep.sync_now(), 1)
                self.assertIsNotNone(
                    late_rep.trie.check_lineage_path(
                        "/task-m6-historical-before-svid-rot/OrchestratorAlpha",
                        trust_domain="org-alpha.io",
                    )
                )
                aud_entries = audit_svc.get_all_entries()
                self.assertGreaterEqual(len(aud_entries), 4)
            finally:
                aud_emitter.stop()
                sync_orch.stop_background_refresh()
                sync_gw.stop_background_refresh()
                sync_rev.stop_background_refresh()
                sidecar_orch.stop()
                app_srv.stop()
                audit_svc.stop()
                dir_svc.stop()
                rev_svc.stop()
                mtls_orch.cleanup()
                mtls_gw.cleanup()
                mtls_rev.cleanup()
                ca_alpha.stop()

    # -------------------------------------------------------------------------
    # 7. Clock-Skew Preflight Evaluation & CLI Argument Validation
    # -------------------------------------------------------------------------
    def test_07_clock_skew_preflight_and_cli_validation(self) -> None:
        base_epoch = 1_800_000_000.0
        hdr_ok = email.utils.format_datetime(
            dt.datetime.fromtimestamp(base_epoch + 2.0, tz=dt.timezone.utc), usegmt=True
        )
        res_ok = evaluate_http_date_clock_skew(hdr_ok, local_epoch=base_epoch)
        self.assertEqual(res_ok["status"], "OK")
        self.assertTrue(res_ok["ok"])

        hdr_warn = email.utils.format_datetime(
            dt.datetime.fromtimestamp(base_epoch - 14.0, tz=dt.timezone.utc), usegmt=True
        )
        res_warn = evaluate_http_date_clock_skew(hdr_warn, local_epoch=base_epoch)
        self.assertEqual(res_warn["status"], "WARN")
        self.assertTrue(res_warn["ok"])

        hdr_fail = email.utils.format_datetime(
            dt.datetime.fromtimestamp(base_epoch + 31.0, tz=dt.timezone.utc), usegmt=True
        )
        res_fail = evaluate_http_date_clock_skew(hdr_fail, local_epoch=base_epoch)
        self.assertEqual(res_fail["status"], "FAIL")
        self.assertFalse(res_fail["ok"])

        # CLI argument validation
        parser = build_cli_parser()
        parsed_send = parser.parse_args(["send", "--text", "Book Tokyo flight", "--stream"])
        self.assertTrue(parsed_send.stream)

        for bad_argv in (
            ["send", "--text", "   "],
            ["send", "--text", "Tokyo", "--max-amount", "-5"],
            ["trust", "fetch", "--domain", "org-beta.io", "--ip", "127.0.0.1"],
            ["trust", "fetch", "--domain", "org-beta.io", "--ip", "not-an-ip"],
            ["trust", "add", "org-beta.io", "sha256:bad:digest"],
        ):
            with self.assertRaises(SystemExit):
                cli_main(bad_argv)

        # `org-audit.io` requires `:keyless`, while `org-beta.io` forbids `:keyless`
        with self.assertRaises(TrustAnchorPinError):
            cli_main(
                [
                    "trust",
                    "add",
                    "org-audit.io",
                    f"sha256:{'a' * 64}:{'b' * 64}",
                    "--roles",
                    "audit",
                ]
            )
        with self.assertRaises(TrustAnchorPinError):
            cli_main(
                [
                    "trust",
                    "add",
                    "org-beta.io",
                    f"sha256:{'a' * 64}:keyless",
                    "--roles",
                    "beta",
                ]
            )

    # -------------------------------------------------------------------------
    # 8. [HIGH-M6-01] Verified Peer Spoof Resilience + Single-Root Canonicality
    # -------------------------------------------------------------------------
    def test_08_qa_high_m6_01_spoof_resilience_and_single_root_canonicality(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io", alg="ES256")
        x509_alpha = X509DomainAuthority("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io", alg="ES256")
        x509_beta = X509DomainAuthority("org-beta.io")

        genuine_bundle: Dict[str, Any] = ca_beta.export_public_bundle()
        genuine_bundle["x509_root_pem"] = x509_beta.export_root_pem()
        genuine_pin = compute_bundle_trust_anchor(genuine_bundle)

        ca_rogue = TrustDomainCA("org-beta.io", alg="ES256")
        x509_rogue = X509DomainAuthority("org-beta.io")
        spoofed_bundle: Dict[str, Any] = ca_rogue.export_public_bundle()
        spoofed_bundle["x509_root_pem"] = x509_rogue.export_root_pem()

        mode = {"state": "genuine"}

        def _bundle_handler(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
            if req.path != "/v1/federation/bundle":
                return 404, {"error": "not_found"}, {}
            if mode["state"] == "spoof_keys":
                return 200, spoofed_bundle, {}
            if mode["state"] == "spoof_domain":
                bad_dom = dict(genuine_bundle)
                bad_dom["trust_domain"] = "org-evil.io"
                return 200, bad_dom, {}
            if mode["state"] == "malformed_pem":
                bad_pem = dict(genuine_bundle)
                bad_pem["x509_root_pem"] = "-----BEGIN CERTIFICATE-----\nCORRUPTED\n-----END CERTIFICATE-----"
                return 200, bad_pem, {}
            return 200, genuine_bundle, {}

        peer_http = ManagedHTTPService("peer-beta-bundle", _bundle_handler, host="127.0.0.1", port=0)
        peer_url = peer_http.start()

        # Real mTLS 1.3 Beta server to confirm mTLS keeps working during LAN spoofing!
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
            "spiffe://org-beta.io/ns/lineage-beta/sa/flight-specialist",
            kp_b,
            leaf_b,
            store_b,
        )
        beta_srv = ManagedHTTPService(
            "beta-mtls-target",
            lambda r: (200, {"peer": r.peer_spiffe_id}, {}),
            host="127.0.0.1",
            port=0,
            ssl_context_provider=mtls_b.server_ssl_context_provider(require_client_cert=True),
            peer_cert_verifier=store_b.verify_peer_der_cert,
        )
        beta_srv.start()
        beta_https = f"https://localhost:{beta_srv.port}"

        kp_a = KeyPair.generate("ES256")
        leaf_a = x509_alpha.issue_x509_svid(
            "spiffe://org-alpha.io/ns/lineage-alpha/sa/orchestrator-alpha",
            kp_a.public_jwk(),
            dns_names=("localhost",),
        )
        pins = TrustAnchorPinStore(initial_pins={"org-beta.io": genuine_pin})
        syncer = FederationBundleSyncer(
            peer_ca_urls={"org-beta.io": peer_url},
            anchor_store=pins,
            require_pinned_anchors=True,
        )
        syncer.x509_trust_store.register_domain_root_pem(
            "org-alpha.io", x509_alpha.export_root_pem()
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

            for attack_state in ("spoof_keys", "spoof_domain", "malformed_pem"):
                mode["state"] = attack_state
                syncer.sync_all(require_all=False, max_wait_sec=0.2)
                ready_ok, diag = syncer.is_ready()
                self.assertTrue(
                    ready_ok, f"Spoof state {attack_state!r} must NOT flip /readyz to False!"
                )
                self.assertIn("org-beta.io", syncer.trust_resolver.trusted_domains())
                self.assertTrue(syncer.x509_trust_store.has_domain("org-beta.io"))
                self.assertGreaterEqual(diag["rejected_bundle_counts"].get("org-beta.io", 0), 1)

                # Live mTLS 1.3 handshake to Beta still succeeds!
                with httpx.Client(
                    verify=mtls_a.verify_for_target(
                        target_url=beta_https, expected_trust_domain="org-beta.io"
                    ),
                    timeout=3.0,
                ) as cli:
                    r_mtls = cli.get(f"{beta_https}/healthz")
                    self.assertEqual(r_mtls.status_code, 200)

            # Multi-root smuggling (`x509_roots_pem` with >1 cert or conflicting PEMs) is strictly rejected!
            multi_root_bundle = dict(genuine_bundle)
            multi_root_bundle["x509_roots_pem"] = [
                x509_beta.export_root_pem(),
                x509_rogue.export_root_pem(),
            ]
            with self.assertRaises(TrustAnchorPinError):
                compute_bundle_trust_anchor(multi_root_bundle)
            with self.assertRaises(FederationSecurityError):
                syncer._verify_and_apply_bundle("org-beta.io", multi_root_bundle)
            # And existing verified peer was STILL not evicted!
            self.assertTrue(syncer.is_ready()[0])

            conflicting_bundle = dict(genuine_bundle)
            conflicting_bundle["x509_roots_pem"] = [x509_rogue.export_root_pem()]
            with self.assertRaises(TrustAnchorPinError):
                compute_bundle_trust_anchor(conflicting_bundle)

            # Local pin removal DOES evict immediately via reconcile_anchor_evictions()
            pins.remove_pin("org-beta.io")
            self.assertTrue(syncer.reconcile_anchor_evictions())
            self.assertFalse(syncer.is_ready()[0])
            self.assertNotIn("org-beta.io", syncer.trust_resolver.trusted_domains())
            self.assertFalse(syncer.x509_trust_store.has_domain("org-beta.io"))
        finally:
            mtls_a.cleanup()
            mtls_b.cleanup()
            beta_srv.stop()
            peer_http.stop()

    # -------------------------------------------------------------------------
    # 9. [HIGH-M6-02] Audit Timestamp Bounds + Revocation Per-Instance Monotonicity
    # -------------------------------------------------------------------------
    def test_09_qa_high_m6_02_audit_timestamp_bounds_and_revocation_instance_monotonicity(
        self,
    ) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io", alg="ES256")
        ca_pay = TrustDomainCA("org-payment.io", alg="ES256")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_pay)

        now = time.time()
        expired_ts = now - 86400.0
        expired_id = ca_alpha.issue_workload(
            "/ns/lineage-alpha/sa/orchestrator-alpha", ttl_seconds=60.0, now=expired_ts
        )
        collector = AuditCollectorService(
            trust_resolver=resolver,
            host="127.0.0.1",
            port=0,
            max_ingest_age_seconds=3600.0,
            max_entries=3,
            max_streams=2,
        )

        # (A) 24-hour back-dated AuditEntry under expired SVID -> REJECTED!
        em_old = AuditStreamEmitter(signer=expired_id, stream_id="backdated-stream")
        with mock.patch("lineage.audit.logger.time.time", return_value=expired_ts + 10.0):
            backdated_entry = em_old.emit(
                event_type=AuditEventType.TOOL_INVOCATION,
                task_id="task-ancient",
                sub="user:alice@org-alpha.io",
                lineage_path="/task-ancient/OrchestratorAlpha",
                hop_index=0,
                epoch=0,
                root_block_hash="r1",
                current_block_hash="c1",
                decision="ALLOW",
            )
        with self.assertRaises(AuditIngestError):
            collector.append_direct(backdated_entry)

        # (B) Future-dated (+1200s > +30s) AuditEntry under live SVID -> REJECTED!
        live_id = ca_alpha.issue_workload(
            "/ns/lineage-alpha/sa/orchestrator-alpha", ttl_seconds=1800.0
        )
        em_fut = AuditStreamEmitter(signer=live_id, stream_id="future-stream")
        with mock.patch("lineage.audit.logger.time.time", return_value=now + 1200.0):
            future_entry = em_fut.emit(
                event_type=AuditEventType.TOOL_INVOCATION,
                task_id="task-future",
                sub="user:alice@org-alpha.io",
                lineage_path="/task-future/OrchestratorAlpha",
                hop_index=0,
                epoch=0,
                root_block_hash="r2",
                current_block_hash="c2",
                decision="ALLOW",
            )
        with self.assertRaises(AuditIngestError):
            collector.append_direct(future_entry)

        # (C) Per-stream timestamp rollback (`seq=1` 60s before `seq=0`) -> REJECTED!
        em_live = AuditStreamEmitter(signer=live_id, stream_id="mono-stream")
        with mock.patch("lineage.audit.logger.time.time", return_value=now):
            e0 = em_live.emit(
                event_type=AuditEventType.INBOUND_AUTHZ,
                task_id="task-mono",
                sub="user:alice@org-alpha.io",
                lineage_path="/task-mono/OrchestratorAlpha",
                hop_index=0,
                epoch=0,
                root_block_hash="r3",
                current_block_hash="c3",
                decision="ALLOW",
            )
        self.assertEqual(collector.append_direct(e0), 1)
        with mock.patch("lineage.audit.logger.time.time", return_value=now - 60.0):
            e1_rollback = em_live.emit(
                event_type=AuditEventType.TOOL_INVOCATION,
                task_id="task-mono",
                sub="user:alice@org-alpha.io",
                lineage_path="/task-mono/OrchestratorAlpha",
                hop_index=0,
                epoch=0,
                root_block_hash="r3",
                current_block_hash="c3",
                decision="ALLOW",
            )
        with self.assertRaises(AuditIngestError):
            collector.append_direct(e1_rollback)

        # (D) Bounded stream & entry capacity enforced!
        em_s2 = AuditStreamEmitter(signer=live_id, stream_id="second-stream")
        self.assertEqual(
            collector.append_direct(
                em_s2.emit(
                    event_type=AuditEventType.INBOUND_AUTHZ,
                    task_id="t-s2",
                    sub="user:alice@org-alpha.io",
                    lineage_path="/t-s2/O",
                    hop_index=0,
                    epoch=0,
                    root_block_hash="r",
                    current_block_hash="c",
                    decision="ALLOW",
                )
            ),
            2,
        )
        em_s3 = AuditStreamEmitter(signer=live_id, stream_id="third-stream-overflow")
        with self.assertRaises(AuditIngestError):
            collector.append_direct(
                em_s3.emit(
                    event_type=AuditEventType.INBOUND_AUTHZ,
                    task_id="t-s3",
                    sub="user:alice@org-alpha.io",
                    lineage_path="/t-s3/O",
                    hop_index=0,
                    epoch=0,
                    root_block_hash="r",
                    current_block_hash="c",
                    decision="ALLOW",
                )
            )
        self.assertEqual(
            collector.append_direct(
                em_s2.emit(
                    event_type=AuditEventType.TOOL_INVOCATION,
                    task_id="t-s2",
                    sub="user:alice@org-alpha.io",
                    lineage_path="/t-s2/O",
                    hop_index=0,
                    epoch=0,
                    root_block_hash="r",
                    current_block_hash="c",
                    decision="ALLOW",
                )
            ),
            3,
        )
        with self.assertRaises(AuditIngestError):
            collector.append_direct(
                em_s2.emit(
                    event_type=AuditEventType.TOOL_INVOCATION,
                    task_id="t-s2",
                    sub="user:alice@org-alpha.io",
                    lineage_path="/t-s2/O",
                    hop_index=0,
                    epoch=0,
                    root_block_hash="r",
                    current_block_hash="c",
                    decision="ALLOW",
                )
            )

        # (E) Revocation per-instance monotonicity + restart resync
        rev_alpha_id1 = ca_alpha.issue_workload("/ns/sys/sa/revocation", ttl_seconds=600.0)
        rev_pay_id = ca_pay.issue_workload("/ns/sys/sa/revocation", ttl_seconds=600.0)

        # Mock peer server simulating same-JKT rollback, timestamp rollback, equivocation, then genuine restart!
        alpha_rev_svc1 = RevocationService(rev_alpha_id1, resolver, host="127.0.0.1", port=0)
        ev1 = alpha_rev_svc1.revoke_prefix_direct(
            "/task-r1/OrchestratorAlpha", requested_by="ca", trust_domain="org-alpha.io"
        )
        ev2 = alpha_rev_svc1.revoke_prefix_direct(
            "/task-r2/OrchestratorAlpha", requested_by="ca", trust_domain="org-alpha.io"
        )
        fed_state: Dict[str, Any] = {
            "svid": rev_alpha_id1.workload_svid,
            "version": 2,
            "events": [ev1.to_dict(), ev2.to_dict()],
        }

        def _mock_fed_handler(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
            since = int(req.query.get("since_version", 0))
            evs = [e for e in fed_state["events"] if int(e["version"]) > since]
            return (
                200,
                {
                    "trust_domain": "org-alpha.io",
                    "version": fed_state["version"],
                    "service_svid": fed_state["svid"],
                    "events": evs,
                },
                {},
            )

        mock_peer = ManagedHTTPService("mock-alpha-rev-fed", _mock_fed_handler, host="127.0.0.1", port=0)
        peer_fed_url = mock_peer.start()
        pay_rev_svc = RevocationService(
            rev_pay_id,
            resolver,
            strict_domain_isolation=True,
            peer_revocation_urls={"org-alpha.io": peer_fed_url},
            host="127.0.0.1",
            port=0,
        )
        pay_rev_url = pay_rev_svc.start()
        replica = RevocationReplicaClient(pay_rev_url, resolver)
        try:
            self.assertEqual(replica.sync_now(required_trust_domains=["org-alpha.io"]), 2)

            # 1. Version rollback (`version=1 < 2`) under SAME `rev_alpha_id1` JKT -> MUST raise RevocationError!
            fed_state["version"] = 1
            fed_state["events"] = [ev1.to_dict()]
            with self.assertRaises(RevocationError):
                pay_rev_svc.sync_from_federation_peers(strict_required_domains=["org-alpha.io"])

            # 2. Timestamp rollback (`ev3.timestamp = ev2.timestamp - 30s`) under SAME JKT -> MUST raise RevocationError!
            back_claims = {
                "version": 3,
                "kind": "SUBTREE",
                "target": "/task-r3-back/OrchestratorAlpha",
                "reason": "backdated",
                "requested_by": "ca",
                "timestamp": ev2.timestamp - 30.0,
                "trust_domain": "org-alpha.io",
            }
            back_sig = jws_sign_compact(
                back_claims, rev_alpha_id1.keypair, typ="lct-revocation-event+jwt"
            )
            fed_state["version"] = 3
            fed_state["events"] = [
                ev1.to_dict(),
                ev2.to_dict(),
                {**back_claims, "service_signature": back_sig, "service_svid": rev_alpha_id1.workload_svid},
            ]
            with self.assertRaises(RevocationError):
                pay_rev_svc.sync_from_federation_peers(strict_required_domains=["org-alpha.io"])

            # 3. Equivocated `origin_version=2` under SAME JKT -> MUST raise RevocationError!
            equiv_claims = {
                "version": 2,
                "kind": "SUBTREE",
                "target": "/task-equivocated/OrchestratorAlpha",
                "reason": "equiv",
                "requested_by": "ca",
                "timestamp": ev2.timestamp + 1.0,
                "trust_domain": "org-alpha.io",
            }
            equiv_sig = jws_sign_compact(
                equiv_claims, rev_alpha_id1.keypair, typ="lct-revocation-event+jwt"
            )
            with self.assertRaises(RevocationError):
                pay_rev_svc.ingest_federated_event(
                    {
                        **equiv_claims,
                        "service_signature": equiv_sig,
                        "service_svid": rev_alpha_id1.workload_svid,
                    },
                    expected_peer_domain="org-alpha.io",
                )

            # 4. Genuine rolling restart (`rev_alpha_id2` has a NEW JKT, starting fresh at `version=1`):
            #    Lossless resync imports new `v1` while preserving `ev1` & `ev2`!
            rev_alpha_id2 = ca_alpha.issue_workload("/ns/sys/sa/revocation", ttl_seconds=600.0)
            alpha_rev_svc2 = RevocationService(rev_alpha_id2, resolver, host="127.0.0.1", port=0)
            ev_restarted_1 = alpha_rev_svc2.revoke_prefix_direct(
                "/task-after-restart/OrchestratorAlpha",
                requested_by="ca",
                trust_domain="org-alpha.io",
            )
            fed_state["svid"] = rev_alpha_id2.workload_svid
            fed_state["version"] = 1
            fed_state["events"] = [ev_restarted_1.to_dict()]
            self.assertEqual(
                replica.sync_now(required_trust_domains=["org-alpha.io"]), 3
            )
            self.assertIsNotNone(
                replica.trie.check_lineage_path(
                    "/task-r1/OrchestratorAlpha", trust_domain="org-alpha.io"
                )
            )
            self.assertIsNotNone(
                replica.trie.check_lineage_path(
                    "/task-after-restart/OrchestratorAlpha", trust_domain="org-alpha.io"
                )
            )
        finally:
            pay_rev_svc.stop()
            mock_peer.stop()

    # -------------------------------------------------------------------------
    # 10. [MEDIUM-M6-01..03] & [LOW-M6-01..02] Remediations
    # -------------------------------------------------------------------------
    def test_10_qa_medium_and_low_m6_remediations_sse_tofu_sync_and_scripts(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        lineage_root = repo_root / "lineage"

        # (1) [MEDIUM-M6-01] Default `alpha` manifests do NOT expose permanent sync Service
        alpha_docs = list(yaml.safe_load_all(render_role_k8s_manifests("alpha")))
        svc_names = {d["metadata"]["name"] for d in alpha_docs if d["kind"] == "Service"}
        self.assertNotIn("e2e-user-gateway-sync", svc_names)
        transient_svc = render_e2e_sync_service_manifest("lineage-alpha")
        self.assertEqual(
            transient_svc["spec"]["ports"][0]["nodePort"],
            allocate_role_ports("alpha")["e2e_sync_hook"],
        )

        # (2) [MEDIUM-M6-02] `trust fetch --expect` match/mismatch + `--yes` UNVERIFIED TOFU warning
        ca_beta = TrustDomainCA("org-beta.io", alg="ES256")
        x509_beta = X509DomainAuthority("org-beta.io")
        bundle_beta = ca_beta.export_public_bundle()
        bundle_beta["x509_root_pem"] = x509_beta.export_root_pem()
        expected_anc = compute_bundle_trust_anchor(bundle_beta)
        wrong_anc = f"sha256:{'f' * 64}:{'e' * 64}"

        bundle_srv = ManagedHTTPService(
            "mock-trust-fetch",
            lambda r: (200, bundle_beta, {}) if r.path == "/v1/federation/bundle" else (404, {}, {}),
            host="127.0.0.1",
            port=0,
        )
        bundle_srv.start()
        written_pins: List[Dict[str, str]] = []
        try:
            real_http_client = httpx.Client

            def _loopback_redirect_client(*args: Any, **kwargs: Any) -> httpx.Client:
                # Redirect test peer IP 192.0.2.10 -> 127.0.0.1:<bundle_srv.port> via custom transport
                orig_client = real_http_client(*args, **kwargs)
                orig_get = orig_client.get

                def _patched_get(url: str, *g_args: Any, **g_kwargs: Any) -> Any:
                    return orig_get(url.replace("192.0.2.10", "127.0.0.1"), *g_args, **g_kwargs)

                orig_client.get = _patched_get  # type: ignore[method-assign]
                return orig_client

            with (
                mock.patch("lineage.multihost.lct_multihost_cli.httpx.Client", side_effect=_loopback_redirect_client),
                mock.patch("lineage.multihost.lct_multihost_cli._detect_local_lctmh_roles", return_value=("alpha",)),
                mock.patch("lineage.multihost.lct_multihost_cli._read_configmap_anchors", return_value={}),
                mock.patch(
                    "lineage.multihost.lct_multihost_cli._write_configmap_anchors",
                    side_effect=lambda _c, _n, d: written_pins.append(dict(d)),
                ),
            ):
                # Wrong `--expect` -> exit 1 WITHOUT pinning!
                err_buf1 = io.StringIO()
                with mock.patch("sys.stderr", new=err_buf1):
                    rc_bad = cli_main(
                        [
                            "trust",
                            "fetch",
                            "--domain",
                            "org-beta.io",
                            "--ip",
                            "192.0.2.10",
                            "--port",
                            str(bundle_srv.port),
                            "--expect",
                            wrong_anc,
                        ]
                    )
                self.assertEqual(rc_bad, 1)
                self.assertEqual(written_pins, [])
                self.assertIn("mismatch", err_buf1.getvalue().lower())

                # Matching `--expect` -> exit 0 and pins without TOFU warning!
                err_buf2 = io.StringIO()
                with mock.patch("sys.stderr", new=err_buf2):
                    rc_good = cli_main(
                        [
                            "trust",
                            "fetch",
                            "--domain",
                            "org-beta.io",
                            "--ip",
                            "192.0.2.10",
                            "--port",
                            str(bundle_srv.port),
                            "--expect",
                            expected_anc,
                        ]
                    )
                self.assertEqual(rc_good, 0)
                self.assertEqual(len(written_pins), 1)
                self.assertEqual(written_pins[0]["org-beta.io"], expected_anc)
                self.assertNotIn("UNVERIFIED TOFU", err_buf2.getvalue())

                # `--yes` WITHOUT `--expect` -> prints prominent `[SECURITY WARNING: UNVERIFIED TOFU]` to stderr!
                err_buf3 = io.StringIO()
                with mock.patch("sys.stderr", new=err_buf3):
                    rc_tofu = cli_main(
                        [
                            "trust",
                            "fetch",
                            "--domain",
                            "org-beta.io",
                            "--ip",
                            "192.0.2.10",
                            "--port",
                            str(bundle_srv.port),
                            "--yes",
                        ]
                    )
                self.assertEqual(rc_tofu, 0)
                self.assertIn("[SECURITY WARNING: UNVERIFIED TOFU]", err_buf3.getvalue())
        finally:
            bundle_srv.stop()

        # (3) [MEDIUM-M6-03] Real `A2AServerEngine` SSE stream parsing & exit-code enforcement
        from lineage.a2a.rpc import A2ARPCExecutionError

        def _sse_work(
            inv_ctx: A2AInvocationContext,
            user_msg: Message,
            emit_artifact: Callable[[Artifact], None],
        ) -> Tuple[Message, Dict[str, Any]]:
            if "FAIL_ME" in user_msg.extract_text():
                raise A2ARPCExecutionError(-32005, "simulated_downstream_failure")
            emit_artifact(
                Artifact.create(
                    name="flight-specialist-booking",
                    description="Booked flight NH-108",
                    data={"flight_no": "NH-108", "charged_usd": 580.0},
                )
            )
            return Message.create_agent(text="Trip completed.", data={"ok": True}), {}

        engine = A2AServerEngine(agent_name="test-sse-orch", work_handler=_sse_work)

        def _a2a_http_dispatch(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
            body_obj = req.json() if req.body else {}
            msg_tid = (
                ((body_obj.get("params") or {}).get("message") or {}).get("taskId")
                or f"task-sse-{secrets.token_hex(4)}"
            )
            req_headers = dict(req.headers)
            req_headers["x-lct-request-id"] = "req-sse-1"
            req_headers["x-lct-task-id"] = str(msg_tid)
            req_headers["x-lct-sub"] = "user:alice@org-alpha.io"
            req_headers["x-lct-lineage-path"] = f"/{msg_tid}/OrchestratorAlpha"
            patched_req = HTTPRequestContext(
                method=req.method,
                raw_path=req.raw_path,
                headers=req_headers,
                body=req.body,
                server_host=req.server_host,
                server_port=req.server_port,
            )
            return engine.dispatch(patched_req)

        a2a_srv = ManagedHTTPService("real-a2a-sse-test", _a2a_http_dispatch, host="127.0.0.1", port=0)
        a2a_url = a2a_srv.start()
        try:
            a2a_cli = A2AClient(agent_base_url=a2a_url, rpc_path="/a2a", timeout=5.0)
            sink_ok = io.StringIO()
            rc_ok, summary_ok = stream_and_summarize_a2a_sse(
                a2a_client=a2a_cli,
                message=Message.create_user(text="Book Tokyo trip", task_id="task-sse-ok"),
                event_sink=sink_ok,
            )
            self.assertEqual(rc_ok, 0)
            self.assertIn("TASK_STATE_WORKING", summary_ok["sse_states"])
            self.assertEqual(summary_ok["terminal_state"], TaskState.COMPLETED.value)
            self.assertEqual(summary_ok["artifact_update_count"], 1)
            self.assertEqual(summary_ok["artifact_names"], ["flight-specialist-booking"])
            self.assertIsNotNone(summary_ok["final_event"])
            self.assertTrue(summary_ok["final_event"]["final"])
            self.assertIn("[sse] statusUpdate state=TASK_STATE_COMPLETED final=True", sink_ok.getvalue())
            self.assertIn("[sse] artifactUpdate name=flight-specialist-booking", sink_ok.getvalue())

            sink_fail = io.StringIO()
            rc_fail, summary_fail = stream_and_summarize_a2a_sse(
                a2a_client=a2a_cli,
                message=Message.create_user(text="FAIL_ME now", task_id="task-sse-fail"),
                event_sink=sink_fail,
            )
            self.assertEqual(rc_fail, 1)
            self.assertEqual(summary_fail["terminal_state"], TaskState.FAILED.value)
        finally:
            a2a_srv.stop()

        # (4) [LOW-M6-01] & [LOW-M6-02] Doc & shell script checks
        arch_txt = (lineage_root / "ARCHITECTURE.md").read_text(encoding="utf-8")
        self.assertIn("defaultMode: 0440", arch_txt)
        self.assertIn("fsGroup: 2000", arch_txt)
        self.assertIn("e2e-user-gateway-sync", arch_txt)
        self.assertNotIn("`0400`", arch_txt)

        preflight_txt = (lineage_root / "multihost" / "preflight.sh").read_text(encoding="utf-8")
        self.assertIn("httpx.Client(timeout=4.0, trust_env=False)", preflight_txt)

        bad_role_proc = subprocess.run(
            ["bash", str(lineage_root / "multihost" / "fault.sh"), "--heal", "--role", "invalid_role_xyz"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(bad_role_proc.returncode, 2)
        self.assertIn("Invalid --role", bad_role_proc.stderr)


if __name__ == "__main__":
    unittest.main()
