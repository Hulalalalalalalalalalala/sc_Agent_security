"""Milestone 7 Unit & Adversarial Integration Tests: Identity-Based Addressing & Signed Locators.

Covers:
1. Signed workload locators (`AgentCard` + MCP tool cards), A2A v1.0 `url`/`supportedInterfaces`
   derivation from primary locator, and signature tamper detection.
2. Directory version rollback rejection, same-version equivocation rejection, and unbound-key
   signature rejection.
3. Locator CIDR allowlist enforcement: RFC1918-only by default (`100.64.0.0/10` rejected unless
   explicitly opted in; loopback, link-local, multicast, unspecified, broadcast, and public IPs
   always rejected).
4. `SignedDomainDescriptor` verification chain against `TrustAnchorPinStore` (both ES256 JWKS
   domains and keyless `org-audit.io` X.509 root signature, wrong pin, unpinned fail-closed,
   rollback, equivocation, and spoofed local-domain anchor rejection).
5. Malicious seed resilience (unpinned & spoofed descriptors ignored/rejected while valid pinned
   peers converge without eviction).
6. Multi-hop transitive gossip propagation across 4 autonomous domains (`alpha -> beta -> pay -> audit`).
7. Identity-based TLS 1.3 connection by IP literal with mandatory `expected_spiffe_id` pinning:
   wrong SPIFFE ID from the SAME valid domain CA rejected at handshake; `check_hostname=False`
   without `expected_spiffe_id` raises `MTLSError`; raw TCP ClientHello byte inspection proving
   zero IP literal bytes in TLS SNI.
8. Live locator change propagation (`NodeLocatorWatcher` -> `version + 1` re-sign without restart)
   and multi-locator priority failover (`priority=10` dead -> `priority=20` live).
9. Windows+WSL2 PowerShell / `ipconfig.exe` LAN parser (filtering `vEthernet (WSL)` & `VMware`)
   and CLI `trust import` / `seeds` / `update-peer-ips` deprecation verification.
10. Static manifest, code, CLI, and documentation audit proving zero hardcoded peer IPs, peer
    ports, cross-domain FQDN URLs, CoreDNS `hosts` injections, or Tailscale references.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from typing import Any, Dict, List, Tuple
from unittest import mock

import httpx
import yaml

from lineage.a2a import A2AClient, A2AInvocationContext, A2AServerEngine, Message
from lineage.common.crypto import KeyPair, jws_sign_compact
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService, find_free_port
from lineage.common.locators import (
    DEFAULT_ALLOWED_LOCATOR_CIDRS,
    LocatorValidationError,
    NodeLocatorWatcher,
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
    DescriptorVerificationError,
    DomainDescriptorStore,
    FederationBundleSyncer,
    SignedDomainDescriptor,
    TrustAnchorPinStore,
    UnpinnedDomainDescriptorError,
    compute_bundle_trust_anchor,
)
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.k8s.bootstrap_services import K8sServiceAccountVerifier, MinimalAuditTLSCAService
from lineage.multihost import (
    ROLE_ORDER,
    allocate_role_ports,
    render_kind_cluster_config,
    render_role_k8s_manifests,
)
from lineage.multihost.lct_multihost_cli import main as cli_main
from lineage.multihost.locator_agent import (
    parse_windows_ipconfig_lan_ips,
    parse_windows_powershell_lan_ips,
)
from lineage.registry import (
    AgentCard,
    AgentCardError,
    AgentDirectoryClient,
    AgentDirectoryService,
)


class Milestone7IdentityAddressingTests(unittest.TestCase):
    def _make_k8s_verifier(self, oidc_kp: KeyPair) -> K8sServiceAccountVerifier:
        jwk = oidc_kp.public_jwk()
        v = K8sServiceAccountVerifier(allowed_audiences=("lct-federation-ca",))
        v._keys_by_kid = {jwk["kid"]: jwk}
        v._last_refresh = time.time() + 3600.0
        return v

    # -------------------------------------------------------------------------
    # 1. Signed Workload Locators, A2A v1.0 Derivation, & MCP Tool Cards
    # -------------------------------------------------------------------------
    def test_01_signed_workload_locators_a2a_v1_derivation_and_mcp_tool_cards(self) -> None:
        ca_pay = TrustDomainCA("org-payment.io", alg="ES256")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_pay)

        conv_id = ca_pay.issue_workload("/ns/lineage-pay/sa/settlement-converger")
        locs = (
            ServiceLocator(
                transport="mtls-tcp",
                host="10.29.49.219",
                port=32103,
                priority=10,
                spiffe_id=conv_id.spiffe_id,
            ),
            ServiceLocator(
                transport="mtls-tcp",
                host="192.168.65.254",
                port=32103,
                priority=20,
                spiffe_id=conv_id.spiffe_id,
            ),
        )
        card = AgentCard.sign_and_create(
            identity=conv_id,
            name="Settlement Converger",
            skills=["settlement.converge"],
            priority=10,
            version=101,
            locators=locs,
        )
        self.assertEqual(card.endpoint, "https://10.29.49.219:32103")
        self.assertEqual(card.return_endpoint, "https://10.29.49.219:32103")
        self.assertEqual(
            card.candidate_origins(),
            ["https://10.29.49.219:32103", "https://192.168.65.254:32103"],
        )

        a2a_doc = card.to_dict()
        self.assertEqual(a2a_doc["url"], "https://10.29.49.219:32103")
        self.assertGreaterEqual(len(a2a_doc["supportedInterfaces"]), 2)
        self.assertEqual(
            a2a_doc["supportedInterfaces"][0]["url"], "https://10.29.49.219:32103"
        )
        self.assertEqual(
            a2a_doc["supportedInterfaces"][1]["url"], "https://192.168.65.254:32103"
        )

        verified_a2a = AgentCard.verify_and_parse(a2a_doc, resolver)
        self.assertEqual(verified_a2a.spiffe_id, conv_id.spiffe_id)
        self.assertEqual(len(verified_a2a.locators), 2)

        # MCP Tool server signed card (`mcp.payment-vault`)
        mcp_id = ca_pay.issue_workload("/ns/lineage-pay/sa/payment-vault-mcp")
        mcp_card = AgentCard.sign_and_create(
            identity=mcp_id,
            name="Payment Vault MCP",
            skills=["mcp.payment-vault"],
            supported_tools=["execute_settlement", "audit_ledger"],
            streaming_supported=False,
            version=5,
            locators=(
                ServiceLocator(
                    transport="mtls-tcp",
                    host="10.29.49.219",
                    port=32105,
                    priority=10,
                    spiffe_id=mcp_id.spiffe_id,
                ),
            ),
        )
        verified_mcp = AgentCard.verify_and_parse(mcp_card.to_dict(), resolver)
        self.assertEqual(verified_mcp.skills, ("mcp.payment-vault",))
        self.assertEqual(
            verified_mcp.supported_tools, ("audit_ledger", "execute_settlement")
        )

        # Tampering locator port inside outer JSON MUST fail JWS verification
        tampered = mcp_card.to_dict()
        tampered["locators"][0]["port"] = 39999
        tampered["endpoint"] = "https://10.29.49.219:39999"
        with self.assertRaises(AgentCardError):
            AgentCard.verify_and_parse(tampered, resolver)

    # -------------------------------------------------------------------------
    # 2. Directory Rollback, Equivocation, & Unbound-Key Signature Rejection
    # -------------------------------------------------------------------------
    def test_02_directory_version_rollback_equivocation_and_unbound_key_rejection(self) -> None:
        ca_beta = TrustDomainCA("org-beta.io", alg="ES256")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_beta)
        dir_svc = AgentDirectoryService(
            resolver, local_trust_domain="org-beta.io", host="127.0.0.1", port=0
        )
        dir_url = dir_svc.start()
        dir_cli = AgentDirectoryClient(dir_url, resolver)
        try:
            b1 = ca_beta.issue_workload("/ns/lineage-beta/sa/flight-specialist")
            c_v10 = AgentCard.sign_and_create(
                identity=b1,
                name="Flight B1",
                skills=["travel.flight"],
                version=10,
                locators=(
                    ServiceLocator(
                        transport="mtls-tcp",
                        host="10.29.101.203",
                        port=31103,
                        priority=10,
                        spiffe_id=b1.spiffe_id,
                    ),
                ),
            )
            dir_cli.register(c_v10)

            c_v11 = AgentCard.sign_and_create(
                identity=b1,
                name="Flight B1",
                skills=["travel.flight"],
                version=11,
                locators=(
                    ServiceLocator(
                        transport="mtls-tcp",
                        host="10.29.101.204",
                        port=31103,
                        priority=10,
                        spiffe_id=b1.spiffe_id,
                    ),
                ),
            )
            dir_cli.register(c_v11)
            self.assertEqual(
                dir_cli.get_agent(b1.spiffe_id).endpoint, "https://10.29.101.204:31103"
            )

            # Rollback v10 < v11 -> rejected!
            with self.assertRaises(AgentCardError):
                dir_cli.register(c_v10)

            # Same-version v11 equivocation with different IP -> rejected!
            c_v11_equiv = AgentCard.sign_and_create(
                identity=b1,
                name="Flight B1",
                skills=["travel.flight"],
                version=11,
                locators=(
                    ServiceLocator(
                        transport="mtls-tcp",
                        host="10.29.101.250",
                        port=31103,
                        priority=10,
                        spiffe_id=b1.spiffe_id,
                    ),
                ),
            )
            with self.assertRaises(AgentCardError):
                dir_cli.register(c_v11_equiv)

            # Locator signed by unbound attacker keypair while reusing b1's valid SVID -> rejected!
            unbound_kp = KeyPair.generate("ES256")
            forged_claims = c_v11.core_claims()
            forged_claims["version"] = "12"
            forged_claims["public_jwk"] = unbound_kp.public_jwk()
            forged_claims["jkt"] = unbound_kp.jkt
            forged_sig = jws_sign_compact(
                forged_claims, unbound_kp, typ="a2a-agent-card+jwt"
            )
            forged_raw = dict(forged_claims)
            forged_raw.pop("workload_svid_sha256", None)
            forged_raw["workload_svid"] = b1.workload_svid
            forged_raw["jws_signature"] = forged_sig
            forged_raw["signatures"] = [
                {
                    "protected_typ": "a2a-agent-card+jwt",
                    "jws": forged_sig,
                    "workload_svid": b1.workload_svid,
                    "spiffe_id": b1.spiffe_id,
                    "jkt": unbound_kp.jkt,
                }
            ]
            resp_bad = httpx.post(f"{dir_url}/v1/agents/register", json=forged_raw)
            self.assertIn(resp_bad.status_code, (400, 403))
        finally:
            dir_svc.stop()

    # -------------------------------------------------------------------------
    # 3. Locator CIDR Validation (RFC1918 Only by Default; No Default Tailscale)
    # -------------------------------------------------------------------------
    def test_03_locator_cidr_allowlist_rfc1918_only_by_default_and_forbidden_ranges(self) -> None:
        self.assertEqual(
            DEFAULT_ALLOWED_LOCATOR_CIDRS,
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
        )
        for good_ip in ("10.29.77.23", "172.19.0.2", "192.168.65.254"):
            self.assertEqual(validate_locator_host(good_ip), good_ip)

        # CGNAT 100.64.0.0/10 MUST be rejected by default!
        for cgnat_ip in ("100.64.0.1", "100.71.172.83"):
            with self.assertRaises(LocatorValidationError):
                validate_locator_host(cgnat_ip)
        # Explicit opt-in allows 100.64.0.0/10 when operator explicitly configures it
        self.assertEqual(
            validate_locator_host("100.71.172.83", allowed_cidrs=("100.64.0.0/10",)),
            "100.71.172.83",
        )

        # Loopback, link-local, multicast, unspecified, broadcast, hostname ALWAYS rejected even under 0.0.0.0/0!
        for bad_ip in (
            "127.0.0.1",
            "127.0.1.1",
            "169.254.169.254",
            "224.0.0.251",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "beta.org-beta.io",
        ):
            with self.assertRaises(
                LocatorValidationError, msg=f"Expected rejection for {bad_ip!r}"
            ):
                validate_locator_host(
                    bad_ip,
                    allowed_cidrs=("0.0.0.0/0",),
                )
        for public_ip in ("8.8.8.8", "1.1.1.1"):
            with self.assertRaises(LocatorValidationError):
                validate_locator_host(public_ip)

        # Verify K8s bootstrap env helpers construct SeedEndpointStore / DomainDescriptorStore / NodeLocatorWatcher cleanly
        from lineage.k8s.bootstrap_services import (
            _build_env_descriptor_store,
            _build_env_node_locator_watcher,
            _build_env_seed_store,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            sdir = Path(tmpdir) / "seeds"
            sdir.mkdir()
            (sdir / "seeds.txt").write_text("10.29.77.23:30100\n", encoding="utf-8")
            lfile = Path(tmpdir) / "locator.json"
            lfile.write_text(
                json.dumps({"locators": [{"host": "10.29.77.23", "priority": 10}], "ports": {"ca_federation": 30100}}),
                encoding="utf-8",
            )
            with mock.patch.dict(
                "os.environ",
                {
                    "LCT_IDENTITY_ADDRESSING": "true",
                    "LCT_SEEDS_DIR": str(sdir),
                    "LCT_NODE_LOCATOR_FILE": str(lfile),
                },
                clear=False,
            ):
                ss = _build_env_seed_store()
                assert ss is not None
                self.assertEqual(ss.list_seeds(), ["10.29.77.23:30100"])
                ds = _build_env_descriptor_store(None, False, local_trust_domain="org-alpha.io")
                self.assertIsNotNone(ds)
                nw = _build_env_node_locator_watcher()
                assert nw is not None
                self.assertIsNotNone(nw.current_snapshot())

    # -------------------------------------------------------------------------
    # 4. SignedDomainDescriptor Pin Verification (JWKS + Keyless X.509 Root)
    # -------------------------------------------------------------------------
    def test_04_signed_domain_descriptors_pin_verification_keyless_audit_and_rollback(self) -> None:
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
        desc_beta_v1 = SignedDomainDescriptor.sign_with_domain_ca(
            ca=ca_beta.ca,
            x509_root_pem=ca_beta.x509_ca.export_root_pem(),
            locators={
                "ca_bundle": [
                    ServiceLocator(transport="http-ro", host="10.29.101.203", port=31100)
                ],
                "directory_federation": [
                    ServiceLocator(
                        transport="mtls-tcp",
                        host="10.29.101.203",
                        port=31101,
                        spiffe_id="spiffe://org-beta.io/ns/sys/sa/directory",
                    )
                ],
            },
            version=1,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            csr_file = Path(tmpdir) / "csr"
            csr_file.write_text(secrets.token_urlsafe(32), encoding="utf-8")
            audit_ca = MinimalAuditTLSCAService(
                csr_token_file=str(csr_file), host="127.0.0.1", port=0
            )
            audit_bundle = audit_ca.export_public_bundle()
            desc_audit_v1 = SignedDomainDescriptor.sign_with_x509_root(
                x509_ca=audit_ca.x509_ca,
                bundle=audit_bundle,
                locators={
                    "ca_bundle": [
                        ServiceLocator(transport="http-ro", host="10.29.50.10", port=30800)
                    ],
                    "audit_collector": [
                        ServiceLocator(
                            transport="tls-tcp",
                            host="10.29.50.10",
                            port=30801,
                            spiffe_id="spiffe://org-audit.io/ns/lineage-audit/sa/audit-collector",
                        )
                    ],
                },
                version=1,
            )

            pin_store = TrustAnchorPinStore(
                static_pins={
                    "org-beta.io": ca_beta.trust_anchor,
                    "org-audit.io": audit_bundle["trust_anchor"],
                }
            )
            store = DomainDescriptorStore(
                anchor_store=pin_store,
                require_pinned_anchors=True,
                local_trust_domain="org-alpha.io",
                local_trust_anchor=ca_alpha.trust_anchor,
            )

            # Good pinned JWKS descriptor & keyless X.509-root audit descriptor accepted!
            updated_b, _ = store.ingest_raw_descriptor(desc_beta_v1.to_dict())
            updated_a, _ = store.ingest_raw_descriptor(desc_audit_v1.to_dict())
            self.assertTrue(updated_b)
            self.assertTrue(updated_a)

            # Unpinned domain `org-payment.io` -> fail-closed `UnpinnedDomainDescriptorError`
            ca_pay = AutonomousDomainCAService(
                trust_domain="org-payment.io",
                allowed_k8s_namespace="lineage-pay",
                k8s_verifier=self._make_k8s_verifier(oidc_kp),
                host="127.0.0.1",
                port=0,
            )
            desc_pay = SignedDomainDescriptor.sign_with_domain_ca(
                ca=ca_pay.ca,
                x509_root_pem=ca_pay.x509_ca.export_root_pem(),
                locators={
                    "ca_bundle": [
                        ServiceLocator(transport="http-ro", host="10.29.49.219", port=32100)
                    ]
                },
                version=1,
            )
            with self.assertRaises(UnpinnedDomainDescriptorError):
                store.ingest_raw_descriptor(desc_pay.to_dict())

            # Wrong pin -> `DescriptorVerificationError`
            wrong_pin_store = TrustAnchorPinStore(
                static_pins={"org-beta.io": f"sha256:{'a' * 64}:{'b' * 64}"}
            )
            bad_store = DomainDescriptorStore(
                anchor_store=wrong_pin_store, require_pinned_anchors=True
            )
            with self.assertRaises(DescriptorVerificationError):
                bad_store.ingest_raw_descriptor(desc_beta_v1.to_dict())

            # Spoofed local-domain (`org-alpha.io`) descriptor signed by attacker CA -> rejected!
            rogue_alpha = AutonomousDomainCAService(
                trust_domain="org-alpha.io",
                allowed_k8s_namespace="lineage-alpha",
                k8s_verifier=self._make_k8s_verifier(oidc_kp),
                host="127.0.0.1",
                port=0,
            )
            spoof_own = SignedDomainDescriptor.sign_with_domain_ca(
                ca=rogue_alpha.ca,
                x509_root_pem=rogue_alpha.x509_ca.export_root_pem(),
                locators={
                    "ca_bundle": [
                        ServiceLocator(transport="http-ro", host="10.29.99.99", port=30100)
                    ]
                },
                version=99,
            )
            with self.assertRaises(DescriptorVerificationError):
                store.ingest_raw_descriptor(spoof_own.to_dict())

            # Upgrade to v2, then reject rollback v1 and equivocation v2!
            desc_beta_v2 = SignedDomainDescriptor.sign_with_domain_ca(
                ca=ca_beta.ca,
                x509_root_pem=ca_beta.x509_ca.export_root_pem(),
                locators={
                    "ca_bundle": [
                        ServiceLocator(transport="http-ro", host="10.29.101.205", port=31100)
                    ]
                },
                version=2,
            )
            store.ingest_raw_descriptor(desc_beta_v2.to_dict())
            with self.assertRaises(DescriptorVerificationError):
                store.ingest_raw_descriptor(desc_beta_v1.to_dict())

            desc_beta_v2_equiv = SignedDomainDescriptor.sign_with_domain_ca(
                ca=ca_beta.ca,
                x509_root_pem=ca_beta.x509_ca.export_root_pem(),
                locators={
                    "ca_bundle": [
                        ServiceLocator(transport="http-ro", host="10.29.101.209", port=31100)
                    ]
                },
                version=2,
            )
            with self.assertRaises(DescriptorVerificationError):
                store.ingest_raw_descriptor(desc_beta_v2_equiv.to_dict())

    # -------------------------------------------------------------------------
    # 5. Malicious Seed Endpoint Ignored While Valid Pinned Peers Converge
    # -------------------------------------------------------------------------
    def test_05_malicious_seed_resilience_and_unpinned_spoof_isolation(self) -> None:
        oidc_kp = KeyPair.generate("RS256")
        ca_alpha = AutonomousDomainCAService(
            trust_domain="org-alpha.io",
            allowed_k8s_namespace="lineage-alpha",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
        )
        ca_beta_real = AutonomousDomainCAService(
            trust_domain="org-beta.io",
            allowed_k8s_namespace="lineage-beta",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
        )
        ca_beta_fake = AutonomousDomainCAService(
            trust_domain="org-beta.io",
            allowed_k8s_namespace="lineage-beta",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
        )
        ca_evil = AutonomousDomainCAService(
            trust_domain="org-evil.io",
            allowed_k8s_namespace="lineage-evil",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
        )

        good_desc = SignedDomainDescriptor.sign_with_domain_ca(
            ca=ca_beta_real.ca,
            x509_root_pem=ca_beta_real.x509_ca.export_root_pem(),
            locators={
                "ca_bundle": [
                    ServiceLocator(transport="http-ro", host="10.29.101.203", port=31100)
                ]
            },
            version=5,
        )
        forged_beta_desc = SignedDomainDescriptor.sign_with_domain_ca(
            ca=ca_beta_fake.ca,
            x509_root_pem=ca_beta_fake.x509_ca.export_root_pem(),
            locators={
                "ca_bundle": [
                    ServiceLocator(transport="http-ro", host="10.29.66.66", port=31100)
                ]
            },
            version=999,
        )
        evil_desc = SignedDomainDescriptor.sign_with_domain_ca(
            ca=ca_evil.ca,
            x509_root_pem=ca_evil.x509_ca.export_root_pem(),
            locators={
                "ca_bundle": [
                    ServiceLocator(transport="http-ro", host="10.29.66.67", port=31999)
                ]
            },
            version=1,
        )

        malicious_srv = ManagedHTTPService(
            "malicious-seed",
            lambda r: (
                200,
                {"descriptors": [evil_desc.to_dict(), forged_beta_desc.to_dict()]},
                {},
            )
            if r.path == "/v1/federation/descriptors"
            else (404, {}, {}),
            host="127.0.0.1",
            port=0,
        )
        good_srv = ManagedHTTPService(
            "good-seed",
            lambda r: (200, {"descriptors": [good_desc.to_dict()]}, {})
            if r.path == "/v1/federation/descriptors"
            else (404, {}, {}),
            host="127.0.0.1",
            port=0,
        )
        malicious_srv.start()
        good_srv.start()
        try:
            pins = TrustAnchorPinStore(static_pins={"org-beta.io": ca_beta_real.trust_anchor})
            d_store = DomainDescriptorStore(
                anchor_store=pins,
                require_pinned_anchors=True,
                local_trust_domain="org-alpha.io",
                local_trust_anchor=ca_alpha.trust_anchor,
            )
            s_store = SeedEndpointStore(
                static_seeds=[
                    f"10.29.250.1:{malicious_srv.port}",
                    f"10.29.250.2:{good_srv.port}",
                ]
            )
            syncer = FederationBundleSyncer(
                anchor_store=pins,
                require_pinned_anchors=True,
                local_trust_domain="org-alpha.io",
                seed_store=s_store,
                descriptor_store=d_store,
            )

            real_http_client = httpx.Client

            def _seed_loopback_client(*args: Any, **kwargs: Any) -> httpx.Client:
                c = real_http_client(*args, **kwargs)
                orig_req = c.request

                def _req(method: str, url: str, *ga: Any, **gk: Any) -> Any:
                    patched = url.replace("10.29.250.1", "127.0.0.1").replace(
                        "10.29.250.2", "127.0.0.1"
                    )
                    return orig_req(method, patched, *ga, **gk)

                c.request = _req  # type: ignore[method-assign]
                return c

            with mock.patch("lineage.federation.sync.httpx.Client", side_effect=_seed_loopback_client):
                syncer.sync_all(require_all=True, max_wait_sec=5.0)
                # Run a second sync pass against malicious seed AFTER convergence to prove zero eviction!
                syncer.sync_descriptors_from_seeds_and_peers()

            ready, diag = syncer.is_ready()
            self.assertTrue(ready, diag)
            self.assertIsNone(d_store.get_descriptor("org-evil.io"))
            learned_beta = d_store.get_descriptor("org-beta.io")
            self.assertIsNotNone(learned_beta)
            assert learned_beta is not None
            self.assertEqual(learned_beta.version, 5)
            self.assertEqual(
                learned_beta.get_locators("ca_bundle")[0].host, "10.29.101.203"
            )
        finally:
            malicious_srv.stop()
            good_srv.stop()

    # -------------------------------------------------------------------------
    # 6. Multi-Hop Transitive Gossip Propagation Across 4 Domains
    # -------------------------------------------------------------------------
    def test_06_transitive_gossip_propagation_across_4_domains(self) -> None:
        oidc_kp = KeyPair.generate("RS256")
        with tempfile.TemporaryDirectory() as tmpdir:
            csr_f = Path(tmpdir) / "csr"
            csr_f.write_text(secrets.token_urlsafe(32), encoding="utf-8")

            # Start 4 CAs on loopback, mapped via virtual LAN IPs 10.29.10.{1..4}
            ca_a = AutonomousDomainCAService(
                trust_domain="org-alpha.io",
                allowed_k8s_namespace="lineage-alpha",
                k8s_verifier=self._make_k8s_verifier(oidc_kp),
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=DomainDescriptorStore(require_pinned_anchors=False),
            )
            ca_b = AutonomousDomainCAService(
                trust_domain="org-beta.io",
                allowed_k8s_namespace="lineage-beta",
                k8s_verifier=self._make_k8s_verifier(oidc_kp),
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=DomainDescriptorStore(require_pinned_anchors=False),
            )
            ca_p = AutonomousDomainCAService(
                trust_domain="org-payment.io",
                allowed_k8s_namespace="lineage-pay",
                k8s_verifier=self._make_k8s_verifier(oidc_kp),
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=DomainDescriptorStore(require_pinned_anchors=False),
            )
            ca_aud = MinimalAuditTLSCAService(
                csr_token_file=str(csr_f),
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=DomainDescriptorStore(require_pinned_anchors=False),
            )
            ca_a.start()
            ca_b.start()
            ca_p.start()
            ca_aud.start()
            try:
                assert ca_a.federation_http is not None
                assert ca_b.federation_http is not None
                assert ca_p.federation_http is not None
                assert ca_aud.federation_http is not None

                ca_a.publish_domain_locators(
                    {
                        "ca_bundle": [
                            ServiceLocator("http-ro", "10.29.10.1", ca_a.federation_http.port)
                        ]
                    }
                )
                ca_b.publish_domain_locators(
                    {
                        "ca_bundle": [
                            ServiceLocator("http-ro", "10.29.10.2", ca_b.federation_http.port)
                        ]
                    }
                )
                ca_p.publish_domain_locators(
                    {
                        "ca_bundle": [
                            ServiceLocator("http-ro", "10.29.10.3", ca_p.federation_http.port)
                        ]
                    }
                )
                desc_aud = SignedDomainDescriptor.sign_with_x509_root(
                    x509_ca=ca_aud.x509_ca,
                    bundle=ca_aud.export_public_bundle(),
                    locators={
                        "ca_bundle": [
                            ServiceLocator("http-ro", "10.29.10.4", ca_aud.federation_http.port)
                        ],
                        "audit_collector": [
                            ServiceLocator(
                                "tls-tcp",
                                "10.29.10.4",
                                30801,
                                spiffe_id="spiffe://org-audit.io/ns/lineage-audit/sa/audit-collector",
                            )
                        ],
                    },
                    version=1,
                )
                assert ca_aud.descriptor_store is not None
                ca_aud.descriptor_store.set_own_descriptor(desc_aud)

                all_pins = {
                    "org-alpha.io": ca_a.trust_anchor,
                    "org-beta.io": ca_b.trust_anchor,
                    "org-payment.io": ca_p.trust_anchor,
                    "org-audit.io": ca_aud.export_public_bundle()["trust_anchor"],
                }

                # Linear chain ONLY: alpha -> beta -> pay -> audit (alpha has NO seed for pay or audit!)
                def _make_node_syncer(
                    own_td: str,
                    own_ca_svc: AutonomousDomainCAService,
                    single_seed: str,
                ) -> FederationBundleSyncer:
                    ps = TrustAnchorPinStore(
                        static_pins={k: v for k, v in all_pins.items() if k != own_td}
                    )
                    ds = own_ca_svc.descriptor_store
                    assert ds is not None
                    ds.anchor_store = ps
                    ds.require_pinned_anchors = True
                    ds.set_local_trust_domain(own_td, own_ca_svc.trust_anchor)
                    return FederationBundleSyncer(
                        anchor_store=ps,
                        require_pinned_anchors=True,
                        local_trust_domain=own_td,
                        seed_store=SeedEndpointStore(static_seeds=[single_seed]),
                        descriptor_store=ds,
                    )

                sync_p = _make_node_syncer(
                    "org-payment.io", ca_p, f"10.29.10.4:{ca_aud.federation_http.port}"
                )
                sync_b = _make_node_syncer(
                    "org-beta.io", ca_b, f"10.29.10.3:{ca_p.federation_http.port}"
                )
                sync_a = _make_node_syncer(
                    "org-alpha.io", ca_a, f"10.29.10.2:{ca_b.federation_http.port}"
                )

                real_http_client = httpx.Client

                def _lan_to_loopback(*args: Any, **kwargs: Any) -> httpx.Client:
                    c = real_http_client(*args, **kwargs)
                    orig_req = c.request

                    def _req(method: str, url: str, *ga: Any, **gk: Any) -> Any:
                        u = url
                        for fake_ip in ("10.29.10.1", "10.29.10.2", "10.29.10.3", "10.29.10.4"):
                            u = u.replace(fake_ip, "127.0.0.1")
                        return orig_req(method, u, *ga, **gk)

                    c.request = _req  # type: ignore[method-assign]
                    return c

                with mock.patch("lineage.federation.sync.httpx.Client", side_effect=_lan_to_loopback):
                    # Hop 1: pay learns audit; Hop 2: beta learns pay + audit; Hop 3: alpha learns beta + pay + audit!
                    sync_p.sync_descriptors_from_seeds_and_peers()
                    sync_b.sync_descriptors_from_seeds_and_peers()
                    sync_a.sync_descriptors_from_seeds_and_peers()

                ready_a, diag_a = sync_a.is_ready()
                self.assertTrue(ready_a, diag_a)
                assert ca_a.descriptor_store is not None
                self.assertEqual(
                    set(ca_a.descriptor_store.all_descriptors().keys()),
                    {"org-alpha.io", "org-beta.io", "org-payment.io", "org-audit.io"},
                )
                self.assertEqual(len(sync_a.audit_locators()), 1)
                self.assertEqual(sync_a.audit_locators()[0].port, 30801)
            finally:
                ca_a.stop()
                ca_b.stop()
                ca_p.stop()
                ca_aud.stop()

    # -------------------------------------------------------------------------
    # 7. Identity-Pinned TLS 1.3 by IP, Wrong SPIFFE Rejection, & Zero IP-SNI
    # -------------------------------------------------------------------------
    def test_07_identity_pinned_mtls_ip_connect_wrong_spiffe_rejection_and_zero_ip_sni(self) -> None:
        x509_beta = X509DomainAuthority("org-beta.io")
        x509_alpha = X509DomainAuthority("org-alpha.io")
        trust = X509FederationTrustStore()
        trust.register_domain_root_pem("org-beta.io", x509_beta.export_root_pem())
        trust.register_domain_root_pem("org-alpha.io", x509_alpha.export_root_pem())

        kp_srv = KeyPair.generate("ES256")
        flight_spiffe = "spiffe://org-beta.io/ns/lineage-beta/sa/flight-specialist"
        hotel_spiffe = "spiffe://org-beta.io/ns/lineage-beta/sa/hotel-specialist-primary"
        leaf_srv = x509_beta.issue_x509_svid(
            flight_spiffe, kp_srv.public_jwk(), dns_names=("localhost",)
        )
        srv_mtls = WorkloadMTLSBundle(flight_spiffe, kp_srv, leaf_srv, trust)

        kp_cli = KeyPair.generate("ES256")
        orch_spiffe = "spiffe://org-alpha.io/ns/lineage-alpha/sa/orchestrator-alpha"
        leaf_cli = x509_alpha.issue_x509_svid(
            orch_spiffe, kp_cli.public_jwk(), dns_names=("localhost",)
        )
        cli_mtls = WorkloadMTLSBundle(orch_spiffe, kp_cli, leaf_cli, trust)

        # (a) Hard API invariant: `check_hostname=False` WITHOUT `expected_spiffe_id` MUST raise `MTLSError`!
        with self.assertRaises(MTLSError):
            cli_mtls.build_client_ssl_context(check_hostname=False, expected_spiffe_id=None)
        with self.assertRaises(MTLSError):
            trust.build_server_verify_ssl_context(
                expected_trust_domain="org-beta.io",
                check_hostname=False,
                expected_spiffe_id=None,
            )
        with self.assertRaises(MTLSError):
            cli_mtls.verify_for_target(
                target_url="https://10.29.101.203:31103/a2a",
                expected_spiffe_id=None,
            )

        srv = ManagedHTTPService(
            "beta-mtls-ip-target",
            lambda r: (200, {"ok": True}, {}),
            host="127.0.0.1",
            port=0,
            ssl_context_provider=srv_mtls.server_ssl_context_provider(require_client_cert=True),
            peer_cert_verifier=trust.verify_peer_der_cert,
        )
        srv.start()
        try:
            ip_url = f"https://127.0.0.1:{srv.port}/healthz"

            # (b) Wrong SPIFFE ID (`hotel-specialist-primary` vs actual `flight-specialist`,
            #     even though signed by the SAME pinned `org-beta.io` CA!) -> REJECTED at TLS handshake!
            wrong_ctx = cli_mtls.verify_for_target(
                target_url=ip_url,
                expected_spiffe_id=hotel_spiffe,
            )
            with self.assertRaises(Exception):
                with httpx.Client(verify=wrong_ctx, timeout=3.0) as bad_c:
                    bad_c.get(ip_url)

            # (c) Exact matching SPIFFE ID -> TLS 1.3 handshake succeeds!
            good_ctx = cli_mtls.verify_for_target(
                target_url=ip_url,
                expected_spiffe_id=flight_spiffe,
            )
            with httpx.Client(verify=good_ctx, timeout=3.0) as ok_c:
                r = ok_c.get(ip_url)
                self.assertEqual(r.status_code, 200)

            # (d) Raw TCP ClientHello wire inspection: prove ZERO IP literal bytes (`b"127.0.0.1"`) in TLS SNI!
            captured_client_hello: List[bytes] = []
            ready_ev = threading.Event()
        finally:
            srv.stop()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as lsock:
            lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            lsock.bind(("127.0.0.1", 0))
            lsock.listen(1)
            lport = lsock.getsockname()[1]

            def _accept_once() -> None:
                ready_ev.set()
                conn, _ = lsock.accept()
                with conn:
                    conn.settimeout(2.0)
                    captured_client_hello.append(conn.recv(4096))

            t_acc = threading.Thread(target=_accept_once, daemon=True)
            t_acc.start()
            ready_ev.wait(2.0)

            sni_test_ctx = cli_mtls.verify_for_target(
                target_url=f"https://127.0.0.1:{lport}/a2a",
                expected_spiffe_id=flight_spiffe,
            )
            try:
                with socket.create_connection(("127.0.0.1", lport), timeout=2.0) as csock:
                    # Pass IP literal as server_hostname (just like httpx/httpcore does) — wrapper MUST strip it!
                    with sni_test_ctx.wrap_socket(csock, server_hostname="127.0.0.1"):
                        pass
            except Exception:
                pass
            t_acc.join(timeout=2.0)

        self.assertEqual(len(captured_client_hello), 1)
        hello_bytes = captured_client_hello[0]
        self.assertGreater(len(hello_bytes), 40)
        self.assertEqual(hello_bytes[0], 0x16)  # TLS Handshake record
        self.assertNotIn(
            b"127.0.0.1",
            hello_bytes,
            "IP literal was illegally sent inside TLS ClientHello SNI extension!",
        )
        srv_mtls.cleanup()
        cli_mtls.cleanup()

    # -------------------------------------------------------------------------
    # 8. Live Locator Change Propagation & Multi-Locator Priority Fallback
    # -------------------------------------------------------------------------
    def test_08_live_locator_ip_port_change_without_restart_and_multi_locator_fallback(self) -> None:
        ca_beta = TrustDomainCA("org-beta.io", alg="ES256")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_beta)

        dir_svc = AgentDirectoryService(
            resolver, local_trust_domain="org-beta.io", host="127.0.0.1", port=0
        )
        dir_url = dir_svc.start()
        dir_cli = AgentDirectoryClient(dir_url, resolver)

        def _work(
            _ctx: A2AInvocationContext, msg: Message, _emit: Any
        ) -> Tuple[Message, Dict[str, Any]]:
            return Message.create_agent(text=f"Echo:{msg.extract_text()}"), {}

        eng_1 = A2AServerEngine("agent-port-1", _work)
        eng_2 = A2AServerEngine("agent-port-2", _work)

        def _wrap_engine(eng: A2AServerEngine) -> Any:
            def _disp(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
                hdrs = dict(req.headers)
                hdrs.setdefault("x-lct-task-id", "task-live-loc")
                hdrs.setdefault("x-lct-sub", "user:alice@org-alpha.io")
                hdrs.setdefault("x-lct-lineage-path", "/task-live-loc/Agent")
                return eng.dispatch(
                    HTTPRequestContext(
                        req.method,
                        req.raw_path,
                        hdrs,
                        req.body,
                        req.server_host,
                        req.server_port,
                    )
                )

            return _disp

        srv_1 = ManagedHTTPService("a2a-loc-1", _wrap_engine(eng_1), host="127.0.0.1", port=0)
        srv_2 = ManagedHTTPService("a2a-loc-2", _wrap_engine(eng_2), host="127.0.0.1", port=0)
        srv_1.start()
        srv_2.start()

        try:
            agent_id = ca_beta.issue_workload("/ns/lineage-beta/sa/flight-specialist")
            with tempfile.TemporaryDirectory() as tmpdir:
                loc_file = Path(tmpdir) / "locator.json"
                loc_file.write_text(
                    json.dumps(
                        {
                            "locators": [{"host": "10.29.77.23", "priority": 10}],
                            "ports": {"flight-specialist": srv_1.port},
                        }
                    ),
                    encoding="utf-8",
                )
                state = {"ver": 1}

                def _register_from_snap(snap: Any) -> None:
                    locs = snap.build_service_locators(
                        "flight-specialist",
                        transport="http-ro",
                        spiffe_id=agent_id.spiffe_id,
                    )
                    state["ver"] += 1
                    c = AgentCard.sign_and_create(
                        identity=agent_id,
                        name="Flight B1",
                        skills=["travel.flight"],
                        version=state["ver"],
                        locators=locs,
                    )
                    dir_cli.register(c)

                watcher = NodeLocatorWatcher(
                    str(loc_file), poll_interval_sec=0.15, on_change=_register_from_snap
                )
                init_snap = watcher.current_snapshot()
                assert init_snap is not None
                _register_from_snap(init_snap)
                watcher.start()
                try:
                    c_before = dir_cli.get_agent(agent_id.spiffe_id)
                    self.assertEqual(c_before.locators[0].port, srv_1.port)
                    v_before = c_before.version

                    # Live update `locator.json` -> switches port from srv_1.port to srv_2.port + new IP 192.168.65.254!
                    loc_file.write_text(
                        json.dumps(
                            {
                                "locators": [{"host": "192.168.65.254", "priority": 10}],
                                "ports": {"flight-specialist": srv_2.port},
                            }
                        ),
                        encoding="utf-8",
                    )
                    deadline = time.time() + 4.0
                    c_after = c_before
                    while time.time() < deadline:
                        c_after = dir_cli.get_agent(agent_id.spiffe_id)
                        if c_after.version > v_before:
                            break
                        time.sleep(0.1)
                    self.assertGreater(c_after.version, v_before)
                    self.assertEqual(c_after.locators[0].host, "192.168.65.254")
                    self.assertEqual(c_after.locators[0].port, srv_2.port)
                finally:
                    watcher.stop()

            # Multi-locator priority fallback: priority=10 points to dead closed port; priority=20 points to live srv_2!
            dead_port = find_free_port()
            multi_card = AgentCard.sign_and_create(
                identity=agent_id,
                name="Flight Multi-Locator",
                skills=["travel.flight"],
                version=50,
                locators=(
                    ServiceLocator(
                        transport="http-ro",
                        host="10.29.77.23",
                        port=dead_port,
                        priority=10,
                        spiffe_id=agent_id.spiffe_id,
                    ),
                    ServiceLocator(
                        transport="http-ro",
                        host="192.168.65.254",
                        port=srv_2.port,
                        priority=20,
                        spiffe_id=agent_id.spiffe_id,
                    ),
                ),
            )
            real_http_client = httpx.Client

            def _fallback_loopback_client(*args: Any, **kwargs: Any) -> httpx.Client:
                c = real_http_client(*args, **kwargs)
                orig_post = c.post

                def _post(url: str, *pa: Any, **pk: Any) -> Any:
                    patched = url.replace("10.29.77.23", "127.0.0.1").replace(
                        "192.168.65.254", "127.0.0.1"
                    )
                    return orig_post(patched, *pa, **pk)

                c.post = _post  # type: ignore[method-assign]
                return c

            with mock.patch("lineage.a2a.rpc.httpx.Client", side_effect=_fallback_loopback_client):
                a2a_cli = A2AClient(agent_card=multi_card, timeout=3.0)
                st, body = a2a_cli.send_message(Message.create_user(text="hello-fallback"))
            self.assertEqual(st, 200, body)
            self.assertIn("Echo:hello-fallback", str(body))
        finally:
            srv_1.stop()
            srv_2.stop()
            dir_svc.stop()

    # -------------------------------------------------------------------------
    # 9. WSL2 Windows Host LAN Parser & CLI `trust import` / `seeds` / Deprecation
    # -------------------------------------------------------------------------
    def test_09_wsl2_windows_host_lan_parser_and_cli_trust_import_seeds(self) -> None:
        ps_sample = """
        [
          {"InterfaceAlias":"vEthernet (WSL (Hyper-V firewall))","InterfaceDescription":"Hyper-V Virtual Ethernet Adapter","IPAddress":"172.24.16.1"},
          {"InterfaceAlias":"VMware Network Adapter VMnet8","InterfaceDescription":"VMware Virtual Ethernet Adapter for VMnet8","IPAddress":"192.168.137.1"},
          {"InterfaceAlias":"Wi-Fi","InterfaceDescription":"Intel(R) Wi-Fi 6E AX211 160MHz","IPAddress":"10.29.101.203"}
        ]
        """
        self.assertEqual(parse_windows_powershell_lan_ips(ps_sample), ["10.29.101.203"])

        ipconfig_sample = (
            "Ethernet adapter vEthernet (WSL):\r\n"
            "   IPv4 Address. . . . . . . . . . . : 172.24.16.1\r\n"
            "Ethernet adapter VMware Network Adapter VMnet1:\r\n"
            "   IPv4 Address. . . . . . . . . . . : 192.168.56.1\r\n"
            "Wireless LAN adapter WLAN:\r\n"
            "   IPv4 Address. . . . . . . . . . . : 10.29.49.219\r\n"
        )
        self.assertEqual(parse_windows_ipconfig_lan_ips(ipconfig_sample), ["10.29.49.219"])

        # CLI `update-peer-ips` deprecation exit code 2
        err_dep = io.StringIO()
        with mock.patch("sys.stderr", new=err_dep):
            rc_dep = cli_main(["update-peer-ips"])
        self.assertEqual(rc_dep, 2)
        self.assertIn("DEPRECATED", err_dep.getvalue())

        # CLI `trust import <file>`: displays lines, requires confirmation, checks own-domain consistency
        anc_alpha = f"sha256:{'1' * 64}:{'2' * 64}"
        anc_beta = f"sha256:{'3' * 64}:{'4' * 64}"
        anc_audit = f"sha256:{'5' * 64}:keyless"
        written: List[Dict[str, str]] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            af = Path(tmpdir) / "anchors.txt"
            af.write_text(
                f"# Campus 4-machine anchors\n"
                f"org-alpha.io {anc_alpha}\n"
                f"org-beta.io {anc_beta}\n"
                f"org-audit.io {anc_audit}\n",
                encoding="utf-8",
            )
            with (
                mock.patch(
                    "lineage.multihost.lct_multihost_cli._detect_local_lctmh_roles",
                    return_value=("alpha",),
                ),
                mock.patch(
                    "lineage.multihost.lct_multihost_cli._read_local_cluster_own_anchor",
                    return_value=anc_alpha,
                ),
                mock.patch(
                    "lineage.multihost.lct_multihost_cli._read_configmap_anchors",
                    return_value={},
                ),
                mock.patch(
                    "lineage.multihost.lct_multihost_cli._write_configmap_anchors",
                    side_effect=lambda _c, _n, d: written.append(dict(d)),
                ),
            ):
                # User declines confirmation -> exit 1 without writing
                out_no = io.StringIO()
                with (
                    mock.patch("builtins.input", return_value="n"),
                    mock.patch("sys.stdout", new=out_no),
                ):
                    rc_no = cli_main(["trust", "import", str(af)])
                self.assertEqual(rc_no, 1)
                self.assertEqual(written, [])
                self.assertIn(anc_beta, out_no.getvalue())

                # User confirms -> pins peer domains (`org-beta.io`, `org-audit.io`), skips own (`org-alpha.io`)
                out_yes = io.StringIO()
                with (
                    mock.patch("builtins.input", return_value="yes"),
                    mock.patch("sys.stdout", new=out_yes),
                ):
                    rc_yes = cli_main(["trust", "import", str(af)])
                self.assertEqual(rc_yes, 0)
                self.assertEqual(
                    written[-1],
                    {"org-beta.io": anc_beta, "org-audit.io": anc_audit},
                )

    # -------------------------------------------------------------------------
    # 10. Static Audit: Zero Peer IPs/Ports/FQDN URLs or Tailscale References
    # -------------------------------------------------------------------------
    def test_10_static_audit_zero_hardcoded_peer_ips_ports_fqdns_or_tailscale(self) -> None:
        forbidden_env_names = {
            "PEER_CA_URLS",
            "PEER_DIRECTORY_URLS",
            "PEER_REVOCATION_URLS",
            "AUDIT_COLLECTOR_URL",
            "PUBLIC_ORIGIN",
            "TRAVEL_MCP_URL",
            "PAYMENT_MCP_URL",
            "BETA_CA_URL",
            "PAYMENT_CA_URL",
            "ORCH_URL",
            "FLIGHT_URL",
            "HOTEL_PRIMARY_URL",
            "HOTEL_BACKUP_URL",
            "CONVERGER_URL",
            "SYNC_HOOK_URL",
        }
        forbidden_fqdns = (
            "alpha-ca.org-alpha.io",
            "beta-ca.org-beta.io",
            "payment-ca.org-payment.io",
            "audit-collector.org-audit.io",
            "flight-specialist.org-beta.io",
            "settlement-converger.org-payment.io",
            "travel-ops-mcp.org-payment.io",
            "payment-vault-mcp.org-payment.io",
        )

        # Custom per-machine `--base-port` proves zero global port convention
        custom_beta_ports = allocate_role_ports("beta", base_port=31750)
        self.assertEqual(
            set(custom_beta_ports.values()),
            {31750, 31751, 31752, 31753, 31754, 31755, 31756},
        )
        custom_kind_cfg = yaml.safe_load(
            render_kind_cluster_config("beta", role_ports=custom_beta_ports)
        )
        self.assertEqual(
            {m["hostPort"] for m in custom_kind_cfg["nodes"][0]["extraPortMappings"]},
            {31750, 31751, 31752, 31753, 31754, 31755, 31756},
        )

        for role in ROLE_ORDER:
            raw_yaml = render_role_k8s_manifests(role)
            for fqdn in forbidden_fqdns:
                self.assertNotIn(
                    fqdn,
                    raw_yaml,
                    f"Rendered manifest for role {role!r} still contains static FQDN {fqdn!r}",
                )
            for doc in yaml.safe_load_all(raw_yaml):
                if doc["kind"] == "Deployment":
                    for c in doc["spec"]["template"]["spec"]["containers"]:
                        env_keys = {e["name"] for e in c.get("env") or []}
                        overlap = env_keys & forbidden_env_names
                        self.assertEqual(
                            overlap,
                            set(),
                            f"Deployment {doc['metadata']['name']} has forbidden static env(s): {overlap}",
                        )

        repo_root = Path(__file__).resolve().parents[2]
        lineage_root = repo_root / "lineage"

        # Verify multihost Python modules contain zero cross-domain peer FQDN URL constants
        for py_file in (lineage_root / "multihost").glob("*.py"):
            src = py_file.read_text(encoding="utf-8")
            for fqdn in forbidden_fqdns:
                self.assertNotIn(fqdn, src, f"{py_file.name} contains {fqdn!r}")

        # Verify ZERO Tailscale references in docs, CLI help, and shell scripts (Scope Correction)
        for doc_or_script in (
            lineage_root / "README.md",
            lineage_root / "ARCHITECTURE.md",
            lineage_root / "multihost" / "MULTIHOST_GUIDE.md",
            lineage_root / "multihost" / "preflight.sh",
            lineage_root / "multihost" / "deploy-role.sh",
            lineage_root / "multihost" / "locator_agent.py",
            lineage_root / "multihost" / "lct_multihost_cli.py",
            lineage_root / "scripts" / "multihost.sh",
        ):
            txt = doc_or_script.read_text(encoding="utf-8")
            self.assertNotIn(
                "tailscale",
                txt.lower(),
                f"{doc_or_script.name} still references Tailscale!",
            )

        readme_txt = (lineage_root / "README.md").read_text(encoding="utf-8")
        for stale_flag in ("--alpha-ip", "--beta-ip", "--pay-ip", "update-peer-ips"):
            self.assertNotIn(stale_flag, readme_txt, f"README.md still has stale M6 token {stale_flag!r}")
        arch_txt = (lineage_root / "ARCHITECTURE.md").read_text(encoding="utf-8")
        self.assertIn('typ="a2a-agent-card+jwt"', arch_txt)
        self.assertNotIn('typ="lct-agent-card+jwt"', arch_txt)

        for help_cmd in (
            [str(lineage_root / "multihost" / "locator-agent.py"), "--help"],
            [str(lineage_root / "multihost" / "lct_multihost_cli.py"), "--help"],
        ):
            proc = subprocess.run(
                [subprocess.sys.executable, *help_cmd],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertNotIn("tailscale", proc.stdout.lower())

    # -------------------------------------------------------------------------
    # 11. Star-Topology Seedless Hub Convergence & Zero-Seed-Edit Role Migration
    # -------------------------------------------------------------------------
    def test_11_star_topology_seedless_alpha_convergence_and_zero_seed_edit_role_migration(self) -> None:
        oidc_kp = KeyPair.generate("RS256")
        with tempfile.TemporaryDirectory() as tmpdir:
            csr_f = Path(tmpdir) / "csr"
            csr_f.write_text(secrets.token_urlsafe(32), encoding="utf-8")

            ds_alpha = DomainDescriptorStore(require_pinned_anchors=False)
            ds_beta = DomainDescriptorStore(require_pinned_anchors=False)
            ds_pay = DomainDescriptorStore(require_pinned_anchors=False)
            ds_audit = DomainDescriptorStore(require_pinned_anchors=False)

            ca_alpha = AutonomousDomainCAService(
                trust_domain="org-alpha.io",
                allowed_k8s_namespace="lineage-alpha",
                k8s_verifier=self._make_k8s_verifier(oidc_kp),
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=ds_alpha,
            )
            ca_beta = AutonomousDomainCAService(
                trust_domain="org-beta.io",
                allowed_k8s_namespace="lineage-beta",
                k8s_verifier=self._make_k8s_verifier(oidc_kp),
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=ds_beta,
            )
            ca_pay = AutonomousDomainCAService(
                trust_domain="org-payment.io",
                allowed_k8s_namespace="lineage-pay",
                k8s_verifier=self._make_k8s_verifier(oidc_kp),
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=ds_pay,
            )
            ca_audit = MinimalAuditTLSCAService(
                csr_token_file=str(csr_f),
                host="127.0.0.1",
                port=0,
                federation_port=find_free_port(),
                descriptor_store=ds_audit,
            )
            ca_alpha.start()
            ca_beta.start()
            ca_pay.start()
            ca_audit.start()
            dir_alpha = dir_beta = dir_pay = None
            ca_audit_new = None
            try:
                assert ca_alpha.federation_http is not None
                assert ca_beta.federation_http is not None
                assert ca_pay.federation_http is not None
                assert ca_audit.federation_http is not None

                all_pins = {
                    "org-alpha.io": ca_alpha.trust_anchor,
                    "org-beta.io": ca_beta.trust_anchor,
                    "org-payment.io": ca_pay.trust_anchor,
                    "org-audit.io": ca_audit.export_public_bundle()["trust_anchor"],
                }

                def _wire_syncer(
                    own_td: str,
                    ds: DomainDescriptorStore,
                    own_anchor: str,
                    seeds: List[str],
                    own_bundle: Dict[str, Any],
                ) -> Tuple[TrustAnchorPinStore, FederationBundleSyncer]:
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
                    )
                    if own_bundle.get("keys"):
                        syn.trust_resolver.register_bundle(own_bundle)
                    syn.x509_trust_store.register_domain_root_pem(
                        own_td, str(own_bundle["x509_root_pem"])
                    )
                    return ps, syn

                alpha_seed = f"10.29.77.23:{ca_alpha.federation_http.port}"
                # Star topology: alpha has ZERO seeds (`[]`); beta, pay, audit seed ONLY alpha!
                ps_alpha, sync_alpha = _wire_syncer(
                    "org-alpha.io",
                    ds_alpha,
                    ca_alpha.trust_anchor,
                    [],
                    ca_alpha.export_federation_bundle(),
                )
                ps_beta, sync_beta = _wire_syncer(
                    "org-beta.io",
                    ds_beta,
                    ca_beta.trust_anchor,
                    [alpha_seed],
                    ca_beta.export_federation_bundle(),
                )
                ps_pay, sync_pay = _wire_syncer(
                    "org-payment.io",
                    ds_pay,
                    ca_pay.trust_anchor,
                    [alpha_seed],
                    ca_pay.export_federation_bundle(),
                )
                _, sync_audit = _wire_syncer(
                    "org-audit.io",
                    ds_audit,
                    all_pins["org-audit.io"],
                    [alpha_seed],
                    ca_audit.export_public_bundle(),
                )
                ca_alpha.on_descriptor_learned = sync_alpha.apply_verified_descriptor
                ca_beta.on_descriptor_learned = sync_beta.apply_verified_descriptor
                ca_pay.on_descriptor_learned = sync_pay.apply_verified_descriptor
                ca_audit.on_descriptor_learned = sync_audit.apply_verified_descriptor

                # Start mTLS directory federation services on alpha, beta, pay
                def _make_dir(ca_svc: AutonomousDomainCAService, syn: FederationBundleSyncer, ds: DomainDescriptorStore) -> Tuple[AgentDirectoryService, WorkloadMTLSBundle]:
                    td = ca_svc.trust_domain
                    kp_d = KeyPair.generate("ES256")
                    sp_d = f"spiffe://{td}/ns/sys/sa/directory"
                    leaf_d = ca_svc.x509_ca.issue_x509_svid(sp_d, kp_d.public_jwk(), dns_names=("localhost",))
                    mb = WorkloadMTLSBundle(sp_d, kp_d, leaf_d, syn.x509_trust_store)
                    d_svc = AgentDirectoryService(
                        syn.trust_resolver,
                        local_trust_domain=td,
                        host="127.0.0.1",
                        port=0,
                        federation_port=find_free_port(),
                        mtls_bundle=mb,
                        descriptor_store=ds,
                        on_descriptor_learned=syn.apply_verified_descriptor,
                    )
                    d_svc.start()
                    return d_svc, mb

                dir_alpha, mb_a = _make_dir(ca_alpha, sync_alpha, ds_alpha)
                dir_beta, mb_b = _make_dir(ca_beta, sync_beta, ds_beta)
                dir_pay, mb_p = _make_dir(ca_pay, sync_pay, ds_pay)
                assert dir_alpha._federation_http is not None
                assert dir_beta._federation_http is not None
                assert dir_pay._federation_http is not None

                ca_alpha.publish_domain_locators(
                    {
                        "ca_bundle": [ServiceLocator("http-ro", "10.29.77.23", ca_alpha.federation_http.port)],
                        "directory_federation": [
                            ServiceLocator(
                                "mtls-tcp",
                                "10.29.77.23",
                                dir_alpha._federation_http.port,
                                spiffe_id="spiffe://org-alpha.io/ns/sys/sa/directory",
                            )
                        ],
                    }
                )
                ca_beta.publish_domain_locators(
                    {
                        "ca_bundle": [ServiceLocator("http-ro", "10.29.101.203", ca_beta.federation_http.port)],
                        "directory_federation": [
                            ServiceLocator(
                                "mtls-tcp",
                                "10.29.101.203",
                                dir_beta._federation_http.port,
                                spiffe_id="spiffe://org-beta.io/ns/sys/sa/directory",
                            )
                        ],
                    }
                )
                ca_pay.publish_domain_locators(
                    {
                        "ca_bundle": [ServiceLocator("http-ro", "10.29.49.219", ca_pay.federation_http.port)],
                        "directory_federation": [
                            ServiceLocator(
                                "mtls-tcp",
                                "10.29.49.219",
                                dir_pay._federation_http.port,
                                spiffe_id="spiffe://org-payment.io/ns/sys/sa/directory",
                            )
                        ],
                    }
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
                ds_audit.set_own_descriptor(desc_audit)

                # Register workload AgentCards locally on beta & pay
                flight_id = ca_beta.ca.issue_workload("/ns/lineage-beta/sa/flight-specialist")
                AgentDirectoryClient(dir_beta._http.base_url, sync_beta.trust_resolver).register(
                    AgentCard.sign_and_create(
                        identity=flight_id,
                        name="Flight B1",
                        skills=["travel.flight"],
                        version=1,
                        locators=(ServiceLocator("mtls-tcp", "10.29.101.203", 31103, spiffe_id=flight_id.spiffe_id),),
                    )
                )
                conv_id = ca_pay.ca.issue_workload("/ns/lineage-pay/sa/settlement-converger")
                AgentDirectoryClient(dir_pay._http.base_url, sync_pay.trust_resolver).register(
                    AgentCard.sign_and_create(
                        identity=conv_id,
                        name="Converger C",
                        skills=["settlement.converge"],
                        version=1,
                        locators=(ServiceLocator("mtls-tcp", "10.29.49.219", 32103, spiffe_id=conv_id.spiffe_id),),
                    )
                )

                # External mutating CA route `/v1/ca/issue-workload` MUST still return 403 on federation port!
                r_forbid = httpx.post(
                    f"http://127.0.0.1:{ca_alpha.federation_http.port}/v1/ca/issue-workload",
                    json={},
                    trust_env=False,
                )
                self.assertEqual(r_forbid.status_code, 403)

                real_client = httpx.Client

                def _loopback_rewriter(*args: Any, **kwargs: Any) -> httpx.Client:
                    cli = real_client(*args, **kwargs)
                    orig_req = cli.request

                    def _req(method: str, url: str, *ra: Any, **rk: Any) -> Any:
                        patched = url
                        for ip in ("10.29.77.23", "10.29.101.203", "10.29.49.219", "10.29.88.10", "10.29.99.55"):
                            patched = patched.replace(ip, "127.0.0.1")
                        return orig_req(method, patched, *ra, **rk)

                    cli.request = _req  # type: ignore[method-assign]
                    return cli

                with (
                    mock.patch("lineage.federation.sync.httpx.Client", side_effect=_loopback_rewriter),
                    mock.patch("lineage.registry.directory.httpx.Client", side_effect=_loopback_rewriter),
                ):
                    for _ in range(2):
                        sync_alpha.sync_descriptors_from_seeds_and_peers()
                        sync_beta.sync_descriptors_from_seeds_and_peers()
                        sync_pay.sync_descriptors_from_seeds_and_peers()
                        sync_audit.sync_descriptors_from_seeds_and_peers()
                    dir_alpha.sync_from_federation_peers()

                # ALL 4 domains MUST reach Ready (`4/4` descriptors) despite alpha having `seeds=[]`!
                for lbl, syn, ds in (
                    ("alpha", sync_alpha, ds_alpha),
                    ("beta", sync_beta, ds_beta),
                    ("pay", sync_pay, ds_pay),
                    ("audit", sync_audit, ds_audit),
                ):
                    ok, diag = syn.is_ready()
                    self.assertTrue(ok, f"{lbl} failed to converge in star topology: {diag}")
                    self.assertEqual(
                        set(ds.all_descriptors().keys()),
                        {"org-alpha.io", "org-beta.io", "org-payment.io", "org-audit.io"},
                    )

                # Seedless alpha's directory federated BOTH beta's & pay's signed AgentCards over mTLS 1.3!
                self.assertEqual(len(dir_alpha.discover_cards(skill="travel.flight")), 1)
                self.assertEqual(len(dir_alpha.discover_cards(skill="settlement.converge")), 1)

                # Part B: Zero-seed-edit role migration (`audit` moves to new IP `10.29.99.55`, new port `30951`, new CA root)
                ca_audit.stop()
                ds_audit_new = DomainDescriptorStore(require_pinned_anchors=False)
                ca_audit_new = MinimalAuditTLSCAService(
                    csr_token_file=str(csr_f),
                    host="127.0.0.1",
                    port=0,
                    federation_port=find_free_port(),
                    descriptor_store=ds_audit_new,
                )
                ca_audit_new.start()
                assert ca_audit_new.federation_http is not None
                new_audit_bundle = ca_audit_new.export_public_bundle()
                new_audit_anchor = str(new_audit_bundle["trust_anchor"])
                desc_audit_new = SignedDomainDescriptor.sign_with_x509_root(
                    x509_ca=ca_audit_new.x509_ca,
                    bundle=new_audit_bundle,
                    locators={
                        "ca_bundle": [ServiceLocator("http-ro", "10.29.99.55", ca_audit_new.federation_http.port)],
                        "audit_collector": [
                            ServiceLocator(
                                "tls-tcp",
                                "10.29.99.55",
                                30951,
                                spiffe_id="spiffe://org-audit.io/ns/lineage-audit/sa/audit-collector",
                            )
                        ],
                    },
                    version=1,
                )
                ds_audit_new.set_own_descriptor(desc_audit_new)

                # Update ONLY the org-audit.io pin on alpha, beta, pay — ZERO `seeds add` anywhere!
                ps_alpha.set_pin("org-audit.io", new_audit_anchor)
                ps_beta.set_pin("org-audit.io", new_audit_anchor)
                ps_pay.set_pin("org-audit.io", new_audit_anchor)

                _, sync_audit_new = _wire_syncer(
                    "org-audit.io",
                    ds_audit_new,
                    new_audit_anchor,
                    [alpha_seed],
                    new_audit_bundle,
                )
                with mock.patch("lineage.federation.sync.httpx.Client", side_effect=_loopback_rewriter):
                    sync_audit_new.sync_descriptors_from_seeds_and_peers()
                    sync_beta.sync_descriptors_from_seeds_and_peers()
                    sync_pay.sync_descriptors_from_seeds_and_peers()

                for lbl, syn in (("alpha", sync_alpha), ("beta", sync_beta), ("pay", sync_pay)):
                    locs = syn.audit_locators()
                    self.assertEqual(len(locs), 1, f"{lbl} missing migrated audit locator")
                    self.assertEqual(locs[0].host, "10.29.99.55")
                    self.assertEqual(locs[0].port, 30951)

                mb_a.cleanup()
                mb_b.cleanup()
                mb_p.cleanup()
            finally:
                for svc in (dir_alpha, dir_beta, dir_pay, ca_alpha, ca_beta, ca_pay, ca_audit, ca_audit_new):
                    if svc is not None:
                        svc.stop()

    # -------------------------------------------------------------------------
    # 12. Simplified Chinese Windows 10/11 GBK + WSL2 Host LAN IP Detection
    # -------------------------------------------------------------------------
    def test_12_chinese_windows_gbk_wsl2_host_ip_detection_and_adapter_filtering(self) -> None:
        from lineage.multihost import locator_agent

        cn_ipconfig_all = (
            "Windows IP 配置\r\n\r\n"
            "以太网适配器 以太网 2:\r\n"
            "   描述. . . . . . . . . . . . . . . : VMware Virtual Ethernet Adapter for VMnet1\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 192.168.207.1(首选)\r\n"
            "   子网掩码  . . . . . . . . . . . . : 255.255.255.0\r\n"
            "   默认网关. . . . . . . . . . . . . : \r\n\r\n"
            "以太网适配器 以太网 5:\r\n"
            "   描述. . . . . . . . . . . . . . . : Hyper-V Virtual Ethernet Adapter (Docker)\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 192.168.22.1(首选)\r\n"
            "   默认网关. . . . . . . . . . . . . : \r\n\r\n"
            "未知适配器 QuickQ:\r\n"
            "   描述. . . . . . . . . . . . . . . : QuickQ Wintun Tunnel\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 30.233.233.233(首选)\r\n"
            "   默认网关. . . . . . . . . . . . . : 30.233.233.1\r\n\r\n"
            "以太网适配器 以太网 4:\r\n"
            "   描述. . . . . . . . . . . . . . . : Realtek PCIe GbE Family Controller\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 183.175.12.34(首选)\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 183.175.12.35\r\n"
            "   默认网关. . . . . . . . . . . . . : \r\n\r\n"
            "无线局域网适配器 WLAN:\r\n"
            "   描述. . . . . . . . . . . . . . . : Intel(R) Wi-Fi 6E AX211 160MHz\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 10.29.49.219(首选)\r\n"
            "   子网掩码  . . . . . . . . . . . . : 255.255.0.0\r\n"
            "   默认网关. . . . . . . . . . . . . : 10.29.0.1\r\n"
        )
        gbk_bytes = cn_ipconfig_all.encode("gbk")

        # (a) PowerShell returning GBK bytes (if UTF-8 console encoding wasn't honored) must NOT raise UnicodeDecodeError
        ps_gbk = (
            '[{"InterfaceAlias":"以太网 2","InterfaceDescription":"VMware Virtual Ethernet Adapter for VMnet1","IPAddress":"192.168.207.1"},'
            '{"InterfaceAlias":"WLAN","InterfaceDescription":"Intel(R) Wi-Fi 6E AX211 160MHz","IPAddress":"10.29.49.219"}]'
        ).encode("gbk")

        def _fake_ps_gbk(cmd: List[str], *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
            self.assertFalse(kwargs.get("text", False), "Windows CLI must be invoked with text=False")
            return subprocess.CompletedProcess(cmd, 0, ps_gbk, b"")

        with mock.patch("lineage.multihost.locator_agent.subprocess.run", side_effect=_fake_ps_gbk):
            det_ps = locator_agent._detect_wsl2_windows_host_ips()
        self.assertEqual(det_ps, [("10.29.49.219", 10, "wsl2-powershell-host-lan")])

        # (b) PowerShell unavailable -> `ipconfig.exe /all` with real GBK bytes preserves `'默认网关'` & `'描述'` -> picks `10.29.49.219`!
        def _fake_ipconfig_gbk(cmd: List[str], *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
            self.assertFalse(kwargs.get("text", False))
            if "powershell" in str(cmd[0]).lower():
                return subprocess.CompletedProcess(cmd, 1, b"", b"")
            return subprocess.CompletedProcess(cmd, 0, gbk_bytes, b"")

        with mock.patch("lineage.multihost.locator_agent.subprocess.run", side_effect=_fake_ipconfig_gbk):
            det_ipc = locator_agent._detect_wsl2_windows_host_ips()
        self.assertEqual(det_ipc, [("10.29.49.219", 10, "wsl2-ipconfig-host-lan")])

        # (c) Even on bare `ipconfig.exe` without `Description` or `默认网关`, `.1` host-only IPs are deprioritized behind non-`.1` LAN IPs
        no_gw_sample = (
            "以太网适配器 以太网 2:\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 192.168.207.1\r\n"
            "无线局域网适配器 WLAN:\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 10.29.101.203\r\n"
        )
        self.assertEqual(
            locator_agent.parse_windows_ipconfig_lan_ips(no_gw_sample)[0],
            "10.29.101.203",
        )

    # -------------------------------------------------------------------------
    # 13. Bounded Descriptor/Seed Maps, HTTP Limits, & `seeds` ConfigMap Key
    # -------------------------------------------------------------------------
    def test_13_bounded_descriptor_seed_maps_http_limits_and_seeds_configmap_key(self) -> None:
        from lineage.federation import MAX_BOOTSTRAP_SEEDS, MAX_DESCRIPTORS_PER_MESSAGE, MAX_DESCRIPTOR_HTTP_BYTES
        from lineage.multihost import locator_agent

        # (a) 500 random unpinned & malformed domain names stay strictly bounded (`<= 64` entries, key len `<= 128`)
        pin_store = TrustAnchorPinStore(static_pins={"org-beta.io": f"sha256:{'a' * 64}:{'b' * 64}"})
        d_store = DomainDescriptorStore(anchor_store=pin_store, require_pinned_anchors=True)
        for idx in range(500):
            with self.assertRaises(Exception):
                d_store.ingest_raw_descriptor({"trust_domain": f"unpinned-{idx}-{'x' * 160}.evil.io"})
            with self.assertRaises(Exception):
                d_store.ingest_raw_descriptor({"trust_domain": f"bad name {idx} {'y' * 160}"})
        diag = d_store.diagnostics()
        self.assertLessEqual(len(diag["ignored_unpinned_domains"]), 64)
        self.assertLessEqual(len(diag["rejected_descriptor_counts"]), 64)
        self.assertLessEqual(len(diag["last_descriptor_errors"]), 64)
        for k in (*diag["ignored_unpinned_domains"], *diag["rejected_descriptor_counts"].keys()):
            self.assertLessEqual(len(k), 128)

        # (b) `SeedEndpointStore` caps dynamic seeds at `MAX_BOOTSTRAP_SEEDS` (`32`)
        s_store = SeedEndpointStore()
        for idx in range(1, 201):
            s_store.add_dynamic_seed(f"10.29.1.{idx}:30100")
        self.assertLessEqual(len(s_store.list_seeds()), MAX_BOOTSTRAP_SEEDS)

        # (c) `POST /v1/federation/descriptors` rejects `> 32` items (`400`) and `> 1 MiB` payloads (`413`)
        oidc_kp = KeyPair.generate("RS256")
        ca_svc = AutonomousDomainCAService(
            trust_domain="org-alpha.io",
            allowed_k8s_namespace="lineage-alpha",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
            federation_port=find_free_port(),
            descriptor_store=d_store,
        )
        ca_svc.start()
        try:
            assert ca_svc.federation_http is not None
            fed_url = f"http://127.0.0.1:{ca_svc.federation_http.port}/v1/federation/descriptors"
            r_many = httpx.post(
                fed_url,
                json={"descriptors": [{} for _ in range(MAX_DESCRIPTORS_PER_MESSAGE + 1)]},
                trust_env=False,
            )
            self.assertEqual(r_many.status_code, 400)
            oversized_bytes = b'{"descriptors":[],"pad":"' + (b"A" * MAX_DESCRIPTOR_HTTP_BYTES) + b'"}'
            r_big = httpx.post(
                fed_url,
                content=oversized_bytes,
                headers={"Content-Type": "application/json"},
                trust_env=False,
            )
            self.assertEqual(r_big.status_code, 413)
        finally:
            ca_svc.stop()

        # (d) `append_seed_to_local_clusters` preserves existing `"seeds"` ConfigMap entries and writes key `"seeds"`
        applied_cm_data: List[Dict[str, str]] = []
        existing_cm = {"data": {"seeds": "10.29.77.23:30100\n"}}
        with (
            mock.patch("lineage.multihost.locator_agent.discover_local_active_roles", return_value=["beta"]),
            mock.patch("lineage.multihost.locator_agent._kubectl_json", return_value=existing_cm),
            mock.patch(
                "lineage.multihost.locator_agent._apply_configmap",
                side_effect=lambda _ctx, _ns, _name, data, **_kw: applied_cm_data.append(dict(data)),
            ),
        ):
            locator_agent.append_seed_to_local_clusters("10.29.49.219:32100", roles=["beta"])

        self.assertEqual(len(applied_cm_data), 1)
        self.assertEqual(set(applied_cm_data[0].keys()), {"seeds"})
        self.assertIn("10.29.77.23:30100", applied_cm_data[0]["seeds"])
        self.assertIn("10.29.49.219:32100", applied_cm_data[0]["seeds"])


if __name__ == "__main__":
    unittest.main()
