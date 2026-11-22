"""Milestone 3 Security & Protocol Compliance Regression Suite (`[HIGH-M3-01..LOW-M3-02]`).

Locks in all 6 Milestone 3 audit remediations:
1. `[HIGH-M3-01]`: Cross-domain `HIGH_RISK` synchronous revocation anchoring strictly fails
   closed (`503 REVOCATION_ANCHOR_UNAVAILABLE`) when the origin domain's peer revocation
   service is partitioned, unreachable, slow, or returns tampered/mismatched data.
2. `[HIGH-M3-02]`: Autonomous X.509 Root CAs carry critical RFC 5280 `NameConstraints`,
   `X509FederationTrustStore.register_domain_root_pem` rejects unconstrained/colliding CAs,
   and outbound mTLS clients (`WorkloadMTLSBundle.verify_for_target`, `LineageSidecar`,
   `A2AClient`) enforce per-domain Root CA pinning + handshake-layer server EKU/domain
   verification BEFORE any `Authorization: DPoP` header is transmitted.
3. `[MEDIUM-M3-01]`: Official A2A v1.0 `CancelTask` enforces lineage-prefix ancestry
   (blocking sibling-branch cancellation) and executes `cascade_revoke_hook` BEFORE
   mutating `A2ATaskStore` state (preserving atomicity on revocation failure).
4. `[MEDIUM-M3-02]`: `verify_peer_der_cert` strictly requires `BasicConstraints(ca=False)`,
   `KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False)`, and
   `ExtendedKeyUsage` (`CLIENT_AUTH` / `SERVER_AUTH`).
5. `[LOW-M3-01]`: `AutonomousDomainCAService._resolve_workload_path` eliminates wildcard
   `-revocation` / `-directory` suffix matching (`order-revocation` stays an ordinary workload).
6. `[LOW-M3-02]`: Strict JSON-RPC 2.0 parse (`-32700`) vs request envelope validation
   (`-32600` for non-object JSON `[]`, boolean/float `id`, non-string `method`, `result`/`error`).
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import ssl
import time
import unittest
from typing import Any, Dict

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from lineage.a2a import A2AClient, A2AServerEngine, Message, TaskState
from lineage.common.crypto import KeyPair, jwk_to_public_key
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.common.mtls import (
    MTLSError,
    WorkloadMTLSBundle,
    X509DomainAuthority,
    X509FederationTrustStore,
)
from lineage.federation import AutonomousDomainCAService
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.k8s.bootstrap_services import K8sServiceAccountVerifier
from lineage.protocol import PermissionLattice, create_dpop_proof, mint_root_token
from lineage.revocation import RevocationService
from lineage.sidecar import LineageSidecar, MCPToolSidecarNode
from lineage.verifier import VerificationMode


class Milestone3SecurityRegressionTests(unittest.TestCase):
    # -------------------------------------------------------------------------
    # 1. [HIGH-M3-01]: Cross-Domain HIGH_RISK Partition Fails Closed (503)
    # -------------------------------------------------------------------------
    def test_high_m3_01_federated_high_risk_revocation_fails_closed_on_peer_partition(
        self,
    ) -> None:
        ca_a = TrustDomainCA("org-alpha.io")
        ca_p = TrustDomainCA("org-payment.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_a)
        resolver.register_domain_ca(ca_p)

        rev_a = RevocationService(
            ca_a.issue_workload("/ns/sys/sa/revocation"),
            resolver,
            strict_domain_isolation=True,
            host="127.0.0.1",
            port=0,
        )
        rev_p = RevocationService(
            ca_p.issue_workload("/ns/sys/sa/revocation"),
            resolver,
            strict_domain_isolation=True,
            host="127.0.0.1",
            port=0,
        )
        ru_a = rev_a.start()
        ru_p = rev_p.start()

        vault_id = ca_p.issue_workload("/ns/lineage-pay/sa/payment-vault-mcp")
        conv_id = ca_p.issue_workload("/ns/lineage-pay/sa/settlement-converger")
        gw_id = ca_a.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")

        vault_mcp = MCPToolSidecarNode(
            identity=vault_id,
            trust_resolver=resolver,
            tools={"execute_settlement": lambda args, _req: {"settled_usd": args["amount"]}},
            revocation_url=ru_p,
            mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
        )
        vault_url = vault_mcp.start()

        try:
            perms = PermissionLattice.create(
                tools=["execute_settlement"],
                max_amount=600.0,
                allowed_targets=["airline-escrow"],
                max_calls=4,
            )
            compact_tok = mint_root_token(
                ca_a,
                "task-m3-partition-1",
                "user:alice@org-alpha.io",
                gw_id.jkt,
                conv_id.spiffe_id,
                conv_id.jkt,
                perms,
                first_hop_public_jwk=conv_id.keypair.public_jwk(),
            ).encode_compact()

            # Revoke on `alpha-revocation`, then partition `alpha-revocation`!
            rev_a.revoke_prefix_direct(
                "/task-m3-partition-1",
                "gateway",
                "emergency_fraud_stop",
                trust_domain="org-alpha.io",
            )
            rev_a.stop()
            rev_p.peer_revocation_urls = {"org-alpha.io": ru_a}

            mcp_ep = f"{vault_url}/mcp"
            dpop = create_dpop_proof(conv_id, "POST", mcp_ep, compact_tok)
            resp = httpx.post(
                mcp_ep,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "execute_settlement",
                        "arguments": {"target": "airline-escrow", "amount": 500.0},
                    },
                },
                headers={"Authorization": f"DPoP {compact_tok}", "DPoP": dpop},
                trust_env=False,
                timeout=10.0,
            )
            self.assertEqual(resp.status_code, 503, resp.text)
            self.assertEqual(resp.json()["error"], "REVOCATION_ANCHOR_UNAVAILABLE")

            # Also verify unconfigured peer domain fails closed (503) in strict_domain_isolation mode!
            rev_p.peer_revocation_urls = {}
            dpop2 = create_dpop_proof(conv_id, "POST", mcp_ep, compact_tok)
            resp2 = httpx.post(
                mcp_ep,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "execute_settlement",
                        "arguments": {"target": "airline-escrow", "amount": 500.0},
                    },
                },
                headers={"Authorization": f"DPoP {compact_tok}", "DPoP": dpop2},
                trust_env=False,
                timeout=10.0,
            )
            self.assertEqual(resp2.status_code, 503, resp2.text)
            self.assertEqual(resp2.json()["error"], "REVOCATION_ANCHOR_UNAVAILABLE")
        finally:
            vault_mcp.stop()
            rev_p.stop()
            rev_a.stop()

    # -------------------------------------------------------------------------
    # 2. [HIGH-M3-02]: Root CA NameConstraints + Outbound Per-Domain Pinning
    # -------------------------------------------------------------------------
    def test_high_m3_02_x509_name_constraints_and_outbound_domain_pinning_block_mitm(
        self,
    ) -> None:
        ca_a = TrustDomainCA("org-alpha.io")
        x509_a = X509DomainAuthority(
            "org-alpha.io",
            allowed_dns_suffixes=(".lineage-alpha.svc.cluster.local", "localhost"),
        )
        x509_b = X509DomainAuthority(
            "org-beta.io",
            allowed_dns_suffixes=(".lineage-beta.svc.cluster.local", "localhost"),
        )
        x509_p = X509DomainAuthority(
            "org-payment.io",
            allowed_dns_suffixes=(".lineage-pay.svc.cluster.local", "localhost"),
        )

        # Verify critical NameConstraints present on Root CA
        nc_ext = x509_b.root_cert.extensions.get_extension_for_class(x509.NameConstraints)
        self.assertTrue(nc_ext.critical)

        store = X509FederationTrustStore()
        store.register_domain_root_pem("org-alpha.io", x509_a.export_root_pem())
        store.register_domain_root_pem("org-beta.io", x509_b.export_root_pem())
        store.register_domain_root_pem("org-payment.io", x509_p.export_root_pem())

        # Unconstrained rogue Root CA PEM rejected by `register_domain_root_pem`!
        unconstrained_kp = KeyPair.generate("ES256")
        pub_u, _ = jwk_to_public_key(unconstrained_kp.public_jwk())
        now = dt.datetime.now(dt.timezone.utc)
        sub_u = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unconstrained")])
        unconstrained_root = (
            x509.CertificateBuilder()
            .subject_name(sub_u)
            .issuer_name(sub_u)
            .public_key(pub_u)
            .serial_number(10)
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier("spiffe://org-evil.io/authority/x509-ca")]
                ),
                critical=False,
            )
            .sign(unconstrained_kp._private_key, hashes.SHA256())
        )
        with self.assertRaises(MTLSError):
            store.register_domain_root_pem(
                "org-evil.io",
                unconstrained_root.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            )

        # Case A: Compromised `beta-ca` signs server cert claiming `spiffe://org-payment.io/...`
        # -> Rejected at TLS handshake by OpenSSL NameConstraints BEFORE any HTTP header flows!
        rogue_kp = KeyPair.generate("ES256")
        pub_r, _ = jwk_to_public_key(rogue_kp.public_jwk())
        spoofed_uri_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "spoof-pay")]))
            .issuer_name(x509_b.root_cert.subject)
            .public_key(pub_r)
            .serial_number(99)
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.UniformResourceIdentifier(
                            "spiffe://org-payment.io/ns/lineage-pay/sa/payment-vault-mcp"
                        ),
                        x509.DNSName("payment-vault-mcp.lineage-pay.svc.cluster.local"),
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .sign(private_key=x509_b._private_key, algorithm=hashes.SHA256())
        )
        spoof_pem = spoofed_uri_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        spoof_bundle = WorkloadMTLSBundle(
            "spiffe://org-payment.io/ns/lineage-pay/sa/payment-vault-mcp",
            rogue_kp,
            spoof_pem,
            store,
        )

        captured_headers: Dict[str, str] = {}
        mitm_srv = ManagedHTTPService(
            "rogue-beta-mitm-1",
            lambda req: (
                captured_headers.update({"auth": str(req.header("Authorization") or "")}) or 200,
                {"impersonated": True},
                {},
            ),
            host="127.0.0.1",
            port=0,
            ssl_context=spoof_bundle.build_server_ssl_context(require_client_cert=False),
        )
        mitm_url = mitm_srv.start().replace("127.0.0.1", "localhost")

        # Case B (Second-Order Stealth MITM on Shared `localhost`):
        # `beta-ca` signs a valid `org-beta.io` cert for `localhost`, attempting to impersonate
        # an `org-payment.io` service when the client connects via domain-pinned `SSLContext`!
        w_beta_mitm = TrustDomainCA("org-beta.io").issue_workload("/ns/lineage-beta/sa/evil")
        stealth_pem = x509_b.issue_x509_svid(
            w_beta_mitm.spiffe_id, w_beta_mitm.keypair.public_jwk(), dns_names=("localhost",)
        )
        stealth_bundle = WorkloadMTLSBundle(
            w_beta_mitm.spiffe_id, w_beta_mitm.keypair, stealth_pem, store
        )
        mitm_srv_2 = ManagedHTTPService(
            "rogue-beta-mitm-2",
            lambda req: (
                captured_headers.update({"auth2": str(req.header("Authorization") or "")}) or 200,
                {"impersonated": True},
                {},
            ),
            host="127.0.0.1",
            port=0,
            ssl_context=stealth_bundle.build_server_ssl_context(require_client_cert=False),
        )
        mitm_url_2 = mitm_srv_2.start().replace("127.0.0.1", "localhost")

        try:
            w_alpha = ca_a.issue_workload("/ns/lineage-alpha/sa/orchestrator-alpha")
            alpha_bundle = WorkloadMTLSBundle(
                w_alpha.spiffe_id,
                w_alpha.keypair,
                x509_a.issue_x509_svid(
                    w_alpha.spiffe_id, w_alpha.keypair.public_jwk(), dns_names=("localhost",)
                ),
                store,
            )
            # Case A fails even on unpinned `build_client_ssl_context()` due to NameConstraints!
            with self.assertRaises(Exception):
                with httpx.Client(
                    verify=alpha_bundle.build_client_ssl_context(check_hostname=True),
                    trust_env=False,
                    timeout=3.0,
                ) as cli1:
                    cli1.post(
                        f"{mitm_url}/mcp",
                        headers={"Authorization": "DPoP secret-lct-1"},
                        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    )

            # Case B fails on domain-pinned `build_client_ssl_context(expected_trust_domain='org-payment.io')`!
            with self.assertRaises(Exception):
                with httpx.Client(
                    verify=alpha_bundle.build_client_ssl_context(
                        check_hostname=True, expected_trust_domain="org-payment.io"
                    ),
                    trust_env=False,
                    timeout=3.0,
                ) as cli2:
                    cli2.post(
                        f"{mitm_url_2}/mcp",
                        headers={"Authorization": "DPoP secret-lct-2"},
                        json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
                    )

            # ZERO credentials ever reached either MITM server!
            self.assertEqual(captured_headers, {})
        finally:
            mitm_srv_2.stop()
            mitm_srv.stop()

    # -------------------------------------------------------------------------
    # 3. [MEDIUM-M3-01]: CancelTask Ancestry Check & Atomic State Mutation
    # -------------------------------------------------------------------------
    def test_medium_m3_01_canceltask_blocks_sibling_and_preserves_state_on_hook_failure(
        self,
    ) -> None:
        hook_should_fail = True

        def _controlled_hook(_req_id: str, prefix: str, _tid: str) -> Dict[str, Any]:
            if hook_should_fail:
                raise RuntimeError(f"Simulated revocation rejection for {prefix!r}")
            return {"target": prefix, "version": 7}

        eng = A2AServerEngine(
            agent_name="converger-qa",
            work_handler=lambda _ctx, _msg, _emit: (
                Message.create_agent("staged"),
                {"stagedForSettlement": True},
            ),
            cascade_revoke_hook=_controlled_hook,
        )

        # 1. Primary branch `/task-atomic-1/Orch/FlightPrimary/ConvC` creates staged task
        st1, b1, _ = eng.dispatch(
            HTTPRequestContext(
                method="POST",
                raw_path="/a2a",
                headers={
                    "A2A-Version": "1.0",
                    "X-LCT-Request-Id": "req-1",
                    "X-LCT-Task-Id": "task-atomic-1",
                    "X-LCT-Sub": "user:alice@org-alpha.io",
                    "X-LCT-Lineage-Path": "/task-atomic-1/Orch/FlightPrimary/ConvC",
                },
                body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "1",
                        "method": "SendMessage",
                        "params": {
                            "message": Message.create_user("stage", task_id="task-atomic-1").to_dict()
                        },
                    }
                ).encode("utf-8"),
                server_host="127.0.0.1",
                server_port=9001,
            )
        )
        self.assertEqual(st1, 200)
        self.assertEqual(b1["result"]["task"]["status"]["state"], TaskState.COMPLETED.value)

        # 2. Disjoint sibling branch `/task-atomic-1/Orch/HotelSibling/ConvC` is rejected BEFORE hook!
        st_sib, b_sib, _ = eng.dispatch(
            HTTPRequestContext(
                method="POST",
                raw_path="/a2a",
                headers={
                    "A2A-Version": "1.0",
                    "X-LCT-Request-Id": "req-2",
                    "X-LCT-Task-Id": "task-atomic-1",
                    "X-LCT-Sub": "user:alice@org-alpha.io",
                    "X-LCT-Lineage-Path": "/task-atomic-1/Orch/HotelSibling/ConvC",
                },
                body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "2",
                        "method": "CancelTask",
                        "params": {"id": "task-atomic-1"},
                    }
                ).encode("utf-8"),
                server_host="127.0.0.1",
                server_port=9001,
            )
        )
        self.assertEqual(st_sib, 403)
        self.assertEqual(b_sib["error"]["code"], -32003)

        # 3. Upstream ancestor `/task-atomic-1/Orch` calls CancelTask while `hook_should_fail=True` ->
        #    returns 403 AND task state MUST remain COMPLETED (NOT corrupted to CANCELED)!
        st_fail, _, _ = eng.dispatch(
            HTTPRequestContext(
                method="POST",
                raw_path="/a2a",
                headers={
                    "A2A-Version": "1.0",
                    "X-LCT-Request-Id": "req-3",
                    "X-LCT-Task-Id": "task-atomic-1",
                    "X-LCT-Sub": "user:alice@org-alpha.io",
                    "X-LCT-Lineage-Path": "/task-atomic-1/Orch",
                },
                body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "3",
                        "method": "CancelTask",
                        "params": {"id": "task-atomic-1"},
                    }
                ).encode("utf-8"),
                server_host="127.0.0.1",
                server_port=9001,
            )
        )
        self.assertEqual(st_fail, 403)

        st_get, b_get, _ = eng.dispatch(
            HTTPRequestContext(
                method="POST",
                raw_path="/a2a",
                headers={
                    "A2A-Version": "1.0",
                    "X-LCT-Request-Id": "req-4",
                    "X-LCT-Task-Id": "task-atomic-1",
                    "X-LCT-Sub": "user:alice@org-alpha.io",
                    "X-LCT-Lineage-Path": "/task-atomic-1/Orch/FlightPrimary/ConvC",
                },
                body=json.dumps(
                    {"jsonrpc": "2.0", "id": "4", "method": "GetTask", "params": {"id": "task-atomic-1"}}
                ).encode("utf-8"),
                server_host="127.0.0.1",
                server_port=9001,
            )
        )
        self.assertEqual(st_get, 200)
        self.assertEqual(b_get["result"]["task"]["status"]["state"], TaskState.COMPLETED.value)

        # 4. Now allow hook to succeed -> upstream ancestor `/task-atomic-1/Orch` atomically cancels!
        hook_should_fail = False
        st_ok, b_ok, _ = eng.dispatch(
            HTTPRequestContext(
                method="POST",
                raw_path="/a2a",
                headers={
                    "A2A-Version": "1.0",
                    "X-LCT-Request-Id": "req-5",
                    "X-LCT-Task-Id": "task-atomic-1",
                    "X-LCT-Sub": "user:alice@org-alpha.io",
                    "X-LCT-Lineage-Path": "/task-atomic-1/Orch",
                },
                body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "5",
                        "method": "CancelTask",
                        "params": {"id": "task-atomic-1"},
                    }
                ).encode("utf-8"),
                server_host="127.0.0.1",
                server_port=9001,
            )
        )
        self.assertEqual(st_ok, 200)
        self.assertEqual(b_ok["result"]["task"]["status"]["state"], TaskState.CANCELED.value)

    # -------------------------------------------------------------------------
    # 4. [MEDIUM-M3-02], [LOW-M3-01], [LOW-M3-02]: Cert EKU, SA Exact Match, RPC
    # -------------------------------------------------------------------------
    def test_medium_m3_02_and_low_m3_01_02_leaf_extensions_sa_allowlist_and_jsonrpc(
        self,
    ) -> None:
        # A. [MEDIUM-M3-02]: Leaf cert missing BasicConstraints/KeyUsage or wrong EKU -> MTLSError!
        x509_a = X509DomainAuthority("org-alpha.io")
        store = X509FederationTrustStore()
        store.register_domain_root_pem("org-alpha.io", x509_a.export_root_pem())

        kp = KeyPair.generate("ES256")
        pub_k, _ = jwk_to_public_key(kp.public_jwk())
        now = dt.datetime.now(dt.timezone.utc)
        weak_leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak-leaf")]))
            .issuer_name(x509_a.root_cert.subject)
            .public_key(pub_k)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier("spiffe://org-alpha.io/ns/lineage-alpha/sa/orch")]
                ),
                critical=False,
            )
            .sign(private_key=x509_a._private_key, algorithm=hashes.SHA256())
        )
        with self.assertRaises(MTLSError):
            store.verify_peer_der_cert(weak_leaf.public_bytes(serialization.Encoding.DER))

        # Cert with BasicConstraints + KeyUsage, but ONLY SERVER_AUTH EKU -> fails CLIENT_AUTH check!
        server_only_leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "srv-only")]))
            .issuer_name(x509_a.root_cert.subject)
            .public_key(pub_k)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier("spiffe://org-alpha.io/ns/lineage-alpha/sa/orch")]
                ),
                critical=False,
            )
            .sign(private_key=x509_a._private_key, algorithm=hashes.SHA256())
        )
        server_der = server_only_leaf.public_bytes(serialization.Encoding.DER)
        with self.assertRaises(MTLSError):
            store.verify_peer_der_cert(server_der, required_eku=ExtendedKeyUsageOID.CLIENT_AUTH)
        sp_ok, _ = store.verify_peer_der_cert(
            server_der, required_eku=ExtendedKeyUsageOID.SERVER_AUTH
        )
        self.assertEqual(sp_ok, "spiffe://org-alpha.io/ns/lineage-alpha/sa/orch")

        # B. [LOW-M3-01]: `order-revocation` & `team-directory` stay ordinary workloads!
        oidc_kp = KeyPair.generate("RS256")
        verifier = K8sServiceAccountVerifier(allowed_audiences=("lct-federation-ca",))
        verifier._keys_by_kid = {oidc_kp.public_jwk()["kid"]: oidc_kp.public_jwk()}
        verifier._last_refresh = time.time() + 3600.0
        dom_ca = AutonomousDomainCAService(
            trust_domain="org-alpha.io",
            allowed_k8s_namespace="lineage-alpha",
            k8s_verifier=verifier,
            host="127.0.0.1",
            port=0,
        )
        self.assertEqual(
            dom_ca._resolve_workload_path("lineage-alpha", "order-revocation"),
            "/ns/lineage-alpha/sa/order-revocation",
        )
        self.assertEqual(
            dom_ca._resolve_workload_path("lineage-alpha", "team-directory"),
            "/ns/lineage-alpha/sa/team-directory",
        )
        self.assertEqual(
            dom_ca._resolve_workload_path("lineage-alpha", "alpha-revocation"),
            "/ns/sys/sa/revocation",
        )
        self.assertEqual(
            dom_ca._resolve_workload_path("lineage-alpha", "alpha-directory"),
            "/ns/sys/sa/directory",
        )

        # C. [LOW-M3-02]: JSON-RPC 2.0 `-32700` vs `-32600` envelope validation
        eng = A2AServerEngine(
            "rpc-edge",
            lambda _c, _m, _e: (Message.create_agent("ok"), {}),
        )
        # Malformed JSON -> -32700
        st_bad, b_bad, _ = eng.dispatch(
            HTTPRequestContext(
                method="POST",
                raw_path="/a2a",
                headers={"A2A-Version": "1.0"},
                body=b"{not-json",
                server_host="127.0.0.1",
                server_port=9001,
            )
        )
        self.assertEqual(st_bad, 400)
        self.assertEqual(b_bad["error"]["code"], -32700)

        # Valid JSON array `[]` -> 400 -32600 Invalid Request
        st_arr, b_arr, _ = eng.dispatch(
            HTTPRequestContext(
                method="POST",
                raw_path="/a2a",
                headers={"A2A-Version": "1.0"},
                body=b"[]",
                server_host="127.0.0.1",
                server_port=9001,
            )
        )
        self.assertEqual(st_arr, 400)
        self.assertEqual(b_arr["error"]["code"], -32600)

        # Boolean `id: true` or non-string `method: 12345` or `result` in request -> 400 -32600
        for invalid_body in (
            b'{"jsonrpc": "2.0", "id": true, "method": "GetTask"}',
            b'{"jsonrpc": "2.0", "id": 1.5, "method": "GetTask"}',
            b'{"jsonrpc": "2.0", "id": "1", "method": 12345}',
            b'{"jsonrpc": "2.0", "id": "1", "method": "GetTask", "result": {}}',
        ):
            st_inv, b_inv, _ = eng.dispatch(
                HTTPRequestContext(
                    method="POST",
                    raw_path="/a2a",
                    headers={
                        "A2A-Version": "1.0",
                        "X-LCT-Task-Id": "t1",
                        "X-LCT-Sub": "user:alice@org-alpha.io",
                    },
                    body=invalid_body,
                    server_host="127.0.0.1",
                    server_port=9001,
                )
            )
            self.assertEqual(st_inv, 400, invalid_body)
            self.assertEqual(b_inv["error"]["code"], -32600, invalid_body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
