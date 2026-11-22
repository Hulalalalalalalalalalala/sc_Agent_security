"""Independent Milestone 3 Security, Protocol & Compliance Verification Suite.

Written by `k8s-qa-reviewer` (`lineage/reviews/qa_milestone3_review.py`).
Strictly read-only against business source code, manifests, and existing K8s workloads.

Covers:
1. Milestone 3 E2E artifact redaction compliance (`runs/20261119T091029Z/`).
2. Official A2A v1.0 AgentCard schema, `A2A-Version: 1.0`, `GetTask` tenant isolation,
   and real-time incremental SSE streaming (`SendStreamingMessage`) over mTLS 1.3.
3. Autonomous 3-domain federation: `/v1/federation/notify` SSRF immunity, cross-domain
   `AgentCard` & `RevocationEvent` anti-spoofing, and healthy synchronous `wait_ms=0` pull.
4. Inbound mTLS 1.3 client-cert domain pinning, `MTLS_CHANNEL_BINDING_MISMATCH` enforcement,
   and `LCT_MTLS_RAM_DIR` zero-residue private key hygiene.
5. Deterministic proof-of-concept tests reproducing Milestone 3 audit findings:
   - `HIGH-M3-01`: Federated `HIGH_RISK` revocation fail-open during cross-domain peer partition.
   - `HIGH-M3-02`: Outbound mTLS client accepts cross-domain spoofed server cert (missing
     X.509 `NameConstraints` + flat `combined_ca_pem()` without server domain pinning).
   - `MEDIUM-M3-01`: `CancelTask` non-atomic state mutation prior to `cascade_revoke_hook`
     and missing lineage-prefix ancestry check (sibling branch cancellation).
   - `MEDIUM-M3-02`: `verify_peer_der_cert` omits mandatory `BasicConstraints(ca=False)`,
     `KeyUsage`, and `ExtendedKeyUsage` (`CLIENT_AUTH` / `SERVER_AUTH`) validation.
   - `LOW-M3-01`: Wildcard `-revocation` / `-directory` SA suffix privilege elevation in
     `AutonomousDomainCAService._resolve_workload_path`.
   - `LOW-M3-02`: Minor JSON-RPC 2.0 envelope edge cases (`id` type, non-string `method`,
     array body `-32700` vs `-32600`).
"""

from __future__ import annotations

import datetime as dt
import glob
import ipaddress
import json
import os
import re
import tempfile
import time
import unittest
from typing import Any, Dict, List, Tuple

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from lineage.a2a import A2AClient, A2AServerEngine, Artifact, Message, TaskState
from lineage.common.crypto import KeyPair, jwk_to_public_key, jws_sign_compact
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
from lineage.protocol import (
    PermissionLattice,
    create_dpop_proof,
    mint_root_token,
)
from lineage.registry import AgentCard, AgentCardError, AgentDirectoryService
from lineage.revocation import (
    RevocationError,
    RevocationReplicaClient,
    RevocationService,
)
from lineage.sidecar import LineageSidecar, MCPToolSidecarNode
from lineage.verifier import VerificationMode


REPO_ROOT = "/Users/hulalala/Desktop/A"
M3_RUN_DIR = os.path.join(REPO_ROOT, "lineage/k8s/runs/20261119T091029Z")


class Milestone3IndependentQAReviewTests(unittest.TestCase):
    """Independent QA verification & adversarial boundary tests for Milestone 3."""

    # -------------------------------------------------------------------------
    # 1. E2E Run Directory Redaction & Causal Reconstruction Integrity
    # -------------------------------------------------------------------------
    def test_01_run_artifacts_redaction_and_causal_report_integrity(self) -> None:
        self.assertTrue(os.path.isdir(M3_RUN_DIR), f"Missing M3 run dir: {M3_RUN_DIR}")
        files = sorted(glob.glob(os.path.join(M3_RUN_DIR, "*")))
        self.assertGreaterEqual(len(files), 14)

        forbidden_patterns = {
            "PEM_PRIVATE_KEY": re.compile(r"BEGIN [A-Z0-9 ]*PRIVATE KEY"),
            "RAW_LCT_TOKEN": re.compile(r"\blct(?:mp)?1\.[A-Za-z0-9_-]{12,}"),
            "RAW_COMPACT_JWS": re.compile(
                r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
            ),
            "JWK_PRIVATE_D": re.compile(r'"d"\s*:\s*"[A-Za-z0-9_-]{20,}"'),
        }

        leaks: List[Tuple[str, str, str]] = []
        for path in files:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            for label, pat in forbidden_patterns.items():
                m = pat.search(text)
                if m:
                    leaks.append((os.path.basename(path), label, m.group(0)[:48]))
        self.assertEqual(leaks, [], f"Sensitive material leaked in M3 run artifacts: {leaks}")

        with open(os.path.join(M3_RUN_DIR, "scenario5_causal_audit_report.json"), "r", encoding="utf-8") as fh:
            s5 = json.load(fh)
        self.assertEqual(s5["status"], "PASS")
        self.assertTrue(s5["clean"])
        self.assertTrue(s5["stream_hash_chain_integrity_ok"])
        self.assertEqual(s5["reconstructed_tasks_numerator"], s5["total_tasks_denominator"])
        self.assertGreaterEqual(s5["total_signed_entries"], 200)

    # -------------------------------------------------------------------------
    # 2. Official A2A v1.0 AgentCard, Tenant Isolation & Real-Time SSE Streaming
    # -------------------------------------------------------------------------
    def test_02_a2a_v1_agent_card_tenant_isolation_and_realtime_sse(self) -> None:
        ca_a = TrustDomainCA("org-alpha.io")
        x509_a = X509DomainAuthority("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_a)

        store = X509FederationTrustStore()
        store.register_domain_root_pem("org-alpha.io", x509_a.export_root_pem())

        w_srv = ca_a.issue_workload("/ns/lineage-alpha/sa/orch")
        w_cli = ca_a.issue_workload("/ns/lineage-alpha/sa/gateway")

        b_srv = WorkloadMTLSBundle(
            w_srv.spiffe_id,
            w_srv.keypair,
            x509_a.issue_x509_svid(w_srv.spiffe_id, w_srv.keypair.public_jwk(), dns_names=("localhost",)),
            store,
        )
        b_cli = WorkloadMTLSBundle(
            w_cli.spiffe_id,
            w_cli.keypair,
            x509_a.issue_x509_svid(w_cli.spiffe_id, w_cli.keypair.public_jwk(), dns_names=("localhost",)),
            store,
        )

        def _timed_work(ctx: Any, msg: Message, emit_art: Any) -> Tuple[Message, Dict[str, Any]]:
            time.sleep(0.28)
            emit_art(Artifact.create(name="streaming-chunk-1", text="chunk-1"))
            time.sleep(0.28)
            return Message.create_agent(text=f"Processed: {msg.extract_text()}"), {}

        sec = "loopback-secret-qa-m3-0123456789"
        eng = A2AServerEngine("orch-qa", _timed_work)

        def _app_dispatch(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
            if req.header("X-LCT-Loopback-Auth") != sec:
                return 403, {"error": "forbidden"}, {}
            return eng.dispatch(req)

        app_srv = ManagedHTTPService("qa-a2a-app", _app_dispatch, host="127.0.0.1", port=0)
        app_url = app_srv.start()
        sc = LineageSidecar(
            w_srv,
            resolver,
            app_url,
            sec,
            mode=VerificationMode.LOCAL_FULL_CHAIN,
            mtls_bundle=b_srv,
        )
        in_url, _ = sc.start()
        try:
            card = AgentCard.sign_and_create(
                w_srv, "Orch QA", in_url, ["travel.orchestrate"], return_endpoint=in_url
            )
            sc.set_agent_card(card)

            cli_ssl = b_cli.build_client_ssl_context(check_hostname=True)
            a2a_cli = A2AClient(in_url, signer=w_cli, ssl_context=cli_ssl, rpc_path="/a2a")

            # A. Verify /.well-known/agent-card.json A2A v1.0 schema & anti-poisoning
            ver_card, raw_card = a2a_cli.fetch_agent_card(resolver, "/.well-known/agent-card.json")
            self.assertEqual(ver_card.spiffe_id, w_srv.spiffe_id)
            self.assertEqual(raw_card["protocolVersion"], "1.0")
            self.assertIn("organization", raw_card["provider"])
            self.assertTrue(raw_card["capabilities"]["streaming"])
            self.assertIn("lct_dpop", raw_card["securitySchemes"])
            self.assertIsInstance(raw_card["skills"][0], dict)
            self.assertTrue(raw_card["signatures"][0]["jws"])

            tampered_raw = dict(raw_card)
            tampered_raw["url"] = "https://evil.example.com:8443"
            with self.assertRaises(AgentCardError):
                AgentCard.from_dict_and_verify(tampered_raw, resolver)

            # B. Verify real-time incremental SSE streaming (frames arrive BEFORE work finishes!)
            perms = PermissionLattice.create(tools=["search_flight"], max_amount=100.0, max_calls=5)
            tok_alice = mint_root_token(
                ca_a,
                "task-qa-sse-1",
                "user:alice@org-alpha.io",
                w_cli.jkt,
                w_srv.spiffe_id,
                w_srv.jkt,
                perms,
                first_hop_public_jwk=w_srv.keypair.public_jwk(),
            ).encode_compact()

            u_rpc = f"{in_url}/a2a"
            dpop = create_dpop_proof(w_cli, "POST", u_rpc, tok_alice)
            t0 = time.monotonic()
            frame_times: List[Tuple[float, Dict[str, Any]]] = []
            with httpx.Client(verify=cli_ssl, trust_env=False, timeout=10.0) as hcli:
                with hcli.stream(
                    "POST",
                    u_rpc,
                    json={
                        "jsonrpc": "2.0",
                        "id": "sse-req-1",
                        "method": "SendStreamingMessage",
                        "params": {
                            "message": Message.create_user("stream test", task_id="task-qa-sse-1").to_dict()
                        },
                    },
                    headers={
                        "A2A-Version": "1.0",
                        "Authorization": f"DPoP {tok_alice}",
                        "DPoP": dpop,
                    },
                ) as resp:
                    self.assertEqual(resp.status_code, 200)
                    self.assertIn("text/event-stream", resp.headers.get("content-type", ""))
                    for line in resp.iter_lines():
                        if line.startswith("data:"):
                            frame_times.append(
                                (time.monotonic() - t0, json.loads(line[len("data:") :].strip()))
                            )

            self.assertEqual(len(frame_times), 4)
            # First two frames (SUBMITTED, WORKING) MUST arrive well before the first 0.28s sleep ends;
            # Artifact frame MUST arrive around ~0.28s, well before final COMPLETED at ~0.56s!
            self.assertLess(frame_times[0][0], 0.20, f"First SSE frame was buffered: {frame_times}")
            self.assertLess(frame_times[2][0], 0.48, f"Mid-stream artifact was buffered: {frame_times}")
            self.assertGreater(frame_times[3][0] - frame_times[0][0], 0.45)

            # C. GetTask cross-tenant isolation
            tok_bob = mint_root_token(
                ca_a,
                "task-qa-bob-other",
                "user:bob@org-alpha.io",
                w_cli.jkt,
                w_srv.spiffe_id,
                w_srv.jkt,
                perms,
                first_hop_public_jwk=w_srv.keypair.public_jwk(),
            ).encode_compact()
            st_cross, body_cross = a2a_cli.get_task("task-qa-sse-1", compact_token=tok_bob)
            self.assertEqual(st_cross, 403)
            self.assertEqual(body_cross["error"]["code"], -32003)
        finally:
            sc.stop()
            app_srv.stop()

    # -------------------------------------------------------------------------
    # 3. Federation `/v1/federation/notify` SSRF Immunity & Anti-Spoofing
    # -------------------------------------------------------------------------
    def test_03_federation_notify_ssrf_immunity_and_card_event_anti_spoofing(self) -> None:
        ca_a = TrustDomainCA("org-alpha.io")
        ca_b = TrustDomainCA("org-beta.io")
        ca_p = TrustDomainCA("org-payment.io")
        resolver = TrustBundleResolver()
        for ca in (ca_a, ca_b, ca_p):
            resolver.register_domain_ca(ca)

        ssrf_hits: List[str] = []
        ssrf_target = ManagedHTTPService(
            "ssrf-canary",
            lambda req: (ssrf_hits.append(req.raw_path) or 200, {"canary": True}, {}),
            host="127.0.0.1",
            port=0,
        )
        canary_url = ssrf_target.start()

        dir_a = AgentDirectoryService(resolver, local_trust_domain="org-alpha.io", host="127.0.0.1", port=0)
        dir_b = AgentDirectoryService(resolver, local_trust_domain="org-beta.io", host="127.0.0.1", port=0)
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
        du_a, du_b = dir_a.start(), dir_b.start()
        ru_a, ru_p = rev_a.start(), rev_p.start()
        dir_a.peer_directory_urls = {"org-beta.io": du_b}
        rev_p.peer_revocation_urls = {"org-alpha.io": ru_a}

        try:
            # A. Attempt SSRF via attacker-supplied URLs in `/v1/federation/notify` body & query
            ssrf_payload = {
                "peer_url": canary_url,
                "callback_url": f"{canary_url}/steal",
                "source": canary_url,
            }
            r_dn = httpx.post(
                f"{du_a}/v1/federation/notify?peer_url={canary_url}",
                json=ssrf_payload,
                trust_env=False,
            )
            r_rn = httpx.post(
                f"{ru_p}/v1/federation/notify?peer_url={canary_url}",
                json=ssrf_payload,
                trust_env=False,
            )
            self.assertEqual(r_dn.status_code, 200)
            self.assertEqual(r_rn.status_code, 200)
            self.assertEqual(ssrf_hits, [], f"SSRF canary was contacted: {ssrf_hits}")

            # B. Cross-domain card spoofing & version downgrade protection
            w_b = ca_b.issue_workload("/ns/lineage-beta/sa/flight")
            card_v2 = AgentCard.sign_and_create(w_b, "Flight v2", "https://127.0.0.1:8443", ["travel.flight"], version=2)
            card_v1 = AgentCard.sign_and_create(w_b, "Flight v1", "https://127.0.0.1:9999", ["travel.flight"], version=1)
            dir_b.register_card_direct(card_v2.to_dict())
            with self.assertRaises(AgentCardError):
                dir_b.register_card_direct(card_v1.to_dict())

            # Third-party domain (`org-payment.io`) card smuggled via `beta-directory` rejected!
            w_p = ca_p.issue_workload("/ns/lineage-pay/sa/conv")
            card_p = AgentCard.sign_and_create(w_p, "Conv", "https://127.0.0.1:8445", ["settlement.converge"])
            with self.assertRaises(AgentCardError):
                dir_a.ingest_federated_card(card_p.to_dict(), expected_peer_domain="org-beta.io")

            # C. Healthy synchronous cross-domain revocation pull (`wait_ms=0`) BEFORE async notify
            #    Disable rev_a -> rev_p notify by leaving rev_a.peer_revocation_urls empty, then
            #    verify `payment-revocation` `GET /v1/events?wait_ms=0` pulls synchronously from `alpha-revocation`!
            rev_a.revoke_prefix_direct("/task-sync-1/Orch/FlightB1", "gateway", "test_sync", trust_domain="org-alpha.io")
            pay_replica = RevocationReplicaClient(ru_p, resolver)
            pay_replica.sync_now(wait_ms=0)
            self.assertIsNotNone(
                pay_replica.trie.check_lineage_path(
                    "/task-sync-1/Orch/FlightB1/Leaf", trust_domain="org-alpha.io"
                )
            )
        finally:
            for srv in (rev_p, rev_a, dir_b, dir_a, ssrf_target):
                srv.stop()

    # -------------------------------------------------------------------------
    # 4. Inbound mTLS Cross-Domain Client Pinning, Channel Binding & RAM Hygiene
    # -------------------------------------------------------------------------
    def test_04_mtls_inbound_client_domain_pinning_and_ram_key_cleanup(self) -> None:
        ca_a = TrustDomainCA("org-alpha.io")
        ca_b = TrustDomainCA("org-beta.io")
        x509_a = X509DomainAuthority("org-alpha.io")
        x509_b = X509DomainAuthority("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_a)
        resolver.register_domain_ca(ca_b)

        store = X509FederationTrustStore()
        store.register_domain_root_pem("org-alpha.io", x509_a.export_root_pem())
        store.register_domain_root_pem("org-beta.io", x509_b.export_root_pem())

        # Compromised `beta-ca` manually signs a leaf client cert claiming `spiffe://org-alpha.io/...`
        spoof_kp = KeyPair.generate("ES256")
        pub_k, _ = jwk_to_public_key(spoof_kp.public_jwk())
        now = dt.datetime.now(dt.timezone.utc)
        forged_client_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "spoof")]))
            .issuer_name(x509_b.root_cert.subject)
            .public_key(pub_k)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier("spiffe://org-alpha.io/ns/lineage-alpha/sa/orch")]
                ),
                critical=False,
            )
            .sign(private_key=x509_b._private_key, algorithm=hashes.SHA256())
        )
        # Inbound `verify_peer_der_cert` strictly pins `org-alpha.io` URI SAN to `alpha-ca` -> MTLSError!
        with self.assertRaises(MTLSError):
            store.verify_peer_der_cert(forged_client_cert.public_bytes(serialization.Encoding.DER))

        # Verify `LCT_MTLS_RAM_DIR` leaves zero residual files after `SSLContext` creation
        with tempfile.TemporaryDirectory() as fake_ram:
            prev = os.environ.get("LCT_MTLS_RAM_DIR")
            os.environ["LCT_MTLS_RAM_DIR"] = fake_ram
            try:
                w_a = ca_a.issue_workload("/ns/lineage-alpha/sa/orch")
                mb = WorkloadMTLSBundle(
                    w_a.spiffe_id,
                    w_a.keypair,
                    x509_a.issue_x509_svid(w_a.spiffe_id, w_a.keypair.public_jwk()),
                    store,
                )
                _ = mb.build_server_ssl_context()
                _ = mb.build_client_ssl_context()
                self.assertEqual(os.listdir(fake_ram), [])
            finally:
                if prev is None:
                    os.environ.pop("LCT_MTLS_RAM_DIR", None)
                else:
                    os.environ["LCT_MTLS_RAM_DIR"] = prev

    # -------------------------------------------------------------------------
    # 5. [HIGH-M3-01] Federated HIGH_RISK Revocation Fail-Open on Peer Partition
    # -------------------------------------------------------------------------
    def test_05_finding_high_m3_01_federated_high_risk_revocation_fail_open_on_partition(self) -> None:
        """Reproduces [HIGH-M3-01]:
        `org-alpha.io` revokes a task/subtree on `alpha-revocation`, while the cross-domain link
        between `payment-revocation` (`org-payment.io`) and `alpha-revocation` is partitioned.
        `RevocationService.sync_from_federation_peers` (`lineage/revocation/service.py:170-171`)
        silently swallows the peer connection failure (`except Exception: continue`) and returns
        200 OK on `GET /v1/events?wait_ms=0`, causing `payment-vault-mcp` (`ADAPTIVE_RISK_ANCHORED`,
        `fail_closed_on_high_risk=True`) to FAIL-OPEN (200 ALLOW) on a revoked HIGH_RISK payment!
        """
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
            # 1. Mint org-alpha.io root token -> attenuate to settlement-converger for HIGH_RISK settlement
            perms = PermissionLattice.create(
                tools=["execute_settlement"],
                max_amount=600.0,
                allowed_targets=["airline-escrow"],
                max_calls=4,
            )
            t_root = mint_root_token(
                ca_a,
                "task-partition-1",
                "user:alice@org-alpha.io",
                gw_id.jkt,
                conv_id.spiffe_id,
                conv_id.jkt,
                perms,
                first_hop_public_jwk=conv_id.keypair.public_jwk(),
            )
            compact_tok = t_root.encode_compact()

            # 2. `org-alpha.io` revokes `/task-partition-1` on `alpha-revocation`, AND cross-domain
            #    connectivity from `payment-revocation` -> `alpha-revocation` drops (partition)!
            rev_a.revoke_prefix_direct(
                "/task-partition-1", "gateway", "emergency_fraud_stop", trust_domain="org-alpha.io"
            )
            rev_a.stop()  # Simulate cross-domain partition where alpha-revocation is unreachable from lineage-pay
            rev_p.peer_revocation_urls = {"org-alpha.io": ru_a}

            # 3. Invoke HIGH_RISK `execute_settlement` (`amount=500.0`) on `payment-vault-mcp`
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
            # BUG DEMONSTRATION (`HIGH-M3-01`): Instead of failing closed with 503 REVOCATION_ANCHOR_UNAVAILABLE,
            # `payment-revocation` swallowed the `alpha-revocation` connection error and `payment-vault-mcp`
            # returned 200 ALLOW on a revoked HIGH_RISK transaction!
            self.assertEqual(
                resp.status_code,
                200,
                "Expected PoC to reproduce HIGH-M3-01 fail-open 200 response",
            )
            self.assertEqual(resp.json()["result"]["decision"], "ALLOW")
        finally:
            vault_mcp.stop()
            rev_p.stop()
            rev_a.stop()

    # -------------------------------------------------------------------------
    # 6. [HIGH-M3-02] Outbound mTLS Client Trusts Cross-Domain Spoofed Server Cert
    # -------------------------------------------------------------------------
    def test_06_finding_high_m3_02_outbound_mtls_client_trusts_cross_domain_spoofed_server_cert(
        self,
    ) -> None:
        """Reproduces [HIGH-M3-02]:
        `X509DomainAuthority.root_cert` (`lineage/common/mtls.py:80-115`) lacks `x509.NameConstraints`,
        and `WorkloadMTLSBundle.build_client_ssl_context` (`mtls.py:383-392`) loads all federated Root CAs
        into one flat OpenSSL context without server-side `verify_peer_der_cert` or per-domain pinning.
        Consequently, a compromised `beta-ca` can sign a TLS server certificate impersonating an
        `org-payment.io` / `org-alpha.io` service, and outbound mTLS clients accept the connection and
        transmit live `Authorization: DPoP <LCT>` credentials!
        """
        ca_a = TrustDomainCA("org-alpha.io")
        x509_a = X509DomainAuthority("org-alpha.io")
        x509_b = X509DomainAuthority("org-beta.io")
        x509_p = X509DomainAuthority("org-payment.io")

        store = X509FederationTrustStore()
        store.register_domain_root_pem("org-alpha.io", x509_a.export_root_pem())
        store.register_domain_root_pem("org-beta.io", x509_b.export_root_pem())
        store.register_domain_root_pem("org-payment.io", x509_p.export_root_pem())

        # Confirm Root CAs lack NameConstraints extension
        with self.assertRaises(x509.ExtensionNotFound):
            x509_b.root_cert.extensions.get_extension_for_class(x509.NameConstraints)

        # Compromised `beta-ca` mints a server leaf cert claiming `spiffe://org-payment.io/...` + target DNS
        rogue_kp = KeyPair.generate("ES256")
        pub_k, _ = jwk_to_public_key(rogue_kp.public_jwk())
        now = dt.datetime.now(dt.timezone.utc)
        spoofed_server_cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME,
                            "spiffe://org-payment.io/ns/lineage-pay/sa/payment-vault-mcp",
                        )
                    ]
                )
            )
            .issuer_name(x509_b.root_cert.subject)
            .public_key(pub_k)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
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
        spoof_pem = spoofed_server_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        spoof_srv_bundle = WorkloadMTLSBundle(
            "spiffe://org-payment.io/ns/lineage-pay/sa/payment-vault-mcp",
            rogue_kp,
            spoof_pem,
            store,
        )

        captured_headers: Dict[str, str] = {}
        mitm_srv = ManagedHTTPService(
            "rogue-beta-mitm",
            lambda req: (
                captured_headers.update({"auth": str(req.header("Authorization") or "")}) or 200,
                {"impersonated": True},
                {},
            ),
            host="127.0.0.1",
            port=0,
            ssl_context=spoof_srv_bundle.build_server_ssl_context(require_client_cert=True),
        )
        mitm_url = mitm_srv.start().replace("127.0.0.1", "localhost")
        try:
            w_alpha = ca_a.issue_workload("/ns/lineage-alpha/sa/orchestrator-alpha")
            alpha_bundle = WorkloadMTLSBundle(
                w_alpha.spiffe_id,
                w_alpha.keypair,
                x509_a.issue_x509_svid(w_alpha.spiffe_id, w_alpha.keypair.public_jwk(), dns_names=("localhost",)),
                store,
            )
            with httpx.Client(
                verify=alpha_bundle.build_client_ssl_context(check_hostname=True),
                trust_env=False,
                timeout=5.0,
            ) as client:
                r = client.post(
                    f"{mitm_url}/mcp",
                    headers={"Authorization": "DPoP live-sensitive-lct-token"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                )
            # BUG DEMONSTRATION (`HIGH-M3-02`): Outbound mTLS client accepted the cross-domain spoofed server cert!
            self.assertEqual(r.status_code, 200)
            self.assertEqual(captured_headers.get("auth"), "DPoP live-sensitive-lct-token")
        finally:
            mitm_srv.stop()

    # -------------------------------------------------------------------------
    # 7. [MEDIUM-M3-01] `CancelTask` Non-Atomic State Mutation & Sibling Cancel
    # -------------------------------------------------------------------------
    def test_07_finding_medium_m3_01_canceltask_atomicity_and_sibling_branch_cancel(self) -> None:
        """Reproduces [MEDIUM-M3-01]:
        (a) `A2AServerEngine.dispatch` (`lineage/a2a/rpc.py:510-536`) permanently mutates the task
            in `A2ATaskStore` to `TASK_STATE_CANCELED` BEFORE `cascade_revoke_hook` validates
            revocation authority, leaving state corrupted as `CANCELED` even when `CancelTask`
            returns HTTP 403!
        (b) `A2ATaskStore.cancel_authorized` (`lineage/a2a/models.py:685`) checks only `owner_sub`
            and omits lineage-prefix ancestry verification, allowing a sibling branch for the same
            `(task_id, sub)` to cancel the primary branch's task!
        """
        def _reject_foreign_prefix(_req_id: str, prefix: str, _tid: str) -> Dict[str, Any]:
            if not prefix.startswith("/task-atomic-1/Orch/HotelSibling"):
                raise RuntimeError(f"Caller lacks authority over prefix {prefix!r}")
            return {"target": prefix, "version": 1}

        eng = A2AServerEngine(
            agent_name="converger-qa",
            work_handler=lambda _ctx, _msg, _emit: (
                Message.create_agent("staged"),
                {"stagedForSettlement": True},
            ),
            cascade_revoke_hook=_reject_foreign_prefix,
        )

        # Primary branch `/task-atomic-1/Orch/FlightPrimary/ConvC` creates staged task
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
                        "params": {"message": Message.create_user("stage", task_id="task-atomic-1").to_dict()},
                    }
                ).encode("utf-8"),
                server_host="127.0.0.1",
                server_port=9001,
            )
        )
        self.assertEqual(st1, 200)
        self.assertEqual(b1["result"]["task"]["status"]["state"], TaskState.COMPLETED.value)

        # Sibling branch `/task-atomic-1/Orch/HotelSibling/ConvC` calls CancelTask WITHOUT authority
        # over `/task-atomic-1/Orch/FlightPrimary/ConvC` -> `cascade_revoke_hook` fails with 403!
        st_can, b_can, _ = eng.dispatch(
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
        self.assertEqual(st_can, 403)
        self.assertEqual(b_can["error"]["code"], -32003)

        # BUG DEMONSTRATION (`MEDIUM-M3-01`): Even though CancelTask returned 403 Forbidden AND was
        # called from a non-ancestor sibling branch, the task is now permanently CANCELED!
        st_get, b_get, _ = eng.dispatch(
            HTTPRequestContext(
                method="POST",
                raw_path="/a2a",
                headers={
                    "A2A-Version": "1.0",
                    "X-LCT-Request-Id": "req-3",
                    "X-LCT-Task-Id": "task-atomic-1",
                    "X-LCT-Sub": "user:alice@org-alpha.io",
                    "X-LCT-Lineage-Path": "/task-atomic-1/Orch/FlightPrimary/ConvC",
                },
                body=json.dumps(
                    {"jsonrpc": "2.0", "id": "3", "method": "GetTask", "params": {"id": "task-atomic-1"}}
                ).encode("utf-8"),
                server_host="127.0.0.1",
                server_port=9001,
            )
        )
        self.assertEqual(st_get, 200)
        self.assertEqual(b_get["result"]["task"]["status"]["state"], TaskState.CANCELED.value)

    # -------------------------------------------------------------------------
    # 8. [MEDIUM-M3-02], [LOW-M3-01], [LOW-M3-02] Leaf Cert EKU, SA Suffix & RPC
    # -------------------------------------------------------------------------
    def test_08_findings_medium_m3_02_and_low_m3_01_02_cert_eku_sa_suffix_and_jsonrpc(
        self,
    ) -> None:
        # A. [MEDIUM-M3-02]: Leaf cert WITHOUT BasicConstraints, WITHOUT KeyUsage, and with ONLY
        #    EMAIL_PROTECTION ExtendedKeyUsage is accepted by `verify_peer_der_cert`!
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
            # Deliberately omit BasicConstraints & KeyUsage, and set wrong EKU (EMAIL_PROTECTION)
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
        spiffe_uri, _ = store.verify_peer_der_cert(weak_leaf.public_bytes(serialization.Encoding.DER))
        self.assertEqual(spiffe_uri, "spiffe://org-alpha.io/ns/lineage-alpha/sa/orch")

        # B. [LOW-M3-01]: Wildcard `-revocation` suffix elevates ordinary business SA `order-revocation`
        #    to system control-plane identity `/ns/sys/sa/revocation`!
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
        resolved_path = dom_ca._resolve_workload_path("lineage-alpha", "order-revocation")
        self.assertEqual(resolved_path, "/ns/sys/sa/revocation")

        # C. [LOW-M3-02]: JSON-RPC 2.0 edge cases (`[]` -> -32700 instead of -32600; `"method": 123` -> 404 -32601)
        eng = A2AServerEngine(
            "rpc-edge",
            lambda _c, _m, _e: (Message.create_agent("ok"), {}),
        )
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
        self.assertEqual(b_arr["error"]["code"], -32700)  # Should be -32600 Invalid Request

        st_num_m, b_num_m, _ = eng.dispatch(
            HTTPRequestContext(
                method="POST",
                raw_path="/a2a",
                headers={
                    "A2A-Version": "1.0",
                    "X-LCT-Task-Id": "t1",
                    "X-LCT-Sub": "user:alice@org-alpha.io",
                },
                body=b'{"jsonrpc": "2.0", "id": true, "method": 12345}',
                server_host="127.0.0.1",
                server_port=9001,
            )
        )
        self.assertEqual(st_num_m, 404)
        self.assertEqual(b_num_m["error"]["code"], -32601)  # Should be 400 -32600 Invalid Request


if __name__ == "__main__":
    unittest.main(verbosity=2)
