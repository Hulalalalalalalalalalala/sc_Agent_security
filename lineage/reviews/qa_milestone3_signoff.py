"""Milestone 3 Round 2 Independent Final Sign-Off Verification Suite.

Written by `k8s-qa-reviewer` (`lineage/reviews/qa_milestone3_signoff.py`).
Strictly read-only on business source code, manifests, prior review artifacts, and K8s state.

Positively verifies all 6 Milestone 3 remediations (`HIGH-M3-01..LOW-M3-02`),
latest E2E run artifacts (`lineage/k8s/runs/20261119T095032Z/`), and live
`kind-agent-identity-lab` cluster security invariants.
"""

from __future__ import annotations

import datetime as dt
import glob
import ipaddress
import json
import os
import re
import shutil
import subprocess
import time
import unittest
from typing import Any, Dict, List, Tuple

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from lineage.a2a import A2AServerEngine, Message, TaskState
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
from lineage.sidecar import MCPToolSidecarNode
from lineage.verifier import VerificationMode


REPO_ROOT = "/Users/hulalala/Desktop/A"
REVIEWS_DIR = os.path.join(REPO_ROOT, "lineage/reviews")
M3_SIGN_RUN_DIR = os.path.join(REPO_ROOT, "lineage/k8s/runs/20261119T095032Z")


class Milestone3FinalSignoffTests(unittest.TestCase):
    """Positive sign-off suite locking in all Milestone 3 security & compliance guarantees."""

    # -------------------------------------------------------------------------
    # 1. Artifact Redaction, Prior Review Preservation & Causal Audit Integrity
    # -------------------------------------------------------------------------
    def test_01_prior_reviews_intact_and_latest_run_redacted_and_clean(self) -> None:
        for expected_review_file in (
            "MILESTONE1_QA_REPORT.md",
            "MILESTONE1_QA_SIGNOFF.md",
            "MILESTONE2_QA_REPORT.md",
            "MILESTONE2_QA_SIGNOFF.md",
            "MILESTONE3_QA_REPORT.md",
            "qa_milestone2_review.py",
            "qa_milestone2_signoff.py",
            "qa_milestone3_review.py",
        ):
            self.assertTrue(
                os.path.isfile(os.path.join(REVIEWS_DIR, expected_review_file)),
                f"Missing historical review file: {expected_review_file}",
            )

        self.assertTrue(os.path.isdir(M3_SIGN_RUN_DIR), f"Missing run dir: {M3_SIGN_RUN_DIR}")
        files = sorted(glob.glob(os.path.join(M3_SIGN_RUN_DIR, "*")))
        self.assertEqual(len(files), 15)

        forbidden = {
            "PEM_PRIVATE_KEY": re.compile(r"BEGIN [A-Z0-9 ]*PRIVATE KEY"),
            "RAW_LCT_TOKEN": re.compile(r"\blct(?:mp)?1\.[A-Za-z0-9_-]{12,}"),
            "RAW_COMPACT_JWS": re.compile(
                r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
            ),
            "JWK_PRIVATE_D": re.compile(r'"d"\s*:\s*"[A-Za-z0-9_-]{20,}"'),
        }
        leaks: List[Tuple[str, str, str]] = []
        for fpath in files:
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            for name, pat in forbidden.items():
                m = pat.search(content)
                if m:
                    leaks.append((os.path.basename(fpath), name, m.group(0)[:48]))
        self.assertEqual(leaks, [], f"Redaction violation in {M3_SIGN_RUN_DIR}: {leaks}")

        for scen_file in (
            "scenario1_normal_dag.json",
            "scenario2a_zombie_prune_graft.json",
            "scenario2b_pod_down_prune_graft.json",
            "scenario3a_false_skip_blocked.json",
            "scenario3b_skip_level_return.json",
            "scenario4_fagin_degradation_and_isolation.json",
            "scenario5_causal_audit_report.json",
        ):
            with open(os.path.join(M3_SIGN_RUN_DIR, scen_file), "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc.get("status"), "PASS", f"{scen_file} did not PASS")

        with open(
            os.path.join(M3_SIGN_RUN_DIR, "scenario5_causal_audit_report.json"),
            "r",
            encoding="utf-8",
        ) as fh:
            s5 = json.load(fh)
        self.assertTrue(s5["clean"])
        self.assertTrue(s5["stream_hash_chain_integrity_ok"])
        self.assertEqual(s5["reconstructed_tasks_numerator"], 13)
        self.assertEqual(s5["total_tasks_denominator"], 13)

    # -------------------------------------------------------------------------
    # 2. [HIGH-M3-01] Cross-Domain HIGH_RISK Synchronous Fail-Closed Matrix
    # -------------------------------------------------------------------------
    def test_02_high_m3_01_cross_domain_high_risk_fail_closed_matrix(self) -> None:
        ca_a = TrustDomainCA("org-alpha.io")
        ca_b = TrustDomainCA("org-beta.io")
        ca_p = TrustDomainCA("org-payment.io")
        resolver = TrustBundleResolver()
        for ca in (ca_a, ca_b, ca_p):
            resolver.register_domain_ca(ca)

        rev_a = RevocationService(
            ca_a.issue_workload("/ns/sys/sa/revocation"),
            resolver,
            strict_domain_isolation=True,
            host="127.0.0.1",
            port=0,
        )
        rev_b = RevocationService(
            ca_b.issue_workload("/ns/sys/sa/revocation"),
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
        ru_a, ru_b, ru_p = rev_a.start(), rev_b.start(), rev_p.start()
        rev_p.peer_revocation_urls = {"org-alpha.io": ru_a, "org-beta.io": ru_b}

        # Rogue peer returning ordinary non-revocation workload SVID on `/v1/federation/events`
        non_rev_alpha = ca_a.issue_workload("/ns/lineage-alpha/sa/rogue-app")
        rogue_peer = ManagedHTTPService(
            "rogue-rev-peer",
            lambda _req: (
                200,
                {
                    "trust_domain": "org-alpha.io",
                    "service_svid": non_rev_alpha.workload_svid,
                    "events": [],
                },
                {},
            ),
            host="127.0.0.1",
            port=0,
        )
        rogue_peer_url = rogue_peer.start()

        gw_id = ca_a.issue_workload("/ns/lineage-alpha/sa/gateway")
        beta_id = ca_b.issue_workload("/ns/lineage-beta/sa/flight-specialist")
        conv_id = ca_p.issue_workload("/ns/lineage-pay/sa/settlement-converger")
        vault_id = ca_p.issue_workload("/ns/lineage-pay/sa/payment-vault-mcp")

        vault_mcp = MCPToolSidecarNode(
            identity=vault_id,
            trust_resolver=resolver,
            tools={"execute_settlement": lambda args, _req: {"settled_usd": args["amount"]}},
            revocation_url=ru_p,
            mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
        )
        vault_url = vault_mcp.start()
        mcp_ep = f"{vault_url}/mcp"

        try:
            perms = PermissionLattice.create(
                tools=["execute_settlement"],
                max_amount=600.0,
                allowed_targets=["airline-escrow"],
                max_calls=6,
            )
            # 3-domain chain: org-alpha.io (root) -> org-beta.io (beta_id) -> org-payment.io (conv_id)
            t0 = mint_root_token(
                ca_a,
                "task-signoff-hr-1",
                "user:alice@org-alpha.io",
                gw_id.jkt,
                beta_id.spiffe_id,
                beta_id.jkt,
                perms,
                first_hop_public_jwk=beta_id.keypair.public_jwk(),
            )
            t1 = t0.attenuate(
                issuer_identity=beta_id,
                delegate_spiffe_id=conv_id.spiffe_id,
                delegate_jkt=conv_id.jkt,
                permissions=perms,
                hop_segment="SettlementC",
            )
            tok_chain = t1.encode_compact()

            def _call_high_risk(tok_str: str) -> httpx.Response:
                dpop = create_dpop_proof(conv_id, "POST", mcp_ep, tok_str)
                return httpx.post(
                    mcp_ep,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "execute_settlement",
                            "arguments": {"target": "airline-escrow", "amount": 450.0},
                        },
                    },
                    headers={"Authorization": f"DPoP {tok_str}", "DPoP": dpop},
                    trust_env=False,
                    timeout=8.0,
                )

            # Case 1: Origin domain `alpha-revocation` unreachable -> 503 Fail-Closed!
            rev_p.peer_revocation_urls = {
                "org-alpha.io": "http://127.0.0.1:9",
                "org-beta.io": ru_b,
            }
            r1 = _call_high_risk(tok_chain)
            self.assertEqual(r1.status_code, 503)
            self.assertEqual(r1.json()["error"], "REVOCATION_ANCHOR_UNAVAILABLE")

            # Case 2: Intermediate visited domain `beta-revocation` unreachable -> 503 Fail-Closed!
            rev_p.peer_revocation_urls = {
                "org-alpha.io": ru_a,
                "org-beta.io": "http://127.0.0.1:9",
            }
            r2 = _call_high_risk(tok_chain)
            self.assertEqual(r2.status_code, 503)
            self.assertEqual(r2.json()["error"], "REVOCATION_ANCHOR_UNAVAILABLE")

            # Case 3: Rogue peer presenting non-system workload SVID with empty events -> 503 Fail-Closed!
            rev_p.peer_revocation_urls = {
                "org-alpha.io": rogue_peer_url,
                "org-beta.io": ru_b,
            }
            r3 = _call_high_risk(tok_chain)
            self.assertEqual(r3.status_code, 503)
            self.assertEqual(r3.json()["error"], "REVOCATION_ANCHOR_UNAVAILABLE")

            # Case 4: Restore healthy peers -> unrevoked chain succeeds (200), then revoke on alpha -> 403!
            rev_p.peer_revocation_urls = {"org-alpha.io": ru_a, "org-beta.io": ru_b}
            r4_ok = _call_high_risk(tok_chain)
            self.assertEqual(r4_ok.status_code, 200)

            rev_a.revoke_prefix_direct(
                "/task-signoff-hr-1",
                "gateway",
                "post_check_revoke",
                trust_domain="org-alpha.io",
            )
            r4_rev = _call_high_risk(tok_chain)
            self.assertEqual(r4_rev.status_code, 403)
            self.assertEqual(r4_rev.json()["error"], "LINEAGE_REVOKED")
        finally:
            vault_mcp.stop()
            rogue_peer.stop()
            rev_p.stop()
            rev_b.stop()
            rev_a.stop()

    # -------------------------------------------------------------------------
    # 3. [HIGH-M3-02] Critical NameConstraints & Handshake-Layer Server Pinning
    # -------------------------------------------------------------------------
    def test_03_high_m3_02_name_constraints_and_handshake_layer_mitm_block(self) -> None:
        ca_a = TrustDomainCA("org-alpha.io")
        ca_b = TrustDomainCA("org-beta.io")
        x509_a = X509DomainAuthority(
            "org-alpha.io",
            allowed_dns_suffixes=(".lineage-alpha.svc.cluster.local", ".lineage-alpha.svc", "localhost"),
        )
        x509_b = X509DomainAuthority(
            "org-beta.io",
            allowed_dns_suffixes=(".lineage-beta.svc.cluster.local", ".lineage-beta.svc", "localhost"),
        )
        x509_p = X509DomainAuthority(
            "org-payment.io",
            allowed_dns_suffixes=(".lineage-pay.svc.cluster.local", ".lineage-pay.svc", "localhost"),
        )

        store = X509FederationTrustStore()
        store.register_domain_root_pem("org-alpha.io", x509_a.export_root_pem())
        store.register_domain_root_pem("org-beta.io", x509_b.export_root_pem())
        store.register_domain_root_pem("org-payment.io", x509_p.export_root_pem())

        # DNS subtree collision across peer domains (`org-rogue.io` claiming `.lineage-pay.svc`) -> MTLSError!
        x509_colliding = X509DomainAuthority(
            "org-rogue.io",
            allowed_dns_suffixes=(".lineage-pay.svc.cluster.local", "localhost"),
        )
        with self.assertRaises(MTLSError):
            store.register_domain_root_pem("org-rogue.io", x509_colliding.export_root_pem())

        # Verify K8s service hostname domain inference
        self.assertEqual(
            store.infer_trust_domain_from_hostname("payment-vault-mcp.lineage-pay.svc.cluster.local"),
            "org-payment.io",
        )
        self.assertEqual(
            store.infer_trust_domain_from_hostname("flight-specialist.lineage-beta.svc"),
            "org-beta.io",
        )

        # Verify zero HTTP bytes reach a rogue `beta-ca`-certified server when client expects `org-payment.io`
        leaked_headers: List[str] = []
        w_beta = ca_b.issue_workload("/ns/lineage-beta/sa/rogue-srv")
        beta_srv_bundle = WorkloadMTLSBundle(
            w_beta.spiffe_id,
            w_beta.keypair,
            x509_b.issue_x509_svid(w_beta.spiffe_id, w_beta.keypair.public_jwk(), dns_names=("localhost",)),
            store,
        )
        rogue_srv = ManagedHTTPService(
            "rogue-beta-srv",
            lambda req: (leaked_headers.append(str(req.header("Authorization") or "")) or 200, {"ok": True}, {}),
            host="127.0.0.1",
            port=0,
            ssl_context=beta_srv_bundle.build_server_ssl_context(require_client_cert=True),
        )
        rogue_url = rogue_srv.start().replace("127.0.0.1", "localhost")
        try:
            w_alpha = ca_a.issue_workload("/ns/lineage-alpha/sa/orchestrator-alpha")
            alpha_bundle = WorkloadMTLSBundle(
                w_alpha.spiffe_id,
                w_alpha.keypair,
                x509_a.issue_x509_svid(w_alpha.spiffe_id, w_alpha.keypair.public_jwk(), dns_names=("localhost",)),
                store,
            )
            pinned_ctx = alpha_bundle.verify_for_target(
                target_url=rogue_url,
                expected_spiffe_id="spiffe://org-payment.io/ns/lineage-pay/sa/payment-vault-mcp",
            )
            with self.assertRaises(httpx.HTTPError):
                with httpx.Client(verify=pinned_ctx, trust_env=False, timeout=3.0) as cli:
                    cli.post(
                        f"{rogue_url}/mcp",
                        headers={"Authorization": "DPoP top-secret-token"},
                        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    )
            self.assertEqual(leaked_headers, [])
        finally:
            rogue_srv.stop()

    # -------------------------------------------------------------------------
    # 4. [MEDIUM-M3-01] CancelTask Segment-Exact Ancestry & State Atomicity
    # -------------------------------------------------------------------------
    def test_04_medium_m3_01_canceltask_segment_ancestry_and_atomicity(self) -> None:
        allow_hook = False

        def _hook(_req_id: str, prefix: str, _tid: str) -> Dict[str, Any]:
            if not allow_hook:
                raise RuntimeError("Simulated revocation service outage")
            return {"target": prefix, "version": 11}

        eng = A2AServerEngine(
            "conv-signoff",
            work_handler=lambda _c, _m, _e: (
                Message.create_agent("staged"),
                {"stagedForSettlement": True},
            ),
            cascade_revoke_hook=_hook,
        )

        def _mk_req(path: str, payload: Dict[str, Any]) -> HTTPRequestContext:
            return HTTPRequestContext(
                method="POST",
                raw_path="/a2a",
                headers={
                    "A2A-Version": "1.0",
                    "X-LCT-Request-Id": "r1",
                    "X-LCT-Task-Id": "task-can-1",
                    "X-LCT-Sub": "user:alice@org-alpha.io",
                    "X-LCT-Lineage-Path": path,
                },
                body=json.dumps(payload).encode("utf-8"),
                server_host="127.0.0.1",
                server_port=9001,
            )

        st_s, _, _ = eng.dispatch(
            _mk_req(
                "/task-can-1/Orch/FlightExtra/ConvC",
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "SendMessage",
                    "params": {"message": Message.create_user("go", task_id="task-can-1").to_dict()},
                },
            )
        )
        self.assertEqual(st_s, 200)

        # Near-miss segment prefix `/task-can-1/Orch/Flight` MUST NOT match `/task-can-1/Orch/FlightExtra/ConvC`!
        st_near, b_near, _ = eng.dispatch(
            _mk_req(
                "/task-can-1/Orch/Flight",
                {"jsonrpc": "2.0", "id": 2, "method": "CancelTask", "params": {"id": "task-can-1"}},
            )
        )
        self.assertEqual(st_near, 403)
        self.assertEqual(b_near["error"]["code"], -32003)

        # Valid upstream ancestor `/task-can-1/Orch` while hook fails -> 403 AND task stays COMPLETED!
        st_fail, _, _ = eng.dispatch(
            _mk_req(
                "/task-can-1/Orch",
                {"jsonrpc": "2.0", "id": 3, "method": "CancelTask", "params": {"id": "task-can-1"}},
            )
        )
        self.assertEqual(st_fail, 403)
        snap_still_ok = eng.task_store.get_authorized("task-can-1", "user:alice@org-alpha.io")
        self.assertEqual(snap_still_ok.status.state, TaskState.COMPLETED)

        # Enable hook -> upstream ancestor `/task-can-1/Orch` atomically cancels & records revocation!
        allow_hook = True
        st_ok, b_ok, _ = eng.dispatch(
            _mk_req(
                "/task-can-1/Orch",
                {"jsonrpc": "2.0", "id": 4, "method": "CancelTask", "params": {"id": "task-can-1"}},
            )
        )
        self.assertEqual(st_ok, 200)
        self.assertEqual(b_ok["result"]["task"]["status"]["state"], TaskState.CANCELED.value)
        self.assertEqual(b_ok["result"]["revocation"]["version"], 11)

    # -------------------------------------------------------------------------
    # 5. [MEDIUM-M3-02], [LOW-M3-01], [LOW-M3-02] Extensions, SA Allowlist & RPC
    # -------------------------------------------------------------------------
    def test_05_medium_m3_02_and_low_m3_01_02_extensions_allowlist_and_jsonrpc(self) -> None:
        x509_a = X509DomainAuthority("org-alpha.io")
        store = X509FederationTrustStore()
        store.register_domain_root_pem("org-alpha.io", x509_a.export_root_pem())

        kp = KeyPair.generate("ES256")
        pub_k, _ = jwk_to_public_key(kp.public_jwk())
        now = dt.datetime.now(dt.timezone.utc)

        def _mint_custom_leaf(
            add_bc: bool,
            add_ku: bool,
            key_cert_sign: bool,
            ekus: List[x509.ObjectIdentifier] | None,
        ) -> bytes:
            b = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
                .issuer_name(x509_a.root_cert.subject)
                .public_key(pub_k)
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=1))
                .not_valid_after(now + dt.timedelta(hours=1))
                .add_extension(
                    x509.SubjectAlternativeName(
                        [x509.UniformResourceIdentifier("spiffe://org-alpha.io/ns/lineage-alpha/sa/orch")]
                    ),
                    critical=False,
                )
            )
            if add_bc:
                b = b.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            if add_ku:
                b = b.add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=True,
                        data_encipherment=False,
                        key_agreement=True,
                        key_cert_sign=key_cert_sign,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
            if ekus is not None:
                b = b.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
            return b.sign(x509_a._private_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

        # Missing BC, missing KU, key_cert_sign=True, missing EKU, wrong EKU -> ALL rejected!
        for bad_der, req_eku in (
            (_mint_custom_leaf(False, True, False, [ExtendedKeyUsageOID.CLIENT_AUTH]), ExtendedKeyUsageOID.CLIENT_AUTH),
            (_mint_custom_leaf(True, False, False, [ExtendedKeyUsageOID.CLIENT_AUTH]), ExtendedKeyUsageOID.CLIENT_AUTH),
            (_mint_custom_leaf(True, True, True, [ExtendedKeyUsageOID.CLIENT_AUTH]), ExtendedKeyUsageOID.CLIENT_AUTH),
            (_mint_custom_leaf(True, True, False, None), ExtendedKeyUsageOID.CLIENT_AUTH),
            (_mint_custom_leaf(True, True, False, [ExtendedKeyUsageOID.EMAIL_PROTECTION]), ExtendedKeyUsageOID.CLIENT_AUTH),
            (_mint_custom_leaf(True, True, False, [ExtendedKeyUsageOID.CLIENT_AUTH]), ExtendedKeyUsageOID.SERVER_AUTH),
        ):
            with self.assertRaises(MTLSError):
                store.verify_peer_der_cert(bad_der, required_eku=req_eku)

        # Valid leaf with CLIENT_AUTH + SERVER_AUTH passes both checks
        good_der = _mint_custom_leaf(
            True, True, False, [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
        )
        sp_uri, _ = store.verify_peer_der_cert(good_der, required_eku=ExtendedKeyUsageOID.SERVER_AUTH)
        self.assertEqual(sp_uri, "spiffe://org-alpha.io/ns/lineage-alpha/sa/orch")

        # [LOW-M3-01] Exact SA allowlist check
        oidc_kp = KeyPair.generate("RS256")
        v = K8sServiceAccountVerifier(allowed_audiences=("lct-federation-ca",))
        v._keys_by_kid = {oidc_kp.public_jwk()["kid"]: oidc_kp.public_jwk()}
        v._last_refresh = time.time() + 3600.0
        dom_ca = AutonomousDomainCAService("org-alpha.io", "lineage-alpha", k8s_verifier=v, host="127.0.0.1", port=0)
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

        # [LOW-M3-02] Strict JSON-RPC 2.0 parse (-32700) vs Invalid Request (-32600)
        eng = A2AServerEngine("rpc-signoff", lambda _c, _m, _e: (Message.create_agent("ok"), {}))

        def _rpc(raw_bytes: bytes) -> Tuple[int, Dict[str, Any]]:
            st, body, _ = eng.dispatch(
                HTTPRequestContext(
                    method="POST",
                    raw_path="/a2a",
                    headers={
                        "A2A-Version": "1.0",
                        "X-LCT-Task-Id": "t1",
                        "X-LCT-Sub": "user:alice@org-alpha.io",
                    },
                    body=raw_bytes,
                    server_host="127.0.0.1",
                    server_port=9001,
                )
            )
            return st, body  # type: ignore[return-value]

        st_bad_json, b_bad_json = _rpc(b"{not-json")
        self.assertEqual((st_bad_json, b_bad_json["error"]["code"]), (400, -32700))

        for invalid_req_bytes in (
            b"[]",
            b'"scalar"',
            b'{"jsonrpc": "2.0", "id": true, "method": "GetTask"}',
            b'{"jsonrpc": "2.0", "id": 1.5, "method": "GetTask"}',
            b'{"jsonrpc": "2.0", "id": 1, "method": 12345}',
            b'{"jsonrpc": "2.0", "id": 1, "method": "GetTask", "result": {}}',
        ):
            st_inv, b_inv = _rpc(invalid_req_bytes)
            self.assertEqual(
                (st_inv, b_inv["error"]["code"]),
                (400, -32600),
                f"Payload {invalid_req_bytes!r} returned {st_inv} {b_inv}",
            )

    # -------------------------------------------------------------------------
    # 6. Live K8s Cluster Read-Only Sign-Off Verification
    # -------------------------------------------------------------------------
    def test_06_live_k8s_cluster_root_ca_constraints_and_pod_isolation(self) -> None:
        env = dict(os.environ)
        env["PATH"] = f"{REPO_ROOT}/.tools/bin:{os.path.expanduser('~')}/.docker/bin:{env.get('PATH', '')}"
        kubectl = shutil.which("kubectl", path=env["PATH"])
        self.assertIsNotNone(kubectl, "kubectl binary not found")

        # 1. Verify `team1` 3 baseline pods remain 2/2 Running
        r_t1 = subprocess.run(
            [kubectl, "--context", "kind-agent-identity-lab", "-n", "team1", "get", "pods", "-o", "json"],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        t1_items = json.loads(r_t1.stdout)["items"]
        self.assertEqual(len(t1_items), 3)
        for pod in t1_items:
            self.assertEqual(pod["status"]["phase"], "Running")

        # 2. Verify all 3 live autonomous CAs serve critical NameConstraints + BasicConstraints(path_length=0)
        expected_cas = (
            ("lineage-alpha", "deploy/alpha-ca", "org-alpha.io", ".lineage-alpha.svc.cluster.local"),
            ("lineage-beta", "deploy/beta-ca", "org-beta.io", ".lineage-beta.svc.cluster.local"),
            ("lineage-pay", "deploy/payment-ca", "org-payment.io", ".lineage-pay.svc.cluster.local"),
        )
        for ns, dep, exp_td, exp_dns in expected_cas:
            probe = subprocess.run(
                [
                    kubectl,
                    "--context",
                    "kind-agent-identity-lab",
                    "-n",
                    ns,
                    "exec",
                    dep,
                    "--",
                    "/app/.venv/bin/python3",
                    "-c",
                    "import httpx, json; print(json.dumps(httpx.get('http://127.0.0.1:8090/v1/federation/bundle', trust_env=False, timeout=3.0).json()))",
                ],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            bundle = json.loads(probe.stdout.strip())
            self.assertEqual(bundle["trust_domain"], exp_td)
            cert = x509.load_pem_x509_certificate(bundle["x509_root_pem"].encode("ascii"))
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            nc = cert.extensions.get_extension_for_class(x509.NameConstraints)
            self.assertTrue(bc.critical and bc.value.ca and bc.value.path_length == 0)
            self.assertTrue(nc.critical)
            uris = [
                g.value
                for g in (nc.value.permitted_subtrees or [])
                if isinstance(g, x509.UniformResourceIdentifier)
            ]
            dns_list = [
                g.value
                for g in (nc.value.permitted_subtrees or [])
                if isinstance(g, x509.DNSName)
            ]
            self.assertEqual(uris, [exp_td])
            self.assertIn(exp_dns, dns_list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
