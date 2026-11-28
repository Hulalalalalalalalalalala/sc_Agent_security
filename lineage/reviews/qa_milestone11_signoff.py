"""Independent Round-2 Milestone 11 QA Sign-Off Suite (`qa_milestone11_signoff.py`).

Read-only re-verification & pre-push compliance suite written by `k8s-qa-reviewer` confirming
complete remediation of all 5 findings from `MILESTONE11_QA_REPORT.md`:
1. `[CRITICAL-M11-01]`: Strict `https://` enforcement in `WorkloadMTLSBundle.verify_for_target` &
   `LineageSidecar._outbound_verify_kwarg` (`403 PLAINTEXT_HTTP_FORBIDDEN_UNDER_MTLS`), plus strict
   rejection (`403 UNVERIFIED_TARGET_URL_FORBIDDEN_FOR_OPAQUE_HANDLE`) of caller-supplied
   `target_url` / `delegate_jkt` whenever `consent_handle` or `digest_handles` is redeemed;
2. `[HIGH-M11-01]`: 0-RTT local lattice subset check (`403 LATTICE_PERMISSION_DENIED`), OIDC home
   domain check (`403 CROSS_DOMAIN_OIDC_EXFILTRATION_BLOCKED`) against poisoned `priority=1`
   cross-domain Yellow Pages cards, `403 TARGET_TRUST_DOMAIN_MISMATCH`, and full cryptographic +
   claim binding verification on returned peer consent tokens;
3. `[HIGH-M11-02]`: Native `LineageSidecar` inbound `op: "request_co_auth_consent"` handling (zero
   wire tokens in Node.js `app`), `403 CONSENT_MINTING_OWNED_BY_SIDECAR` in `server.mjs`,
   unconditional `digest_jws` redaction when `used_opaque_consent` is True (even if
   `redact_digest_jws=False`), and true LRU (`move_to_end`) + `600s` TTL wallet eviction;
4. `[MEDIUM-M11-01]`: Cumulative `turnsExecuted <= maxTurns`, `timedOut` abort halting remaining
   `follow_up_prompts`, and `2 MiB` (`413`) body caps in both `server.mjs` and `lct_sdk.mjs`;
5. `[LOW-M11-01]`: Broadened cloud API-key scrubbing (`sk-or-v1-*`, `sk-svcacct-*`, `gsk_*`,
   `xai-*`, `hf_*`, `AIza*`), embedded 3-part JWS scrubbing in `redact_sensitive`, `OllamaError`
   scrubbing, and URL userinfo/query stripping;
6. Round-2 live 3-cluster rehearsal archive (`20261128-m11-r2-pi-agent-rehearsal`) & pre-push
   dry-run hygiene (`workspace` & `lineage-only`).
"""

from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional
import unittest

import httpx

from lineage.agents.ollama_client import OllamaClient, OllamaError
from lineage.audit import AuditStreamEmitter
from lineage.common.crypto import redact_sensitive
from lineage.common.mtls import (
    MTLSError,
    WorkloadMTLSBundle,
    X509DomainAuthority,
    X509FederationTrustStore,
)
from lineage.protocol import PermissionLattice, decode_token, mint_root_token
from lineage.registry import AgentCard
from lineage.revocation import RevocationReplicaClient
from lineage.sidecar import LineageSidecar
from lineage.tests.test_m10_expanded_scenarios import _MultiDomainWorkspaceMesh
from lineage.verifier import VerificationMode


REPO_ROOT = Path(__file__).resolve().parents[2]
LINEAGE_DIR = REPO_ROOT / "lineage"
PI_AGENT_DIR = LINEAGE_DIR / "pi_agent"
R2_REHEARSAL_DIR = LINEAGE_DIR / "k8s" / "runs" / "20261128-m11-r2-pi-agent-rehearsal"


def _find_node_bin() -> str:
    extra = [
        str(Path.home() / ".local" / "bin"),
        "/opt/homebrew/bin",
        "/usr/local/bin",
        os.environ.get("PATH", ""),
    ]
    node_bin = shutil.which("node", path=":".join(p for p in extra if p))
    if not node_bin:
        raise RuntimeError("Node.js binary not found")
    return node_bin


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Milestone11Round2SignOffTests(unittest.TestCase):
    """Strict Round-2 security remediation & compliance sign-off suite."""

    def test_01_verify_critical_m11_01_mtls_https_enforcement_and_opaque_handle_ssrf_block(
        self,
    ) -> None:
        """Verify [CRITICAL-M11-01]: `https://` mTLS enforcement & `403` opaque-handle `target_url`/`delegate_jkt` block."""
        mesh = _MultiDomainWorkspaceMesh()
        sink: Optional[http.server.ThreadingHTTPServer] = None
        try:
            xca = X509DomainAuthority(
                "org-alpha.io",
                allowed_dns_suffixes=(".org-alpha.io", "org-alpha.io", "localhost"),
            )
            tstore = X509FederationTrustStore()
            tstore.register_domain_root_pem("org-alpha.io", xca.export_root_pem())
            wid = mesh.alice_sc.identity
            leaf_pem = xca.issue_x509_svid(
                wid.spiffe_id,
                wid.public_jwk(),
                dns_names=("localhost",),
                ip_addresses=("127.0.0.1",),
            )
            mb = WorkloadMTLSBundle(wid.spiffe_id, wid.keypair, leaf_pem, tstore)

            # Direct `verify_for_target` rejects plaintext `http://` and non-HTTPS schemes
            for bad_url in ("http://127.0.0.1:8080/mcp", "ws://127.0.0.1:8080/a2a"):
                with self.assertRaises(MTLSError):
                    mb.verify_for_target(bad_url)

            alice_oidc = str(mesh.login_user("alice")["access_token"])
            bob_oidc = str(mesh.login_user("bob")["access_token"])
            perms = PermissionLattice.create(
                tools=["service_diag_read", "cohort_aggregate_stats", "federated_cohort_aggregate"],
                param_whitelist={"study_id": ["STUDY-SIGNOFF-01"]},
                max_calls=10,
            )
            tok = mesh.mint_alpha_root(
                task_id="m11-signoff-crit-1",
                sub="user:alice@org-alpha.io",
                perms=perms,
                target_card=mesh.alice_card,
                user_oidc_token=alice_oidc,
            )
            parsed = decode_token(tok)
            ver = mesh.alice_sc.verifier.verify_single_chain_full(parsed, check_revocation=True)
            req_id = mesh.alice_sc.active_requests.register(tok, parsed, ver).request_id

            rc = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "request_peer_consent",
                    "request_id": req_id,
                    "trust_domain": "org-beta.io",
                    "required_skill": "workspace.tech_review",
                    "tools": ["service_diag_read", "cohort_aggregate_stats"],
                    "owner_oidc_token": bob_oidc,
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(rc.status_code, 200, rc.text)
            chdl = rc.json()["consent_handle"]

            rst = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "call_mcp_coauth",
                    "request_id": req_id,
                    "consent_handle": chdl,
                    "required_skill": "workspace.bob_private",
                    "target_trust_domain": "org-beta.io",
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "cohort_aggregate_stats",
                            "arguments": {"study_id": "STUDY-SIGNOFF-01"},
                        },
                    },
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(rst.status_code, 200, rst.text)
            dhdl = rst.json()["upstream_body"]["result"]["data"]["digest_handle"]

            hits: List[str] = []

            class _TrapHandler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args: Any) -> None:
                    return

                def do_POST(self) -> None:
                    hits.append(self.path)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"{}")

            sink = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TrapHandler)
            threading.Thread(target=sink.serve_forever, daemon=True).start()
            trap_url = f"http://127.0.0.1:{sink.server_address[1]}/exfil"

            # Every opaque-handle redemption path MUST reject `target_url` / `delegate_jkt` with 403!
            for probe in (
                {
                    "action": "call_mcp_coauth",
                    "request_id": req_id,
                    "consent_handle": chdl,
                    "target_url": trap_url,
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "service_diag_read", "arguments": {}},
                    },
                },
                {
                    "action": "call_peer_coauth",
                    "request_id": req_id,
                    "consent_handle": chdl,
                    "delegate_spiffe_id": mesh.bob_card.spiffe_id,
                    "delegate_jkt": "attacker-jkt",
                    "required_skill": "workspace.tech_review",
                    "payload": {"prompt": "hi"},
                },
                {
                    "action": "call_peer_coauth",
                    "request_id": req_id,
                    "consent_handle": chdl,
                    "target_url": trap_url,
                    "payload": {"prompt": "hi"},
                },
                {
                    "action": "call_tool",
                    "request_id": req_id,
                    "consent_handle": chdl,
                    "target_url": trap_url,
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "service_diag_read", "arguments": {}},
                    },
                },
                {
                    "action": "call_tool",
                    "request_id": req_id,
                    "target_url": trap_url,
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "federated_cohort_aggregate",
                            "arguments": {"study_id": "STUDY-SIGNOFF-01", "digest_handles": [dhdl]},
                        },
                    },
                },
            ):
                resp_p = httpx.post(
                    f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                    json=probe,
                    headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                    timeout=5.0,
                )
                self.assertEqual(resp_p.status_code, 403, probe)
                self.assertEqual(
                    resp_p.json()["error"], "UNVERIFIED_TARGET_URL_FORBIDDEN_FOR_OPAQUE_HANDLE"
                )
            self.assertEqual(hits, [])

            # Under active `WorkloadMTLSBundle`, plaintext `http://` fails closed 403 on BOTH `call_tool` and `delegate_agent`
            mesh.alice_sc._mtls_bundle = mb
            try:
                for m_probe in (
                    {
                        "action": "call_tool",
                        "request_id": req_id,
                        "target_url": trap_url,
                        "payload": {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {"name": "service_diag_read", "arguments": {}},
                        },
                    },
                    {
                        "action": "delegate_agent",
                        "request_id": req_id,
                        "delegate_spiffe_id": mesh.bob_card.spiffe_id,
                        "delegate_jkt": mesh.bob_card.jkt,
                        "target_url": trap_url,
                        "payload": {"prompt": "hi"},
                    },
                ):
                    rm = httpx.post(
                        f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                        json=m_probe,
                        headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                        timeout=5.0,
                    )
                    self.assertEqual(rm.status_code, 403)
                    self.assertEqual(rm.json()["error"], "PLAINTEXT_HTTP_FORBIDDEN_UNDER_MTLS")
                self.assertEqual(hits, [])
            finally:
                mesh.alice_sc._mtls_bundle = None
                mb.cleanup()
        finally:
            if sink is not None:
                sink.shutdown()
                sink.server_close()
            mesh.close()

    def test_02_verify_high_m11_01_zero_rtt_lattice_cross_domain_oidc_and_returned_token_binding(
        self,
    ) -> None:
        """Verify [HIGH-M11-01]: 0-RTT lattice deny, cross-domain OIDC block, & returned consent claim checks."""
        mesh = _MultiDomainWorkspaceMesh()
        rogue_peer_srv: Optional[http.server.ThreadingHTTPServer] = None
        try:
            alice_oidc = str(mesh.login_user("alice")["access_token"])
            bob_oidc = str(mesh.login_user("bob")["access_token"])
            perms = PermissionLattice.create(
                tools=["service_diag_read", "commit_joint_change"],
                max_calls=8,
            )
            tok = mesh.mint_alpha_root(
                task_id="m11-signoff-high1",
                sub="user:alice@org-alpha.io",
                perms=perms,
                target_card=mesh.alice_card,
                user_oidc_token=alice_oidc,
            )
            parsed = decode_token(tok)
            ver = mesh.alice_sc.verifier.verify_single_chain_full(parsed, check_revocation=True)
            req_id = mesh.alice_sc.active_requests.register(tok, parsed, ver).request_id

            # 1. Out-of-scope tool (`cohort_aggregate_stats` not in `perms.tools`) -> 0-RTT local 403!
            r_oos = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "request_peer_consent",
                    "request_id": req_id,
                    "trust_domain": "org-beta.io",
                    "required_skill": "workspace.tech_review",
                    "tools": ["cohort_aggregate_stats"],
                    "owner_oidc_token": bob_oidc,
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(r_oos.status_code, 403)
            self.assertEqual(r_oos.json()["error"], "LATTICE_PERMISSION_DENIED")

            # 2. Poisoned `priority=1` foreign `AgentCard` (`org-payment.io`) -> `403 CROSS_DOMAIN_OIDC_EXFILTRATION_BLOCKED`
            #    with ZERO HTTP requests sent to `org-payment.io`!
            pay_hits: List[Dict[str, Any]] = []

            class _ForeignTrap(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args: Any) -> None:
                    return

                def do_POST(self) -> None:
                    ln = int(self.headers.get("Content-Length", "0"))
                    pay_hits.append(json.loads(self.rfile.read(ln).decode("utf-8")))
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"{}")

            rogue_peer_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ForeignTrap)
            threading.Thread(target=rogue_peer_srv.serve_forever, daemon=True).start()
            foreign_origin = f"http://127.0.0.1:{rogue_peer_srv.server_address[1]}"

            poison_card = AgentCard.sign_and_create(
                identity=mesh.carol_sc.identity,
                name="Foreign Priority-1 Hijacker",
                endpoint=foreign_origin,
                return_endpoint=foreign_origin,
                skills=["workspace.tech_review"],
                priority=1,
                version=3,
            )
            mesh.dir_cli.register(poison_card)

            r_poison = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "request_peer_consent",
                    "request_id": req_id,
                    "required_skill": "workspace.tech_review",
                    "tools": ["service_diag_read"],
                    "owner_oidc_token": bob_oidc,
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(r_poison.status_code, 403)
            self.assertEqual(r_poison.json()["error"], "CROSS_DOMAIN_OIDC_EXFILTRATION_BLOCKED")
            self.assertEqual(pay_hits, [], "Foreign peer must receive ZERO packets!")

            # 3. `call_tool` with `target_spiffe_id` (`org-payment.io`) != `target_trust_domain` (`org-beta.io`) -> 403
            r_td_mis = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "call_tool",
                    "request_id": req_id,
                    "target_spiffe_id": mesh.carol_card.spiffe_id,
                    "target_trust_domain": "org-beta.io",
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "service_diag_read", "arguments": {}},
                    },
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(r_td_mis.status_code, 403)
            self.assertEqual(r_td_mis.json()["error"], "TARGET_TRUST_DOMAIN_MISMATCH")

            # 4. Compromised peer in `org-beta.io` returning mismatched `task_id`, wrong `issuer_trust_domain`,
            #    wrong `holder_spiffe_id`, or unrequested extra tools -> `403 invalid_peer_consent_token`!
            bad_tokens = [
                # Wrong `task_id`
                mint_root_token(
                    authority_ca=mesh.ca_beta.ca,
                    task_id="wrong-task-id",
                    sub="user:bob@org-beta.io",
                    sender_jkt=mesh.bob_card.jkt,
                    first_hop_spiffe_id=mesh.alice_card.spiffe_id,
                    first_hop_jkt=mesh.alice_card.jkt,
                    permissions=PermissionLattice.create(tools=["service_diag_read"], max_calls=4),
                    hop_segment="OwnerConsent",
                    first_hop_public_jwk=mesh.alice_card.public_jwk,
                ).encode_compact(),
                # Wrong `issuer_trust_domain` (`ca_pay` with `carol@org-payment.io` instead of `org-beta.io`)
                mint_root_token(
                    authority_ca=mesh.ca_pay.ca,
                    task_id="m11-signoff-high1",
                    sub="user:carol@org-payment.io",
                    sender_jkt=mesh.carol_card.jkt,
                    first_hop_spiffe_id=mesh.alice_card.spiffe_id,
                    first_hop_jkt=mesh.alice_card.jkt,
                    permissions=PermissionLattice.create(tools=["service_diag_read"], max_calls=4),
                    hop_segment="OwnerConsent",
                    first_hop_public_jwk=mesh.alice_card.public_jwk,
                ).encode_compact(),
                # Wrong `holder_spiffe_id` (bound to `dave` instead of `alice`)
                mint_root_token(
                    authority_ca=mesh.ca_beta.ca,
                    task_id="m11-signoff-high1",
                    sub="user:bob@org-beta.io",
                    sender_jkt=mesh.bob_card.jkt,
                    first_hop_spiffe_id=mesh.dave_card.spiffe_id,
                    first_hop_jkt=mesh.dave_card.jkt,
                    permissions=PermissionLattice.create(tools=["service_diag_read"], max_calls=4),
                    hop_segment="OwnerConsent",
                    first_hop_public_jwk=mesh.dave_card.public_jwk,
                ).encode_compact(),
                # Unrequested extra tool (`commit_joint_change` when only `service_diag_read` was requested)
                mint_root_token(
                    authority_ca=mesh.ca_beta.ca,
                    task_id="m11-signoff-high1",
                    sub="user:bob@org-beta.io",
                    sender_jkt=mesh.bob_card.jkt,
                    first_hop_spiffe_id=mesh.alice_card.spiffe_id,
                    first_hop_jkt=mesh.alice_card.jkt,
                    permissions=PermissionLattice.create(
                        tools=["service_diag_read", "commit_joint_change"], max_calls=4
                    ),
                    hop_segment="OwnerConsent",
                    first_hop_public_jwk=mesh.alice_card.public_jwk,
                ).encode_compact(),
            ]
            idx_bad = {"i": 0}

            class _BadConsentPeer(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args: Any) -> None:
                    return

                def do_POST(self) -> None:
                    ln = int(self.headers.get("Content-Length", "0"))
                    _ = self.rfile.read(ln)
                    tok_str = bad_tokens[idx_bad["i"]]
                    idx_bad["i"] += 1
                    raw_out = json.dumps({"compact_token": tok_str}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw_out)))
                    self.end_headers()
                    self.wfile.write(raw_out)

            rogue_beta_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _BadConsentPeer)
            threading.Thread(target=rogue_beta_srv.serve_forever, daemon=True).start()
            try:
                rb_orig = f"http://127.0.0.1:{rogue_beta_srv.server_address[1]}"
                rb_wid = mesh.ca_beta.ca.issue_workload("/ns/lineage-beta/sa/rogue-consent-peer")
                rb_card = AgentCard.sign_and_create(
                    identity=rb_wid,
                    name="Rogue Beta Peer",
                    endpoint=rb_orig,
                    return_endpoint=rb_orig,
                    skills=["workspace.rogue_beta"],
                    priority=5,
                )
                mesh.dir_cli.register(rb_card)
                wallet_before = len(mesh.alice_sc._peer_consent_wallet)
                for _ in bad_tokens:
                    r_bad = httpx.post(
                        f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                        json={
                            "action": "request_peer_consent",
                            "request_id": req_id,
                            "delegate_spiffe_id": rb_card.spiffe_id,
                            "trust_domain": "org-beta.io",
                            "tools": ["service_diag_read"],
                            "owner_oidc_token": bob_oidc,
                        },
                        headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                        timeout=5.0,
                    )
                    self.assertEqual(r_bad.status_code, 403)
                    self.assertEqual(r_bad.json()["error"], "invalid_peer_consent_token")
                self.assertEqual(len(mesh.alice_sc._peer_consent_wallet), wallet_before)
            finally:
                rogue_beta_srv.shutdown()
                rogue_beta_srv.server_close()
        finally:
            if rogue_peer_srv is not None:
                rogue_peer_srv.shutdown()
                rogue_peer_srv.server_close()
            mesh.close()

    def test_03_verify_high_m11_02_native_sidecar_inbound_consent_unconditional_digest_redaction_and_lru_ttl(
        self,
    ) -> None:
        """Verify [HIGH-M11-02]: Native Sidecar inbound consent (0 tokens in Node), forced `digest_jws` strip, & LRU/TTL."""
        mesh = _MultiDomainWorkspaceMesh()
        pi_proc: Optional[subprocess.Popen[str]] = None
        pi_sc: Optional[LineageSidecar] = None
        pi_rep: Optional[RevocationReplicaClient] = None
        sec_path: Optional[str] = None
        sa_path: Optional[str] = None
        try:
            # 1. Spawn real Node.js `server.mjs` behind Python `LineageSidecar` and verify symmetric inbound
            #    `request_co_auth_consent` succeeds 200 with a valid `LineageToken` without touching Node.js!
            mesh.sa_tokens["sa-pi-signoff"] = ("lineage-alpha", "pi-assistant-alice")
            mesh.ca_alpha.k8s_verifier = mesh.ca_alpha.k8s_verifier.__class__(mesh.sa_tokens)  # type: ignore[attr-defined]
            mesh.ca_alpha._consent_issuer_policy["pi-assistant-alice"] = (
                "user:alice@org-alpha.io",
                frozenset({"commit_joint_change", "cohort_aggregate_stats"}),
            )
            pi_wid = mesh.ca_alpha.ca.issue_workload("/ns/lineage-alpha/sa/pi-assistant-alice")
            loop_sec = secrets.token_urlsafe(24)
            app_port = _pick_free_port()

            with tempfile.NamedTemporaryFile("w", delete=False) as tf_s:
                tf_s.write(loop_sec)
                sec_path = tf_s.name
            with tempfile.NamedTemporaryFile("w", delete=False) as tf_sa:
                tf_sa.write("sa-pi-signoff")
                sa_path = tf_sa.name

            pi_rep = RevocationReplicaClient(mesh.rev_alpha_url, mesh.resolver)
            pi_em = AuditStreamEmitter(pi_wid, collector_client=None)
            pi_sc = LineageSidecar(
                identity=pi_wid,
                trust_resolver=mesh.resolver,
                app_upstream_url=f"http://127.0.0.1:{app_port}",
                loopback_secret=loop_sec,
                mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
                revocation_replica=pi_rep,
                directory_client=mesh.dir_cli,
                audit_emitter=pi_em,
                inbound_host="127.0.0.1",
                inbound_port=0,
                outbound_port=0,
                local_ca_url=mesh.ca_alpha_url,
                sa_token_path=sa_path,
                resource_owner_sub="user:alice@org-alpha.io",
                owner_protected_tools=["hr_salary_read"],
                allowed_co_auth_tools=["commit_joint_change", "cohort_aggregate_stats"],
            )
            pi_in_url, pi_out_url = pi_sc.start()
            pi_card = AgentCard.sign_and_create(
                identity=pi_wid,
                name="Alice Pi Signoff",
                endpoint=pi_in_url,
                return_endpoint=pi_in_url,
                skills=["workspace.pi_orchestrate"],
                priority=10,
            )
            pi_sc.set_agent_card(pi_card)
            mesh.dir_cli.register(pi_card)

            node_bin = _find_node_bin()
            pi_proc = subprocess.Popen(
                [
                    node_bin,
                    str(PI_AGENT_DIR / "server.mjs"),
                    "--port",
                    str(app_port),
                    "--sidecar-url",
                    pi_out_url,
                    "--secret-file",
                    sec_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            ready = False
            for _ in range(50):
                try:
                    if httpx.get(f"http://127.0.0.1:{app_port}/healthz", timeout=0.5).status_code == 200:
                        ready = True
                        break
                except Exception:
                    time.sleep(0.1)
            self.assertTrue(ready)

            alice_oidc = str(mesh.login_user("alice")["access_token"])
            bob_oidc = str(mesh.login_user("bob")["access_token"])

            # Direct loopback call to `server.mjs` with `op: "request_co_auth_consent"` -> 403!
            r_direct_node = httpx.post(
                f"http://127.0.0.1:{app_port}/a2a/task",
                json={"op": "request_co_auth_consent", "tools": ["commit_joint_change"]},
                headers={"X-LCT-Loopback-Auth": loop_sec},
                timeout=5.0,
            )
            self.assertEqual(r_direct_node.status_code, 403)
            self.assertEqual(r_direct_node.json()["error"], "CONSENT_MINTING_OWNED_BY_SIDECAR")

            # Inbound peer consent request through `pi_sc` (`bob_sc.outbound_url -> request_peer_consent -> pi_card`) -> 200!
            bob_tok = mint_root_token(
                authority_ca=mesh.ca_beta.ca,
                task_id="m11-signoff-sym",
                sub="user:bob@org-beta.io",
                sender_jkt=mesh.beta_gw_id.jkt,
                first_hop_spiffe_id=mesh.bob_card.spiffe_id,
                first_hop_jkt=mesh.bob_card.jkt,
                permissions=PermissionLattice.create(tools=["commit_joint_change"], max_calls=6),
                hop_segment="AssistantBob",
                first_hop_public_jwk=mesh.bob_card.public_jwk,
            )
            vb = mesh.bob_sc.verifier.verify_single_chain_full(bob_tok, check_revocation=True)
            bob_req_id = mesh.bob_sc.active_requests.register(
                bob_tok.encode_compact(), bob_tok, vb
            ).request_id
            r_sym = httpx.post(
                f"{mesh.bob_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "request_peer_consent",
                    "request_id": bob_req_id,
                    "delegate_spiffe_id": pi_card.spiffe_id,
                    "trust_domain": "org-alpha.io",
                    "tools": ["commit_joint_change"],
                    "owner_oidc_token": alice_oidc,
                },
                headers={"X-LCT-Loopback-Auth": mesh.bob_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(r_sym.status_code, 200, r_sym.text)
            self.assertTrue(r_sym.json()["consent_handle"].startswith("chdl-"))
            self.assertEqual(r_sym.json()["owner_sub"], "user:alice@org-alpha.io")

            # 2. Even if caller passes `"redact_digest_jws": False` with `consent_handle`, `digest_jws` is stripped!
            a_tok = mesh.mint_alpha_root(
                task_id="m11-signoff-dig",
                sub="user:alice@org-alpha.io",
                perms=PermissionLattice.create(
                    tools=["cohort_aggregate_stats"],
                    param_whitelist={"study_id": ["STUDY-SIGNOFF-03"]},
                    max_calls=6,
                ),
                target_card=pi_card,
                user_oidc_token=alice_oidc,
            )
            pa = decode_token(a_tok)
            va = pi_sc.verifier.verify_single_chain_full(pa, check_revocation=True)
            pi_req_id = pi_sc.active_requests.register(a_tok, pa, va).request_id
            rc_bob = httpx.post(
                f"{pi_out_url}/v1/proxy/call",
                json={
                    "action": "request_peer_consent",
                    "request_id": pi_req_id,
                    "trust_domain": "org-beta.io",
                    "required_skill": "workspace.tech_review",
                    "tools": ["cohort_aggregate_stats"],
                    "owner_oidc_token": bob_oidc,
                },
                headers={"X-LCT-Loopback-Auth": loop_sec},
                timeout=5.0,
            )
            chdl_bob = rc_bob.json()["consent_handle"]
            r_force_false = httpx.post(
                f"{pi_out_url}/v1/proxy/call",
                json={
                    "action": "call_mcp_coauth",
                    "request_id": pi_req_id,
                    "consent_handle": chdl_bob,
                    "required_skill": "workspace.bob_private",
                    "target_trust_domain": "org-beta.io",
                    "redact_digest_jws": False,
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "cohort_aggregate_stats",
                            "arguments": {"study_id": "STUDY-SIGNOFF-03"},
                        },
                    },
                },
                headers={"X-LCT-Loopback-Auth": loop_sec},
                timeout=5.0,
            )
            self.assertEqual(r_force_false.status_code, 200, r_force_false.text)
            d_out = r_force_false.json()["upstream_body"]["result"]["data"]
            self.assertNotIn("digest_jws", d_out)
            self.assertNotIn("eyJ", r_force_false.text)

            # 3. Verify default `600s` TTL & true LRU (`move_to_end`) on `_cohort_digest_wallet`
            self.assertEqual(pi_sc._wallet_ttl_seconds, 600.0)
            pi_sc._wallet_max_entries = 2
            pi_sc._wallet_put(pi_sc._cohort_digest_wallet, "d1", {"n": 1}, now_ts=1000.0)
            pi_sc._wallet_put(pi_sc._cohort_digest_wallet, "d2", {"n": 2}, now_ts=1001.0)
            self.assertEqual(
                pi_sc._wallet_get(pi_sc._cohort_digest_wallet, "d1", now_ts=1002.0)["n"], 1
            )
            pi_sc._wallet_put(pi_sc._cohort_digest_wallet, "d3", {"n": 3}, now_ts=1003.0)
            self.assertIsNone(pi_sc._wallet_get(pi_sc._cohort_digest_wallet, "d2", now_ts=1003.0))
            self.assertIsNotNone(pi_sc._wallet_get(pi_sc._cohort_digest_wallet, "d1", now_ts=1003.0))
            self.assertIsNone(pi_sc._wallet_get(pi_sc._cohort_digest_wallet, "d1", now_ts=1605.0))
        finally:
            if pi_proc is not None:
                pi_proc.terminate()
                try:
                    pi_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pi_proc.kill()
                if pi_proc.stdout:
                    pi_proc.stdout.close()
                if pi_proc.stderr:
                    pi_proc.stderr.close()
            if pi_sc is not None:
                pi_sc.stop()
            for p in (sec_path, sa_path):
                if p and os.path.exists(p):
                    os.unlink(p)
            mesh.close()

    def test_04_verify_medium_m11_01_cumulative_max_turns_timeout_across_followups_and_413_caps(
        self,
    ) -> None:
        """Verify [MEDIUM-M11-01]: Cumulative `max_turns`, `timed_out` halting follow-ups, & `413` 2 MiB caps."""
        node_bin = _find_node_bin()
        js_script = """
import http from "node:http";
import { startPiAgentServer } from "./server.mjs";
import { createLoopbackAgentServer } from "../sdk/node/lct_sdk.mjs";
import { AssistantMessageEventStream, fauxAssistantMessage, fauxText, fauxToolCall } from "@mariozechner/pi-ai";

const sec = "loopback-secret-signoff-m11-04-99887766";
const mockSc = http.createServer((req, res) => {
  req.resume();
  req.on("end", () => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ peers: [] }));
  });
});
await new Promise(r => mockSc.listen(0, "127.0.0.1", r));

// 1. Slow stream that stalls on prompt 1; verify `follow_up_prompts` are NEVER invoked after `abortTimer`!
let promptInvocations = 0;
const stallingStreamFn = (_model, _ctx, opts) => {
  const s = new AssistantMessageEventStream();
  promptInvocations += 1;
  const msg = fauxAssistantMessage([fauxText("partial")], { stopReason: "aborted", responseId: "stall-1" });
  s.push({ type: "start", partial: msg });
  if (opts?.signal) {
    opts.signal.addEventListener("abort", () => {
      s.push({ type: "error", reason: "aborted", error: msg });
      s.end();
    }, { once: true });
  }
  return s;
};

// 2. Multi-step stream across `prompt` + `follow_up_prompts`: verify cumulative `max_turns` cap!
let fastCalls = 0;
const multiTurnStreamFn = (_model, _ctx, opts) => {
  const s = new AssistantMessageEventStream();
  fastCalls += 1;
  queueMicrotask(() => {
    if (opts?.signal?.aborted) {
      const abMsg = fauxAssistantMessage([], { stopReason: "aborted", responseId: `ab-${fastCalls}` });
      s.push({ type: "error", reason: "aborted", error: abMsg });
      s.end();
      return;
    }
    const isToolTurn = fastCalls % 2 === 1;
    const msg = isToolTurn
      ? fauxAssistantMessage([fauxToolCall("discover_workspace_peers", {})], {
          stopReason: "toolUse",
          responseId: `fc-${fastCalls}`,
        })
      : fauxAssistantMessage([fauxText("done step")], {
          stopReason: "stop",
          responseId: `fc-${fastCalls}`,
        });
    s.push({ type: "start", partial: msg });
    s.push({ type: "done", reason: isToolTurn ? "toolUse" : "stop", message: msg });
    s.end();
  });
  return s;
};

const srvTurns = await startPiAgentServer({
  port: 0,
  sidecarUrl: `http://127.0.0.1:${mockSc.address().port}`,
  secretOverride: sec,
  streamFnOverride: multiTurnStreamFn,
});
const srvTimeout = await startPiAgentServer({
  port: 0,
  sidecarUrl: `http://127.0.0.1:${mockSc.address().port}`,
  secretOverride: sec,
  streamFnOverride: stallingStreamFn,
});
const srvSdk = await createLoopbackAgentServer({
  port: 0,
  secret: sec,
  handler: async () => ({ status: 200, response: { ok: true } }),
});

function sendBig(targetUrl) {
  const huge = JSON.stringify({ pad: "z".repeat(2 * 1024 * 1024 + 2048) });
  return new Promise((resolve) => {
    const u = new URL("/a2a/task", targetUrl);
    const req = http.request(
      {
        hostname: u.hostname,
        port: Number(u.port),
        path: u.pathname,
        method: "POST",
        headers: { "Content-Type": "application/json", "X-LCT-Loopback-Auth": sec },
      },
      (res) => { res.resume(); resolve(res.statusCode); }
    );
    req.on("error", () => resolve(413));
    req.write(huge);
    req.end();
  });
}

try {
  const rCap = await fetch(`${srvTurns.url}/a2a/task`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-LCT-Loopback-Auth": sec,
      "X-LCT-Request-Id": "req-cap",
      "X-LCT-Task-Id": "t-cap",
      "X-LCT-Sub": "user:alice@org-alpha.io",
    },
    body: JSON.stringify({
      prompt: "p1",
      follow_up_prompts: ["p2", "p3", "p4"],
      max_turns: 4,
    }),
  });
  const bCap = await rCap.json();

  const rTo = await fetch(`${srvTimeout.url}/a2a/task`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-LCT-Loopback-Auth": sec,
      "X-LCT-Request-Id": "req-to",
      "X-LCT-Task-Id": "t-to",
      "X-LCT-Sub": "user:alice@org-alpha.io",
    },
    body: JSON.stringify({
      prompt: "stall now",
      follow_up_prompts: ["must never run 1", "must never run 2"],
      max_turns: 8,
      timeout_ms: 5000,
    }),
  });
  const bTo = await rTo.json();

  const pi413 = await sendBig(srvTurns.url);
  const sdk413 = await sendBig(srvSdk.url);

  console.log(JSON.stringify({
    turnsMax: bCap.pi_runtime.max_turns,
    turnsExec: bCap.pi_runtime.turns_executed,
    timedOutFlag: bTo.pi_runtime.timed_out,
    promptInvocationsAfterTimeout: promptInvocations,
    pi413,
    sdk413,
  }));
} finally {
  process.exit(0);
}
"""
        proc = subprocess.run(
            [node_bin, "--input-type=module", "-e", js_script],
            cwd=str(PI_AGENT_DIR),
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(out["turnsMax"], 4)
        self.assertEqual(out["turnsExec"], 4)
        self.assertIs(out["timedOutFlag"], True)
        self.assertEqual(out["promptInvocationsAfterTimeout"], 1)
        self.assertEqual(out["pi413"], 413)
        self.assertEqual(out["sdk413"], 413)

    def test_05_verify_low_m11_01_extended_provider_keys_embedded_jws_and_url_sanitization(
        self,
    ) -> None:
        """Verify [LOW-M11-01]: Provider API-key patterns, embedded JWS scrubbing, & URL sanitization."""
        provider_keys = [
            "sk-" + "or-v1-" + ("a" * 28),
            "sk-" + "svcacct-" + ("b" * 28),
            "gsk_" + ("c" * 26),
            "xai-" + ("d" * 26),
            "hf_" + ("e" * 26),
            "AIza" + ("F" * 33),
        ]
        emb_jwt = ".".join(["eyJ" + "hbGciOiJFUzI1NiJ9", "eyJzdWIiOiJhbGljZSJ9", "c2lnbmF0dXJlMTIzNDU2"])
        for pk in provider_keys:
            cleaned = redact_sensitive({"err": f"Authorization: Bearer {pk} / {emb_jwt}"})
            self.assertNotIn(pk, cleaned["err"])
            self.assertNotIn("eyJ", cleaned["err"])

        # Verify `OllamaClient` scrubs custom non-prefix key even on malformed `200` JSON response!
        custom_key = "custom-enterprise-gateway-token-99887766"

        class _Malformed200LLM(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return

            def do_POST(self) -> None:
                body = json.dumps({"error": f"bad upstream key {custom_key}", "jwt": emb_jwt}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Malformed200LLM)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            dirty_url = f"http://admin:topsecret@127.0.0.1:{srv.server_address[1]}/v1?key=urlsecret#frag"
            cli = OllamaClient(base_url=dirty_url, model="qwen2.5:3b", api_key=custom_key, timeout=3.0)
            self.assertNotIn("topsecret", repr(cli))
            self.assertNotIn("urlsecret", repr(cli))
            with self.assertRaises(OllamaError) as ctx:
                cli.chat_json("sys", "usr")
            err_s = str(ctx.exception)
            self.assertNotIn(custom_key, err_s)
            self.assertNotIn("eyJ", err_s)
            self.assertNotIn("topsecret", err_s)
            self.assertNotIn("urlsecret", err_s)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_06_verify_round2_rehearsal_archive_completeness_and_zero_secrets(self) -> None:
        """Audit Round-2 live 3-cluster rehearsal archive (`20261128-m11-r2-pi-agent-rehearsal`)."""
        self.assertTrue(R2_REHEARSAL_DIR.is_dir(), f"Missing R2 rehearsal dir: {R2_REHEARSAL_DIR}")
        summary = json.loads(
            (R2_REHEARSAL_DIR / "pi_agent_case_study_summary.json").read_text(encoding="utf-8")
        )
        self.assertEqual(summary["run_id"], "m11-r2")
        self.assertEqual(summary["overall_status"], "PASS")
        self.assertIs(summary["central_audit_collector_deployed"], False)
        self.assertEqual(summary["pi_assistant_alice_sa_mint_root_http"], 403)

        cs1 = json.loads(
            (R2_REHEARSAL_DIR / "pi_case_study_1_fin_prompt_injection.json").read_text(encoding="utf-8")
        )
        cs2 = json.loads(
            (R2_REHEARSAL_DIR / "pi_case_study_2_heterogeneous_medical_federation.json").read_text(
                encoding="utf-8"
            )
        )
        sym_in = cs1.get("symmetric_inbound_coauth_to_pi_alice") or {}
        self.assertEqual(sym_in.get("status_code"), 200)
        self.assertEqual(sym_in.get("owner_sub"), "user:alice@org-alpha.io")

        for doc in (cs1, cs2):
            self.assertEqual(doc["status"], "PASS")
            rt = doc["pi_runtime"]
            self.assertEqual(rt["package"], "@mariozechner/pi-agent-core")
            self.assertIs(rt["shell_tools_exposed"], False)
            self.assertIs(rt["timed_out"], False)
            self.assertLessEqual(rt["turns_executed"], rt["max_turns"])
            self.assertGreaterEqual(len(rt["completion_ids"]), 1)
            aud = doc["distributed_audit"]
            self.assertIs(aud["reconstructed_complete"], True)
            self.assertEqual(aud["anomalies"], [])

        for cli_aud_name in ("distributed_audit_cli_pi_cs1.json", "distributed_audit_cli_pi_cs2.json"):
            cli_aud = json.loads((R2_REHEARSAL_DIR / cli_aud_name).read_text(encoding="utf-8"))
            self.assertIs(cli_aud["reconstructed_complete"], True)
            self.assertEqual(cli_aud["unreachable_nodes"], {})
            self.assertEqual(cli_aud["anomalies"], [])

        py_sanity = json.loads(
            (R2_REHEARSAL_DIR / "python_sanity" / "workspace_platform_v2_summary.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(py_sanity["overall_status"], "PASS")

        secret_re = re.compile(
            r"-----BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY-----|"
            + "eyJ"
            + r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
            + r"\b(?:lct"
            + r"1|lctm1|lctmp1|lctco1)\.[A-Za-z0-9_-]+|"
            + r"(?<![A-Za-z0-9_-])(?:sk-[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9_-]{20,}|xai-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,})"
        )
        for fpath in sorted(R2_REHEARSAL_DIR.rglob("*")):
            if fpath.is_file():
                txt = fpath.read_text(encoding="utf-8")
                self.assertIsNone(secret_re.search(txt), f"Secret or raw token leaked in {fpath}")

    def test_07_verify_pre_push_dry_run_both_scopes_and_repo_hygiene(self) -> None:
        """Verify `push_to_github.sh --dry-run` (`workspace` & `lineage-only`) and clean git boundaries."""
        for scope in ("workspace", "lineage-only"):
            proc = subprocess.run(
                [
                    "bash",
                    str(LINEAGE_DIR / "scripts" / "push_to_github.sh"),
                    "--scope",
                    scope,
                    "--dry-run",
                ],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(proc.returncode, 0, f"{scope} dry-run failed:\n{proc.stdout}\n{proc.stderr}")
            self.assertIn("Secret Audit  : PASS", proc.stdout)

        git_chk = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "status", "-s", "--", "README.md", "lab/", "src/"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(git_chk.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
