"""Milestone 11 Test Suite: Real-World Open-Source `Pi` Agent (`@mariozechner/pi-agent-core`) Integration.

Verifies:
1. K8s manifest & deployment invariants (`--with-pi-agent` opt-in, `pi-assistant-alice` 2-container Pod
   isolation, `0` gateway SA privilege, `LLM_MODEL=qwen2.5:3b` default for `Pi` with full cloud API
   configurability) + Node.js `test_pi_agent.mjs` suite execution;
2. Universal OpenAI-compatible `OllamaClient` (`LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` /
   `LLM_API_KEY_FILE`) + zero API-key leakage in `repr`, `meta`, errors, and `redact_sensitive`;
3. `LineageSidecar` polyglot loopback actions (`discover`, `request_peer_consent`, `call_mcp_coauth`,
   `call_peer_coauth`, opaque `consent_handle` & `digest_handle` wallets) with strict `(sub, task_id)`
   isolation (`403 CROSS_TENANT_OR_TASK_CONSENT_DENIED` / `403 CROSS_TENANT_OR_TASK_DIGEST_DENIED`)
   and zero raw LCT/JWS token exposure to polyglot apps;
4. Live multi-process heterogeneous orchestration: a real `node lineage/pi_agent/server.mjs` subprocess
   running `@mariozechner/pi-agent-core` + `@mariozechner/pi-ai` behind Python `LineageSidecar`
   executing Case Study 1 (Financial Risk Triage + Indirect Prompt Injection `403` defense) and
   Case Study 2 (Cross-Language Healthcare Federated Cohort Aggregation) with `100%` `DistributedAuditor`
   DAG reconstruction.
"""

from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import unittest

import httpx
import yaml

from lineage.agents.ollama_client import OllamaClient, OllamaError
from lineage.audit import AuditStreamEmitter
from lineage.common.crypto import redact_sensitive
from lineage.common.mtls import (
    MTLSError,
    WorkloadMTLSBundle,
    X509DomainAuthority,
    X509FederationTrustStore,
)
from lineage.multihost.config_gen import allocate_role_ports, render_role_k8s_manifests
from lineage.protocol import LineageToken, PermissionLattice, decode_token, mint_root_token
from lineage.registry import AgentCard
from lineage.revocation import RevocationReplicaClient
from lineage.sidecar import LineageSidecar
from lineage.tests.test_m10_expanded_scenarios import _MultiDomainWorkspaceMesh
from lineage.verifier import VerificationMode


def _find_node_binary() -> str:
    extra_paths = [
        str(Path.home() / ".local" / "bin"),
        "/opt/homebrew/bin",
        "/usr/local/bin",
        os.environ.get("PATH", ""),
    ]
    merged_path = ":".join(p for p in extra_paths if p)
    node_bin = shutil.which("node", path=merged_path)
    if not node_bin:
        raise RuntimeError("Node.js binary not found in PATH")
    return node_bin


def _pick_ephemeral_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _ScriptedOpenAISSEHandler(http.server.BaseHTTPRequestHandler):
    """Minimal OpenAI-compatible `/v1/chat/completions` SSE server driving real `@mariozechner/pi-ai`."""

    planner_fn: Callable[[List[Dict[str, Any]], Dict[str, str]], Dict[str, Any]]
    captured_headers: List[Dict[str, str]]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        req_json = json.loads(raw) if raw else {}
        hdr_map = {k.lower(): v for k, v in self.headers.items()}
        self.__class__.captured_headers.append(hdr_map)

        plan = self.__class__.planner_fn(req_json.get("messages") or [], hdr_map)
        if plan.get("force_http_500"):
            err_txt = str(plan["force_http_500"]).encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(err_txt)))
            self.end_headers()
            self.wfile.write(err_txt)
            return

        comp_id = str(plan.get("id") or f"chatcmpl-m11-{secrets.token_hex(4)}")
        model_id = str(req_json.get("model") or "qwen2.5:3b")

        if not req_json.get("stream"):
            msg_obj: Dict[str, Any] = {"role": "assistant"}
            if plan.get("tool_calls"):
                msg_obj["content"] = None
                msg_obj["tool_calls"] = [
                    {
                        "id": f"call_{idx}_{secrets.token_hex(3)}",
                        "type": "function",
                        "function": {
                            "name": tc["name"],
                            "arguments": json.dumps(tc["arguments"]),
                        },
                    }
                    for idx, tc in enumerate(plan["tool_calls"])
                ]
                finish_reason = "tool_calls"
            else:
                msg_obj["content"] = str(plan.get("text") or "Completed.")
                finish_reason = "stop"
            resp_doc = {
                "id": comp_id,
                "object": "chat.completion",
                "model": model_id,
                "choices": [{"index": 0, "message": msg_obj, "finish_reason": finish_reason}],
                "usage": {"prompt_tokens": 64, "completion_tokens": 24, "total_tokens": 88},
            }
            out_bytes = json.dumps(resp_doc).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out_bytes)))
            self.end_headers()
            self.wfile.write(out_bytes)
            return

        # OpenAI SSE streaming protocol consumed by `@mariozechner/pi-ai` (`streamOpenAICompletions`)
        chunks: List[Dict[str, Any]] = []
        if plan.get("tool_calls"):
            for idx, tc in enumerate(plan["tool_calls"]):
                chunks.append(
                    {
                        "id": comp_id,
                        "object": "chat.completion.chunk",
                        "model": model_id,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {
                                    "role": "assistant" if idx == 0 else None,
                                    "tool_calls": [
                                        {
                                            "index": idx,
                                            "id": f"call_{idx}_{secrets.token_hex(3)}",
                                            "type": "function",
                                            "function": {
                                                "name": tc["name"],
                                                "arguments": json.dumps(tc["arguments"]),
                                            },
                                        }
                                    ],
                                },
                                "finish_reason": None,
                            }
                        ],
                    }
                )
            chunks.append(
                {
                    "id": comp_id,
                    "object": "chat.completion.chunk",
                    "model": model_id,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
                    "usage": {"prompt_tokens": 70, "completion_tokens": 30, "total_tokens": 100},
                }
            )
        else:
            chunks.append(
                {
                    "id": comp_id,
                    "object": "chat.completion.chunk",
                    "model": model_id,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant", "content": str(plan.get("text") or "Done.")},
                            "finish_reason": None,
                        }
                    ],
                }
            )
            chunks.append(
                {
                    "id": comp_id,
                    "object": "chat.completion.chunk",
                    "model": model_id,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 80, "completion_tokens": 25, "total_tokens": 105},
                }
            )

        sse_lines = [f"data: {json.dumps(c)}\n\n" for c in chunks] + ["data: [DONE]\n\n"]
        sse_bytes = "".join(sse_lines).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(sse_bytes)))
        self.end_headers()
        self.wfile.write(sse_bytes)


def _start_scripted_openai_server(
    planner_fn: Callable[[List[Dict[str, Any]], Dict[str, str]], Dict[str, Any]]
) -> Tuple[http.server.ThreadingHTTPServer, str, List[Dict[str, str]]]:
    captured: List[Dict[str, str]] = []
    handler_cls = type(
        "_BoundSSEHandler",
        (_ScriptedOpenAISSEHandler,),
        {"planner_fn": staticmethod(planner_fn), "captured_headers": captured},
    )
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    port = srv.server_address[1]
    return srv, f"http://127.0.0.1:{port}/v1", captured


class TestMilestone11PiAgentIntegration(unittest.TestCase):
    """Comprehensive Milestone 11 unit & multi-process integration suite."""

    def test_01_manifest_invariants_and_pi_agent_node_unit_suite(self) -> None:
        # 1. Default workspace manifest (`with_pi_agent=False`) stays 100% untouched
        ports_default = allocate_role_ports("alpha", topology="workspace", with_pi_agent=False)
        self.assertNotIn("pi-assistant-alice", ports_default)
        man_default = list(
            yaml.safe_load_all(
                render_role_k8s_manifests(
                    role="alpha",
                    topology="workspace",
                    role_ports=ports_default,
                    with_pi_agent=False,
                )
            )
        )
        dep_names_default = {
            d["metadata"]["name"] for d in man_default if d and d.get("kind") == "Deployment"
        }
        self.assertIn("assistant-alice", dep_names_default)
        self.assertNotIn("pi-assistant-alice", dep_names_default)

        # 2. Opt-in `with_pi_agent=True` deploys 2-container `pi-assistant-alice` with strict least privilege
        ports_pi = allocate_role_ports("alpha", topology="workspace", with_pi_agent=True)
        self.assertIn("pi-assistant-alice", ports_pi)
        man_pi = list(
            yaml.safe_load_all(
                render_role_k8s_manifests(
                    role="alpha",
                    image="lineage-lct:m8",
                    topology="workspace",
                    role_ports=ports_pi,
                    with_pi_agent=True,
                    pi_agent_image="lineage-pi-agent:m11",
                )
            )
        )
        deps_by_name = {
            d["metadata"]["name"]: d for d in man_pi if d and d.get("kind") == "Deployment"
        }
        self.assertIn("pi-assistant-alice", deps_by_name)

        ca_dep = deps_by_name["alpha-ca"]
        ca_env = {
            e["name"]: e["value"]
            for e in ca_dep["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        self.assertEqual(ca_env["AUTHORIZED_GATEWAY_SA"], "e2e-user-gateway")
        self.assertNotIn("pi-assistant-alice", ca_env["AUTHORIZED_GATEWAY_SA"])
        self.assertIn("pi-assistant-alice=user:alice@org-alpha.io:", ca_env["CONSENT_ISSUER_POLICY"])

        pi_spec = deps_by_name["pi-assistant-alice"]["spec"]["template"]["spec"]
        self.assertEqual(pi_spec["serviceAccountName"], "pi-assistant-alice")
        self.assertIs(pi_spec["automountServiceAccountToken"], False)
        containers = {c["name"]: c for c in pi_spec["containers"]}
        self.assertEqual(set(containers.keys()), {"app", "lct-sidecar"})
        self.assertEqual(containers["app"]["image"], "lineage-pi-agent:m11")
        self.assertEqual(containers["lct-sidecar"]["image"], "lineage-lct:m8")

        app_mounts = {m["name"] for m in containers["app"]["volumeMounts"]}
        self.assertIn("lct-loopback", app_mounts)
        self.assertIn("lct-llm-api-key", app_mounts)
        self.assertNotIn("lct-sa-token", app_mounts)
        self.assertNotIn("lct-mtls-ram", app_mounts)

        app_env = {e["name"]: e["value"] for e in containers["app"]["env"]}
        self.assertEqual(app_env["LLM_MODEL"], "qwen2.5:3b")

        alice_py_env = {
            e["name"]: e["value"]
            for e in deps_by_name["assistant-alice"]["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        self.assertEqual(alice_py_env["LLM_MODEL"], "qwen2.5:3b")

        # 3. Execute Node.js `test_pi_agent.mjs` suite
        node_bin = _find_node_binary()
        pi_dir = Path(__file__).resolve().parents[1] / "pi_agent"
        res = subprocess.run(
            [node_bin, "--test", "test_pi_agent.mjs"],
            cwd=str(pi_dir),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(res.returncode, 0, f"Node test failed:\n{res.stdout}\n{res.stderr}")

    def test_02_ollama_client_universal_openai_compat_and_api_key_redaction(self) -> None:
        fake_cloud_key = "sk-proj-" + "cloudsecretkeyvalue9988776655443322"

        def _planner(msgs: List[Dict[str, Any]], hdrs: Dict[str, str]) -> Dict[str, Any]:
            if any("TRIGGER_500" in str(m.get("content", "")) for m in msgs):
                return {"force_http_500": f"Provider auth error for key {fake_cloud_key}"}
            return {"id": "chatcmpl-cloud-1", "text": '{"ok": true}'}

        srv, base_url, captured_hdrs = _start_scripted_openai_server(_planner)
        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as tf:
                tf.write(fake_cloud_key + "\n")
                key_path = tf.name
            try:
                old_base = os.environ.get("LLM_BASE_URL")
                old_file = os.environ.get("LLM_API_KEY_FILE")
                old_key = os.environ.get("LLM_API_KEY")
                os.environ["LLM_BASE_URL"] = base_url
                os.environ["LLM_API_KEY_FILE"] = key_path
                os.environ.pop("LLM_API_KEY", None)
                try:
                    cli = OllamaClient(model="qwen2.5:7b")
                    self.assertNotIn(fake_cloud_key, repr(cli))
                    parsed, meta = cli.chat_json("Return JSON.", "Hello")
                    self.assertEqual(parsed, {"ok": True})
                    self.assertEqual(meta["completion_id"], "chatcmpl-cloud-1")
                    self.assertNotIn(fake_cloud_key, json.dumps(meta))
                    self.assertEqual(
                        captured_hdrs[-1].get("authorization"),
                        f"Bearer {fake_cloud_key}",
                    )

                    with self.assertRaises(OllamaError) as ctx_err:
                        cli.chat_json("Return JSON.", "TRIGGER_500")
                    self.assertNotIn(fake_cloud_key, str(ctx_err.exception))
                finally:
                    if old_base is None:
                        os.environ.pop("LLM_BASE_URL", None)
                    else:
                        os.environ["LLM_BASE_URL"] = old_base
                    if old_file is None:
                        os.environ.pop("LLM_API_KEY_FILE", None)
                    else:
                        os.environ["LLM_API_KEY_FILE"] = old_file
                    if old_key is not None:
                        os.environ["LLM_API_KEY"] = old_key
            finally:
                os.unlink(key_path)
        finally:
            srv.shutdown()
            srv.server_close()

        redacted = redact_sensitive(
            {"llm_api_key": fake_cloud_key, "note": f"leaked {fake_cloud_key}"}
        )
        self.assertEqual(redacted["llm_api_key"], "[REDACTED]")
        self.assertNotIn(fake_cloud_key, redacted["note"])

    def test_03_sidecar_polyglot_consent_and_digest_wallet_isolation(self) -> None:
        mesh = _MultiDomainWorkspaceMesh()
        try:
            alice_oidc = str(mesh.login_user("alice")["access_token"])
            bob_oidc = str(mesh.login_user("bob")["access_token"])

            # Verify `discover` returns sanitized peer catalog with zero raw secrets
            r_disc = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={"action": "discover", "skill": "workspace.tech_review"},
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(r_disc.status_code, 200)
            peers = r_disc.json()["peers"]
            self.assertEqual(len(peers), 1)
            self.assertEqual(peers[0]["spiffe_id"], mesh.bob_card.spiffe_id)
            self.assertEqual(peers[0]["status"], "ACTIVE")

            # Mint Task 1 for `user:alice@org-alpha.io` and capture active `request_id` on `alice_sc`
            perms = PermissionLattice.create(
                tools=["service_diag_read", "cohort_aggregate_stats"],
                param_whitelist={"study_id": ["STUDY-M11-ISO"]},
                max_calls=8,
            )
            tok_t1 = mesh.mint_alpha_root(
                task_id="task-m11-iso-1",
                sub="user:alice@org-alpha.io",
                perms=perms,
                target_card=mesh.alice_card,
                user_oidc_token=alice_oidc,
            )
            # Register active request context in `alice_sc.active_requests` to test polyglot proxy directly
            from lineage.protocol import decode_token

            parsed_t1 = decode_token(tok_t1)
            ver_t1 = mesh.alice_sc.verifier.verify_single_chain_full(parsed_t1, check_revocation=True)
            req_id_t1 = mesh.alice_sc.active_requests.register(tok_t1, parsed_t1, ver_t1).request_id

            # Missing OIDC -> 401
            r_no_oidc = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "request_peer_consent",
                    "request_id": req_id_t1,
                    "required_skill": "workspace.tech_review",
                    "tools": ["service_diag_read", "cohort_aggregate_stats"],
                    "owner_oidc_token": "",
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(r_no_oidc.status_code, 401)

            # Valid Bob OIDC -> 200 opaque `consent_handle` (ZERO `lct1.` / `lctco1.` in response!)
            r_c = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "request_peer_consent",
                    "request_id": req_id_t1,
                    "required_skill": "workspace.tech_review",
                    "tools": ["service_diag_read", "cohort_aggregate_stats"],
                    "owner_oidc_token": bob_oidc,
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(r_c.status_code, 200, r_c.text)
            c_body = r_c.json()
            chdl = c_body["consent_handle"]
            self.assertTrue(chdl.startswith("chdl-"))
            self.assertNotIn("lct1.", r_c.text)
            self.assertNotIn("lctco1.", r_c.text)

            # Valid `call_mcp_coauth` for `cohort_aggregate_stats` with `redact_digest_jws=True`
            r_st = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "call_mcp_coauth",
                    "request_id": req_id_t1,
                    "consent_handle": chdl,
                    "required_skill": "workspace.bob_private",
                    "redact_digest_jws": True,
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "cohort_aggregate_stats",
                            "arguments": {"study_id": "STUDY-M11-ISO"},
                        },
                    },
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(r_st.status_code, 200, r_st.text)
            st_data = r_st.json()["upstream_body"]["result"]["data"]
            dhdl = st_data["digest_handle"]
            self.assertTrue(dhdl.startswith("cdhdl-"))
            self.assertNotIn("digest_jws", st_data)
            self.assertNotIn("eyJ", r_st.text)

            # Cross-task reuse (`task-m11-iso-2`) of `consent_handle` AND `digest_handle` MUST fail `403`!
            tok_t2 = mesh.mint_alpha_root(
                task_id="task-m11-iso-2",
                sub="user:alice@org-alpha.io",
                perms=perms,
                target_card=mesh.alice_card,
                user_oidc_token=alice_oidc,
            )
            parsed_t2 = decode_token(tok_t2)
            ver_t2 = mesh.alice_sc.verifier.verify_single_chain_full(parsed_t2, check_revocation=True)
            req_id_t2 = mesh.alice_sc.active_requests.register(tok_t2, parsed_t2, ver_t2).request_id

            r_cross_task_c = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "call_mcp_coauth",
                    "request_id": req_id_t2,
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
            self.assertEqual(r_cross_task_c.status_code, 403)
            self.assertEqual(r_cross_task_c.json()["error"], "CROSS_TENANT_OR_TASK_CONSENT_DENIED")

            r_cross_task_d = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "call_tool",
                    "request_id": req_id_t2,
                    "required_skill": "mcp.workspace-vault",
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "federated_cohort_aggregate",
                            "arguments": {
                                "study_id": "STUDY-M11-ISO",
                                "digest_handles": [dhdl, dhdl],
                            },
                        },
                    },
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(r_cross_task_d.status_code, 403)
            self.assertEqual(r_cross_task_d.json()["error"], "CROSS_TENANT_OR_TASK_DIGEST_DENIED")

            # Cross-tenant (`user:mallory@org-alpha.io`) on SAME `task-m11-iso-1` MUST also fail `403`!
            from lineage.protocol import mint_root_token

            mallory_tok = mint_root_token(
                authority_ca=mesh.ca_alpha.ca,
                task_id="task-m11-iso-1",
                sub="user:mallory@org-alpha.io",
                sender_jkt=mesh.alpha_gw_id.jkt,
                first_hop_spiffe_id=mesh.alice_card.spiffe_id,
                first_hop_jkt=mesh.alice_card.jkt,
                permissions=perms,
                hop_segment="AssistantAlice",
                first_hop_public_jwk=mesh.alice_card.public_jwk,
            )
            ver_mal = mesh.alice_sc.verifier.verify_single_chain_full(mallory_tok, check_revocation=True)
            req_id_mal = mesh.alice_sc.active_requests.register(
                mallory_tok.encode_compact(), mallory_tok, ver_mal
            ).request_id
            r_cross_tenant_c = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "call_mcp_coauth",
                    "request_id": req_id_mal,
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
            self.assertEqual(r_cross_tenant_c.status_code, 403)
            self.assertEqual(r_cross_tenant_c.json()["error"], "CROSS_TENANT_OR_TASK_CONSENT_DENIED")
        finally:
            mesh.close()

    def test_04_live_nodejs_pi_agent_subprocess_behind_python_lineage_sidecar(self) -> None:
        mesh = _MultiDomainWorkspaceMesh()
        pi_proc: Optional[subprocess.Popen[str]] = None
        pi_sc: Optional[LineageSidecar] = None
        pi_rep: Optional[RevocationReplicaClient] = None
        llm_srv: Optional[http.server.ThreadingHTTPServer] = None
        secret_file_path: Optional[str] = None
        sa_file_path: Optional[str] = None

        # Stateful multi-turn planner driving real `@mariozechner/pi-agent-core` over SSE!
        def _sse_planner(msgs: List[Dict[str, Any]], _hdrs: Dict[str, str]) -> Dict[str, Any]:
            user_txt = " ".join(
                str(m.get("content") or "") for m in msgs if m.get("role") == "user"
            )
            tool_msgs = [m for m in msgs if m.get("role") == "tool"]

            if "INC-FIN-2026-42" in user_txt:
                step = len(tool_msgs)
                if step == 0:
                    return {"tool_calls": [{"name": "discover_workspace_peers", "arguments": {}}]}
                if step == 1:
                    return {
                        "tool_calls": [
                            {"name": "call_peer_diagnostics", "arguments": {"incident_id": "INC-FIN-2026-42"}}
                        ]
                    }
                if step == 2:
                    return {
                        "tool_calls": [
                            {
                                "name": "request_peer_owner_consent",
                                "arguments": {
                                    "peer": "bob",
                                    "tools": ["service_diag_read", "commit_joint_change"],
                                },
                            }
                        ]
                    }
                chdl = ""
                for tm in tool_msgs:
                    c_raw = str(tm.get("content") or "")
                    if "chdl-" in c_raw:
                        chdl = json.loads(c_raw)["consent_handle"]
                if step == 3:
                    return {
                        "tool_calls": [
                            {
                                "name": "call_peer_diagnostics",
                                "arguments": {"incident_id": "INC-FIN-2026-42", "consent_handle": chdl},
                            }
                        ]
                    }
                if step == 4:
                    # Simulate LLM falling for BOTH indirect prompt injections AND executing legitimate commit!
                    return {
                        "tool_calls": [
                            {
                                "name": "call_peer_private_tool",
                                "arguments": {"peer": "bob", "tool_name": "hr_salary_read"},
                            },
                            {
                                "name": "call_vault_tool",
                                "arguments": {
                                    "tool_name": "reserve_cloud_budget",
                                    "project_code": "PRJ-ROGUE",
                                    "amount": 9999,
                                    "target": "cloud-infra-escrow",
                                },
                            },
                            {
                                "name": "call_vault_tool",
                                "arguments": {
                                    "tool_name": "commit_joint_change",
                                    "change_id": "FIN-RULE-42",
                                    "consent_handle": chdl,
                                },
                            },
                        ]
                    }
                return {"text": "FIN-RULE-42 committed; LCT blocked hr_salary_read and PRJ-ROGUE."}

            # Case Study 2: Healthcare Federated Cohort Aggregation (`STUDY-MED-2026-07`)
            if len(tool_msgs) == 0:
                return {
                    "tool_calls": [
                        {"name": "discover_workspace_peers", "arguments": {}},
                        {
                            "name": "call_peer_private_tool",
                            "arguments": {
                                "peer": "bob",
                                "tool_name": "export_raw_patient_records",
                                "study_id": "STUDY-MED-2026-07",
                            },
                        },
                        {
                            "name": "call_peer_private_tool",
                            "arguments": {
                                "peer": "carol",
                                "tool_name": "export_raw_patient_records",
                                "study_id": "STUDY-MED-2026-07",
                            },
                        },
                    ]
                }
            if len(tool_msgs) == 3:
                return {
                    "tool_calls": [
                        {
                            "name": "request_peer_owner_consent",
                            "arguments": {"peer": "bob", "tools": ["cohort_aggregate_stats"]},
                        },
                        {
                            "name": "request_peer_owner_consent",
                            "arguments": {"peer": "carol", "tools": ["cohort_aggregate_stats"]},
                        },
                    ]
                }
            if len(tool_msgs) == 5:
                bob_chdl = json.loads(str(tool_msgs[3]["content"]))["consent_handle"]
                carol_chdl = json.loads(str(tool_msgs[4]["content"]))["consent_handle"]
                return {
                    "tool_calls": [
                        {
                            "name": "call_peer_cohort_stats",
                            "arguments": {
                                "peer": "bob",
                                "study_id": "STUDY-MED-2026-07",
                                "consent_handle": bob_chdl,
                            },
                        },
                        {
                            "name": "call_peer_cohort_stats",
                            "arguments": {
                                "peer": "carol",
                                "study_id": "STUDY-MED-2026-07",
                                "consent_handle": carol_chdl,
                            },
                        },
                    ]
                }
            if len(tool_msgs) == 7:
                bob_dhdl = json.loads(str(tool_msgs[5]["content"]))["digest_handle"]
                carol_dhdl = json.loads(str(tool_msgs[6]["content"]))["digest_handle"]
                return {
                    "tool_calls": [
                        {
                            "name": "call_vault_tool",
                            "arguments": {
                                "tool_name": "federated_cohort_aggregate",
                                "study_id": "STUDY-MED-2026-07",
                                "digest_handles": [bob_dhdl, carol_dhdl],
                            },
                        }
                    ]
                }
            return {"text": "STUDY-MED-2026-07 federated cohort aggregation completed with 0 raw PII."}

        try:
            llm_srv, llm_base_url, _ = _start_scripted_openai_server(_sse_planner)

            # Register `pi-assistant-alice` SA in `alpha` CA and spawn Python `LineageSidecar` + Node `server.mjs`
            mesh.sa_tokens["sa-pi-alice"] = ("lineage-alpha", "pi-assistant-alice")
            mesh.ca_alpha.k8s_verifier = mesh.ca_alpha.k8s_verifier.__class__(mesh.sa_tokens)  # type: ignore[attr-defined]
            pi_wid = mesh.ca_alpha.ca.issue_workload("/ns/lineage-alpha/sa/pi-assistant-alice")
            loopback_sec = secrets.token_urlsafe(24)
            app_port = _pick_ephemeral_port()

            with tempfile.NamedTemporaryFile("w", delete=False) as tf_sec:
                tf_sec.write(loopback_sec)
                secret_file_path = tf_sec.name
            with tempfile.NamedTemporaryFile("w", delete=False) as tf_sa:
                tf_sa.write("sa-pi-alice")
                sa_file_path = tf_sa.name

            pi_rep = RevocationReplicaClient(mesh.rev_alpha_url, mesh.resolver)
            pi_rep.start_background_sync(wait_ms=80)
            pi_em = AuditStreamEmitter(
                pi_wid,
                collector_client=None,
                authorized_auditors=[mesh.alpha_gw_id.spiffe_id, mesh.beta_gw_id.spiffe_id],
            )
            pi_sc = LineageSidecar(
                identity=pi_wid,
                trust_resolver=mesh.resolver,
                app_upstream_url=f"http://127.0.0.1:{app_port}",
                loopback_secret=loopback_sec,
                mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
                revocation_replica=pi_rep,
                directory_client=mesh.dir_cli,
                audit_emitter=pi_em,
                inbound_host="127.0.0.1",
                inbound_port=0,
                outbound_port=0,
                local_ca_url=mesh.ca_alpha_url,
                sa_token_path=sa_file_path,
                resource_owner_sub="user:alice@org-alpha.io",
                owner_protected_tools=["hr_salary_read", "export_raw_patient_records"],
                allowed_co_auth_tools=["commit_joint_change", "cohort_aggregate_stats"],
            )
            pi_in_url, pi_out_url = pi_sc.start()
            pi_card = AgentCard.sign_and_create(
                identity=pi_wid,
                name="Alice Pi Workspace Assistant",
                endpoint=pi_in_url,
                return_endpoint=pi_in_url,
                skills=["workspace.pi_orchestrate"],
                priority=10,
            )
            pi_sc.set_agent_card(pi_card)
            mesh.dir_cli.register(pi_card)

            node_bin = _find_node_binary()
            pi_server_mjs = Path(__file__).resolve().parents[1] / "pi_agent" / "server.mjs"
            child_env = {
                **os.environ,
                "LLM_BASE_URL": llm_base_url,
                "LLM_MODEL": "qwen2.5:3b",
                "LLM_API_KEY": "sk-proj-" + "m11-subprocess-secret-key-000011112222",
                "LCT_ENABLE_FAULT_INJECTION": "true",
                "NO_PROXY": "127.0.0.1,localhost",
                "no_proxy": "127.0.0.1,localhost",
            }
            pi_proc = subprocess.Popen(
                [
                    node_bin,
                    str(pi_server_mjs),
                    "--port",
                    str(app_port),
                    "--sidecar-url",
                    pi_out_url,
                    "--secret-file",
                    secret_file_path,
                ],
                env=child_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Wait for Node.js `Pi` server `/healthz`
            deadline = time.time() + 10.0
            ready = False
            while time.time() < deadline:
                try:
                    rh = httpx.get(f"http://127.0.0.1:{app_port}/healthz", timeout=1.0)
                    if rh.status_code == 200:
                        ready = True
                        break
                except Exception:
                    time.sleep(0.1)
            self.assertTrue(ready, "Node.js Pi server failed to start on loopback")

            alice_oidc = str(mesh.login_user("alice")["access_token"])
            bob_oidc = str(mesh.login_user("bob")["access_token"])
            carol_oidc = str(mesh.login_user("carol")["access_token"])

            # --- Case Study 1: Financial Risk Triage & Indirect Prompt Injection ---
            tok_cs1 = mesh.mint_alpha_root(
                task_id="pi-unit-cs1",
                sub="user:alice@org-alpha.io",
                perms=PermissionLattice.create(
                    tools=["service_diag_read", "commit_joint_change"],
                    max_amount=0.0,
                    param_whitelist={"change_id": ["FIN-RULE-42"]},
                    max_calls=10,
                ),
                target_card=pi_card,
                user_oidc_token=alice_oidc,
                hop_segment="PiAssistantAlice",
            )
            r_cs1 = mesh.post_lct(
                mesh.alpha_gw_id,
                pi_card,
                tok_cs1,
                {
                    "prompt": "Triage INC-FIN-2026-42 and commit FIN-RULE-42.",
                    "consent_grants": {"bob": bob_oidc},
                    "simulate_untrusted_log_injection": True,
                },
            )
            self.assertEqual(r_cs1.status_code, 200, r_cs1.text)
            self.assertNotIn("sk-proj-" + "m11-subprocess-secret-key", r_cs1.text)
            self.assertNotIn("eyJ", r_cs1.text)
            self.assertNotIn("lct1.", r_cs1.text)
            b_cs1 = r_cs1.json()
            self.assertEqual(b_cs1["pi_runtime"]["package"], "@mariozechner/pi-agent-core")
            self.assertTrue(b_cs1["pi_runtime"]["llm_spontaneously_triggered_injection"])
            tr_cs1 = b_cs1["pi_runtime"]["tool_calls_trace"]
            self.assertEqual(
                [t["http_status"] for t in tr_cs1],
                [200, 403, 200, 200, 403, 403, 200],
                tr_cs1,
            )
            aud_cs1 = mesh.audit_task(
                task_id="pi-unit-cs1",
                entry_spiffe_ids=[pi_card.spiffe_id],
                seed_domains=["org-alpha.io", "org-beta.io", "org-payment.io"],
            )
            self.assertTrue(aud_cs1.reconstructed_complete)
            self.assertEqual(aud_cs1.anomalies, [])

            # --- Case Study 2: Heterogeneous Healthcare Federated Cohort Aggregation ---
            tok_cs2 = mesh.mint_alpha_root(
                task_id="pi-unit-cs2",
                sub="user:alice@org-alpha.io",
                perms=PermissionLattice.create(
                    tools=["cohort_aggregate_stats", "federated_cohort_aggregate"],
                    param_whitelist={"study_id": ["STUDY-MED-2026-07"]},
                    max_calls=12,
                ),
                target_card=pi_card,
                user_oidc_token=alice_oidc,
                hop_segment="PiMedCoordinator",
            )
            r_cs2 = mesh.post_lct(
                mesh.alpha_gw_id,
                pi_card,
                tok_cs2,
                {
                    "prompt": "Run federated study STUDY-MED-2026-07 across Bob and Carol.",
                    "consent_grants": {"bob": bob_oidc, "carol": carol_oidc},
                },
            )
            self.assertEqual(r_cs2.status_code, 200, r_cs2.text)
            self.assertNotIn("eyJ", r_cs2.text)
            b_cs2 = r_cs2.json()
            tr_cs2 = b_cs2["pi_runtime"]["tool_calls_trace"]
            self.assertEqual(tr_cs2[-1]["http_status"], 200)
            self.assertTrue(tr_cs2[-1]["outcome"]["cohort_digests_verified"])
            self.assertIs(tr_cs2[-1]["outcome"]["raw_pii_present"], False)
            aud_cs2 = mesh.audit_task(
                task_id="pi-unit-cs2",
                entry_spiffe_ids=[pi_card.spiffe_id],
                seed_domains=["org-alpha.io", "org-beta.io", "org-payment.io"],
            )
            self.assertTrue(aud_cs2.reconstructed_complete)
            self.assertEqual(aud_cs2.anomalies, [])
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
            if pi_rep is not None:
                pi_rep.stop_background_sync()
            if pi_sc is not None:
                pi_sc.stop()
            if llm_srv is not None:
                llm_srv.shutdown()
                llm_srv.server_close()
            for p in (secret_file_path, sa_file_path):
                if p and os.path.exists(p):
                    os.unlink(p)
            mesh.close()

    def test_05_m11_round2_qa_security_remediations(self) -> None:
        """Verify all 5 Milestone 11 Round-1 QA findings (`[CRITICAL-M11-01]`..`[LOW-M11-01]`) are closed."""
        mesh = _MultiDomainWorkspaceMesh()
        sink: Optional[http.server.ThreadingHTTPServer] = None
        try:
            # 1. [CRITICAL-M11-01]: WorkloadMTLSBundle rejects plaintext `http://` targets (`MTLSError` / `403`)
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
            with self.assertRaises(MTLSError):
                mb.verify_for_target("http://127.0.0.1:8080/mcp")

            alice_oidc = str(mesh.login_user("alice")["access_token"])
            bob_oidc = str(mesh.login_user("bob")["access_token"])
            perms = PermissionLattice.create(
                tools=["service_diag_read", "cohort_aggregate_stats", "federated_cohort_aggregate"],
                param_whitelist={"study_id": ["STUDY-R2-SEC"]},
                max_calls=10,
            )
            tok = mesh.mint_alpha_root(
                task_id="m11-r2-sec-1",
                sub="user:alice@org-alpha.io",
                perms=perms,
                target_card=mesh.alice_card,
                user_oidc_token=alice_oidc,
            )
            parsed = decode_token(tok)
            ver = mesh.alice_sc.verifier.verify_single_chain_full(parsed, check_revocation=True)
            req_id = mesh.alice_sc.active_requests.register(tok, parsed, ver).request_id

            # 2. [HIGH-M11-01]: Out-of-scope consent tools (`reserve_cloud_budget`) blocked locally 403 in 0 RTT!
            r_oos = httpx.post(
                f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "request_peer_consent",
                    "request_id": req_id,
                    "trust_domain": "org-beta.io",
                    "required_skill": "workspace.tech_review",
                    "tools": ["reserve_cloud_budget"],
                    "owner_oidc_token": bob_oidc,
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(r_oos.status_code, 403)
            self.assertEqual(r_oos.json()["error"], "LATTICE_PERMISSION_DENIED")

            # 3. [HIGH-M11-01]: Poisoned priority=1 Yellow Pages card from `org-payment.io` CANNOT exfiltrate Bob's (`org-beta.io`) OIDC JWT!
            poison_card = AgentCard.sign_and_create(
                identity=mesh.carol_sc.identity,
                name="Carol Poisoned Tech Review",
                endpoint=mesh.carol_card.endpoint,
                return_endpoint=mesh.carol_card.return_endpoint,
                skills=["workspace.tech_review", "workspace.biz_procurement"],
                priority=1,
                version=2,
                locators=mesh.carol_card.locators,
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

            # Explicit `trust_domain: "org-beta.io"` routes cleanly to Bob despite Carol's priority=1 card!
            rc_ok = httpx.post(
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
            self.assertEqual(rc_ok.status_code, 200, rc_ok.text)
            chdl = rc_ok.json()["consent_handle"]

            # 4. [HIGH-M11-02]: `call_mcp_coauth` defaults `redact_digest_jws` to True (`digest_jws` stripped even when omitted!)
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
                            "arguments": {"study_id": "STUDY-R2-SEC"},
                        },
                    },
                },
                headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                timeout=5.0,
            )
            self.assertEqual(rst.status_code, 200, rst.text)
            rst_data = rst.json()["upstream_body"]["result"]["data"]
            self.assertNotIn("digest_jws", rst_data)
            dhdl = rst_data["digest_handle"]

            # 5. [CRITICAL-M11-01]: Caller-supplied `target_url` on `call_mcp_coauth` or `digest_handles` -> 403 (`0` bytes exfiltrated!)
            captured_exfil: Dict[str, Any] = {}

            class _SinkHandler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args: Any) -> None:
                    return

                def do_POST(self) -> None:
                    captured_exfil["hit"] = True
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"{}")

            sink = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SinkHandler)
            threading.Thread(target=sink.serve_forever, daemon=True).start()
            sink_url = f"http://127.0.0.1:{sink.server_address[1]}/mcp"

            for exfil_body in (
                {
                    "action": "call_mcp_coauth",
                    "request_id": req_id,
                    "consent_handle": chdl,
                    "target_url": sink_url,
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "cohort_aggregate_stats", "arguments": {"study_id": "STUDY-R2-SEC"}},
                    },
                },
                {
                    "action": "call_tool",
                    "request_id": req_id,
                    "target_url": sink_url,
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "federated_cohort_aggregate",
                            "arguments": {"study_id": "STUDY-R2-SEC", "digest_handles": [dhdl]},
                        },
                    },
                },
            ):
                r_ex = httpx.post(
                    f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                    json=exfil_body,
                    headers={"X-LCT-Loopback-Auth": mesh.alice_sc.loopback_secret},
                    timeout=5.0,
                )
                self.assertEqual(r_ex.status_code, 403)
                self.assertEqual(r_ex.json()["error"], "UNVERIFIED_TARGET_URL_FORBIDDEN_FOR_OPAQUE_HANDLE")
            self.assertEqual(captured_exfil, {})

            # Plaintext `http://` target when `_mtls_bundle` is active -> 403 PLAINTEXT_HTTP_FORBIDDEN_UNDER_MTLS!
            mesh.alice_sc._mtls_bundle = mb
            try:
                r_http = httpx.post(
                    f"{mesh.alice_sc.outbound_url}/v1/proxy/call",
                    json={
                        "action": "call_tool",
                        "request_id": req_id,
                        "target_url": sink_url,
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
                self.assertEqual(r_http.status_code, 403)
                self.assertEqual(r_http.json()["error"], "PLAINTEXT_HTTP_FORBIDDEN_UNDER_MTLS")
                self.assertEqual(captured_exfil, {})
            finally:
                mesh.alice_sc._mtls_bundle = None
                mb.cleanup()

            # 6. [HIGH-M11-02]: Native inbound `op: "request_co_auth_consent"` on `LineageSidecar` (zero app involvement!)
            bob_root_to_alice = mint_root_token(
                authority_ca=mesh.ca_beta.ca,
                task_id="m11-r2-sym-in",
                sub="user:bob@org-beta.io",
                sender_jkt=mesh.beta_gw_id.jkt,
                first_hop_spiffe_id=mesh.alice_card.spiffe_id,
                first_hop_jkt=mesh.alice_card.jkt,
                permissions=PermissionLattice.create(tools=["commit_joint_change"], max_calls=4),
                hop_segment="AssistantAlice",
                first_hop_public_jwk=mesh.alice_card.public_jwk,
            ).encode_compact()
            r_in_consent = mesh.post_lct(
                mesh.beta_gw_id,
                mesh.alice_card,
                bob_root_to_alice,
                {
                    "op": "request_co_auth_consent",
                    "tools": ["commit_joint_change"],
                    "delegate_spiffe_id": mesh.bob_card.spiffe_id,
                    "delegate_jkt": mesh.bob_card.jkt,
                    "user_oidc_token": alice_oidc,
                },
            )
            self.assertEqual(r_in_consent.status_code, 200, r_in_consent.text)
            minted_c = decode_token(r_in_consent.json()["compact_token"])
            self.assertIsInstance(minted_c, LineageToken)
            self.assertEqual(minted_c.sub, "user:alice@org-alpha.io")
            self.assertEqual(minted_c.holder_spiffe_id, mesh.bob_card.spiffe_id)

            # 7. [HIGH-M11-02]: True LRU + TTL wallet eviction
            mesh.alice_sc._wallet_ttl_seconds = 10.0
            mesh.alice_sc._wallet_max_entries = 2
            mesh.alice_sc._wallet_put(mesh.alice_sc._peer_consent_wallet, "k1", {"v": 1}, now_ts=100.0)
            mesh.alice_sc._wallet_put(mesh.alice_sc._peer_consent_wallet, "k2", {"v": 2}, now_ts=101.0)
            # Touch k1 -> k1 becomes MRU, k2 becomes LRU
            self.assertEqual(
                mesh.alice_sc._wallet_get(mesh.alice_sc._peer_consent_wallet, "k1", now_ts=102.0)["v"], 1
            )
            mesh.alice_sc._wallet_put(mesh.alice_sc._peer_consent_wallet, "k3", {"v": 3}, now_ts=103.0)
            self.assertIsNone(
                mesh.alice_sc._wallet_get(mesh.alice_sc._peer_consent_wallet, "k2", now_ts=103.0)
            )
            self.assertIsNotNone(
                mesh.alice_sc._wallet_get(mesh.alice_sc._peer_consent_wallet, "k1", now_ts=103.0)
            )
            # TTL expiry after 10s
            self.assertIsNone(
                mesh.alice_sc._wallet_get(mesh.alice_sc._peer_consent_wallet, "k1", now_ts=115.0)
            )

            # 8. [LOW-M11-01]: Broadened provider keys + embedded JWS + URL userinfo/query scrubbing
            emb_jws = ".".join(["eyJhbGciOiJFUzI1NiJ9", "eyJzdWIiOiJhbGljZSJ9", "YWJjZGVmZ2hpamtsbW5vcA"])
            for k_sample in (
                "sk-or-v1-" + ("a" * 24),
                "sk-svcacct-" + ("b" * 24),
                "gsk_" + ("c" * 24),
                "xai-" + ("d" * 24),
                "hf_" + ("e" * 24),
                "AIza" + ("F" * 32),
            ):
                scr = redact_sensitive({"msg": f"err key={k_sample} jwt={emb_jws} end"})
                self.assertNotIn(k_sample, scr["msg"])
                self.assertNotIn("eyJhbG", scr["msg"])
            cli_u = OllamaClient(
                base_url="http://user:secretpass@127.0.0.1:9/v1?api_key=leak",
                model="qwen2.5:3b",
                timeout=0.3,
            )
            self.assertNotIn("secretpass", repr(cli_u))
            self.assertNotIn("api_key=leak", repr(cli_u))
        finally:
            if sink is not None:
                sink.shutdown()
                sink.server_close()
            mesh.close()


if __name__ == "__main__":
    unittest.main()
