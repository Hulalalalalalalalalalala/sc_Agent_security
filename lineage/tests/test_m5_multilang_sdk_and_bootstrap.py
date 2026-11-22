"""Milestone 5 Polyglot Sidecar SDKs (`Go`, `Node.js`, `Python`), Scaffolder,
Dependency Bootstrapper (`setup_deps.sh`), and GitHub Pre-Flight Tests.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from typing import Any, Dict
import zipfile

import httpx
import yaml

import lineage
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.protocol import PermissionLattice, create_dpop_proof, mint_root_token
from lineage.sdk.python import (
    LCTAgentServer,
    LCTSidecarClient,
    load_loopback_secret,
    verify_loopback_secret,
)
from lineage.sdk.python.example_agent import build_agent_handler
from lineage.sidecar import AgentSidecarNode, LineageSidecar, MCPToolSidecarNode


def _augmented_env() -> Dict[str, str]:
    env = dict(os.environ)
    extra_bins = [
        str(Path.home() / ".local" / "bin"),
        "/opt/homebrew/bin",
        "/usr/local/bin",
    ]
    env["PATH"] = ":".join(extra_bins + [env.get("PATH", "")])
    return env


def _pick_free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_http_ok(url: str, timeout_sec: float = 10.0) -> None:
    deadline = time.time() + timeout_sec
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            r = httpx.get(url, timeout=1.0, trust_env=False)
            if r.status_code == 200:
                return
        except Exception as exc:
            last_err = exc
        time.sleep(0.1)
    raise TimeoutError(f"Timed out waiting for 200 OK from {url}: {last_err}")


class Milestone5PolyglotSDKAndBootstrapTests(unittest.TestCase):
    def _setup_test_mesh(self):
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        ca_pay = TrustDomainCA("org-payment.io")
        resolver = TrustBundleResolver()
        for ca in (ca_alpha, ca_beta, ca_pay):
            resolver.register_bundle(ca.export_public_bundle())

        gw_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/gw")
        orch_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/polyglot-orch")
        sub_id = ca_beta.issue_workload("/ns/lineage-beta/sa/sub-specialist")
        mcp_id = ca_pay.issue_workload("/ns/lineage-pay/sa/travel-mcp")

        mcp_node = MCPToolSidecarNode(
            identity=mcp_id,
            trust_resolver=resolver,
            tools={
                "search_flight": lambda args, _req: {
                    "city": args.get("city", "Tokyo"),
                    "flight_no": "NH-108",
                    "price_usd": 580.0,
                }
            },
        )
        mcp_url = mcp_node.start()

        sub_node = AgentSidecarNode(
            identity=sub_id,
            trust_resolver=resolver,
            name="BetaSubSpecialist",
            skills=["travel.sub"],
            handler=lambda _node, req, payload: (
                200,
                {
                    "sub_specialist": "ok",
                    "received_payload": payload,
                    "lineage_path": req.header("X-LCT-Lineage-Path"),
                },
            ),
        )
        sub_card = sub_node.start(register_in_directory=False)

        return {
            "ca_alpha": ca_alpha,
            "resolver": resolver,
            "gw_id": gw_id,
            "orch_id": orch_id,
            "sub_id": sub_id,
            "mcp_node": mcp_node,
            "mcp_url": f"{mcp_url}/mcp",
            "sub_node": sub_node,
            "sub_url": f"{sub_card.endpoint}/a2a/task",
        }

    def test_01_live_go_agent_behind_python_sidecar_and_attenuated_downstream(self) -> None:
        env = _augmented_env()
        go_bin = shutil.which("go", path=env["PATH"])
        self.assertIsNotNone(go_bin, "Expected Go toolchain at ~/.local/bin/go")
        assert go_bin is not None

        lineage_dir = Path(lineage.__file__).resolve().parent
        go_sdk_dir = lineage_dir / "sdk" / "go"
        mesh = self._setup_test_mesh()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            agent_exe = tmp_path / "go-example-agent"
            subprocess.run(
                [go_bin, "build", "-o", str(agent_exe), "./cmd/example_agent"],
                cwd=str(go_sdk_dir),
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            secret = secrets.token_urlsafe(32)
            secret_file = tmp_path / "loopback.secret"
            secret_file.write_text(secret, encoding="utf-8")
            os.chmod(secret_file, 0o600)

            app_port = _pick_free_loopback_port()
            sidecar_out_port = _pick_free_loopback_port()

            sidecar = LineageSidecar(
                identity=mesh["orch_id"],
                trust_resolver=mesh["resolver"],
                app_upstream_url=f"http://127.0.0.1:{app_port}",
                loopback_secret=secret,
                inbound_host="127.0.0.1",
                inbound_port=0,
                outbound_port=sidecar_out_port,
            )
            in_url, out_url = sidecar.start()

            proc = subprocess.Popen(
                [
                    str(agent_exe),
                    "-port",
                    str(app_port),
                    "-sidecar-url",
                    out_url,
                    "-secret-file",
                    str(secret_file),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
            )
            try:
                _wait_http_ok(f"http://127.0.0.1:{app_port}/healthz")

                # 1. Direct loopback request without or with wrong X-LCT-Loopback-Auth -> 403!
                r_bypass = httpx.post(
                    f"http://127.0.0.1:{app_port}/a2a/task",
                    json={"op": "echo"},
                    headers={"X-LCT-Loopback-Auth": "wrong-secret"},
                    trust_env=False,
                )
                self.assertEqual(r_bypass.status_code, 403)
                self.assertEqual(r_bypass.json()["error"], "direct_loopback_bypass_blocked")

                # 2. Valid LCT + DPoP inbound -> Go agent -> Sidecar /v1/proxy/call -> MCP Tool!
                root_perms = PermissionLattice.create(
                    tools=["search_flight", "book_flight"],
                    max_amount=600.0,
                    allowed_targets=["airline-escrow"],
                    param_whitelist={"city": ["Tokyo"]},
                    max_calls=5,
                )
                tok = mint_root_token(
                    mesh["ca_alpha"],
                    "task-m5-go-live",
                    "user:alice@org-alpha.io",
                    mesh["gw_id"].jkt,
                    mesh["orch_id"].spiffe_id,
                    mesh["orch_id"].jkt,
                    root_perms,
                    hop_segment="GoOrch",
                ).encode_compact()

                target_task_url = f"{in_url}/a2a/task"
                dpop_1 = create_dpop_proof(mesh["gw_id"], "POST", target_task_url, tok)
                r_tool = httpx.post(
                    target_task_url,
                    json={
                        "op": "call_tool",
                        "target_url": mesh["mcp_url"],
                        "tool_name": "search_flight",
                        "arguments": {"city": "Tokyo"},
                    },
                    headers={"Authorization": f"DPoP {tok}", "DPoP": dpop_1},
                    trust_env=False,
                )
                self.assertEqual(r_tool.status_code, 200, r_tool.text)
                tool_data = r_tool.json()
                self.assertEqual(tool_data["lang"], "go")
                self.assertEqual(tool_data["lct_context"]["sub"], "user:alice@org-alpha.io")
                self.assertEqual(
                    tool_data["sidecar_result"]["upstream_body"]["result"]["data"]["flight_no"],
                    "NH-108",
                )

                # 3. Attenuated sub-agent delegation (`max_amount=250.0` <= `600.0` -> 200 OK)!
                dpop_2 = create_dpop_proof(mesh["gw_id"], "POST", target_task_url, tok)
                r_del_ok = httpx.post(
                    target_task_url,
                    json={
                        "op": "delegate_agent",
                        "delegate_spiffe_id": mesh["sub_id"].spiffe_id,
                        "delegate_jkt": mesh["sub_id"].jkt,
                        "target_url": mesh["sub_url"],
                        "hop_segment": "GoSubHop",
                        "payload": {"step": "verify_from_go"},
                        "permissions": {
                            "tools": ["search_flight"],
                            "methods": ["tools/call"],
                            "max_amount": 250.0,
                            "numeric_bounds": {},
                            "allowed_scopes": None,
                            "allowed_targets": ["airline-escrow"],
                            "param_whitelist": {"city": ["Tokyo"]},
                            "max_calls": 2,
                        },
                    },
                    headers={"Authorization": f"DPoP {tok}", "DPoP": dpop_2},
                    trust_env=False,
                )
                self.assertEqual(r_del_ok.status_code, 200, r_del_ok.text)
                del_body = r_del_ok.json()["sidecar_result"]["upstream_body"]
                self.assertEqual(
                    del_body["lineage_path"], "/task-m5-go-live/GoOrch/GoSubHop"
                )

                # 4. Privilege escalation attempt (`max_amount=950.0` > `600.0` -> 403)!
                dpop_3 = create_dpop_proof(mesh["gw_id"], "POST", target_task_url, tok)
                r_del_bad = httpx.post(
                    target_task_url,
                    json={
                        "op": "delegate_agent",
                        "delegate_spiffe_id": mesh["sub_id"].spiffe_id,
                        "delegate_jkt": mesh["sub_id"].jkt,
                        "target_url": mesh["sub_url"],
                        "hop_segment": "GoEscalate",
                        "payload": {},
                        "permissions": {
                            "tools": ["search_flight"],
                            "methods": ["tools/call"],
                            "max_amount": 950.0,
                            "numeric_bounds": {},
                            "allowed_scopes": None,
                            "allowed_targets": ["airline-escrow"],
                            "param_whitelist": {"city": ["Tokyo"]},
                            "max_calls": 2,
                        },
                    },
                    headers={"Authorization": f"DPoP {tok}", "DPoP": dpop_3},
                    trust_env=False,
                )
                self.assertEqual(r_del_bad.status_code, 403)
                self.assertEqual(
                    r_del_bad.json()["sidecar_result"]["error"], "attenuation_rejected"
                )
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2.0)
                sidecar.stop()
                mesh["sub_node"].stop()
                mesh["mcp_node"].stop()

    def test_02_live_nodejs_agent_behind_python_sidecar_and_attenuated_downstream(self) -> None:
        env = _augmented_env()
        node_bin = shutil.which("node", path=env["PATH"])
        self.assertIsNotNone(node_bin, "Expected Node.js runtime at ~/.local/bin/node")
        assert node_bin is not None

        lineage_dir = Path(lineage.__file__).resolve().parent
        node_script = lineage_dir / "sdk" / "node" / "example_agent.mjs"
        mesh = self._setup_test_mesh()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            secret = secrets.token_urlsafe(32)
            secret_file = tmp_path / "loopback.secret"
            secret_file.write_text(secret, encoding="utf-8")
            os.chmod(secret_file, 0o600)

            app_port = _pick_free_loopback_port()
            sidecar_out_port = _pick_free_loopback_port()

            sidecar = LineageSidecar(
                identity=mesh["orch_id"],
                trust_resolver=mesh["resolver"],
                app_upstream_url=f"http://127.0.0.1:{app_port}",
                loopback_secret=secret,
                inbound_host="127.0.0.1",
                inbound_port=0,
                outbound_port=sidecar_out_port,
            )
            in_url, out_url = sidecar.start()

            proc = subprocess.Popen(
                [
                    node_bin,
                    str(node_script),
                    "--port",
                    str(app_port),
                    "--sidecar-url",
                    out_url,
                    "--secret-file",
                    str(secret_file),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
            )
            try:
                _wait_http_ok(f"http://127.0.0.1:{app_port}/healthz")

                # 1. Direct loopback bypass without secret -> 403!
                r_bypass = httpx.post(
                    f"http://127.0.0.1:{app_port}/a2a/task",
                    json={"op": "echo"},
                    trust_env=False,
                )
                self.assertEqual(r_bypass.status_code, 403)
                self.assertEqual(r_bypass.json()["error"], "direct_loopback_bypass_blocked")

                # 2. Valid LCT + DPoP -> Node.js agent -> Sidecar -> MCP Tool -> 200 OK!
                root_perms = PermissionLattice.create(
                    tools=["search_flight"],
                    max_amount=500.0,
                    param_whitelist={"city": ["Tokyo"]},
                    max_calls=4,
                )
                tok = mint_root_token(
                    mesh["ca_alpha"],
                    "task-m5-node-live",
                    "user:bob@org-alpha.io",
                    mesh["gw_id"].jkt,
                    mesh["orch_id"].spiffe_id,
                    mesh["orch_id"].jkt,
                    root_perms,
                    hop_segment="NodeOrch",
                ).encode_compact()

                target_task_url = f"{in_url}/a2a/task"
                dpop_1 = create_dpop_proof(mesh["gw_id"], "POST", target_task_url, tok)
                r_tool = httpx.post(
                    target_task_url,
                    json={
                        "op": "call_tool",
                        "target_url": mesh["mcp_url"],
                        "tool_name": "search_flight",
                        "arguments": {"city": "Tokyo"},
                    },
                    headers={"Authorization": f"DPoP {tok}", "DPoP": dpop_1},
                    trust_env=False,
                )
                self.assertEqual(r_tool.status_code, 200, r_tool.text)
                body = r_tool.json()
                self.assertEqual(body["lang"], "node")
                self.assertEqual(body["lct_context"]["sub"], "user:bob@org-alpha.io")
                self.assertEqual(
                    body["sidecar_result"]["upstream_body"]["result"]["data"]["flight_no"],
                    "NH-108",
                )

                # 3. Attenuated sub-agent delegation from Node.js (`max_amount=200.0` <= `500.0`)
                dpop_2 = create_dpop_proof(mesh["gw_id"], "POST", target_task_url, tok)
                r_del = httpx.post(
                    target_task_url,
                    json={
                        "op": "delegate_agent",
                        "delegate_spiffe_id": mesh["sub_id"].spiffe_id,
                        "delegate_jkt": mesh["sub_id"].jkt,
                        "target_url": mesh["sub_url"],
                        "hop_segment": "NodeSubHop",
                        "payload": {"origin": "nodejs"},
                        "permissions": {
                            "tools": ["search_flight"],
                            "methods": ["tools/call"],
                            "max_amount": 200.0,
                            "numeric_bounds": {},
                            "allowed_scopes": None,
                            "allowed_targets": None,
                            "param_whitelist": {"city": ["Tokyo"]},
                            "max_calls": 2,
                        },
                    },
                    headers={"Authorization": f"DPoP {tok}", "DPoP": dpop_2},
                    trust_env=False,
                )
                self.assertEqual(r_del.status_code, 200, r_del.text)
                self.assertEqual(
                    r_del.json()["sidecar_result"]["upstream_body"]["lineage_path"],
                    "/task-m5-node-live/NodeOrch/NodeSubHop",
                )
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2.0)
                sidecar.stop()
                mesh["sub_node"].stop()
                mesh["mcp_node"].stop()

    def test_03_live_python_sdk_agent_behind_sidecar(self) -> None:
        mesh = self._setup_test_mesh()
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "secret"
            secret_val = secrets.token_urlsafe(32)
            secret_path.write_text(secret_val, encoding="utf-8")
            loaded = load_loopback_secret(str(secret_path))
            self.assertEqual(loaded, secret_val)

            out_port = _pick_free_loopback_port()
            py_client = LCTSidecarClient(loaded, f"http://127.0.0.1:{out_port}")
            py_srv = LCTAgentServer(loaded, build_agent_handler(py_client), port=0)
            app_url = py_srv.start()

            sidecar = LineageSidecar(
                identity=mesh["orch_id"],
                trust_resolver=mesh["resolver"],
                app_upstream_url=app_url,
                loopback_secret=loaded,
                inbound_host="127.0.0.1",
                inbound_port=0,
                outbound_port=out_port,
            )
            in_url, _ = sidecar.start()
            try:
                r_bypass = httpx.post(f"{app_url}/a2a/task", json={"op": "echo"}, trust_env=False)
                self.assertEqual(r_bypass.status_code, 403)

                perms = PermissionLattice.create(
                    tools=["search_flight"],
                    max_amount=400.0,
                    param_whitelist={"city": ["Tokyo"]},
                    max_calls=3,
                )
                tok = mint_root_token(
                    mesh["ca_alpha"],
                    "task-m5-py-sdk",
                    "user:carol@org-alpha.io",
                    mesh["gw_id"].jkt,
                    mesh["orch_id"].spiffe_id,
                    mesh["orch_id"].jkt,
                    perms,
                    hop_segment="PySDKOrch",
                ).encode_compact()
                target_url = f"{in_url}/a2a/task"
                dpop = create_dpop_proof(mesh["gw_id"], "POST", target_url, tok)
                r_ok = httpx.post(
                    target_url,
                    json={
                        "op": "call_tool",
                        "target_url": mesh["mcp_url"],
                        "tool_name": "search_flight",
                        "arguments": {"city": "Tokyo"},
                    },
                    headers={"Authorization": f"DPoP {tok}", "DPoP": dpop},
                    trust_env=False,
                )
                self.assertEqual(r_ok.status_code, 200, r_ok.text)
                self.assertEqual(r_ok.json()["lang"], "python")
                self.assertEqual(
                    r_ok.json()["sidecar_result"]["upstream_body"]["result"]["data"]["flight_no"],
                    "NH-108",
                )

                dpop_del = create_dpop_proof(mesh["gw_id"], "POST", target_url, tok)
                r_py_del = httpx.post(
                    target_url,
                    json={
                        "op": "delegate_agent",
                        "delegate_spiffe_id": mesh["sub_id"].spiffe_id,
                        "delegate_jkt": mesh["sub_id"].jkt,
                        "target_url": mesh["sub_url"],
                        "hop_segment": "PySubHop",
                        "payload": {"origin": "python-sdk"},
                        "permissions": {
                            "tools": ["search_flight"],
                            "max_amount": 150.0,
                            "param_whitelist": {"city": ["Tokyo"]},
                            "max_calls": 1,
                        },
                    },
                    headers={"Authorization": f"DPoP {tok}", "DPoP": dpop_del},
                    trust_env=False,
                )
                self.assertEqual(r_py_del.status_code, 200, r_py_del.text)
                self.assertEqual(
                    r_py_del.json()["sidecar_result"]["upstream_body"]["lineage_path"],
                    "/task-m5-py-sdk/PySDKOrch/PySubHop",
                )
            finally:
                sidecar.stop()
                py_srv.stop()
                mesh["sub_node"].stop()
                mesh["mcp_node"].stop()

    def test_04_scaffolder_all_5_langs_setup_deps_push_dry_run_and_zero_hardcoded_paths(
        self,
    ) -> None:
        env = _augmented_env()
        lineage_dir = Path(lineage.__file__).resolve().parent
        scripts_dir = lineage_dir / "scripts"

        # 1. Verify ZERO `.sh` scripts under `lineage/` contain hardcoded `/Users/hulalala`!
        sh_files = sorted(lineage_dir.rglob("*.sh"))
        self.assertGreaterEqual(len(sh_files), 7)
        for sh_file in sh_files:
            txt = sh_file.read_text(encoding="utf-8")
            self.assertNotIn(
                "/Users/hulalala",
                txt,
                f"Hardcoded machine path leaked in {sh_file}",
            )

        # 2. Scaffold all 5 languages (`python`, `go`, `node`, `java`, `rust`) via `configure_agent_lang.sh`
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            lang_specs: list[tuple[str, str, str, str]] = [
                ("python", "org-alpha.io", "py-planner", "requirements.txt"),
                ("go", "org-beta.io", "go-flight", "go.mod"),
                ("node", "org-payment.io", "node-ledger", "package.json"),
                ("java", "org-alpha.io", "java-booking", "pom.xml"),
                ("rust", "org-beta.io", "rust-guard", "Cargo.toml"),
            ]
            for idx, (lang, domain, name, expected_manifest) in enumerate(lang_specs):
                out_dir = tmp_root / f"agent-{lang}"
                res = subprocess.run(
                    [
                        "bash",
                        str(scripts_dir / "configure_agent_lang.sh"),
                        "--lang",
                        lang,
                        "--target",
                        str(out_dir),
                        "--name",
                        name,
                        "--domain",
                        domain,
                        "--skill",
                        f"skill.{lang}",
                        "--nodeport",
                        str(30500 + idx),
                    ],
                    env=env,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertIn("Scaffolded", res.stdout)
                self.assertTrue((out_dir / expected_manifest).is_file())
                self.assertTrue((out_dir / "Dockerfile").is_file())
                k8s_yaml = out_dir / "k8s-2of2-pod.yaml"
                self.assertTrue(k8s_yaml.is_file())
                docs = [d for d in yaml.safe_load_all(k8s_yaml.read_text("utf-8")) if d]
                self.assertEqual(len(docs), 3)
                dep = docs[1]
                pod_spec = dep["spec"]["template"]["spec"]
                self.assertIs(pod_spec["automountServiceAccountToken"], False)
                containers = {c["name"]: c for c in pod_spec["containers"]}
                self.assertEqual(set(containers.keys()), {"app", "lct-sidecar"})
                app_mounts = [m["name"] for m in containers["app"]["volumeMounts"]]
                self.assertEqual(app_mounts, ["lct-loopback"])

            # Verify scaffolded Go & Node projects pass native toolchain checks!
            go_bin = shutil.which("go", path=env["PATH"])
            if go_bin:
                subprocess.run(
                    [go_bin, "vet", "./..."],
                    cwd=str(tmp_root / "agent-go"),
                    env=env,
                    check=True,
                    capture_output=True,
                )
            node_bin = shutil.which("node", path=env["PATH"])
            if node_bin:
                subprocess.run(
                    [node_bin, "--check", "example_agent.mjs"],
                    cwd=str(tmp_root / "agent-node"),
                    env=env,
                    check=True,
                    capture_output=True,
                )
                # Verify Node.js length-hiding `verifyLoopbackHeader` & short-secret rejection (`[MEDIUM-M5-02]`)
                node_eval = (
                    "import('./lct_sdk.mjs').then(m => {"
                    "  if (!m.verifyLoopbackHeader('a'.repeat(32), 'a'.repeat(32))) process.exit(1);"
                    "  if (m.verifyLoopbackHeader('short', 'a'.repeat(32))) process.exit(1);"
                    "  if (m.verifyLoopbackHeader('', 'a'.repeat(32))) process.exit(1);"
                    "});"
                )
                subprocess.run(
                    [node_bin, "-e", node_eval],
                    cwd=str(tmp_root / "agent-node"),
                    env=env,
                    check=True,
                    capture_output=True,
                )

            # Negative input validation tests on `configure_agent_lang.sh` (`[LOW-M5-01]`)
            bad_cases = [
                ["--lang", "go", "--target", str(tmp_root / "bad1"), "--name", "BAD_UPPER_NAME"],
                ["--lang", "go", "--target", str(tmp_root / "bad2"), "--name", "-leading-dash"],
                ["--lang", "go", "--target", str(tmp_root / "bad3"), "--skill", "bad skill;inject"],
                ["--lang", "go", "--target", str(tmp_root / "bad4"), "--nodeport", "29999"],
                ["--lang", "go", "--target", str(tmp_root / "bad5"), "--nodeport", "32768"],
                ["--lang", "go", "--target", str(tmp_root / "bad6"), "--nodeport", "not-an-int"],
            ]
            for bad_args in bad_cases:
                bad_res = subprocess.run(
                    ["bash", str(scripts_dir / "configure_agent_lang.sh"), *bad_args],
                    env=env,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(bad_res.returncode, 2, f"Expected exit 2 for {bad_args}")

            # Verify `lineage/pyproject.toml` PEP 621 + `package-dir = {"lineage" = "."}` (`[MEDIUM-M5-03]`)
            pyproject_data = tomllib.loads(
                (lineage_dir / "pyproject.toml").read_text(encoding="utf-8")
            )
            self.assertEqual(pyproject_data["project"]["name"], "lineage-lct")
            st_cfg = pyproject_data["tool"]["setuptools"]
            self.assertNotIn("packages.find", st_cfg)
            self.assertEqual(st_cfg["package-dir"], {"lineage": "."})
            declared_pkgs = set(st_cfg["packages"])
            actual_pkgs = {"lineage"}
            for init_py in lineage_dir.rglob("__init__.py"):
                rel_parts = init_py.parent.relative_to(lineage_dir).parts
                if not rel_parts or rel_parts[0] == "reviews":
                    continue
                actual_pkgs.add("lineage." + ".".join(rel_parts))
            self.assertEqual(declared_pkgs, actual_pkgs)

            if (
                importlib.util.find_spec("setuptools") is not None
                and importlib.util.find_spec("wheel") is not None
            ):
                wheel_dir = tmp_root / "wheels"
                wheel_dir.mkdir()
                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "pip",
                        "wheel",
                        "--no-deps",
                        "--no-build-isolation",
                        str(lineage_dir),
                        "-w",
                        str(wheel_dir),
                    ],
                    env=env,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                wheels = list(wheel_dir.glob("lineage_lct-*.whl"))
                self.assertEqual(len(wheels), 1)
                with zipfile.ZipFile(wheels[0], "r") as zf:
                    names = set(zf.namelist())
                    self.assertIn("lineage/__init__.py", names)
                    self.assertIn("lineage/sidecar/proxy.py", names)
                    self.assertIn("lineage/sdk/python/lct_sdk.py", names)

        # Verify Python SDK short `LCT_LOOPBACK_SECRET` rejection & length-hiding check (`[MEDIUM-M5-02]`)
        prev_inline = os.environ.get("LCT_LOOPBACK_SECRET")
        try:
            os.environ["LCT_LOOPBACK_SECRET"] = "too-short"
            with self.assertRaises(ValueError):
                load_loopback_secret()
        finally:
            if prev_inline is None:
                os.environ.pop("LCT_LOOPBACK_SECRET", None)
            else:
                os.environ["LCT_LOOPBACK_SECRET"] = prev_inline
        self.assertTrue(verify_loopback_secret("x" * 32, "x" * 32))
        self.assertFalse(verify_loopback_secret("short", "x" * 32))
        self.assertFalse(verify_loopback_secret("", "x" * 32))

        # 3. Verify `setup_deps.sh --check` succeeds cleanly
        chk = subprocess.run(
            ["bash", str(scripts_dir / "setup_deps.sh"), "--check"],
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("LCT Dependency & Polyglot Toolchain Status Report", chk.stdout)

        # 4. Verify `push_to_github.sh --dry-run` (both `workspace` and `lineage-only` scopes)
        for scope in ("workspace", "lineage-only"):
            dry = subprocess.run(
                [
                    "bash",
                    str(scripts_dir / "push_to_github.sh"),
                    "--scope",
                    scope,
                    "--dry-run",
                ],
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("Secret Audit  : PASS", dry.stdout)
            self.assertIn("0 symlinks; 0 files > 50 MB", dry.stdout)
            self.assertIn("0 raw JWTs", dry.stdout)
            self.assertIn(".tools/ (0 staged), src/ (0 staged)", dry.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
