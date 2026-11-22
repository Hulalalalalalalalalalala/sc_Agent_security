"""Milestone 2 Final QA Sign-Off Verification Suite (`qa_milestone2_signoff.py`).

Author : `k8s-qa-reviewer` (Independent Read-Only Code Quality & System Compliance Session)
Purpose: Positive end-to-end & boundary sign-off verification confirming all 6 Round-1 findings
         (`CRITICAL-M2-01`, `HIGH-M2-01`, `HIGH-M2-02`, `MEDIUM-M2-01`, `MEDIUM-M2-02`, `LOW-M2-01`)
         are remediated across code, Kubernetes manifests, live `kind-agent-identity-lab` Pods,
         host Ollama (`qwen2.5:3b`), and run evidence `lineage/k8s/runs/20261118T153149Z/`.
"""

from __future__ import annotations

import glob
import json
import os
import subprocess
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import patch

import httpx
import yaml

from lineage.agents.mcp_servers import PaymentVaultMCPApp, TravelOpsMCPApp
from lineage.agents.ollama_client import OllamaClient, OllamaError, _extract_json_object
from lineage.agents.specialist_apps import (
    FlightSpecialistApp,
    HotelSpecialistApp,
    OrchestratorAlphaApp,
    SettlementConvergerApp,
    _validate_sync_hook_url,
)
from lineage.audit import (
    AuditCollectorClient,
    AuditCollectorService,
    AuditEventType,
    AuditStreamEmitter,
    CausalChainAuditor,
)
from lineage.common.crypto import KeyPair, jws_sign_compact, redact_sensitive
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.k8s.bootstrap_services import FederationCAService, create_ca_pop_jws
from lineage.protocol import PermissionLattice, create_dpop_proof, mint_root_token
from lineage.registry import AgentCard, AgentDirectoryClient, AgentDirectoryService
from lineage.resilience.coordinator import ResilientDelegationCoordinator
from lineage.resilience.receipts import FailureEvidence, FaultType, ResilienceError, SkipLevelReceipt
from lineage.revocation import RevocationReplicaClient, RevocationService
from lineage.sidecar import LineageSidecar
from lineage.verifier import VerificationMode

REPO_ROOT = Path("/Users/hulalala/Desktop/A")
RUN_DIR_R2 = REPO_ROOT / "lineage/k8s/runs/20261118T153149Z"
MANIFEST_CTRL = REPO_ROOT / "lineage/k8s/manifests/01-control-plane.yaml"
MANIFEST_DP = REPO_ROOT / "lineage/k8s/manifests/02-data-plane-agents-and-mcp.yaml"


def _k8s_env() -> Dict[str, str]:
    env = os.environ.copy()
    env["PATH"] = f"{REPO_ROOT}/.tools/bin:{os.path.expanduser('~/.docker/bin')}:{env.get('PATH', '')}"
    return env


class _StubSignoffOllama(OllamaClient):
    """Fast deterministic in-process LLM helper for protocol boundary tests."""

    def __init__(self) -> None:
        super().__init__(base_url="http://127.0.0.1:9/v1", model="qwen2.5:3b")
        self.seen_text_sys_prompts: List[str] = []

    def chat_json(self, system_prompt: str, user_prompt: str, **_: Any) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        meta = {"model": "qwen2.5:3b", "completion_id": "chatcmpl-signoff", "system_fingerprint": "fp_ollama"}
        if "audit_tag" in system_prompt:
            return {"audit_tag": "AUDIT-SIGNOFF"}, meta
        return {"city": "Tokyo", "flight_budget_usd": 650.0, "hotel_budget_usd": 420.0}, meta

    def chat_tool_call(
        self, system_prompt: str, user_prompt: str, tools_schema: List[Dict[str, Any]], **_: Any
    ) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        fn = tools_schema[0]["function"]["name"]
        meta = {"model": "qwen2.5:3b", "completion_id": f"chatcmpl-{fn}", "system_fingerprint": "fp_ollama"}
        if fn in ("search_flight", "search_hotel"):
            return fn, {"city": "Tokyo"}, meta
        if fn == "book_flight":
            return fn, {"city": "Tokyo", "flight_no": "NH-108", "amount": 580.0}, meta
        return fn, {"city": "Tokyo", "hotel_id": "HTL-TYO-09", "amount": 360.0}, meta

    def chat_text(self, system_prompt: str, user_prompt: str, **_: Any) -> Tuple[str, Dict[str, Any]]:
        self.seen_text_sys_prompts.append(system_prompt)
        return "Confirmed NH-108 (580 USD) and HTL-TYO-09 (360 USD).", {
            "model": "qwen2.5:3b",
            "completion_id": "chatcmpl-synth",
        }


class TestMilestone2FinalSignoff(unittest.TestCase):
    """All-green sign-off tests verifying remediation of all 6 Round-1 findings."""

    # -------------------------------------------------------------------------
    # 1. Baseline Preservation, Prior Reviews Integrity & Run Evidence Audit
    # -------------------------------------------------------------------------
    def test_01_baseline_prior_reviews_and_r2_evidence_compliance(self) -> None:
        lineage_init_mtime = (REPO_ROOT / "lineage/__init__.py").stat().st_mtime
        touched: List[str] = []
        for target in (REPO_ROOT / "README.md", REPO_ROOT / "lab", REPO_ROOT / "src"):
            if target.is_file():
                if target.stat().st_mtime > lineage_init_mtime:
                    touched.append(str(target))
            else:
                for r, _, files in os.walk(target):
                    for fn in files:
                        fp = Path(r) / fn
                        if fp.stat().st_mtime > lineage_init_mtime:
                            touched.append(str(fp))
        self.assertEqual(touched, [], f"Baseline files unexpectedly modified: {touched}")

        # Verify Round-1 QA files remain intact
        self.assertTrue((REPO_ROOT / "lineage/reviews/MILESTONE2_QA_REPORT.md").is_file())
        self.assertTrue((REPO_ROOT / "lineage/reviews/qa_milestone2_review.py").is_file())

        # Verify new E2E evidence directory `20261118T153149Z`
        self.assertTrue(RUN_DIR_R2.is_dir())
        files = sorted(glob.glob(str(RUN_DIR_R2 / "*")))
        self.assertGreaterEqual(len(files), 15)

        for f_str in files:
            txt = Path(f_str).read_text(encoding="utf-8", errors="replace")
            self.assertNotRegex(txt, r"BEGIN [A-Z ]*PRIVATE KEY")
            self.assertNotRegex(txt, r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
            self.assertNotRegex(txt, r"\blct(?:m|mp)?1\.[A-Za-z0-9_.-]{10,}")
            self.assertNotRegex(txt, r'"(?:d|p|q|dp|dq|qi)"\s*:\s*"(?!\[REDACTED)[A-Za-z0-9_-]{10,}"')

        # Verify [LOW-M2-01] grounded synthesis quality in Scenario 1 & Scenario 4
        s1 = json.loads((RUN_DIR_R2 / "scenario1_normal_dag.json").read_text("utf-8"))
        self.assertEqual(s1["status"], "PASS")
        s1_ans = s1["final_answer"]
        for expected in ("NH-108", "580", "HTL-TYO-09", "360"):
            self.assertIn(expected, s1_ans)
        self.assertNotIn("null flight_booking", s1_ans.lower())
        self.assertNotIn("not executed", s1_ans.lower())

        s4 = json.loads((RUN_DIR_R2 / "scenario4_fagin_degradation_and_isolation.json").read_text("utf-8"))
        self.assertEqual(s4["status"], "PASS")
        self.assertIn("360", s4["alice_degraded_llm_answer"])
        self.assertNotIn("580", s4["alice_degraded_llm_answer"])
        self.assertNotIn("only the hotel", s4["carol_final_answer"].lower())

        s5 = json.loads((RUN_DIR_R2 / "scenario5_causal_audit_report.json").read_text("utf-8"))
        self.assertTrue(s5["clean"])
        self.assertTrue(s5["stream_hash_chain_integrity_ok"])
        self.assertEqual(s5["reconstruction_rate_pct"], 100.0)

    # -------------------------------------------------------------------------
    # 2. Live K8s Cluster Verification (`[HIGH-M2-01]`, `[HIGH-M2-02]`, `[MEDIUM-M2-01]`)
    # -------------------------------------------------------------------------
    def test_02_live_k8s_zero_app_sa_token_projected_aud_and_incluster_guards(self) -> None:
        env = _k8s_env()

        # 1. Verify `team1` remains 3/3 `2/2 Running`
        r_t1 = subprocess.run(
            ["kubectl", "--context", "kind-agent-identity-lab", "get", "pods", "-n", "team1", "--no-headers"],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(r_t1.returncode, 0, r_t1.stderr)
        t1_lines = [ln for ln in r_t1.stdout.strip().splitlines() if ln.strip()]
        self.assertEqual(len(t1_lines), 3)
        for ln in t1_lines:
            self.assertIn("2/2", ln)
            self.assertIn("Running", ln)

        # 2. Verify manifests set `automountServiceAccountToken: false` on all 12 Deployments
        all_deps = [
            d
            for f in (MANIFEST_CTRL, MANIFEST_DP)
            for d in yaml.safe_load_all(f.read_text("utf-8"))
            if d and d.get("kind") == "Deployment"
        ]
        self.assertEqual(len(all_deps), 12)
        for dep in all_deps:
            self.assertIs(dep["spec"]["template"]["spec"].get("automountServiceAccountToken"), False)

        # 3. Verify all 7 live `2/2` Pods have ZERO SA tokens inside `app` and `aud=['lct-federation-ca']` inside `lct-sidecar`
        targets = [
            ("lineage-alpha", "orchestrator-alpha"),
            ("lineage-beta", "flight-specialist"),
            ("lineage-beta", "hotel-specialist-primary"),
            ("lineage-beta", "hotel-specialist-backup"),
            ("lineage-pay", "settlement-converger"),
            ("lineage-pay", "travel-ops-mcp"),
            ("lineage-pay", "payment-vault-mcp"),
        ]
        for ns, app_label in targets:
            pod_name = subprocess.check_output(
                [
                    "kubectl", "--context", "kind-agent-identity-lab",
                    "-n", ns, "get", "pod", "-l", f"app={app_label}",
                    "-o", "jsonpath={.items[0].metadata.name}",
                ],
                env=env,
                text=True,
                timeout=10,
            ).strip()
            app_check = subprocess.check_output(
                [
                    "kubectl", "--context", "kind-agent-identity-lab",
                    "-n", ns, "exec", pod_name, "-c", "app", "--",
                    "/app/.venv/bin/python3", "-c",
                    "import json, os; print(json.dumps({'def': os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount/token'), 'proj': os.path.exists('/var/run/lct-sa/token'), 'loop': os.path.exists('/var/run/lct-loopback/secret')}))",
                ],
                env=env,
                text=True,
                timeout=10,
            ).strip()
            parsed_app = json.loads(app_check)
            self.assertFalse(parsed_app["def"], f"{ns}/{pod_name} app has default SA token!")
            self.assertFalse(parsed_app["proj"], f"{ns}/{pod_name} app has projected SA token!")
            self.assertTrue(parsed_app["loop"])

            sc_check = subprocess.check_output(
                [
                    "kubectl", "--context", "kind-agent-identity-lab",
                    "-n", ns, "exec", pod_name, "-c", "lct-sidecar", "--",
                    "/app/.venv/bin/python3", "-c",
                    "import json; from lineage.common.crypto import jws_parse_unverified; _, c, _, _ = jws_parse_unverified(open('/var/run/lct-sa/token').read().strip()); print(json.dumps({'iss': c.get('iss'), 'aud': c.get('aud'), 'ttl': c.get('exp',0)-c.get('iat',0)}))",
                ],
                env=env,
                text=True,
                timeout=10,
            ).strip()
            parsed_sc = json.loads(sc_check)
            self.assertEqual(parsed_sc["iss"], "https://kubernetes.default.svc.cluster.local")
            self.assertEqual(parsed_sc["aud"], ["lct-federation-ca"])
            self.assertLessEqual(parsed_sc["ttl"], 1805)

        # 4. Live read-only HTTP boundary probes from inside `e2e-user-gateway` Pod against live services
        gw_pod = subprocess.check_output(
            [
                "kubectl", "--context", "kind-agent-identity-lab",
                "-n", "lineage-alpha", "get", "pod", "-l", "app=e2e-user-gateway",
                "-o", "jsonpath={.items[0].metadata.name}",
            ],
            env=env,
            text=True,
            timeout=10,
        ).strip()
        live_probe_out = subprocess.check_output(
            [
                "kubectl", "--context", "kind-agent-identity-lab",
                "-n", "lineage-alpha", "exec", gw_pod, "--",
                "/app/.venv/bin/python3", "-c",
                """
import json, httpx
from lineage.common.crypto import KeyPair
sa_jwt = open('/var/run/lct-sa/token').read().strip()
kp = KeyPair.generate('ES256')
# 1) Unauthenticated GET /v1/audit/entries -> 401
r_aud = httpx.get('http://audit-collector.lineage-ctrl.svc.cluster.local:8093/v1/audit/entries', timeout=5.0)
# 2) /v1/ca/issue-workload missing pop_jws -> 400
r_nopop = httpx.post('http://federation-ca.lineage-ctrl.svc.cluster.local:8090/v1/ca/issue-workload',
    json={'public_jwk': kp.public_jwk()}, headers={'Authorization': f'Bearer {sa_jwt}'}, timeout=5.0)
# 3) /v1/ca/mint-root-token cross-domain -> 403
r_xdom = httpx.post('http://federation-ca.lineage-ctrl.svc.cluster.local:8090/v1/ca/mint-root-token',
    json={'trust_domain': 'org-payment.io'}, headers={'Authorization': f'Bearer {sa_jwt}'}, timeout=5.0)
print(json.dumps({'anon_audit': r_aud.status_code, 'no_pop': r_nopop.status_code, 'cross_dom': r_xdom.status_code}))
""",
            ],
            env=env,
            text=True,
            timeout=15,
        ).strip()
        live_codes = json.loads(live_probe_out)
        self.assertEqual(live_codes["anon_audit"], 401)
        self.assertEqual(live_codes["no_pop"], 400)
        self.assertEqual(live_codes["cross_dom"], 403)

    # -------------------------------------------------------------------------
    # 3. `FederationCAService` Full Claims, PoP Replay, TTL & Revocation Proof (`[HIGH-M2-02]`)
    # -------------------------------------------------------------------------
    def test_03_federation_ca_strict_claims_pop_ttl_and_revocation_proof(self) -> None:
        oidc_kp = KeyPair.generate("RS256", kid="k8s-rs256-signoff")
        tmp_ca = TrustDomainCA("org-tmp.io")
        res = TrustBundleResolver()
        res.register_domain_ca(tmp_ca)
        collector = AuditCollectorService(res, host="127.0.0.1", port=0)
        col_url = collector.start()

        ca_svc = FederationCAService(audit_collector_url=col_url, host="127.0.0.1", port=0)
        collector.trust_resolver.register_federation(ca_svc.resolver.export_federation_bundles())
        ca_svc.k8s_verifier._keys_by_kid = {oidc_kp.kid: oidc_kp.public_jwk()}
        ca_svc.k8s_verifier._last_refresh = time.time() + 600.0
        base = ca_svc.http.start()

        try:
            now = time.time()
            wl_kp = KeyPair.generate("ES256")

            def _sa(ns: str, sa: str, **overrides: Any) -> str:
                claims: Dict[str, Any] = {
                    "iss": "https://kubernetes.default.svc.cluster.local",
                    "aud": ["lct-federation-ca"],
                    "sub": f"system:serviceaccount:{ns}:{sa}",
                    "iat": now,
                    "nbf": now,
                    "exp": now + 900.0,
                }
                claims.update(overrides)
                if overrides.get("exp", "KEEP") is None:
                    claims.pop("exp", None)
                return jws_sign_compact(claims, oidc_kp)

            # Reject bad iss, bad aud, missing exp, NaN/Inf exp, future iat/nbf
            for bad_tok in (
                _sa("lineage-beta", "flight-specialist", iss="https://evil.example"),
                _sa("lineage-beta", "flight-specialist", aud=["https://kubernetes.default.svc.cluster.local"]),
                _sa("lineage-beta", "flight-specialist", exp=None),
                _sa("lineage-beta", "flight-specialist", exp="nan"),
                _sa("lineage-beta", "flight-specialist", exp="inf"),
                _sa("lineage-beta", "flight-specialist", iat=now + 120.0),
                _sa("lineage-beta", "flight-specialist", nbf=now + 120.0),
            ):
                r = httpx.post(
                    f"{base}/v1/ca/issue-workload",
                    json={"public_jwk": wl_kp.public_jwk(), "pop_jws": create_ca_pop_jws(wl_kp, bad_tok)},
                    headers={"Authorization": f"Bearer {bad_tok}"},
                )
                self.assertEqual(r.status_code, 403)

            good_sa = _sa("lineage-beta", "flight-specialist")
            pop = create_ca_pop_jws(wl_kp, good_sa)
            r_ok = httpx.post(
                f"{base}/v1/ca/issue-workload",
                json={"public_jwk": wl_kp.public_jwk(), "pop_jws": pop, "ttl_seconds": 1800.0},
                headers={"Authorization": f"Bearer {good_sa}"},
            )
            self.assertEqual(r_ok.status_code, 200)
            self.assertLessEqual(r_ok.json()["expires_at"] - r_ok.json()["issued_at"], 935.0)

            # Replay of exact same PoP JWS blocked (400)
            r_rep = httpx.post(
                f"{base}/v1/ca/issue-workload",
                json={"public_jwk": wl_kp.public_jwk(), "pop_jws": pop, "ttl_seconds": 600.0},
                headers={"Authorization": f"Bearer {good_sa}"},
            )
            self.assertEqual(r_rep.status_code, 400)

            # Out-of-bounds / non-finite TTL -> 400 (never 500)
            for bad_ttl in ("nan", "inf", 0.0, -10.0, 999999.0):
                r_t = httpx.post(
                    f"{base}/v1/ca/issue-workload",
                    json={
                        "public_jwk": wl_kp.public_jwk(),
                        "pop_jws": create_ca_pop_jws(wl_kp, good_sa),
                        "ttl_seconds": bad_ttl,
                    },
                    headers={"Authorization": f"Bearer {good_sa}"},
                )
                self.assertEqual(r_t.status_code, 400)

            # Cross-domain root minting & forged revocation audit blocked
            gw_sa = _sa("lineage-alpha", "e2e-user-gateway")
            self.assertEqual(
                httpx.post(
                    f"{base}/v1/ca/mint-root-token",
                    json={"trust_domain": "org-beta.io"},
                    headers={"Authorization": f"Bearer {gw_sa}"},
                ).status_code,
                403,
            )
            self.assertEqual(
                httpx.post(
                    f"{base}/v1/ca/emit-revocation-audit",
                    json={"trust_domain": "org-alpha.io", "task_id": "t1", "revocation_event": {"fake": 1}},
                    headers={"Authorization": f"Bearer {gw_sa}"},
                ).status_code,
                403,
            )
        finally:
            ca_svc.http.stop()
            collector.stop()

    # -------------------------------------------------------------------------
    # 4. Public A2A Hardening, Outbound Smuggling Block & Audit Auth (`CRITICAL/MEDIUM/LOW`)
    # -------------------------------------------------------------------------
    def test_04_public_a2a_hardening_tenant_isolation_and_outbound_smuggling_block(self) -> None:
        # Verify `_validate_sync_hook_url` blocks Ollama `:11434`, control-plane `:8090`, external IPs, and loopback
        for bad_hook in (
            "http://host.docker.internal:11434/api/delete",
            "http://federation-ca.lineage-ctrl.svc.cluster.local:8090/v1/ca/bundles",
            "http://10.244.0.167:8080/sync",
            "http://10.244.0.167:19090/other",
            "http://127.0.0.1:19090/sync",
            "http://192.168.1.10:19090/sync",
        ):
            with self.assertRaises(ValueError):
                _validate_sync_hook_url(bad_hook)
        self.assertEqual(
            _validate_sync_hook_url("http://10.244.0.167:19090/sync"),
            "http://10.244.0.167:19090/sync",
        )

        # Verify `_extract_json_object` raises `OllamaError` on malformed JSON inside braces
        with self.assertRaises(OllamaError):
            _extract_json_object("model note {broken_json: true}")

        # Verify `redact_sensitive` scrubs `compact_lineage_token` and `lct1.`/`lctm1.` values
        red = redact_sensitive({"compact_lineage_token": "lct1.abc.def", "arr": ["lct1.xyz", "lctm1.uvw"]})
        self.assertEqual(red["compact_lineage_token"], "[REDACTED]")
        self.assertTrue(red["arr"][0].startswith("[REDACTED_LCT_TOKEN_SHA256:"))
        self.assertTrue(red["arr"][1].startswith("[REDACTED_LCT_TOKEN_SHA256:"))

        # Spin up full multi-domain topology and verify default-off hooks, tenant isolation, and outbound guard
        ca_a = TrustDomainCA("org-alpha.io")
        ca_b = TrustDomainCA("org-beta.io")
        ca_p = TrustDomainCA("org-payment.io")
        resolver = TrustBundleResolver()
        for c in (ca_a, ca_b, ca_p):
            resolver.register_domain_ca(c)

        rev_id = ca_a.issue_workload("/ns/sys/sa/revocation")
        rev_svc = RevocationService(rev_id, resolver, host="127.0.0.1", port=0)
        rev_url = rev_svc.start()
        collector = AuditCollectorService(resolver, host="127.0.0.1", port=0)
        aud_url = collector.start()
        dir_svc = AgentDirectoryService(
            resolver, revocation_replica=RevocationReplicaClient(rev_url, resolver), host="127.0.0.1", port=0
        )
        dir_url = dir_svc.start()

        sink_hits: List[str] = []
        sink_srv = ManagedHTTPService(
            "sink", lambda req: (sink_hits.append(req.path) or 200, {"ok": True}, {}), host="127.0.0.1", port=0
        )
        sink_url = sink_srv.start()
        stub = _StubSignoffOllama()
        stops: List[Any] = [rev_svc, collector, dir_svc, sink_srv]

        def _node(ca: TrustDomainCA, path: str, skill: str, prio: int, mk_app: Any) -> Tuple[Any, LineageSidecar, AgentCard]:
            sec = f"sec-{path.replace('/', '-')}-signoff-256b"
            wl = ca.issue_workload(path)
            sc = LineageSidecar(
                identity=wl,
                trust_resolver=resolver,
                app_upstream_url="http://127.0.0.1:9",
                loopback_secret=sec,
                revocation_replica=RevocationReplicaClient(rev_url, resolver),
                directory_client=AgentDirectoryClient(dir_url, resolver),
                audit_emitter=AuditStreamEmitter(wl, AuditCollectorClient(aud_url), stream_id=f"{wl.spiffe_id}#s"),
                is_tool_server=(skill == ""),
            )
            in_u, out_u = sc.start()
            app = mk_app(sec, out_u)
            sc.app_upstream_url = app.start().rstrip("/")
            stops.extend([sc, app])
            card = None
            if skill:
                card = AgentCard.sign_and_create(
                    identity=wl,
                    name=path,
                    endpoint=in_u,
                    return_endpoint=in_u,
                    skills=[skill],
                    priority=prio,
                )
                sc.set_agent_card(card)
                AgentDirectoryClient(dir_url, resolver).register(card)
            return app, sc, card  # type: ignore[return-value]

        try:
            t_app, t_sc, _ = _node(ca_p, "/ns/lineage-pay/sa/travel-ops-mcp", "", 10, lambda s, _: TravelOpsMCPApp(s, 0))
            p_app, p_sc, _ = _node(ca_p, "/ns/lineage-pay/sa/payment-vault-mcp", "", 10, lambda s, _: PaymentVaultMCPApp(s, 0))
            _, f_sc, _ = _node(ca_b, "/ns/lineage-beta/sa/flight-specialist", "travel.flight", 10, lambda s, o: FlightSpecialistApp(s, o, f"{t_sc.inbound_url}/mcp", stub, 0))
            h1_app, h1_sc, _ = _node(ca_b, "/ns/lineage-beta/sa/hotel-specialist-primary", "travel.hotel", 10, lambda s, o: HotelSpecialistApp(s, o, f"{t_sc.inbound_url}/mcp", "primary", stub, 0))
            _, h2_sc, _ = _node(ca_b, "/ns/lineage-beta/sa/hotel-specialist-backup", "travel.hotel", 20, lambda s, o: HotelSpecialistApp(s, o, f"{t_sc.inbound_url}/mcp", "backup", stub, 0))
            _, c_sc, _ = _node(ca_p, "/ns/lineage-pay/sa/settlement-converger", "settlement.converge", 10, lambda s, o: SettlementConvergerApp(s, o, f"{p_sc.inbound_url}/mcp", stub, 0))
            _, o_sc, o_card = _node(ca_a, "/ns/lineage-alpha/sa/orchestrator-alpha", "travel.orchestrate", 10, lambda s, o: OrchestratorAlphaApp(s, o, stub, 0))

            gw = ca_a.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
            perms = PermissionLattice.create(
                tools=["search_flight", "book_flight", "search_hotel", "reserve_hotel", "execute_settlement", "record_itinerary_audit"],
                max_amount=800.0,
                allowed_targets=["airline-escrow", "hotel-escrow", "audit-ledger"],
                param_whitelist={"city": ["Tokyo"]},
                max_calls=12,
            )
            tok_alice = mint_root_token(
                ca_a,
                task_id="task-signoff-alice",
                sub="user:alice@org-alpha.io",
                sender_jkt=gw.jkt,
                first_hop_spiffe_id=o_card.spiffe_id,
                first_hop_jkt=o_card.jkt,
                permissions=perms,
                first_hop_public_jwk=o_card.public_jwk,
                first_hop_return_endpoint=o_card.return_endpoint,
            )

            def _call_orch(tok_obj: Any, body: Dict[str, Any], path: str = "/a2a/task") -> httpx.Response:
                ct = tok_obj.encode_compact()
                u = f"{o_sc.inbound_url}{path}"
                return httpx.post(
                    u,
                    json=body,
                    headers={"Authorization": f"DPoP {ct}", "DPoP": create_dpop_proof(gw, "POST", u, ct)},
                    timeout=15.0,
                )

            # Default (`LCT_ENABLE_FAULT_INJECTION` unset/false): all debug hooks rejected with 403/400
            with patch.dict(os.environ, {"LCT_ENABLE_FAULT_INJECTION": "false"}, clear=False):
                self.assertEqual(_call_orch(tok_alice, {}, path="/a2a/other").status_code, 404)
                self.assertEqual(
                    _call_orch(tok_alice, {"op": "delegate_upward_return_chain", "override_direct_parent_url": sink_url}).status_code,
                    403,
                )
                self.assertEqual(
                    _call_orch(tok_alice, {"op": "delegate_upward_return_chain", "simulate_direct_parent_unreachable": True}).status_code,
                    403,
                )
                self.assertEqual(
                    _call_orch(tok_alice, {"op": "plan_and_execute_trip", "simulate_primary_zombie_delay_sec": 3.0}).status_code,
                    403,
                )
                self.assertEqual(
                    _call_orch(tok_alice, {"op": "plan_and_execute_trip", "simulate_primary_zombie_delay_sec": "inf"}).status_code,
                    400,
                )

            # Enabled (`LCT_ENABLE_FAULT_INJECTION=true`): `override_direct_parent_url` still 400,
            # `zombie_delay < hotel_timeout + 0.5` blocked with 400 (zero double-booking!),
            # and `inspect_inbox` enforces per-`sub` tenant isolation + redacts `compact_lineage_token`!
            with patch.dict(os.environ, {"LCT_ENABLE_FAULT_INJECTION": "true"}, clear=False):
                self.assertEqual(
                    _call_orch(tok_alice, {"op": "delegate_upward_return_chain", "override_direct_parent_url": sink_url}).status_code,
                    400,
                )
                self.assertEqual(
                    _call_orch(
                        tok_alice,
                        {"op": "plan_and_execute_trip", "hotel_timeout_sec": 10.0, "simulate_primary_zombie_delay_sec": 0.05},
                    ).status_code,
                    400,
                )
                self.assertEqual(sink_hits, [])

                # Record a genuine SkipLevelReceipt for Alice, then verify Bob sees `[]` while Alice sees redacted token
                t_b2 = tok_alice.attenuate(
                    issuer_identity=o_sc.identity,
                    delegate_spiffe_id=h1_sc.identity.spiffe_id,
                    delegate_jkt=h1_sc.identity.jkt,
                    permissions=perms,
                    hop_segment="H1",
                    issuer_return_endpoint=o_sc.inbound_url,
                )
                t_leaf = t_b2.attenuate(
                    issuer_identity=h1_sc.identity,
                    delegate_spiffe_id=c_sc.identity.spiffe_id,
                    delegate_jkt=c_sc.identity.jkt,
                    permissions=perms,
                    hop_segment="C",
                    issuer_return_endpoint=h1_sc.inbound_url,
                )
                h1_old = h1_sc.inbound_url
                h1_sc._inbound_http.stop()
                sr = SkipLevelReceipt.create_and_sign(
                    child_identity=c_sc.identity,
                    lineage_token=t_leaf,
                    skipped_ancestors=[h1_sc.identity.spiffe_id],
                    target_ancestor_spiffe_id=o_sc.identity.spiffe_id,
                    failure_evidence=FailureEvidence(
                        h1_sc.identity.spiffe_id, h1_old, FaultType.CRASH, "down", 1, time.time()
                    ),
                    result_payload={"secret_note": "ALICE-ONLY-777"},
                )
                c_leaf = t_leaf.encode_compact()
                r_sk = httpx.post(
                    f"{o_sc.inbound_url}/v1/skip-level-return",
                    json={"skip_level_receipt": sr.to_dict()},
                    headers={
                        "Authorization": f"DPoP {c_leaf}",
                        "DPoP": create_dpop_proof(c_sc.identity, "POST", f"{o_sc.inbound_url}/v1/skip-level-return", c_leaf),
                    },
                )
                self.assertEqual(r_sk.status_code, 200)

                tok_bob = mint_root_token(
                    ca_a,
                    task_id="task-signoff-bob",
                    sub="user:bob@org-alpha.io",
                    sender_jkt=gw.jkt,
                    first_hop_spiffe_id=o_card.spiffe_id,
                    first_hop_jkt=o_card.jkt,
                    permissions=perms,
                )
                r_bob = _call_orch(tok_bob, {"op": "inspect_inbox", "inspect_task_id": "task-signoff-alice"})
                self.assertEqual(r_bob.status_code, 200)
                self.assertEqual(r_bob.json()["skip_level_results"], [])

                r_alice_in = _call_orch(tok_alice, {"op": "inspect_inbox", "inspect_task_id": "task-signoff-alice"})
                self.assertEqual(r_alice_in.status_code, 200)
                self.assertEqual(r_alice_in.json()["skip_level_results"][0]["compact_lineage_token"], "[REDACTED]")
                self.assertNotIn("lct1.", r_alice_in.text)

            # AuditCollectorService: unauthenticated -> 401, non-auditor agent -> 403, authorized gateway -> 200
            self.assertEqual(httpx.get(f"{aud_url}/v1/audit/entries").status_code, 401)
            with self.assertRaises(httpx.HTTPStatusError) as e_info:
                AuditCollectorClient(aud_url, signer=f_sc.identity).fetch_entries()
            self.assertEqual(e_info.exception.response.status_code, 403)
            self.assertIsInstance(AuditCollectorClient(aud_url, signer=gw).fetch_entries(), list)

            # Outbound proxy `@host` authority smuggling blocked (400) & zero sink hits
            act = o_sc.active_requests.register(
                compact_token=tok_alice.encode_compact(),
                parsed_token=tok_alice,
                verification=o_sc.verifier.verify_request(
                    compact_token=tok_alice.encode_compact(),
                    dpop_proof=create_dpop_proof(gw, "POST", f"{o_sc.inbound_url}/a2a/task", tok_alice.encode_compact()),
                    htm="POST",
                    htu=f"{o_sc.inbound_url}/a2a/task",
                    check_invocation_lattice=False,
                ),
            )
            try:
                r_smug = httpx.post(
                    f"{o_sc.outbound_url}/v1/proxy/call",
                    headers={"X-LCT-Loopback-Auth": o_sc.loopback_secret},
                    json={
                        "action": "delegate_agent",
                        "request_id": act.request_id,
                        "required_skill": "travel.flight",
                        "task_path": f"@127.0.0.1:{sink_srv.port}/smuggled",
                    },
                )
                self.assertEqual(r_smug.status_code, 400)
                self.assertEqual(sink_hits, [])
            finally:
                o_sc.active_requests.release(act.request_id)

            # MCP positive finite amount checks
            for invalid_amt in (0.0, -10.0, True):
                r_m = httpx.post(
                    f"{t_app.http.base_url}/mcp",
                    headers={"X-LCT-Loopback-Auth": t_app.loopback_secret},
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "book_flight", "arguments": {"city": "Tokyo", "amount": invalid_amt}}},
                )
                self.assertEqual(r_m.status_code, 400)
        finally:
            for s in reversed(stops):
                try:
                    s.stop()
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
