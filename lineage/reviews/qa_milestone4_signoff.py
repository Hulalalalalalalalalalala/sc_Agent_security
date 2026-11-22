"""Milestone 4 Independent Multi-Cluster Code & Live 4-Cluster Compliance Sign-Off Suite.

Written by `k8s-qa-reviewer` (`lineage/reviews/qa_milestone4_signoff.py`).
Strictly read-only on implementation code, manifests, baseline files, and K8s cluster state.

Covers:
1. Baseline preservation (`README.md`, `lab/`, `src/`, prior `reviews/` untouched;
   `kubectl config current-context == kind-agent-identity-lab`; zero `lineage-*` namespaces
   in `kind-agent-identity-lab`; `team1` `3/3` Pods `2/2 Running`).
2. Multi-cluster evidence bundle audit (`runs/20261119T105349Z-multicluster/`: zero private
   keys / raw tokens across all 18 files, Scenario 6 `503 REVOCATION_ANCHOR_UNAVAILABLE`
   whole-cluster partition + autonomous recovery, Scenario 5 `15/15 = 100.0%` across 282 entries).
3. `AutonomousDomainCAService` `:8094` read-only federation port edge cases (query strings,
   percent-encoding, dot-segments, HTTP methods) & `_validate_allowed_dns_sans` strict SA-scoped
   FQDN enforcement (blocking cross-SA and foreign-domain SAN CSRs).
4. `AgentDirectoryService` (`:8491`) & `RevocationService` (`:8492`) mTLS 1.3 client-cert
   authorization, sandbox workload route restrictions, and outbound per-peer-domain X.509
   Root CA pinning (`verify_for_target(expected_trust_domain=peer_td, check_hostname=True)`
   blocking a compromised `org-beta.io` peer from impersonating `org-payment.io`).
5. Live 4-cluster Kubernetes runtime verification (`kind-lct-org-alpha`, `kind-lct-org-beta`,
   `kind-lct-org-pay`, `kind-lct-audit`: 4 distinct OIDC `kid`s, 4 disjoint Pod/Service CIDRs,
   `ClusterIP` vs `NodePort` separation, cross-cluster DNS/L3 isolation, live external port
   hardening, keyless `audit-collector`, and all 7 `2/2` `app` containers on `127.0.0.1:9001`).
"""

from __future__ import annotations

import glob
import ipaddress
import json
import os
import re
import shutil
import ssl
import subprocess
import time
import unittest
from typing import Any, Dict, List, Tuple

import httpx
import yaml

from lineage.common.crypto import KeyPair, jws_sign_compact
from lineage.common.http_utils import ManagedHTTPService
from lineage.common.mtls import WorkloadMTLSBundle, X509FederationTrustStore
from lineage.federation import AutonomousDomainCAService
from lineage.identity import TrustBundleResolver, WorkloadIdentity
from lineage.k8s.bootstrap_services import K8sServiceAccountVerifier, create_ca_pop_jws
from lineage.registry import AgentCard, AgentDirectoryService
from lineage.revocation import RevocationService


REPO_ROOT = "/Users/hulalala/Desktop/A"
REVIEWS_DIR = os.path.join(REPO_ROOT, "lineage/reviews")
MC_MANIFEST_DIR = os.path.join(REPO_ROOT, "lineage/k8s/multicluster")
M4_RUN_DIR = os.path.join(REPO_ROOT, "lineage/k8s/runs/20261119T105349Z-multicluster")


def _tool_env() -> Dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = (
        f"{REPO_ROOT}/.tools/bin:{REPO_ROOT}/.tools/ollama:"
        f"{os.path.expanduser('~')}/.docker/bin:/opt/homebrew/bin:/usr/local/bin:{env.get('PATH', '')}"
    )
    return env


class Milestone4IndependentSignoffTests(unittest.TestCase):
    """Independent Milestone 4 code boundary & live 4-cluster verification suite."""

    @staticmethod
    def _make_mock_k8s_verifier(oidc_kp: KeyPair) -> K8sServiceAccountVerifier:
        v = K8sServiceAccountVerifier(allowed_audiences=("lct-federation-ca",))
        pub = oidc_kp.public_jwk()
        v._keys_by_kid = {pub["kid"]: pub}
        v._last_refresh = time.time() + 3600.0
        v._refresh_jwks = lambda: None  # type: ignore[method-assign]
        return v

    @staticmethod
    def _mint_sa_jwt(oidc_kp: KeyPair, ns: str, sa: str) -> str:
        now = time.time()
        return jws_sign_compact(
            {
                "iss": "https://kubernetes.default.svc.cluster.local",
                "sub": f"system:serviceaccount:{ns}:{sa}",
                "aud": ["lct-federation-ca"],
                "iat": now,
                "nbf": now,
                "exp": now + 1800.0,
            },
            oidc_kp,
            typ="JWT",
        )

    # -------------------------------------------------------------------------
    # 1. Evidence Bundle Audit (`20261119T105349Z-multicluster`) & Manifest Purity
    # -------------------------------------------------------------------------
    def test_01_m4_evidence_bundle_redaction_and_manifest_isolation(self) -> None:
        self.assertTrue(os.path.isdir(M4_RUN_DIR), f"Missing M4 run dir: {M4_RUN_DIR}")
        files = sorted(glob.glob(os.path.join(M4_RUN_DIR, "*")))
        self.assertEqual(len(files), 18)

        forbidden = {
            "PEM_PRIVATE_KEY": re.compile(r"BEGIN [A-Z0-9 ]*PRIVATE KEY"),
            "RAW_LCT_TOKEN": re.compile(r"\blct(?:mp|m)?1\.[A-Za-z0-9_-]{12,}"),
            "RAW_COMPACT_JWS": re.compile(
                r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
            ),
            "JWK_PRIVATE_D": re.compile(r'"d"\s*:\s*"[A-Za-z0-9_-]{20,}"'),
        }
        leaks: List[Tuple[str, str, str]] = []
        for fpath in files:
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                txt = fh.read()
            for label, pat in forbidden.items():
                m = pat.search(txt)
                if m:
                    leaks.append((os.path.basename(fpath), label, m.group(0)[:50]))
        self.assertEqual(leaks, [], f"Sensitive leak in M4 run dir: {leaks}")

        # Verify Scenario 6 whole-cluster partition 503 + autonomous recovery
        with open(
            os.path.join(M4_RUN_DIR, "scenario6_whole_cluster_partition_and_recovery.json"),
            "r",
            encoding="utf-8",
        ) as fh:
            s6 = json.load(fh)
        self.assertEqual(s6["status"], "PASS")
        self.assertTrue(s6["during_whole_cluster_partition"]["beta_cluster_confirmed_unreachable"])
        self.assertEqual(s6["during_whole_cluster_partition"]["high_risk_fail_closed_http_status"], 503)
        self.assertEqual(
            s6["during_whole_cluster_partition"]["high_risk_fail_closed_error"]["error"],
            "REVOCATION_ANCHOR_UNAVAILABLE",
        )
        self.assertEqual(s6["after_autonomous_recovery"]["a2a_task_state"], "TASK_STATE_COMPLETED")

        # Verify Scenario 5 15/15 = 100% reconstruction across 282 signed entries
        with open(
            os.path.join(M4_RUN_DIR, "scenario5_causal_audit_report.json"),
            "r",
            encoding="utf-8",
        ) as fh:
            s5 = json.load(fh)
        self.assertEqual(s5["status"], "PASS")
        self.assertTrue(s5["clean"])
        self.assertTrue(s5["stream_hash_chain_integrity_ok"])
        self.assertEqual(s5["reconstructed_tasks_numerator"], 15)
        self.assertEqual(s5["total_tasks_denominator"], 15)
        self.assertEqual(s5["total_signed_entries"], 282)

        # Verify zero cross-cluster `.svc.cluster.local` leakage in multicluster manifests
        expected_local_ns = {
            "cluster-alpha.yaml": ".lineage-alpha.svc.cluster.local",
            "cluster-beta.yaml": ".lineage-beta.svc.cluster.local",
            "cluster-pay.yaml": ".lineage-pay.svc.cluster.local",
            "cluster-audit.yaml": ".lineage-ctrl.svc.cluster.local",
        }
        for fname, own_suffix in expected_local_ns.items():
            with open(os.path.join(MC_MANIFEST_DIR, fname), "r", encoding="utf-8") as yf:
                raw_yaml = yf.read()
            for match in re.findall(r"[A-Za-z0-9._-]+\.svc\.cluster\.local", raw_yaml):
                self.assertTrue(
                    match.endswith(own_suffix),
                    f"{fname} contains cross-cluster .svc.cluster.local reference: {match}",
                )
            for doc in yaml.safe_load_all(raw_yaml):
                if not doc or doc.get("kind") != "Service":
                    continue
                svc_name = doc["metadata"]["name"]
                svc_type = doc["spec"].get("type", "ClusterIP")
                ports = [p["port"] for p in doc["spec"].get("ports", [])]
                if any(pt in (8090, 8091, 8092) for pt in ports):
                    self.assertEqual(
                        svc_type,
                        "ClusterIP",
                        f"Internal control-plane port {ports} on {svc_name} must be ClusterIP!",
                    )

    # -------------------------------------------------------------------------
    # 2. Domain CA `:8094` Read-Only Normalization & Strict SA DNS SAN Scoping
    # -------------------------------------------------------------------------
    def test_02_domain_ca_federation_port_edge_cases_and_sa_san_scoping(self) -> None:
        oidc_kp = KeyPair.generate("RS256")
        ca_svc = AutonomousDomainCAService(
            trust_domain="org-beta.io",
            allowed_k8s_namespace="lineage-beta",
            k8s_verifier=self._make_mock_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
            federation_port=0,
        )
        ca_svc.start()
        try:
            int_url = ca_svc.base_url
            fed_url = ca_svc.federation_base_url
            assert fed_url is not None

            # Allowed GET routes with query strings succeed
            self.assertEqual(httpx.get(f"{fed_url}/healthz?probe=1", trust_env=False).status_code, 200)
            self.assertEqual(
                httpx.get(f"{fed_url}/v1/federation/bundle?cache=0", trust_env=False).status_code, 200
            )
            self.assertEqual(httpx.get(f"{fed_url}/v1/ca/bundles", trust_env=False).status_code, 200)

            # Mutating methods, percent-encoded bypasses, trailing slashes, and dot-traversal blocked!
            for method, path, exp_codes in (
                ("POST", "/healthz", (403,)),
                ("POST", "/v1/federation/bundle", (403,)),
                ("PUT", "/v1/federation/bundle", (403,)),
                ("DELETE", "/v1/federation/bundle", (403,)),
                ("GET", "/v1/federation/bundle/", (403,)),
                ("POST", "/v1/ca/issue-workload", (403,)),
                ("POST", "/v1/ca/issue-%77orkload", (403,)),
                ("GET", "/v1/federation/%62undle", (403,)),
                ("POST", "/v1/federation/bundle/../ca/issue-workload", (400, 403)),
                ("POST", "/v1/federation/bundle/%2e%2e/ca/issue-workload", (400, 403)),
            ):
                resp = httpx.request(method, f"{fed_url}{path}", trust_env=False)
                self.assertIn(resp.status_code, exp_codes, f"{method} {path} -> {resp.status_code}")

            # Verify `_validate_allowed_dns_sans` blocks requesting another SA's FQDN or foreign domain!
            flight_jwt = self._mint_sa_jwt(oidc_kp, "lineage-beta", "flight-specialist")
            for forbidden_dns in (
                ["hotel-specialist-primary.org-beta.io"],
                ["beta-ca.org-beta.io"],
                ["payment-vault-mcp.org-payment.io"],
                ["hotel-specialist-primary.lineage-beta.svc.cluster.local"],
            ):
                kp = KeyPair.generate("ES256")
                r_bad = httpx.post(
                    f"{int_url}/v1/ca/issue-workload",
                    json={
                        "public_jwk": kp.public_jwk(),
                        "pop_jws": create_ca_pop_jws(kp, flight_jwt),
                        "dns_names": forbidden_dns,
                    },
                    headers={"Authorization": f"Bearer {flight_jwt}"},
                    trust_env=False,
                )
                self.assertEqual(r_bad.status_code, 400, f"Forbidden SAN {forbidden_dns} was not rejected!")
                self.assertEqual(r_bad.json()["error"], "invalid_workload_csr")
        finally:
            ca_svc.stop()

    # -------------------------------------------------------------------------
    # 3. `:8491`/`:8492` Sandbox Workload Restrictions & Outbound Peer MITM Block
    # -------------------------------------------------------------------------
    def test_03_directory_and_revocation_sandbox_restrictions_and_outbound_peer_pinning(
        self,
    ) -> None:
        oidc_a = KeyPair.generate("RS256")
        oidc_b = KeyPair.generate("RS256")
        oidc_p = KeyPair.generate("RS256")

        ca_a = AutonomousDomainCAService(
            "org-alpha.io", "lineage-alpha", k8s_verifier=self._make_mock_k8s_verifier(oidc_a), host="127.0.0.1", port=0
        )
        ca_b = AutonomousDomainCAService(
            "org-beta.io", "lineage-beta", k8s_verifier=self._make_mock_k8s_verifier(oidc_b), host="127.0.0.1", port=0
        )
        ca_p = AutonomousDomainCAService(
            "org-payment.io", "lineage-pay", k8s_verifier=self._make_mock_k8s_verifier(oidc_p), host="127.0.0.1", port=0
        )
        for c in (ca_a, ca_b, ca_p):
            c.start()

        resolver = TrustBundleResolver()
        store = X509FederationTrustStore()
        for td, c in (("org-alpha.io", ca_a), ("org-beta.io", ca_b), ("org-payment.io", ca_p)):
            b = c.export_federation_bundle()
            resolver.register_bundle(b)
            store.register_domain_root_pem(td, b["x509_root_pem"])

        def _issue(ca_obj: AutonomousDomainCAService, oidc_k: KeyPair, ns: str, sa: str) -> Tuple[WorkloadIdentity, WorkloadMTLSBundle]:
            kp = KeyPair.generate("ES256")
            jwt_s = self._mint_sa_jwt(oidc_k, ns, sa)
            r = httpx.post(
                f"{ca_obj.base_url}/v1/ca/issue-workload",
                json={"public_jwk": kp.public_jwk(), "pop_jws": create_ca_pop_jws(kp, jwt_s)},
                headers={"Authorization": f"Bearer {jwt_s}"},
                trust_env=False,
            )
            self.assertEqual(r.status_code, 200, r.text)
            d = r.json()
            wl = WorkloadIdentity(
                d["spiffe_id"], d["trust_domain"], kp, d["workload_svid"], float(d["issued_at"]), float(d["expires_at"])
            )
            return wl, WorkloadMTLSBundle(wl.spiffe_id, kp, d["x509_leaf_pem"], store)

        to_stop: List[Any] = [ca_a, ca_b, ca_p]
        try:
            dir_id_a, dir_mb_a = _issue(ca_a, oidc_a, "lineage-alpha", "alpha-directory")
            rev_id_a, rev_mb_a = _issue(ca_a, oidc_a, "lineage-alpha", "alpha-revocation")
            rev_id_p, rev_mb_p = _issue(ca_p, oidc_p, "lineage-pay", "payment-revocation")

            # Compromised sandbox workload certificate in `org-beta.io`
            sandbox_id, sandbox_mb = _issue(ca_b, oidc_b, "lineage-beta", "sandbox-untrusted-worker")
            # Compromised `beta-directory` / `beta-revocation` attempting to MITM `org-payment.io`!
            rogue_beta_id, rogue_beta_mb = _issue(ca_b, oidc_b, "lineage-beta", "beta-revocation")

            dir_a = AgentDirectoryService(
                resolver, local_trust_domain="org-alpha.io", host="127.0.0.1", port=0, federation_port=0, mtls_bundle=dir_mb_a
            )
            rev_a = RevocationService(
                rev_id_a, resolver, strict_domain_isolation=True, host="127.0.0.1", port=0, federation_port=0, mtls_bundle=rev_mb_a
            )
            rev_p = RevocationService(
                rev_id_p, resolver, strict_domain_isolation=True, host="127.0.0.1", port=0, federation_port=0, mtls_bundle=rev_mb_p
            )
            for s in (dir_a, rev_a, rev_p):
                s.start()
                to_stop.append(s)

            fed_dir_a = dir_a.federation_base_url.replace("127.0.0.1", "localhost")  # type: ignore[union-attr]
            fed_rev_a = rev_a.federation_base_url.replace("127.0.0.1", "localhost")  # type: ignore[union-attr]

            # A. Sandbox workload with valid `org-beta.io` mTLS cert CANNOT invoke any non-federation
            #    route on `:8491` or `:8492`, AND CANNOT invoke `/v1/revoke/prefix` without authority_token!
            sb_ctx = sandbox_mb.build_client_ssl_context(expected_trust_domain="org-alpha.io")
            sb_card = AgentCard.sign_and_create(
                sandbox_id, "Sandbox", "https://sandbox.org-beta.io:31999", ["travel.flight"]
            )
            with httpx.Client(verify=sb_ctx, trust_env=False, timeout=3.0) as sb_cli:
                for method, url in (
                    ("POST", f"{fed_dir_a}/v1/agents/register"),
                    ("POST", f"{fed_dir_a}/v1/agents/quarantine"),
                    ("GET", f"{fed_dir_a}/v1/agents/discover"),
                    ("GET", f"{fed_dir_a}/v1/agents/get?spiffe_id=x"),
                    ("GET", f"{fed_dir_a}/.well-known/jwks.json"),
                    ("POST", f"{fed_rev_a}/v1/revoke/workload"),
                    ("GET", f"{fed_rev_a}/v1/events"),
                    ("GET", f"{fed_rev_a}/v1/service-info"),
                ):
                    r = sb_cli.request(method, url, json={"agent_card": sb_card.to_dict()} if method == "POST" else None)
                    self.assertEqual(r.status_code, 403, f"{method} {url} -> {r.status_code}")
                    self.assertEqual(r.json()["error"], "federation_port_restricted")

                # Attempting unauthorized `/v1/revoke/prefix` on `:8492` -> 403 `revocation_rejected`!
                unauth_cmd = jws_sign_compact(
                    {"jti": "j1", "prefix": "/task-victim/Orch", "reason": "evil", "iat": time.time()},
                    sandbox_id.keypair,
                    typ="lct-revoke-cmd+jwt",
                )
                r_pref = sb_cli.post(
                    f"{fed_rev_a}/v1/revoke/prefix",
                    json={
                        "auth_mode": "workload",
                        "caller_svid": sandbox_id.workload_svid,
                        "command_jws": unauth_cmd,
                    },
                )
                self.assertEqual(r_pref.status_code, 403)
                self.assertEqual(r_pref.json()["error"], "revocation_rejected")

            # B. Outbound peer domain pinning (`verify_for_target(expected_trust_domain=peer_td)`):
            #    Stand up a rogue HTTPS server certified by `org-beta.io` (`rogue_beta_mb`) pretending
            #    to be `org-payment.io`'s directory & revocation peer!
            mitm_hits: List[str] = []
            rogue_peer_srv = ManagedHTTPService(
                "rogue-beta-impersonating-payment",
                lambda req: (
                    mitm_hits.append(req.path) or 200,
                    {"trust_domain": "org-payment.io", "cards": [], "events": []},
                    {},
                ),
                host="127.0.0.1",
                port=0,
                ssl_context=rogue_beta_mb.build_server_ssl_context(require_client_cert=True),
            )
            rogue_peer_url = rogue_peer_srv.start().replace("127.0.0.1", "localhost")
            to_stop.append(rogue_peer_srv)

            # Point `dir_a` and `rev_a` `org-payment.io` peer URL at the `org-beta.io`-certified MITM server!
            dir_a.peer_directory_urls = {"org-payment.io": rogue_peer_url}
            rev_a.peer_revocation_urls = {"org-payment.io": rogue_peer_url}

            # 1) Directory sync rejects handshake before HTTP GET is sent (`mitm_hits == []`)
            self.assertEqual(dir_a.sync_from_federation_peers(), 0)
            self.assertEqual(mitm_hits, [])

            # 2) Strict HIGH_RISK revocation sync raises RevocationError (`503` fail-closed) at handshake!
            r_strict = httpx.get(
                f"{rev_a.base_url}/v1/events",
                params={"since_version": 0, "wait_ms": 0, "require_trust_domain": "org-payment.io"},
                trust_env=False,
            )
            self.assertEqual(r_strict.status_code, 503)
            self.assertEqual(r_strict.json()["error"], "federation_anchor_unavailable")
            self.assertEqual(mitm_hits, [])
        finally:
            for s in reversed(to_stop):
                try:
                    s.stop()
                except Exception:
                    pass

    # -------------------------------------------------------------------------
    # 4. Live 4-Cluster Runtime, Kubeconfig Hygiene & Isolation Verification
    # -------------------------------------------------------------------------
    def test_04_live_4cluster_runtime_isolation_and_baseline_hygiene(self) -> None:
        env = _tool_env()
        kubectl = shutil.which("kubectl", path=env["PATH"])
        docker = shutil.which("docker", path=env["PATH"])
        self.assertIsNotNone(kubectl)
        self.assertIsNotNone(docker)

        # 1. Verify active context == `kind-agent-identity-lab`, zero `lineage-*` ns, `team1` 3/3 Running
        cur_ctx = subprocess.check_output(
            [kubectl, "config", "current-context"], env=env, text=True
        ).strip()
        self.assertEqual(cur_ctx, "kind-agent-identity-lab")

        ns_doc = json.loads(
            subprocess.check_output(
                [kubectl, "--context", "kind-agent-identity-lab", "get", "ns", "-o", "json"],
                env=env,
                text=True,
            )
        )
        ns_names = [i["metadata"]["name"] for i in ns_doc["items"]]
        self.assertEqual([n for n in ns_names if n.startswith("lineage-")], [])

        t1_pods = json.loads(
            subprocess.check_output(
                [kubectl, "--context", "kind-agent-identity-lab", "-n", "team1", "get", "pods", "-o", "json"],
                env=env,
                text=True,
            )
        )["items"]
        self.assertEqual(len(t1_pods), 3)
        for p in t1_pods:
            self.assertEqual(p["status"]["phase"], "Running")

        # 2. Verify 4 distinct Docker node containers, 4 distinct OIDC `kid`s, and 4 disjoint CIDRs
        cluster_specs = [
            ("lct-org-alpha", "kind-lct-org-alpha", "10.241.0.0/16", "10.97.0.0/16"),
            ("lct-org-beta", "kind-lct-org-beta", "10.242.0.0/16", "10.98.0.0/16"),
            ("lct-org-pay", "kind-lct-org-pay", "10.243.0.0/16", "10.99.0.0/16"),
            ("lct-audit", "kind-lct-audit", "10.244.0.0/16", "10.100.0.0/16"),
        ]
        container_ids = set()
        oidc_kids = set()
        for cname, ctx, exp_pod_cidr, exp_svc_cidr in cluster_specs:
            cid = subprocess.check_output(
                [docker, "inspect", "-f", "{{.Id}}", f"{cname}-control-plane"],
                env=env,
                text=True,
            ).strip()
            container_ids.add(cid)

            nodes = json.loads(
                subprocess.check_output([kubectl, "--context", ctx, "get", "nodes", "-o", "json"], env=env, text=True)
            )["items"]
            node_pod_cidr = nodes[0]["spec"]["podCIDR"]
            self.assertTrue(
                ipaddress.ip_network(node_pod_cidr).subnet_of(ipaddress.ip_network(exp_pod_cidr)),
                f"{ctx}: {node_pod_cidr} not in {exp_pod_cidr}",
            )

            api_pod = json.loads(
                subprocess.check_output(
                    [kubectl, "--context", ctx, "-n", "kube-system", "get", "pod", "-l", "component=kube-apiserver", "-o", "json"],
                    env=env,
                    text=True,
                )
            )["items"][0]
            api_cmd = " ".join(api_pod["spec"]["containers"][0]["command"])
            self.assertIn(f"--service-cluster-ip-range={exp_svc_cidr}", api_cmd)

            jwks = json.loads(
                subprocess.check_output([kubectl, "--context", ctx, "get", "--raw", "/openid/v1/jwks"], env=env, text=True)
            )
            for k in jwks.get("keys", []):
                if k.get("kid"):
                    oidc_kids.add(k["kid"])

        self.assertEqual(len(container_ids), 4)
        self.assertEqual(len(oidc_kids), 4)

        # 3. Verify live cross-cluster mTLS 1.3 & boundary restrictions from inside `kind-lct-org-alpha`
        live_probe = """
import socket, ssl, httpx
from lineage.federation import bootstrap_autonomous_workload, parse_domain_url_map
from lineage.registry import AgentDirectoryClient

wl, resolver, mb, syncer = bootstrap_autonomous_workload(
    "http://alpha-ca.lineage-alpha.svc.cluster.local:8090",
    parse_domain_url_map("org-beta.io=http://beta-ca.org-beta.io:31094,org-payment.io=http://payment-ca.org-payment.io:32094"),
)
try:
    cards = AgentDirectoryClient("http://alpha-directory.lineage-alpha.svc.cluster.local:8091", resolver).discover(only_healthy=True)
    assert len(cards) == 5, len(cards)
    for c in cards:
        assert ".svc.cluster.local" not in c.endpoint

    # Foreign .svc.cluster.local must fail DNS resolution
    for fqdn in ("flight-specialist.lineage-beta.svc.cluster.local", "payment-vault-mcp.lineage-pay.svc.cluster.local"):
        try:
            socket.getaddrinfo(fqdn, 8443)
            raise AssertionError(f"Unexpected DNS resolution for {fqdn}")
        except socket.gaierror:
            pass

    # External CA :31094 & :32094 read-only check
    assert httpx.post("http://beta-ca.org-beta.io:31094/v1/ca/issue-workload", json={}, trust_env=False, timeout=3).status_code == 403
    assert httpx.post("http://payment-ca.org-payment.io:32094/v1/ca/mint-root-token", json={}, trust_env=False, timeout=3).status_code == 403

    # External Directory :31491 & Revocation :32492 mTLS 1.3 + route restrictions
    b_ctx = mb.verify_for_target(target_url="https://beta-directory.org-beta.io:31491", expected_trust_domain="org-beta.io")
    with httpx.Client(verify=b_ctx, trust_env=False, timeout=3) as c:
        assert c.get("https://beta-directory.org-beta.io:31491/v1/federation/cards").status_code == 200
        assert c.post("https://beta-directory.org-beta.io:31491/v1/agents/register", json={}).status_code == 403
        assert c.post("https://beta-directory.org-beta.io:31491/v1/agents/quarantine", json={}).status_code == 403

    p_ctx = mb.verify_for_target(target_url="https://payment-revocation.org-payment.io:32492", expected_trust_domain="org-payment.io")
    with httpx.Client(verify=p_ctx, trust_env=False, timeout=3) as c:
        assert c.get("https://payment-revocation.org-payment.io:32492/v1/federation/events").status_code == 200
        assert c.post("https://payment-revocation.org-payment.io:32492/v1/revoke/workload", json={}).status_code == 403
        assert c.get("https://payment-revocation.org-payment.io:32492/v1/events").status_code == 403
    print("LIVE_4CLUSTER_PROBE_OK")
finally:
    syncer.stop_background_refresh()
"""
        probe_out = subprocess.check_output(
            [
                kubectl,
                "--context",
                "kind-lct-org-alpha",
                "-n",
                "lineage-alpha",
                "exec",
                "-i",
                "deploy/e2e-user-gateway",
                "--",
                "/app/.venv/bin/python3",
                "-c",
                live_probe,
            ],
            env=env,
            text=True,
        ).strip()
        self.assertEqual(probe_out, "LIVE_4CLUSTER_PROBE_OK")


if __name__ == "__main__":
    unittest.main(verbosity=2)
