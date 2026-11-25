"""Milestone 4 Multi-Cluster Boundary Hardening & mTLS 1.3 Federation Unit Tests.

Verifies:
1. `AutonomousDomainCAService`:
   - Issues leaf X.509-SVIDs containing public organization FQDN SANs (`<sa>.<trust_domain>`)
     satisfying critical `NameConstraints` and enabling automatic outbound per-domain CA pinning.
   - Enforces strict read-only boundary on external `federation_port` (`200` on `/healthz` and
     `/v1/federation/bundle`; `403 federation_endpoint_read_only` on `/v1/ca/issue-workload`,
     `/v1/ca/mint-root-token`, and `/v1/ca/emit-revocation-audit`).
2. `AgentDirectoryService`:
   - Enforces bidirectional X.509 mTLS 1.3 (`ssl.CERT_REQUIRED`) on `federation_port` (`:8491`).
   - Synchronizes public `AgentCard`s over HTTPS mTLS while rejecting unauthenticated TLS
     clients and blocking external `/v1/agents/register` & `/v1/agents/quarantine` (`403`).
3. `RevocationService`:
   - Enforces bidirectional X.509 mTLS 1.3 (`ssl.CERT_REQUIRED`) on `federation_port` (`:8492`).
   - Synchronizes `RevocationEvent`s and forwards cross-domain `/v1/revoke/prefix` over HTTPS
     mTLS, blocks external `/v1/revoke/workload` (`403`), and fails closed (`503`) when a
     required peer cluster's mTLS revocation endpoint is partitioned.
"""

from __future__ import annotations

import ast
import builtins
from collections import deque
import importlib
import inspect
from pathlib import Path
import pkgutil
import secrets
import ssl
import time
import typing
import unittest

import httpx
import yaml
from cryptography import x509

import lineage
from lineage.a2a import A2AServerEngine, Message
from lineage.agents.mcp_servers import PaymentVaultMCPApp, TravelOpsMCPApp
from lineage.common.crypto import KeyPair, jws_sign_compact
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.common.mtls import WorkloadMTLSBundle, X509FederationTrustStore
from lineage.federation import AutonomousDomainCAService
from lineage.identity import TrustBundleResolver, TrustDomainCA, WorkloadIdentity
from lineage.k8s.bootstrap_services import K8sServiceAccountVerifier, create_ca_pop_jws
from lineage.k8s.e2e_driver import _scrub_for_disk
from lineage.protocol import PermissionLattice, create_dpop_proof, mint_root_token
from lineage.registry import AgentCard, AgentDirectoryService
from lineage.revocation import RevocationReplicaClient, RevocationService
from lineage.sidecar import LineageSidecar, MCPToolSidecarNode
from lineage.verifier import VerificationMode


class Milestone4MultiClusterFederationTests(unittest.TestCase):
    @staticmethod
    def _mint_sa_jwt(
        oidc_kp: KeyPair,
        namespace: str,
        sa_name: str,
        aud: str = "lct-federation-ca",
    ) -> str:
        now = time.time()
        return jws_sign_compact(
            payload={
                "iss": "https://kubernetes.default.svc.cluster.local",
                "sub": f"system:serviceaccount:{namespace}:{sa_name}",
                "aud": [aud],
                "iat": now,
                "nbf": now,
                "exp": now + 1800.0,
            },
            keypair=oidc_kp,
            typ="JWT",
        )

    @staticmethod
    def _make_mock_k8s_verifier(oidc_kp: KeyPair) -> K8sServiceAccountVerifier:
        v = K8sServiceAccountVerifier(allowed_audiences=("lct-federation-ca",))
        pub = oidc_kp.public_jwk()
        v._keys_by_kid = {pub["kid"]: pub}
        v._last_refresh = time.time() + 3600.0
        v._refresh_jwks = lambda: None  # type: ignore[method-assign]
        return v

    def test_01_domain_ca_public_org_fqdn_san_and_readonly_federation_port(self) -> None:
        # Distinct OIDC RSA signing keys simulating two independent Kind `kube-apiserver`s!
        oidc_alpha = KeyPair.generate("RS256")
        oidc_beta = KeyPair.generate("RS256")

        ca_alpha = AutonomousDomainCAService(
            trust_domain="org-alpha.io",
            allowed_k8s_namespace="lineage-alpha",
            authorized_gateway_sa="e2e-user-gateway",
            k8s_verifier=self._make_mock_k8s_verifier(oidc_alpha),
            host="127.0.0.1",
            port=0,
            federation_port=0,
        )
        ca_alpha.start()
        try:
            int_url = ca_alpha.base_url
            fed_url = ca_alpha.federation_base_url
            self.assertIsNotNone(fed_url)
            assert fed_url is not None

            # 1. External `federation_port` serves `/healthz` and `/v1/federation/bundle`
            r_h = httpx.get(f"{fed_url}/healthz", trust_env=False)
            self.assertEqual(r_h.status_code, 200)
            self.assertEqual(r_h.json()["mode"], "federation_readonly")

            r_b = httpx.get(f"{fed_url}/v1/federation/bundle", trust_env=False)
            self.assertEqual(r_b.status_code, 200)
            bundle = r_b.json()
            self.assertEqual(bundle["trust_domain"], "org-alpha.io")
            self.assertIn("BEGIN CERTIFICATE", bundle["x509_root_pem"])

            # 2. External `federation_port` strictly rejects ALL mutating CA endpoints with `403`!
            sa_jwt = self._mint_sa_jwt(oidc_alpha, "lineage-alpha", "e2e-user-gateway")
            w_kp = KeyPair.generate("ES256")
            pop = create_ca_pop_jws(w_kp, sa_jwt)
            for forbidden_path in (
                "/v1/ca/issue-workload",
                "/v1/ca/mint-root-token",
                "/v1/ca/emit-revocation-audit",
            ):
                r_forb = httpx.post(
                    f"{fed_url}{forbidden_path}",
                    json={"public_jwk": w_kp.public_jwk(), "pop_jws": pop},
                    headers={"Authorization": f"Bearer {sa_jwt}"},
                    trust_env=False,
                )
                self.assertEqual(r_forb.status_code, 403, forbidden_path)
                self.assertEqual(r_forb.json()["error"], "federation_endpoint_read_only")

            # 3. Foreign cluster K8s SA JWT (signed by Cluster Beta's `kube-apiserver` key, even if
            #    claiming namespace `lineage-alpha`!) is rejected on internal `:8090`!
            foreign_cluster_jwt = self._mint_sa_jwt(
                oidc_beta, "lineage-alpha", "orchestrator-alpha"
            )
            r_foreign = httpx.post(
                f"{int_url}/v1/ca/issue-workload",
                json={
                    "public_jwk": w_kp.public_jwk(),
                    "pop_jws": create_ca_pop_jws(w_kp, foreign_cluster_jwt),
                },
                headers={"Authorization": f"Bearer {foreign_cluster_jwt}"},
                trust_env=False,
            )
            self.assertEqual(r_foreign.status_code, 403)
            self.assertIn("Unknown Kubernetes signing kid", r_foreign.json()["detail"])

            # 4. Internal `:8090` issues leaf X.509-SVID carrying public org FQDN SAN `<sa>.<trust_domain>`!
            orch_jwt = self._mint_sa_jwt(oidc_alpha, "lineage-alpha", "orchestrator-alpha")
            r_ok = httpx.post(
                f"{int_url}/v1/ca/issue-workload",
                json={
                    "public_jwk": w_kp.public_jwk(),
                    "pop_jws": create_ca_pop_jws(w_kp, orch_jwt),
                },
                headers={"Authorization": f"Bearer {orch_jwt}"},
                trust_env=False,
            )
            self.assertEqual(r_ok.status_code, 200, r_ok.text)
            leaf_pem = r_ok.json()["x509_leaf_pem"]
            leaf_cert = x509.load_pem_x509_certificate(leaf_pem.encode("ascii"))
            san = leaf_cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            dns_sans = san.get_values_for_type(x509.DNSName)
            self.assertIn("orchestrator-alpha.org-alpha.io", dns_sans)

            store = X509FederationTrustStore()
            store.register_domain_root_pem("org-alpha.io", bundle["x509_root_pem"])
            self.assertEqual(
                store.infer_trust_domain_from_hostname("orchestrator-alpha.org-alpha.io"),
                "org-alpha.io",
            )
        finally:
            ca_alpha.stop()

    def test_02_directory_and_revocation_mtls_federation_ports_and_partition_fail_closed(
        self,
    ) -> None:
        oidc_a = KeyPair.generate("RS256")
        oidc_b = KeyPair.generate("RS256")
        oidc_p = KeyPair.generate("RS256")

        ca_a = AutonomousDomainCAService(
            "org-alpha.io",
            "lineage-alpha",
            k8s_verifier=self._make_mock_k8s_verifier(oidc_a),
            host="127.0.0.1",
            port=0,
        )
        ca_b = AutonomousDomainCAService(
            "org-beta.io",
            "lineage-beta",
            k8s_verifier=self._make_mock_k8s_verifier(oidc_b),
            host="127.0.0.1",
            port=0,
        )
        ca_p = AutonomousDomainCAService(
            "org-payment.io",
            "lineage-pay",
            k8s_verifier=self._make_mock_k8s_verifier(oidc_p),
            host="127.0.0.1",
            port=0,
        )
        ca_map = {"org-alpha.io": (ca_a, oidc_a, "lineage-alpha"), "org-beta.io": (ca_b, oidc_b, "lineage-beta"), "org-payment.io": (ca_p, oidc_p, "lineage-pay")}

        resolver = TrustBundleResolver()
        x509_store = X509FederationTrustStore()
        for td, (ca_svc, _, _) in ca_map.items():
            b = ca_svc.export_federation_bundle()
            resolver.register_bundle(b)
            x509_store.register_domain_root_pem(td, b["x509_root_pem"])

        def _issue_node(td: str, sa: str) -> tuple[WorkloadIdentity, WorkloadMTLSBundle]:
            ca_svc, oidc_k, ns = ca_map[td]
            ca_svc.start()
            kp = KeyPair.generate("ES256")
            jwt_tok = self._mint_sa_jwt(oidc_k, ns, sa)
            resp = httpx.post(
                f"{ca_svc.base_url}/v1/ca/issue-workload",
                json={"public_jwk": kp.public_jwk(), "pop_jws": create_ca_pop_jws(kp, jwt_tok)},
                headers={"Authorization": f"Bearer {jwt_tok}"},
                trust_env=False,
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            d = resp.json()
            ident = WorkloadIdentity(
                d["spiffe_id"], td, kp, d["workload_svid"], float(d["issued_at"]), float(d["expires_at"])
            )
            mb = WorkloadMTLSBundle(ident.spiffe_id, kp, d["x509_leaf_pem"], x509_store)
            return ident, mb

        to_stop = [ca_a, ca_b, ca_p]
        try:
            rev_id_a, rev_mb_a = _issue_node("org-alpha.io", "alpha-revocation")
            rev_id_b, rev_mb_b = _issue_node("org-beta.io", "beta-revocation")
            rev_id_p, rev_mb_p = _issue_node("org-payment.io", "payment-revocation")

            dir_id_a, dir_mb_a = _issue_node("org-alpha.io", "alpha-directory")
            dir_id_b, dir_mb_b = _issue_node("org-beta.io", "beta-directory")

            rev_a = RevocationService(
                rev_id_a, resolver, strict_domain_isolation=True, host="127.0.0.1", port=0, federation_port=0, mtls_bundle=rev_mb_a
            )
            rev_b = RevocationService(
                rev_id_b, resolver, strict_domain_isolation=True, host="127.0.0.1", port=0, federation_port=0, mtls_bundle=rev_mb_b
            )
            rev_p = RevocationService(
                rev_id_p, resolver, strict_domain_isolation=True, host="127.0.0.1", port=0, federation_port=0, mtls_bundle=rev_mb_p
            )
            dir_a = AgentDirectoryService(
                resolver, local_trust_domain="org-alpha.io", host="127.0.0.1", port=0, federation_port=0, mtls_bundle=dir_mb_a
            )
            dir_b = AgentDirectoryService(
                resolver, local_trust_domain="org-beta.io", host="127.0.0.1", port=0, federation_port=0, mtls_bundle=dir_mb_b
            )
            for s in (rev_a, rev_b, rev_p, dir_a, dir_b):
                s.start()
                to_stop.append(s)

            fed_rev_a = rev_a.federation_base_url.replace("127.0.0.1", "localhost")  # type: ignore[union-attr]
            fed_rev_b = rev_b.federation_base_url.replace("127.0.0.1", "localhost")  # type: ignore[union-attr]
            fed_rev_p = rev_p.federation_base_url.replace("127.0.0.1", "localhost")  # type: ignore[union-attr]
            fed_dir_a = dir_a.federation_base_url.replace("127.0.0.1", "localhost")  # type: ignore[union-attr]
            fed_dir_b = dir_b.federation_base_url.replace("127.0.0.1", "localhost")  # type: ignore[union-attr]

            self.assertTrue(fed_rev_a.startswith("https://"))
            self.assertTrue(fed_dir_b.startswith("https://"))

            rev_a.peer_revocation_urls = {"org-beta.io": fed_rev_b, "org-payment.io": fed_rev_p}
            rev_b.peer_revocation_urls = {"org-alpha.io": fed_rev_a, "org-payment.io": fed_rev_p}
            rev_p.peer_revocation_urls = {"org-alpha.io": fed_rev_a, "org-beta.io": fed_rev_b}
            dir_a.peer_directory_urls = {"org-beta.io": fed_dir_b}
            dir_b.peer_directory_urls = {"org-alpha.io": fed_dir_a}

            # A. Unauthenticated TLS client (no client cert) rejected on BOTH `:8491` and `:8492`!
            server_only_ctx = ssl.create_default_context(cadata=x509_store.combined_ca_pem())
            for target_fed_url in (f"{fed_dir_b}/v1/federation/cards", f"{fed_rev_a}/v1/federation/events"):
                with self.assertRaises(Exception):
                    with httpx.Client(verify=server_only_ctx, trust_env=False, timeout=3.0) as bad_c:
                        bad_c.get(target_fed_url)

            # B. External `/v1/agents/register`, `/v1/agents/quarantine`, `/v1/revoke/workload`, `/v1/events`
            #    blocked with `403 federation_port_restricted` even with a valid mTLS client cert!
            flight_id, flight_mb = _issue_node("org-beta.io", "flight-specialist")
            flight_card = AgentCard.sign_and_create(
                flight_id,
                "Flight B1",
                "https://flight-specialist.org-beta.io:31441",
                ["travel.flight"],
                return_endpoint="https://flight-specialist.org-beta.io:31441",
            )
            with httpx.Client(
                verify=flight_mb.build_client_ssl_context(expected_trust_domain="org-beta.io"),
                trust_env=False,
            ) as m_cli:
                r_ext_reg = m_cli.post(
                    f"{fed_dir_b}/v1/agents/register", json={"agent_card": flight_card.to_dict()}
                )
                self.assertEqual(r_ext_reg.status_code, 403)
                self.assertEqual(r_ext_reg.json()["error"], "federation_port_restricted")

                r_ext_q = m_cli.post(f"{fed_dir_b}/v1/agents/quarantine", json={})
                self.assertEqual(r_ext_q.status_code, 403)
                self.assertEqual(r_ext_q.json()["error"], "federation_port_restricted")

                r_ext_rw = m_cli.post(f"{fed_rev_b}/v1/revoke/workload", json={})
                self.assertEqual(r_ext_rw.status_code, 403)
                self.assertEqual(r_ext_rw.json()["error"], "federation_port_restricted")

                r_ext_ev = m_cli.get(f"{fed_rev_b}/v1/events")
                self.assertEqual(r_ext_ev.status_code, 403)
                self.assertEqual(r_ext_ev.json()["error"], "federation_port_restricted")

            # C. Internal registration on `dir_b` (`:8091`) syncs over mTLS 1.3 (`:8491`) to `dir_a`!
            r_int_reg = httpx.post(
                f"{dir_b.base_url}/v1/agents/register",
                json={"agent_card": flight_card.to_dict()},
                trust_env=False,
            )
            self.assertEqual(r_int_reg.status_code, 200)
            dir_a.sync_from_federation_peers()
            cards_in_a = dir_a.discover_cards(skill="travel.flight")
            self.assertEqual(len(cards_in_a), 1)
            self.assertEqual(
                cards_in_a[0].endpoint, "https://flight-specialist.org-beta.io:31441"
            )

            # D. Cross-domain `/v1/revoke/prefix` forwarded over mTLS 1.3 (`:8492`) from `rev_b` -> `rev_a`!
            gw_id, _ = _issue_node("org-alpha.io", "e2e-user-gateway")
            conv_id, _ = _issue_node("org-payment.io", "settlement-converger")
            vault_id, _ = _issue_node("org-payment.io", "payment-vault-mcp")
            perms = PermissionLattice.create(
                tools=["execute_settlement"],
                max_amount=600.0,
                allowed_targets=["airline-escrow"],
                max_calls=4,
            )
            t_root = mint_root_token(
                ca_a.ca,
                "task-m4-cross-cluster",
                "user:alice@org-alpha.io",
                gw_id.jkt,
                flight_id.spiffe_id,
                flight_id.jkt,
                perms,
                hop_segment="FlightB1",
                first_hop_public_jwk=flight_id.keypair.public_jwk(),
            )
            t_leaf = t_root.attenuate(
                issuer_identity=flight_id,
                delegate_spiffe_id=conv_id.spiffe_id,
                delegate_jkt=conv_id.jkt,
                permissions=perms,
                hop_segment="ConvC",
            )

            # Forward revocation of `/task-m4-cross-cluster/FlightB1/ConvC` via `rev_b` -> `rev_a` (mTLS)!
            rep_b = RevocationReplicaClient(rev_b.base_url, resolver)
            ev_fwd = rep_b.revoke_prefix(
                caller=flight_id,
                prefix=t_leaf.lineage_path,
                reason="cross_cluster_fwd",
                authority_token=t_leaf.encode_compact(),
            )
            self.assertEqual(ev_fwd.trust_domain, "org-alpha.io")
            rev_p.sync_from_federation_peers()
            self.assertIsNotNone(
                rev_p.trie.check_lineage_path(t_leaf.lineage_path, trust_domain="org-alpha.io")
            )

            # E. Whole-Cluster Partition Simulation (`rev_b.stop()`):
            #    Attempting HIGH_RISK settlement on `payment-vault-mcp` whose lineage traverses
            #    `org-beta.io` (`flight_id`) MUST fail closed (`503 REVOCATION_ANCHOR_UNAVAILABLE`)!
            t_root_2 = mint_root_token(
                ca_a.ca,
                "task-m4-beta-outage",
                "user:alice@org-alpha.io",
                gw_id.jkt,
                flight_id.spiffe_id,
                flight_id.jkt,
                perms,
                hop_segment="FlightB1",
                first_hop_public_jwk=flight_id.keypair.public_jwk(),
            )
            t_leaf_2 = t_root_2.attenuate(
                issuer_identity=flight_id,
                delegate_spiffe_id=conv_id.spiffe_id,
                delegate_jkt=conv_id.jkt,
                permissions=perms,
                hop_segment="ConvC",
            )
            vault_mcp = MCPToolSidecarNode(
                identity=vault_id,
                trust_resolver=resolver,
                tools={"execute_settlement": lambda a, _r: {"settled_usd": a["amount"]}},
                revocation_url=rev_p.base_url,
                mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
            )
            vault_url = vault_mcp.start()
            to_stop.append(vault_mcp)

            rev_b.stop()  # Cluster Beta offline!
            compact_2 = t_leaf_2.encode_compact()
            dpop_2 = create_dpop_proof(conv_id, "POST", f"{vault_url}/mcp", compact_2)
            r_part = httpx.post(
                f"{vault_url}/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "execute_settlement",
                        "arguments": {"target": "airline-escrow", "amount": 500.0},
                    },
                },
                headers={"Authorization": f"DPoP {compact_2}", "DPoP": dpop_2},
                trust_env=False,
                timeout=10.0,
            )
            self.assertEqual(r_part.status_code, 503, r_part.text)
            self.assertEqual(r_part.json()["error"], "REVOCATION_ANCHOR_UNAVAILABLE")
        finally:
            for s in reversed(to_stop):
                try:
                    s.stop()
                except Exception:
                    pass

    def test_03_multicluster_manifests_hygiene_and_public_fqdn_purity(self) -> None:
        mc_dir = Path(__file__).resolve().parent.parent / "k8s" / "multicluster"
        cluster_files = [
            "cluster-alpha.yaml",
            "cluster-beta.yaml",
            "cluster-pay.yaml",
            "cluster-audit.yaml",
        ]
        total_deployments = 0
        for fname in cluster_files:
            docs = [
                d
                for d in yaml.safe_load_all((mc_dir / fname).read_text("utf-8"))
                if d
            ]
            for doc in docs:
                if doc.get("kind") == "Service" and doc["spec"].get("type") == "NodePort":
                    svc_name = doc["metadata"]["name"]
                    # Internal CA (:8090), Directory (:8091), Revocation (:8092) MUST NEVER be NodePort!
                    for p in doc["spec"].get("ports") or []:
                        self.assertNotIn(
                            p.get("port"),
                            (8090, 8091, 8092),
                            f"Internal control-plane port exposed via NodePort on {svc_name}!",
                        )
                if doc.get("kind") != "Deployment":
                    continue
                total_deployments += 1
                dep_name = doc["metadata"]["name"]
                pod_spec = doc["spec"]["template"]["spec"]
                self.assertIs(
                    pod_spec.get("automountServiceAccountToken"),
                    False,
                    f"{fname}/{dep_name} must set automountServiceAccountToken: false",
                )
                containers = {c["name"]: c for c in pod_spec["containers"]}
                if "app" in containers:
                    app_mounts = [m["name"] for m in (containers["app"].get("volumeMounts") or [])]
                    self.assertEqual(app_mounts, ["lct-loopback"], f"{dep_name}/app mounts={app_mounts}")
                for cname, cspec in containers.items():
                    for env_item in cspec.get("env") or []:
                        ename = env_item.get("name", "")
                        eval_str = str(env_item.get("value", ""))
                        if ename in (
                            "PUBLIC_ORIGIN",
                            "PEER_CA_URLS",
                            "PEER_DIRECTORY_URLS",
                            "PEER_REVOCATION_URLS",
                        ):
                            self.assertNotIn(
                                ".svc.cluster.local",
                                eval_str,
                                f"{fname}/{dep_name}/{cname} {ename} leaked .svc.cluster.local: {eval_str}",
                            )
        self.assertEqual(total_deployments, 18)

    @staticmethod
    def _scan_file_undefined_names(py_path: Path) -> list[str]:
        """Lexical-scope AST analyzer detecting F821-style undefined `Name` loads
        (including inside deferred PEP 563 annotations!).
        """
        source = py_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(py_path))
        builtin_names = set(dir(builtins)) | {"__file__", "__name__", "__package__", "__doc__", "__annotations__"}

        def _collect_target_names(target: ast.AST, out: set[str]) -> None:
            if isinstance(target, ast.Name):
                out.add(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                for elt in target.elts:
                    _collect_target_names(elt, out)
            elif isinstance(target, ast.Starred):
                _collect_target_names(target.value, out)

        def _collect_scope_bindings(stmts: list[ast.stmt], bound: set[str]) -> None:
            for st in stmts:
                if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    bound.add(st.name)
                elif isinstance(st, ast.Import):
                    for alias in st.names:
                        bound.add(alias.asname or alias.name.split(".")[0])
                elif isinstance(st, ast.ImportFrom):
                    for alias in st.names:
                        if alias.name != "*":
                            bound.add(alias.asname or alias.name)
                elif isinstance(st, ast.Assign):
                    for t in st.targets:
                        _collect_target_names(t, bound)
                elif isinstance(st, ast.AnnAssign):
                    _collect_target_names(st.target, bound)
                elif isinstance(st, ast.AugAssign):
                    _collect_target_names(st.target, bound)
                elif isinstance(st, (ast.For, ast.AsyncFor)):
                    _collect_target_names(st.target, bound)
                    _collect_scope_bindings(st.body, bound)
                    _collect_scope_bindings(st.orelse, bound)
                elif isinstance(st, (ast.With, ast.AsyncWith)):
                    for item in st.items:
                        if item.optional_vars is not None:
                            _collect_target_names(item.optional_vars, bound)
                    _collect_scope_bindings(st.body, bound)
                elif isinstance(st, ast.If):
                    _collect_scope_bindings(st.body, bound)
                    _collect_scope_bindings(st.orelse, bound)
                elif isinstance(st, ast.While):
                    _collect_scope_bindings(st.body, bound)
                    _collect_scope_bindings(st.orelse, bound)
                elif isinstance(st, ast.Try):
                    _collect_scope_bindings(st.body, bound)
                    _collect_scope_bindings(st.orelse, bound)
                    _collect_scope_bindings(st.finalbody, bound)
                    for h in st.handlers:
                        if h.name:
                            bound.add(h.name)
                        _collect_scope_bindings(h.body, bound)
                elif isinstance(st, (ast.Global, ast.Nonlocal)):
                    bound.update(st.names)

            # Also pick up NamedExpr (`:=`) inside expressions within this statement block without descending into nested defs
            def _scan_walrus(node: ast.AST) -> None:
                if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                    bound.add(node.target.id)
                for ch in ast.iter_child_nodes(node):
                    if isinstance(
                        ch,
                        (
                            ast.FunctionDef,
                            ast.AsyncFunctionDef,
                            ast.ClassDef,
                            ast.Lambda,
                            ast.ListComp,
                            ast.SetComp,
                            ast.DictComp,
                            ast.GeneratorExp,
                        ),
                    ):
                        continue
                    _scan_walrus(ch)

            for st in stmts:
                if not isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    _scan_walrus(st)

        errors: list[str] = []

        # Track enclosing non-class lexical scopes (Python class bodies are NOT visible inside nested methods!)
        def _walk_node(node: ast.AST, enclosing_scopes: list[set[str]], current_scope: set[str]) -> None:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                ident = node.id
                if (
                    ident not in current_scope
                    and all(ident not in s for s in enclosing_scopes)
                    and ident not in builtin_names
                ):
                    errors.append(f"{py_path.name}:{node.lineno}: undefined name {ident!r}")
                return

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Decorators, defaults, and return/arg annotations evaluate in outer scope (or deferred module scope)
                for dec in node.decorator_list:
                    _walk_node(dec, enclosing_scopes, current_scope)
                for d in node.args.defaults:
                    _walk_node(d, enclosing_scopes, current_scope)
                for kd in node.args.kw_defaults:
                    if kd is not None:
                        _walk_node(kd, enclosing_scopes, current_scope)

                fn_bound: set[str] = set()
                for arg in (
                    node.args.posonlyargs
                    + node.args.args
                    + node.args.kwonlyargs
                    + ([node.args.vararg] if node.args.vararg else [])
                    + ([node.args.kwarg] if node.args.kwarg else [])
                ):
                    fn_bound.add(arg.arg)
                for tp in getattr(node, "type_params", ()):
                    if hasattr(tp, "name"):
                        fn_bound.add(tp.name)
                _collect_scope_bindings(node.body, fn_bound)

                # Annotations must resolve cleanly against module/enclosing scopes
                for arg in (
                    node.args.posonlyargs
                    + node.args.args
                    + node.args.kwonlyargs
                    + ([node.args.vararg] if node.args.vararg else [])
                    + ([node.args.kwarg] if node.args.kwarg else [])
                ):
                    if arg.annotation is not None:
                        _walk_node(arg.annotation, enclosing_scopes, current_scope | fn_bound)
                if node.returns is not None:
                    _walk_node(node.returns, enclosing_scopes, current_scope | fn_bound)

                next_enclosing = enclosing_scopes + [fn_bound]
                for st in node.body:
                    _walk_node(st, next_enclosing, fn_bound)
                return

            if isinstance(node, ast.ClassDef):
                for dec in node.decorator_list:
                    _walk_node(dec, enclosing_scopes, current_scope)
                for b in node.bases:
                    _walk_node(b, enclosing_scopes, current_scope)
                for kw in node.keywords:
                    _walk_node(kw.value, enclosing_scopes, current_scope)
                cls_bound: set[str] = set()
                for tp in getattr(node, "type_params", ()):
                    if hasattr(tp, "name"):
                        cls_bound.add(tp.name)
                _collect_scope_bindings(node.body, cls_bound)
                # Note: `cls_bound` is NOT added to `enclosing_scopes` for methods inside the class!
                for st in node.body:
                    _walk_node(st, enclosing_scopes, cls_bound)
                return

            if isinstance(node, ast.Lambda):
                for d in node.args.defaults:
                    _walk_node(d, enclosing_scopes, current_scope)
                for kd in node.args.kw_defaults:
                    if kd is not None:
                        _walk_node(kd, enclosing_scopes, current_scope)
                lam_bound: set[str] = {
                    arg.arg
                    for arg in (
                        node.args.posonlyargs
                        + node.args.args
                        + node.args.kwonlyargs
                        + ([node.args.vararg] if node.args.vararg else [])
                        + ([node.args.kwarg] if node.args.kwarg else [])
                    )
                }
                _walk_node(node.body, enclosing_scopes + [lam_bound], lam_bound)
                return

            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                comp_bound = set()
                active_enclosing = list(enclosing_scopes)
                for idx, gen in enumerate(node.generators):
                    if idx == 0:
                        _walk_node(gen.iter, active_enclosing, current_scope)
                    else:
                        _walk_node(gen.iter, active_enclosing + [comp_bound], comp_bound)
                    _collect_target_names(gen.target, comp_bound)
                    for if_expr in gen.ifs:
                        _walk_node(if_expr, active_enclosing + [comp_bound], comp_bound)
                if isinstance(node, ast.DictComp):
                    _walk_node(node.key, active_enclosing + [comp_bound], comp_bound)
                    _walk_node(node.value, active_enclosing + [comp_bound], comp_bound)
                else:
                    _walk_node(node.elt, active_enclosing + [comp_bound], comp_bound)
                return

            for ch in ast.iter_child_nodes(node):
                _walk_node(ch, enclosing_scopes, current_scope)

        mod_bound: set[str] = set()
        _collect_scope_bindings(tree.body, mod_bound)
        for stmt in tree.body:
            _walk_node(stmt, [mod_bound], mod_bound)
        return errors

    def test_04_sse_non_stream_fallback_ast_undefined_names_and_polish_gates(self) -> None:
        # 1. `[MEDIUM-PRE-01]` Regression: `SendStreamingMessage` (`Accept: text/event-stream`)
        #    with invalid JSON-RPC `params` through `LineageSidecar` MUST return a clean JSON-RPC
        #    `-32602` error (`400` `application/json`), NEVER `500 NameError: name 'json' is not defined`!
        ca = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_bundle(ca.export_public_bundle())
        gw_id = ca.issue_workload("/ns/lineage-alpha/sa/gw")
        agent_id = ca.issue_workload("/ns/lineage-alpha/sa/orch")

        loopback_secret = secrets.token_urlsafe(32)
        a2a_engine = A2AServerEngine(
            agent_name="orch",
            work_handler=lambda _ctx, _msg, _emit: (Message.create_agent("ok"), {}),
        )

        def _app_dispatch(req: HTTPRequestContext) -> tuple[int, object, dict[str, str]]:
            if req.path == "/healthz":
                return 200, {"status": "ok"}, {}
            if req.path == "/a2a":
                return a2a_engine.dispatch(req)
            return 404, {"error": "not_found"}, {}

        app_http = ManagedHTTPService("test-a2a-app", _app_dispatch, host="127.0.0.1", port=0)
        app_url = app_http.start()
        card = AgentCard.sign_and_create(
            agent_id,
            "Orch",
            "http://127.0.0.1:18080",
            ["travel.orchestrate"],
        )
        sidecar = LineageSidecar(
            identity=agent_id,
            trust_resolver=resolver,
            app_upstream_url=app_url,
            loopback_secret=loopback_secret,
            agent_card=card,
            inbound_host="127.0.0.1",
            inbound_port=0,
            outbound_port=0,
        )
        in_url, _ = sidecar.start()
        try:
            perms = PermissionLattice.create(tools=["search_flight"], max_calls=2)
            tok = mint_root_token(
                ca,
                "task-sse-err-regression",
                "user:alice@org-alpha.io",
                gw_id.jkt,
                agent_id.spiffe_id,
                agent_id.jkt,
                perms,
                hop_segment="Orch",
            ).encode_compact()
            target_a2a = f"{in_url}/a2a"
            dpop = create_dpop_proof(gw_id, "POST", target_a2a, tok)
            resp = httpx.post(
                target_a2a,
                json={
                    "jsonrpc": "2.0",
                    "id": "bad-sse-1",
                    "method": "SendStreamingMessage",
                    "params": {"message": "NOT_AN_OBJECT"},
                },
                headers={
                    "Authorization": f"DPoP {tok}",
                    "DPoP": dpop,
                    "Accept": "text/event-stream",
                    "A2A-Version": "1.0",
                },
                trust_env=False,
            )
            self.assertEqual(resp.status_code, 400, resp.text)
            body = resp.json()
            self.assertEqual(body["jsonrpc"], "2.0")
            self.assertEqual(body["id"], "bad-sse-1")
            self.assertEqual(body["error"]["code"], -32602)
        finally:
            sidecar.stop()
            app_http.stop()

        # 2. `[LOW-PRE-01]` Full-Repo AST Undefined-Name (`F821`) & `typing.get_type_hints()` Gate
        lineage_root = Path(lineage.__file__).resolve().parent
        all_py_files = [
            p
            for p in sorted(lineage_root.rglob("*.py"))
            if "reviews" not in p.relative_to(lineage_root).parts
        ]
        self.assertGreaterEqual(len(all_py_files), 40)
        undefined_findings: list[str] = []
        for py_file in all_py_files:
            undefined_findings.extend(self._scan_file_undefined_names(py_file))
        self.assertEqual(
            undefined_findings,
            [],
            f"Undefined names found in lineage/: {undefined_findings}",
        )

        # Explicitly verify `typing.get_type_hints` succeeds on `TrustDomainCA.sign_svid_for_public_jwk`
        # and across all public classes/functions in every `lineage.*` module (excluding `reviews`)!
        hints = typing.get_type_hints(TrustDomainCA.sign_svid_for_public_jwk)
        self.assertIn("return", hints)
        type_hint_failures: list[str] = []
        for mod_info in pkgutil.walk_packages(lineage.__path__, prefix="lineage."):
            if mod_info.name.startswith(("lineage.reviews", "lineage.tests")):
                continue
            mod = importlib.import_module(mod_info.name)
            for name, obj in inspect.getmembers(mod):
                if getattr(obj, "__module__", None) != mod_info.name:
                    continue
                if inspect.isfunction(obj):
                    try:
                        typing.get_type_hints(obj)
                    except Exception as exc:
                        type_hint_failures.append(f"{mod_info.name}.{name}: {exc}")
                elif inspect.isclass(obj):
                    for m_name, m_obj in inspect.getmembers(obj, predicate=inspect.isfunction):
                        if getattr(m_obj, "__module__", None) != mod_info.name:
                            continue
                        try:
                            typing.get_type_hints(m_obj)
                        except Exception as exc:
                            type_hint_failures.append(f"{mod_info.name}.{name}.{m_name}: {exc}")
        self.assertEqual(
            type_hint_failures,
            [],
            f"Broken typing.get_type_hints annotations: {type_hint_failures}",
        )

        # 3. `[LOW-PRE-02]` & `[LOW-PRE-03]` Secondary `lctmp1.` Scrubbing & Bounded MCP Ledgers
        scrubbed_mp = _scrub_for_disk({"mp": "lctmp1.secret_multiparent_wire_token"})
        self.assertTrue(scrubbed_mp["mp"].startswith("[REDACTED_LCT_TOKEN_SHA256:"))

        t_app = TravelOpsMCPApp(loopback_secret="s" * 32, port=0)
        p_app = PaymentVaultMCPApp(loopback_secret="s" * 32, port=0)
        self.assertIsInstance(t_app._bookings, deque)
        self.assertEqual(t_app._bookings.maxlen, 10_000)
        self.assertIsInstance(p_app._settlements, deque)
        self.assertEqual(p_app._settlements.maxlen, 10_000)

        # Verify `WorkloadMTLSBundle.cleanup()` deterministically clears cached SSLContexts
        from lineage.common.mtls import X509DomainAuthority

        x_ca = X509DomainAuthority("org-alpha.io")
        x_store = X509FederationTrustStore()
        x_store.register_domain_root_pem("org-alpha.io", x_ca.export_root_pem())
        leaf_pem = x_ca.issue_x509_svid(
            agent_id.spiffe_id,
            agent_id.keypair.public_jwk(),
            dns_names=["orchestrator-alpha.org-alpha.io"],
        )
        w_bundle = WorkloadMTLSBundle(agent_id.spiffe_id, agent_id.keypair, leaf_pem, x_store)
        _ = w_bundle.verify_for_target("https://orchestrator-alpha.org-alpha.io:30441")
        self.assertGreaterEqual(len(w_bundle._client_ctx_cache), 1)
        w_bundle.cleanup()
        self.assertEqual(len(w_bundle._client_ctx_cache), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
