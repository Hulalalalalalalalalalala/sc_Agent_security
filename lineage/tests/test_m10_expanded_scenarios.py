"""Milestone 10 Test Suite: Platform v2.1 Complete 12-Scenario Multi-Entity Workspace Suite.

Covers all 6 new domain-vertical scenarios (`S2`, `S3`, `S5`, `S6`, `S7`, `S8`) and security
controls across Financial Risk Control, Enterprise Legal & Procurement, and Healthcare Federated
Cohort Aggregation:
1. Symmetric `CONSENT_ISSUER_POLICY`, `OWNER_PROTECTED_TOOLS`, multi-org OIDC (`alice`, `bob`,
   `carol`), `"user_gateway"` `SignedDomainDescriptor` locator, and mTLS+OIDC `DomainUserGatewayService`;
2. Catalog S2: Bidirectional `A -> B` & `B -> A` Ping-Pong + `commit_joint_change` + dual-domain revocation interlock;
3. Catalog S3: Multi-round `A -> B -> D` legal redline + `PermissionLattice` `numeric_bounds` & `param_whitelist` guardrails;
4. Catalog S5: 4-hop signed `lct-compliance-attestation+jwt` (`sast_scan`) + `[alice, carol]` SoD `sign_release`;
5. Catalog S6: Healthcare DP `cohort_aggregate_stats` + `export_raw_patient_records` deny + cross-task replay block;
6. Catalog S7 & S8: 4-hop indirect prompt injection + cascading subtree revocation of pre-minted Hop-3 token +
   symmetric `org-beta` Bob entry (`beta-user-gateway`), stolen-token cross-agent replay (`403`), cross-tenant Vault
   isolation, and `DistributedAuditor` starting from `org-beta.io`.
"""

from __future__ import annotations

import os
import secrets
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple
import unittest

import httpx
import yaml

from lineage.audit import AuditStreamEmitter, DistributedAuditor
from lineage.common.crypto import jws_sign_compact
from lineage.common.locators import ServiceLocator
from lineage.common.mtls import WorkloadMTLSBundle, X509FederationTrustStore
from lineage.federation import (
    AutonomousDomainCAService,
    DomainUserGatewayService,
    SignedDomainDescriptor,
)
from lineage.federation.domain_ca import K8sServiceAccountVerifier
from lineage.identity import TrustBundleResolver
from lineage.multihost.config_gen import (
    allocate_role_ports,
    render_role_k8s_manifests,
)
from lineage.oauth_sts import (
    DEFAULT_USER_HOME_DOMAINS,
    OAuthSTSError,
    OAuthSTSService,
    OAuthTokenExchangeClient,
    OIDCTokenVerifier,
    generate_keycloak_realm_bundle,
)
from lineage.protocol import (
    PermissionLattice,
    create_dpop_proof,
    mint_root_token,
)
from lineage.registry import AgentCard, AgentDirectoryClient, AgentDirectoryService
from lineage.revocation import RevocationReplicaClient, RevocationService
from lineage.sidecar import LineageSidecar
from lineage.verifier import VerificationMode
from lineage.workspace_agents import WorkspaceAssistantPeerApp, WorkspaceVaultMCPApp


class _StaticSAVerifier:
    """Deterministic K8s SA token map for in-process multi-domain CA tests."""

    def __init__(self, mapping: Dict[str, Tuple[str, str]]) -> None:
        self._map = dict(mapping)

    def verify_sa_jwt(self, raw_jwt: str, now: float | None = None) -> Tuple[str, str, float]:
        if raw_jwt not in self._map:
            raise ValueError(f"Unknown SA token: {raw_jwt!r}")
        ns, sa = self._map[raw_jwt]
        return ns, sa, (now or time.time()) + 600.0


class _MultiDomainWorkspaceMesh:
    """Real HTTP 3-domain (`org-alpha.io`, `org-beta.io`, `org-payment.io`) symmetric workspace mesh."""

    def __init__(self) -> None:
        self._prev_fault_env = os.environ.get("LCT_ENABLE_FAULT_INJECTION")
        os.environ["LCT_ENABLE_FAULT_INJECTION"] = "true"
        self.temp_files: List[str] = []
        self.started: List[Any] = []
        self.rep_clients: List[RevocationReplicaClient] = []

        self.realm_bundle = generate_keycloak_realm_bundle()
        self.resolver = TrustBundleResolver()

        self.sts_alpha = OAuthSTSService(
            trust_domain="org-alpha.io",
            realm=self.realm_bundle.realm_name,
            user_passwords=self.realm_bundle.user_passwords,
            client_secrets=self.realm_bundle.client_secrets,
            spiffe_trust_resolver=self.resolver,
            host="127.0.0.1",
            port=0,
        )
        self.sts_beta = OAuthSTSService(
            trust_domain="org-beta.io",
            realm=self.realm_bundle.realm_name,
            user_passwords=self.realm_bundle.user_passwords,
            client_secrets=self.realm_bundle.client_secrets,
            spiffe_trust_resolver=self.resolver,
            host="127.0.0.1",
            port=0,
        )
        self.sts_pay = OAuthSTSService(
            trust_domain="org-payment.io",
            realm=self.realm_bundle.realm_name,
            user_passwords=self.realm_bundle.user_passwords,
            client_secrets=self.realm_bundle.client_secrets,
            spiffe_trust_resolver=self.resolver,
            host="127.0.0.1",
            port=0,
        )
        self.sts_url = self.sts_alpha.start()
        self.sts_beta_url = self.sts_beta.start()
        self.sts_pay_url = self.sts_pay.start()
        self.sts_alpha.issuer_origin = self.sts_url
        self.sts_beta.issuer_origin = self.sts_beta_url
        self.sts_pay.issuer_origin = self.sts_pay_url
        self.sts_urls_by_domain: Dict[str, str] = {
            "org-alpha.io": self.sts_url,
            "org-beta.io": self.sts_beta_url,
            "org-payment.io": self.sts_pay_url,
        }
        self.started.extend([self.sts_alpha, self.sts_beta, self.sts_pay])

        self.oauth_cli = OAuthTokenExchangeClient(
            realm=self.realm_bundle.realm_name,
            client_secrets=self.realm_bundle.client_secrets,
        )
        jwks_a = self.oauth_cli.jwks_endpoint(self.sts_url)
        iss_a = f"{self.sts_url}/realms/{self.realm_bundle.realm_name}"
        jwks_b = self.oauth_cli.jwks_endpoint(self.sts_beta_url)
        iss_b = f"{self.sts_beta_url}/realms/{self.realm_bundle.realm_name}"
        jwks_p = self.oauth_cli.jwks_endpoint(self.sts_pay_url)
        iss_p = f"{self.sts_pay_url}/realms/{self.realm_bundle.realm_name}"

        self.oidc_alpha = OIDCTokenVerifier(
            jwks_urls=[jwks_a],
            expected_issuer=iss_a,
            default_user_domain="org-alpha.io",
            allowed_user_domains=("org-alpha.io",),
            single_entity_issuers=True,
        )
        self.oidc_beta = OIDCTokenVerifier(
            jwks_urls=[jwks_b],
            expected_issuer=iss_b,
            default_user_domain="org-beta.io",
            allowed_user_domains=("org-beta.io",),
            single_entity_issuers=True,
        )
        self.oidc_pay = OIDCTokenVerifier(
            jwks_urls=[jwks_p],
            expected_issuer=iss_p,
            default_user_domain="org-payment.io",
            allowed_user_domains=("org-payment.io",),
            single_entity_issuers=True,
        )
        self.oidc_federated = OIDCTokenVerifier(
            jwks_urls=[jwks_a, jwks_b, jwks_p],
            allowed_issuers=[iss_a, iss_b, iss_p],
            issuer_user_domain_map={
                iss_a: "org-alpha.io",
                iss_b: "org-beta.io",
                iss_p: "org-payment.io",
            },
            default_user_domain="org-alpha.io",
            single_entity_issuers=False,
        )

        # Auditor identities (`alpha` & `beta` gateways)
        self.sa_tokens = {
            "sa-alpha-gw": ("lineage-alpha", "e2e-user-gateway"),
            "sa-alice": ("lineage-alpha", "assistant-alice"),
            "sa-beta-gw": ("lineage-beta", "beta-user-gateway"),
            "sa-bob": ("lineage-beta", "assistant-bob"),
            "sa-dave": ("lineage-beta", "assistant-dave"),
            "sa-carol": ("lineage-pay", "assistant-carol"),
            "sa-vault": ("lineage-pay", "assistant-vault"),
        }
        auditors = [
            "spiffe://org-alpha.io/ns/lineage-alpha/sa/e2e-user-gateway",
            "spiffe://org-beta.io/ns/lineage-beta/sa/beta-user-gateway",
        ]

        self.ca_alpha = AutonomousDomainCAService(
            trust_domain="org-alpha.io",
            allowed_k8s_namespace="lineage-alpha",
            authorized_gateway_sa="e2e-user-gateway",
            oidc_verifier=self.oidc_alpha,
            federation_trust_resolver=self.resolver,
            authorized_auditors=auditors,
            consent_issuer_policy="assistant-alice=user:alice@org-alpha.io:calendar_free_busy,gateway_config_read,commit_joint_change,cohort_aggregate_stats",
            host="127.0.0.1",
            port=0,
        )
        self.ca_beta = AutonomousDomainCAService(
            trust_domain="org-beta.io",
            allowed_k8s_namespace="lineage-beta",
            authorized_gateway_sa="beta-user-gateway",
            oidc_verifier=self.oidc_beta,
            federation_trust_resolver=self.resolver,
            authorized_auditors=auditors,
            consent_issuer_policy="assistant-bob=user:bob@org-beta.io:calendar_free_busy,service_diag_read,commit_joint_change,commit_negotiated_contract,cohort_aggregate_stats",
            host="127.0.0.1",
            port=0,
        )
        self.ca_pay = AutonomousDomainCAService(
            trust_domain="org-payment.io",
            allowed_k8s_namespace="lineage-pay",
            oidc_verifier=self.oidc_pay,
            federation_trust_resolver=self.resolver,
            authorized_auditors=auditors,
            consent_issuer_policy="assistant-carol=user:carol@org-payment.io:calendar_free_busy,sign_release,commit_joint_change,cohort_aggregate_stats",
            host="127.0.0.1",
            port=0,
        )
        for ca_s in (self.ca_alpha, self.ca_beta, self.ca_pay):
            ca_s.k8s_verifier = _StaticSAVerifier(self.sa_tokens)  # type: ignore[assignment]
            self.resolver.register_domain_ca(ca_s.ca)

        self.ca_alpha_url = self.ca_alpha.start()
        self.ca_beta_url = self.ca_beta.start()
        self.ca_pay_url = self.ca_pay.start()
        self.started.extend([self.ca_alpha, self.ca_beta, self.ca_pay])

        # Federated Revocation Mesh (bidirectional replication across all 3 domains)
        self.rev_alpha = RevocationService(
            self.ca_alpha.ca.issue_workload("/ns/sys/sa/revocation"),
            self.resolver,
            host="127.0.0.1",
            port=0,
        )
        self.rev_beta = RevocationService(
            self.ca_beta.ca.issue_workload("/ns/sys/sa/revocation"),
            self.resolver,
            host="127.0.0.1",
            port=0,
        )
        self.rev_pay = RevocationService(
            self.ca_pay.ca.issue_workload("/ns/sys/sa/revocation"),
            self.resolver,
            host="127.0.0.1",
            port=0,
        )
        self.rev_alpha_url = self.rev_alpha.start()
        self.rev_beta_url = self.rev_beta.start()
        self.rev_pay_url = self.rev_pay.start()
        self.started.extend([self.rev_alpha, self.rev_beta, self.rev_pay])

        self.rev_alpha.peer_revocation_urls = {
            "org-beta.io": self.rev_beta_url,
            "org-payment.io": self.rev_pay_url,
        }
        self.rev_beta.peer_revocation_urls = {
            "org-alpha.io": self.rev_alpha_url,
            "org-payment.io": self.rev_pay_url,
        }
        self.rev_pay.peer_revocation_urls = {
            "org-alpha.io": self.rev_alpha_url,
            "org-beta.io": self.rev_beta_url,
        }
        for rev_s in (self.rev_alpha, self.rev_beta, self.rev_pay):
            rev_s.strict_domain_isolation = True
            rev_s.start_federation_sync(interval_sec=0.08)

        self.rev_cli_alpha = RevocationReplicaClient(self.rev_alpha_url, self.resolver)
        self.rev_cli_beta = RevocationReplicaClient(self.rev_beta_url, self.resolver)
        self.rev_cli_pay = RevocationReplicaClient(self.rev_pay_url, self.resolver)

        # Untrusted Public Yellow Pages
        self.dir_svc = AgentDirectoryService(
            self.resolver,
            host="127.0.0.1",
            port=0,
            registry_mode="centralized",
        )
        self.dir_url = self.dir_svc.start()
        self.started.append(self.dir_svc)
        self.dir_cli = AgentDirectoryClient(self.dir_url, self.resolver)

        self.alpha_gw_id = self.ca_alpha.ca.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
        self.beta_gw_id = self.ca_beta.ca.issue_workload("/ns/lineage-beta/sa/beta-user-gateway")

        self.beta_gw = DomainUserGatewayService(
            identity=self.beta_gw_id,
            local_ca_url=self.ca_beta_url,
            sa_jwt_provider=lambda: "sa-beta-gw",
            oidc_verifier=self.oidc_beta,
            mtls_bundle=None,
            inbound_host="127.0.0.1",
            inbound_port=0,
            health_host="127.0.0.1",
            health_port=0,
        )
        self.beta_gw_url = self.beta_gw.start()
        self.started.append(self.beta_gw)

        # Spawn symmetric peer assistants + Shared-Vault
        self.alice_app, self.alice_sc, self.alice_card = self._spawn_peer(
            ca_svc=self.ca_alpha,
            rev_url=self.rev_alpha_url,
            sa_tok="sa-alice",
            ns="lineage-alpha",
            sa_name="assistant-alice",
            peer_name="alice",
            owner_sub="user:alice@org-alpha.io",
            skills=["workspace.orchestrate", "workspace.alice_private"],
            owner_protected=[
                "hr_salary_read",
                "calendar_write",
                "calendar_free_busy",
                "gateway_config_read",
                "alice_private_roadmap",
                "export_raw_patient_records",
            ],
            allowed_co_auth=[
                "calendar_free_busy",
                "gateway_config_read",
                "commit_joint_change",
                "cohort_aggregate_stats",
            ],
        )
        self.bob_app, self.bob_sc, self.bob_card = self._spawn_peer(
            ca_svc=self.ca_beta,
            rev_url=self.rev_beta_url,
            sa_tok="sa-bob",
            ns="lineage-beta",
            sa_name="assistant-bob",
            peer_name="bob",
            owner_sub="user:bob@org-beta.io",
            skills=["workspace.tech_review", "workspace.bob_private"],
            owner_protected=[
                "hr_salary_read",
                "calendar_write",
                "calendar_free_busy",
                "service_diag_read",
                "pricing_floor_read",
                "cohort_aggregate_stats",
                "export_raw_patient_records",
            ],
            allowed_co_auth=[
                "calendar_free_busy",
                "service_diag_read",
                "commit_joint_change",
                "commit_negotiated_contract",
                "cohort_aggregate_stats",
            ],
        )
        self.dave_app, self.dave_sc, self.dave_card = self._spawn_peer(
            ca_svc=self.ca_beta,
            rev_url=self.rev_beta_url,
            sa_tok="sa-dave",
            ns="lineage-beta",
            sa_name="assistant-dave",
            peer_name="dave",
            owner_sub="user:dave@org-beta.io",
            skills=["workspace.deep_analysis"],
            owner_protected=None,
            allowed_co_auth=None,
        )
        self.carol_app, self.carol_sc, self.carol_card = self._spawn_peer(
            ca_svc=self.ca_pay,
            rev_url=self.rev_pay_url,
            sa_tok="sa-carol",
            ns="lineage-pay",
            sa_name="assistant-carol",
            peer_name="carol",
            owner_sub="user:carol@org-payment.io",
            skills=["workspace.biz_procurement", "workspace.carol_private"],
            owner_protected=[
                "hr_salary_read",
                "calendar_write",
                "calendar_free_busy",
                "cohort_aggregate_stats",
                "export_raw_patient_records",
            ],
            allowed_co_auth=[
                "calendar_free_busy",
                "sign_release",
                "commit_joint_change",
                "cohort_aggregate_stats",
            ],
        )
        self.vault_app, self.vault_sc, self.vault_card = self._spawn_peer(
            ca_svc=self.ca_pay,
            rev_url=self.rev_pay_url,
            sa_tok="sa-vault",
            ns="lineage-pay",
            sa_name="assistant-vault",
            peer_name="vault",
            owner_sub="",
            skills=["workspace.vault_converge", "mcp.workspace-vault"],
            owner_protected=None,
            allowed_co_auth=None,
            is_vault=True,
        )

    def _spawn_peer(
        self,
        *,
        ca_svc: AutonomousDomainCAService,
        rev_url: str,
        sa_tok: str,
        ns: str,
        sa_name: str,
        peer_name: str,
        owner_sub: str,
        skills: List[str],
        owner_protected: Optional[List[str]],
        allowed_co_auth: Optional[List[str]],
        is_vault: bool = False,
    ) -> Tuple[Any, LineageSidecar, AgentCard]:
        wid = ca_svc.ca.issue_workload(f"/ns/{ns}/sa/{sa_name}")
        lsec = secrets.token_urlsafe(20)
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write(sa_tok)
            sa_file = tf.name
        self.temp_files.append(sa_file)

        rep = RevocationReplicaClient(rev_url, self.resolver)
        rep.start_background_sync(wait_ms=80)
        self.rep_clients.append(rep)
        em = AuditStreamEmitter(
            wid,
            collector_client=None,
            authorized_auditors=[self.alpha_gw_id.spiffe_id, self.beta_gw_id.spiffe_id],
        )
        sc = LineageSidecar(
            identity=wid,
            trust_resolver=self.resolver,
            app_upstream_url="http://127.0.0.1:1",
            loopback_secret=lsec,
            mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
            revocation_replica=rep,
            directory_client=self.dir_cli,
            audit_emitter=em,
            inbound_host="127.0.0.1",
            inbound_port=0,
            outbound_port=0,
            delegation_mode="dual",
            oauth_central_verifier=self.oidc_alpha,
            oauth_local_verifier=self.oidc_federated,
            oauth_exchange_client=self.oauth_cli,
            oauth_central_sts_origins_provider=lambda: [self.sts_url],
            oauth_domain_sts_origins_provider=lambda td: [self.sts_urls_by_domain.get(td, self.sts_url)],
            resource_owner_sub=(owner_sub if (owner_sub and owner_protected is not None) else None),
            owner_protected_tools=owner_protected,
            allowed_co_auth_tools=allowed_co_auth,
            local_ca_url=ca_svc.base_url,
            sa_token_path=sa_file,
        )
        in_u, out_u = sc.start()
        if is_vault:
            app: Any = WorkspaceVaultMCPApp(
                loopback_secret=lsec, outbound_proxy_url=out_u, ollama=None, port=0
            )
        else:
            app = WorkspaceAssistantPeerApp(
                peer_name=peer_name,
                owner_sub=owner_sub,
                outbound_proxy_url=out_u,
                loopback_secret=lsec,
                ollama=None,
                port=0,
            )
        app_u = app.start()
        sc.app_upstream_url = app_u.rstrip("/")
        card = AgentCard.sign_and_create(
            identity=wid,
            name=sa_name,
            endpoint=in_u,
            return_endpoint=in_u,
            skills=skills,
            priority=10,
        )
        sc.set_agent_card(card)
        self.dir_cli.register(card)
        self.started.extend([sc, app])
        return app, sc, card

    def login_user(self, username: str) -> Dict[str, Any]:
        home_td = DEFAULT_USER_HOME_DOMAINS.get(username, "org-alpha.io")
        return self.oauth_cli.login_user_password(
            sts_origins=self.sts_urls_by_domain[home_td],
            username=username,
            password=self.realm_bundle.user_passwords[username],
            client_id="lct-gateway",
        )

    def mint_alpha_root(
        self,
        task_id: str,
        sub: str,
        perms: PermissionLattice,
        target_card: AgentCard,
        user_oidc_token: str,
        hop_segment: str = "AssistantAlice",
    ) -> str:
        r = httpx.post(
            f"{self.ca_alpha_url}/v1/ca/mint-root-token",
            json={
                "trust_domain": "org-alpha.io",
                "task_id": task_id,
                "sub": sub,
                "sender_jkt": self.alpha_gw_id.jkt,
                "first_hop_spiffe_id": target_card.spiffe_id,
                "first_hop_jkt": target_card.jkt,
                "first_hop_public_jwk": target_card.public_jwk,
                "first_hop_return_endpoint": target_card.return_endpoint,
                "permissions": perms.to_dict(),
                "hop_segment": hop_segment,
                "user_oidc_token": user_oidc_token,
            },
            headers={"Authorization": "Bearer sa-alpha-gw"},
            timeout=5.0,
        )
        assert r.status_code == 200, (r.status_code, r.text)
        return str(r.json()["compact_token"])

    def post_lct(
        self,
        signer: Any,
        card: AgentCard,
        compact_tok: str,
        payload: Dict[str, Any],
        path: str = "/a2a/task",
    ) -> httpx.Response:
        url = f"{card.endpoint.rstrip('/')}{path}"
        dpop = create_dpop_proof(signer, "POST", url, compact_tok)
        return httpx.post(
            url,
            json=payload,
            headers={"Authorization": f"DPoP {compact_tok}", "DPoP": dpop},
            timeout=30.0,
        )

    def sync_revocations(self) -> None:
        self.rev_alpha.sync_from_federation_peers()
        self.rev_beta.sync_from_federation_peers()
        self.rev_pay.sync_from_federation_peers()
        for rc in self.rep_clients:
            rc.sync_now()

    def audit_task(
        self,
        task_id: str,
        entry_spiffe_ids: List[str],
        seed_domains: List[str],
        signer: Any = None,
    ) -> Any:
        aud = DistributedAuditor(
            trust_resolver=self.resolver,
            signer=(signer or self.alpha_gw_id),
            directory_client=self.dir_cli,
            domain_ca_urls={
                "org-alpha.io": self.ca_alpha_url,
                "org-beta.io": self.ca_beta_url,
                "org-payment.io": self.ca_pay_url,
            },
            trusted_revocation_spiffe_ids=[
                "spiffe://org-alpha.io/ns/sys/sa/revocation",
                "spiffe://org-beta.io/ns/sys/sa/revocation",
                "spiffe://org-payment.io/ns/sys/sa/revocation",
            ],
            allowed_locator_cidrs=["127.0.0.0/8", "10.0.0.0/8"],
        )
        return aud.pull_and_reconstruct(
            task_id=task_id,
            entry_spiffe_ids=entry_spiffe_ids,
            seed_domains=seed_domains,
        )

    def close(self) -> None:
        for rc in self.rep_clients:
            rc.stop_background_sync()
        for obj in reversed(self.started):
            try:
                obj.stop()
            except Exception:
                pass
        for f in self.temp_files:
            try:
                os.unlink(f)
            except OSError:
                pass
        if self._prev_fault_env is None:
            os.environ.pop("LCT_ENABLE_FAULT_INJECTION", None)
        else:
            os.environ["LCT_ENABLE_FAULT_INJECTION"] = self._prev_fault_env


class TestMilestone10ExpandedScenarios(unittest.TestCase):
    """Comprehensive Milestone 10 (Platform v2.1) unit & adversarial regression suite."""

    def test_01_manifest_invariants_oidc_multiorg_and_beta_user_gateway_mtls_hardening(self) -> None:
        # 1) Manifest least-privilege & symmetric owner isolation checks across alpha, beta, pay
        for role in ("alpha", "beta", "pay"):
            ports = allocate_role_ports(role, topology="workspace")
            man_txt = render_role_k8s_manifests(
                role=role,
                role_ports=ports,
                sts_engine=("keycloak" if role == "alpha" else "lightweight"),
                topology="workspace",
                registry_mode="centralized",
            )
            self.assertNotIn("AUTHORIZED_GATEWAY_SAS", man_txt)
            self.assertIn("CONSENT_ISSUER_POLICY", man_txt)
            docs = [d for d in yaml.safe_load_all(man_txt) if d]
            deps = {d["metadata"]["name"]: d for d in docs if d.get("kind") == "Deployment"}

            if role == "alpha":
                ca_env = {e["name"]: e["value"] for e in deps["alpha-ca"]["spec"]["template"]["spec"]["containers"][0]["env"]}
                self.assertEqual(ca_env["AUTHORIZED_GATEWAY_SA"], "e2e-user-gateway")
                self.assertIn("gateway_config_read", ca_env["CONSENT_ISSUER_POLICY"])
                self.assertNotIn("alice_private_roadmap", ca_env["CONSENT_ISSUER_POLICY"])
                self.assertNotIn("hr_salary_read", ca_env["CONSENT_ISSUER_POLICY"])
                alice_sc = deps["assistant-alice"]["spec"]["template"]["spec"]["containers"][1]
                a_env = {e["name"]: e["value"] for e in alice_sc["env"]}
                self.assertEqual(a_env["RESOURCE_OWNER_SUB"], "user:alice@org-alpha.io")
                self.assertIn("alice_private_roadmap", a_env["OWNER_PROTECTED_TOOLS"])
            elif role == "beta":
                self.assertIn("beta-user-gateway", deps)
                bgw_spec = deps["beta-user-gateway"]["spec"]["template"]["spec"]
                self.assertIs(bgw_spec["automountServiceAccountToken"], False)
                self.assertEqual(bgw_spec["securityContext"]["fsGroup"], 2000)
                ca_env = {e["name"]: e["value"] for e in deps["beta-ca"]["spec"]["template"]["spec"]["containers"][0]["env"]}
                self.assertEqual(ca_env["AUTHORIZED_GATEWAY_SA"], "beta-user-gateway")
                self.assertNotIn("assistant-bob", ca_env["AUTHORIZED_GATEWAY_SA"])
                self.assertIn("commit_negotiated_contract", ca_env["CONSENT_ISSUER_POLICY"])
                self.assertNotIn("pricing_floor_read", ca_env["CONSENT_ISSUER_POLICY"])
                self.assertNotIn("export_raw_patient_records", ca_env["CONSENT_ISSUER_POLICY"])
            else:
                ca_env = {e["name"]: e["value"] for e in deps["payment-ca"]["spec"]["template"]["spec"]["containers"][0]["env"]}
                self.assertNotIn("AUTHORIZED_GATEWAY_SA", ca_env)
                self.assertIn("sign_release", ca_env["CONSENT_ISSUER_POLICY"])
                self.assertNotIn("export_raw_patient_records", ca_env["CONSENT_ISSUER_POLICY"])

        # 2) SignedDomainDescriptor supports `"user_gateway"` with mandatory mTLS + SPIFFE ID
        ca_b = AutonomousDomainCAService(trust_domain="org-beta.io", allowed_k8s_namespace="lineage-beta", port=0)
        desc = SignedDomainDescriptor.sign_with_domain_ca(
            ca_b.ca,
            x509_root_pem=ca_b.x509_ca.export_root_pem(),
            locators={
                "ca_bundle": [ServiceLocator(transport="http-ro", host="10.29.101.203", port=31100)],
                "user_gateway": [
                    ServiceLocator(
                        transport="mtls-tcp",
                        host="10.29.101.203",
                        port=31107,
                        spiffe_id="spiffe://org-beta.io/ns/lineage-beta/sa/beta-user-gateway",
                    )
                ],
            },
            version=1,
        )
        self.assertEqual(len(desc.get_locators("user_gateway")), 1)

        # 3) Real mTLS 1.3 + Sovereign OIDC hardening on `DomainUserGatewayService`
        self.assertEqual(DEFAULT_USER_HOME_DOMAINS.get("dave"), "org-beta.io")
        ca_a = AutonomousDomainCAService(trust_domain="org-alpha.io", allowed_k8s_namespace="lineage-alpha", port=0)
        bundle = generate_keycloak_realm_bundle()
        sts_a = OAuthSTSService(
            trust_domain="org-alpha.io",
            realm=bundle.realm_name,
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
            host="127.0.0.1",
            port=0,
        )
        sts_b = OAuthSTSService(
            trust_domain="org-beta.io",
            realm=bundle.realm_name,
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
            host="127.0.0.1",
            port=0,
        )
        sts_p = OAuthSTSService(
            trust_domain="org-payment.io",
            realm=bundle.realm_name,
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
            host="127.0.0.1",
            port=0,
        )
        sts_a_u = sts_a.start()
        sts_b_u = sts_b.start()
        sts_p_u = sts_p.start()
        ca_b.oidc_verifier = OIDCTokenVerifier(
            jwks_urls=[f"{sts_b_u}/realms/lct/protocol/openid-connect/certs"],
            expected_issuer=f"{sts_b_u}/realms/lct",
            default_user_domain="org-beta.io",
            allowed_user_domains=("org-beta.io",),
            single_entity_issuers=True,
        )
        ca_b._authorized_gateway_sas = frozenset({"beta-user-gateway"})
        ca_b.k8s_verifier = _StaticSAVerifier({"sa-bgw": ("lineage-beta", "beta-user-gateway")})  # type: ignore[assignment]
        ca_b_u = ca_b.start()

        x509_store = X509FederationTrustStore()
        x509_store.register_domain_root_pem("org-alpha.io", ca_a.x509_ca.export_root_pem())
        x509_store.register_domain_root_pem("org-beta.io", ca_b.x509_ca.export_root_pem())

        bgw_id = ca_b.ca.issue_workload("/ns/lineage-beta/sa/beta-user-gateway")
        bgw_leaf = ca_b.x509_ca.issue_x509_svid(
            bgw_id.spiffe_id, bgw_id.keypair.public_jwk(), ip_addresses=("127.0.0.1",)
        )
        bgw_mtls = WorkloadMTLSBundle(bgw_id.spiffe_id, bgw_id.keypair, bgw_leaf, x509_store)

        agw_id = ca_a.ca.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
        agw_leaf = ca_a.x509_ca.issue_x509_svid(
            agw_id.spiffe_id, agw_id.keypair.public_jwk(), ip_addresses=("127.0.0.1",)
        )
        agw_mtls = WorkloadMTLSBundle(agw_id.spiffe_id, agw_id.keypair, agw_leaf, x509_store)

        rogue_id = ca_a.ca.issue_workload("/ns/lineage-alpha/sa/rogue-caller")
        rogue_leaf = ca_a.x509_ca.issue_x509_svid(
            rogue_id.spiffe_id, rogue_id.keypair.public_jwk(), ip_addresses=("127.0.0.1",)
        )
        rogue_mtls = WorkloadMTLSBundle(rogue_id.spiffe_id, rogue_id.keypair, rogue_leaf, x509_store)

        bob_w = ca_b.ca.issue_workload("/ns/lineage-beta/sa/assistant-bob")
        ugw = DomainUserGatewayService(
            identity=bgw_id,
            local_ca_url=ca_b_u,
            sa_jwt_provider=lambda: "sa-bgw",
            oidc_verifier=ca_b.oidc_verifier,
            mtls_bundle=bgw_mtls,
            inbound_host="127.0.0.1",
            inbound_port=0,
            health_port=-1,
        )
        ugw_u = ugw.start()
        try:
            ocli = OAuthTokenExchangeClient(realm="lct", client_secrets=bundle.client_secrets)
            alice_tok = ocli.login_user_password(sts_a_u, "alice", bundle.user_passwords["alice"], "lct-gateway")["access_token"]
            bob_tok = ocli.login_user_password(sts_b_u, "bob", bundle.user_passwords["bob"], "lct-gateway")["access_token"]
            dave_tok = ocli.login_user_password(sts_b_u, "dave", bundle.user_passwords["dave"], "lct-gateway")["access_token"]
            carol_tok = ocli.login_user_password(sts_p_u, "carol", bundle.user_passwords["carol"], "lct-gateway")["access_token"]

            with self.assertRaises(OAuthSTSError):
                ca_b.oidc_verifier.verify_jwt(alice_tok)
            with self.assertRaises(OAuthSTSError):
                ca_b.oidc_verifier.verify_jwt(carol_tok)
            self.assertEqual(ca_b.oidc_verifier.verify_jwt(bob_tok).canonical_lct_sub, "user:bob@org-beta.io")
            self.assertEqual(ca_b.oidc_verifier.verify_jwt(dave_tok).canonical_lct_sub, "user:dave@org-beta.io")

            mint_url = f"{ugw_u}/v1/gateway/mint-root"
            req_base = {
                "task_id": "t-ugw",
                "sub": "user:bob@org-beta.io",
                "first_hop_spiffe_id": bob_w.spiffe_id,
                "first_hop_jkt": bob_w.jkt,
                "permissions": PermissionLattice.create(tools=["service_diag_read"], max_calls=2).to_dict(),
            }
            # Unauthorized mTLS caller -> 403 MTLS_CALLER_UNAUTHORIZED
            with httpx.Client(verify=rogue_mtls.verify_for_target(mint_url, expected_spiffe_id=bgw_id.spiffe_id)) as c_rogue:
                r_unauth_peer = c_rogue.post(mint_url, json={**req_base, "user_oidc_token": bob_tok})
                self.assertEqual(r_unauth_peer.status_code, 403)
                self.assertEqual(r_unauth_peer.json()["error"], "MTLS_CALLER_UNAUTHORIZED")

            with httpx.Client(verify=agw_mtls.verify_for_target(mint_url, expected_spiffe_id=bgw_id.spiffe_id)) as c_ok:
                # Missing OIDC -> 401
                self.assertEqual(c_ok.post(mint_url, json=req_base).status_code, 401)
                # Foreign domain Alice OIDC from `alpha-sts` -> 401 INVALID_USER_OIDC_TOKEN (sovereign IdP isolation!)
                r_alice = c_ok.post(mint_url, json={**req_base, "sub": "user:alice@org-alpha.io", "user_oidc_token": alice_tok})
                self.assertEqual(r_alice.status_code, 401)
                self.assertEqual(r_alice.json()["error"], "INVALID_USER_OIDC_TOKEN")
                # Same-domain wrong principal (`dave_tok` claiming `sub="user:bob@org-beta.io"`) -> 403 GATEWAY_PRINCIPAL_DOMAIN_MISMATCH
                r_dave_spoof = c_ok.post(mint_url, json={**req_base, "sub": "user:bob@org-beta.io", "user_oidc_token": dave_tok})
                self.assertEqual(r_dave_spoof.status_code, 403)
                self.assertEqual(r_dave_spoof.json()["error"], "GATEWAY_PRINCIPAL_DOMAIN_MISMATCH")
                # Spoofed / foreign sender_jkt (`agw_id.jkt` or `bob_w.jkt`) -> 403 SENDER_JKT_MISMATCH
                for bad_jkt in (agw_id.jkt, bob_w.jkt):
                    r_jkt = c_ok.post(mint_url, json={**req_base, "user_oidc_token": bob_tok, "sender_jkt": bad_jkt})
                    self.assertEqual(r_jkt.status_code, 403)
                    self.assertEqual(r_jkt.json()["error"], "SENDER_JKT_MISMATCH")
                # Valid Bob OIDC -> 200 (strictly bound to `bgw_id.jkt`)
                r_valid = c_ok.post(mint_url, json={**req_base, "user_oidc_token": bob_tok})
                self.assertEqual(r_valid.status_code, 200)
                self.assertEqual(r_valid.json()["sub"], "user:bob@org-beta.io")
        finally:
            ugw.stop()
            ca_b.stop()
            sts_a.stop()
            sts_b.stop()
            sts_p.stop()
            bgw_mtls.cleanup()
            agw_mtls.cleanup()
            rogue_mtls.cleanup()

    def test_02_s2_financial_risk_bidirectional_pingpong_and_revocation_interlock(self) -> None:
        mesh = _MultiDomainWorkspaceMesh()
        try:
            alice_jwt = mesh.login_user("alice")["access_token"]
            bob_jwt = mesh.login_user("bob")["access_token"]
            tid = "task-m10-s2-pingpong"

            tok_a = mesh.mint_alpha_root(
                tid,
                "user:alice@org-alpha.io",
                PermissionLattice.create(
                    tools=["service_diag_read", "commit_joint_change"],
                    param_whitelist={"change_id": ["FIN-RULE-42"]},
                    max_calls=10,
                ),
                mesh.alice_card,
                alice_jwt,
            )
            # Round 1: A -> B unilateral 403, CoAuth([alice, bob]) 200
            self.assertEqual(
                mesh.post_lct(mesh.alpha_gw_id, mesh.alice_card, tok_a, {"op": "probe_peer_private_resource", "target_tool": "service_diag_read"}).status_code,
                403,
            )
            r1 = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_a,
                {"op": "request_peer_co_auth_and_read", "target_tool": "service_diag_read", "owner_oidc_token": bob_jwt},
            )
            self.assertEqual(r1.status_code, 200, r1.text)
            self.assertEqual(
                r1.json()["upstream_body"]["result"]["data"]["co_authorized_principals"],
                ["user:alice@org-alpha.io", "user:bob@org-beta.io"],
            )

            # Round 2: Reverse B -> A (dual-OAuth A2A JSON-RPC 403 + LCT unilateral 403 + roadmap refusal 403 + reverse CoAuth([bob, alice]) 200)
            ex_bob = mesh.oauth_cli.exchange_token(
                sts_origins=mesh.sts_beta_url,
                subject_token=bob_jwt,
                target_audience=mesh.alice_card.spiffe_id,
                client_id="lct-gateway",
            )
            r_oauth_b2a = httpx.post(
                f"{mesh.alice_card.endpoint}/a2a",
                json={
                    "jsonrpc": "2.0",
                    "id": "oauth-r2",
                    "method": "message/send",
                    "params": {
                        "message": {
                            "role": "ROLE_USER",
                            "parts": [{"data": {"private_tool": "gateway_config_read"}}],
                        }
                    },
                },
                headers={"Authorization": f"Bearer {ex_bob.access_token}", "X-LCT-Delegation-Mode": "oauth_federated"},
            )
            self.assertEqual(r_oauth_b2a.status_code, 403)
            self.assertEqual(r_oauth_b2a.json()["error"], "CROSS_PRINCIPAL_DENIED")

            r_b2a = httpx.post(
                f"{mesh.beta_gw_url}/v1/gateway/dispatch",
                json={
                    "task_id": f"{tid}-b2a",
                    "sub": "user:bob@org-beta.io",
                    "user_oidc_token": bob_jwt,
                    "first_hop_spiffe_id": mesh.bob_card.spiffe_id,
                    "first_hop_jkt": mesh.bob_card.jkt,
                    "permissions": PermissionLattice.create(tools=["gateway_config_read", "alice_private_roadmap"], max_calls=6).to_dict(),
                    "target_endpoint": mesh.bob_card.endpoint,
                    "payload": {"op": "reverse_pingpong_inspect_alpha", "alice_oidc_token": alice_jwt},
                },
                timeout=20.0,
            )
            self.assertEqual(r_b2a.status_code, 200, r_b2a.text)
            b2a_d = r_b2a.json()["upstream_body"]
            self.assertEqual(b2a_d["unilateral_gateway_config_http"], 403)
            self.assertEqual(b2a_d["roadmap_consent_refusal_http"], 403)
            self.assertEqual(
                b2a_d["reverse_coauth_gateway_config"]["co_authorized_principals"],
                ["user:bob@org-beta.io", "user:alice@org-alpha.io"],
            )

            # Round 3: Vault commit_joint_change (403 unilateral -> 200 CoAuth -> 409 conflict -> Bob revoke -> 403 interlock)
            self.assertEqual(
                mesh.post_lct(
                    mesh.alpha_gw_id,
                    mesh.alice_card,
                    tok_a,
                    {"op": "call_mcp_with_wallet", "tool_name": "commit_joint_change", "arguments": {"change_id": "FIN-RULE-42"}},
                ).status_code,
                403,
            )
            r_mc = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_a,
                {
                    "op": "request_peer_co_auth_and_read",
                    "target_tool": "commit_joint_change",
                    "consent_tools": ["commit_joint_change"],
                    "consent_param_whitelist": {"change_id": ["FIN-RULE-42"]},
                    "owner_oidc_token": bob_jwt,
                    "cache_consent_key": "chg42",
                    "mint_consent_only": True,
                },
            )
            self.assertEqual(r_mc.status_code, 200, r_mc.text)
            consent_pfx = r_mc.json()["consent_lineage_path"]

            r_cm = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_a,
                {
                    "op": "call_mcp_with_wallet",
                    "use_consent_key": "chg42",
                    "tool_name": "commit_joint_change",
                    "arguments": {"change_id": "FIN-RULE-42", "risk_rule_digest": "sha256:v1"},
                    "idempotency_key": "idem-chg42",
                },
            )
            self.assertEqual(r_cm.status_code, 200, r_cm.text)
            r_conf = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_a,
                {
                    "op": "call_mcp_with_wallet",
                    "use_consent_key": "chg42",
                    "tool_name": "commit_joint_change",
                    "arguments": {"change_id": "FIN-RULE-42", "risk_rule_digest": "sha256:v2-conflict"},
                    "idempotency_key": "idem-chg42",
                },
            )
            self.assertEqual(r_conf.status_code, 409)

            # Revoke Bob's beta consent prefix -> subsequent CoAuth commit fails 403!
            r_rev = httpx.post(
                f"{mesh.beta_gw_url}/v1/gateway/dispatch",
                json={
                    "task_id": f"{tid}-rev",
                    "sub": "user:bob@org-beta.io",
                    "user_oidc_token": bob_jwt,
                    "first_hop_spiffe_id": mesh.bob_card.spiffe_id,
                    "first_hop_jkt": mesh.bob_card.jkt,
                    "permissions": PermissionLattice.create(tools=["service_diag_read"], max_calls=2).to_dict(),
                    "target_endpoint": mesh.bob_card.endpoint,
                    "payload": {"op": "revoke_own_consent", "target_task_id": tid, "prefix": consent_pfx},
                },
                timeout=15.0,
            )
            self.assertEqual(r_rev.status_code, 200, r_rev.text)
            mesh.sync_revocations()

            r_after = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_a,
                {
                    "op": "call_mcp_with_wallet",
                    "use_consent_key": "chg42",
                    "tool_name": "commit_joint_change",
                    "arguments": {"change_id": "FIN-RULE-42", "risk_rule_digest": "sha256:v3"},
                    "idempotency_key": "idem-chg42-new",
                },
            )
            self.assertEqual(r_after.status_code, 403)

            aud = mesh.audit_task(tid, [mesh.alice_card.spiffe_id], ["org-alpha.io", "org-beta.io", "org-payment.io"])
            self.assertTrue(aud.reconstructed_complete)
            self.assertEqual(aud.unreachable_nodes, {})
        finally:
            mesh.close()

    def test_03_s3_legal_redline_subdelegation_and_lattice_numeric_guardrails(self) -> None:
        mesh = _MultiDomainWorkspaceMesh()
        try:
            alice_jwt = mesh.login_user("alice")["access_token"]
            bob_jwt = mesh.login_user("bob")["access_token"]
            tid = "task-m10-s3-legal"

            tok_a = mesh.mint_alpha_root(
                tid,
                "user:alice@org-alpha.io",
                PermissionLattice.create(
                    tools=["legal_redline_review", "commit_negotiated_contract"],
                    numeric_bounds={"unit_price_usd": 120.0, "max_penalty_pct": 10.0},
                    param_whitelist={"contract_id": ["NDA-2026-99"], "warranty_tier": ["24M", "36M"]},
                    max_calls=12,
                ),
                mesh.alice_card,
                alice_jwt,
            )
            r_rl = mesh.post_lct(mesh.alpha_gw_id, mesh.alice_card, tok_a, {"op": "bob_relay_legal_redline", "contract_id": "NDA-2026-99"})
            self.assertEqual(r_rl.status_code, 200, r_rl.text)
            self.assertEqual(r_rl.json()["pricing_floor_probe_http"], 403)

            r_sc = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_a,
                {
                    "op": "request_peer_co_auth_and_read",
                    "target_tool": "commit_negotiated_contract",
                    "consent_tools": ["commit_negotiated_contract"],
                    "consent_numeric_bounds": {"unit_price_usd": 200.0, "max_penalty_pct": 12.0},
                    "consent_param_whitelist": {"contract_id": ["NDA-2026-99"], "warranty_tier": ["12M", "24M", "36M"]},
                    "owner_oidc_token": bob_jwt,
                    "cache_consent_key": "nda99",
                    "mint_consent_only": True,
                },
            )
            self.assertEqual(r_sc.status_code, 200, r_sc.text)

            # Breaching numeric_bounds (165 > 120) or param_whitelist (12M) -> 403 LATTICE_PERMISSION_DENIED
            r_b1 = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_a,
                {
                    "op": "call_mcp_with_wallet",
                    "use_consent_key": "nda99",
                    "tool_name": "commit_negotiated_contract",
                    "arguments": {"contract_id": "NDA-2026-99", "warranty_tier": "24M", "unit_price_usd": 165.0, "max_penalty_pct": 8.0},
                },
            )
            self.assertEqual(r_b1.status_code, 403)
            r_b2 = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_a,
                {
                    "op": "call_mcp_with_wallet",
                    "use_consent_key": "nda99",
                    "tool_name": "commit_negotiated_contract",
                    "arguments": {"contract_id": "NDA-2026-99", "warranty_tier": "12M", "unit_price_usd": 115.0, "max_penalty_pct": 8.0},
                },
            )
            self.assertEqual(r_b2.status_code, 403)

            # Compliant -> 200
            r_ok = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_a,
                {
                    "op": "call_mcp_with_wallet",
                    "use_consent_key": "nda99",
                    "tool_name": "commit_negotiated_contract",
                    "arguments": {"contract_id": "NDA-2026-99", "warranty_tier": "24M", "unit_price_usd": 115.0, "max_penalty_pct": 8.0},
                },
            )
            self.assertEqual(r_ok.status_code, 200, r_ok.text)
            aud = mesh.audit_task(tid, [mesh.alice_card.spiffe_id], ["org-alpha.io", "org-beta.io", "org-payment.io"])
            self.assertTrue(aud.reconstructed_complete)
        finally:
            mesh.close()

    def test_04_s5_compliance_release_sod_and_signed_scanner_attestation(self) -> None:
        mesh = _MultiDomainWorkspaceMesh()
        try:
            alice_jwt = mesh.login_user("alice")["access_token"]
            carol_jwt = mesh.login_user("carol")["access_token"]
            tid = "task-m10-s5-sod"

            tok_a = mesh.mint_alpha_root(
                tid,
                "user:alice@org-alpha.io",
                PermissionLattice.create(
                    tools=["sast_scan", "sign_release"],
                    param_whitelist={"release_id": ["REL-2026-884", "REL-2026-999"]},
                    max_calls=12,
                ),
                mesh.alice_card,
                alice_jwt,
            )
            r_scan = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_a,
                {"op": "sast_scan_pipeline", "release_id": "REL-2026-884", "artifact_sha256": "sha256:abc884"},
            )
            self.assertEqual(r_scan.status_code, 200, r_scan.text)
            att_jws = r_scan.json()["attestation_jws"]

            # Self-approve without Carol -> 403 DUAL_APPROVAL_REQUIRED
            self.assertEqual(
                mesh.post_lct(
                    mesh.alpha_gw_id,
                    mesh.alice_card,
                    tok_a,
                    {"op": "call_mcp_with_wallet", "tool_name": "sign_release", "arguments": {"release_id": "REL-2026-884", "compliance_attestation_jws": att_jws}},
                ).status_code,
                403,
            )

            # Obtain Carol consent via pay-ca
            r_cc = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_a,
                {
                    "op": "request_peer_co_auth_and_read",
                    "target_tool": "sign_release",
                    "target_peer_skill": "workspace.biz_procurement",
                    "consent_tools": ["sign_release"],
                    "consent_param_whitelist": {"release_id": ["REL-2026-884", "REL-2026-999"]},
                    "owner_oidc_token": carol_jwt,
                    "cache_consent_key": "carol-rel",
                    "mint_consent_only": True,
                },
            )
            self.assertEqual(r_cc.status_code, 200, r_cc.text)

            # Forged attestation signed by non-scanner workload (`assistant-bob` instead of `assistant-dave`) -> 403!
            now_f = time.time()
            forged_att = jws_sign_compact(
                {
                    "jti": "forged-1",
                    "issuer_spiffe_id": mesh.bob_sc.identity.spiffe_id,
                    "issuer_jwk": mesh.bob_sc.identity.public_jwk(),
                    "issuer_svid": mesh.bob_sc.identity.workload_svid,
                    "task_id": tid,
                    "release_id": "REL-2026-884",
                    "artifact_sha256": "sha256:evil",
                    "scan_passed": True,
                    "iat": now_f,
                    "exp": now_f + 300.0,
                },
                mesh.bob_sc.identity.keypair,
                typ="lct-compliance-attestation+jwt",
            )
            r_forged = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_a,
                {
                    "op": "call_mcp_with_wallet",
                    "use_consent_key": "carol-rel",
                    "tool_name": "sign_release",
                    "arguments": {"release_id": "REL-2026-884", "compliance_attestation_jws": forged_att},
                },
            )
            self.assertEqual(r_forged.status_code, 403)
            self.assertEqual(r_forged.json()["upstream_body"]["error"], "MISSING_OR_INVALID_COMPLIANCE_ATTESTATION")

            # Mismatched release_id -> 403
            r_mis = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_a,
                {
                    "op": "call_mcp_with_wallet",
                    "use_consent_key": "carol-rel",
                    "tool_name": "sign_release",
                    "arguments": {"release_id": "REL-2026-999", "compliance_attestation_jws": att_jws},
                },
            )
            self.assertEqual(r_mis.status_code, 403)

            # Valid SoD release -> 200
            r_ok = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_a,
                {
                    "op": "call_mcp_with_wallet",
                    "use_consent_key": "carol-rel",
                    "tool_name": "sign_release",
                    "arguments": {"release_id": "REL-2026-884", "compliance_attestation_jws": att_jws},
                },
            )
            self.assertEqual(r_ok.status_code, 200, r_ok.text)
            self.assertTrue(r_ok.json()["upstream_body"]["result"]["data"]["sod_verified"])
            aud = mesh.audit_task(tid, [mesh.alice_card.spiffe_id], ["org-alpha.io", "org-beta.io", "org-payment.io"])
            self.assertTrue(aud.reconstructed_complete)
        finally:
            mesh.close()

    def test_05_s6_healthcare_federated_cohort_and_cross_task_replay_defense(self) -> None:
        mesh = _MultiDomainWorkspaceMesh()
        try:
            alice_jwt = mesh.login_user("alice")["access_token"]
            bob_jwt = mesh.login_user("bob")["access_token"]
            carol_jwt = mesh.login_user("carol")["access_token"]
            tid = "task-m10-s6-med"
            study_id = "STUDY-MED-2026-07"

            tok_med = mesh.mint_alpha_root(
                tid,
                "user:alice@org-alpha.io",
                PermissionLattice.create(
                    tools=["cohort_aggregate_stats", "export_raw_patient_records", "federated_cohort_aggregate"],
                    param_whitelist={"study_id": [study_id]},
                    max_calls=14,
                ),
                mesh.alice_card,
                alice_jwt,
            )
            self.assertEqual(
                mesh.post_lct(mesh.alpha_gw_id, mesh.alice_card, tok_med, {"op": "probe_peer_private_resource", "target_tool": "export_raw_patient_records"}).status_code,
                403,
            )
            self.assertEqual(
                mesh.post_lct(
                    mesh.alpha_gw_id,
                    mesh.alice_card,
                    tok_med,
                    {"op": "probe_peer_private_resource", "target_tool": "export_raw_patient_records", "target_peer_mcp": "skill://workspace.carol_private"},
                ).status_code,
                403,
            )

            rb = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_med,
                {
                    "op": "request_peer_co_auth_and_read",
                    "target_tool": "cohort_aggregate_stats",
                    "target_peer_skill": "workspace.tech_review",
                    "target_peer_mcp": "skill://workspace.bob_private",
                    "consent_param_whitelist": {"study_id": [study_id]},
                    "arguments": {"study_id": study_id},
                    "owner_oidc_token": bob_jwt,
                    "cache_consent_key": "bob-med",
                },
            )
            rc = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_med,
                {
                    "op": "request_peer_co_auth_and_read",
                    "target_tool": "cohort_aggregate_stats",
                    "target_peer_skill": "workspace.biz_procurement",
                    "target_peer_mcp": "skill://workspace.carol_private",
                    "consent_param_whitelist": {"study_id": [study_id]},
                    "arguments": {"study_id": study_id},
                    "owner_oidc_token": carol_jwt,
                    "handshake_hop_segment": "CarolMedHandshake",
                },
            )
            self.assertEqual(rb.status_code, 200, rb.text)
            self.assertEqual(rc.status_code, 200, rc.text)
            dig_b = rb.json()["upstream_body"]["result"]["data"]
            dig_c = rc.json()["upstream_body"]["result"]["data"]

            # Raw PII injection rejected by aggregator -> 403 RAW_PII_REJECTED_BY_AGGREGATOR
            r_pii = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_med,
                {
                    "op": "call_mcp_with_wallet",
                    "tool_name": "federated_cohort_aggregate",
                    "arguments": {"study_id": study_id, "cohort_digests": [{**dig_b, "raw_pii_present": True}, dig_c]},
                },
            )
            self.assertEqual(r_pii.status_code, 403)
            self.assertEqual(r_pii.json()["upstream_body"]["error"], "RAW_PII_REJECTED_BY_AGGREGATOR")

            r_agg = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_med,
                {
                    "op": "call_mcp_with_wallet",
                    "tool_name": "federated_cohort_aggregate",
                    "arguments": {"study_id": study_id, "cohort_digests": [dig_b, dig_c]},
                },
            )
            self.assertEqual(r_agg.status_code, 200, r_agg.text)
            self.assertEqual(r_agg.json()["upstream_body"]["result"]["data"]["institutions_aggregated"], 2)

            # Cross-task commercial replay -> 403!
            tok_comm = mesh.mint_alpha_root(
                "task-m10-s6-commercial",
                "user:alice@org-alpha.io",
                PermissionLattice.create(tools=["cohort_aggregate_stats"], param_whitelist={"study_id": ["STUDY-COMMERCIAL-99"]}, max_calls=4),
                mesh.alice_card,
                alice_jwt,
            )
            r_xtask = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_comm,
                {
                    "op": "call_mcp_with_wallet",
                    "target_mcp": "skill://workspace.bob_private",
                    "use_consent_key": "bob-med",
                    "tool_name": "cohort_aggregate_stats",
                    "arguments": {"study_id": "STUDY-COMMERCIAL-99"},
                },
            )
            self.assertEqual(r_xtask.status_code, 403)
            aud = mesh.audit_task(tid, [mesh.alice_card.spiffe_id], ["org-alpha.io", "org-beta.io", "org-payment.io"])
            self.assertTrue(aud.reconstructed_complete)
        finally:
            mesh.close()

    def test_06_s7_and_s8_prompt_injection_cascade_revocation_beta_entry_and_token_theft(self) -> None:
        mesh = _MultiDomainWorkspaceMesh()
        try:
            alice_jwt = mesh.login_user("alice")["access_token"]
            bob_jwt = mesh.login_user("bob")["access_token"]

            # --- Part A: Catalog S7 (4-Hop Indirect Prompt Injection + Cascading Subtree Revocation) ---
            tid_s7 = "task-m10-s7-inj"
            tok_s7 = mesh.mint_alpha_root(
                tid_s7,
                "user:alice@org-alpha.io",
                PermissionLattice.create(
                    tools=["reserve_cloud_budget", "procure_vendor_quote", "query_operation_status", "record_compliance_note", "lock_joint_project"],
                    max_amount=700.0,
                    allowed_targets=["cloud-infra-escrow", "vendor-procurement-escrow", "compliance-ledger"],
                    param_whitelist={"project_code": ["PRJ-AUDIT"]},
                    max_calls=16,
                ),
                mesh.alice_card,
                alice_jwt,
            )
            r_fan = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_s7,
                {"op": "prompt_injection_audit_fanout", "project_code": "PRJ-AUDIT", "cache_key": tid_s7},
            )
            self.assertEqual(r_fan.status_code, 200, r_fan.text)
            bob_pfx = r_fan.json()["branch_bob_dave"]["hop2_lineage_path"]
            d_hop3 = r_fan.json()["branch_bob_dave"]["dave_hop3"]
            self.assertEqual(d_hop3["legitimate_note_http"], 200)
            self.assertEqual(d_hop3["injected_budget_escalation_http"], 403)
            self.assertEqual(d_hop3["injected_param_exfil_http"], 403)

            mesh.rev_cli_alpha.revoke_prefix(
                caller=mesh.alpha_gw_id,
                prefix=bob_pfx,
                reason="compromised_bob_subtree",
                authority_token=tok_s7,
            )
            mesh.sync_revocations()

            # Both Hop-2 (`bob`) and pre-minted Hop-3 (`dave`) tokens fail 403!
            tok_ctl_b = mint_root_token(
                mesh.ca_beta.ca, "ctl-b", "user:bob@org-beta.io", mesh.beta_gw_id.jkt,
                mesh.bob_card.spiffe_id, mesh.bob_card.jkt,
                PermissionLattice.create(tools=["query_operation_status"], max_calls=2),
            ).encode_compact()
            tok_ctl_d = mint_root_token(
                mesh.ca_beta.ca, "ctl-d", "user:dave@org-beta.io", mesh.beta_gw_id.jkt,
                mesh.dave_card.spiffe_id, mesh.dave_card.jkt,
                PermissionLattice.create(tools=["record_compliance_note"], max_calls=2),
            ).encode_compact()
            self.assertEqual(
                mesh.post_lct(
                    mesh.beta_gw_id, mesh.bob_card, tok_ctl_b,
                    {"op": "replay_cached_pre_revocation_token", "cache_key": f"{tid_s7}:bob-hop2", "tool_name": "query_operation_status", "arguments": {"idempotency_key": "x"}},
                ).status_code,
                403,
            )
            r_d_rep = mesh.post_lct(
                mesh.beta_gw_id, mesh.dave_card, tok_ctl_d,
                {"op": "replay_cached_pre_revocation_token", "cache_key": f"{tid_s7}:dave-hop3", "tool_name": "record_compliance_note", "arguments": {"project_code": "PRJ-AUDIT", "note": "after-revoke"}},
            )
            self.assertEqual(r_d_rep.status_code, 403)
            self.assertEqual(r_d_rep.json()["upstream_body"]["error"], "LINEAGE_REVOKED")

            r_deg = mesh.post_lct(mesh.alpha_gw_id, mesh.alice_card, tok_s7, {"op": "trigger_converged_project_lock", "project_code": "PRJ-AUDIT"})
            self.assertEqual(r_deg.status_code, 200, r_deg.text)
            lo = r_deg.json()["upstream_body"]["lock_outcomes"]
            self.assertEqual(lo["cloud-infra-escrow"]["http_status"], 403)
            self.assertEqual(lo["vendor-procurement-escrow"]["http_status"], 200)

            # --- Part B: Catalog S8 (Symmetric `org-beta` Entry + Stolen-Token Replay 403 + Cross-Tenant Isolation) ---
            tid_s8 = "task-m10-s8-sym"
            bob_perms = PermissionLattice.create(
                tools=["gateway_config_read", "record_compliance_note", "procure_vendor_quote", "query_operation_status"],
                max_amount=300.0,
                allowed_targets=["compliance-ledger", "vendor-procurement-escrow"],
                param_whitelist={"project_code": ["PRJ-BETA-SYM"]},
                max_calls=12,
            )
            r_sym = httpx.post(
                f"{mesh.beta_gw_url}/v1/gateway/dispatch",
                json={
                    "task_id": tid_s8,
                    "sub": "user:bob@org-beta.io",
                    "user_oidc_token": bob_jwt,
                    "first_hop_spiffe_id": mesh.bob_card.spiffe_id,
                    "first_hop_jkt": mesh.bob_card.jkt,
                    "hop_segment": "CoordinatorBob",
                    "permissions": bob_perms.to_dict(),
                    "target_endpoint": mesh.bob_card.endpoint,
                    "payload": {"op": "bob_symmetric_orchestrate", "project_code": "PRJ-BETA-SYM", "alice_oidc_token": alice_jwt},
                },
                timeout=30.0,
            )
            self.assertEqual(r_sym.status_code, 200, r_sym.text)
            bob_idem = r_sym.json()["upstream_body"]["bob_branch_idempotency_key"]

            # Stolen token replay by `alpha_gw_id` against `Shared-Vault` & `Assistant-A` -> 403!
            r_st = httpx.post(
                f"{mesh.beta_gw_url}/v1/gateway/mint-root",
                json={
                    "task_id": f"{tid_s8}-stolen",
                    "sub": "user:bob@org-beta.io",
                    "user_oidc_token": bob_jwt,
                    "first_hop_spiffe_id": mesh.bob_card.spiffe_id,
                    "first_hop_jkt": mesh.bob_card.jkt,
                    "permissions": bob_perms.to_dict(),
                },
                timeout=10.0,
            )
            self.assertEqual(r_st.status_code, 200)
            stolen_tok = r_st.json()["compact_token"]
            self.assertEqual(
                mesh.post_lct(
                    mesh.alpha_gw_id, mesh.vault_card, stolen_tok,
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "procure_vendor_quote", "arguments": {"project_code": "PRJ-BETA-SYM", "amount": 50.0}}},
                    path="/mcp",
                ).status_code,
                403,
            )
            self.assertEqual(
                mesh.post_lct(
                    mesh.alpha_gw_id, mesh.alice_card, stolen_tok,
                    {"private_tool": "gateway_config_read"},
                    path="/a2a/task",
                ).status_code,
                403,
            )

            # Cross-tenant Vault isolation: Alice querying Bob's idempotency_key -> found=False!
            tok_alice_q = mesh.mint_alpha_root(
                f"{tid_s8}-snoop",
                "user:alice@org-alpha.io",
                PermissionLattice.create(tools=["query_operation_status"], max_calls=3),
                mesh.vault_card,
                alice_jwt,
            )
            r_snoop = mesh.post_lct(
                mesh.alpha_gw_id, mesh.vault_card, tok_alice_q,
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "query_operation_status", "arguments": {"idempotency_key": bob_idem}}},
                path="/mcp",
            )
            self.assertEqual(r_snoop.status_code, 200)
            self.assertFalse(r_snoop.json()["result"]["data"]["found"])

            # DistributedAuditor starting purely from `entry_spiffe_ids=[bob_card.spiffe_id]` (`org-beta.io`)!
            aud_s8 = mesh.audit_task(tid_s8, [mesh.bob_card.spiffe_id], ["org-beta.io"])
            self.assertTrue(aud_s8.reconstructed_complete)
            self.assertEqual(aud_s8.unreachable_nodes, {})
            self.assertEqual(aud_s8.anomalies, [])
        finally:
            mesh.close()

    def test_07_m10_round2_qa_security_remediations(self) -> None:
        """Verify all 7 Milestone 10 Round-1 QA findings are deterministically remediated."""
        mesh = _MultiDomainWorkspaceMesh()
        try:
            alice_jwt = mesh.login_user("alice")["access_token"]
            bob_jwt = mesh.login_user("bob")["access_token"]
            carol_jwt = mesh.login_user("carol")["access_token"]

            # 1) [CRITICAL-M10-01]: Per-issuer JWKS key binding & multi-issuer unqualified principal defense
            spoofed_beta_iss, _ = mesh.sts_alpha._mint_jwt(
                issuer=f"{mesh.sts_beta_url}/realms/lct",
                sub="spoof-bob",
                preferred_username="bob",
                aud="lct-gateway",
                azp="lct-gateway",
                scope="openid",
                lct_sub="user:bob@org-beta.io",
            )
            with self.assertRaises(OAuthSTSError):
                mesh.oidc_federated.verify_jwt(spoofed_beta_iss)

            unmapped_multi = OIDCTokenVerifier(
                jwks_urls=[
                    mesh.oauth_cli.jwks_endpoint(mesh.sts_url),
                    mesh.oauth_cli.jwks_endpoint(mesh.sts_beta_url),
                ],
                allowed_issuers=[
                    f"{mesh.sts_url}/realms/lct",
                    f"{mesh.sts_beta_url}/realms/lct",
                ],
                default_user_domain="org-beta.io",
            )
            unqual_alpha, _ = mesh.sts_alpha._mint_jwt(
                issuer=f"{mesh.sts_url}/realms/lct",
                sub="op-1",
                preferred_username="operator",
                aud="lct-gateway",
                azp="lct-gateway",
                scope="openid",
                lct_sub=None,
            )
            with self.assertRaises(OAuthSTSError):
                unmapped_multi.verify_jwt(unqual_alpha)

            # 2) [HIGH-M10-01]: `(sub, key)` + `task_id` isolated `_consent_wallet` & foreign `revoke_own_consent` 403
            tid_w = "task-r2-wallet"
            tok_alice = mesh.mint_alpha_root(
                tid_w,
                "user:alice@org-alpha.io",
                PermissionLattice.create(tools=["service_diag_read", "commit_joint_change"], max_calls=8),
                mesh.alice_card,
                alice_jwt,
            )
            r_mint_w = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_alice,
                {
                    "op": "request_peer_co_auth_and_read",
                    "target_tool": "commit_joint_change",
                    "consent_tools": ["commit_joint_change"],
                    "owner_oidc_token": bob_jwt,
                    "cache_consent_key": "shared-k",
                    "mint_consent_only": True,
                },
            )
            self.assertEqual(r_mint_w.status_code, 200)
            self.assertNotIn("shared-k", mesh.alice_app._consent_wallet)
            self.assertIn(("user:alice@org-alpha.io", "shared-k"), mesh.alice_app._consent_wallet)
            consent_pfx = r_mint_w.json()["consent_lineage_path"]

            # Foreign principal (`user:alice@org-alpha.io`) cannot steal or revoke Bob's consent via `revoke_own_consent`!
            tok_foreign_rev = mesh.mint_alpha_root(
                "task-r2-foreign-rev",
                "user:alice@org-alpha.io",
                PermissionLattice.create(tools=["commit_joint_change"], max_calls=2),
                mesh.bob_card,
                alice_jwt,
            )
            r_for_rev = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.bob_card,
                tok_foreign_rev,
                {"op": "revoke_own_consent", "target_task_id": tid_w, "prefix": consent_pfx},
            )
            self.assertEqual(r_for_rev.status_code, 403)
            self.assertEqual(r_for_rev.json()["error"], "FORBIDDEN_FOREIGN_CONSENT_REVOCATION")

            # Foreign principal (`user:bob@org-beta.io`) calling `call_mcp_with_wallet("shared-k")` on Alice -> 403!
            r_bob_steal_w = httpx.post(
                f"{mesh.beta_gw_url}/v1/gateway/dispatch",
                json={
                    "task_id": tid_w,
                    "sub": "user:bob@org-beta.io",
                    "user_oidc_token": bob_jwt,
                    "first_hop_spiffe_id": mesh.alice_card.spiffe_id,
                    "first_hop_jkt": mesh.alice_card.jkt,
                    "permissions": PermissionLattice.create(tools=["commit_joint_change"], max_calls=2).to_dict(),
                    "target_endpoint": mesh.alice_card.endpoint,
                    "payload": {
                        "op": "call_mcp_with_wallet",
                        "use_consent_key": "shared-k",
                        "tool_name": "commit_joint_change",
                        "arguments": {"change_id": "FIN-RULE-99"},
                    },
                },
            )
            self.assertEqual(r_bob_steal_w.status_code, 403)
            self.assertEqual(r_bob_steal_w.json()["upstream_body"]["error"], "CROSS_TENANT_OR_TASK_CONSENT_DENIED")

            # 3) [HIGH-M10-02]: Omitted constrained arguments rejected offline by `PermissionLattice.check_invocation`!
            strict_lat = PermissionLattice.create(
                tools=["reserve_cloud_budget", "commit_negotiated_contract"],
                max_amount=10.0,
                numeric_bounds={"unit_price_usd": 50.0, "max_penalty_pct": 2.0},
                allowed_targets=["compliance-ledger"],
                param_whitelist={
                    "project_code": ["PRJ-RESTRICTED"],
                    "contract_id": ["NDA-RESTRICTED"],
                    "warranty_tier": ["36M"],
                },
                max_calls=5,
            )
            self.assertFalse(strict_lat.check_invocation("tools/call", "reserve_cloud_budget", arguments={})[0])
            self.assertFalse(strict_lat.check_invocation("tools/call", "commit_negotiated_contract", arguments={})[0])

            # 4) [HIGH-M10-03]: Cross-domain `/sa/assistant-dave` SVID lookalike & replayed `jti` rejected!
            rogue_alpha_dave = mesh.ca_alpha.ca.issue_workload("/ns/lineage-alpha/sa/assistant-dave")
            now_ts = time.time()
            forged_att = jws_sign_compact(
                {
                    "jti": "att-rogue-1",
                    "issuer_spiffe_id": rogue_alpha_dave.spiffe_id,
                    "issuer_jwk": rogue_alpha_dave.public_jwk(),
                    "issuer_svid": rogue_alpha_dave.workload_svid,
                    "task_id": "t-r2-sod",
                    "release_id": "REL-2026-884",
                    "artifact_sha256": "sha256:rogue",
                    "scan_passed": True,
                    "iat": now_ts,
                    "exp": now_ts + 300.0,
                },
                rogue_alpha_dave.keypair,
                typ="lct-compliance-attestation+jwt",
            )
            r_rogue_att = httpx.post(
                f"{mesh.vault_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "verify_compliance_attestation",
                    "attestation_jws": forged_att,
                    "expected_task_id": "t-r2-sod",
                    "expected_release_id": "REL-2026-884",
                    "allowed_scanner_suffix": "/sa/assistant-dave",
                },
                headers={"X-LCT-Loopback-Auth": mesh.vault_app.loopback_secret},
            )
            self.assertEqual(r_rogue_att.status_code, 403)

            valid_dave_att = jws_sign_compact(
                {
                    "jti": "att-dave-replay-check",
                    "issuer_spiffe_id": mesh.dave_sc.identity.spiffe_id,
                    "issuer_jwk": mesh.dave_sc.identity.public_jwk(),
                    "issuer_svid": mesh.dave_sc.identity.workload_svid,
                    "task_id": "t-r2-sod",
                    "release_id": "REL-2026-884",
                    "artifact_sha256": "sha256:ok",
                    "scan_passed": True,
                    "iat": now_ts,
                    "exp": now_ts + 300.0,
                },
                mesh.dave_sc.identity.keypair,
                typ="lct-compliance-attestation+jwt",
            )
            r_att_1 = httpx.post(
                f"{mesh.vault_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "verify_compliance_attestation",
                    "attestation_jws": valid_dave_att,
                    "expected_task_id": "t-r2-sod",
                    "expected_release_id": "REL-2026-884",
                },
                headers={"X-LCT-Loopback-Auth": mesh.vault_app.loopback_secret},
            )
            self.assertEqual(r_att_1.status_code, 200)
            r_att_replay = httpx.post(
                f"{mesh.vault_sc.outbound_url}/v1/proxy/call",
                json={
                    "action": "verify_compliance_attestation",
                    "attestation_jws": valid_dave_att,
                    "expected_task_id": "t-r2-sod",
                    "expected_release_id": "REL-2026-884",
                },
                headers={"X-LCT-Loopback-Auth": mesh.vault_app.loopback_secret},
            )
            self.assertEqual(r_att_replay.status_code, 403)

            # 5) [MEDIUM-M10-02]: `DomainUserGatewayService` SSRF & malformed token return 400/403 (never 500)!
            r_ssrf = httpx.post(
                f"{mesh.beta_gw_url}/v1/gateway/dispatch",
                json={
                    "task_id": "t-ssrf",
                    "sub": "user:bob@org-beta.io",
                    "user_oidc_token": bob_jwt,
                    "first_hop_spiffe_id": mesh.bob_card.spiffe_id,
                    "first_hop_jkt": mesh.bob_card.jkt,
                    "permissions": PermissionLattice.create(tools=["service_diag_read"], max_calls=2).to_dict(),
                    "target_endpoint": "http://8.8.8.8:8080",
                    "payload": {},
                },
            )
            self.assertEqual(r_ssrf.status_code, 403)
            self.assertEqual(r_ssrf.json()["error"], "FORBIDDEN_DISPATCH_TARGET")

            r_https_nomtls = httpx.post(
                f"{mesh.beta_gw_url}/v1/gateway/dispatch",
                json={
                    "task_id": "t-https-nomtls",
                    "sub": "user:bob@org-beta.io",
                    "user_oidc_token": bob_jwt,
                    "first_hop_spiffe_id": mesh.bob_card.spiffe_id,
                    "first_hop_jkt": mesh.bob_card.jkt,
                    "permissions": PermissionLattice.create(tools=["service_diag_read"], max_calls=2).to_dict(),
                    "target_endpoint": "https://10.29.101.203:31103",
                    "payload": {},
                },
            )
            self.assertEqual(r_https_nomtls.status_code, 400)

            r_bad_tok = httpx.post(
                f"{mesh.beta_gw_url}/v1/gateway/dispatch",
                json={
                    "sub": "user:bob@org-beta.io",
                    "user_oidc_token": bob_jwt,
                    "compact_token": "malformed-not-lct",
                    "target_endpoint": mesh.bob_card.endpoint,
                    "payload": {},
                },
            )
            self.assertEqual(r_bad_tok.status_code, 403)
            self.assertEqual(r_bad_tok.json()["error"], "INVALID_GATEWAY_ROOT_TOKEN")

            # 6) [LOW-M10-01]: Unsigned / forged `cohort_digests` rejected (`403 INVALID_COHORT_DIGEST_SIGNATURE`)!
            tid_cd = "task-r2-cohort-sig"
            tok_cd = mesh.mint_alpha_root(
                tid_cd,
                "user:alice@org-alpha.io",
                PermissionLattice.create(
                    tools=["cohort_aggregate_stats", "federated_cohort_aggregate"],
                    param_whitelist={"study_id": ["STUDY-R2"]},
                    max_calls=8,
                ),
                mesh.alice_card,
                alice_jwt,
            )
            r_db = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_cd,
                {
                    "op": "request_peer_co_auth_and_read",
                    "target_tool": "cohort_aggregate_stats",
                    "consent_tools": ["cohort_aggregate_stats"],
                    "consent_param_whitelist": {"study_id": ["STUDY-R2"]},
                    "arguments": {"study_id": "STUDY-R2"},
                    "owner_oidc_token": bob_jwt,
                },
            )
            self.assertEqual(r_db.status_code, 200)
            dig_b = r_db.json()["upstream_body"]["result"]["data"]
            self.assertTrue(bool(dig_b.get("digest_jws")))
            forged_c = {**dig_b, "institution": "institution-fake-c"}
            forged_c.pop("digest_jws", None)
            r_forged_cd = mesh.post_lct(
                mesh.alpha_gw_id,
                mesh.alice_card,
                tok_cd,
                {
                    "op": "call_mcp_with_wallet",
                    "tool_name": "federated_cohort_aggregate",
                    "arguments": {"study_id": "STUDY-R2", "cohort_digests": [dig_b, forged_c]},
                },
            )
            self.assertEqual(r_forged_cd.status_code, 403)
            self.assertEqual(
                r_forged_cd.json()["upstream_body"]["error"],
                "INVALID_COHORT_DIGEST_SIGNATURE",
            )
            _ = carol_jwt
        finally:
            mesh.close()


if __name__ == "__main__":
    unittest.main()
