"""Milestone 8 Unit & Adversarial Tests: OAuth 2.0 RFC 8693 Token Exchange,
Real Keycloak 26.5.2 Realm/Manifests, Hop-0 OIDC -> LCT Bridge, & Dual-Mode Sidecar Contrast.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, List, Tuple
import unittest

import httpx
import yaml

from lineage.common.crypto import KeyPair, compute_jwk_thumbprint, jws_parse_unverified, jws_sign_compact
from lineage.common.http_utils import HTTPRequestContext
from lineage.common.locators import ServiceLocator
from lineage.federation.anchors import (
    TrustAnchorPinStore,
    compute_bundle_trust_anchor,
)
from lineage.federation.domain_ca import AutonomousDomainCAService, K8sServiceAccountVerifier
from lineage.federation.locators import DomainDescriptorStore, SignedDomainDescriptor
from lineage.identity.spiffe import TrustDomainCA
from lineage.identity.trust_bundle import TrustBundleResolver
from lineage.k8s.bootstrap_services import create_ca_pop_jws
from lineage.multihost.config_gen import render_role_k8s_manifests
from lineage.multihost.lct_multihost_cli import build_cli_parser, format_m8_comparison_markdown
from lineage.oauth_sts import (
    CLIENT_ASSERTION_JWT_SPIFFE,
    DEFAULT_REALM_NAME,
    GRANT_TOKEN_EXCHANGE,
    KEYCLOAK_IMAGE,
    OAuthSTSError,
    OAuthSTSService,
    OAuthTokenExchangeClient,
    OIDCTokenVerifier,
    TOKEN_TYPE_ACCESS,
    generate_keycloak_realm_bundle,
)
from lineage.protocol.dpop import create_dpop_proof
from lineage.protocol.lattice import PermissionLattice
from lineage.protocol.token import decode_token, mint_root_token
from lineage.sidecar.proxy import AgentSidecarNode, MCPToolSidecarNode


class _InMemoryK8sSAVerifier(K8sServiceAccountVerifier):
    """Real RS256 K8s ServiceAccount JWT verifier for pure-Python CA tests."""

    def __init__(self) -> None:
        self.kp = KeyPair.generate("RS256")
        jwk = self.kp.public_jwk()
        super().__init__(allowed_audiences=("lct-federation-ca",))
        self._keys_by_kid = {jwk["kid"]: jwk}
        self._last_refresh = time.time()

    def _refresh_jwks(self) -> None:
        jwk = self.kp.public_jwk()
        with self._lock:
            self._keys_by_kid = {jwk["kid"]: jwk}
            self._last_refresh = time.time()

    def sign_sa_jwt(self, namespace: str, sa_name: str, ttl_sec: float = 600.0) -> str:
        now = time.time()
        return jws_sign_compact(
            {
                "iss": "https://kubernetes.default.svc.cluster.local",
                "sub": f"system:serviceaccount:{namespace}:{sa_name}",
                "aud": ["lct-federation-ca"],
                "iat": now,
                "exp": now + ttl_sec,
                "kubernetes.io": {
                    "namespace": namespace,
                    "serviceaccount": {"name": sa_name, "uid": "uid-1"},
                },
            },
            self.kp,
            typ="JWT",
        )


class Milestone8OAuthAndCompareTests(unittest.TestCase):
    # -------------------------------------------------------------------------
    # 1. Centralized RFC 8693 Multi-Hop `act` Nesting, Scope Subsetting & Revoke
    # -------------------------------------------------------------------------
    def test_01_rfc8693_oauth_centralized_multihop_act_nesting_scope_subsetting_and_revoke(
        self,
    ) -> None:
        bundle = generate_keycloak_realm_bundle()
        sts = OAuthSTSService(
            trust_domain="org-alpha.io",
            realm=bundle.realm_name,
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
        )
        sts_url = sts.start()
        try:
            disc = httpx.get(
                f"{sts_url}/realms/{DEFAULT_REALM_NAME}/.well-known/openid-configuration",
                timeout=5.0,
            )
            self.assertEqual(disc.status_code, 200)
            self.assertIn(GRANT_TOKEN_EXCHANGE, disc.json()["grant_types_supported"])

            cli = OAuthTokenExchangeClient(
                realm=bundle.realm_name,
                client_secrets=bundle.client_secrets,
            )
            verifier = OIDCTokenVerifier(
                jwks_urls=[cli.jwks_endpoint(sts_url)],
                expected_issuer=f"{sts_url}/realms/{DEFAULT_REALM_NAME}",
            )

            # Hop 0: Alice human login
            login_res = cli.login_user_password(
                sts_origins=sts_url,
                username="alice",
                password=bundle.user_passwords["alice"],
                client_id="lct-gateway",
            )
            t0 = login_res["access_token"]
            v0 = verifier.verify_jwt(t0, expected_audience="orchestrator-alpha")
            self.assertEqual(v0.canonical_lct_sub, "user:alice@org-alpha.io")
            self.assertIn("travel:book", v0.scopes)
            self.assertIn("travel:pay", v0.scopes)

            # Hop 1: Gateway -> OrchestratorAlpha
            ex1 = cli.exchange_token(
                sts_origins=sts_url,
                subject_token=t0,
                target_audience="spiffe://org-alpha.io/ns/lineage-alpha/sa/orchestrator-alpha",
                client_id="lct-gateway",
            )
            # Hop 2: OrchestratorAlpha -> FlightSpecialist (narrowing scope to `travel:book`)
            ex2 = cli.exchange_token(
                sts_origins=sts_url,
                subject_token=ex1.access_token,
                target_audience="spiffe://org-beta.io/ns/lineage-beta/sa/flight-specialist",
                client_id="orchestrator-alpha",
                requested_scope="travel:book",
            )
            # Hop 3: FlightSpecialist -> TravelOpsMCP
            ex3 = cli.exchange_token(
                sts_origins=sts_url,
                subject_token=ex2.access_token,
                target_audience="spiffe://org-payment.io/ns/lineage-pay/sa/travel-ops-mcp",
                client_id="flight-specialist",
            )
            v3 = verifier.verify_jwt(
                ex3.access_token,
                expected_audience="travel-ops-mcp",
                required_scopes=["travel:book"],
            )
            self.assertEqual(v3.scopes, ("travel:book",))
            self.assertEqual(
                v3.act,
                {
                    "sub": "flight-specialist",
                    "act": {
                        "sub": "orchestrator-alpha",
                        "act": {"sub": "lct-gateway"},
                    },
                },
            )

            # Scope escalation attempt (`travel:pay` from `ex2` which only holds `travel:book`) -> 400!
            with self.assertRaises(OAuthSTSError) as ctx_esc:
                cli.exchange_token(
                    sts_origins=sts_url,
                    subject_token=ex2.access_token,
                    target_audience="payment-vault-mcp",
                    client_id="flight-specialist",
                    requested_scope="travel:pay",
                )
            self.assertIn("invalid_scope", str(ctx_esc.exception))

            # Unsupported `subject_token_type` -> 400 `invalid_request`
            r_bad_type = httpx.post(
                cli.token_endpoint(sts_url),
                data={
                    "grant_type": GRANT_TOKEN_EXCHANGE,
                    "client_id": "lct-gateway",
                    "client_secret": bundle.client_secrets["lct-gateway"],
                    "subject_token": t0,
                    "subject_token_type": "urn:ietf:params:oauth:token-type:saml2",
                },
                timeout=5.0,
            )
            self.assertEqual(r_bad_type.status_code, 400)
            self.assertEqual(r_bad_type.json()["error"], "invalid_request")

            # RFC 7662 Introspection (`active=True`) -> RFC 7009 Revocation -> `active=False` & exchange rejected!
            r_int_before = httpx.post(
                f"{sts_url}/realms/{DEFAULT_REALM_NAME}/protocol/openid-connect/introspect",
                data={
                    "client_id": "lct-gateway",
                    "client_secret": bundle.client_secrets["lct-gateway"],
                    "token": ex1.access_token,
                },
                timeout=5.0,
            )
            self.assertTrue(r_int_before.json()["active"])

            cli.revoke_token(
                sts_origin=sts_url,
                token=ex1.access_token,
                client_id="lct-gateway",
            )
            r_int_after = httpx.post(
                f"{sts_url}/realms/{DEFAULT_REALM_NAME}/protocol/openid-connect/introspect",
                data={
                    "client_id": "lct-gateway",
                    "client_secret": bundle.client_secrets["lct-gateway"],
                    "token": ex1.access_token,
                },
                timeout=5.0,
            )
            self.assertFalse(r_int_after.json()["active"])
            with self.assertRaises(OAuthSTSError) as ctx_rev:
                cli.exchange_token(
                    sts_origins=sts_url,
                    subject_token=ex1.access_token,
                    target_audience="flight-specialist",
                    client_id="orchestrator-alpha",
                )
            self.assertIn("subject_token_revoked", str(ctx_rev.exception))
        finally:
            sts.stop()

    # -------------------------------------------------------------------------
    # 2. Federated 3-Org STS Relay with Pinned SPIFFE `JWT-SVID` Assertions
    # -------------------------------------------------------------------------
    def test_02_rfc8693_oauth_federated_three_org_relay_with_spiffe_assertions(
        self,
    ) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        ca_pay = TrustDomainCA("org-payment.io")
        ca_evil = TrustDomainCA("org-evil.io")

        resolver = TrustBundleResolver()
        for ca in (ca_alpha, ca_beta, ca_pay):
            resolver.register_bundle(ca.export_public_bundle())

        bundle = generate_keycloak_realm_bundle()
        peer_urls_box: Dict[str, List[str]] = {"beta": [], "pay": []}

        sts_alpha = OAuthSTSService(
            trust_domain="org-alpha.io",
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
            spiffe_trust_resolver=resolver,
        )
        sts_beta = OAuthSTSService(
            trust_domain="org-beta.io",
            spiffe_trust_resolver=resolver,
            peer_sts_jwks_Urls_provider=lambda: peer_urls_box["beta"],
        )
        sts_pay = OAuthSTSService(
            trust_domain="org-payment.io",
            spiffe_trust_resolver=resolver,
            peer_sts_jwks_Urls_provider=lambda: peer_urls_box["pay"],
        )
        u_alpha = sts_alpha.start()
        u_beta = sts_beta.start()
        u_pay = sts_pay.start()
        try:
            cli = OAuthTokenExchangeClient(client_secrets={"lct-gateway": bundle.client_secrets["lct-gateway"]})
            peer_urls_box["beta"] = [cli.jwks_endpoint(u_alpha)]
            peer_urls_box["pay"] = [cli.jwks_endpoint(u_beta), cli.jwks_endpoint(u_alpha)]

            orch_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/orchestrator-alpha")
            flight_id = ca_beta.issue_workload("/ns/lineage-beta/sa/flight-specialist")
            evil_id = ca_evil.issue_workload("/ns/evil/sa/attacker")

            # Hop 0 at Alpha STS
            login_res = cli.login_user_password(
                sts_origins=u_alpha,
                username="alice",
                password=bundle.user_passwords["alice"],
                client_id="lct-gateway",
            )
            t0_alpha = login_res["access_token"]

            # Cross-org Hop 1: OrchestratorAlpha (`org-alpha.io`) -> Beta STS (`org-beta.io`) using SPIFFE SVID ONLY!
            ex_beta = cli.exchange_token(
                sts_origins=u_beta,
                subject_token=t0_alpha,
                target_audience="spiffe://org-beta.io/ns/lineage-beta/sa/flight-specialist",
                caller_spiffe_id=orch_id.spiffe_id,
                caller_workload_svid=orch_id.workload_svid,
            )
            # Cross-org Hop 2: FlightSpecialist (`org-beta.io`) -> Payment STS (`org-payment.io`) using SPIFFE SVID ONLY!
            ex_pay = cli.exchange_token(
                sts_origins=u_pay,
                subject_token=ex_beta.access_token,
                target_audience="spiffe://org-payment.io/ns/lineage-pay/sa/travel-ops-mcp",
                caller_spiffe_id=flight_id.spiffe_id,
                caller_workload_svid=flight_id.workload_svid,
            )

            pay_verifier = OIDCTokenVerifier(
                jwks_urls=[cli.jwks_endpoint(u_pay)],
                expected_issuer=f"{u_pay}/realms/{DEFAULT_REALM_NAME}",
            )
            verified_pay = pay_verifier.verify_jwt(
                ex_pay.access_token,
                expected_audience="travel-ops-mcp",
            )
            self.assertEqual(verified_pay.canonical_lct_sub, "user:alice@org-alpha.io")
            self.assertEqual(
                verified_pay.act,
                {
                    "sub": flight_id.spiffe_id,
                    "act": {"sub": orch_id.spiffe_id},
                },
            )

            # Adversarial: Unpinned `org-evil.io` SPIFFE SVID assertion MUST fail 401!
            r_evil = httpx.post(
                cli.token_endpoint(u_beta),
                data={
                    "grant_type": GRANT_TOKEN_EXCHANGE,
                    "subject_token": t0_alpha,
                    "subject_token_type": TOKEN_TYPE_ACCESS,
                    "audience": "flight-specialist",
                    "client_assertion_type": CLIENT_ASSERTION_JWT_SPIFFE,
                    "client_assertion": evil_id.workload_svid,
                },
                timeout=5.0,
            )
            self.assertEqual(r_evil.status_code, 401)

            # Adversarial: Token signed by unknown RSA key MUST fail 400!
            rogue_rsa = KeyPair.generate("RS256")
            forged_subj = jws_sign_compact(
                {
                    "iss": f"{u_alpha}/realms/lct",
                    "sub": "admin",
                    "aud": "flight-specialist",
                    "scope": "travel:book travel:pay",
                    "iat": int(time.time()),
                    "exp": int(time.time()) + 600,
                },
                rogue_rsa,
                typ="JWT",
            )
            with self.assertRaises(OAuthSTSError) as ctx_forged:
                cli.exchange_token(
                    sts_origins=u_beta,
                    subject_token=forged_subj,
                    target_audience="flight-specialist",
                    caller_spiffe_id=orch_id.spiffe_id,
                    caller_workload_svid=orch_id.workload_svid,
                )
            self.assertIn("unknown_signing_kid", str(ctx_forged.exception))
        finally:
            sts_alpha.stop()
            sts_beta.stop()
            sts_pay.stop()

    # -------------------------------------------------------------------------
    # 3. Hop-0 OIDC/Keycloak RS256 Bridge into LCT `RootBlock` `B_0`
    # -------------------------------------------------------------------------
    def test_03_hop0_oidc_user_token_bridge_into_lct_root_block_and_rejections(
        self,
    ) -> None:
        bundle = generate_keycloak_realm_bundle()
        sts = OAuthSTSService(
            trust_domain="org-alpha.io",
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
        )
        sts_url = sts.start()
        k8s_ver = _InMemoryK8sSAVerifier()
        oidc_ver = OIDCTokenVerifier(
            jwks_urls=[f"{sts_url}/realms/{DEFAULT_REALM_NAME}/protocol/openid-connect/certs"],
            allowed_issuers=[f"{sts_url}/realms/{DEFAULT_REALM_NAME}"],
            default_user_domain="org-alpha.io",
        )
        ca_svc = AutonomousDomainCAService(
            trust_domain="org-alpha.io",
            allowed_k8s_namespace="lineage-alpha",
            authorized_gateway_sa="e2e-user-gateway",
            k8s_verifier=k8s_ver,
            oidc_verifier=oidc_ver,
            host="127.0.0.1",
            port=0,
        )
        ca_url = ca_svc.start()
        try:
            gw_sa_jwt = k8s_ver.sign_sa_jwt("lineage-alpha", "e2e-user-gateway")
            gw_kp = KeyPair.generate("ES256")
            orch_kp = KeyPair.generate("ES256")
            perms = PermissionLattice.create(
                tools=["search_flight", "book_flight"],
                max_amount=650.0,
                allowed_targets=["airline-escrow"],
                param_whitelist={"city": ["Tokyo"]},
                max_calls=4,
            )

            cli = OAuthTokenExchangeClient(client_secrets=bundle.client_secrets)
            login_alice = cli.login_user_password(
                sts_origins=sts_url,
                username="alice",
                password=bundle.user_passwords["alice"],
                client_id="lct-gateway",
            )

            def _mint_call(extra_fields: Dict[str, Any]) -> httpx.Response:
                base_req = {
                    "trust_domain": "org-alpha.io",
                    "task_id": f"task-bridge-{int(time.time() * 1000)}",
                    "sender_jkt": gw_kp.jkt,
                    "first_hop_spiffe_id": "spiffe://org-alpha.io/ns/lineage-alpha/sa/orchestrator-alpha",
                    "first_hop_jkt": orch_kp.jkt,
                    "permissions": perms.to_dict(),
                    **extra_fields,
                }
                return httpx.post(
                    f"{ca_url}/v1/ca/mint-root-token",
                    json=base_req,
                    headers={"Authorization": f"Bearer {gw_sa_jwt}"},
                    timeout=5.0,
                )

            # (A) Valid Hop-0 `user_oidc_token` bridges `user:alice@org-alpha.io` into `RootBlock` `B_0`!
            r_ok = _mint_call({"user_oidc_token": login_alice["id_token"]})
            self.assertEqual(r_ok.status_code, 200, r_ok.text)
            meta_ok = r_ok.json()
            self.assertTrue(meta_ok["hop0_oidc_bridged"])
            self.assertEqual(meta_ok["sub"], "user:alice@org-alpha.io")
            parsed_lct = decode_token(meta_ok["compact_token"])
            self.assertEqual(parsed_lct.sub, "user:alice@org-alpha.io")

            # (B) Backward compatibility: omitting `user_oidc_token` still works when `require_oidc_user_token=False`
            r_legacy = _mint_call({"sub": "user:bob@org-alpha.io"})
            self.assertEqual(r_legacy.status_code, 200, r_legacy.text)
            self.assertFalse(r_legacy.json()["hop0_oidc_bridged"])
            self.assertNotIn("oidc_bridge", r_legacy.json())

            # (C) Subject spoofing (`sub="user:bob@org-alpha.io"` + Alice's OIDC token) -> 403!
            r_mismatch = _mint_call(
                {
                    "sub": "user:bob@org-alpha.io",
                    "user_oidc_token": login_alice["id_token"],
                }
            )
            self.assertEqual(r_mismatch.status_code, 403)
            self.assertEqual(r_mismatch.json()["error"], "oidc_sub_mismatch")

            # (D) Tampered OIDC JWT signature -> 401!
            parts = login_alice["id_token"].split(".")
            tampered_payload = base64.urlsafe_b64encode(
                json.dumps({"iss": f"{sts_url}/realms/lct", "sub": "admin", "exp": int(time.time()) + 600}).encode()
            ).decode().rstrip("=")
            tampered_jwt = f"{parts[0]}.{tampered_payload}.{parts[2]}"
            r_tampered = _mint_call({"user_oidc_token": tampered_jwt})
            self.assertEqual(r_tampered.status_code, 401)
            self.assertEqual(r_tampered.json()["error"], "invalid_user_oidc_token")

            # (E) Expired OIDC JWT -> 401!
            exp_jwt = jws_sign_compact(
                {
                    "iss": f"{sts_url}/realms/lct",
                    "sub": "alice",
                    "preferred_username": "alice",
                    "aud": "lct-gateway",
                    "iat": int(time.time()) - 900,
                    "exp": int(time.time()) - 60,
                },
                sts.keypair,
                typ="JWT",
            )
            r_exp = _mint_call({"user_oidc_token": exp_jwt})
            self.assertEqual(r_exp.status_code, 401)
            self.assertIn("oidc_token_expired", r_exp.json()["detail"])

            # (F) Wrong issuer signed by same key -> 401!
            bad_iss_jwt = jws_sign_compact(
                {
                    "iss": "https://evil-idp.example/realms/lct",
                    "sub": "alice",
                    "preferred_username": "alice",
                    "aud": "lct-gateway",
                    "iat": int(time.time()),
                    "exp": int(time.time()) + 600,
                },
                sts.keypair,
                typ="JWT",
            )
            r_bad_iss = _mint_call({"user_oidc_token": bad_iss_jwt})
            self.assertEqual(r_bad_iss.status_code, 401)
            self.assertIn("oidc_issuer_not_allowed", r_bad_iss.json()["detail"])
        finally:
            ca_svc.stop()
            sts.stop()

    # -------------------------------------------------------------------------
    # 4. Dual-Mode `LineageSidecar` Empirical Contrast (OAuth vs. LCT)
    # -------------------------------------------------------------------------
    def test_04_dual_mode_sidecar_overprivilege_audience_and_zero_rtt_attenuation(
        self,
    ) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        ca_pay = TrustDomainCA("org-payment.io")
        resolver = TrustBundleResolver()
        for ca in (ca_alpha, ca_beta, ca_pay):
            resolver.register_bundle(ca.export_public_bundle())

        bundle = generate_keycloak_realm_bundle()
        sts_urls: Dict[str, str] = {}

        sts_alpha = OAuthSTSService(
            trust_domain="org-alpha.io",
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
            spiffe_trust_resolver=resolver,
        )
        sts_beta = OAuthSTSService(
            trust_domain="org-beta.io",
            spiffe_trust_resolver=resolver,
            peer_sts_jwks_Urls_provider=lambda: [
                f"{sts_urls['org-alpha.io']}/realms/lct/protocol/openid-connect/certs"
            ],
        )
        sts_pay = OAuthSTSService(
            trust_domain="org-payment.io",
            spiffe_trust_resolver=resolver,
            peer_sts_jwks_Urls_provider=lambda: [
                f"{sts_urls['org-beta.io']}/realms/lct/protocol/openid-connect/certs",
                f"{sts_urls['org-alpha.io']}/realms/lct/protocol/openid-connect/certs",
            ],
        )
        sts_urls["org-alpha.io"] = sts_alpha.start()
        sts_urls["org-beta.io"] = sts_beta.start()
        sts_urls["org-payment.io"] = sts_pay.start()

        gw_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
        orch_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/orchestrator-alpha")
        flight_id = ca_beta.issue_workload("/ns/lineage-beta/sa/flight-specialist")
        mcp_id = ca_pay.issue_workload("/ns/lineage-pay/sa/travel-ops-mcp")

        ex_cli = OAuthTokenExchangeClient(client_secrets=bundle.client_secrets)
        central_ver = OIDCTokenVerifier(
            jwks_urls=[ex_cli.jwks_endpoint(sts_urls["org-alpha.io"])],
            allowed_issuers=[f"{sts_urls['org-alpha.io']}/realms/lct"],
        )
        ver_by_td = {
            td: OIDCTokenVerifier(
                jwks_urls=[ex_cli.jwks_endpoint(u)],
                allowed_issuers=[f"{u}/realms/lct"],
            )
            for td, u in sts_urls.items()
        }

        mcp_node = MCPToolSidecarNode(
            identity=mcp_id,
            trust_resolver=resolver,
            tools={
                "book_flight": lambda args, _req: {
                    "booked": True,
                    "city": args["city"],
                    "charged_usd": float(args["amount"]),
                }
            },
            delegation_mode="dual",
            oauth_central_verifier=central_ver,
            oauth_local_verifier=ver_by_td["org-payment.io"],
        )
        mcp_url = mcp_node.start()

        def _flight_handler(
            node: AgentSidecarNode, req: HTTPRequestContext, body: Dict[str, Any]
        ) -> Tuple[int, Dict[str, Any]]:
            req_id = str(req.header("X-LCT-Request-Id", ""))
            return node.sidecar_call_tool(
                request_id=req_id,
                target_mcp_url=f"{mcp_url}/mcp",
                tool_name="book_flight",
                arguments={"city": body["attempt_city"], "amount": body["attempt_amount"]},
                target_spiffe_id=mcp_id.spiffe_id,
                target_trust_domain="org-payment.io",
            )

        flight_node = AgentSidecarNode(
            identity=flight_id,
            trust_resolver=resolver,
            name="Flight Specialist",
            skills=["travel.flight"],
            handler=_flight_handler,
            delegation_mode="dual",
            oauth_central_verifier=central_ver,
            oauth_local_verifier=ver_by_td["org-beta.io"],
            oauth_exchange_client=ex_cli,
            oauth_central_sts_origins_provider=lambda: [sts_urls["org-alpha.io"]],
            oauth_domain_sts_origins_provider=lambda td: [sts_urls[td]],
        )
        flight_card = flight_node.start(register_in_directory=False)

        def _orch_handler(
            node: AgentSidecarNode, req: HTTPRequestContext, body: Dict[str, Any]
        ) -> Tuple[int, Dict[str, Any]]:
            req_id = str(req.header("X-LCT-Request-Id", ""))
            att_perms = PermissionLattice.create(
                tools=["book_flight"],
                max_amount=650.0,
                allowed_targets=["airline-escrow"],
                param_whitelist={"city": ["Tokyo"]},
                max_calls=2,
            )
            return node.sidecar_delegate(
                request_id=req_id,
                permissions=att_perms,
                payload=body,
                target_card=flight_card,
            )

        orch_node = AgentSidecarNode(
            identity=orch_id,
            trust_resolver=resolver,
            name="Orchestrator Alpha",
            skills=["travel.orchestrate"],
            handler=_orch_handler,
            delegation_mode="dual",
            oauth_central_verifier=central_ver,
            oauth_local_verifier=ver_by_td["org-alpha.io"],
            oauth_exchange_client=ex_cli,
            oauth_central_sts_origins_provider=lambda: [sts_urls["org-alpha.io"]],
            oauth_domain_sts_origins_provider=lambda td: [sts_urls[td]],
        )
        orch_card = orch_node.start(register_in_directory=False)

        try:
            login_res = ex_cli.login_user_password(
                sts_origins=sts_urls["org-alpha.io"],
                username="alice",
                password=bundle.user_passwords["alice"],
                client_id="lct-gateway",
            )
            t0 = login_res["access_token"]

            # Audience Restriction Proof: token minted for `flight-specialist` rejected by `travel-ops-mcp`!
            ex_for_flight = ex_cli.exchange_token(
                sts_origins=sts_urls["org-alpha.io"],
                subject_token=t0,
                target_audience=flight_id.spiffe_id,
                client_id="lct-gateway",
            )
            r_aud_spoof = httpx.post(
                f"{mcp_url}/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "book_flight", "arguments": {"city": "Tokyo", "amount": 500}},
                },
                headers={
                    "Authorization": f"Bearer {ex_for_flight.access_token}",
                    "X-LCT-Delegation-Mode": "oauth_centralized",
                },
                timeout=5.0,
            )
            self.assertEqual(r_aud_spoof.status_code, 401)
            self.assertIn("oidc_audience_mismatch", r_aud_spoof.json()["detail"])

            # Over-privilege contrast (`$950` / `Paris` vs `$650` / `Tokyo`):
            # 1) `oauth_centralized` -> 200 OK (flat scope `travel:book` bypasses parameter bounds!)
            ex_orch = ex_cli.exchange_token(
                sts_origins=sts_urls["org-alpha.io"],
                subject_token=t0,
                target_audience=orch_id.spiffe_id,
                client_id="lct-gateway",
            )
            for mode_name in ("oauth_centralized", "oauth_federated"):
                r_oauth = httpx.post(
                    f"{orch_card.endpoint}/a2a/task",
                    json={"attempt_city": "Paris", "attempt_amount": 950.0},
                    headers={
                        "Authorization": f"Bearer {ex_orch.access_token}",
                        "X-LCT-Delegation-Mode": mode_name,
                        "X-LCT-Task-Id": f"task-{mode_name}",
                    },
                    timeout=10.0,
                )
                self.assertEqual(r_oauth.status_code, 200, r_oauth.text)
                o_body = r_oauth.json()
                self.assertEqual(o_body["oauth_telemetry"]["sts_exchanges"], 1)
                self.assertEqual(o_body["upstream_body"]["oauth_telemetry"]["sts_exchanges"], 1)
                self.assertEqual(
                    o_body["upstream_body"]["upstream_body"]["result"]["data"]["charged_usd"],
                    950.0,
                )

            # 2) `LCT` on the EXACT SAME dual-mode Sidecar pods -> 403 LATTICE_VIOLATION (0 STS calls!)
            lct_root = mint_root_token(
                ca_alpha,
                task_id="task-lct-dual-contrast",
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=orch_id.spiffe_id,
                first_hop_jkt=orch_id.jkt,
                permissions=PermissionLattice.create(
                    tools=["book_flight"],
                    max_amount=900.0,
                    allowed_targets=["airline-escrow"],
                    param_whitelist={"city": ["Tokyo"]},
                    max_calls=4,
                ),
            ).encode_compact()
            target_orch_url = f"{orch_card.endpoint}/a2a/task"
            dpop_orch = create_dpop_proof(gw_id, "POST", target_orch_url, lct_root)
            r_lct_deny = httpx.post(
                target_orch_url,
                json={"attempt_city": "Paris", "attempt_amount": 950.0},
                headers={"Authorization": f"DPoP {lct_root}", "DPoP": dpop_orch},
                timeout=10.0,
            )
            self.assertEqual(r_lct_deny.status_code, 403, r_lct_deny.text)

            # 3) Within-bounds LCT call (`$580` / `Tokyo`) -> 200 OK with 0 STS exchanges!
            lct_root_ok = mint_root_token(
                ca_alpha,
                task_id="task-lct-dual-ok",
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=orch_id.spiffe_id,
                first_hop_jkt=orch_id.jkt,
                permissions=PermissionLattice.create(
                    tools=["book_flight"],
                    max_amount=900.0,
                    allowed_targets=["airline-escrow"],
                    param_whitelist={"city": ["Tokyo"]},
                    max_calls=4,
                ),
            ).encode_compact()
            dpop_ok = create_dpop_proof(gw_id, "POST", target_orch_url, lct_root_ok)
            r_lct_ok = httpx.post(
                target_orch_url,
                json={"attempt_city": "Tokyo", "attempt_amount": 580.0},
                headers={"Authorization": f"DPoP {lct_root_ok}", "DPoP": dpop_ok},
                timeout=10.0,
            )
            self.assertEqual(r_lct_ok.status_code, 200, r_lct_ok.text)
            self.assertNotIn("oauth_telemetry", r_lct_ok.json())
        finally:
            orch_node.stop()
            flight_node.stop()
            mcp_node.stop()
            sts_alpha.stop()
            sts_beta.stop()
            sts_pay.stop()

    # -------------------------------------------------------------------------
    # 5. Keycloak 26.5.2 Realm, K8s Manifests, Secret Isolation & Markdown Table
    # -------------------------------------------------------------------------
    def test_05_keycloak_26_5_2_manifests_secret_isolation_and_comparison_report(
        self,
    ) -> None:
        b1 = generate_keycloak_realm_bundle()
        b2 = generate_keycloak_realm_bundle()
        self.assertEqual(b1.realm_name, "lct")
        self.assertNotEqual(b1.admin_password, b2.admin_password)
        self.assertNotEqual(
            b1.client_secrets["orchestrator-alpha"],
            b2.client_secrets["orchestrator-alpha"],
        )
        for c_doc in b1.realm_dict["clients"]:
            self.assertEqual(
                c_doc["attributes"]["standard.token.exchange.enabled"], "true"
            )

        alpha_yaml = render_role_k8s_manifests("alpha", sts_engine="keycloak")
        alpha_docs = list(yaml.safe_load_all(alpha_yaml))
        sts_deps = [
            d
            for d in alpha_docs
            if d["kind"] == "Deployment" and d["metadata"]["name"] == "alpha-sts"
        ]
        self.assertEqual(len(sts_deps), 1)
        sts_c = sts_deps[0]["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(sts_c["image"], KEYCLOAK_IMAGE)
        self.assertIn("--features=token-exchange,token-exchange-standard:v2", sts_c["args"])
        self.assertIn("--import-realm", sts_c["args"])
        self.assertEqual(
            sts_deps[0]["spec"]["template"]["spec"]["securityContext"]["fsGroup"],
            2000,
        )

        # Verify strict Secret isolation:
        # - `lct-keycloak-realm` ONLY mounted in `alpha-sts`
        # - `lct-oauth-credentials` NEVER mounted in any `app` container!
        for role_name, eng in (("alpha", "keycloak"), ("beta", "lightweight"), ("pay", "lightweight")):
            for doc in yaml.safe_load_all(render_role_k8s_manifests(role_name, sts_engine=eng)):
                if doc["kind"] != "Deployment":
                    continue
                dep_name = doc["metadata"]["name"]
                pod_spec = doc["spec"]["template"]["spec"]
                vol_secrets = {
                    v["secret"]["secretName"]
                    for v in (pod_spec.get("volumes") or [])
                    if "secret" in v
                }
                if dep_name != f"{role_name}-sts":
                    self.assertNotIn(
                        "lct-keycloak-realm",
                        vol_secrets,
                        f"Deployment {dep_name} must not mount lct-keycloak-realm!",
                    )
                for c in pod_spec["containers"]:
                    if c["name"] == "app":
                        m_names = {m["name"] for m in (c.get("volumeMounts") or [])}
                        self.assertNotIn(
                            "lct-oauth-credentials",
                            m_names,
                            f"Business app container in {dep_name} must NEVER mount OAuth secrets!",
                        )

        # Verify `SignedDomainDescriptor` accepts `oauth_sts` locators
        ca_alpha = TrustDomainCA("org-alpha.io")
        x509_pem = AutonomousDomainCAService(
            trust_domain="org-alpha.io",
            allowed_k8s_namespace="lineage-alpha",
            k8s_verifier=_InMemoryK8sSAVerifier(),
        ).x509_ca.export_root_pem()
        pub_b = ca_alpha.export_public_bundle()
        pub_b["x509_root_pem"] = x509_pem
        anc = compute_bundle_trust_anchor(pub_b)
        desc = SignedDomainDescriptor.sign_with_domain_ca(
            ca=ca_alpha,
            x509_root_pem=x509_pem,
            locators={
                "ca_bundle": [ServiceLocator("http-ro", "10.29.77.23", 30100)],
                "oauth_sts": [ServiceLocator("http-ro", "10.29.77.23", 30105)],
            },
            version=1,
        )
        pins = TrustAnchorPinStore({"org-alpha.io": anc})
        dstore = DomainDescriptorStore(anchor_store=pins, require_pinned_anchors=True)
        accepted, _ = dstore.ingest_raw_descriptor(desc.to_dict())
        self.assertTrue(accepted)
        self.assertEqual(dstore.get_locators("org-alpha.io", "oauth_sts")[0].port, 30105)

        # CLI & Markdown formatter check
        parser = build_cli_parser()
        parsed_cmp = parser.parse_args(["compare", "--skip-sts-partition"])
        self.assertEqual(parsed_cmp.subcmd, "compare")
        md = format_m8_comparison_markdown(
            {
                "run_id": "unit-1",
                "alpha_sts_engine": "keycloak-26.5.2",
                "dimensions": {
                    "1_latency_and_sts_rpcs": {
                        "oauth_centralized": {"online_sts_exchange_rpcs": 10, "cumulative_sts_rtt_ms": 48.2, "e2e_wall_ms": 950.0},
                        "oauth_federated": {"online_sts_exchange_rpcs": 10, "cumulative_sts_rtt_ms": 31.4, "e2e_wall_ms": 910.0},
                        "lct": {"online_sts_exchange_rpcs": 0, "hop0_ca_bridge_ms": 4.1, "e2e_wall_ms": 840.0},
                    },
                    "2_fine_grained_overprivilege": {
                        "oauth_centralized": {"http_status": 200, "overprivileged_call_outcome": "ALLOWED_BY_FLAT_SCOPE", "charged_usd": 950.0, "booked_city": "Paris"},
                        "oauth_federated": {"http_status": 200, "overprivileged_call_outcome": "ALLOWED_BY_FLAT_SCOPE", "charged_usd": 950.0, "booked_city": "Paris"},
                        "lct": {"http_status": 403, "overprivileged_call_outcome": "BLOCKED_BY_PERMISSION_LATTICE"},
                    },
                    "3_multiparent_convergence_and_branch_cancel": {
                        "oauth_centralized": {"airline_escrow_status_after_flight_cancel": 200, "hotel_escrow_status": 200, "outcome": "LINEAR_ACT_NO_BRANCH_SCOPED_DEGRADATION"},
                        "oauth_federated": {"airline_escrow_status_after_flight_cancel": 200, "hotel_escrow_status": 200, "outcome": "LINEAR_ACT_NO_BRANCH_SCOPED_DEGRADATION"},
                        "lct": {"airline_escrow_status_after_flight_cancel": 403, "hotel_escrow_status": 200, "hotel_lineage_decision": "ALLOW_DEGRADED_DAG"},
                    },
                    "4_zombie_primary_failover_double_spend": {
                        "oauth_centralized": {"zombie_wakeup_mcp_status": 200, "double_spend_prevented": False},
                        "oauth_federated": {"zombie_wakeup_mcp_status": 200, "double_spend_prevented": False},
                        "lct": {"zombie_wakeup_mcp_status": 403, "double_spend_prevented": True},
                    },
                    "5_central_sts_partition_impact": {
                        "oauth_centralized": {"http_status_during_alpha_sts_outage": 502, "survives_central_sts_outage": False},
                        "oauth_federated": {"beta_to_pay_http_status_during_alpha_sts_outage": 200, "downstream_orgs_survive_alpha_sts_outage": True},
                        "lct": {"alpha_to_beta_to_pay_http_status_during_alpha_sts_outage": 200, "survives_central_sts_outage": True},
                    },
                    "6_causal_audit_reconstruction": {
                        "oauth_centralized": {"hash_linked_causal_coverage_pct": 0.0, "task_correlated_dag_events": 0},
                        "oauth_federated": {"hash_linked_causal_coverage_pct": 0.0, "task_correlated_dag_events": 0},
                        "lct": {"hash_linked_causal_coverage_pct": 100.0, "verified_causal_events_for_d1_trip": 14, "tampered_or_unverified_events": 0},
                    },
                },
            }
        )
        self.assertIn("keycloak-26.5.2", md)
        self.assertIn("ALLOW_DEGRADED_DAG", md)


if __name__ == "__main__":
    unittest.main()
