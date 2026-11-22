"""Milestone-3 Comprehensive Verification Suite:
1. Official A2A (Agent2Agent) v1.0 Protocol (`SendMessage`, `SendStreamingMessage` SSE,
   `GetTask` tenant isolation, `CancelTask` cross-domain cascading revocation, and
   `/.well-known/agent-card.json` v1.0 schema + anti-poisoning).
2. Physically Isolated 3-Domain Autonomous Control Planes (`alpha-ca`, `beta-ca`,
   `payment-ca`) + Federated Bundle, Directory, and Revocation Peering with Anti-Spoofing.
3. End-to-End Bidirectional SPIFFE X.509-SVID mTLS 1.3 (`https://`, `ssl.CERT_REQUIRED`)
   + Channel-Token Dual Binding Enforcement.
"""

from __future__ import annotations

import time
import unittest
from typing import Any, Dict, List, Tuple

import httpx

from lineage.a2a import A2AClient, Message, TaskState
from lineage.agents import (
    FlightSpecialistApp,
    HotelSpecialistApp,
    OrchestratorAlphaApp,
    PaymentVaultMCPApp,
    SettlementConvergerApp,
    TravelOpsMCPApp,
)
from lineage.audit import AuditCollectorClient, AuditCollectorService, CausalChainAuditor
from lineage.common.crypto import KeyPair, jws_sign_compact
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.common.mtls import (
    WorkloadMTLSBundle,
    X509DomainAuthority,
    X509FederationTrustStore,
)
from lineage.federation import (
    AutonomousDomainCAService,
    FederationBundleSyncer,
    FederationSecurityError,
)
from lineage.k8s.bootstrap_services import K8sServiceAccountVerifier, create_ca_pop_jws
from lineage.protocol import PermissionLattice, create_dpop_proof
from lineage.registry import (
    AgentCard,
    AgentCardError,
    AgentDirectoryClient,
    AgentDirectoryService,
)
from lineage.revocation import (
    RevocationError,
    RevocationReplicaClient,
    RevocationService,
)
from lineage.sidecar import LineageSidecar
from lineage.verifier import VerificationMode


class _DeterministicM3LLM:
    """Fast deterministic LLM implementation for local protocol & mTLS integration tests."""

    def chat_json(self, system_prompt: str, user_prompt: str, **_: Any) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        city = "London" if "london" in user_prompt.lower() else "Tokyo"
        if "audit_tag" in system_prompt:
            return {"audit_tag": f"AUDIT-{city.upper()}"}, {"model": "stub-m3", "completion_id": "cmpl-j1"}
        return (
            {"city": city, "flight_budget_usd": 650.0, "hotel_budget_usd": 420.0},
            {"model": "stub-m3", "completion_id": "cmpl-plan"},
        )

    def chat_tool_call(
        self, system_prompt: str, user_prompt: str, tools_schema: List[Dict[str, Any]], **_: Any
    ) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        fn = tools_schema[0]["function"]["name"]
        city = "London" if "london" in user_prompt.lower() else "Tokyo"
        if fn in ("search_flight", "search_hotel"):
            return fn, {"city": city}, {"model": "stub-m3", "completion_id": f"cmpl-{fn}"}
        if fn == "book_flight":
            fno = "BA-284" if city == "London" else "NH-108"
            amt = 510.0 if city == "London" else 580.0
            return fn, {"city": city, "flight_no": fno, "amount": amt}, {"model": "stub-m3", "completion_id": "cmpl-bf"}
        hid = "HTL-LON-04" if city == "London" else "HTL-TYO-09"
        amt_h = 340.0 if city == "London" else 360.0
        return fn, {"city": city, "hotel_id": hid, "amount": amt_h}, {"model": "stub-m3", "completion_id": "cmpl-rh"}

    def chat_text(self, system_prompt: str, user_prompt: str, **_: Any) -> Tuple[str, Dict[str, Any]]:
        if "ONLY the hotel" in system_prompt:
            return (
                "Only the hotel reservation HTL-TYO-09 and hotel escrow settlement ($360.00) were executed under degraded authorization.",
                {"model": "stub-m3", "completion_id": "cmpl-deg"},
            )
        return (
            "Confirmed flight NH-108 ($580.00) and hotel HTL-TYO-09 ($360.00) with both escrow settlements completed.",
            {"model": "stub-m3", "completion_id": "cmpl-full"},
        )


class Milestone3A2AFederationMTLSTests(unittest.TestCase):
    def _make_k8s_verifier(self, oidc_kp: KeyPair) -> K8sServiceAccountVerifier:
        jwk = oidc_kp.public_jwk()
        v = K8sServiceAccountVerifier(
            allowed_audiences=(
                "lct-federation-ca",
                "lct-ca-org-alpha.io",
                "lct-ca-org-beta.io",
                "lct-ca-org-payment.io",
            )
        )
        v._keys_by_kid = {jwk["kid"]: jwk}
        v._last_refresh = time.time() + 3600.0
        return v

    def _mint_sa_jwt(self, oidc_kp: KeyPair, ns: str, sa: str, aud: str = "lct-federation-ca") -> str:
        now = time.time()
        return jws_sign_compact(
            {
                "iss": "https://kubernetes.default.svc.cluster.local",
                "aud": [aud],
                "sub": f"system:serviceaccount:{ns}:{sa}",
                "iat": now,
                "nbf": now,
                "exp": now + 1200.0,
            },
            oidc_kp,
        )

    # -------------------------------------------------------------------------
    # 1. Autonomous 3-Domain CAs + Bundle/Directory/Revocation Anti-Spoofing
    # -------------------------------------------------------------------------
    def test_01_autonomous_3domain_federation_and_anti_spoofing(self) -> None:
        oidc_kp = KeyPair.generate("RS256")
        ca_alpha = AutonomousDomainCAService(
            trust_domain="org-alpha.io",
            allowed_k8s_namespace="lineage-alpha",
            authorized_gateway_sa="e2e-user-gateway",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
        )
        ca_beta = AutonomousDomainCAService(
            trust_domain="org-beta.io",
            allowed_k8s_namespace="lineage-beta",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
        )
        ca_pay = AutonomousDomainCAService(
            trust_domain="org-payment.io",
            allowed_k8s_namespace="lineage-pay",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
        )
        u_alpha = ca_alpha.start()
        u_beta = ca_beta.start()
        u_pay = ca_pay.start()

        to_stop: List[Any] = [ca_alpha, ca_beta, ca_pay]
        try:
            # A. Physical key isolation: each CA holds ONLY its own domain CA
            self.assertEqual(ca_alpha.ca.trust_domain, "org-alpha.io")
            self.assertEqual(ca_beta.ca.trust_domain, "org-beta.io")
            self.assertEqual(ca_pay.ca.trust_domain, "org-payment.io")

            # Cross-namespace K8s SA token (`lineage-beta` calling `alpha-ca`) -> 403!
            kp_b = KeyPair.generate("ES256")
            sa_beta = self._mint_sa_jwt(oidc_kp, "lineage-beta", "flight-specialist")
            r_cross_ns = httpx.post(
                f"{u_alpha}/v1/ca/issue-workload",
                json={"public_jwk": kp_b.public_jwk(), "pop_jws": create_ca_pop_jws(kp_b, sa_beta)},
                headers={"Authorization": f"Bearer {sa_beta}"},
            )
            self.assertEqual(r_cross_ns.status_code, 403)

            # B. Bundle Federation Sync + Spoofed Peer Domain Rejection
            syncer = FederationBundleSyncer(
                {"org-alpha.io": u_alpha, "org-beta.io": u_beta, "org-payment.io": u_pay}
            )
            syncer.sync_all(require_all=True, max_wait_sec=5.0)
            self.assertEqual(
                syncer.trust_resolver.trusted_domains(),
                ["org-alpha.io", "org-beta.io", "org-payment.io"],
            )

            # Pointing expected `org-alpha.io` at `u_beta` (`org-beta.io`) -> FederationSecurityError!
            bad_syncer = FederationBundleSyncer({"org-alpha.io": u_beta})
            with self.assertRaises(FederationSecurityError):
                bad_syncer.sync_all(require_all=True, max_wait_sec=1.0)

            # C. Federated Directory Peering + Cross-Domain Card Spoofing Rejection
            dir_alpha = AgentDirectoryService(
                syncer.trust_resolver, local_trust_domain="org-alpha.io", host="127.0.0.1", port=0
            )
            dir_beta = AgentDirectoryService(
                syncer.trust_resolver, local_trust_domain="org-beta.io", host="127.0.0.1", port=0
            )
            du_alpha = dir_alpha.start()
            du_beta = dir_beta.start()
            to_stop.extend([dir_alpha, dir_beta])
            dir_alpha.peer_directory_urls = {"org-beta.io": du_beta}

            w_alpha = ca_alpha.ca.issue_workload("/ns/lineage-alpha/sa/orch")
            w_beta = ca_beta.ca.issue_workload("/ns/lineage-beta/sa/flight")
            card_alpha = AgentCard.sign_and_create(w_alpha, "Orch", "https://127.0.0.1:8443", ["travel.orchestrate"])
            card_beta = AgentCard.sign_and_create(w_beta, "Flight", "https://127.0.0.1:8444", ["travel.flight"])

            # Direct registration of `org-beta.io` card on `alpha-directory` rejected!
            with self.assertRaises(AgentCardError):
                dir_alpha.register_card_direct(card_beta.to_dict())

            dir_beta.register_card_direct(card_beta.to_dict())
            dir_alpha.sync_from_federation_peers()
            discovered = dir_alpha.discover_cards(skill="travel.flight")
            self.assertEqual([c.spiffe_id for c in discovered], [w_beta.spiffe_id])

            # Rogue `beta` peer trying to smuggle an `org-alpha.io` card via federation -> AgentCardError!
            with self.assertRaises(AgentCardError):
                dir_alpha.ingest_federated_card(
                    card_alpha.to_dict(), expected_peer_domain="org-beta.io"
                )

            # D. Federated Revocation Peering + Cross-Domain Revocation Forgery Rejection
            rev_alpha_id = ca_alpha.ca.issue_workload("/ns/sys/sa/revocation")
            rev_beta_id = ca_beta.ca.issue_workload("/ns/sys/sa/revocation")
            rev_pay_id = ca_pay.ca.issue_workload("/ns/sys/sa/revocation")

            rev_alpha = RevocationService(
                rev_alpha_id, syncer.trust_resolver, strict_domain_isolation=True, host="127.0.0.1", port=0
            )
            rev_beta = RevocationService(
                rev_beta_id, syncer.trust_resolver, strict_domain_isolation=True, host="127.0.0.1", port=0
            )
            rev_pay = RevocationService(
                rev_pay_id, syncer.trust_resolver, strict_domain_isolation=True, host="127.0.0.1", port=0
            )
            ru_alpha = rev_alpha.start()
            ru_beta = rev_beta.start()
            ru_pay = rev_pay.start()
            to_stop.extend([rev_alpha, rev_beta, rev_pay])

            rev_beta.peer_revocation_urls = {"org-alpha.io": ru_alpha, "org-payment.io": ru_pay}
            rev_pay.peer_revocation_urls = {"org-alpha.io": ru_alpha, "org-beta.io": ru_beta}

            # Revoke `/task-fed-1/Orch/B1` on `alpha-revocation` -> propagates to `payment-revocation` replica!
            alpha_cli = RevocationReplicaClient(ru_alpha, syncer.trust_resolver)
            ev_a = alpha_cli.revoke_prefix(
                ca_alpha.ca, "/task-fed-1/Orch/B1", reason="cancel_branch"
            )
            pay_cli = RevocationReplicaClient(ru_pay, syncer.trust_resolver)
            pay_cli.sync_now()
            self.assertIsNotNone(
                pay_cli.trie.check_lineage_path(
                    "/task-fed-1/Orch/B1/SettlementC", trust_domain="org-alpha.io"
                )
            )

            # Rogue `beta-revocation` forging an event claiming `trust_domain="org-alpha.io"` -> RevocationError!
            forged_ev = rev_beta.revoke_prefix_direct(
                prefix="/task-victim-alpha/Orch",
                requested_by="attacker",
                reason="forged",
                trust_domain="org-alpha.io",
            )
            with self.assertRaises(RevocationError):
                rev_pay.ingest_federated_event(
                    forged_ev.to_dict(), expected_peer_domain="org-beta.io"
                )
            with self.assertRaises(RevocationError):
                rev_pay.ingest_federated_event(
                    forged_ev.to_dict(), expected_peer_domain="org-alpha.io"
                )
            self.assertIsNone(
                pay_cli.trie.check_lineage_path(
                    "/task-victim-alpha/Orch", trust_domain="org-alpha.io"
                )
            )
        finally:
            for s in reversed(to_stop):
                try:
                    s.stop()
                except Exception:
                    pass

    # -------------------------------------------------------------------------
    # 2. Full A2A v1.0 (`SendMessage`, `SendStreamingMessage` SSE, `GetTask`,
    #    `CancelTask` Cascading Revocation) over Bidirectional X.509 mTLS 1.3!
    # -------------------------------------------------------------------------
    def test_02_official_a2a_v1_sse_canceltask_and_bidirectional_mtls(self) -> None:
        oidc_kp = KeyPair.generate("RS256")

        # Start independent keyless AuditCollectorService first
        ca_alpha = AutonomousDomainCAService(
            trust_domain="org-alpha.io",
            allowed_k8s_namespace="lineage-alpha",
            authorized_gateway_sa="e2e-user-gateway",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
        )
        ca_beta = AutonomousDomainCAService(
            trust_domain="org-beta.io",
            allowed_k8s_namespace="lineage-beta",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
        )
        ca_pay = AutonomousDomainCAService(
            trust_domain="org-payment.io",
            allowed_k8s_namespace="lineage-pay",
            k8s_verifier=self._make_k8s_verifier(oidc_kp),
            host="127.0.0.1",
            port=0,
        )
        u_alpha, u_beta, u_pay = ca_alpha.start(), ca_beta.start(), ca_pay.start()

        syncer = FederationBundleSyncer(
            {"org-alpha.io": u_alpha, "org-beta.io": u_beta, "org-payment.io": u_pay}
        )
        syncer.sync_all(require_all=True, max_wait_sec=5.0)
        resolver = syncer.trust_resolver
        x509_store = syncer.x509_trust_store

        collector = AuditCollectorService(resolver, host="127.0.0.1", port=0)
        audit_url = collector.start()
        ca_alpha._audit_emitter = ca_alpha._audit_emitter or None
        from lineage.audit import AuditStreamEmitter
        ca_alpha._audit_emitter = AuditStreamEmitter(
            ca_alpha.ca, AuditCollectorClient(audit_url), stream_id="spiffe://org-alpha.io/authority/root"
        )

        # 3 Autonomous Revocation Services + 3 Autonomous Directory Services
        rev_a = RevocationService(
            ca_alpha.ca.issue_workload("/ns/sys/sa/revocation"),
            resolver,
            strict_domain_isolation=True,
            host="127.0.0.1",
            port=0,
        )
        rev_b = RevocationService(
            ca_beta.ca.issue_workload("/ns/sys/sa/revocation"),
            resolver,
            strict_domain_isolation=True,
            host="127.0.0.1",
            port=0,
        )
        rev_p = RevocationService(
            ca_pay.ca.issue_workload("/ns/sys/sa/revocation"),
            resolver,
            strict_domain_isolation=True,
            host="127.0.0.1",
            port=0,
        )
        ru_a, ru_b, ru_p = rev_a.start(), rev_b.start(), rev_p.start()
        rev_a.peer_revocation_urls = {"org-beta.io": ru_b, "org-payment.io": ru_p}
        rev_b.peer_revocation_urls = {"org-alpha.io": ru_a, "org-payment.io": ru_p}
        rev_p.peer_revocation_urls = {"org-alpha.io": ru_a, "org-beta.io": ru_b}

        dir_a = AgentDirectoryService(
            resolver,
            revocation_replica=RevocationReplicaClient(ru_a, resolver),
            local_trust_domain="org-alpha.io",
            host="127.0.0.1",
            port=0,
        )
        dir_b = AgentDirectoryService(
            resolver,
            revocation_replica=RevocationReplicaClient(ru_b, resolver),
            local_trust_domain="org-beta.io",
            host="127.0.0.1",
            port=0,
        )
        dir_p = AgentDirectoryService(
            resolver,
            revocation_replica=RevocationReplicaClient(ru_p, resolver),
            local_trust_domain="org-payment.io",
            host="127.0.0.1",
            port=0,
        )
        du_a, du_b, du_p = dir_a.start(), dir_b.start(), dir_p.start()
        dir_a.peer_directory_urls = {"org-beta.io": du_b, "org-payment.io": du_p}
        dir_b.peer_directory_urls = {"org-alpha.io": du_a, "org-payment.io": du_p}
        dir_p.peer_directory_urls = {"org-alpha.io": du_a, "org-beta.io": du_b}

        to_stop: List[Any] = [ca_alpha, ca_beta, ca_pay, collector, rev_a, rev_b, rev_p, dir_a, dir_b, dir_p]
        stub_llm = _DeterministicM3LLM()

        domain_env = {
            "org-alpha.io": (ca_alpha, "lineage-alpha", du_a, ru_a),
            "org-beta.io": (ca_beta, "lineage-beta", du_b, ru_b),
            "org-payment.io": (ca_pay, "lineage-pay", du_p, ru_p),
        }

        def _issue_mtls_identity(td: str, sa: str) -> Tuple[Any, WorkloadMTLSBundle]:
            dom_ca, ns, _, _ = domain_env[td]
            sa_jwt = self._mint_sa_jwt(oidc_kp, ns, sa)
            kp = KeyPair.generate("ES256")
            r = httpx.post(
                f"{dom_ca.base_url}/v1/ca/issue-workload",
                json={"public_jwk": kp.public_jwk(), "pop_jws": create_ca_pop_jws(kp, sa_jwt)},
                headers={"Authorization": f"Bearer {sa_jwt}"},
            )
            self.assertEqual(r.status_code, 200, r.text)
            d = r.json()
            from lineage.identity import WorkloadIdentity
            wl = WorkloadIdentity(
                spiffe_id=d["spiffe_id"],
                trust_domain=d["trust_domain"],
                keypair=kp,
                workload_svid=d["workload_svid"],
                issued_at=float(d["issued_at"]),
                expires_at=float(d["expires_at"]),
            )
            mb = WorkloadMTLSBundle(
                spiffe_id=wl.spiffe_id,
                keypair=kp,
                leaf_cert_pem=d["x509_leaf_pem"],
                trust_store=x509_store,
            )
            return wl, mb

        def _spawn_mtls_node(td: str, sa: str, skill: str, prio: int, app_factory: Any) -> Tuple[Any, LineageSidecar, AgentCard]:
            _, _, local_du, local_ru = domain_env[td]
            wl, mb = _issue_mtls_identity(td, sa)
            sec = f"mtls-loopback-{sa}-256bit-secret"
            sc = LineageSidecar(
                identity=wl,
                trust_resolver=resolver,
                app_upstream_url="http://127.0.0.1:9",
                loopback_secret=sec,
                mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
                revocation_replica=RevocationReplicaClient(local_ru, resolver),
                directory_client=AgentDirectoryClient(local_du, resolver),
                audit_emitter=AuditStreamEmitter(wl, AuditCollectorClient(audit_url), stream_id=f"{wl.spiffe_id}#m3"),
                is_tool_server=(skill == ""),
                mtls_bundle=mb,
            )
            in_url, out_url = sc.start()
            self.assertTrue(in_url.startswith("https://127.0.0.1:"), in_url)
            app_obj = app_factory(sec, out_url)
            sc.app_upstream_url = app_obj.start().rstrip("/")
            to_stop.extend([sc, app_obj])

            card = None
            if skill:
                card = AgentCard.sign_and_create(
                    identity=wl,
                    name=sa,
                    endpoint=in_url,
                    return_endpoint=in_url,
                    skills=[skill],
                    priority=prio,
                )
                sc.set_agent_card(card)
                # Register ONLY with this agent's OWN autonomous domain directory!
                AgentDirectoryClient(local_du, resolver).register(card)
            return app_obj, sc, card  # type: ignore[return-value]

        try:
            _, travel_sc, _ = _spawn_mtls_node(
                "org-payment.io", "travel-ops-mcp", "", 10,
                lambda s, _o: TravelOpsMCPApp(s, port=0),
            )
            _, pay_sc, _ = _spawn_mtls_node(
                "org-payment.io", "payment-vault-mcp", "", 10,
                lambda s, _o: PaymentVaultMCPApp(s, port=0),
            )
            _, flight_sc, _ = _spawn_mtls_node(
                "org-beta.io", "flight-specialist", "travel.flight", 10,
                lambda s, o: FlightSpecialistApp(s, o, f"{travel_sc.inbound_url}/mcp", ollama=stub_llm, port=0),
            )
            _, hotel1_sc, _ = _spawn_mtls_node(
                "org-beta.io", "hotel-specialist-primary", "travel.hotel", 10,
                lambda s, o: HotelSpecialistApp(s, o, f"{travel_sc.inbound_url}/mcp", instance_label="primary", ollama=stub_llm, port=0),
            )
            _, conv_sc, _ = _spawn_mtls_node(
                "org-payment.io", "settlement-converger", "settlement.converge", 10,
                lambda s, o: SettlementConvergerApp(s, o, f"{pay_sc.inbound_url}/mcp", ollama=stub_llm, port=0),
            )
            _, orch_sc, orch_card = _spawn_mtls_node(
                "org-alpha.io", "orchestrator-alpha", "travel.orchestrate", 10,
                lambda s, o: OrchestratorAlphaApp(s, o, ollama=stub_llm, port=0),
            )

            # Sync all 3 federated directories
            dir_a.sync_from_federation_peers()
            dir_b.sync_from_federation_peers()
            dir_p.sync_from_federation_peers()

            gw_id, gw_mtls = _issue_mtls_identity("org-alpha.io", "e2e-user-gateway")
            gw_ssl = gw_mtls.build_client_ssl_context(check_hostname=True)
            gw_sa_jwt = self._mint_sa_jwt(oidc_kp, "lineage-alpha", "e2e-user-gateway")

            # --- A. mTLS 1.3 Enforcement Checks ---
            # 1. Client WITHOUT X.509 client certificate is rejected at TLS handshake!
            no_client_cert_ssl = WorkloadMTLSBundle(
                spiffe_id="none",
                keypair=KeyPair.generate("ES256"),
                leaf_cert_pem="",
                trust_store=x509_store,
            )
            import ssl as _ssl
            server_only_verify = _ssl.create_default_context(cadata=x509_store.combined_ca_pem())
            with self.assertRaises(Exception):
                with httpx.Client(verify=server_only_verify, timeout=3.0) as bad_cli:
                    bad_cli.get(f"{orch_sc.inbound_url}/healthz")

            # 2. Client WITH rogue/unfederated CA X.509 certificate is rejected at TLS handshake!
            # 3. Cross-domain X.509 CA spoofing (`beta-ca` attempting to certify `spiffe://org-alpha.io/...`)
            #    blocked both at `X509DomainAuthority.issue_x509_svid` AND at `X509FederationTrustStore.verify_peer_der_cert`!
            from lineage.common.mtls import MTLSError
            rogue_x509 = X509DomainAuthority("org-rogue.io")
            rogue_kp = KeyPair.generate("ES256")
            with self.assertRaises(MTLSError):
                ca_beta.x509_ca.issue_x509_svid(
                    "spiffe://org-alpha.io/ns/lineage-alpha/sa/spoofed", rogue_kp.public_jwk()
                )
            rogue_leaf = rogue_x509.issue_x509_svid(
                "spiffe://org-rogue.io/ns/rogue/sa/evil", rogue_kp.public_jwk()
            )
            rogue_bundle = WorkloadMTLSBundle(
                "spiffe://org-rogue.io/ns/rogue/sa/evil", rogue_kp, rogue_leaf, x509_store
            )
            with self.assertRaises(Exception):
                with httpx.Client(verify=rogue_bundle.build_client_ssl_context(), timeout=3.0) as r_cli:
                    r_cli.get(f"{orch_sc.inbound_url}/healthz")

            # --- B. Official A2A v1.0 `/.well-known/agent-card.json` Discovery over mTLS ---
            a2a_cli = A2AClient(
                agent_base_url=orch_sc.inbound_url,
                signer=gw_id,
                ssl_context=gw_ssl,
                rpc_path="/a2a",
            )
            verified_card, raw_card = a2a_cli.fetch_agent_card(resolver, "/.well-known/agent-card.json")
            self.assertEqual(verified_card.spiffe_id, orch_card.spiffe_id)
            self.assertEqual(raw_card["protocolVersion"], "1.0")
            self.assertEqual(raw_card["url"], orch_sc.inbound_url)
            self.assertTrue(raw_card["capabilities"]["streaming"])
            self.assertTrue(raw_card["capabilities"]["stateTransitionHistory"])
            self.assertIn("lct_dpop", raw_card["securitySchemes"])
            self.assertIsInstance(raw_card["skills"][0], dict)
            self.assertEqual(raw_card["skills"][0]["id"], "travel.orchestrate")
            self.assertTrue(raw_card["signatures"][0]["jws"])

            # Helper to mint RootBlock from `alpha-ca`
            perms = PermissionLattice.create(
                tools=["search_flight", "book_flight", "search_hotel", "reserve_hotel", "execute_settlement", "record_itinerary_audit"],
                max_amount=800.0,
                allowed_targets=["airline-escrow", "hotel-escrow", "audit-ledger"],
                param_whitelist={"city": ["Tokyo", "London"]},
                max_calls=12,
            )

            def _mint_user_root(tid: str, sub: str) -> str:
                rm = httpx.post(
                    f"{u_alpha}/v1/ca/mint-root-token",
                    json={
                        "trust_domain": "org-alpha.io",
                        "task_id": tid,
                        "sub": sub,
                        "sender_jkt": gw_id.jkt,
                        "first_hop_spiffe_id": orch_card.spiffe_id,
                        "first_hop_jkt": orch_card.jkt,
                        "first_hop_public_jwk": orch_card.public_jwk,
                        "first_hop_return_endpoint": orch_card.return_endpoint,
                        "permissions": perms.to_dict(),
                    },
                    headers={"Authorization": f"Bearer {gw_sa_jwt}"},
                )
                self.assertEqual(rm.status_code, 200, rm.text)
                return str(rm.json()["compact_token"])

            # --- C. mTLS Channel + Token Dual Binding Enforcement ---
            # `flight-specialist` connects with its valid mTLS cert (`org-beta.io`) while presenting
            # `gw_id`'s LCT token + DPoP -> MUST be blocked with 403 `MTLS_CHANNEL_BINDING_MISMATCH`!
            tok_bind = _mint_user_root("task-m3-bind-check", "user:alice@org-alpha.io")
            assert flight_sc._client_ssl_ctx is not None
            with httpx.Client(verify=flight_sc._client_ssl_ctx, timeout=5.0) as spoof_ch_cli:
                u_target = f"{orch_sc.inbound_url}/a2a"
                r_ch_mismatch = spoof_ch_cli.post(
                    u_target,
                    json={"jsonrpc": "2.0", "id": "1", "method": "SendMessage", "params": {}},
                    headers={
                        "A2A-Version": "1.0",
                        "Authorization": f"DPoP {tok_bind}",
                        "DPoP": create_dpop_proof(gw_id, "POST", u_target, tok_bind),
                    },
                )
            self.assertEqual(r_ch_mismatch.status_code, 403)
            self.assertEqual(r_ch_mismatch.json()["error"], "MTLS_CHANNEL_BINDING_MISMATCH")

            # Missing `A2A-Version` header -> 400 JSON-RPC `-32600`
            with httpx.Client(verify=gw_ssl, timeout=5.0) as raw_cli:
                u_target = f"{orch_sc.inbound_url}/a2a"
                r_no_ver = raw_cli.post(
                    u_target,
                    json={"jsonrpc": "2.0", "id": "1", "method": "SendMessage", "params": {}},
                    headers={
                        "Authorization": f"DPoP {tok_bind}",
                        "DPoP": create_dpop_proof(gw_id, "POST", u_target, tok_bind),
                    },
                )
            self.assertEqual(r_no_ver.status_code, 400)
            self.assertEqual(r_no_ver.json()["error"]["code"], -32600)

            # --- D. Official A2A v1.0 `SendStreamingMessage` (Real SSE) + `GetTask` Isolation ---
            tok_sse = _mint_user_root("task-m3-sse-tokyo", "user:alice@org-alpha.io")
            st_sse, ct_sse, sse_events = a2a_cli.send_streaming_message(
                message=Message.create_user(
                    text="Book business travel to Tokyo with flight and hotel settlement."
                ),
                compact_token=tok_sse,
            )
            self.assertEqual(st_sse, 200)
            self.assertIn("text/event-stream", ct_sse)
            status_states = [
                ev["result"]["statusUpdate"]["status"]["state"]
                for ev in sse_events
                if "result" in ev and "statusUpdate" in ev["result"]
            ]
            artifact_names = [
                ev["result"]["artifactUpdate"]["artifact"]["name"]
                for ev in sse_events
                if "result" in ev and "artifactUpdate" in ev["result"]
            ]
            self.assertEqual(
                status_states,
                [
                    TaskState.SUBMITTED.value,
                    TaskState.WORKING.value,
                    TaskState.COMPLETED.value,
                ],
            )
            self.assertGreaterEqual(len(artifact_names), 4)
            self.assertTrue(sse_events[-1]["result"]["statusUpdate"]["final"])

            # `GetTask` by owner Alice -> 200 with full history & artifacts
            st_get, get_body = a2a_cli.get_task("task-m3-sse-tokyo", compact_token=tok_sse)
            self.assertEqual(st_get, 200)
            self.assertEqual(get_body["result"]["task"]["status"]["state"], TaskState.COMPLETED.value)
            self.assertGreaterEqual(len(get_body["result"]["task"]["artifacts"]), 4)

            # `GetTask` by Carol attempting to read Alice's task -> 403 `-32003`!
            tok_carol = _mint_user_root("task-m3-carol-1", "user:carol@org-alpha.io")
            st_cross, cross_body = a2a_cli.get_task("task-m3-sse-tokyo", compact_token=tok_carol)
            self.assertEqual(st_cross, 403)
            self.assertEqual(cross_body["error"]["code"], -32003)

            # --- E. Official A2A v1.0 `CancelTask` -> Cross-3-Domain Cascading Revocation! ---
            tok_cancel = _mint_user_root("task-m3-cancel-cascade", "user:alice@org-alpha.io")
            st_stage, stage_body = a2a_cli.send_message(
                message=Message.create_user(
                    text="Stage Tokyo travel bookings before settlement.",
                    data={"pause_before_settlement": True},
                ),
                compact_token=tok_cancel,
            )
            self.assertEqual(st_stage, 200, stage_body)
            staged_data = stage_body["result"]["task"]["status"]["message"]["parts"][1]["data"]
            flight_branch_prefix = staged_data["flight_branch"]["upstream_body"]["lineage_path"]

            # Invoke A2A `CancelTask` revoking the FlightB1 subtree -> propagates from
            # `alpha-revocation` (`org-alpha.io`) -> `payment-revocation` (`org-payment.io`)!
            st_can, can_body = a2a_cli.cancel_task(
                "task-m3-cancel-cascade",
                compact_token=tok_cancel,
                revoke_prefix=flight_branch_prefix,
            )
            self.assertEqual(st_can, 200, can_body)
            self.assertEqual(
                can_body["result"]["task"]["status"]["state"],
                TaskState.CANCELED.value,
            )
            self.assertEqual(can_body["result"]["revocation"]["target"], flight_branch_prefix)

            # Attempting to send another message on the CANCELED task (reusing `tok_cancel`) returns 409 `-32002`!
            st_after_cancel, after_cancel_body = a2a_cli.send_message(
                message=Message.create_user(text="Try resuming canceled task"),
                compact_token=tok_cancel,
            )
            self.assertEqual(st_after_cancel, 409)
            self.assertEqual(after_cancel_body["error"]["code"], -32002)

            # Verify federated `payment-revocation` immediately synced the canceled prefix,
            # AND `settlement-converger` calling `payment-vault-mcp` (`org-payment.io`) with the
            # converged MultiParentToken rejects `airline-escrow` (403) while allowing `hotel-escrow` (`ALLOW_DEGRADED_DAG`)!
            rev_p.sync_from_federation_peers()
            self.assertIsNotNone(
                rev_p.trie.check_lineage_path(
                    f"{flight_branch_prefix}/SettlementC", trust_domain="org-alpha.io"
                )
            )
            st_air_rev, air_rev_res = conv_sc._outbound_http._dispatcher(  # noqa: SLF001
                HTTPRequestContext(
                    method="POST",
                    raw_path="/v1/proxy/call",
                    headers={"X-LCT-Loopback-Auth": conv_sc.loopback_secret},
                    body=b'{"action":"call_tool","use_converged_multiparent":true,"task_id":"task-m3-cancel-cascade","sub":"user:alice@org-alpha.io","target_url":"'
                    + f"{pay_sc.inbound_url}/mcp".encode("ascii")
                    + b'","payload":{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_settlement","arguments":{"target":"airline-escrow","amount":580.0,"city":"Tokyo","reference_id":"FLT-1"}}}}',
                    server_host="127.0.0.1",
                    server_port=conv_sc._outbound_http.port,
                )
            )[:2]
            self.assertEqual(st_air_rev, 403)
            self.assertEqual(
                air_rev_res["upstream_body"]["error"],
                "REVOKED_DEPENDENCY_INSUFFICIENT_SURVIVING_PATHS",
            )

            st_htl_deg, htl_deg_res = conv_sc._outbound_http._dispatcher(  # noqa: SLF001
                HTTPRequestContext(
                    method="POST",
                    raw_path="/v1/proxy/call",
                    headers={"X-LCT-Loopback-Auth": conv_sc.loopback_secret},
                    body=b'{"action":"call_tool","use_converged_multiparent":true,"task_id":"task-m3-cancel-cascade","sub":"user:alice@org-alpha.io","target_url":"'
                    + f"{pay_sc.inbound_url}/mcp".encode("ascii")
                    + b'","payload":{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_settlement","arguments":{"target":"hotel-escrow","amount":360.0,"city":"Tokyo","reference_id":"HTL-1"}}}}',
                    server_host="127.0.0.1",
                    server_port=conv_sc._outbound_http.port,
                )
            )[:2]
            self.assertEqual(st_htl_deg, 200)
            self.assertEqual(
                htl_deg_res["upstream_body"]["result"]["data"]["lineage_decision"],
                "ALLOW_DEGRADED_DAG",
            )

            # --- F. Verify 100% CausalChainAuditor Reconstruction across All Streams ---
            aud_cli = AuditCollectorClient(audit_url, signer=gw_id)
            entries = aud_cli.fetch_entries()
            auditor = CausalChainAuditor(
                resolver,
                trusted_revocation_spiffe_ids=[
                    "spiffe://org-alpha.io/ns/sys/sa/revocation",
                    "spiffe://org-beta.io/ns/sys/sa/revocation",
                    "spiffe://org-payment.io/ns/sys/sa/revocation",
                ],
            )
            rep = auditor.audit(entries)
            self.assertTrue(rep.stream_integrity_ok)
            self.assertTrue(rep.clean, rep.anomalies)
        finally:
            for s in reversed(to_stop):
                try:
                    s.stop()
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
