"""Independent Round-2 Milestone 10 (Platform v2.1) QA Re-Verification & Sign-Off Suite.

Read-only verification suite authored by `k8s-qa-reviewer` confirming complete remediation
of all 7 findings from `MILESTONE10_QA_REPORT.md`:
- `[CRITICAL-M10-01]`: Sovereign single-domain OIDC IdP trust, per-issuer JWKS isolation, & domain binding
- `[HIGH-M10-01]`: `(sub, key)` + `task_id` isolated `_consent_wallet` & dual-layer owner-only consent revocation
- `[HIGH-M10-02]`: Offline `PermissionLattice` required spend/target/schema parameter checks & explicit Vault args
- `[HIGH-M10-03]`: Exact `allowed_scanner_spiffe_ids`, `JTIReplayCache`, & `artifact_sha256` binding on `sign_release`
- `[MEDIUM-M10-01]`: Shared `_extract_inbound_tool_and_args` blocking OAuth A2A JSON-RPC private tool bypass
- `[MEDIUM-M10-02]`: Hardened `DomainUserGatewayService` (`sender_jkt`, CA sig check, SSRF `403`, zero `verify=False`)
- `[LOW-M10-01]`: SVID-signed `lct-cohort-digest+jwt` with two-phase `JTIReplayCache` commit
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

from lineage.common.crypto import jws_sign_compact
from lineage.common.http_utils import ManagedHTTPService
from lineage.common.mtls import WorkloadMTLSBundle, X509FederationTrustStore
from lineage.federation import AutonomousDomainCAService, DomainUserGatewayService
import lineage.federation.user_gateway as user_gateway_mod
from lineage.identity import TrustBundleResolver
import lineage.k8s.bootstrap_services as bootstrap_services_mod
from lineage.oauth_sts import (
    OAuthSTSError,
    OAuthSTSService,
    OAuthTokenExchangeClient,
    OIDCTokenVerifier,
    generate_keycloak_realm_bundle,
)
from lineage.protocol import (
    CoAuthorizedToken,
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
M10_R2_REHEARSAL_DIR = (
    REPO_ROOT / "lineage" / "k8s" / "runs" / "20261126-m10-r2-expanded-scenarios-rehearsal"
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


class Milestone10Round2SignOffTests(unittest.TestCase):
    """Independent Round-2 sign-off suite verifying all 7 Milestone 10 security remediations."""

    def test_01_verify_critical_m10_01_sovereign_idp_per_issuer_jwks_and_realm_isolation(self) -> None:
        """Verify [CRITICAL-M10-01]: Single-domain IdP sovereignty, per-issuer JWKS isolation, & realm filtering."""
        # 1. Confirm `bootstrap_services.py` no longer injects `org-alpha.io` into non-alpha CAs/gateways
        bs_src = inspect.getsource(bootstrap_services_mod.main)
        self.assertNotIn('[trust_domain, "org-alpha.io"]', bs_src)
        self.assertNotIn('[trust_domain_gw, "org-alpha.io"]', bs_src)
        self.assertIn("allowed_user_domains=(trust_domain,)", bs_src)
        self.assertIn("allowed_user_domains=(trust_domain_gw,)", bs_src)

        # 2. Verify Keycloak realm per-domain principal isolation + `"dave": "org-beta.io"`
        b_alpha = generate_keycloak_realm_bundle(realm_trust_domain="org-alpha.io")
        b_beta = generate_keycloak_realm_bundle(realm_trust_domain="org-beta.io")
        b_pay = generate_keycloak_realm_bundle(realm_trust_domain="org-payment.io")
        self.assertEqual([u["username"] for u in b_alpha.realm_dict["users"]], ["alice"])
        self.assertEqual([u["username"] for u in b_beta.realm_dict["users"]], ["bob", "dave"])
        self.assertEqual([u["username"] for u in b_pay.realm_dict["users"]], ["carol"])
        dave_doc = next(u for u in b_beta.realm_dict["users"] if u["username"] == "dave")
        self.assertEqual(dave_doc["attributes"]["lct_sub"], ["user:dave@org-beta.io"])

        # 3. Verify sovereign `OAuthSTSService` & `OIDCTokenVerifier` block all 3 Round-1 attack vectors
        creds = generate_keycloak_realm_bundle(users=("alice", "bob", "bob@org-beta.io", "operator"))
        sts_alpha = OAuthSTSService(
            trust_domain="org-alpha.io",
            realm="lct",
            user_passwords=creds.user_passwords,
            client_secrets=creds.client_secrets,
            host="127.0.0.1",
            port=0,
        )
        sts_beta = OAuthSTSService(
            trust_domain="org-beta.io",
            realm="lct",
            user_passwords=creds.user_passwords,
            client_secrets=creds.client_secrets,
            host="127.0.0.1",
            port=0,
        )
        u_alpha = sts_alpha.start()
        u_beta = sts_beta.start()
        try:
            ocli = OAuthTokenExchangeClient(realm="lct", client_secrets=creds.client_secrets)

            # 3a. Sovereign `alpha-sts` refuses `bob@org-beta.io` login (`403`) & scopes `bob` to `@org-alpha.io`!
            with self.assertRaises(OAuthSTSError):
                ocli.login_user_password(u_alpha, "bob@org-beta.io", creds.user_passwords["bob@org-beta.io"], "lct-gateway")
            alpha_local_bob = ocli.login_user_password(u_alpha, "bob", creds.user_passwords["bob"], "lct-gateway")["access_token"]

            # Sovereign `beta` verifier (mirroring `beta-ca` & `beta-user-gateway`) rejects `alpha-sts` tokens!
            beta_sovereign_ver = OIDCTokenVerifier(
                jwks_urls=[f"{u_beta}/realms/lct/protocol/openid-connect/certs"],
                expected_issuer=f"{u_beta}/realms/lct",
                default_user_domain="org-beta.io",
                allowed_user_domains=("org-beta.io",),
                single_entity_issuers=True,
            )
            with self.assertRaises(OAuthSTSError):
                beta_sovereign_ver.verify_jwt(alpha_local_bob)

            # 3b. Multi-issuer federated verifier blocks key confusion, cross-domain `lct_sub`, & unqualified escalation!
            multi_ver = OIDCTokenVerifier(
                jwks_urls=[
                    f"{u_alpha}/realms/lct/protocol/openid-connect/certs",
                    f"{u_beta}/realms/lct/protocol/openid-connect/certs",
                ],
                allowed_issuers=[f"{u_alpha}/realms/lct", f"{u_beta}/realms/lct"],
                issuer_user_domain_map={
                    f"{u_alpha}/realms/lct": "org-alpha.io",
                    f"{u_beta}/realms/lct": "org-beta.io",
                },
                default_user_domain="org-beta.io",
                single_entity_issuers=False,
            )

            # `alpha-sts` key spoofing `iss = beta-sts` -> rejected!
            spoof_iss_jwt, _ = sts_alpha._mint_jwt(
                issuer=f"{u_beta}/realms/lct",
                sub="bob",
                preferred_username="bob",
                aud="lct-gateway",
                azp="lct-gateway",
                scope="openid",
                lct_sub="user:bob@org-beta.io",
            )
            with self.assertRaises(OAuthSTSError):
                multi_ver.verify_jwt(spoof_iss_jwt)

            # `alpha-sts` asserting foreign `lct_sub = user:bob@org-beta.io` -> rejected!
            spoof_sub_jwt, _ = sts_alpha._mint_jwt(
                issuer=f"{u_alpha}/realms/lct",
                sub="bob",
                preferred_username="bob",
                aud="lct-gateway",
                azp="lct-gateway",
                scope="openid",
                lct_sub="user:bob@org-beta.io",
            )
            with self.assertRaises(OAuthSTSError):
                multi_ver.verify_jwt(spoof_sub_jwt)

            # Unqualified `operator` from `alpha-sts` resolves strictly to `user:operator@org-alpha.io` (never `@org-beta.io`)!
            op_jwt, _ = sts_alpha._mint_jwt(
                issuer=f"{u_alpha}/realms/lct",
                sub="op-id",
                preferred_username="operator",
                aud="lct-gateway",
                azp="lct-gateway",
                scope="openid",
                lct_sub=None,
            )
            self.assertEqual(multi_ver.verify_jwt(op_jwt).canonical_lct_sub, "user:operator@org-alpha.io")
        finally:
            sts_alpha.stop()
            sts_beta.stop()

    def test_02_verify_high_m10_01_consent_wallet_isolation_and_owner_only_revocation_both_layers(self) -> None:
        """Verify [HIGH-M10-01]: `(sub, key)` + `task_id` wallet isolation & dual-layer owner-only consent revocation."""
        bundle = generate_keycloak_realm_bundle()
        sts_b = OAuthSTSService(
            trust_domain="org-beta.io",
            realm="lct",
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
            host="127.0.0.1",
            port=0,
        )
        u_b = sts_b.start()
        oidc_b = OIDCTokenVerifier(
            jwks_urls=[f"{u_b}/realms/lct/protocol/openid-connect/certs"],
            expected_issuer=f"{u_b}/realms/lct",
            default_user_domain="org-beta.io",
            allowed_user_domains=("org-beta.io",),
            single_entity_issuers=True,
        )
        resolver = TrustBundleResolver()
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
        dir_cli = AgentDirectoryClient(dir_svc.start(), resolver)

        tf_bob = tempfile.NamedTemporaryFile("w", delete=False)
        tf_bob.write("sa-bob")
        tf_bob.close()

        started = [sts_b, ca_a, ca_b, ca_p, rev_b, dir_svc]
        try:
            alice_id = ca_a.ca.issue_workload("/ns/lineage-alpha/sa/assistant-alice")
            bob_id = ca_b.ca.issue_workload("/ns/lineage-beta/sa/assistant-bob")
            gw_a = ca_a.ca.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
            gw_b = ca_b.ca.issue_workload("/ns/lineage-beta/sa/beta-user-gateway")
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
                dir_cli.register(AgentCard.sign_and_create(wid, wid.spiffe_id, endpoint=ep, return_endpoint=ep, skills=sk))

            ocli = OAuthTokenExchangeClient(realm="lct", client_secrets=bundle.client_secrets)
            bob_oidc = ocli.login_user_password(u_b, "bob", bundle.user_passwords["bob"], "lct-gateway")["access_token"]

            tid = "signoff-m10-wallet"
            tok_alice = mint_root_token(
                ca_a.ca, tid, "user:alice@org-alpha.io", gw_a.jkt,
                alice_id.spiffe_id, alice_id.jkt,
                PermissionLattice.create(tools=["service_diag_read", "commit_joint_change"], max_calls=8),
            ).encode_compact()
            url_a = f"{in_a.rstrip('/')}/a2a/task"
            r_mint = httpx.post(
                url_a,
                json={
                    "op": "request_peer_co_auth_and_read",
                    "target_tool": "service_diag_read",
                    "consent_tools": ["service_diag_read"],
                    "owner_oidc_token": bob_oidc,
                    "cache_consent_key": "shared-k",
                    "mint_consent_only": True,
                },
                headers={"Authorization": f"DPoP {tok_alice}", "DPoP": create_dpop_proof(gw_a, "POST", url_a, tok_alice)},
            )
            self.assertEqual(r_mint.status_code, 200)
            bob_consent_pfx = r_mint.json()["consent_lineage_path"]

            # 1a. Foreign principal `carol` with SAME `task_id` blocked from reading `"shared-k"` (`403`)!
            tok_carol_same_tid = mint_root_token(
                ca_p.ca, tid, "user:carol@org-payment.io", gw_p.jkt,
                alice_id.spiffe_id, alice_id.jkt,
                PermissionLattice.create(tools=["service_diag_read"], max_calls=4),
            ).encode_compact()
            r_steal = httpx.post(
                url_a,
                json={"op": "probe_peer_private_resource", "target_tool": "service_diag_read", "use_consent_key": "shared-k"},
                headers={
                    "Authorization": f"DPoP {tok_carol_same_tid}",
                    "DPoP": create_dpop_proof(gw_p, "POST", url_a, tok_carol_same_tid),
                },
            )
            self.assertEqual(r_steal.status_code, 403)
            self.assertEqual(r_steal.json()["error"], "CROSS_TENANT_OR_TASK_CONSENT_DENIED")

            # 1b. Same principal `alice` with DIFFERENT `task_id` blocked from reading `"shared-k"` (`403`)!
            tok_alice_other_tid = mint_root_token(
                ca_a.ca, "other-task-id", "user:alice@org-alpha.io", gw_a.jkt,
                alice_id.spiffe_id, alice_id.jkt,
                PermissionLattice.create(tools=["service_diag_read"], max_calls=4),
            ).encode_compact()
            r_xtask = httpx.post(
                url_a,
                json={"op": "probe_peer_private_resource", "target_tool": "service_diag_read", "use_consent_key": "shared-k"},
                headers={
                    "Authorization": f"DPoP {tok_alice_other_tid}",
                    "DPoP": create_dpop_proof(gw_a, "POST", url_a, tok_alice_other_tid),
                },
            )
            self.assertEqual(r_xtask.status_code, 403)
            self.assertEqual(r_xtask.json()["error"], "CROSS_TENANT_OR_TASK_CONSENT_DENIED")

            # 2a. Foreign principal `carol` calling `revoke_own_consent` on `Assistant-B` -> `403 FORBIDDEN_FOREIGN_CONSENT_REVOCATION`!
            tok_carol_b = mint_root_token(
                ca_p.ca, "carol-rev-ctl", "user:carol@org-payment.io", gw_p.jkt,
                bob_id.spiffe_id, bob_id.jkt,
                PermissionLattice.create(tools=["commit_joint_change"], max_calls=2),
            ).encode_compact()
            url_b = f"{in_b.rstrip('/')}/a2a/task"
            r_f_rev = httpx.post(
                url_b,
                json={"op": "revoke_own_consent", "target_task_id": tid, "prefix": bob_consent_pfx},
                headers={"Authorization": f"DPoP {tok_carol_b}", "DPoP": create_dpop_proof(gw_p, "POST", url_b, tok_carol_b)},
            )
            self.assertEqual(r_f_rev.status_code, 403)
            self.assertEqual(r_f_rev.json()["error"], "FORBIDDEN_FOREIGN_CONSENT_REVOCATION")

            # 2b. Direct Sidecar loopback `revoke_consent_prefix` without owner `request_id` -> `403 FORBIDDEN_FOREIGN_CONSENT_REVOCATION`!
            r_sc_direct = httpx.post(
                f"{out_b.rstrip('/')}/v1/proxy/call",
                json={"action": "revoke_consent_prefix", "task_id": tid, "prefix": bob_consent_pfx},
                headers={"X-LCT-Loopback-Auth": lsec_b},
            )
            self.assertEqual(r_sc_direct.status_code, 403)
            self.assertEqual(r_sc_direct.json()["error"], "FORBIDDEN_FOREIGN_CONSENT_REVOCATION")
            rep_b.sync_now()
            self.assertIsNone(rep_b.trie.check_chain(bob_consent_pfx, [], trust_domain="org-beta.io"))

            # 2c. Genuine owner `user:bob@org-beta.io` calling `revoke_own_consent` -> `200` and revokes prefix!
            tok_bob_own = mint_root_token(
                ca_b.ca, "bob-own-rev", "user:bob@org-beta.io", gw_b.jkt,
                bob_id.spiffe_id, bob_id.jkt,
                PermissionLattice.create(tools=["service_diag_read"], max_calls=2),
            ).encode_compact()
            r_bob_rev = httpx.post(
                url_b,
                json={"op": "revoke_own_consent", "target_task_id": tid, "prefix": bob_consent_pfx},
                headers={"Authorization": f"DPoP {tok_bob_own}", "DPoP": create_dpop_proof(gw_b, "POST", url_b, tok_bob_own)},
            )
            self.assertEqual(r_bob_rev.status_code, 200)
            rep_b.sync_now()
            self.assertIsNotNone(rep_b.trie.check_chain(bob_consent_pfx, [], trust_domain="org-beta.io"))
        finally:
            os.unlink(tf_bob.name)
            for s in reversed(started):
                try:
                    s.stop()
                except Exception:
                    pass

    def test_03_verify_high_m10_02_offline_lattice_omitted_args_and_vault_explicit_schema(self) -> None:
        """Verify [HIGH-M10-02]: Offline omitted-parameter lattice rejections + Vault `400` explicit parameter checks."""
        lat = PermissionLattice.create(
            tools=[
                "reserve_cloud_budget",
                "lock_joint_project",
                "commit_negotiated_contract",
                "query_operation_status",
                "legal_redline_review",
            ],
            max_amount=120.0,
            numeric_bounds={"unit_price_usd": 120.0, "max_penalty_pct": 10.0},
            allowed_targets=["compliance-ledger"],
            param_whitelist={
                "project_code": ["PRJ-ATLAS"],
                "contract_id": ["NDA-2026-99"],
                "warranty_tier": ["24M", "36M"],
            },
            max_calls=20,
        )
        # Omitted `amount` on spend tool -> rejected offline
        self.assertFalse(lat.check_invocation("tools/call", "reserve_cloud_budget", {"project_code": "PRJ-ATLAS"})[0])
        # Implicit target `cloud-infra-escrow` not in `allowed_targets=["compliance-ledger"]` -> rejected offline
        self.assertFalse(
            lat.check_invocation("tools/call", "reserve_cloud_budget", {"project_code": "PRJ-ATLAS", "amount": 50.0})[0]
        )
        # Omitted explicit `target` on `lock_joint_project` -> rejected offline
        self.assertFalse(
            lat.check_invocation("tools/call", "lock_joint_project", {"project_code": "PRJ-ATLAS", "amount": 50.0})[0]
        )
        # Omitted `unit_price_usd` or `warranty_tier` on `commit_negotiated_contract` -> rejected offline
        self.assertFalse(
            lat.check_invocation(
                "tools/call",
                "commit_negotiated_contract",
                {"contract_id": "NDA-2026-99", "warranty_tier": "24M", "max_penalty_pct": 5.0},
            )[0]
        )
        self.assertFalse(
            lat.check_invocation(
                "tools/call",
                "commit_negotiated_contract",
                {"contract_id": "NDA-2026-99", "unit_price_usd": 90.0, "max_penalty_pct": 5.0},
            )[0]
        )
        # Multi-tool lattice preserves non-spend / partial-schema tools without false-positive rejection!
        self.assertTrue(lat.check_invocation("tools/call", "query_operation_status", {"idempotency_key": "k1"})[0])
        self.assertTrue(lat.check_invocation("tools/call", "legal_redline_review", {"contract_id": "NDA-2026-99"})[0])

        # Vault app layer: even with unconstrained wildcard lattice (`tools=["*"]`), omitted mutating args return `400`!
        lsec = secrets.token_urlsafe(18)
        vault_app = WorkspaceVaultMCPApp(loopback_secret=lsec, outbound_proxy_url="", port=0)
        vu = vault_app.start()
        try:
            hdrs = {
                "X-LCT-Loopback-Auth": lsec,
                "X-LCT-Task-Id": "t-v",
                "X-LCT-Sub": "user:alice@org-alpha.io",
                "X-LCT-Decision": "ALLOW_CO_AUTHORIZED",
                "X-LCT-Co-Authorized-Principals": "user:alice@org-alpha.io,user:bob@org-beta.io",
            }
            for tname in ("reserve_cloud_budget", "procure_vendor_quote", "lock_joint_project", "record_compliance_note", "commit_joint_change", "commit_negotiated_contract"):
                resp = httpx.post(
                    f"{vu}/mcp",
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tname, "arguments": {}}},
                    headers=hdrs,
                )
                self.assertEqual(resp.status_code, 400, f"Expected 400 on empty arguments for {tname}, got {resp.status_code}")
        finally:
            vault_app.stop()

    def test_04_verify_high_m10_03_exact_scanner_allowlist_jti_anti_replay_and_artifact_digest_match(self) -> None:
        """Verify [HIGH-M10-03]: Exact scanner SPIFFE URI allowlist, `JTIReplayCache`, & `artifact_sha256` match."""
        ca_a = AutonomousDomainCAService("org-alpha.io", "lineage-alpha", host="127.0.0.1", port=0)
        ca_b = AutonomousDomainCAService("org-beta.io", "lineage-beta", host="127.0.0.1", port=0)
        ca_p = AutonomousDomainCAService("org-payment.io", "lineage-pay", host="127.0.0.1", port=0)
        resolver = TrustBundleResolver()
        for c in (ca_a, ca_b, ca_p):
            resolver.register_domain_ca(c.ca)

        rogue_alpha_dave = ca_a.ca.issue_workload("/ns/lineage-alpha/sa/assistant-dave")
        real_beta_dave = ca_b.ca.issue_workload("/ns/lineage-beta/sa/assistant-dave")
        alice_id = ca_a.ca.issue_workload("/ns/lineage-alpha/sa/assistant-alice")
        vault_id = ca_p.ca.issue_workload("/ns/lineage-pay/sa/assistant-vault")

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
            now_ts = time.time()
            # 1. Cross-domain `/sa/assistant-dave` lookalike rejected (`403`) even if caller passes `allowed_scanner_suffix=""`
            forged_att = jws_sign_compact(
                {
                    "jti": "att-rogue-alpha",
                    "issuer_spiffe_id": rogue_alpha_dave.spiffe_id,
                    "issuer_jwk": rogue_alpha_dave.public_jwk(),
                    "issuer_svid": rogue_alpha_dave.workload_svid,
                    "task_id": "t-sod",
                    "release_id": "REL-2026-884",
                    "artifact_sha256": "sha256:evil",
                    "scan_passed": True,
                    "iat": now_ts,
                    "exp": now_ts + 300.0,
                },
                rogue_alpha_dave.keypair,
                typ="lct-compliance-attestation+jwt",
            )
            r_rogue = httpx.post(
                f"{out_u.rstrip('/')}/v1/proxy/call",
                json={
                    "action": "verify_compliance_attestation",
                    "attestation_jws": forged_att,
                    "expected_task_id": "t-sod",
                    "expected_release_id": "REL-2026-884",
                    "allowed_scanner_suffix": "",
                },
                headers={"X-LCT-Loopback-Auth": lsec},
            )
            self.assertEqual(r_rogue.status_code, 403)

            # 2. `sign_release` enforces `artifact_sha256` match (`403 ARTIFACT_DIGEST_MISMATCH`) & JTI single-use!
            t_req = mint_root_token(
                ca_a.ca, "t-sod", "user:alice@org-alpha.io", alice_id.jkt,
                alice_id.spiffe_id, alice_id.jkt,
                PermissionLattice.create(tools=["sign_release"], param_whitelist={"release_id": ["REL-2026-884"]}, max_calls=6),
            )
            t_own = mint_root_token(
                ca_p.ca, "t-sod", "user:carol@org-payment.io", vault_id.jkt,
                alice_id.spiffe_id, alice_id.jkt,
                PermissionLattice.create(tools=["sign_release"], max_amount=0.0, param_whitelist={"release_id": ["REL-2026-884"]}, max_calls=6),
                hop_segment="CarolConsent",
            )
            co_tok = CoAuthorizedToken.assemble_and_sign(alice_id, t_req, t_own).encode_compact()
            mcp_u = f"{in_u.rstrip('/')}/mcp"

            def _dave_att(jti_val: str) -> str:
                return jws_sign_compact(
                    {
                        "jti": jti_val,
                        "issuer_spiffe_id": real_beta_dave.spiffe_id,
                        "issuer_jwk": real_beta_dave.public_jwk(),
                        "issuer_svid": real_beta_dave.workload_svid,
                        "task_id": "t-sod",
                        "release_id": "REL-2026-884",
                        "artifact_sha256": "sha256:good-art",
                        "scan_passed": True,
                        "iat": now_ts,
                        "exp": now_ts + 300.0,
                    },
                    real_beta_dave.keypair,
                    typ="lct-compliance-attestation+jwt",
                )

            att1 = _dave_att("jti-sod-1")
            r_bad_sha = httpx.post(
                mcp_u,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "sign_release",
                        "arguments": {
                            "release_id": "REL-2026-884",
                            "compliance_attestation_jws": att1,
                            "artifact_sha256": "sha256:tampered-art",
                        },
                    },
                },
                headers={"Authorization": f"DPoP {co_tok}", "DPoP": create_dpop_proof(alice_id, "POST", mcp_u, co_tok)},
            )
            self.assertEqual(r_bad_sha.status_code, 403)
            self.assertEqual(r_bad_sha.json()["error"], "ARTIFACT_DIGEST_MISMATCH")

            # Replaying `att1` (`jti-sod-1` already consumed) -> 403!
            r_rep = httpx.post(
                mcp_u,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "sign_release",
                        "arguments": {
                            "release_id": "REL-2026-884",
                            "compliance_attestation_jws": att1,
                            "artifact_sha256": "sha256:good-art",
                        },
                    },
                },
                headers={"Authorization": f"DPoP {co_tok}", "DPoP": create_dpop_proof(alice_id, "POST", mcp_u, co_tok)},
            )
            self.assertEqual(r_rep.status_code, 403)

            # Fresh `att2` with matching `artifact_sha256` -> 200!
            att2 = _dave_att("jti-sod-2")
            r_ok = httpx.post(
                mcp_u,
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "sign_release",
                        "arguments": {
                            "release_id": "REL-2026-884",
                            "compliance_attestation_jws": att2,
                            "artifact_sha256": "sha256:good-art",
                        },
                    },
                },
                headers={"Authorization": f"DPoP {co_tok}", "DPoP": create_dpop_proof(alice_id, "POST", mcp_u, co_tok)},
            )
            self.assertEqual(r_ok.status_code, 200)
            self.assertTrue(r_ok.json()["result"]["data"]["sod_verified"])
        finally:
            vault_app.stop()
            sc.stop()

    def test_05_verify_medium_m10_01_oauth_dual_mode_a2a_jsonrpc_and_configuration_private_tool_blocked(self) -> None:
        """Verify [MEDIUM-M10-01]: All A2A JSON-RPC & top-level private tool envelopes blocked `403` at Sidecar ingress."""
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
            single_entity_issuers=True,
        )
        ocli = OAuthTokenExchangeClient(realm="lct", client_secrets=bundle.client_secrets)
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
            loopback_secret=secrets.token_urlsafe(18),
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
                sts_origins=sts_u, subject_token=alice_tok, target_audience=bob_id.spiffe_id, client_id="lct-gateway"
            ).access_token
            hdrs = {"Authorization": f"Bearer {ex_alice}", "X-LCT-Delegation-Mode": "oauth_centralized"}

            payloads = [
                ("/a2a/task", {"private_tool": "hr_salary_read"}),
                ("/a2a/task", {"tool": "hr_salary_read"}),
                (
                    "/a2a",
                    {
                        "jsonrpc": "2.0",
                        "id": "1",
                        "method": "message/send",
                        "params": {"message": {"role": "ROLE_USER", "parts": [{"data": {"private_tool": "hr_salary_read"}}]}},
                    },
                ),
                (
                    "/a2a",
                    {
                        "jsonrpc": "2.0",
                        "id": "2",
                        "method": "message/send",
                        "params": {"configuration": {"private_tool": "hr_salary_read"}, "message": {"role": "ROLE_USER", "parts": []}},
                    },
                ),
            ]
            for path, body in payloads:
                resp = httpx.post(f"{in_u}{path}", json=body, headers=hdrs)
                self.assertEqual(resp.status_code, 403, (path, resp.text))
                self.assertEqual(resp.json()["error"], "CROSS_PRINCIPAL_DENIED")
            self.assertEqual(reached_upstream["count"], 0)
        finally:
            sc.stop()
            up_srv.stop()
            sts.stop()

    def test_06_verify_medium_m10_02_user_gateway_locked_sender_jkt_ssrf_token_sig_and_zero_verify_false(self) -> None:
        """Verify [MEDIUM-M10-02]: Locked `sender_jkt`, CA sig check, SSRF `403`, & `0` `verify=False`."""
        ugw_src = inspect.getsource(user_gateway_mod)
        self.assertNotIn("verify=False", ugw_src)

        ca_a = AutonomousDomainCAService("org-alpha.io", "lineage-alpha", host="127.0.0.1", port=0)
        ca_b = AutonomousDomainCAService(
            "org-beta.io", "lineage-beta", authorized_gateway_sa="beta-user-gateway", host="127.0.0.1", port=0
        )
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_a.ca)
        resolver.register_domain_ca(ca_b.ca)

        bundle = generate_keycloak_realm_bundle()
        sts_b = OAuthSTSService(
            trust_domain="org-beta.io",
            realm="lct",
            user_passwords=bundle.user_passwords,
            client_secrets=bundle.client_secrets,
            host="127.0.0.1",
            port=0,
        )
        u_b = sts_b.start()
        oidc_b = OIDCTokenVerifier(
            jwks_urls=[f"{u_b}/realms/lct/protocol/openid-connect/certs"],
            expected_issuer=f"{u_b}/realms/lct",
            default_user_domain="org-beta.io",
            allowed_user_domains=("org-beta.io",),
            single_entity_issuers=True,
        )
        ca_b.oidc_verifier = oidc_b
        ca_b.k8s_verifier = _MemSAVerifier({"sa-bgw": ("lineage-beta", "beta-user-gateway")})  # type: ignore[assignment]
        ca_b_u = ca_b.start()

        x509_store = X509FederationTrustStore()
        x509_store.register_domain_root_pem("org-alpha.io", ca_a.x509_ca.export_root_pem())
        x509_store.register_domain_root_pem("org-beta.io", ca_b.x509_ca.export_root_pem())

        bgw_id = ca_b.ca.issue_workload("/ns/lineage-beta/sa/beta-user-gateway")
        bgw_mtls = WorkloadMTLSBundle(
            bgw_id.spiffe_id, bgw_id.keypair,
            ca_b.x509_ca.issue_x509_svid(bgw_id.spiffe_id, bgw_id.keypair.public_jwk(), ip_addresses=("127.0.0.1",)),
            x509_store,
        )
        agw_id = ca_a.ca.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
        agw_mtls = WorkloadMTLSBundle(
            agw_id.spiffe_id, agw_id.keypair,
            ca_a.x509_ca.issue_x509_svid(agw_id.spiffe_id, agw_id.keypair.public_jwk(), ip_addresses=("127.0.0.1",)),
            x509_store,
        )
        bob_id = ca_b.ca.issue_workload("/ns/lineage-beta/sa/assistant-bob")
        sc_bob = LineageSidecar(
            identity=bob_id,
            trust_resolver=resolver,
            app_upstream_url="http://127.0.0.1:1",
            loopback_secret=secrets.token_urlsafe(18),
            inbound_host="127.0.0.1",
            inbound_port=0,
            outbound_port=0,
        )
        bob_in_u, _ = sc_bob.start()

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
            bob_tok = ocli.login_user_password(u_b, "bob", bundle.user_passwords["bob"], "lct-gateway")["access_token"]

            with httpx.Client(verify=agw_mtls.verify_for_target(ugw_u, expected_spiffe_id=bgw_id.spiffe_id)) as cli:
                # 1. Foreign `sender_jkt` rejected (`403 SENDER_JKT_MISMATCH`)!
                r_fk = cli.post(
                    f"{ugw_u}/v1/gateway/mint-root",
                    json={
                        "task_id": "t-fk",
                        "sub": "user:bob@org-beta.io",
                        "user_oidc_token": bob_tok,
                        "sender_jkt": agw_id.jkt,
                        "first_hop_spiffe_id": bob_id.spiffe_id,
                        "first_hop_jkt": bob_id.jkt,
                        "permissions": PermissionLattice.create(tools=["service_diag_read"], max_calls=2).to_dict(),
                    },
                )
                self.assertEqual(r_fk.status_code, 403)
                self.assertEqual(r_fk.json()["error"], "SENDER_JKT_MISMATCH")

                # 2. Minted Bob token binds `sender_jkt == bgw_id.jkt`, so `agw_id` replaying it against `assistant-bob` fails `403`!
                r_m = cli.post(
                    f"{ugw_u}/v1/gateway/mint-root",
                    json={
                        "task_id": "t-stolen-bob",
                        "sub": "user:bob@org-beta.io",
                        "user_oidc_token": bob_tok,
                        "first_hop_spiffe_id": bob_id.spiffe_id,
                        "first_hop_jkt": bob_id.jkt,
                        "permissions": PermissionLattice.create(tools=["service_diag_read"], max_calls=2).to_dict(),
                    },
                )
                self.assertEqual(r_m.status_code, 200)
                minted_tok = r_m.json()["compact_token"]
                self.assertEqual(decode_token(minted_tok).root.sender_jkt, bgw_id.jkt)

                bob_task_u = f"{bob_in_u.rstrip('/')}/a2a/task"
                r_replay_on_bob = httpx.post(
                    bob_task_u,
                    json={"private_tool": "service_diag_read"},
                    headers={
                        "Authorization": f"DPoP {minted_tok}",
                        "DPoP": create_dpop_proof(agw_id, "POST", bob_task_u, minted_tok),
                    },
                )
                self.assertEqual(r_replay_on_bob.status_code, 403)
                self.assertEqual(r_replay_on_bob.json()["error"], "DPOP_FAILED")

                # 3. SSRF target `https://8.8.8.8:8443` -> deterministic `403 FORBIDDEN_DISPATCH_TARGET`!
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
                self.assertEqual(r_ssrf.status_code, 403)
                self.assertEqual(r_ssrf.json()["error"], "FORBIDDEN_DISPATCH_TARGET")

                # 4. Forged-CA `RootBlock` claiming `org-beta.io` rejected by `_get_local_trust_resolver` (`403`)!
                rogue_beta_ca = AutonomousDomainCAService("org-beta.io", "lineage-beta", host="127.0.0.1", port=0)
                forged_root_tok = mint_root_token(
                    rogue_beta_ca.ca,
                    "t-forged",
                    "user:bob@org-beta.io",
                    bgw_id.jkt,
                    bob_id.spiffe_id,
                    bob_id.jkt,
                    PermissionLattice.create(tools=["service_diag_read"], max_calls=2),
                ).encode_compact()
                r_forged = cli.post(
                    f"{ugw_u}/v1/gateway/dispatch",
                    json={
                        "sub": "user:bob@org-beta.io",
                        "user_oidc_token": bob_tok,
                        "compact_token": forged_root_tok,
                        "target_endpoint": "https://10.29.101.203:31103",
                        "payload": {},
                    },
                )
                self.assertEqual(r_forged.status_code, 403)
                self.assertEqual(r_forged.json()["error"], "INVALID_GATEWAY_ROOT_TOKEN")
        finally:
            ugw.stop()
            sc_bob.stop()
            ca_b.stop()
            sts_b.stop()
            bgw_mtls.cleanup()
            agw_mtls.cleanup()

    def test_07_verify_low_m10_01_svid_signed_cohort_digests_and_two_phase_replay_commit(self) -> None:
        """Verify [LOW-M10-01]: SVID-signed `lct-cohort-digest+jwt` & atomic two-phase `JTIReplayCache` commit."""
        ca_a = AutonomousDomainCAService("org-alpha.io", "lineage-alpha", host="127.0.0.1", port=0)
        ca_b = AutonomousDomainCAService("org-beta.io", "lineage-beta", host="127.0.0.1", port=0)
        ca_p = AutonomousDomainCAService("org-payment.io", "lineage-pay", host="127.0.0.1", port=0)
        resolver = TrustBundleResolver()
        for c in (ca_a, ca_b, ca_p):
            resolver.register_domain_ca(c.ca)

        alice_id = ca_a.ca.issue_workload("/ns/lineage-alpha/sa/assistant-alice")
        bob_id = ca_b.ca.issue_workload("/ns/lineage-beta/sa/assistant-bob")
        carol_id = ca_p.ca.issue_workload("/ns/lineage-pay/sa/assistant-carol")
        vault_id = ca_p.ca.issue_workload("/ns/lineage-pay/sa/assistant-vault")

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
            tid = "t-cohort-2pc"
            study_id = "STUDY-MED-2026-07"
            tok = mint_root_token(
                ca_a.ca, tid, "user:alice@org-alpha.io", alice_id.jkt,
                alice_id.spiffe_id, alice_id.jkt,
                PermissionLattice.create(
                    tools=["federated_cohort_aggregate"], param_whitelist={"study_id": [study_id]}, max_calls=10
                ),
            ).encode_compact()
            mcp_u = f"{in_u.rstrip('/')}/mcp"

            def _make_dig(wid: object, inst_name: str, cnt: int, rate: float, jti_v: str) -> Dict[str, object]:
                now_d = time.time()
                w = wid  # type: ignore[assignment]
                jws = jws_sign_compact(
                    {
                        "jti": jti_v,
                        "institution_spiffe_id": w.spiffe_id,  # type: ignore[attr-defined]
                        "institution": inst_name,
                        "issuer_jwk": w.public_jwk(),  # type: ignore[attr-defined]
                        "issuer_svid": w.workload_svid,  # type: ignore[attr-defined]
                        "task_id": tid,
                        "study_id": study_id,
                        "sample_count": cnt,
                        "event_rate": rate,
                        "desensitized": True,
                        "raw_pii_present": False,
                        "iat": now_d,
                        "exp": now_d + 300.0,
                    },
                    w.keypair,  # type: ignore[attr-defined]
                    typ="lct-cohort-digest+jwt",
                )
                return {
                    "institution": inst_name,
                    "study_id": study_id,
                    "desensitized": True,
                    "raw_pii_present": False,
                    "sample_count": cnt,
                    "event_rate": rate,
                    "digest_jws": jws,
                }

            dig_b1 = _make_dig(bob_id, "institution-bob", 420, 0.074, "cdig-b1")
            dig_b2 = _make_dig(bob_id, "institution-bob-alias", 420, 0.074, "cdig-b2")
            dig_c1 = _make_dig(carol_id, "institution-carol", 380, 0.068, "cdig-c1")

            def _post_agg(digests_list: object) -> httpx.Response:
                return httpx.post(
                    mcp_u,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "federated_cohort_aggregate",
                            "arguments": {"study_id": study_id, "cohort_digests": digests_list},
                        },
                    },
                    headers={"Authorization": f"DPoP {tok}", "DPoP": create_dpop_proof(alice_id, "POST", mcp_u, tok)},
                )

            # 1. Unsigned digest rejected (`403 INVALID_COHORT_DIGEST_SIGNATURE`)
            r_unsig = _post_agg([{k: v for k, v in dig_b1.items() if k != "digest_jws"}, dig_c1])
            self.assertEqual(r_unsig.status_code, 403)
            self.assertEqual(r_unsig.json()["error"], "INVALID_COHORT_DIGEST_SIGNATURE")

            # 2. Tampered `sample_count` rejected (`403 INVALID_COHORT_DIGEST_SIGNATURE`)
            r_tamp = _post_agg([{**dig_b1, "sample_count": 9999}, dig_c1])
            self.assertEqual(r_tamp.status_code, 403)
            self.assertEqual(r_tamp.json()["error"], "INVALID_COHORT_DIGEST_SIGNATURE")

            # 3. Two digests signed by the SAME workload (`bob_id`) rejected (`403 INSUFFICIENT_COHORT_INSTITUTIONS`),
            #    AND two-phase check does NOT prematurely burn `dig_b1`'s `jti`!
            r_same_inst = _post_agg([dig_b1, dig_b2])
            self.assertEqual(r_same_inst.status_code, 403)
            self.assertEqual(r_same_inst.json()["error"], "INSUFFICIENT_COHORT_INSTITUTIONS")

            # 4. Subsequent valid `[dig_b1, dig_c1]` succeeds (`200`) and commits both JTIs!
            r_ok = _post_agg([dig_b1, dig_c1])
            self.assertEqual(r_ok.status_code, 200, r_ok.text)
            agg_d = r_ok.json()["result"]["data"]
            self.assertTrue(agg_d["cohort_digests_verified"])
            self.assertEqual(agg_d["institutions_aggregated"], 2)

            # 5. Replaying `[dig_b1, dig_c1]` now fails `403 INVALID_COHORT_DIGEST_SIGNATURE`!
            r_rep = _post_agg([dig_b1, dig_c1])
            self.assertEqual(r_rep.status_code, 403)
            self.assertEqual(r_rep.json()["error"], "INVALID_COHORT_DIGEST_SIGNATURE")
        finally:
            vault_app.stop()
            sc.stop()

    def test_08_verify_r2_rehearsal_evidence_and_secret_hygiene(self) -> None:
        """Verify Round-2 live 3-cluster rehearsal archive (`12/12 PASS`, sovereign OIDC, signed digests, `0` secrets)."""
        summary_file = M10_R2_REHEARSAL_DIR / "workspace_platform_v2_summary.json"
        self.assertTrue(summary_file.is_file(), f"Missing {summary_file}")
        summary = json.loads(summary_file.read_text(encoding="utf-8"))
        self.assertEqual(summary["run_id"], "m10-r2-verified")
        self.assertIs(summary["central_audit_collector_deployed"], False)
        self.assertEqual(summary["overall_status"], "PASS")
        self.assertEqual(len(summary["scenarios"]), 12)
        for name, sc_doc in summary["scenarios"].items():
            self.assertEqual(sc_doc.get("status"), "PASS", f"Scenario {name} did not PASS")

        # Confirm Round-2 specific live evidence
        s9_agg = summary["scenarios"]["9_federated_medical_cohort"]["aggregated_cohort"]
        self.assertIs(s9_agg["cohort_digests_verified"], True)
        self.assertEqual(
            set(s9_agg["verified_institution_spiffe_ids"]),
            {
                "spiffe://org-beta.io/ns/lineage-beta/sa/assistant-bob",
                "spiffe://org-payment.io/ns/lineage-pay/sa/assistant-carol",
            },
        )
        s11 = summary["scenarios"]["11_symmetric_beta_entry_and_token_theft"]
        self.assertEqual(s11["beta_gateway_alice_cross_domain_http"], 401)

        for fname in ("distributed_audit_cli_s8.json", "distributed_audit_cli_s11.json"):
            aud = json.loads((M10_R2_REHEARSAL_DIR / fname).read_text(encoding="utf-8"))
            self.assertIs(aud["reconstructed_complete"], True)
            self.assertEqual(aud["unreachable_nodes"], {})
            self.assertEqual(aud["anomalies"], [])

        jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
        wire_tok_re = re.compile(r"lct(?:1|mp1|m1|co1)\.[A-Za-z0-9_-]{16,}")
        priv_pem_prefix = "-----BEGIN " + "PRIVATE KEY-----"
        ec_pem_prefix = "-----BEGIN EC " + "PRIVATE KEY-----"
        for fpath in M10_R2_REHEARSAL_DIR.iterdir():
            if fpath.is_file():
                txt = fpath.read_text(encoding="utf-8")
                self.assertNotIn(priv_pem_prefix, txt, f"Private key leaked in {fpath.name}")
                self.assertNotIn(ec_pem_prefix, txt, f"EC private key leaked in {fpath.name}")
                self.assertIsNone(jwt_re.search(txt), f"Raw JWT leaked in {fpath.name}")
                self.assertIsNone(wire_tok_re.search(txt), f"Raw LCT wire token leaked in {fpath.name}")


if __name__ == "__main__":
    unittest.main()
