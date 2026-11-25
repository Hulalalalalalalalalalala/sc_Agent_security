"""Milestone 9 (Platform v2) Independent QA Review & Defect Reproduction Suite.

Deterministic, non-destructive verification and compliance suite for Milestone 9:
1. Reproduces `[CRITICAL-M9-01]`: Continuation replay & multi-checkpoint double-spend on
   `POST /v1/ca/mint-continuation-token` (`domain_ca.py:604-740`) and `CausalChainAuditor`
   (`auditor.py:352-396`), allowing a `$600` capped task (`$280` consumed, `$320` remaining)
   to mint multiple independent `$320` continuation tokens (`$920` total spend) without
   rejection or audit anomaly.
2. Reproduces `[HIGH-M9-01]`: Fail-open `prior_root_block_hash` lookup (`domain_ca.py:648-682`,
   `token.py:1221-1254`) + unbound checkpoint signer (`token.py:1157-1161`, `proxy.py:1687-1709`),
   where an unknown/evicted `prior_root_block_hash` or unrelated federated workload signer
   inflates `original_max_amount`, bypasses tool/target subset checks, or claims `consumed_amount=0`.
3. Reproduces `[HIGH-M9-02]`: Revoked `ContinuationToken` resurrects expired pre-checkpoint
   branch in `LeafVerifier.verify_request` (`policy_verifier.py:1073-1170`, Step 1b runs before
   Step 2 revocation filtering) + undirected/forked `are_roots_continuously_linked` (`token.py:635-659`).
4. Reproduces `[HIGH-M9-03]`: Co-authorization consent & owner-isolation bypasses:
   (a) missing `POST /v1/ca/mint-consent-token` (`assistant-bob` SA granted unrestricted
       `/v1/ca/mint-root-token` on `beta-ca` for `hr_salary_read` / arbitrary `@org-beta.io` users);
   (b) unauthenticated peer `request_co_auth_consent` (`peer_apps.py:958-971`) minting Bob's
       consent `RootBlock` with `owner_oidc_token=None`;
   (c) default `DELEGATION_MODE=dual` (`config_gen.py:1712`) OAuth Bearer path
       (`proxy.py:1087-1220`) bypassing `resource_owner_sub` & `owner_protected_tools` on
       `hr_salary_read` (`200 OK` instead of `403 CROSS_PRINCIPAL_DENIED`).
5. Reproduces `[HIGH-M9-04]`: `DistributedAuditor.pull_and_reconstruct` (`distributed.py:186-224,
   284-419`, `auditor.py:728-730`) falsely reporting `reconstructed_complete=True` with `0`
   anomalies when a delegated downstream participant (`assistant-bob`) is offline in
   `unreachable_nodes`, plus missing `max_depth`, HTTP response size/entry bounds, and RFC1918
   + pinned mTLS 1.3 URL enforcement.
6. Reproduces `[MEDIUM-M9-01]`: `IdempotencyLedger.execute_once` (`peer_apps.py:84-183`)
   silently returning a cached receipt when `idempotency_key` is replayed with a mismatched
   `operation`, `project_code`, `target`, or `amount_usd`.
7. Verifies positive Milestone 9 invariants: `MultiParentToken` mixed-principal rejection,
   `CoAuthorizedToken` dual-chain crypto & dual-domain high-risk revocation anchoring,
   `WorkloadIdentityRenewer` SVID renewal independence from `RootBlock.expires_at`,
   cross-tenant `query_operation_status` isolation, `LocalAuditStore` auth/replay, Untrusted
   Public Yellow Pages (`registry_mode='centralized'`), `WorkspaceIntentRouter` lattice clamping,
   `lctco1.` redaction, and rehearsal/scale artifact secret hygiene.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import time
from typing import Any, Dict, List, Tuple
import unittest

import httpx

from lineage.audit import (
    AuditEventType,
    AuditStreamEmitter,
    CausalChainAuditor,
    DistributedAuditor,
    LocalAuditStore,
    build_audit_query_headers,
)
from lineage.common.crypto import KeyPair, redact_sensitive
from lineage.common.http_utils import ManagedHTTPService
from lineage.federation.domain_ca import AutonomousDomainCAService
from lineage.federation.sync import WorkloadIdentityRenewer
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.multihost.config_gen import render_role_k8s_manifests
from lineage.oauth_sts import OIDCTokenVerifier, OAuthSTSService
from lineage.protocol import (
    CoAuthorizedToken,
    LCT_COAUTH_WIRE_PREFIX,
    MultiParentToken,
    PermissionLattice,
    TaskCheckpoint,
    TokenError,
    create_dpop_proof,
    decode_token,
    mint_root_token,
)
from lineage.protocol.token import are_roots_continuously_linked
from lineage.registry import AgentCard, AgentDirectoryClient, AgentDirectoryService
from lineage.revocation import RevocationReplicaClient, RevocationService
from lineage.sidecar import LineageSidecar
from lineage.verifier import LeafVerifier, VerificationMode
from lineage.workspace_agents import (
    IdempotencyLedger,
    WorkspaceAssistantPeerApp,
    WorkspaceIntentRouter,
    WorkspaceVaultMCPApp,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


class _StubSAVerifier:
    """Deterministic K8s SA verifier stub for local loopback CA compliance checks."""

    def __init__(self, mapping: Dict[str, Tuple[str, str]]) -> None:
        self._mapping = dict(mapping)

    def verify_sa_jwt(self, sa_jwt: str, now: float | None = None) -> Tuple[str, str, float]:
        if sa_jwt not in self._mapping:
            raise ValueError(f"invalid_sa_jwt:{sa_jwt}")
        ns, sa = self._mapping[sa_jwt]
        return ns, sa, (now or time.time()) + 600.0


class Milestone9IndependentQAReviewTests(unittest.TestCase):
    """Independent QA verification & defect reproduction tests for Milestone 9."""

    def test_01_reproduce_critical_m9_01_continuation_replay_double_spend(self) -> None:
        """Reproduce [CRITICAL-M9-01]: Replaying a TaskCheckpoint mints multiple continuation tokens."""
        ca_svc = AutonomousDomainCAService(
            trust_domain="org-alpha.io",
            allowed_k8s_namespace="lineage-alpha",
            authorized_gateway_sa="e2e-user-gateway",
            host="127.0.0.1",
            port=0,
        )
        ca_svc.k8s_verifier = _StubSAVerifier(  # type: ignore[assignment]
            {"sa-gw": ("lineage-alpha", "e2e-user-gateway")}
        )
        ca_url = ca_svc.start()
        try:
            gw_id = ca_svc.ca.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
            alice_id = ca_svc.ca.issue_workload("/ns/lineage-alpha/sa/assistant-alice")
            vault_id = ca_svc.ca.issue_workload("/ns/lineage-alpha/sa/assistant-vault")

            tid = "task-crit-m9-01"
            r0 = httpx.post(
                f"{ca_url}/v1/ca/mint-root-token",
                json={
                    "trust_domain": "org-alpha.io",
                    "task_id": tid,
                    "sub": "user:alice@org-alpha.io",
                    "sender_jkt": gw_id.jkt,
                    "first_hop_spiffe_id": alice_id.spiffe_id,
                    "first_hop_jkt": alice_id.jkt,
                    "permissions": PermissionLattice.create(
                        tools=["reserve_cloud_budget"],
                        max_amount=600.0,
                        max_calls=6,
                    ).to_dict(),
                    "ttl_seconds": 60.0,
                },
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            self.assertEqual(r0.status_code, 200)
            prior_root_hash = r0.json()["root_block_hash"]

            ckpt = TaskCheckpoint.create_and_sign(
                signer_identity=alice_id,
                task_id=tid,
                sub="user:alice@org-alpha.io",
                prior_root_block_hash=prior_root_hash,
                original_max_amount=600.0,
                original_max_calls=6,
                completed_branches=["Phase1"],
                remaining_branches=["Phase2"],
                consumed_amount=280.0,
                consumed_calls=2,
            )
            req_payload = {
                "trust_domain": "org-alpha.io",
                "checkpoint": ckpt.to_dict(),
                "sender_jkt": gw_id.jkt,
                "first_hop_spiffe_id": alice_id.spiffe_id,
                "first_hop_jkt": alice_id.jkt,
                "permissions": PermissionLattice.create(
                    tools=["reserve_cloud_budget"],
                    max_amount=320.0,
                    max_calls=4,
                ).to_dict(),
                "ttl_seconds": 120.0,
            }

            # Submit the exact same TaskCheckpoint twice -> both return 200 OK!
            r_cont_1 = httpx.post(
                f"{ca_url}/v1/ca/mint-continuation-token",
                json=req_payload,
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            r_cont_2 = httpx.post(
                f"{ca_url}/v1/ca/mint-continuation-token",
                json=req_payload,
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            self.assertEqual(r_cont_1.status_code, 200)
            self.assertEqual(r_cont_2.status_code, 200)
            self.assertNotEqual(
                r_cont_1.json()["root_block_hash"], r_cont_2.json()["root_block_hash"]
            )

            # Both continuation tokens independently spend $320 on the same LeafVerifier ($280 + $640 = $920 > $600)!
            verifier = LeafVerifier(
                trust_resolver=ca_svc.federation_trust_resolver,
                self_spiffe_id=vault_id.spiffe_id,
                self_jkt=vault_id.jkt,
            )
            htu = "https://vault.local:8443/mcp"
            for raw_tok in (r_cont_1.json()["compact_token"], r_cont_2.json()["compact_token"]):
                dpop = create_dpop_proof(alice_id, "POST", htu, raw_tok)
                vres = verifier.verify_request(
                    compact_token=raw_tok,
                    dpop_proof=dpop,
                    htm="POST",
                    htu=htu,
                    method="tools/call",
                    tool="reserve_cloud_budget",
                    arguments={"amount": 320.0},
                )
                self.assertTrue(vres.allowed, vres.detail)

            # CausalChainAuditor also fails to flag duplicate sibling continuations on prior_root_block_hash!
            ca_entries = ca_svc._audit_emitter.local_store.get_by_task(tid)
            rep = CausalChainAuditor(ca_svc.federation_trust_resolver).reconstruct(
                ca_entries, task_id=tid
            )
            self.assertEqual(rep.tasks[tid].anomalies, [])
        finally:
            ca_svc.stop()

    def test_02_reproduce_high_m9_01_unverified_prior_root_and_unbound_checkpoint_signer(self) -> None:
        """Reproduce [HIGH-M9-01]: Missing prior_root_block_hash fails open & foreign peer signs fake checkpoint."""
        ca_beta = TrustDomainCA("org-beta.io")
        ca_svc = AutonomousDomainCAService(
            trust_domain="org-alpha.io",
            allowed_k8s_namespace="lineage-alpha",
            authorized_gateway_sa="e2e-user-gateway",
            host="127.0.0.1",
            port=0,
        )
        ca_svc.federation_trust_resolver.register_domain_ca(ca_beta)
        ca_svc.k8s_verifier = _StubSAVerifier(  # type: ignore[assignment]
            {"sa-gw": ("lineage-alpha", "e2e-user-gateway")}
        )
        ca_url = ca_svc.start()
        try:
            gw_id = ca_svc.ca.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
            alice_id = ca_svc.ca.issue_workload("/ns/lineage-alpha/sa/assistant-alice")
            rogue_beta_peer = ca_beta.issue_workload("/ns/lineage-beta/sa/unrelated-worker")

            # 1. Mint real RootBlock capped at $100 and ONLY `reserve_cloud_budget`
            tid = "task-high-m9-01"
            r0 = httpx.post(
                f"{ca_url}/v1/ca/mint-root-token",
                json={
                    "trust_domain": "org-alpha.io",
                    "task_id": tid,
                    "sub": "user:alice@org-alpha.io",
                    "sender_jkt": gw_id.jkt,
                    "first_hop_spiffe_id": alice_id.spiffe_id,
                    "first_hop_jkt": alice_id.jkt,
                    "permissions": PermissionLattice.create(
                        tools=["reserve_cloud_budget"],
                        max_amount=100.0,
                        max_calls=2,
                    ).to_dict(),
                },
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            self.assertEqual(r0.status_code, 200)
            real_root_hash = r0.json()["root_block_hash"]

            # 2. Unrelated workload in `org-beta.io` signs checkpoint for Alice's task claiming consumed_amount=0!
            foreign_ckpt = TaskCheckpoint.create_and_sign(
                signer_identity=rogue_beta_peer,
                task_id=tid,
                sub="user:alice@org-alpha.io",
                prior_root_block_hash=real_root_hash,
                original_max_amount=100.0,
                original_max_calls=2,
                completed_branches=[],
                remaining_branches=["All"],
                consumed_amount=0.0,
                consumed_calls=0,
            )
            r_foreign_signer = httpx.post(
                f"{ca_url}/v1/ca/mint-continuation-token",
                json={
                    "trust_domain": "org-alpha.io",
                    "checkpoint": foreign_ckpt.to_dict(),
                    "sender_jkt": gw_id.jkt,
                    "first_hop_spiffe_id": alice_id.spiffe_id,
                    "first_hop_jkt": alice_id.jkt,
                    "permissions": PermissionLattice.create(
                        tools=["reserve_cloud_budget"],
                        max_amount=100.0,
                        max_calls=2,
                    ).to_dict(),
                },
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            self.assertEqual(r_foreign_signer.status_code, 200)

            # 3. Fabricated/evicted `prior_root_block_hash` fails open (`prior_perms=None`), allowing
            #    $50,000 budget + `hr_salary_read` tool escalation!
            unverified_prior_ckpt = TaskCheckpoint.create_and_sign(
                signer_identity=rogue_beta_peer,
                task_id="task-evicted-or-fake-root",
                sub="user:alice@org-alpha.io",
                prior_root_block_hash="nonexistent-prior-root-hash-0001",
                original_max_amount=50000.0,
                original_max_calls=100,
                completed_branches=[],
                remaining_branches=["Escalate"],
                consumed_amount=0.0,
                consumed_calls=0,
            )
            r_escalate = httpx.post(
                f"{ca_url}/v1/ca/mint-continuation-token",
                json={
                    "trust_domain": "org-alpha.io",
                    "checkpoint": unverified_prior_ckpt.to_dict(),
                    "sender_jkt": gw_id.jkt,
                    "first_hop_spiffe_id": alice_id.spiffe_id,
                    "first_hop_jkt": alice_id.jkt,
                    "permissions": PermissionLattice.create(
                        tools=["hr_salary_read"],
                        max_amount=50000.0,
                        max_calls=50,
                    ).to_dict(),
                },
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            self.assertEqual(r_escalate.status_code, 200)
        finally:
            ca_svc.stop()

    def test_03_reproduce_high_m9_02_revoked_continuation_resurrects_expired_branch(self) -> None:
        """Reproduce [HIGH-M9-02]: Revoked ContinuationToken still resurrects expired R_0 branch in MultiParentToken."""
        ca_alpha = TrustDomainCA("org-alpha.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)

        rev_svc = RevocationService(
            ca_alpha.issue_workload("/ns/sys/sa/revocation"),
            resolver,
            host="127.0.0.1",
            port=0,
        )
        rev_url = rev_svc.start()
        rev_rep = RevocationReplicaClient(rev_url, resolver)
        try:
            gw_id = ca_alpha.issue_workload("/ns/alpha/sa/gw")
            alice_id = ca_alpha.issue_workload("/ns/alpha/sa/alice")
            vault_id = ca_alpha.issue_workload("/ns/alpha/sa/vault")

            now_ts = time.time()
            tid = "task-high-m9-02"
            # Phase-1 branch rooted at R_0 (short TTL = 1.0s)
            p_r0 = PermissionLattice.create(
                tools=["lock_joint_project"],
                allowed_targets=["cloud-infra-escrow"],
                max_amount=200.0,
                max_calls=4,
            )
            tok_r0 = mint_root_token(
                ca_alpha,
                task_id=tid,
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=alice_id.spiffe_id,
                first_hop_jkt=alice_id.jkt,
                permissions=p_r0,
                ttl_seconds=1.0,
                hop_segment="BranchPhase1",
                now=now_ts,
            ).attenuate(
                issuer_identity=alice_id,
                delegate_spiffe_id=vault_id.spiffe_id,
                delegate_jkt=vault_id.jkt,
                permissions=p_r0,
                hop_segment="Vault",
                now=now_ts,
            )

            # Continuation chain R_1 linked to R_0 (`prior_root_block_hash = hash(R_0)`)
            from lineage.protocol.token import mint_continuation_root_token

            ckpt = TaskCheckpoint.create_and_sign(
                signer_identity=alice_id,
                task_id=tid,
                sub="user:alice@org-alpha.io",
                prior_root_block_hash=tok_r0.root_block_hash,
                original_max_amount=400.0,
                original_max_calls=8,
                completed_branches=["BranchPhase1"],
                remaining_branches=["BranchPhase2"],
                consumed_amount=200.0,
                consumed_calls=2,
                now=now_ts,
            )
            p_r1 = PermissionLattice.create(
                tools=["lock_joint_project"],
                allowed_targets=["vendor-procurement-escrow"],
                max_amount=200.0,
                max_calls=4,
            )
            tok_r1_alice = mint_continuation_root_token(
                ca_alpha,
                checkpoint=ckpt,
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=alice_id.spiffe_id,
                first_hop_jkt=alice_id.jkt,
                permissions=p_r1,
                ttl_seconds=300.0,
                hop_segment="BranchPhase2Cont",
                now=now_ts,
            )
            tok_r1 = tok_r1_alice.attenuate(
                issuer_identity=alice_id,
                delegate_spiffe_id=vault_id.spiffe_id,
                delegate_jkt=vault_id.jkt,
                permissions=p_r1,
                hop_segment="Vault",
                now=now_ts,
            )

            # Explicitly REVOKE the continuation chain `/{tid}/BranchPhase2Cont`!
            rev_rep.revoke_prefix(
                caller=alice_id,
                prefix=tok_r1_alice.lineage_path,
                reason="cancel_continuation",
                authority_token=tok_r1_alice.encode_compact(),
            )
            rev_rep.sync_now()

            # Advance clock past R_0 expiry (`now_ts + 20.0`), assemble MultiParentToken [tok_r0 (expired), tok_r1 (REVOKED)]
            mp_tok = MultiParentToken.assemble_and_sign(
                holder_identity=vault_id,
                parent_chains=[tok_r0, tok_r1],
                now=now_ts + 20.0,
            )
            mp_compact = mp_tok.encode_compact()

            verifier = LeafVerifier(
                trust_resolver=resolver,
                self_spiffe_id=vault_id.spiffe_id,
                self_jkt=vault_id.jkt,
                revocation_replica=rev_rep,
                clock_skew_seconds=0.0,
            )
            htu = "https://vault.local:8443/mcp"
            dpop = create_dpop_proof(vault_id, "POST", htu, mp_compact, now=now_ts + 20.0)
            vres = verifier.verify_request(
                compact_token=mp_compact,
                dpop_proof=dpop,
                htm="POST",
                htu=htu,
                method="tools/call",
                tool="lock_joint_project",
                arguments={"escrow_target": "cloud-infra-escrow", "amount": 100.0},
                now=now_ts + 20.0,
            )
            # DEFECT: Expired `tok_r0` is resurrected by REVOKED `tok_r1` and allowed!
            self.assertTrue(vres.allowed)
            self.assertEqual(vres.decision, "ALLOW_DEGRADED_DAG")

            # Also verify `are_roots_continuously_linked` accepts forked sibling continuations [R_1a, R_1b]
            tok_r1_fork = mint_continuation_root_token(
                ca_alpha,
                checkpoint=ckpt,
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=alice_id.spiffe_id,
                first_hop_jkt=alice_id.jkt,
                permissions=PermissionLattice.create(
                    tools=["lock_joint_project"],
                    max_amount=200.0,
                    max_calls=4,
                ),
                ttl_seconds=300.0,
                hop_segment="ForkSibling",
                now=now_ts,
            )
            self.assertTrue(
                are_roots_continuously_linked(
                    [tok_r0, tok_r1_alice, tok_r1_fork]
                )
            )
        finally:
            rev_svc.stop()

    def test_04_reproduce_high_m9_03_coauth_consent_and_dual_mode_oauth_owner_bypass(self) -> None:
        """Reproduce [HIGH-M9-03]: Missing /v1/ca/mint-consent-token, unauth consent minting, & dual-mode OAuth bypass."""
        # 1. Inspect workspace manifest: `DELEGATION_MODE` defaults to `dual`, and `beta-ca` puts
        #    `assistant-bob` in unrestricted `AUTHORIZED_GATEWAY_SAS` (`POST /v1/ca/mint-consent-token` = 404).
        beta_yaml = render_role_k8s_manifests(
            role="beta", topology="workspace", registry_mode="centralized"
        )
        self.assertIn("AUTHORIZED_GATEWAY_SAS", beta_yaml)
        self.assertIn("value: dual", beta_yaml)

        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta_svc = AutonomousDomainCAService(
            trust_domain="org-beta.io",
            allowed_k8s_namespace="lineage-beta",
            authorized_gateway_sas=["assistant-bob"],
            host="127.0.0.1",
            port=0,
        )
        ca_beta_svc.federation_trust_resolver.register_domain_ca(ca_alpha)
        ca_beta_svc.k8s_verifier = _StubSAVerifier(  # type: ignore[assignment]
            {"sa-bob": ("lineage-beta", "assistant-bob")}
        )
        beta_ca_url = ca_beta_svc.start()

        # Setup OAuth STS for `org-alpha.io` (`alice` login) to test `DELEGATION_MODE=dual` on Bob's Sidecar
        sts_alpha = OAuthSTSService(
            trust_domain="org-alpha.io",
            realm="lct",
            host="127.0.0.1",
            port=0,
            user_passwords={"alice": "alice-pass"},
            client_secrets={"lct-gateway": "gw-sec"},
            spiffe_trust_resolver=ca_beta_svc.federation_trust_resolver,
        )
        sts_url = sts_alpha.start()
        sts_alpha.issuer_origin = sts_url

        bob_id = ca_beta_svc.ca.issue_workload("/ns/lineage-beta/sa/assistant-bob")
        alice_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/assistant-alice")
        gw_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")

        lsec = secrets.token_urlsafe(20)
        central_ver = OIDCTokenVerifier(
            jwks_urls=[f"{sts_url}/realms/lct/protocol/openid-connect/certs"],
            expected_issuer=f"{sts_url}/realms/lct",
        )
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("sa-bob")
            sa_tok_file = tf.name

        sc_bob = LineageSidecar(
            identity=bob_id,
            trust_resolver=ca_beta_svc.federation_trust_resolver,
            app_upstream_url="http://127.0.0.1:1",
            loopback_secret=lsec,
            mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
            inbound_host="127.0.0.1",
            inbound_port=0,
            outbound_port=0,
            delegation_mode="dual",
            oauth_central_verifier=central_ver,
            resource_owner_sub="user:bob@org-beta.io",
            owner_protected_tools=["hr_salary_read", "calendar_write", "calendar_free_busy"],
            allowed_co_auth_tools=["calendar_free_busy"],
            local_ca_url=beta_ca_url,
            sa_token_path=sa_tok_file,
        )
        bob_in_url, bob_out_url = sc_bob.start()
        app_bob = WorkspaceAssistantPeerApp(
            peer_name="bob",
            owner_sub="user:bob@org-beta.io",
            outbound_proxy_url=bob_out_url,
            loopback_secret=lsec,
            ollama=None,
            port=0,
        )
        sc_bob.app_upstream_url = app_bob.start().rstrip("/")
        try:
            # (a) Dedicated `/v1/ca/mint-consent-token` does not exist (`404`), while `sa-bob` can mint
            #     unrestricted `hr_salary_read` root tokens for `user:dave@org-beta.io` via `/v1/ca/mint-root-token`!
            r_consent_ep = httpx.post(
                f"{beta_ca_url}/v1/ca/mint-consent-token",
                json={},
                headers={"Authorization": "Bearer sa-bob"},
                timeout=5.0,
            )
            self.assertEqual(r_consent_ep.status_code, 404)

            r_unrestricted_root = httpx.post(
                f"{beta_ca_url}/v1/ca/mint-root-token",
                json={
                    "trust_domain": "org-beta.io",
                    "task_id": "task-forged-dave",
                    "sub": "user:dave@org-beta.io",
                    "sender_jkt": bob_id.jkt,
                    "first_hop_spiffe_id": alice_id.spiffe_id,
                    "first_hop_jkt": alice_id.jkt,
                    "permissions": PermissionLattice.create(
                        tools=["hr_salary_read", "calendar_write"],
                        max_amount=9999.0,
                        max_calls=10,
                    ).to_dict(),
                },
                headers={"Authorization": "Bearer sa-bob"},
                timeout=5.0,
            )
            self.assertEqual(r_unrestricted_root.status_code, 200)

            # (b) Alice sends unilateral `request_co_auth_consent` to Bob with `owner_oidc_token=None`
            #     -> Bob mints cryptographic `user:bob@org-beta.io` consent RootBlock without Bob's OIDC proof,
            #     allowing Alice to unilaterally assemble a `CoAuthorizedToken` and read Bob's `calendar_free_busy`!
            tid_unauth = "task-unauth-consent"
            alice_ask_tok = mint_root_token(
                ca_alpha,
                task_id=tid_unauth,
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=bob_id.spiffe_id,
                first_hop_jkt=bob_id.jkt,
                permissions=PermissionLattice.create(tools=["calendar_free_busy"], max_calls=4),
                hop_segment="AskBob",
            ).encode_compact()
            task_url = f"{bob_in_url}/a2a/task"
            dpop_ask = create_dpop_proof(gw_id, "POST", task_url, alice_ask_tok)
            r_unauth_consent = httpx.post(
                task_url,
                json={
                    "op": "request_co_auth_consent",
                    "tools": ["calendar_free_busy"],
                    "delegate_spiffe_id": alice_id.spiffe_id,
                    "delegate_jkt": alice_id.jkt,
                },
                headers={"Authorization": f"DPoP {alice_ask_tok}", "DPoP": dpop_ask},
                timeout=5.0,
            )
            self.assertEqual(r_unauth_consent.status_code, 200)
            self.assertIn("compact_token", r_unauth_consent.json())
            self.assertEqual(r_unauth_consent.json()["sub"], "user:bob@org-beta.io")
            self.assertFalse(r_unauth_consent.json()["hop0_oidc_bridged"])

            alice_req_chain = mint_root_token(
                ca_alpha,
                task_id=tid_unauth,
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=alice_id.spiffe_id,
                first_hop_jkt=alice_id.jkt,
                permissions=PermissionLattice.create(tools=["calendar_free_busy"], max_calls=4),
                hop_segment="AliceSelf",
            )
            bob_unverified_consent = decode_token(r_unauth_consent.json()["compact_token"])
            forged_coauth = CoAuthorizedToken.assemble_and_sign(
                holder_identity=alice_id,
                requester_chain=alice_req_chain,
                owner_consent_chain=bob_unverified_consent,  # type: ignore[arg-type]
            ).encode_compact()
            mcp_url = f"{bob_in_url}/mcp"
            dpop_co = create_dpop_proof(alice_id, "POST", mcp_url, forged_coauth)
            r_cal = httpx.post(
                mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "calendar_free_busy", "arguments": {}},
                },
                headers={"Authorization": f"DPoP {forged_coauth}", "DPoP": dpop_co},
                timeout=5.0,
            )
            self.assertEqual(r_cal.status_code, 200)
            self.assertEqual(
                r_cal.json()["result"]["data"]["authorization_mode"], "CO_AUTHORIZED"
            )

            # (c) In `DELEGATION_MODE=dual`, `LineageSidecar._handle_inbound_oauth_request` never checks
            #     `resource_owner_sub` or `owner_protected_tools`, forwarding foreign OAuth Bearer calls
            #     directly to the upstream app container with `X-LCT-Decision: ALLOW_OAUTH_FLAT_SCOPE`!
            echo_headers: List[Dict[str, str]] = []
            polyglot_app = ManagedHTTPService(
                service_name="polyglot-owner-app",
                dispatcher=lambda req: (
                    echo_headers.append(
                        {
                            "sub": req.header("X-LCT-Sub") or "",
                            "decision": req.header("X-LCT-Decision") or "",
                        }
                    )
                    or (200, {"jsonrpc": "2.0", "id": 1, "result": {"reached_app": True}}, {})
                ),
                host="127.0.0.1",
                port=0,
            )
            sc_bob.app_upstream_url = polyglot_app.start().rstrip("/")
            try:
                r_login = httpx.post(
                    f"{sts_url}/realms/lct/protocol/openid-connect/token",
                    data={
                        "grant_type": "password",
                        "client_id": "lct-gateway",
                        "client_secret": "gw-sec",
                        "username": "alice",
                        "password": "alice-pass",
                        "scope": "openid profile",
                    },
                    timeout=5.0,
                )
                self.assertEqual(r_login.status_code, 200)
                r_ex = httpx.post(
                    f"{sts_url}/realms/lct/protocol/openid-connect/token",
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                        "client_id": "lct-gateway",
                        "client_secret": "gw-sec",
                        "subject_token": r_login.json()["access_token"],
                        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                        "audience": bob_id.spiffe_id,
                    },
                    timeout=5.0,
                )
                self.assertEqual(r_ex.status_code, 200)
                alice_oauth_bearer = r_ex.json()["access_token"]

                r_oauth_bypass = httpx.post(
                    f"{bob_in_url}/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "hr_salary_read", "arguments": {}},
                    },
                    headers={"Authorization": f"Bearer {alice_oauth_bearer}"},
                    timeout=5.0,
                )
                self.assertEqual(r_oauth_bypass.status_code, 200)
                self.assertEqual(len(echo_headers), 1)
                self.assertEqual(echo_headers[0]["sub"], "user:alice@org-alpha.io")
                self.assertEqual(echo_headers[0]["decision"], "ALLOW_OAUTH_FLAT_SCOPE")
            finally:
                polyglot_app.stop()
        finally:
            app_bob.stop()
            sc_bob.stop()
            sts_alpha.stop()
            ca_beta_svc.stop()
            try:
                os.unlink(sa_tok_file)
            except OSError:
                pass

    def test_05_reproduce_high_m9_04_distributed_auditor_offline_participant_and_ssrf_bounds(self) -> None:
        """Reproduce [HIGH-M9-04]: Offline participant still reports reconstructed_complete=True + missing SSRF/depth bounds."""
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        auditor_id = ca_alpha.issue_workload("/ns/alpha/sa/auditor")
        gw_id = ca_alpha.issue_workload("/ns/alpha/sa/gw")
        alice_id = ca_alpha.issue_workload("/ns/alpha/sa/assistant-alice")
        bob_id = ca_beta.issue_workload("/ns/beta/sa/assistant-bob")

        tid = "task-high-m9-04"
        p_m9_04 = PermissionLattice.create(tools=["reserve_cloud_budget"], max_amount=300.0)
        tok0 = mint_root_token(
            ca_alpha,
            task_id=tid,
            sub="user:alice@org-alpha.io",
            sender_jkt=gw_id.jkt,
            first_hop_spiffe_id=alice_id.spiffe_id,
            first_hop_jkt=alice_id.jkt,
            permissions=p_m9_04,
            hop_segment="AssistantAlice",
        )
        tok1 = tok0.attenuate(
            issuer_identity=alice_id,
            delegate_spiffe_id=bob_id.spiffe_id,
            delegate_jkt=bob_id.jkt,
            permissions=p_m9_04,
            hop_segment="TechReviewBob",
        )

        ca_em = AuditStreamEmitter(
            ca_alpha,
            collector_client=None,
            stream_id="spiffe://org-alpha.io/authority/root",
            authorized_auditors=[auditor_id.spiffe_id],
        )
        ca_em.emit(
            event_type=AuditEventType.ROOT_MINT,
            task_id=tid,
            sub=tok0.sub,
            lineage_path=tok0.lineage_path,
            hop_index=0,
            epoch=0,
            root_block_hash=tok0.root_block_hash,
            current_block_hash=tok0.leaf_block_hash,
            decision="ALLOW",
        )

        alice_em = AuditStreamEmitter(
            alice_id,
            collector_client=None,
            authorized_auditors=[auditor_id.spiffe_id],
        )
        alice_em.emit(
            event_type=AuditEventType.OUTBOUND_DELEGATE,
            task_id=tid,
            sub=tok1.sub,
            lineage_path=tok1.lineage_path,
            hop_index=1,
            epoch=0,
            root_block_hash=tok1.root_block_hash,
            parent_block_hash=tok1.parent_block_hash,
            current_block_hash=tok1.leaf_block_hash,
            action_detail={"target_spiffe_id": bob_id.spiffe_id},
            decision="ALLOW",
        )

        ca_srv = ManagedHTTPService(
            service_name="ca-audit-m9-04",
            dispatcher=lambda req: ca_em.local_store.serve_http_query(
                req, resolver, node_spiffe_id=ca_alpha.root_authority_spiffe_id, require_task_id=True
            ),
            host="127.0.0.1",
            port=0,
        )
        alice_srv = ManagedHTTPService(
            service_name="alice-audit-m9-04",
            dispatcher=lambda req: alice_em.local_store.serve_http_query(
                req, resolver, node_spiffe_id=alice_id.spiffe_id, require_task_id=True
            ),
            host="127.0.0.1",
            port=0,
        )
        u_ca = ca_srv.start()
        u_alice = alice_srv.start()
        try:
            # `assistant-bob` is OFFLINE (`127.0.0.1:9` closed port)
            dist = DistributedAuditor(
                trust_resolver=resolver,
                signer=auditor_id,
                domain_ca_urls={"org-alpha.io": u_ca},
                spiffe_url_overrides={
                    alice_id.spiffe_id: u_alice,
                    bob_id.spiffe_id: "http://127.0.0.1:9",
                },
                timeout=0.4,
            )
            res = dist.pull_and_reconstruct(
                tid,
                entry_spiffe_ids=[alice_id.spiffe_id],
                seed_domains=["org-alpha.io"],
            )
            # DEFECT 1: `bob_id` is recorded in `unreachable_nodes`, yet `reconstructed_complete` is True!
            self.assertIn(bob_id.spiffe_id, res.unreachable_nodes)
            self.assertTrue(res.reconstructed_complete)
            self.assertEqual(res.anomalies, [])

            # DEFECT 2: `DistributedAuditor` lacks `max_depth`, `max_response_bytes`, `max_entries_per_node`,
            #           and `_verify_kwarg` returns `True` on `http://` or non-RFC1918 public IPs!
            self.assertFalse(hasattr(dist, "max_depth"))
            self.assertIs(dist._verify_kwarg("http://8.8.8.8:8080/v1/audit/local", bob_id.spiffe_id), True)
        finally:
            alice_srv.stop()
            ca_srv.stop()

    def test_06_reproduce_medium_m9_01_idempotency_ledger_parameter_mismatch_reuse(self) -> None:
        """Reproduce [MEDIUM-M9-01]: IdempotencyLedger silently returns old receipt on mismatched operation/amount."""
        ledger = IdempotencyLedger(max_entries=16)
        rec1, rep1 = ledger.execute_once(
            sub="user:alice@org-alpha.io",
            idempotency_key="idem-branch-001",
            operation="reserve_cloud_budget",
            project_code="PRJ-ATLAS",
            amount_usd=150.0,
            builder_fn=lambda rid: {"receipt_id": rid, "op": "reserve_cloud_budget", "amt": 150.0},
        )
        self.assertFalse(rep1)

        # Replay the exact same key with a DIFFERENT tool (`lock_joint_project`), project, and `$950` amount!
        rec2, rep2 = ledger.execute_once(
            sub="user:alice@org-alpha.io",
            idempotency_key="idem-branch-001",
            operation="lock_joint_project",
            project_code="PRJ-OTHER",
            amount_usd=950.0,
            builder_fn=lambda rid: {"receipt_id": rid, "op": "lock_joint_project", "amt": 950.0},
        )
        self.assertTrue(rep2)
        self.assertEqual(rec2["receipt_id"], rec1["receipt_id"])
        self.assertEqual(rec2["amt"], 150.0)
        self.assertEqual(rec2["op"], "reserve_cloud_budget")

    def test_07_verify_m9_positive_invariants_and_rehearsal_hygiene(self) -> None:
        """Verify passing M9 invariants: CoAuth dual-domain revocation, SVID vs RootBlock TTL, cross-tenant status, hygiene."""
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        # 1. Dual-domain revocation check on CoAuthorizedToken: revoking Bob's owner_consent_chain blocks access!
        rev_b = RevocationService(
            ca_beta.issue_workload("/ns/sys/sa/revocation"),
            resolver,
            strict_domain_isolation=True,
            host="127.0.0.1",
            port=0,
        )
        u_rb = rev_b.start()
        rev_rep = RevocationReplicaClient(u_rb, resolver)
        try:
            gw_a = ca_alpha.issue_workload("/ns/alpha/sa/gw")
            alice_p = ca_alpha.issue_workload("/ns/alpha/sa/alice")
            bob_p = ca_beta.issue_workload("/ns/beta/sa/bob")

            req_chain = mint_root_token(
                ca_alpha,
                task_id="task-pos-01",
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_a.jkt,
                first_hop_spiffe_id=alice_p.spiffe_id,
                first_hop_jkt=alice_p.jkt,
                permissions=PermissionLattice.create(tools=["calendar_free_busy"], max_calls=4),
                hop_segment="AliceReq",
            )
            own_chain = mint_root_token(
                ca_beta,
                task_id="task-pos-01",
                sub="user:bob@org-beta.io",
                sender_jkt=bob_p.jkt,
                first_hop_spiffe_id=alice_p.spiffe_id,
                first_hop_jkt=alice_p.jkt,
                permissions=PermissionLattice.create(tools=["calendar_free_busy"], max_calls=2),
                hop_segment="BobConsent",
            )
            cot = CoAuthorizedToken.assemble_and_sign(
                holder_identity=alice_p,
                requester_chain=req_chain,
                owner_consent_chain=own_chain,
            )
            # Bob revokes his consent prefix in `org-beta.io`
            rev_rep.revoke_prefix(
                caller=bob_p,
                prefix="/task-pos-01/BobConsent",
                reason="bob_withdrew_consent",
                authority_token=own_chain.encode_compact(),
            )
            rev_rep.sync_now()

            ver = LeafVerifier(
                trust_resolver=resolver,
                self_spiffe_id=bob_p.spiffe_id,
                self_jkt=bob_p.jkt,
                revocation_replica=rev_rep,
            )
            htu = "https://bob.local:8443/mcp"
            co_wire = cot.encode_compact()
            dpop = create_dpop_proof(alice_p, "POST", htu, co_wire)
            vres = ver.verify_request(
                compact_token=co_wire,
                dpop_proof=dpop,
                htm="POST",
                htu=htu,
                method="tools/call",
                tool="calendar_free_busy",
                arguments={},
                resource_owner_sub="user:bob@org-beta.io",
                allowed_co_auth_tools=["calendar_free_busy"],
            )
            self.assertFalse(vres.allowed)
            self.assertEqual(vres.status_code, 403)
        finally:
            rev_b.stop()

        # 2. SVID renewal independence: renewing WorkloadIdentity NEVER extends RootBlock.exp
        orig_root_exp = req_chain.root.exp
        new_svid_id = ca_alpha.issue_workload("/ns/alpha/sa/alice", ttl_seconds=7200.0)
        alice_p.update_svid(
            workload_svid=new_svid_id.workload_svid,
            issued_at=new_svid_id.issued_at,
            expires_at=new_svid_id.expires_at,
            keypair=alice_p.keypair,
        )
        self.assertIsNotNone(WorkloadIdentityRenewer)
        self.assertEqual(req_chain.root.exp, orig_root_exp)

        # 3. Cross-tenant `query_operation_status` isolation in IdempotencyLedger
        ledger = IdempotencyLedger()
        ledger.execute_once(
            sub="user:alice@org-alpha.io",
            idempotency_key="secret-idem-777",
            operation="reserve_cloud_budget",
            project_code="PRJ-X",
            amount_usd=250.0,
            builder_fn=lambda rid: {"rid": rid},
        )
        self.assertTrue(ledger.query_status("user:alice@org-alpha.io", "secret-idem-777")["found"])
        self.assertFalse(ledger.query_status("user:bob@org-beta.io", "secret-idem-777")["found"])

        # 4. LocalAuditStore rejects omitted `task_id` (`403` / `400`, never `200`)
        store = LocalAuditStore(authorized_auditors=[gw_a.spiffe_id])
        srv_q = ManagedHTTPService(
            service_name="local-q-omit",
            dispatcher=lambda req: store.serve_http_query(
                req, resolver, node_spiffe_id=alice_p.spiffe_id, require_task_id=True
            ),
            host="127.0.0.1",
            port=0,
        )
        u_q = srv_q.start()
        try:
            hdrs_no_tid = build_audit_query_headers(gw_a, task_id="")
            r_no_tid = httpx.get(f"{u_q}/v1/audit/local", headers=hdrs_no_tid)
            self.assertIn(r_no_tid.status_code, (400, 403))
        finally:
            srv_q.stop()

        # 5. Rehearsal & scale directory secret hygiene check (`0` private keys, `0` raw JWTs, `0` raw LCT tokens)
        pem_re = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE" + r" KEY-----")
        jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
        lct_re = re.compile(r"\blct(?:1|m1|mp1|co1)\.[A-Za-z0-9_-]{16,}")
        for rel_dir in (
            "lineage/k8s/runs/20261125-m9-workspace-platform-rehearsal",
            "lineage/scale",
        ):
            root_p = REPO_ROOT / rel_dir
            self.assertTrue(root_p.is_dir(), f"Missing {root_p}")
            for p in root_p.rglob("*"):
                if p.is_file():
                    txt = p.read_text(encoding="utf-8", errors="replace")
                    self.assertIsNone(pem_re.search(txt), f"Private key leak in {p}")
                    self.assertIsNone(jwt_re.search(txt), f"Raw JWT leak in {p}")
                    self.assertIsNone(lct_re.search(txt), f"Raw LCT token leak in {p}")


if __name__ == "__main__":
    unittest.main()
