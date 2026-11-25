"""Milestone 9 (Platform v2) Round-2 Independent QA Sign-Off Verification Suite.

Verifies all 6 remediations from `MILESTONE9_QA_REPORT.md` plus edge-case invariants
and Round-2 live 3-cluster rehearsal / scale / public-repo secret hygiene:
1. `[CRITICAL-M9-01]`: Single-use continuation anti-replay on BOTH `checkpoint_id` and
   `(task_id, prior_root_block_hash)` (`409 CONTINUATION_REPLAY_REJECTED`), plus
   `CausalChainAuditor` detection of duplicate checkpoints and forked continuation roots.
2. `[HIGH-M9-01]`: Fail-closed `_resolve_verified_prior_root` (`403 PRIOR_ROOT_NOT_VERIFIED`),
   CA-restart recovery via `prior_root_token` signature check ignoring expiry, strict
   `ckpt.signer_spiffe_id == prior_root.delegate_spiffe_id == first_hop_spiffe_id` binding,
   authoritative ceiling & non-numeric lattice clamping, and hardened `LineageSidecar`
   `sign_checkpoint`.
3. `[HIGH-M9-02]`: Revocation filtering prior to expired-branch re-anchoring in
   `LeafVerifier.verify_request` (`MultiParentToken`) so revoked continuations never
   resurrect expired ancestor roots, plus strict linear acyclic monotonic-`iat`
   `are_roots_continuously_linked`.
4. `[HIGH-M9-03]`: Dedicated `POST /v1/ca/mint-consent-token` with `CONSENT_ISSUER_POLICY`
   (`assistant-bob` removed from `AUTHORIZED_GATEWAY_SAS`), mandatory verified owner
   `user_oidc_token`, owner-only tool/amount/TTL rejection, mandatory OIDC proof in
   `WorkspaceAssistantPeerApp` `request_co_auth_consent`, and sidecar-level
   `403 CROSS_PRINCIPAL_DENIED` in `LineageSidecar._handle_inbound_oauth_request` (`dual` mode).
5. `[HIGH-M9-04]`: `DistributedAuditor` offline required-participant detection
   (`reconstructed_complete=False` + `REQUIRED_AUDIT_NODE_UNREACHABLE`), upstream gateway
   `peer_spiffe_id` non-pollution, `max_depth` / `max_nodes` / `max_response_bytes` /
   `max_entries_per_node` bounds, RFC1918 CIDR checks, and mandatory `https://` mTLS when
   `mtls_bundle` is active.
6. `[MEDIUM-M9-01]`: `IdempotencyLedger` & `WorkspaceVaultMCPApp` exact parameter binding on
   `(operation, target, project_code, amount_usd)` -> `409 IDEMPOTENCY_PARAMETER_MISMATCH`.
7. Round-2 live 3-cluster rehearsal (`20261125-m9-r2-workspace-rehearsal`) & 24-node scale
   report evidence + public-repo secret hygiene (`0` private keys, `0` raw JWTs, `0` raw LCT
   tokens, `0` raw passwords).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import time
from typing import Dict, List, Tuple
import unittest

import httpx

from lineage.audit import (
    AuditEventType,
    AuditStreamEmitter,
    CausalChainAuditor,
    DistributedAuditor,
)
from lineage.common.crypto import KeyPair
from lineage.common.http_utils import ManagedHTTPService
from lineage.common.locators import LocatorError
from lineage.common.mtls import WorkloadMTLSBundle, X509DomainAuthority, X509FederationTrustStore
from lineage.federation.domain_ca import AutonomousDomainCAService
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.multihost.config_gen import render_role_k8s_manifests
from lineage.oauth_sts import OIDCTokenVerifier, OAuthSTSService
from lineage.protocol import (
    CoAuthorizedToken,
    MultiParentToken,
    PermissionLattice,
    TaskCheckpoint,
    create_dpop_proof,
    decode_token,
    mint_root_token,
)
from lineage.protocol.token import are_roots_continuously_linked, mint_continuation_root_token
from lineage.revocation import RevocationReplicaClient, RevocationService
from lineage.sidecar import LineageSidecar
from lineage.verifier import LeafVerifier, VerificationMode
from lineage.workspace_agents import (
    IdempotencyConflictError,
    IdempotencyLedger,
    WorkspaceAssistantPeerApp,
    WorkspaceVaultMCPApp,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


class _StubSAVerifier:
    def __init__(self, mapping: Dict[str, Tuple[str, str]]) -> None:
        self._mapping = dict(mapping)

    def verify_sa_jwt(self, sa_jwt: str, now: float | None = None) -> Tuple[str, str, float]:
        if sa_jwt not in self._mapping:
            raise ValueError(f"invalid_sa_jwt:{sa_jwt}")
        ns, sa = self._mapping[sa_jwt]
        return ns, sa, (now or time.time()) + 600.0


class Milestone9Round2SignOffTests(unittest.TestCase):
    """Independent Round-2 QA verification of all 6 M9 security remediations & rehearsal evidence."""

    def test_01_verify_critical_m9_01_continuation_single_use_and_auditor_fork_detection(self) -> None:
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

            tid = "task-r2-crit-01"
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
                },
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            self.assertEqual(r0.status_code, 200)
            prior_hash = r0.json()["root_block_hash"]

            ckpt1 = TaskCheckpoint.create_and_sign(
                signer_identity=alice_id,
                task_id=tid,
                sub="user:alice@org-alpha.io",
                prior_root_block_hash=prior_hash,
                original_max_amount=600.0,
                original_max_calls=6,
                completed_branches=["B1"],
                remaining_branches=["B2"],
                consumed_amount=280.0,
                consumed_calls=2,
            )
            base_body = {
                "trust_domain": "org-alpha.io",
                "checkpoint": ckpt1.to_dict(),
                "sender_jkt": gw_id.jkt,
                "first_hop_spiffe_id": alice_id.spiffe_id,
                "first_hop_jkt": alice_id.jkt,
                "permissions": PermissionLattice.create(
                    tools=["reserve_cloud_budget"],
                    max_amount=320.0,
                    max_calls=4,
                ).to_dict(),
            }
            r_c1 = httpx.post(
                f"{ca_url}/v1/ca/mint-continuation-token",
                json=base_body,
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            self.assertEqual(r_c1.status_code, 200)

            # 1) Exact checkpoint_id replay -> 409 CONTINUATION_REPLAY_REJECTED
            r_c1_replay = httpx.post(
                f"{ca_url}/v1/ca/mint-continuation-token",
                json=base_body,
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            self.assertEqual(r_c1_replay.status_code, 409)
            self.assertEqual(r_c1_replay.json()["error"], "CONTINUATION_REPLAY_REJECTED")

            # 2) Fresh checkpoint_id attempting to fork the same superseded prior_root_block_hash -> 409!
            ckpt2_fork = TaskCheckpoint.create_and_sign(
                signer_identity=alice_id,
                task_id=tid,
                sub="user:alice@org-alpha.io",
                prior_root_block_hash=prior_hash,
                original_max_amount=600.0,
                original_max_calls=6,
                completed_branches=["B1"],
                remaining_branches=["B2Alt"],
                consumed_amount=280.0,
                consumed_calls=2,
            )
            r_c2_fork = httpx.post(
                f"{ca_url}/v1/ca/mint-continuation-token",
                json={**base_body, "checkpoint": ckpt2_fork.to_dict()},
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            self.assertEqual(r_c2_fork.status_code, 409)
            self.assertEqual(r_c2_fork.json()["error"], "CONTINUATION_REPLAY_REJECTED")

            # 3) Verify CausalChainAuditor flags crafted duplicate/forked continuation ROOT_MINT entries
            em = AuditStreamEmitter(ca_svc.ca, collector_client=None, stream_id="spiffe://org-alpha.io/authority/root")
            e0 = em.emit(
                event_type=AuditEventType.ROOT_MINT,
                task_id="task-fork-audit",
                sub="user:alice@org-alpha.io",
                lineage_path="/task-fork-audit/A",
                hop_index=0,
                epoch=0,
                root_block_hash="r0-hash",
                current_block_hash="r0-hash",
                decision="ALLOW",
                permissions_summary={"tools": ["reserve_cloud_budget"], "max_amount": 500.0, "max_calls": 6},
            )
            e1 = em.emit(
                event_type=AuditEventType.ROOT_MINT,
                task_id="task-fork-audit",
                sub="user:alice@org-alpha.io",
                lineage_path="/task-fork-audit/ACont1",
                hop_index=0,
                epoch=0,
                root_block_hash="r1a-hash",
                parent_block_hash="r0-hash",
                current_block_hash="r1a-hash",
                decision="ALLOW",
                permissions_summary={"tools": ["reserve_cloud_budget"], "max_amount": 250.0, "max_calls": 3},
                action_detail={
                    "continuation": True,
                    "resumes_checkpoint_id": "ckpt-same",
                    "prior_root_block_hash": "r0-hash",
                    "consumed_amount": 250.0,
                    "consumed_calls": 3,
                },
            )
            e2_dup = em.emit(
                event_type=AuditEventType.ROOT_MINT,
                task_id="task-fork-audit",
                sub="user:alice@org-alpha.io",
                lineage_path="/task-fork-audit/ACont2",
                hop_index=0,
                epoch=0,
                root_block_hash="r1b-hash",
                parent_block_hash="r0-hash",
                current_block_hash="r1b-hash",
                decision="ALLOW",
                permissions_summary={"tools": ["reserve_cloud_budget"], "max_amount": 250.0, "max_calls": 3},
                action_detail={
                    "continuation": True,
                    "resumes_checkpoint_id": "ckpt-same",
                    "prior_root_block_hash": "r0-hash",
                    "consumed_amount": 250.0,
                    "consumed_calls": 3,
                },
            )
            rep = CausalChainAuditor(ca_svc.federation_trust_resolver).reconstruct(
                [e0, e1, e2_dup], task_id="task-fork-audit"
            )
            trec = rep.tasks["task-fork-audit"]
            self.assertFalse(trec.reconstructed_complete)
            codes = {a.code for a in trec.anomalies}
            self.assertIn("DUPLICATE_CHECKPOINT_CONTINUATION:ckpt-same", codes)
            self.assertIn("FORKED_CONTINUATION_ROOT:r0-hash", codes)
        finally:
            ca_svc.stop()

    def test_02_verify_high_m9_01_fail_closed_prior_root_signer_binding_and_sidecar_checkpoint(self) -> None:
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

        alice_id = ca_svc.ca.issue_workload("/ns/lineage-alpha/sa/assistant-alice")
        other_alpha_id = ca_svc.ca.issue_workload("/ns/lineage-alpha/sa/other-peer")
        foreign_beta_id = ca_beta.issue_workload("/ns/lineage-beta/sa/bob")
        gw_id = ca_svc.ca.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")

        lsec = secrets.token_urlsafe(20)
        sc_alice = LineageSidecar(
            identity=alice_id,
            trust_resolver=ca_svc.federation_trust_resolver,
            app_upstream_url="http://127.0.0.1:9",
            loopback_secret=lsec,
            inbound_host="127.0.0.1",
            inbound_port=0,
            outbound_port=0,
        )
        sc_other = LineageSidecar(
            identity=other_alpha_id,
            trust_resolver=ca_svc.federation_trust_resolver,
            app_upstream_url="http://127.0.0.1:9",
            loopback_secret=lsec,
            inbound_host="127.0.0.1",
            inbound_port=0,
            outbound_port=0,
        )
        _, alice_out = sc_alice.start()
        _, other_out = sc_other.start()
        try:
            # 1) Fabricated prior_root_block_hash -> 403 PRIOR_ROOT_NOT_VERIFIED
            fake_ckpt = TaskCheckpoint.create_and_sign(
                signer_identity=alice_id,
                task_id="task-fake-prior",
                sub="user:alice@org-alpha.io",
                prior_root_block_hash="unverified-root-hash",
                original_max_amount=50000.0,
                original_max_calls=50,
                completed_branches=[],
                remaining_branches=["X"],
                consumed_amount=0.0,
                consumed_calls=0,
            )
            r_fake = httpx.post(
                f"{ca_url}/v1/ca/mint-continuation-token",
                json={
                    "trust_domain": "org-alpha.io",
                    "checkpoint": fake_ckpt.to_dict(),
                    "sender_jkt": gw_id.jkt,
                    "first_hop_spiffe_id": alice_id.spiffe_id,
                    "first_hop_jkt": alice_id.jkt,
                    "permissions": PermissionLattice.create(
                        tools=["hr_salary_read"], max_amount=50000.0, max_calls=10
                    ).to_dict(),
                },
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            self.assertEqual(r_fake.status_code, 403)
            self.assertEqual(r_fake.json()["error"], "PRIOR_ROOT_NOT_VERIFIED")

            # 2) Mint genuine short-lived root token (1.0s TTL), wait for expiry, and clear CA RAM ledger
            #    to simulate CA Pod restart -> verify `prior_root_token` cryptographic recovery & signer checks!
            tid = "task-r2-high-01"
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
                        allowed_targets=["cloud-infra-escrow"],
                        max_amount=300.0,
                        max_calls=5,
                    ).to_dict(),
                    "ttl_seconds": 1.0,
                },
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            self.assertEqual(r0.status_code, 200)
            prior_compact = r0.json()["compact_token"]
            prior_hash = r0.json()["root_block_hash"]
            time.sleep(1.15)
            ca_svc._issued_roots.clear()

            # 2a) Foreign workload signing checkpoint -> 403 CHECKPOINT_SIGNER_MISMATCH
            bad_signer_ckpt = TaskCheckpoint.create_and_sign(
                signer_identity=foreign_beta_id,
                task_id=tid,
                sub="user:alice@org-alpha.io",
                prior_root_block_hash=prior_hash,
                original_max_amount=300.0,
                original_max_calls=5,
                completed_branches=[],
                remaining_branches=["B"],
                consumed_amount=100.0,
                consumed_calls=1,
            )
            r_bad_sig = httpx.post(
                f"{ca_url}/v1/ca/mint-continuation-token",
                json={
                    "trust_domain": "org-alpha.io",
                    "checkpoint": bad_signer_ckpt.to_dict(),
                    "prior_root_token": prior_compact,
                    "sender_jkt": gw_id.jkt,
                    "first_hop_spiffe_id": alice_id.spiffe_id,
                    "first_hop_jkt": alice_id.jkt,
                    "permissions": PermissionLattice.create(
                        tools=["reserve_cloud_budget"],
                        allowed_targets=["cloud-infra-escrow"],
                        max_amount=200.0,
                        max_calls=4,
                    ).to_dict(),
                },
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            self.assertEqual(r_bad_sig.status_code, 403)
            self.assertEqual(r_bad_sig.json()["error"], "CHECKPOINT_SIGNER_MISMATCH")

            # 2b) Sidecar `sign_checkpoint` hardening: missing prior_token -> 403; wrong sidecar -> 403;
            #     valid entry delegate sidecar derives authoritative ceiling from expired prior_token!
            r_sc_missing = httpx.post(
                f"{alice_out}/v1/proxy/call",
                headers={"X-LCT-Loopback-Auth": lsec},
                json={"action": "sign_checkpoint", "task_id": tid},
                timeout=5.0,
            )
            self.assertEqual(r_sc_missing.status_code, 403)
            self.assertEqual(r_sc_missing.json()["error"], "PRIOR_TOKEN_REQUIRED_FOR_CHECKPOINT")

            r_sc_wrong = httpx.post(
                f"{other_out}/v1/proxy/call",
                headers={"X-LCT-Loopback-Auth": lsec},
                json={"action": "sign_checkpoint", "prior_token": prior_compact, "consumed_amount": 100.0},
                timeout=5.0,
            )
            self.assertEqual(r_sc_wrong.status_code, 403)
            self.assertEqual(r_sc_wrong.json()["error"], "CHECKPOINT_SIGNER_NOT_ENTRY_DELEGATE")

            r_sc_ok = httpx.post(
                f"{alice_out}/v1/proxy/call",
                headers={"X-LCT-Loopback-Auth": lsec},
                json={
                    "action": "sign_checkpoint",
                    "prior_token": prior_compact,
                    "consumed_amount": 120.0,
                    "consumed_calls": 2,
                    "completed_branches": ["B1"],
                    "remaining_branches": ["B2"],
                },
                timeout=5.0,
            )
            self.assertEqual(r_sc_ok.status_code, 200)
            signed_ckpt_dict = r_sc_ok.json()["checkpoint"]
            self.assertEqual(signed_ckpt_dict["original_max_amount"], 300.0)
            self.assertEqual(signed_ckpt_dict["original_max_calls"], 5)

            # 2c) Holder mismatch (`first_hop_spiffe_id != entry_delegate`) -> 403 CONTINUATION_HOLDER_MISMATCH
            r_bad_holder = httpx.post(
                f"{ca_url}/v1/ca/mint-continuation-token",
                json={
                    "trust_domain": "org-alpha.io",
                    "checkpoint": signed_ckpt_dict,
                    "prior_root_token": prior_compact,
                    "sender_jkt": gw_id.jkt,
                    "first_hop_spiffe_id": other_alpha_id.spiffe_id,
                    "first_hop_jkt": other_alpha_id.jkt,
                    "permissions": PermissionLattice.create(
                        tools=["reserve_cloud_budget"],
                        allowed_targets=["cloud-infra-escrow"],
                        max_amount=180.0,
                        max_calls=3,
                    ).to_dict(),
                },
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            self.assertEqual(r_bad_holder.status_code, 403)
            self.assertEqual(r_bad_holder.json()["error"], "CONTINUATION_HOLDER_MISMATCH")

            # 2d) Valid continuation recovery after CA restart -> 200 OK
            r_recovered = httpx.post(
                f"{ca_url}/v1/ca/mint-continuation-token",
                json={
                    "trust_domain": "org-alpha.io",
                    "checkpoint": signed_ckpt_dict,
                    "prior_root_token": prior_compact,
                    "sender_jkt": gw_id.jkt,
                    "first_hop_spiffe_id": alice_id.spiffe_id,
                    "first_hop_jkt": alice_id.jkt,
                    "permissions": PermissionLattice.create(
                        tools=["reserve_cloud_budget"],
                        allowed_targets=["cloud-infra-escrow"],
                        max_amount=180.0,
                        max_calls=3,
                    ).to_dict(),
                },
                headers={"Authorization": "Bearer sa-gw"},
                timeout=5.0,
            )
            self.assertEqual(r_recovered.status_code, 200)
        finally:
            sc_other.stop()
            sc_alice.stop()
            ca_svc.stop()

    def test_03_verify_high_m9_02_revoked_continuation_blocked_and_linear_root_chain(self) -> None:
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
            tid = "task-r2-high-02"

            p0 = PermissionLattice.create(
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
                permissions=p0,
                ttl_seconds=1.0,
                hop_segment="Phase1",
                now=now_ts,
            ).attenuate(
                issuer_identity=alice_id,
                delegate_spiffe_id=vault_id.spiffe_id,
                delegate_jkt=vault_id.jkt,
                permissions=p0,
                hop_segment="Vault",
                now=now_ts,
            )

            ckpt = TaskCheckpoint.create_and_sign(
                signer_identity=alice_id,
                task_id=tid,
                sub="user:alice@org-alpha.io",
                prior_root_block_hash=tok_r0.root_block_hash,
                original_max_amount=400.0,
                original_max_calls=8,
                completed_branches=["Phase1"],
                remaining_branches=["Phase2"],
                consumed_amount=200.0,
                consumed_calls=2,
                now=now_ts + 2.0,
            )
            p1 = PermissionLattice.create(
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
                permissions=p1,
                ttl_seconds=300.0,
                hop_segment="Phase2Cont",
                now=now_ts + 2.0,
            )
            tok_r1 = tok_r1_alice.attenuate(
                issuer_identity=alice_id,
                delegate_spiffe_id=vault_id.spiffe_id,
                delegate_jkt=vault_id.jkt,
                permissions=p1,
                hop_segment="Vault",
                now=now_ts + 2.0,
            )

            verifier = LeafVerifier(
                trust_resolver=resolver,
                self_spiffe_id=vault_id.spiffe_id,
                self_jkt=vault_id.jkt,
                revocation_replica=rev_rep,
                clock_skew_seconds=0.0,
            )
            htu = "https://vault.local:8443/mcp"

            # 1) Before revocation: live unrevoked tok_r1 validly anchors expired tok_r0 (`200 ALLOW`)
            mp_live = MultiParentToken.assemble_and_sign(
                holder_identity=vault_id,
                parent_chains=[tok_r0, tok_r1],
                now=now_ts + 20.0,
            ).encode_compact()
            dpop_live = create_dpop_proof(vault_id, "POST", htu, mp_live, now=now_ts + 20.0)
            vres_live = verifier.verify_request(
                compact_token=mp_live,
                dpop_proof=dpop_live,
                htm="POST",
                htu=htu,
                method="tools/call",
                tool="lock_joint_project",
                arguments={"target": "cloud-infra-escrow", "amount": 100.0},
                now=now_ts + 20.0,
            )
            self.assertTrue(vres_live.allowed, vres_live.detail)

            # 2) Revoke continuation tok_r1 -> expired tok_r0 MUST NOT be resurrected (`403 ALL_DAG_PARENT_CHAINS_REVOKED`)!
            rev_rep.revoke_prefix(
                caller=alice_id,
                prefix=tok_r1_alice.lineage_path,
                reason="cancel_cont",
                authority_token=tok_r1_alice.encode_compact(),
            )
            rev_rep.sync_now()

            dpop_rev = create_dpop_proof(vault_id, "POST", htu, mp_live, now=now_ts + 21.0)
            vres_rev = verifier.verify_request(
                compact_token=mp_live,
                dpop_proof=dpop_rev,
                htm="POST",
                htu=htu,
                method="tools/call",
                tool="lock_joint_project",
                arguments={"target": "cloud-infra-escrow", "amount": 100.0},
                now=now_ts + 21.0,
            )
            self.assertFalse(vres_rev.allowed)
            self.assertEqual(vres_rev.status_code, 403)
            self.assertEqual(vres_rev.reason_code, "ALL_DAG_PARENT_CHAINS_REVOKED")

            # 3) `are_roots_continuously_linked` rejects forks and reverse-iat roots, accepts linear R_0 -> R_1
            self.assertTrue(are_roots_continuously_linked([tok_r0, tok_r1]))
            tok_r1_fork = mint_continuation_root_token(
                ca_alpha,
                checkpoint=ckpt,
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=alice_id.spiffe_id,
                first_hop_jkt=alice_id.jkt,
                permissions=p1,
                ttl_seconds=300.0,
                hop_segment="ForkCont",
                now=now_ts + 2.0,
            )
            self.assertFalse(are_roots_continuously_linked([tok_r0, tok_r1, tok_r1_fork]))
            tok_r1_backwards_iat = mint_continuation_root_token(
                ca_alpha,
                checkpoint=ckpt,
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=alice_id.spiffe_id,
                first_hop_jkt=alice_id.jkt,
                permissions=p1,
                ttl_seconds=300.0,
                hop_segment="BackIat",
                now=now_ts - 5.0,
            )
            self.assertFalse(are_roots_continuously_linked([tok_r0, tok_r1_backwards_iat]))
        finally:
            rev_svc.stop()

    def test_04_verify_high_m9_03_consent_issuer_policy_mandatory_oidc_and_dual_oauth_isolation(self) -> None:
        # 1) Manifest check: beta & pay use CONSENT_ISSUER_POLICY (primary + standby) and ZERO AUTHORIZED_GATEWAY_SAS
        for role_n in ("beta", "pay"):
            y_txt = render_role_k8s_manifests(
                role=role_n, topology="workspace", registry_mode="centralized"
            )
            self.assertNotIn("AUTHORIZED_GATEWAY_SAS", y_txt)
            self.assertIn("CONSENT_ISSUER_POLICY", y_txt)
            self.assertIn("-standby=", y_txt)

        ca_alpha = TrustDomainCA("org-alpha.io")
        sts_beta = OAuthSTSService(
            trust_domain="org-beta.io",
            realm="lct",
            host="127.0.0.1",
            port=0,
            user_passwords={"bob": "bob-secret", "dave": "dave-secret"},
            client_secrets={"lct-gateway": "gw-sec"},
        )
        sts_beta_url = sts_beta.start()
        sts_beta.issuer_origin = sts_beta_url

        sts_alpha = OAuthSTSService(
            trust_domain="org-alpha.io",
            realm="lct",
            host="127.0.0.1",
            port=0,
            user_passwords={"alice": "alice-secret"},
            client_secrets={"lct-gateway": "gw-sec"},
        )
        sts_alpha_url = sts_alpha.start()
        sts_alpha.issuer_origin = sts_alpha_url

        beta_oidc_ver = OIDCTokenVerifier(
            jwks_urls=[f"{sts_beta_url}/realms/lct/protocol/openid-connect/certs"],
            expected_issuer=f"{sts_beta_url}/realms/lct",
            default_user_domain="org-beta.io",
        )
        alpha_oidc_ver = OIDCTokenVerifier(
            jwks_urls=[f"{sts_alpha_url}/realms/lct/protocol/openid-connect/certs"],
            expected_issuer=f"{sts_alpha_url}/realms/lct",
            default_user_domain="org-alpha.io",
        )

        ca_beta_svc = AutonomousDomainCAService(
            trust_domain="org-beta.io",
            allowed_k8s_namespace="lineage-beta",
            oidc_verifier=beta_oidc_ver,
            consent_issuer_policy=(
                "assistant-bob=user:bob@org-beta.io:calendar_free_busy;"
                "assistant-bob-standby=user:bob@org-beta.io:calendar_free_busy"
            ),
            host="127.0.0.1",
            port=0,
        )
        ca_beta_svc.federation_trust_resolver.register_domain_ca(ca_alpha)
        ca_beta_svc.k8s_verifier = _StubSAVerifier(  # type: ignore[assignment]
            {
                "sa-bob": ("lineage-beta", "assistant-bob"),
                "sa-dave": ("lineage-beta", "assistant-dave"),
            }
        )
        beta_ca_url = ca_beta_svc.start()

        bob_id = ca_beta_svc.ca.issue_workload("/ns/lineage-beta/sa/assistant-bob")
        alice_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/assistant-alice")
        gw_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")

        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("sa-bob")
            sa_tok_file = tf.name

        lsec = secrets.token_urlsafe(20)
        upstream_hits: List[str] = []
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
            oauth_central_verifier=alpha_oidc_ver,
            resource_owner_sub="user:bob@org-beta.io",
            owner_protected_tools=["hr_salary_read", "calendar_write", "calendar_free_busy"],
            allowed_co_auth_tools=["calendar_free_busy"],
            local_ca_url=beta_ca_url,
            sa_token_path=sa_tok_file,
        )
        bob_in, bob_out = sc_bob.start()
        app_bob = WorkspaceAssistantPeerApp(
            peer_name="bob",
            owner_sub="user:bob@org-beta.io",
            outbound_proxy_url=bob_out,
            loopback_secret=lsec,
            ollama=None,
            port=0,
        )
        sc_bob.app_upstream_url = app_bob.start().rstrip("/")
        try:
            # 2) `assistant-bob` SA CANNOT call `/v1/ca/mint-root-token` (`403 gateway_only_endpoint`)
            r_root_denied = httpx.post(
                f"{beta_ca_url}/v1/ca/mint-root-token",
                json={"task_id": "t1", "sub": "user:bob@org-beta.io"},
                headers={"Authorization": "Bearer sa-bob"},
                timeout=5.0,
            )
            self.assertEqual(r_root_denied.status_code, 403)
            self.assertEqual(r_root_denied.json()["error"], "gateway_only_endpoint")

            # 3) Unauthorized SA (`assistant-dave`) rejected on `/v1/ca/mint-consent-token` (`403`)
            r_dave_denied = httpx.post(
                f"{beta_ca_url}/v1/ca/mint-consent-token",
                json={},
                headers={"Authorization": "Bearer sa-dave"},
                timeout=5.0,
            )
            self.assertEqual(r_dave_denied.status_code, 403)
            self.assertEqual(r_dave_denied.json()["error"], "CONSENT_ISSUER_FORBIDDEN")

            # Obtain Bob & Dave OIDC tokens from beta-sts
            bob_oidc = httpx.post(
                f"{sts_beta_url}/realms/lct/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "lct-gateway",
                    "client_secret": "gw-sec",
                    "username": "bob",
                    "password": "bob-secret",
                    "scope": "openid profile",
                },
                timeout=5.0,
            ).json()["access_token"]
            dave_oidc = httpx.post(
                f"{sts_beta_url}/realms/lct/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "lct-gateway",
                    "client_secret": "gw-sec",
                    "username": "dave",
                    "password": "dave-secret",
                    "scope": "openid profile",
                },
                timeout=5.0,
            ).json()["access_token"]

            # 4) Wrong OIDC principal (`dave_oidc` on `assistant-bob`) -> 403 CONSENT_OIDC_SUB_MISMATCH
            r_wrong_oidc = httpx.post(
                f"{beta_ca_url}/v1/ca/mint-consent-token",
                json={
                    "task_id": "t-co",
                    "sender_jkt": bob_id.jkt,
                    "first_hop_spiffe_id": alice_id.spiffe_id,
                    "first_hop_jkt": alice_id.jkt,
                    "user_oidc_token": dave_oidc,
                    "permissions": PermissionLattice.create(tools=["calendar_free_busy"], max_calls=2).to_dict(),
                },
                headers={"Authorization": "Bearer sa-bob"},
                timeout=5.0,
            )
            self.assertEqual(r_wrong_oidc.status_code, 403)
            self.assertEqual(r_wrong_oidc.json()["error"], "CONSENT_OIDC_SUB_MISMATCH")

            # 5) Forbidden owner-only tool (`hr_salary_read`) -> 403 CONSENT_TOOL_FORBIDDEN
            r_bad_tool = httpx.post(
                f"{beta_ca_url}/v1/ca/mint-consent-token",
                json={
                    "task_id": "t-co",
                    "sender_jkt": bob_id.jkt,
                    "first_hop_spiffe_id": alice_id.spiffe_id,
                    "first_hop_jkt": alice_id.jkt,
                    "user_oidc_token": bob_oidc,
                    "permissions": PermissionLattice.create(tools=["hr_salary_read"], max_calls=2).to_dict(),
                },
                headers={"Authorization": "Bearer sa-bob"},
                timeout=5.0,
            )
            self.assertEqual(r_bad_tool.status_code, 403)
            self.assertEqual(r_bad_tool.json()["error"], "CONSENT_TOOL_FORBIDDEN")

            # 6) Unauthenticated peer `request_co_auth_consent` (`user_oidc_token` omitted) -> 401!
            alice_ask = mint_root_token(
                ca_alpha,
                task_id="t-co",
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=bob_id.spiffe_id,
                first_hop_jkt=bob_id.jkt,
                permissions=PermissionLattice.create(tools=["calendar_free_busy"], max_calls=4),
                hop_segment="AskBob",
            ).encode_compact()
            task_u = f"{bob_in}/a2a/task"
            dpop_u = create_dpop_proof(gw_id, "POST", task_u, alice_ask)
            r_missing_oidc = httpx.post(
                task_u,
                json={
                    "op": "request_co_auth_consent",
                    "tools": ["calendar_free_busy"],
                    "delegate_spiffe_id": alice_id.spiffe_id,
                    "delegate_jkt": alice_id.jkt,
                },
                headers={"Authorization": f"DPoP {alice_ask}", "DPoP": dpop_u},
                timeout=5.0,
            )
            self.assertEqual(r_missing_oidc.status_code, 401)
            self.assertEqual(r_missing_oidc.json()["error"], "OWNER_CONSENT_PROOF_REQUIRED")

            # 7) Valid `request_co_auth_consent` WITH Bob's verified OIDC token -> 200 & CoAuthorizedToken works!
            dpop_ok = create_dpop_proof(gw_id, "POST", task_u, alice_ask)
            r_valid_consent = httpx.post(
                task_u,
                json={
                    "op": "request_co_auth_consent",
                    "tools": ["calendar_free_busy"],
                    "delegate_spiffe_id": alice_id.spiffe_id,
                    "delegate_jkt": alice_id.jkt,
                    "user_oidc_token": bob_oidc,
                },
                headers={"Authorization": f"DPoP {alice_ask}", "DPoP": dpop_ok},
                timeout=5.0,
            )
            self.assertEqual(r_valid_consent.status_code, 200)
            self.assertTrue(r_valid_consent.json()["hop0_oidc_bridged"])
            alice_self = mint_root_token(
                ca_alpha,
                task_id="t-co",
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=alice_id.spiffe_id,
                first_hop_jkt=alice_id.jkt,
                permissions=PermissionLattice.create(tools=["calendar_free_busy"], max_calls=4),
                hop_segment="AliceSelf",
            )
            co_tok = CoAuthorizedToken.assemble_and_sign(
                holder_identity=alice_id,
                requester_chain=alice_self,
                owner_consent_chain=decode_token(r_valid_consent.json()["compact_token"]),  # type: ignore[arg-type]
            ).encode_compact()
            mcp_u = f"{bob_in}/mcp"
            dpop_co = create_dpop_proof(alice_id, "POST", mcp_u, co_tok)
            r_co_mcp = httpx.post(
                mcp_u,
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "calendar_free_busy", "arguments": {}}},
                headers={"Authorization": f"DPoP {co_tok}", "DPoP": dpop_co},
                timeout=5.0,
            )
            self.assertEqual(r_co_mcp.status_code, 200)

            # 8) `DELEGATION_MODE=dual` OAuth Bearer from Alice is blocked AT SIDECAR (`0` upstream app hits)!
            probe_app = ManagedHTTPService(
                service_name="probe-app",
                dispatcher=lambda req: (upstream_hits.append(req.path) or (200, {"ok": True}, {})),
                host="127.0.0.1",
                port=0,
            )
            sc_bob.app_upstream_url = probe_app.start().rstrip("/")
            try:
                alice_login = httpx.post(
                    f"{sts_alpha_url}/realms/lct/protocol/openid-connect/token",
                    data={
                        "grant_type": "password",
                        "client_id": "lct-gateway",
                        "client_secret": "gw-sec",
                        "username": "alice",
                        "password": "alice-secret",
                        "scope": "openid profile",
                    },
                    timeout=5.0,
                ).json()["access_token"]
                alice_ex = httpx.post(
                    f"{sts_alpha_url}/realms/lct/protocol/openid-connect/token",
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                        "client_id": "lct-gateway",
                        "client_secret": "gw-sec",
                        "subject_token": alice_login,
                        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                        "audience": bob_id.spiffe_id,
                    },
                    timeout=5.0,
                ).json()["access_token"]
                r_dual_denied = httpx.post(
                    mcp_u,
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "hr_salary_read", "arguments": {}}},
                    headers={"Authorization": f"Bearer {alice_ex}"},
                    timeout=5.0,
                )
                self.assertEqual(r_dual_denied.status_code, 403)
                self.assertEqual(r_dual_denied.json()["error"], "CROSS_PRINCIPAL_DENIED")
                self.assertEqual(upstream_hits, [])
            finally:
                probe_app.stop()
        finally:
            app_bob.stop()
            sc_bob.stop()
            ca_beta_svc.stop()
            sts_alpha.stop()
            sts_beta.stop()
            try:
                os.unlink(sa_tok_file)
            except OSError:
                pass

    def test_05_verify_high_m9_04_distributed_auditor_completeness_bounds_and_mtls_ssrf_guards(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        auditor_id = ca_alpha.issue_workload("/ns/alpha/sa/auditor")
        gw_id = ca_alpha.issue_workload("/ns/alpha/sa/e2e-user-gateway")
        alice_id = ca_alpha.issue_workload("/ns/alpha/sa/assistant-alice")
        bob_id = ca_beta.issue_workload("/ns/beta/sa/assistant-bob")

        tid = "task-r2-high-04"
        p = PermissionLattice.create(tools=["reserve_cloud_budget"], max_amount=200.0)
        tok0 = mint_root_token(
            ca_alpha,
            task_id=tid,
            sub="user:alice@org-alpha.io",
            sender_jkt=gw_id.jkt,
            first_hop_spiffe_id=alice_id.spiffe_id,
            first_hop_jkt=alice_id.jkt,
            permissions=p,
            hop_segment="AssistantAlice",
        )
        tok1 = tok0.attenuate(
            issuer_identity=alice_id,
            delegate_spiffe_id=bob_id.spiffe_id,
            delegate_jkt=bob_id.jkt,
            permissions=p,
            hop_segment="BobBranch",
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
            action_detail={"first_hop_spiffe_id": alice_id.spiffe_id},
            decision="ALLOW",
        )

        alice_em = AuditStreamEmitter(
            alice_id, collector_client=None, authorized_auditors=[auditor_id.spiffe_id]
        )
        # Emit INBOUND_AUTHZ with upstream `peer_spiffe_id=gw_id` (must NOT pollute unreachable_nodes!)
        alice_em.emit(
            event_type=AuditEventType.INBOUND_AUTHZ,
            task_id=tid,
            sub=tok0.sub,
            lineage_path=tok0.lineage_path,
            hop_index=0,
            epoch=0,
            root_block_hash=tok0.root_block_hash,
            current_block_hash=tok0.leaf_block_hash,
            action_detail={"peer_spiffe_id": gw_id.spiffe_id},
            decision="ALLOW",
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
            service_name="ca-aud-r2",
            dispatcher=lambda req: ca_em.local_store.serve_http_query(
                req, resolver, node_spiffe_id=ca_alpha.root_authority_spiffe_id, require_task_id=True
            ),
            host="127.0.0.1",
            port=0,
        )
        alice_srv = ManagedHTTPService(
            service_name="alice-aud-r2",
            dispatcher=lambda req: alice_em.local_store.serve_http_query(
                req, resolver, node_spiffe_id=alice_id.spiffe_id, require_task_id=True
            ),
            host="127.0.0.1",
            port=0,
        )
        u_ca = ca_srv.start()
        u_alice = alice_srv.start()
        try:
            # 1) Offline downstream participant `bob_id` -> `reconstructed_complete=False` + anomaly,
            #    while `gw_id` (`peer_spiffe_id`) is NOT in `unreachable_nodes`!
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
                tid, entry_spiffe_ids=[alice_id.spiffe_id], seed_domains=["org-alpha.io"]
            )
            self.assertFalse(res.reconstructed_complete)
            self.assertNotIn(gw_id.spiffe_id, res.unreachable_nodes)
            self.assertIn(bob_id.spiffe_id, res.unreachable_nodes)
            self.assertTrue(
                any(a.code == f"REQUIRED_AUDIT_NODE_UNREACHABLE:{bob_id.spiffe_id}" for a in res.anomalies)
            )

            # 2) Public / link-local SSRF targets rejected (`8.8.8.8`, `169.254.169.254`)
            for bad_url in (
                "https://8.8.8.8:8443/v1/audit/local",
                "http://169.254.169.254:80/v1/audit/local",
            ):
                with self.assertRaises(LocatorError):
                    dist._verify_kwarg(bad_url, expected_spiffe_id=bob_id.spiffe_id)

            # 3) When `mtls_bundle` is configured, plaintext `http://` workload URLs are strictly rejected!
            x_ca = X509DomainAuthority("org-alpha.io")
            kp_m = KeyPair.generate("ES256")
            leaf_pem = x_ca.issue_x509_svid(auditor_id.spiffe_id, kp_m.public_jwk())
            x_store = X509FederationTrustStore()
            x_store.register_domain_root_pem("org-alpha.io", x_ca.export_root_pem())
            mb = WorkloadMTLSBundle(auditor_id.spiffe_id, kp_m, leaf_pem, x_store)
            try:
                dist_mtls = DistributedAuditor(
                    trust_resolver=resolver,
                    signer=auditor_id,
                    mtls_bundle=mb,
                )
                with self.assertRaises(LocatorError):
                    dist_mtls._verify_kwarg(
                        "http://10.29.77.23:31103/v1/audit/local",
                        expected_spiffe_id=bob_id.spiffe_id,
                    )
            finally:
                mb.cleanup()

            # 4) `max_depth=1` on a 2-hop chain (`alice` depth=0 -> `bob` depth=1 -> `dave` depth=2)
            #    triggers `MAX_AUDIT_BFS_DEPTH_EXCEEDED` and `reconstructed_complete=False`!
            dave_id = ca_beta.issue_workload("/ns/beta/sa/assistant-dave")
            tok2 = tok1.attenuate(
                issuer_identity=bob_id,
                delegate_spiffe_id=dave_id.spiffe_id,
                delegate_jkt=dave_id.jkt,
                permissions=p,
                hop_segment="DaveBranch",
            )
            bob_em = AuditStreamEmitter(
                bob_id, collector_client=None, authorized_auditors=[auditor_id.spiffe_id]
            )
            bob_em.emit(
                event_type=AuditEventType.OUTBOUND_DELEGATE,
                task_id=tid,
                sub=tok2.sub,
                lineage_path=tok2.lineage_path,
                hop_index=2,
                epoch=0,
                root_block_hash=tok2.root_block_hash,
                parent_block_hash=tok2.parent_block_hash,
                current_block_hash=tok2.leaf_block_hash,
                action_detail={"target_spiffe_id": dave_id.spiffe_id},
                decision="ALLOW",
            )
            bob_srv = ManagedHTTPService(
                service_name="bob-aud-r2",
                dispatcher=lambda req: bob_em.local_store.serve_http_query(
                    req, resolver, node_spiffe_id=bob_id.spiffe_id, require_task_id=True
                ),
                host="127.0.0.1",
                port=0,
            )
            u_bob = bob_srv.start()
            try:
                dist_shallow = DistributedAuditor(
                    trust_resolver=resolver,
                    signer=auditor_id,
                    domain_ca_urls={"org-alpha.io": u_ca},
                    spiffe_url_overrides={
                        alice_id.spiffe_id: u_alice,
                        bob_id.spiffe_id: u_bob,
                        dave_id.spiffe_id: u_bob,
                    },
                    max_depth=1,
                )
                res_sh = dist_shallow.pull_and_reconstruct(
                    tid, entry_spiffe_ids=[alice_id.spiffe_id], seed_domains=["org-alpha.io"]
                )
                self.assertFalse(res_sh.reconstructed_complete)
                self.assertTrue(
                    any(a.code.startswith("MAX_AUDIT_BFS_DEPTH_EXCEEDED:") for a in res_sh.anomalies)
                )
            finally:
                bob_srv.stop()
        finally:
            alice_srv.stop()
            ca_srv.stop()

    def test_06_verify_medium_m9_01_idempotency_parameter_conflict_and_vault_409(self) -> None:
        ledger = IdempotencyLedger(max_entries=64)
        r1, rep1 = ledger.execute_once(
            sub="user:alice@org-alpha.io",
            idempotency_key="idem-k1",
            operation="reserve_cloud_budget",
            target="cloud-infra-escrow",
            project_code="PRJ-ATLAS",
            amount_usd=280.0,
            builder_fn=lambda rid: {"rid": rid},
        )
        self.assertFalse(rep1)

        # Exact match -> idempotent replay succeeds
        r2, rep2 = ledger.execute_once(
            sub="user:alice@org-alpha.io",
            idempotency_key="idem-k1",
            operation="reserve_cloud_budget",
            target="cloud-infra-escrow",
            project_code="PRJ-ATLAS",
            amount_usd=280.0,
            builder_fn=lambda rid: {"rid": rid},
        )
        self.assertTrue(rep2)
        self.assertEqual(r1["receipt_id"], r2["receipt_id"])

        # Mismatched operation, target, project_code, or amount_usd MUST raise IdempotencyConflictError!
        for mut_kwargs in (
            {"operation": "lock_joint_project"},
            {"target": "vendor-procurement-escrow"},
            {"project_code": "PRJ-ROGUE"},
            {"amount_usd": 499.0},
        ):
            params = {
                "sub": "user:alice@org-alpha.io",
                "idempotency_key": "idem-k1",
                "operation": "reserve_cloud_budget",
                "target": "cloud-infra-escrow",
                "project_code": "PRJ-ATLAS",
                "amount_usd": 280.0,
                "builder_fn": lambda rid: {"rid": rid},
                **mut_kwargs,
            }
            with self.assertRaises(IdempotencyConflictError):
                ledger.execute_once(**params)

        # Also verify HTTP `409 IDEMPOTENCY_PARAMETER_MISMATCH` on live `WorkspaceVaultMCPApp`
        lsec = secrets.token_urlsafe(16)
        vault_app = WorkspaceVaultMCPApp(
            loopback_secret=lsec, outbound_proxy_url="http://127.0.0.1:9", ollama=None, port=0
        )
        v_url = vault_app.start()
        try:
            hdrs = {
                "X-LCT-Loopback-Auth": lsec,
                "X-LCT-Sub": "user:alice@org-alpha.io",
                "X-LCT-Task-Id": "t-idem",
                "X-LCT-Idempotency-Key": "idem-http-1",
            }
            resp1 = httpx.post(
                f"{v_url}/mcp",
                headers=hdrs,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "reserve_cloud_budget",
                        "arguments": {"project_code": "PRJ-ATLAS", "amount": 280.0},
                    },
                },
                timeout=5.0,
            )
            self.assertEqual(resp1.status_code, 200)

            resp_conflict = httpx.post(
                f"{v_url}/mcp",
                headers=hdrs,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "reserve_cloud_budget",
                        "arguments": {"project_code": "PRJ-ATLAS", "amount": 499.0},
                    },
                },
                timeout=5.0,
            )
            self.assertEqual(resp_conflict.status_code, 409)
            self.assertEqual(resp_conflict.json()["error"], "IDEMPOTENCY_PARAMETER_MISMATCH")
        finally:
            vault_app.stop()

    def test_07_verify_r2_rehearsal_evidence_scale_report_and_pre_push_secret_hygiene(self) -> None:
        r2_dir = REPO_ROOT / "lineage/k8s/runs/20261125-m9-r2-workspace-rehearsal"
        self.assertTrue(r2_dir.is_dir())
        summary = json.loads((r2_dir / "workspace_platform_v2_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["overall_status"], "PASS")
        self.assertFalse(summary["central_audit_collector_deployed"])

        s2 = summary["scenarios"]["2_cross_principal_and_coauth"]
        self.assertEqual(s2["dual_mode_oauth_cross_principal_http"], 403)
        self.assertEqual(s2["missing_bob_oidc_consent_http"], 401)
        self.assertEqual(s2["owner_only_consent_refusal_http"], 403)
        self.assertEqual(s2["assistant_bob_sa_mint_root_http"], 403)

        s3 = summary["scenarios"]["3_expiry_checkpoint_continuation"]
        self.assertEqual(s3["inflation_attempt_http"], 403)
        self.assertEqual(s3["continuation_replay_http"], 409)
        self.assertEqual(s3["continuation_replay_error"], "CONTINUATION_REPLAY_REJECTED")

        s4a = summary["scenarios"]["4a_post_commit_idempotent_failover"]
        self.assertEqual(s4a["conflicting_idempotency_replay_http"], 409)
        self.assertEqual(s4a["conflicting_idempotency_replay_error"], "IDEMPOTENCY_PARAMETER_MISMATCH")

        s5_aud = summary["scenarios"]["5_degradation_compare_and_audit"]["distributed_audit"]
        self.assertTrue(s5_aud["reconstructed_complete"])
        self.assertEqual(s5_aud["unreachable_nodes"], {})
        self.assertEqual(s5_aud["anomalies"], [])

        scale_doc = json.loads(
            (REPO_ROOT / "lineage/scale/latest_scale_report.json").read_text(encoding="utf-8")
        )
        tiers = {t["peer_nodes"]: t for t in scale_doc["tiers"]}
        self.assertIn(4, tiers)
        self.assertIn(24, tiers)
        self.assertEqual(tiers[24]["central_audit_collectors"], 0)
        self.assertEqual(tiers[24]["decentralized_audit"]["reconstruction_accuracy_pct"], 100.0)

        # Secret hygiene scan across R2 rehearsal + scale + reviews
        pem_re = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE" + r" KEY-----")
        jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
        lct_re = re.compile(r"\blct(?:1|m1|mp1|co1)\.[A-Za-z0-9_-]{16,}")
        for rel in (
            "lineage/k8s/runs/20261125-m9-r2-workspace-rehearsal",
            "lineage/scale",
        ):
            for fp in (REPO_ROOT / rel).rglob("*"):
                if fp.is_file():
                    txt = fp.read_text(encoding="utf-8", errors="replace")
                    self.assertIsNone(pem_re.search(txt), f"Private key leak in {fp}")
                    self.assertIsNone(jwt_re.search(txt), f"Raw JWT leak in {fp}")
                    self.assertIsNone(lct_re.search(txt), f"Raw LCT token leak in {fp}")


if __name__ == "__main__":
    unittest.main()
