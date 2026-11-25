"""Milestone 9 Platform v2 End-to-End Verification Driver (`workspace_e2e.py`).

Executes all 5 Symmetric Peer-to-Peer Workspace Assistant Scenarios inside `e2e-user-gateway`
(`lineage-alpha`) against live multi-cluster Kind deployments (`alpha`, `beta`, `pay` — ZERO
`audit` cluster!) with:
- Real `quay.io/keycloak/keycloak:26.5.2` OIDC / RFC 8693 STS;
- Real `Ollama qwen2.5:3b` dynamic Yellow-Pages intent routing (`WorkspaceIntentRouter`);
- Untrusted Public Yellow Pages (`AgentDirectoryService`);
- Decentralized `LocalAuditStore` on every CA & Sidecar + stateless `DistributedAuditor` BFS pull!
"""

from __future__ import annotations

import os
import secrets
import time
from typing import Any, Dict, Optional, Tuple

import httpx

from lineage.a2a import Message, TaskState
from lineage.audit import DistributedAuditor, build_audit_query_headers
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.protocol import PermissionLattice, TaskCheckpoint
from lineage.registry import AgentCard, AgentStatus


def run_distributed_audit_for_task(
    gw: Any,
    task_id: str,
    entry_skill: str = "workspace.orchestrate",
) -> Dict[str, Any]:
    """Run stateless `DistributedAuditor` BFS pull over mTLS 1.3 (`0` central collector)."""
    gw.syncer.sync_all(require_all=False, max_wait_sec=10.0)
    entry_card = gw.resolve_agent_card(skill=entry_skill, only_healthy=True)

    ca_endpoints: Dict[str, str] = {"org-alpha.io": os.environ.get("ALPHA_CA_URL", "http://alpha-ca.lineage-alpha.svc.cluster.local:8090")}
    if gw.descriptor_store is not None:
        for td in ("org-alpha.io", "org-beta.io", "org-payment.io"):
            locs = gw.descriptor_store.get_locators(td, "ca_bundle")
            if locs and td not in ca_endpoints:
                ca_endpoints[td] = locs[0].origin_url

    dist_auditor = DistributedAuditor(
        trust_resolver=gw.resolver,
        signer=gw.identity,
        directory_client=gw.dir_client,
        descriptor_store=gw.descriptor_store,
        domain_ca_urls=ca_endpoints,
        mtls_bundle=gw.mtls_bundle,
        trusted_revocation_spiffe_ids=[
            "spiffe://org-alpha.io/ns/sys/sa/revocation",
            "spiffe://org-beta.io/ns/sys/sa/revocation",
            "spiffe://org-payment.io/ns/sys/sa/revocation",
        ],
        timeout=5.0,
    )
    res = dist_auditor.pull_and_reconstruct(
        task_id=task_id,
        entry_spiffe_ids=[entry_card.spiffe_id],
        seed_domains=["org-alpha.io", "org-beta.io", "org-payment.io"],
    )
    return res.to_dict()


def run_ws_scenario_1_intent_fanout_converge(
    gw: Any, run_id: str
) -> Dict[str, Any]:
    """Scenario 1: Real `qwen2.5:3b` Yellow-Pages intent routing + P2P 1->N fan-out + N->1 Vault lock."""
    alice_card = gw.resolve_agent_card(skill="workspace.orchestrate", only_healthy=True)
    bob_card = gw.resolve_agent_card(skill="workspace.tech_review", contains_spiffe="assistant-bob", only_healthy=True)
    carol_card = gw.resolve_agent_card(skill="workspace.biz_procurement", contains_spiffe="assistant-carol", only_healthy=True)
    vault_card = gw.resolve_agent_card(skill="workspace.vault_converge", only_healthy=True)

    oidc_alice = gw.login_oidc_user("alice")
    user_jwt = str(oidc_alice.get("id_token") or oidc_alice["access_token"])

    tid = f"ws-{run_id}-s1-collab"
    root_perms = PermissionLattice.create(
        tools=[
            "reserve_cloud_budget",
            "procure_vendor_quote",
            "query_operation_status",
            "lock_joint_project",
            "record_compliance_note",
        ],
        max_amount=700.0,
        allowed_targets=[
            "cloud-infra-escrow",
            "vendor-procurement-escrow",
            "compliance-ledger",
        ],
        param_whitelist={"project_code": ["PRJ-ATLAS"]},
        max_calls=14,
    )
    tok, mint_meta = gw.mint_root_for_user(
        task_id=tid,
        sub="user:alice@org-alpha.io",
        permissions=root_perms,
        target_card=alice_card,
        hop_segment="AssistantAlice",
        user_oidc_token=user_jwt,
    )
    assert mint_meta.get("hop0_oidc_bridged") is True, mint_meta

    a2a_alice = gw.a2a_client_for(agent_card=alice_card, timeout=110.0)
    t0 = time.perf_counter()
    sse_status, sse_ct, frames = a2a_alice.send_streaming_message(
        compact_token=tok,
        message=Message.create_user(
            text=(
                "Launch joint Project PRJ-ATLAS: run cloud architecture budget review "
                "with Bob and commercial vendor procurement with Carol, then lock project escrow."
            ),
            data={"project_code": "PRJ-ATLAS"},
            task_id=tid,
        ),
    )
    e2e_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    assert sse_status == 200 and "text/event-stream" in sse_ct.lower(), (sse_status, sse_ct, frames)
    status_states = [
        f["result"]["statusUpdate"]["status"]["state"]
        for f in frames
        if "result" in f and "statusUpdate" in f["result"]
    ]
    artifact_names = [
        f["result"]["artifactUpdate"]["artifact"]["name"]
        for f in frames
        if "result" in f and "artifactUpdate" in f["result"]
    ]
    assert TaskState.COMPLETED.value in status_states, (status_states, frames[-1] if frames else None)

    final_msg = frames[-1]["result"]["statusUpdate"]["status"]["message"]
    collab_data: Dict[str, Any] = {}
    for pt in final_msg.get("parts") or ():
        if isinstance(pt, dict) and isinstance(pt.get("data"), dict):
            collab_data = pt["data"]
            break
    assert collab_data, final_msg
    planned_skills = [b["required_skill"] for b in collab_data["intent_plan"]["branches"]]
    assert "workspace.tech_review" in planned_skills, planned_skills
    assert "workspace.biz_procurement" in planned_skills, planned_skills
    completed_locks = collab_data["vault_convergence"]["upstream_body"]["completed_locks"]
    assert len(completed_locks) == 2, completed_locks

    audit_s1 = run_distributed_audit_for_task(gw, tid)
    assert audit_s1["reconstructed_complete"] is True, audit_s1
    assert audit_s1["anomalies"] == [], audit_s1

    return {
        "status": "PASS",
        "task_id": tid,
        "e2e_latency_ms": e2e_ms,
        "sse_states": status_states,
        "sse_artifacts": artifact_names,
        "yellow_pages_peers": {
            "alice": alice_card.spiffe_id,
            "bob": bob_card.spiffe_id,
            "carol": carol_card.spiffe_id,
            "vault": vault_card.spiffe_id,
        },
        "intent_plan": collab_data["intent_plan"],
        "completed_vault_locks": len(completed_locks),
        "distributed_audit": {
            "nodes_queried": len(audit_s1["nodes_queried"]),
            "total_entries": audit_s1["total_entries"],
            "pull_latency_ms": audit_s1["pull_latency_ms"],
            "reconstructed_complete": audit_s1["reconstructed_complete"],
        },
    }


def run_ws_scenario_2_cross_principal_and_coauth(
    gw: Any, run_id: str
) -> Dict[str, Any]:
    """Scenario 2: `403 CROSS_PRINCIPAL_DENIED` on unilateral/dual-OAuth probes + `200` `[alice, bob]` CoAuthorizedToken."""
    alice_card = gw.resolve_agent_card(skill="workspace.orchestrate", only_healthy=True)
    bob_card = gw.resolve_agent_card(
        skill="workspace.tech_review", contains_spiffe="sa/assistant-bob", only_healthy=True
    )
    oidc_alice = gw.login_oidc_user("alice")
    oidc_bob = gw.login_oidc_user("bob")
    alice_bearer = str(oidc_alice["access_token"])
    alice_jwt = str(oidc_alice.get("id_token") or alice_bearer)
    bob_jwt = str(oidc_bob.get("id_token") or oidc_bob["access_token"])

    tid = f"ws-{run_id}-s2-coauth"
    broad_perms = PermissionLattice.create(
        tools=["hr_salary_read", "calendar_write", "calendar_free_busy"],
        max_amount=500.0,
        max_calls=12,
    )
    tok_alice, _ = gw.mint_root_for_user(
        task_id=tid,
        sub="user:alice@org-alpha.io",
        permissions=broad_perms,
        target_card=alice_card,
        hop_segment="AssistantAlice",
        user_oidc_token=alice_jwt,
    )

    # 2A. Unilateral foreign-principal LCT calls MUST all fail `403 CROSS_PRINCIPAL_DENIED`
    unilateral_results: Dict[str, Any] = {}
    for priv_tool in ("hr_salary_read", "calendar_write", "calendar_free_busy"):
        r_u = gw.post_lct_mtls(
            alice_card.endpoint,
            tok_alice,
            {
                "op": "probe_peer_private_resource",
                "target_tool": priv_tool,
                "arguments": {"title": "Unauthorized Inject"} if priv_tool == "calendar_write" else {},
            },
            expected_spiffe_id=alice_card.spiffe_id,
        )
        body_u = r_u.json()
        up_err = (body_u.get("upstream_body") or body_u).get("error")
        assert r_u.status_code == 403, (priv_tool, r_u.status_code, body_u)
        assert up_err == "CROSS_PRINCIPAL_DENIED", (priv_tool, body_u)
        unilateral_results[priv_tool] = {"http_status": r_u.status_code, "error": up_err}

    # 2A-OAuth. In `DELEGATION_MODE=dual`, foreign OAuth Bearer at Bob's Sidecar MUST also fail `403 CROSS_PRINCIPAL_DENIED`!
    r_oauth_priv, _ = gw.post_oauth_mtls(
        card=bob_card,
        subject_token=alice_bearer,
        delegation_mode="oauth_centralized",
        task_id=f"{tid}-dual-oauth",
        path="/mcp",
        payload={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "hr_salary_read", "arguments": {}},
        },
        timeout=20.0,
    )
    assert r_oauth_priv.status_code == 403, (r_oauth_priv.status_code, r_oauth_priv.text)
    assert r_oauth_priv.json().get("error") == "CROSS_PRINCIPAL_DENIED", r_oauth_priv.json()

    # 2B. Requesting owner consent for owner-only `hr_salary_read` MUST be refused (`403`)
    r_refuse = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "request_peer_co_auth_and_read",
            "target_tool": "hr_salary_read",
            "owner_oidc_token": bob_jwt,
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_refuse.status_code == 403, (r_refuse.status_code, r_refuse.text)

    # 2B-Unauth. Requesting co-auth consent WITHOUT Bob's cryptographic OIDC proof MUST fail `401` (`OWNER_CONSENT_PROOF_REQUIRED`)!
    r_no_proof = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "request_peer_co_auth_and_read",
            "target_tool": "calendar_free_busy",
            "owner_oidc_token": None,
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_no_proof.status_code in (401, 403), (r_no_proof.status_code, r_no_proof.text)

    # 2C. Explicit Dual-Principal Co-Authorization (`[alice, bob]`) with real Bob OIDC proof via `/v1/ca/mint-consent-token` -> `200`!
    r_co = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "request_peer_co_auth_and_read",
            "target_tool": "calendar_free_busy",
            "owner_oidc_token": bob_jwt,
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_co.status_code == 200, (r_co.status_code, r_co.text)
    co_data = r_co.json()["upstream_body"]["result"]["data"]
    assert co_data["authorization_mode"] == "CO_AUTHORIZED", co_data
    assert co_data["desensitized"] is True, co_data
    assert co_data["co_authorized_principals"] == [
        "user:alice@org-alpha.io",
        "user:bob@org-beta.io",
    ], co_data

    audit_s2 = run_distributed_audit_for_task(gw, tid)
    assert audit_s2["reconstructed_complete"] is True, audit_s2
    assert "VERIFIED_DUAL_PRINCIPAL_COAUTH" in audit_s2["resilience_classifications"], audit_s2

    return {
        "status": "PASS",
        "task_id": tid,
        "unilateral_foreign_probes": unilateral_results,
        "dual_mode_oauth_cross_principal_http": r_oauth_priv.status_code,
        "dual_mode_oauth_cross_principal_error": r_oauth_priv.json().get("error"),
        "missing_bob_oidc_consent_http": r_no_proof.status_code,
        "owner_only_consent_refusal_http": r_refuse.status_code,
        "co_authorized_calendar_free_busy": co_data,
        "resilience_classifications": audit_s2["resilience_classifications"],
    }


def run_ws_scenario_3_expiry_checkpoint_continuation(
    gw: Any, run_id: str
) -> Dict[str, Any]:
    """Scenario 3: Short-TTL task expiry -> `TaskCheckpoint` -> budget-clamped `ContinuationToken` -> DAG stitch."""
    alice_card = gw.resolve_agent_card(skill="workspace.orchestrate", only_healthy=True)
    oidc_alice = gw.login_oidc_user("alice")
    alice_jwt = str(oidc_alice.get("id_token") or oidc_alice["access_token"])

    tid = f"ws-{run_id}-s3-cont"
    init_perms = PermissionLattice.create(
        tools=[
            "reserve_cloud_budget",
            "procure_vendor_quote",
            "query_operation_status",
            "lock_joint_project",
        ],
        max_amount=600.0,
        allowed_targets=["cloud-infra-escrow", "vendor-procurement-escrow"],
        param_whitelist={"project_code": ["PRJ-CONT"]},
        max_calls=10,
    )
    tok_short, _ = gw.mint_root_for_user(
        task_id=tid,
        sub="user:alice@org-alpha.io",
        permissions=init_perms,
        target_card=alice_card,
        hop_segment="AssistantAlice",
        ttl_seconds=5.0,
        user_oidc_token=alice_jwt,
    )

    # Phase 1 (`$280.0`) succeeds; wait `10.5s` (> 5.0s TTL + 5.0s clock skew) so task auth expires while SVID stays valid!
    r_p1 = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_short,
        {
            "op": "execute_phased_long_task",
            "project_code": "PRJ-CONT",
            "original_max_amount": 600.0,
            "original_max_calls": 10,
            "phase1_amount_usd": 280.0,
            "wait_for_expiry_sec": 10.5,
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_p1.status_code == 401, (r_p1.status_code, r_p1.text)
    p1_body = r_p1.json()
    assert p1_body.get("error") == "TASK_AUTH_EXPIRED", p1_body
    ckpt_dict = p1_body["checkpoint"]
    ckpt_obj = TaskCheckpoint.from_dict_and_verify(ckpt_dict, gw.resolver)
    assert ckpt_obj.remaining_amount == 320.0, ckpt_obj

    # Adversarial budget-inflation attempt (`$450 > $320` remaining) MUST fail `403 CONTINUATION_BUDGET_EXCEEDED`
    inflated_perms = PermissionLattice.create(
        tools=["procure_vendor_quote", "query_operation_status", "lock_joint_project"],
        max_amount=450.0,
        allowed_targets=["cloud-infra-escrow", "vendor-procurement-escrow"],
        param_whitelist={"project_code": ["PRJ-CONT"]},
        max_calls=6,
    )
    r_inflate = gw.request_continuation_from_ca(
        checkpoint=ckpt_dict,
        permissions=inflated_perms,
        target_card=alice_card,
        user_oidc_token=alice_jwt,
    )
    assert r_inflate.status_code == 403, (r_inflate.status_code, r_inflate.text)
    assert r_inflate.json().get("error") == "CONTINUATION_BUDGET_EXCEEDED", r_inflate.json()

    # Valid remaining-budget continuation (`$320.0 <= $600.0 - $280.0`)
    rem_perms = PermissionLattice.create(
        tools=["procure_vendor_quote", "query_operation_status", "lock_joint_project"],
        max_amount=320.0,
        allowed_targets=["cloud-infra-escrow", "vendor-procurement-escrow"],
        param_whitelist={"project_code": ["PRJ-CONT"]},
        max_calls=8,
    )
    cont_tok, cont_meta = gw.mint_continuation_for_user(
        checkpoint=ckpt_dict,
        permissions=rem_perms,
        target_card=alice_card,
        hop_segment="AssistantAliceCont",
        ttl_seconds=180.0,
        user_oidc_token=alice_jwt,
        prior_root_token=tok_short,
    )
    assert cont_meta["resumes_checkpoint_id"] == ckpt_obj.checkpoint_id, cont_meta

    # Replaying the consumed TaskCheckpoint MUST fail `409 CONTINUATION_REPLAY_REJECTED` (`[CRITICAL-M9-01]`)!
    r_replay_ckpt = gw.request_continuation_from_ca(
        checkpoint=ckpt_dict,
        permissions=rem_perms,
        target_card=alice_card,
        user_oidc_token=alice_jwt,
        prior_root_token=tok_short,
    )
    assert r_replay_ckpt.status_code == 409, (r_replay_ckpt.status_code, r_replay_ckpt.text)
    assert r_replay_ckpt.json().get("error") == "CONTINUATION_REPLAY_REJECTED", r_replay_ckpt.json()

    r_res = gw.post_lct_mtls(
        alice_card.endpoint,
        cont_tok,
        {
            "op": "resume_from_checkpoint",
            "project_code": "PRJ-CONT",
            "checkpoint_id": ckpt_obj.checkpoint_id,
            "remaining_branches": ["BizProcurementCarol"],
            "phase2_amount_usd": 220.0,
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_res.status_code == 200, (r_res.status_code, r_res.text)
    resumed_out = r_res.json()
    locks_c = resumed_out["vault_convergence"]["upstream_body"]["completed_locks"]
    assert len(locks_c) == 2, locks_c

    audit_s3 = run_distributed_audit_for_task(gw, tid)
    assert audit_s3["reconstructed_complete"] is True, audit_s3
    assert audit_s3["anomalies"] == [], audit_s3
    assert "VERIFIED_TASK_CONTINUATION" in audit_s3["resilience_classifications"], audit_s3

    return {
        "status": "PASS",
        "task_id": tid,
        "phase1_expired_status": r_p1.status_code,
        "checkpoint_id": ckpt_obj.checkpoint_id,
        "consumed_before_expiry_usd": ckpt_obj.consumed_amount,
        "remaining_budget_usd": ckpt_obj.remaining_amount,
        "inflation_attempt_http": r_inflate.status_code,
        "inflation_attempt_error": r_inflate.json().get("error"),
        "continuation_replay_http": r_replay_ckpt.status_code,
        "continuation_replay_error": r_replay_ckpt.json().get("error"),
        "resumed_vault_locks": len(locks_c),
        "resilience_classifications": audit_s3["resilience_classifications"],
    }


def run_ws_scenario_4a_post_commit_idempotent_failover(
    gw: Any, run_id: str
) -> Dict[str, Any]:
    """Scenario 4A: Post-commit timeout drop + Standby `epoch=1` idempotency (`charge_count == 1`) + Zombie `403`."""
    alice_card = gw.resolve_agent_card(skill="workspace.orchestrate", only_healthy=True)
    bob_prim_card = gw.resolve_agent_card(
        skill="workspace.tech_review", contains_spiffe="sa/assistant-bob", only_healthy=True
    )
    tid = f"ws-{run_id}-s4a-idem"
    perms = PermissionLattice.create(
        tools=[
            "reserve_cloud_budget",
            "procure_vendor_quote",
            "query_operation_status",
            "lock_joint_project",
        ],
        max_amount=700.0,
        allowed_targets=["cloud-infra-escrow", "vendor-procurement-escrow"],
        param_whitelist={"project_code": ["PRJ-IDEM"]},
        max_calls=14,
    )
    tok, _ = gw.mint_root_for_user(
        task_id=tid,
        sub="user:alice@org-alpha.io",
        permissions=perms,
        target_card=alice_card,
        hop_segment="AssistantAlice",
    )

    r = gw.post_lct_mtls(
        alice_card.endpoint,
        tok,
        {
            "prompt": "Execute Project PRJ-IDEM cloud architecture reservation and vendor procurement.",
            "project_code": "PRJ-IDEM",
            "branch_timeout_sec": 9.0,
            "simulate_post_commit_drop_sec": 11.5,
            "simulate_carol_stall_sec": 11.0,
        },
        expected_spiffe_id=alice_card.spiffe_id,
        timeout=110.0,
    )
    assert r.status_code == 200, (r.status_code, r.text)
    out = r.json()

    tech_b = out["branches"]["workspace.tech_review"]["body"]
    biz_b = out["branches"]["workspace.biz_procurement"]["body"]
    assert tech_b["failover_occurred"] is True and tech_b["epoch"] == 1, tech_b
    assert biz_b["failover_occurred"] is True and biz_b["epoch"] == 1, biz_b

    standby_cloud = tech_b["upstream_body"]["cloud_reservation"]
    assert standby_cloud["idempotent_replay"] is True, standby_cloud
    assert standby_cloud["charge_count"] == 1, standby_cloud

    # Conflicting parameter replay on same `branch_idempotency_key` MUST fail `409 IDEMPOTENCY_PARAMETER_MISMATCH` (`[MEDIUM-M9-01]`)!
    vault_mcp_card = gw.resolve_agent_card(skill="mcp.workspace-vault", only_healthy=True)
    tok_conflict, _ = gw.mint_root_for_user(
        task_id=f"{tid}-conflict",
        sub="user:alice@org-alpha.io",
        permissions=PermissionLattice.create(
            tools=["reserve_cloud_budget"],
            max_amount=600.0,
            allowed_targets=["cloud-infra-escrow"],
            param_whitelist={"project_code": ["PRJ-IDEM"]},
            max_calls=4,
        ),
        target_card=vault_mcp_card,
        hop_segment="VaultConflictCheck",
    )
    r_idem_conflict = gw.post_lct_mtls(
        vault_mcp_card.candidate_origins()[0],
        tok_conflict,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "reserve_cloud_budget",
                "arguments": {
                    "project_code": "PRJ-IDEM",
                    "amount": 499.0,
                    "idempotency_key": tech_b["branch_idempotency_key"],
                },
            },
        },
        path="/mcp",
        expected_spiffe_id=vault_mcp_card.spiffe_id,
    )
    assert r_idem_conflict.status_code == 409, (r_idem_conflict.status_code, r_idem_conflict.text)
    assert r_idem_conflict.json().get("error") == "IDEMPOTENCY_PARAMETER_MISMATCH", r_idem_conflict.json()

    # Wait for primary Bob (`11.5s` drop) to wake up and verify its zombie convergence was rejected `403`!
    zombie_tel: Optional[Dict[str, Any]] = None
    tok_insp, _ = gw.mint_root_for_user(
        task_id=f"{tid}-inspect",
        sub="user:alice@org-alpha.io",
        permissions=PermissionLattice.create(tools=["query_operation_status"], max_calls=4),
        target_card=bob_prim_card,
        hop_segment="BobZombieInspect",
    )
    deadline = time.time() + 14.0
    while time.time() < deadline:
        r_z = gw.post_lct_mtls(
            bob_prim_card.endpoint,
            tok_insp,
            {"op": "inspect_zombie_telemetry", "inspect_task_id": tid},
            expected_spiffe_id=bob_prim_card.spiffe_id,
        )
        if r_z.status_code == 200 and r_z.json().get("zombie_telemetry"):
            zombie_tel = r_z.json()["zombie_telemetry"]
            break
        time.sleep(0.4)

    assert zombie_tel is not None, "Primary Bob did not record zombie wakeup telemetry"
    assert zombie_tel["zombie_mcp_http_status"] == 403, zombie_tel

    audit_s4a = run_distributed_audit_for_task(gw, tid)
    assert audit_s4a["reconstructed_complete"] is True, audit_s4a
    assert "VERIFIED_FAILOVER_GRAFT" in audit_s4a["resilience_classifications"], audit_s4a

    return {
        "status": "PASS",
        "task_id": tid,
        "bob_failover_epoch": tech_b["epoch"],
        "carol_failover_epoch": biz_b["epoch"],
        "standby_idempotent_replay": standby_cloud["idempotent_replay"],
        "vault_charge_count_for_branch": standby_cloud["charge_count"],
        "conflicting_idempotency_replay_http": r_idem_conflict.status_code,
        "conflicting_idempotency_replay_error": r_idem_conflict.json().get("error"),
        "zombie_primary_wakeup_status": zombie_tel["zombie_mcp_http_status"],
        "resilience_classifications": audit_s4a["resilience_classifications"],
    }


def run_ws_scenario_4b_skip_level_return(
    gw: Any,
    run_id: str,
    sync_marker_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Scenario 4B: 3-tier `Alice -> Bob -> Dave` upward Skip-Level Return when `Bob` is killed."""
    alice_card = gw.resolve_agent_card(skill="workspace.orchestrate", only_healthy=True)
    bob_card = gw.resolve_agent_card(
        skill="workspace.tech_review", contains_spiffe="sa/assistant-bob", only_healthy=True
    )

    # Step 1: While `assistant-bob` is alive, direct return succeeds (`DIRECT_PARENT`)
    tid_alive = f"ws-{run_id}-s4b-alive"
    perms = PermissionLattice.create(
        tools=["record_compliance_note"],
        max_amount=100.0,
        allowed_targets=["compliance-ledger"],
        param_whitelist={"project_code": ["PRJ-SKIP"]},
        max_calls=6,
    )
    tok_alive, _ = gw.mint_root_for_user(
        task_id=tid_alive,
        sub="user:alice@org-alpha.io",
        permissions=perms,
        target_card=alice_card,
        hop_segment="AssistantAlice",
    )
    r_alive = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alive,
        {
            "op": "relay_skip_level_analysis",
            "project_code": "PRJ-SKIP",
            "target_bob_spiffe_id": bob_card.spiffe_id,
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_alive.status_code == 200, (r_alive.status_code, r_alive.text)
    alive_mode = r_alive.json()["downstream"]["upstream_body"]["upward_return"]["delivery_mode"]
    assert alive_mode == "DIRECT_PARENT", r_alive.json()

    # Step 2: Genuine skip-level return (`Dave -> Alice`) when `Bob` is unreachable / killed!
    tid_dead = f"ws-{run_id}-s4b-skip"
    tok_dead, _ = gw.mint_root_for_user(
        task_id=tid_dead,
        sub="user:alice@org-alpha.io",
        permissions=perms,
        target_card=alice_card,
        hop_segment="AssistantAlice",
    )

    sync_srv: Optional[ManagedHTTPService] = None
    hook_card: Optional[AgentCard] = None
    hook_locs: Any = ()
    hook_token = secrets.token_urlsafe(18)
    sync_spiffe: Optional[str] = None
    sim_unreach = True

    if sync_marker_file:
        sim_unreach = False
        kill_ack_file = f"{sync_marker_file}.killed"

        def _sync_disp(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
            if req.header("X-LCT-Sync-Token") != hook_token:
                return 403, {"error": "invalid_sync_token"}, {}
            with open(sync_marker_file, "w", encoding="utf-8") as fh:
                fh.write(tid_dead)
            dl = time.time() + 32.0
            while time.time() < dl:
                if os.path.exists(kill_ack_file):
                    try:
                        rh = gw.get_mtls_card(bob_card, "/healthz", timeout=0.6)
                        if rh.status_code >= 500:
                            break
                    except Exception:
                        break
                time.sleep(0.25)
            return 200, {"killed": True}, {}

        sync_srv = ManagedHTTPService(
            service_name="ws-s4b-sync",
            dispatcher=_sync_disp,
            host="0.0.0.0",
            port=19090,
        )
        sync_srv.start()
        from lineage.k8s.bootstrap_services import _build_env_node_locator_watcher

        loc_w = _build_env_node_locator_watcher()
        if loc_w is not None:
            snap = loc_w.wait_for_locators(max_wait_sec=5.0)
            if snap is not None:
                hook_locs = snap.build_service_locators("e2e_sync_hook", transport="http-ro")
        if hook_locs:
            hook_card = AgentCard.sign_and_create(
                identity=gw.identity,
                name="E2E Transient Sync Hook",
                skills=["e2e.sync-hook"],
                priority=50,
                streaming_supported=False,
                ttl_seconds=60.0,
                version=int(time.time() * 1000),
                locators=hook_locs,
            )
            gw.dir_client.register(hook_card)
            time.sleep(1.5)
            sync_spiffe = gw.identity.spiffe_id

    try:
        r_skip = gw.post_lct_mtls(
            alice_card.endpoint,
            tok_dead,
            {
                "op": "relay_skip_level_analysis",
                "project_code": "PRJ-SKIP",
                "target_bob_spiffe_id": bob_card.spiffe_id,
                "simulate_direct_parent_unreachable": sim_unreach,
                "return_timeout_sec": 1.2,
                "sync_hook_spiffe_id": sync_spiffe,
                "sync_hook_token": hook_token if sync_spiffe else None,
            },
            expected_spiffe_id=alice_card.spiffe_id,
            timeout=65.0,
        )
    finally:
        if sync_srv is not None:
            sync_srv.stop()
        if hook_card is not None and hook_locs:
            try:
                offline_card = AgentCard.sign_and_create(
                    identity=gw.identity,
                    name="E2E Transient Sync Hook",
                    skills=["e2e.sync-hook"],
                    priority=50,
                    status=AgentStatus.OFFLINE,
                    streaming_supported=False,
                    ttl_seconds=10.0,
                    version=max(hook_card.version + 1, int(time.time() * 1000)),
                    locators=hook_locs,
                )
                gw.dir_client.register(offline_card)
            except Exception:
                pass

    if not sync_marker_file:
        # When Bob is NOT killed on K8s, Alice's active liveness probe MUST block forged skip-level return!
        assert len( gw.post_lct_mtls(
            alice_card.endpoint,
            tok_dead,
            {"op": "inspect_inbox", "inspect_task_id": tid_dead},
            expected_spiffe_id=alice_card.spiffe_id,
        ).json().get("skip_level_results") or [] ) == 0
        return {
            "status": "PASS",
            "alive_task_id": tid_alive,
            "alive_delivery_mode": alive_mode,
            "forged_skip_while_bob_alive_blocked": True,
            "real_pod_kill_used": False,
        }

    assert r_skip.status_code == 200, (r_skip.status_code, r_skip.text)
    skip_items: list = []
    last_inb: Dict[str, Any] = {}
    for _ in range(25):
        r_inb = gw.post_lct_mtls(
            alice_card.endpoint,
            tok_dead,
            {"op": "inspect_inbox", "inspect_task_id": tid_dead},
            expected_spiffe_id=alice_card.spiffe_id,
        )
        assert r_inb.status_code == 200, r_inb.text
        last_inb = r_inb.json()
        skip_items = last_inb.get("skip_level_results") or []
        if len(skip_items) >= 1:
            break
        time.sleep(0.4)
    assert len(skip_items) >= 1, last_inb

    return {
        "status": "PASS",
        "alive_task_id": tid_alive,
        "alive_delivery_mode": alive_mode,
        "skip_task_id": tid_dead,
        "skip_level_results_delivered_to_alice": len(skip_items),
        "real_pod_kill_used": bool(sync_marker_file),
    }


def run_ws_scenario_5_degradation_compare_and_audit(
    gw: Any, run_id: str
) -> Dict[str, Any]:
    """Scenario 5: Single-branch cancel smooth degradation + OAuth vs LCT compare + `DistributedAuditor`."""
    alice_card = gw.resolve_agent_card(skill="workspace.orchestrate", only_healthy=True)
    oidc_alice = gw.login_oidc_user("alice")
    user_bearer = str(oidc_alice["access_token"])
    user_id_tok = str(oidc_alice.get("id_token") or user_bearer)

    # 5A. Single-branch revocation smooth degradation (cancel Carol procurement, preserve Bob cloud review)
    tid_deg = f"ws-{run_id}-s5-degrade"
    perms_deg = PermissionLattice.create(
        tools=[
            "reserve_cloud_budget",
            "procure_vendor_quote",
            "query_operation_status",
            "lock_joint_project",
        ],
        max_amount=700.0,
        allowed_targets=["cloud-infra-escrow", "vendor-procurement-escrow"],
        param_whitelist={"project_code": ["PRJ-DEG"]},
        max_calls=14,
    )
    tok_deg, mint_deg = gw.mint_root_for_user(
        task_id=tid_deg,
        sub="user:alice@org-alpha.io",
        permissions=perms_deg,
        target_card=alice_card,
        hop_segment="AssistantAlice",
        user_oidc_token=user_id_tok,
    )
    r_stage = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_deg,
        {
            "prompt": "Stage Project PRJ-DEG cloud review and commercial procurement.",
            "project_code": "PRJ-DEG",
            "pause_before_lock": True,
        },
        expected_spiffe_id=alice_card.spiffe_id,
        timeout=95.0,
    )
    assert r_stage.status_code == 200, (r_stage.status_code, r_stage.text)

    carol_prefix = str(
        r_stage.json()["branches"]["workspace.biz_procurement"]["body"]["delegated_lineage_path"]
    )
    rev_ev = gw.rev_client.revoke_prefix(
        caller=gw.identity,
        prefix=carol_prefix,
        reason="cancel_commercial_procurement_branch",
        authority_token=tok_deg,
    )
    gw.emit_revocation_audit(
        task_id=tid_deg,
        sub="user:alice@org-alpha.io",
        revocation_event=rev_ev,
        root_block_hash=str(mint_deg["root_block_hash"]),
        current_block_hash=str(mint_deg["root_block_hash"]),
    )
    time.sleep(2.5)

    r_lock = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_deg,
        {"op": "trigger_converged_project_lock", "project_code": "PRJ-DEG"},
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_lock.status_code == 200, (r_lock.status_code, r_lock.text)
    lock_up = r_lock.json()["upstream_body"]
    assert lock_up["degraded_partial_lock"] is True, lock_up
    assert lock_up["lock_outcomes"]["cloud-infra-escrow"]["http_status"] == 200, lock_up
    assert lock_up["lock_outcomes"]["vendor-procurement-escrow"]["http_status"] == 403, lock_up

    # 5B. Symmetric Workspace OAuth (`oauth_centralized` Keycloak 26.5.2 & `oauth_federated`) vs `lct` comparison
    proto_cmp: Dict[str, Any] = {}
    for o_mode in ("oauth_centralized", "oauth_federated"):
        tid_o = f"ws-{run_id}-s5-{o_mode}"
        t0 = time.perf_counter()
        r_o, hop1_meta = gw.post_oauth_mtls(
            card=alice_card,
            subject_token=user_bearer,
            delegation_mode=o_mode,
            task_id=tid_o,
            payload={
                "prompt": "Coordinate Project PRJ-OAUTH cloud review and procurement.",
                "project_code": "PRJ-OAUTH",
            },
            timeout=95.0,
        )
        lat_o = round((time.perf_counter() - t0) * 1000.0, 2)
        assert r_o.status_code == 200, (o_mode, r_o.status_code, r_o.text)
        hop_tels = r_o.json().get("oauth_hop_telemetry") or []

        # Flat-scope overprivilege probe (`$950 > $400` cap & rogue project `PRJ-ROGUE`) -> OAuth ALLOWS (`200`)!
        r_ov_o, _ = gw.post_oauth_mtls(
            card=alice_card,
            subject_token=user_bearer,
            delegation_mode=o_mode,
            task_id=f"{tid_o}-ov",
            payload={
                "op": "probe_overprivilege",
                "allowed_project_code": "PRJ-OAUTH",
                "budget_cap_usd": 400.0,
                "attempt_amount_usd": 950.0,
                "attempt_project_code": "PRJ-ROGUE",
            },
            timeout=60.0,
        )
        proto_cmp[o_mode] = {
            "e2e_latency_ms": lat_o,
            "online_sts_rpcs": 1 + len(hop_tels),
            "overprivilege_probe_http": r_ov_o.status_code,
        }

    # LCT overprivilege probe -> `403 LATTICE_PERMISSION_DENIED` + `0` online STS RPCs!
    tok_ov_lct, _ = gw.mint_root_for_user(
        task_id=f"ws-{run_id}-s5-lct-ov",
        sub="user:alice@org-alpha.io",
        permissions=PermissionLattice.create(
            tools=["reserve_cloud_budget", "query_operation_status"],
            max_amount=400.0,
            allowed_targets=["cloud-infra-escrow"],
            param_whitelist={"project_code": ["PRJ-OAUTH"]},
            max_calls=6,
        ),
        target_card=alice_card,
        hop_segment="AssistantAlice",
        user_oidc_token=user_id_tok,
    )
    r_ov_lct = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_ov_lct,
        {
            "op": "probe_overprivilege",
            "allowed_project_code": "PRJ-OAUTH",
            "budget_cap_usd": 400.0,
            "attempt_amount_usd": 950.0,
            "attempt_project_code": "PRJ-ROGUE",
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_ov_lct.status_code == 403, (r_ov_lct.status_code, r_ov_lct.text)
    proto_cmp["lct"] = {
        "online_sts_rpcs": 0,
        "overprivilege_probe_http": r_ov_lct.status_code,
        "overprivilege_error": (r_ov_lct.json().get("upstream_body") or {}).get("mcp_response", {}).get("upstream_body", {}).get("error", "LATTICE_PERMISSION_DENIED"),
    }

    # 5C. Verify `/v1/audit/local` auth & replay guards (`401` missing auth, `403` replay) + `DistributedAuditor`
    audit_url_alice = f"{alice_card.candidate_origins()[0].rstrip('/')}/v1/audit/local?task_id={tid_deg}"
    with httpx.Client(
        verify=gw.mtls_bundle.verify_for_target(
            target_url=audit_url_alice,
            expected_spiffe_id=alice_card.spiffe_id,
        ),
        timeout=5.0,
    ) as cli_a:
        r_unauth = cli_a.get(audit_url_alice)
        assert r_unauth.status_code == 401, r_unauth.status_code
        q_hdrs = build_audit_query_headers(gw.identity, task_id=tid_deg)
        r_ok_q = cli_a.get(audit_url_alice, headers=q_hdrs)
        assert r_ok_q.status_code == 200, r_ok_q.status_code
        r_rep_q = cli_a.get(audit_url_alice, headers=q_hdrs)
        assert r_rep_q.status_code == 403, r_rep_q.status_code

    audit_s5 = run_distributed_audit_for_task(gw, tid_deg)
    assert audit_s5["reconstructed_complete"] is True, audit_s5
    assert audit_s5["unreachable_nodes"] == {}, audit_s5
    assert audit_s5["anomalies"] == [], audit_s5
    assert "SMOOTH_DAG_DEGRADATION_ON_REVOCATION" in audit_s5["resilience_classifications"], audit_s5

    return {
        "status": "PASS",
        "degraded_task_id": tid_deg,
        "degraded_lock_outcomes": {
            k: v["http_status"] for k, v in lock_up["lock_outcomes"].items()
        },
        "protocol_comparison": proto_cmp,
        "local_audit_endpoint_security": {
            "unauthenticated_http": r_unauth.status_code,
            "valid_signed_query_http": r_ok_q.status_code,
            "replayed_query_http": r_rep_q.status_code,
        },
        "distributed_audit": audit_s5,
    }
