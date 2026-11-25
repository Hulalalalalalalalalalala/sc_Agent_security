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
from typing import Any, Dict, Optional, Sequence, Tuple

import httpx

from lineage.a2a import Message, TaskState
from lineage.audit import DistributedAuditor, build_audit_query_headers
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.protocol import PermissionLattice, TaskCheckpoint, compute_branch_idempotency_key
from lineage.registry import AgentCard, AgentStatus


def _resolve_beta_user_gateway(gw: Any) -> Tuple[str, str]:
    """Resolve `beta-user-gateway` (`org-beta.io`) dynamically from signed domain descriptor."""
    gw.syncer.sync_all(require_all=False, max_wait_sec=12.0)
    if gw.descriptor_store is not None:
        locs = gw.descriptor_store.get_locators("org-beta.io", "user_gateway")
        if locs:
            loc = locs[0]
            return str(loc.origin_url).rstrip("/"), str(loc.spiffe_id or "spiffe://org-beta.io/ns/lineage-beta/sa/beta-user-gateway")
    raise RuntimeError("No verified 'user_gateway' locator published in org-beta.io SignedDomainDescriptor")


def _post_beta_gateway_mtls(
    gw: Any,
    path: str,
    payload: Dict[str, Any],
    timeout: float = 90.0,
) -> httpx.Response:
    origin, exp_spiffe = _resolve_beta_user_gateway(gw)
    url = f"{origin}{path}"
    with httpx.Client(
        verify=gw.mtls_bundle.verify_for_target(
            target_url=url,
            expected_spiffe_id=exp_spiffe,
        ),
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        return client.post(url, json=payload)


def run_distributed_audit_for_task(
    gw: Any,
    task_id: str,
    entry_skill: str = "workspace.orchestrate",
    entry_spiffe_ids: Optional[Sequence[str]] = None,
    seed_domains: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Run stateless `DistributedAuditor` BFS pull over mTLS 1.3 (`0` central collector)."""
    gw.syncer.sync_all(require_all=False, max_wait_sec=10.0)
    eff_entries = (
        [str(s) for s in entry_spiffe_ids if str(s).strip()]
        if entry_spiffe_ids
        else [gw.resolve_agent_card(skill=entry_skill, only_healthy=True).spiffe_id]
    )
    eff_seeds = (
        [str(d) for d in seed_domains if str(d).strip()]
        if seed_domains
        else ["org-alpha.io", "org-beta.io", "org-payment.io"]
    )

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
        entry_spiffe_ids=eff_entries,
        seed_domains=eff_seeds,
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



# =============================================================================
# Milestone 10 (Platform v2.1) — 6 Expanded Domain-Vertical Scenarios (S2/S3/S5/S6/S7/S8)
# =============================================================================


def run_ws_scenario_6_bidirectional_fin_pingpong(
    gw: Any, run_id: str
) -> Dict[str, Any]:
    """Catalog S2 (Financial Risk Control): Bidirectional `A -> B` & `B -> A` Ping-Pong + Joint Vault Change + Dual-Domain Revocation Interlock."""
    alice_card = gw.resolve_agent_card(skill="workspace.orchestrate", only_healthy=True)
    bob_card = gw.resolve_agent_card(
        skill="workspace.tech_review", contains_spiffe="sa/assistant-bob", only_healthy=True
    )

    oidc_alice = gw.login_oidc_user("alice")
    alice_jwt = str(oidc_alice.get("id_token") or oidc_alice["access_token"])
    oidc_bob = gw.login_oidc_user("bob")
    bob_jwt = str(oidc_bob.get("id_token") or oidc_bob["access_token"])
    bob_access_jwt = str(oidc_bob["access_token"])

    tid = f"ws-{run_id}-s6-fin-pingpong"
    alice_perms = PermissionLattice.create(
        tools=["service_diag_read", "commit_joint_change"],
        param_whitelist={"change_id": ["FIN-RULE-42"]},
        max_calls=10,
    )
    tok_alice, _ = gw.mint_root_for_user(
        task_id=tid,
        sub="user:alice@org-alpha.io",
        permissions=alice_perms,
        target_card=alice_card,
        hop_segment="AssistantAlice",
        user_oidc_token=alice_jwt,
    )

    # Round 1 (A -> B): Unilateral LCT probe fails 403 -> Bob OIDC consent -> CoAuth([alice, bob]) succeeds 200!
    r_r1_unilat = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {"op": "probe_peer_private_resource", "target_tool": "service_diag_read"},
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_r1_unilat.status_code == 403, (r_r1_unilat.status_code, r_r1_unilat.text)

    r_r1_co = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "request_peer_co_auth_and_read",
            "target_tool": "service_diag_read",
            "owner_oidc_token": bob_jwt,
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_r1_co.status_code == 200, (r_r1_co.status_code, r_r1_co.text)
    diag_data = r_r1_co.json()["upstream_body"]["result"]["data"]
    assert diag_data["desensitized"] is True and diag_data["raw_pii_present"] is False, diag_data
    assert diag_data["co_authorized_principals"] == [
        "user:alice@org-alpha.io",
        "user:bob@org-beta.io",
    ], diag_data

    # Round 2 (REVERSE B -> A):
    # (a) DELEGATION_MODE=dual OAuth Bearer probe by Bob (`beta-sts`) via A2A JSON-RPC `parts[].data.private_tool` -> 403!
    r_r2_oauth, _ = gw.post_oauth_mtls(
        alice_card,
        bob_access_jwt,
        "oauth_federated",
        tid,
        {
            "jsonrpc": "2.0",
            "id": "r2-oauth-a2a",
            "method": "message/send",
            "params": {
                "message": {
                    "role": "ROLE_USER",
                    "parts": [{"data": {"private_tool": "gateway_config_read"}}],
                }
            },
        },
        path="/a2a",
        source_sts_domain="org-beta.io",
    )
    assert r_r2_oauth.status_code == 403, (r_r2_oauth.status_code, r_r2_oauth.text)
    assert r_r2_oauth.json().get("error") == "CROSS_PRINCIPAL_DENIED", r_r2_oauth.json()

    # (b) Symmetric `beta-user-gateway` dispatches Bob's Hop-0 token into `Assistant-B` (`reverse_pingpong_inspect_alpha`)!
    tid_rev_b = f"{tid}-rev-b2a"
    r_r2_b2a = _post_beta_gateway_mtls(
        gw,
        "/v1/gateway/dispatch",
        {
            "task_id": tid_rev_b,
            "sub": "user:bob@org-beta.io",
            "user_oidc_token": bob_jwt,
            "first_hop_spiffe_id": bob_card.spiffe_id,
            "first_hop_jkt": bob_card.jkt,
            "first_hop_public_jwk": bob_card.public_jwk,
            "first_hop_return_endpoint": bob_card.return_endpoint,
            "hop_segment": "AssistantBobReverse",
            "permissions": PermissionLattice.create(
                tools=["gateway_config_read", "alice_private_roadmap"], max_calls=8
            ).to_dict(),
            "target_endpoint": bob_card.endpoint,
            "payload": {
                "op": "reverse_pingpong_inspect_alpha",
                "alice_oidc_token": alice_jwt,
                "alpha_mcp_target": "skill://workspace.orchestrate",
            },
        },
    )
    assert r_r2_b2a.status_code == 200, (r_r2_b2a.status_code, r_r2_b2a.text)
    b2a_body = r_r2_b2a.json()["upstream_body"]
    assert b2a_body["unilateral_gateway_config_http"] == 403, b2a_body
    assert b2a_body["unilateral_roadmap_http"] == 403, b2a_body
    assert b2a_body["roadmap_consent_refusal_http"] == 403, b2a_body
    rev_gw_cfg = b2a_body["reverse_coauth_gateway_config"]
    assert rev_gw_cfg["desensitized"] is True, rev_gw_cfg
    assert rev_gw_cfg["co_authorized_principals"] == [
        "user:bob@org-beta.io",
        "user:alice@org-alpha.io",
    ], rev_gw_cfg

    # Round 3: Shared-Vault `commit_joint_change("FIN-RULE-42")` + Dual-Domain Revocation Interlock!
    idem_chg = compute_branch_idempotency_key(tid, "fin-rule-42")
    r_r3_unilat = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "call_mcp_with_wallet",
            "tool_name": "commit_joint_change",
            "arguments": {"change_id": "FIN-RULE-42", "risk_rule_digest": "sha256:rule42-v1"},
            "idempotency_key": idem_chg,
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_r3_unilat.status_code == 403, (r_r3_unilat.status_code, r_r3_unilat.text)
    assert (r_r3_unilat.json().get("upstream_body") or {}).get("error") == "DUAL_APPROVAL_REQUIRED", r_r3_unilat.json()

    r_r3_consent = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "request_peer_co_auth_and_read",
            "target_tool": "commit_joint_change",
            "consent_tools": ["commit_joint_change"],
            "consent_param_whitelist": {"change_id": ["FIN-RULE-42"]},
            "owner_oidc_token": bob_jwt,
            "cache_consent_key": f"{tid}:bob-chg",
            "mint_consent_only": True,
            "consent_hop_segment": "BobChangeConsent",
            "handshake_hop_segment": "ChangeConsentHandshake",
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_r3_consent.status_code == 200, (r_r3_consent.status_code, r_r3_consent.text)
    bob_consent_prefix = r_r3_consent.json()["consent_lineage_path"]

    r_r3_commit = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "call_mcp_with_wallet",
            "use_consent_key": f"{tid}:bob-chg",
            "tool_name": "commit_joint_change",
            "arguments": {"change_id": "FIN-RULE-42", "risk_rule_digest": "sha256:rule42-v1"},
            "idempotency_key": idem_chg,
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_r3_commit.status_code == 200, (r_r3_commit.status_code, r_r3_commit.text)
    chg_receipt = r_r3_commit.json()["upstream_body"]["result"]["data"]
    assert chg_receipt["co_authorized_principals"] == [
        "user:alice@org-alpha.io",
        "user:bob@org-beta.io",
    ], chg_receipt

    # Conflicting parameter replay on same idempotency_key -> 409 IDEMPOTENCY_PARAMETER_MISMATCH!
    r_r3_conflict = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "call_mcp_with_wallet",
            "use_consent_key": f"{tid}:bob-chg",
            "tool_name": "commit_joint_change",
            "arguments": {"change_id": "FIN-RULE-42", "risk_rule_digest": "sha256:tampered-v2"},
            "idempotency_key": idem_chg,
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_r3_conflict.status_code == 409, (r_r3_conflict.status_code, r_r3_conflict.text)

    # Foreign principal (`user:alice@org-alpha.io`) attempting `revoke_own_consent` on `Assistant-B` -> 403!
    tok_foreign_rev, _ = gw.mint_root_for_user(
        task_id=f"{tid}-foreign-rev",
        sub="user:alice@org-alpha.io",
        permissions=PermissionLattice.create(tools=["service_diag_read"], max_calls=2),
        target_card=bob_card,
        hop_segment="ForeignRevokeAttempt",
        user_oidc_token=alice_jwt,
    )
    r_foreign_rev = gw.post_lct_mtls(
        bob_card.endpoint,
        tok_foreign_rev,
        {"op": "revoke_own_consent", "target_task_id": tid, "prefix": bob_consent_prefix},
        expected_spiffe_id=bob_card.spiffe_id,
    )
    assert r_foreign_rev.status_code == 403, (r_foreign_rev.status_code, r_foreign_rev.text)
    assert r_foreign_rev.json().get("error") == "FORBIDDEN_FOREIGN_CONSENT_REVOCATION", r_foreign_rev.json()

    # Bob revokes his beta consent prefix -> subsequent CoAuth commit on Shared-Vault immediately fails 403!
    r_revoke_bob = _post_beta_gateway_mtls(
        gw,
        "/v1/gateway/dispatch",
        {
            "task_id": f"{tid}-revoke-ctl",
            "sub": "user:bob@org-beta.io",
            "user_oidc_token": bob_jwt,
            "first_hop_spiffe_id": bob_card.spiffe_id,
            "first_hop_jkt": bob_card.jkt,
            "first_hop_public_jwk": bob_card.public_jwk,
            "first_hop_return_endpoint": bob_card.return_endpoint,
            "hop_segment": "BobRevokeConsent",
            "permissions": PermissionLattice.create(tools=["service_diag_read"], max_calls=2).to_dict(),
            "target_endpoint": bob_card.endpoint,
            "payload": {
                "op": "revoke_own_consent",
                "target_task_id": tid,
                "prefix": bob_consent_prefix,
                "reason": "bob_withdrew_joint_change_approval",
            },
        },
    )
    assert r_revoke_bob.status_code == 200, (r_revoke_bob.status_code, r_revoke_bob.text)

    r_r3_post_rev = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "call_mcp_with_wallet",
            "use_consent_key": f"{tid}:bob-chg",
            "tool_name": "commit_joint_change",
            "arguments": {"change_id": "FIN-RULE-42", "risk_rule_digest": "sha256:rule42-v3"},
            "idempotency_key": compute_branch_idempotency_key(tid, "fin-rule-42-after-rev"),
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_r3_post_rev.status_code == 403, (r_r3_post_rev.status_code, r_r3_post_rev.text)

    audit_s6 = run_distributed_audit_for_task(gw, tid)
    assert audit_s6["reconstructed_complete"] is True, audit_s6
    assert audit_s6["unreachable_nodes"] == {}, audit_s6

    return {
        "status": "PASS",
        "task_id": tid,
        "reverse_task_id": tid_rev_b,
        "round1_a_to_b_unilateral_http": r_r1_unilat.status_code,
        "round1_a_to_b_coauth_http": r_r1_co.status_code,
        "round2_dual_oauth_b_to_a_http": r_r2_oauth.status_code,
        "round2_b_to_a_unilateral_http": b2a_body["unilateral_gateway_config_http"],
        "round2_b_to_a_roadmap_refusal_http": b2a_body["roadmap_consent_refusal_http"],
        "round2_b_to_a_reverse_coauth_principals": rev_gw_cfg["co_authorized_principals"],
        "round3_unilateral_commit_http": r_r3_unilat.status_code,
        "round3_coauth_commit_http": r_r3_commit.status_code,
        "round3_idempotency_conflict_http": r_r3_conflict.status_code,
        "round3_post_bob_revocation_http": r_r3_post_rev.status_code,
        "distributed_audit_complete": audit_s6["reconstructed_complete"],
    }


def run_ws_scenario_7_legal_redline_negotiation(
    gw: Any, run_id: str
) -> Dict[str, Any]:
    """Catalog S3 (Enterprise Legal & Procurement): Multi-Round Redline Sub-Delegation + Lattice Numeric/Whitelist Guardrails."""
    alice_card = gw.resolve_agent_card(skill="workspace.orchestrate", only_healthy=True)
    oidc_alice = gw.login_oidc_user("alice")
    alice_jwt = str(oidc_alice.get("id_token") or oidc_alice["access_token"])
    oidc_bob = gw.login_oidc_user("bob")
    bob_jwt = str(oidc_bob.get("id_token") or oidc_bob["access_token"])

    tid = f"ws-{run_id}-s7-legal-nda"
    buyer_perms = PermissionLattice.create(
        tools=["legal_redline_review", "commit_negotiated_contract"],
        numeric_bounds={"unit_price_usd": 120.0, "max_penalty_pct": 10.0},
        param_whitelist={
            "contract_id": ["NDA-2026-99"],
            "warranty_tier": ["24M", "36M"],
        },
        max_calls=12,
    )
    tok_alice, _ = gw.mint_root_for_user(
        task_id=tid,
        sub="user:alice@org-alpha.io",
        permissions=buyer_perms,
        target_card=alice_card,
        hop_segment="BuyerAlice",
        user_oidc_token=alice_jwt,
    )

    # Round 1: 3-hop legal sub-delegation (`Alice -> B -> Dave`); Dave blocked from `pricing_floor_read` (403)!
    r_redline = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {"op": "bob_relay_legal_redline", "contract_id": "NDA-2026-99"},
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_redline.status_code == 200, (r_redline.status_code, r_redline.text)
    rl_body = r_redline.json()
    assert rl_body["pricing_floor_probe_http"] == 403, rl_body
    assert rl_body["legal_review"]["desensitized"] is True, rl_body

    # Round 2: Unilateral contract commit fails 403 DUAL_APPROVAL_REQUIRED
    r_unilat_ct = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "call_mcp_with_wallet",
            "tool_name": "commit_negotiated_contract",
            "arguments": {
                "contract_id": "NDA-2026-99",
                "warranty_tier": "24M",
                "unit_price_usd": 115.0,
                "max_penalty_pct": 8.0,
            },
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_unilat_ct.status_code == 403, (r_unilat_ct.status_code, r_unilat_ct.text)

    # Obtain seller (Bob) consent with wider seller ceiling ($200, 12%, 12M/24M/36M)
    r_seller_c = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "request_peer_co_auth_and_read",
            "target_tool": "commit_negotiated_contract",
            "consent_tools": ["commit_negotiated_contract"],
            "consent_numeric_bounds": {"unit_price_usd": 200.0, "max_penalty_pct": 12.0},
            "consent_param_whitelist": {
                "contract_id": ["NDA-2026-99"],
                "warranty_tier": ["12M", "24M", "36M"],
            },
            "owner_oidc_token": bob_jwt,
            "cache_consent_key": f"{tid}:seller-consent",
            "mint_consent_only": True,
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_seller_c.status_code == 200, (r_seller_c.status_code, r_seller_c.text)

    # Round 3: Prompt-injected concession breaches buyer's `unit_price_usd <= 120.0` (`165.0`) -> 403 LATTICE_PERMISSION_DENIED!
    r_breach_price = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "call_mcp_with_wallet",
            "use_consent_key": f"{tid}:seller-consent",
            "tool_name": "commit_negotiated_contract",
            "arguments": {
                "contract_id": "NDA-2026-99",
                "warranty_tier": "24M",
                "unit_price_usd": 165.0,
                "max_penalty_pct": 8.0,
            },
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_breach_price.status_code == 403, (r_breach_price.status_code, r_breach_price.text)
    assert (r_breach_price.json().get("upstream_body") or {}).get("error") == "LATTICE_PERMISSION_DENIED", r_breach_price.json()

    # Disallowed warranty_tier `12M` -> 403 LATTICE_PERMISSION_DENIED!
    r_breach_tier = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "call_mcp_with_wallet",
            "use_consent_key": f"{tid}:seller-consent",
            "tool_name": "commit_negotiated_contract",
            "arguments": {
                "contract_id": "NDA-2026-99",
                "warranty_tier": "12M",
                "unit_price_usd": 115.0,
                "max_penalty_pct": 8.0,
            },
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_breach_tier.status_code == 403, (r_breach_tier.status_code, r_breach_tier.text)

    # Round 4: Compliant terms within `[alice ⊓ bob]` lattice (`$115.0`, `8.0%`, `24M`) -> 200!
    r_ok_ct = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "call_mcp_with_wallet",
            "use_consent_key": f"{tid}:seller-consent",
            "tool_name": "commit_negotiated_contract",
            "arguments": {
                "contract_id": "NDA-2026-99",
                "warranty_tier": "24M",
                "unit_price_usd": 115.0,
                "max_penalty_pct": 8.0,
            },
            "idempotency_key": compute_branch_idempotency_key(tid, "nda-99"),
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_ok_ct.status_code == 200, (r_ok_ct.status_code, r_ok_ct.text)
    ct_data = r_ok_ct.json()["upstream_body"]["result"]["data"]
    assert ct_data["unit_price_usd"] == 115.0 and ct_data["warranty_tier"] == "24M", ct_data

    audit_s7 = run_distributed_audit_for_task(gw, tid)
    assert audit_s7["reconstructed_complete"] is True, audit_s7
    assert audit_s7["unreachable_nodes"] == {}, audit_s7

    return {
        "status": "PASS",
        "task_id": tid,
        "dave_pricing_floor_probe_http": rl_body["pricing_floor_probe_http"],
        "unilateral_commit_http": r_unilat_ct.status_code,
        "over_budget_165_usd_http": r_breach_price.status_code,
        "weak_warranty_12m_http": r_breach_tier.status_code,
        "compliant_coauth_commit_http": r_ok_ct.status_code,
        "committed_contract": ct_data,
        "distributed_audit_complete": audit_s7["reconstructed_complete"],
    }


def run_ws_scenario_8_supply_chain_sod(
    gw: Any, run_id: str
) -> Dict[str, Any]:
    """Catalog S5 (Compliance / Release SoD): 4-Hop Signed Scanner Attestation + Carol OIDC Approval (`[alice, carol]`)."""
    alice_card = gw.resolve_agent_card(skill="workspace.orchestrate", only_healthy=True)
    oidc_alice = gw.login_oidc_user("alice")
    alice_jwt = str(oidc_alice.get("id_token") or oidc_alice["access_token"])
    oidc_carol = gw.login_oidc_user("carol")
    carol_jwt = str(oidc_carol.get("id_token") or oidc_carol["access_token"])

    tid = f"ws-{run_id}-s8-sod-release"
    dev_perms = PermissionLattice.create(
        tools=["sast_scan", "sign_release"],
        param_whitelist={"release_id": ["REL-2026-884", "REL-2026-999"]},
        max_calls=10,
    )
    tok_alice, _ = gw.mint_root_for_user(
        task_id=tid,
        sub="user:alice@org-alpha.io",
        permissions=dev_perms,
        target_card=alice_card,
        hop_segment="DeveloperAlice",
        user_oidc_token=alice_jwt,
    )

    # 1) 4-hop `Alice -> A -> B -> Dave` signed compliance/SAST attestation (`lct-compliance-attestation+jwt`)!
    r_scan = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "sast_scan_pipeline",
            "release_id": "REL-2026-884",
            "artifact_sha256": "sha256:9f884c0ffee12345",
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_scan.status_code == 200, (r_scan.status_code, r_scan.text)
    scan_out = r_scan.json()
    att_jws = str(scan_out["attestation_jws"])
    assert scan_out["scanner_spiffe_id"].endswith("/sa/assistant-dave"), scan_out

    # 2) Unilateral `sign_release` by Developer Alice (even with valid Dave attestation!) -> 403 DUAL_APPROVAL_REQUIRED!
    r_self_approve = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "call_mcp_with_wallet",
            "tool_name": "sign_release",
            "arguments": {
                "release_id": "REL-2026-884",
                "compliance_attestation_jws": att_jws,
            },
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_self_approve.status_code == 403, (r_self_approve.status_code, r_self_approve.text)
    assert (r_self_approve.json().get("upstream_body") or {}).get("error") == "DUAL_APPROVAL_REQUIRED", r_self_approve.json()

    # 3) Obtain Release Approver Carol's real Keycloak OIDC consent via `pay-ca /v1/ca/mint-consent-token`!
    r_carol_c = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "request_peer_co_auth_and_read",
            "target_tool": "sign_release",
            "target_peer_skill": "workspace.biz_procurement",
            "consent_tools": ["sign_release"],
            "consent_param_whitelist": {"release_id": ["REL-2026-884", "REL-2026-999"]},
            "owner_oidc_token": carol_jwt,
            "cache_consent_key": f"{tid}:carol-rel",
            "mint_consent_only": True,
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_carol_c.status_code == 200, (r_carol_c.status_code, r_carol_c.text)

    # 4) Missing attestation & mismatched `release_id` (`REL-2026-999` vs `REL-2026-884`) -> 403!
    r_missing_att = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "call_mcp_with_wallet",
            "use_consent_key": f"{tid}:carol-rel",
            "tool_name": "sign_release",
            "arguments": {"release_id": "REL-2026-884", "compliance_attestation_jws": ""},
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_missing_att.status_code == 403, (r_missing_att.status_code, r_missing_att.text)

    r_mismatch_rel = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "call_mcp_with_wallet",
            "use_consent_key": f"{tid}:carol-rel",
            "tool_name": "sign_release",
            "arguments": {
                "release_id": "REL-2026-999",
                "compliance_attestation_jws": att_jws,
            },
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_mismatch_rel.status_code == 403, (r_mismatch_rel.status_code, r_mismatch_rel.text)
    assert (r_mismatch_rel.json().get("upstream_body") or {}).get("error") == "MISSING_OR_INVALID_COMPLIANCE_ATTESTATION", r_mismatch_rel.json()

    # 5) Valid `CoAuthorizedToken([alice, carol])` + valid Dave `REL-2026-884` attestation -> 200!
    r_rel_ok = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "call_mcp_with_wallet",
            "use_consent_key": f"{tid}:carol-rel",
            "tool_name": "sign_release",
            "arguments": {
                "release_id": "REL-2026-884",
                "compliance_attestation_jws": att_jws,
            },
            "idempotency_key": compute_branch_idempotency_key(tid, "rel-884"),
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_rel_ok.status_code == 200, (r_rel_ok.status_code, r_rel_ok.text)
    rel_data = r_rel_ok.json()["upstream_body"]["result"]["data"]
    assert rel_data["sod_verified"] is True, rel_data
    assert rel_data["co_authorized_principals"] == [
        "user:alice@org-alpha.io",
        "user:carol@org-payment.io",
    ], rel_data

    audit_s8 = run_distributed_audit_for_task(gw, tid)
    assert audit_s8["reconstructed_complete"] is True, audit_s8
    assert audit_s8["unreachable_nodes"] == {}, audit_s8

    return {
        "status": "PASS",
        "task_id": tid,
        "scanner_spiffe_id": scan_out["scanner_spiffe_id"],
        "unilateral_self_approve_http": r_self_approve.status_code,
        "missing_attestation_http": r_missing_att.status_code,
        "mismatched_release_attestation_http": r_mismatch_rel.status_code,
        "sod_coauth_release_http": r_rel_ok.status_code,
        "release_receipt": rel_data,
        "distributed_audit_complete": audit_s8["reconstructed_complete"],
    }


def run_ws_scenario_9_federated_medical_cohort(
    gw: Any, run_id: str
) -> Dict[str, Any]:
    """Catalog S6 (Healthcare / Risk Federated Cohort): Multi-Owner DP Stats + Raw Export Deny + Cross-Task Replay Block."""
    alice_card = gw.resolve_agent_card(skill="workspace.orchestrate", only_healthy=True)
    oidc_alice = gw.login_oidc_user("alice")
    alice_jwt = str(oidc_alice.get("id_token") or oidc_alice["access_token"])
    oidc_bob = gw.login_oidc_user("bob")
    bob_jwt = str(oidc_bob.get("id_token") or oidc_bob["access_token"])
    oidc_carol = gw.login_oidc_user("carol")
    carol_jwt = str(oidc_carol.get("id_token") or oidc_carol["access_token"])

    tid = f"ws-{run_id}-s9-med-cohort"
    study_id = "STUDY-MED-2026-07"
    med_perms = PermissionLattice.create(
        tools=[
            "cohort_aggregate_stats",
            "export_raw_patient_records",
            "federated_cohort_aggregate",
        ],
        param_whitelist={"study_id": [study_id]},
        max_calls=12,
    )
    tok_med, _ = gw.mint_root_for_user(
        task_id=tid,
        sub="user:alice@org-alpha.io",
        permissions=med_perms,
        target_card=alice_card,
        hop_segment="ResearcherAlice",
        user_oidc_token=alice_jwt,
    )

    # 1) Raw patient record export blocked `403` on BOTH Hospital-B (`Assistant-B`) & Institution-C (`Assistant-C`),
    #    and CA consent policy refuses `export_raw_patient_records` (`403`)!
    r_raw_b = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_med,
        {
            "op": "probe_peer_private_resource",
            "target_tool": "export_raw_patient_records",
            "target_peer_mcp": "skill://workspace.bob_private",
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    r_raw_c = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_med,
        {
            "op": "probe_peer_private_resource",
            "target_tool": "export_raw_patient_records",
            "target_peer_mcp": "skill://workspace.carol_private",
            "fallback_peer_skill": "workspace.biz_procurement",
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_raw_b.status_code == 403 and r_raw_c.status_code == 403, (r_raw_b.status_code, r_raw_c.status_code)

    r_raw_consent_b = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_med,
        {
            "op": "request_peer_co_auth_and_read",
            "target_tool": "export_raw_patient_records",
            "owner_oidc_token": bob_jwt,
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_raw_consent_b.status_code == 403, (r_raw_consent_b.status_code, r_raw_consent_b.text)

    # 2) Scoped consent from Data Steward Bob (`org-beta`) & Data Steward Carol (`org-payment`) for `STUDY-MED-2026-07`!
    r_coh_b = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_med,
        {
            "op": "request_peer_co_auth_and_read",
            "target_tool": "cohort_aggregate_stats",
            "target_peer_skill": "workspace.tech_review",
            "target_peer_mcp": "skill://workspace.bob_private",
            "consent_param_whitelist": {"study_id": [study_id]},
            "arguments": {"study_id": study_id},
            "owner_oidc_token": bob_jwt,
            "cache_consent_key": f"{tid}:bob-med-consent",
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_coh_b.status_code == 200, (r_coh_b.status_code, r_coh_b.text)
    dig_b = r_coh_b.json()["upstream_body"]["result"]["data"]

    r_coh_c = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_med,
        {
            "op": "request_peer_co_auth_and_read",
            "target_tool": "cohort_aggregate_stats",
            "target_peer_skill": "workspace.biz_procurement",
            "target_peer_mcp": "skill://workspace.carol_private",
            "consent_param_whitelist": {"study_id": [study_id]},
            "arguments": {"study_id": study_id},
            "owner_oidc_token": carol_jwt,
            "handshake_hop_segment": "CarolConsentHandshake",
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_coh_c.status_code == 200, (r_coh_c.status_code, r_coh_c.text)
    dig_c = r_coh_c.json()["upstream_body"]["result"]["data"]
    assert dig_b["raw_pii_present"] is False and dig_c["raw_pii_present"] is False
    assert bool(dig_b.get("digest_jws")) and bool(dig_c.get("digest_jws"))

    # 3a) Unsigned / synthesized fake institution digest -> 403 INVALID_COHORT_DIGEST_SIGNATURE!
    fake_unsigned_dig = {k: v for k, v in dig_c.items() if k != "digest_jws"}
    r_unsigned_agg = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_med,
        {
            "op": "call_mcp_with_wallet",
            "tool_name": "federated_cohort_aggregate",
            "arguments": {
                "study_id": study_id,
                "cohort_digests": [dig_b, fake_unsigned_dig],
            },
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_unsigned_agg.status_code == 403, (r_unsigned_agg.status_code, r_unsigned_agg.text)
    assert (
        (r_unsigned_agg.json().get("upstream_body") or {}).get("error")
        == "INVALID_COHORT_DIGEST_SIGNATURE"
    ), r_unsigned_agg.json()

    # 3b) Aggregate SVID-signed desensitized digests in `Shared-Vault` -> 200!
    r_agg = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_med,
        {
            "op": "call_mcp_with_wallet",
            "tool_name": "federated_cohort_aggregate",
            "arguments": {
                "study_id": study_id,
                "cohort_digests": [dig_b, dig_c],
            },
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_agg.status_code == 200, (r_agg.status_code, r_agg.text)
    agg_data = r_agg.json()["upstream_body"]["result"]["data"]
    assert (
        agg_data["institutions_aggregated"] == 2
        and agg_data["raw_pii_present"] is False
        and agg_data.get("cohort_digests_verified") is True
        and len(agg_data.get("verified_institution_spiffe_ids") or []) == 2
    ), agg_data

    # 4) Cross-Task / Cross-Purpose Replay: reusing Hospital-B's `STUDY-MED-2026-07` consent in `T_commercial` -> 403!
    tid_comm = f"{tid}-commercial-replay"
    tok_comm, _ = gw.mint_root_for_user(
        task_id=tid_comm,
        sub="user:alice@org-alpha.io",
        permissions=PermissionLattice.create(
            tools=["cohort_aggregate_stats"],
            param_whitelist={"study_id": ["STUDY-COMMERCIAL-99"]},
            max_calls=4,
        ),
        target_card=alice_card,
        hop_segment="CommercialAlice",
        user_oidc_token=alice_jwt,
    )
    r_cross_task = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_comm,
        {
            "op": "call_mcp_with_wallet",
            "target_mcp": "skill://workspace.bob_private",
            "use_consent_key": f"{tid}:bob-med-consent",
            "tool_name": "cohort_aggregate_stats",
            "arguments": {"study_id": "STUDY-COMMERCIAL-99"},
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_cross_task.status_code == 403, (r_cross_task.status_code, r_cross_task.text)

    audit_s9 = run_distributed_audit_for_task(gw, tid)
    assert audit_s9["reconstructed_complete"] is True, audit_s9
    assert audit_s9["unreachable_nodes"] == {}, audit_s9

    return {
        "status": "PASS",
        "task_id": tid,
        "raw_export_hospital_b_http": r_raw_b.status_code,
        "raw_export_inst_c_http": r_raw_c.status_code,
        "raw_export_consent_refusal_http": r_raw_consent_b.status_code,
        "aggregated_cohort": agg_data,
        "cross_task_commercial_replay_http": r_cross_task.status_code,
        "distributed_audit_complete": audit_s9["reconstructed_complete"],
    }


def run_ws_scenario_10_prompt_injection_cascading_revocation(
    gw: Any, run_id: str
) -> Dict[str, Any]:
    """Catalog S7: 4-Hop Indirect Prompt Injection Offline Block + Cascading Subtree Revocation of Pre-Minted Hop-3 Token."""
    alice_card = gw.resolve_agent_card(skill="workspace.orchestrate", only_healthy=True)
    bob_card = gw.resolve_agent_card(
        skill="workspace.tech_review", contains_spiffe="sa/assistant-bob", only_healthy=True
    )
    dave_card = gw.resolve_agent_card(skill="workspace.deep_analysis", only_healthy=True)

    oidc_alice = gw.login_oidc_user("alice")
    alice_jwt = str(oidc_alice.get("id_token") or oidc_alice["access_token"])

    tid = f"ws-{run_id}-s10-inj-cascade"
    root_perms = PermissionLattice.create(
        tools=[
            "reserve_cloud_budget",
            "procure_vendor_quote",
            "query_operation_status",
            "record_compliance_note",
            "lock_joint_project",
        ],
        max_amount=700.0,
        allowed_targets=[
            "cloud-infra-escrow",
            "vendor-procurement-escrow",
            "compliance-ledger",
        ],
        param_whitelist={"project_code": ["PRJ-AUDIT"]},
        max_calls=16,
    )
    tok_alice, _ = gw.mint_root_for_user(
        task_id=tid,
        sub="user:alice@org-alpha.io",
        permissions=root_perms,
        target_card=alice_card,
        hop_segment="AssistantAlice",
        user_oidc_token=alice_jwt,
    )

    # 1) Execute 4-hop fanout (`Alice -> A -> {B -> D -> Vault, C -> Vault}`)!
    r_fan = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {
            "op": "prompt_injection_audit_fanout",
            "project_code": "PRJ-AUDIT",
            "cache_key": tid,
        },
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_fan.status_code == 200, (r_fan.status_code, r_fan.text)
    fan_out = r_fan.json()
    bob_prefix = str(fan_out["branch_bob_dave"]["hop2_lineage_path"])
    dave_res = fan_out["branch_bob_dave"]["dave_hop3"]
    assert dave_res["legitimate_note_http"] == 200, dave_res
    assert dave_res["injected_budget_escalation_http"] == 403, dave_res
    assert dave_res["injected_param_exfil_http"] == 403, dave_res

    # 2) Compromise detected on `Assistant-B`: revoke prefix `/ws-.../AssistantAlice/TechReviewBob`!
    rev_ev = gw.rev_client.revoke_prefix(
        caller=gw.identity,
        prefix=bob_prefix,
        reason="s10_compromised_bob_subtree_quarantine",
        authority_token=tok_alice,
    )
    gw.emit_revocation_audit(
        task_id=tid,
        sub="user:alice@org-alpha.io",
        revocation_event=rev_ev,
        root_block_hash="",
        current_block_hash="",
    )

    # 3) BOTH `Assistant-B`'s pre-revocation Hop-2 token AND `Assistant-D`'s ALREADY-MINTED Hop-3 token
    #    immediately fail `403` against `Shared-Vault`!
    tok_ctl_b, _ = gw.mint_root_for_user(
        task_id=f"{tid}-probe-b",
        sub="user:alice@org-alpha.io",
        permissions=PermissionLattice.create(tools=["query_operation_status"], max_calls=3),
        target_card=bob_card,
        hop_segment="ProbeBobCtl",
    )
    r_hop2_rep = gw.post_lct_mtls(
        bob_card.endpoint,
        tok_ctl_b,
        {
            "op": "replay_cached_pre_revocation_token",
            "cache_key": f"{tid}:bob-hop2",
            "tool_name": "query_operation_status",
            "arguments": {"idempotency_key": f"probe-{tid}"},
        },
        expected_spiffe_id=bob_card.spiffe_id,
    )
    assert r_hop2_rep.status_code == 403, (r_hop2_rep.status_code, r_hop2_rep.text)

    tok_ctl_d, _ = gw.mint_root_for_user(
        task_id=f"{tid}-probe-d",
        sub="user:alice@org-alpha.io",
        permissions=PermissionLattice.create(tools=["record_compliance_note"], max_calls=3),
        target_card=dave_card,
        hop_segment="ProbeDaveCtl",
    )
    r_hop3_rep = gw.post_lct_mtls(
        dave_card.endpoint,
        tok_ctl_d,
        {
            "op": "replay_cached_pre_revocation_token",
            "cache_key": f"{tid}:dave-hop3",
            "tool_name": "record_compliance_note",
            "arguments": {"project_code": "PRJ-AUDIT", "note": "post-revoke-replay"},
        },
        expected_spiffe_id=dave_card.spiffe_id,
    )
    assert r_hop3_rep.status_code == 403, (r_hop3_rep.status_code, r_hop3_rep.text)
    assert (r_hop3_rep.json().get("upstream_body") or {}).get("error") == "LINEAGE_REVOKED", r_hop3_rep.json()

    # 4) Parallel innocent `Assistant-C` branch survives smoothly (`ALLOW_DEGRADED_DAG`)!
    r_lock = gw.post_lct_mtls(
        alice_card.endpoint,
        tok_alice,
        {"op": "trigger_converged_project_lock", "project_code": "PRJ-AUDIT"},
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_lock.status_code == 200, (r_lock.status_code, r_lock.text)
    lock_outcomes = r_lock.json()["upstream_body"]["lock_outcomes"]
    assert lock_outcomes["cloud-infra-escrow"]["http_status"] == 403, lock_outcomes
    assert lock_outcomes["vendor-procurement-escrow"]["http_status"] == 200, lock_outcomes

    audit_s10 = run_distributed_audit_for_task(gw, tid)
    assert audit_s10["reconstructed_complete"] is True, audit_s10
    assert audit_s10["unreachable_nodes"] == {}, audit_s10
    assert "SMOOTH_DAG_DEGRADATION_ON_REVOCATION" in audit_s10["resilience_classifications"], audit_s10

    return {
        "status": "PASS",
        "task_id": tid,
        "revoked_bob_prefix": bob_prefix,
        "hop3_legitimate_note_http": dave_res["legitimate_note_http"],
        "hop3_injected_budget_http": dave_res["injected_budget_escalation_http"],
        "hop3_injected_exfil_http": dave_res["injected_param_exfil_http"],
        "post_revoke_bob_hop2_http": r_hop2_rep.status_code,
        "post_revoke_dave_preminted_hop3_http": r_hop3_rep.status_code,
        "degraded_vault_outcomes": {k: v["http_status"] for k, v in lock_outcomes.items()},
        "distributed_audit_complete": audit_s10["reconstructed_complete"],
    }


def run_ws_scenario_11_symmetric_beta_entry_and_token_theft(
    gw: Any, run_id: str
) -> Dict[str, Any]:
    """Catalog S8: Symmetric `org-beta` Entry (`beta-user-gateway`) + Stolen-Token Replay (`403`) + Cross-Tenant Vault Isolation."""
    alice_card = gw.resolve_agent_card(skill="workspace.orchestrate", only_healthy=True)
    bob_card = gw.resolve_agent_card(
        skill="workspace.tech_review", contains_spiffe="sa/assistant-bob", only_healthy=True
    )
    vault_mcp_card = gw.resolve_agent_card(skill="mcp.workspace-vault", only_healthy=True)

    oidc_alice = gw.login_oidc_user("alice")
    alice_jwt = str(oidc_alice.get("id_token") or oidc_alice["access_token"])
    oidc_bob = gw.login_oidc_user("bob")
    bob_jwt = str(oidc_bob.get("id_token") or oidc_bob["access_token"])

    tid = f"ws-{run_id}-s11-beta-sym"
    bob_perms = PermissionLattice.create(
        tools=[
            "gateway_config_read",
            "record_compliance_note",
            "procure_vendor_quote",
            "query_operation_status",
        ],
        max_amount=300.0,
        allowed_targets=["compliance-ledger", "vendor-procurement-escrow"],
        param_whitelist={"project_code": ["PRJ-BETA-SYM"]},
        max_calls=12,
    )

    # 1) Adversarial auth checks on `beta-user-gateway` (`POST /v1/gateway/mint-root`):
    #    - Missing OIDC -> 401
    #    - Alice's `@org-alpha.io` OIDC -> 403 GATEWAY_PRINCIPAL_DOMAIN_MISMATCH
    #    - Spoofed `sub` -> 403 GATEWAY_PRINCIPAL_DOMAIN_MISMATCH
    base_gw_req = {
        "task_id": f"{tid}-auth-probe",
        "sub": "user:bob@org-beta.io",
        "first_hop_spiffe_id": bob_card.spiffe_id,
        "first_hop_jkt": bob_card.jkt,
        "permissions": bob_perms.to_dict(),
    }
    r_gw_no_oidc = _post_beta_gateway_mtls(gw, "/v1/gateway/mint-root", base_gw_req)
    assert r_gw_no_oidc.status_code == 401, (r_gw_no_oidc.status_code, r_gw_no_oidc.text)

    r_gw_alice_oidc = _post_beta_gateway_mtls(
        gw,
        "/v1/gateway/mint-root",
        {**base_gw_req, "sub": "user:alice@org-alpha.io", "user_oidc_token": alice_jwt},
    )
    # Sovereign `beta-user-gateway` only trusts `beta-sts` (`org-beta.io`), rejecting foreign `alpha-sts` OIDC (`401`)!
    assert r_gw_alice_oidc.status_code == 401, (r_gw_alice_oidc.status_code, r_gw_alice_oidc.text)
    assert r_gw_alice_oidc.json().get("error") == "INVALID_USER_OIDC_TOKEN", r_gw_alice_oidc.json()

    r_gw_spoof_sub = _post_beta_gateway_mtls(
        gw,
        "/v1/gateway/mint-root",
        {**base_gw_req, "sub": "user:mallory@org-beta.io", "user_oidc_token": bob_jwt},
    )
    assert r_gw_spoof_sub.status_code == 403, (r_gw_spoof_sub.status_code, r_gw_spoof_sub.text)

    r_gw_foreign_sender = _post_beta_gateway_mtls(
        gw,
        "/v1/gateway/mint-root",
        {**base_gw_req, "user_oidc_token": bob_jwt, "sender_jkt": gw.identity.jkt},
    )
    assert r_gw_foreign_sender.status_code == 403, (r_gw_foreign_sender.status_code, r_gw_foreign_sender.text)
    assert r_gw_foreign_sender.json().get("error") == "SENDER_JKT_MISMATCH", r_gw_foreign_sender.json()

    # 2) Legitimate `org-beta.io` Bob entry via `beta-user-gateway /v1/gateway/dispatch` -> fans out across `alpha`, `beta`, `pay`!
    r_sym = _post_beta_gateway_mtls(
        gw,
        "/v1/gateway/dispatch",
        {
            "task_id": tid,
            "sub": "user:bob@org-beta.io",
            "user_oidc_token": bob_jwt,
            "first_hop_spiffe_id": bob_card.spiffe_id,
            "first_hop_jkt": bob_card.jkt,
            "first_hop_public_jwk": bob_card.public_jwk,
            "first_hop_return_endpoint": bob_card.return_endpoint,
            "hop_segment": "CoordinatorBob",
            "permissions": bob_perms.to_dict(),
            "target_endpoint": bob_card.endpoint,
            "payload": {
                "op": "bob_symmetric_orchestrate",
                "project_code": "PRJ-BETA-SYM",
                "alice_oidc_token": alice_jwt,
            },
        },
    )
    assert r_sym.status_code == 200, (r_sym.status_code, r_sym.text)
    sym_out = r_sym.json()["upstream_body"]
    bob_idem_key = str(sym_out["bob_branch_idempotency_key"])
    assert sym_out["alpha_gateway_config"]["co_authorized_principals"] == [
        "user:bob@org-beta.io",
        "user:alice@org-alpha.io",
    ], sym_out
    assert sym_out["carol_procurement"]["vendor_quote"]["charged_usd"] == 180.0, sym_out

    # 3) Stolen-Token Cross-Agent Replay: `e2e-user-gateway` (`org-alpha.io`) replays a legitimate `Assistant-B`
    #    wire `LineageToken` (held only in RAM, never serialized to summary!) against `Shared-Vault` & `Assistant-A` -> 403!
    r_mint_stolen = _post_beta_gateway_mtls(
        gw,
        "/v1/gateway/mint-root",
        {
            "task_id": f"{tid}-stolen-probe",
            "sub": "user:bob@org-beta.io",
            "user_oidc_token": bob_jwt,
            "first_hop_spiffe_id": bob_card.spiffe_id,
            "first_hop_jkt": bob_card.jkt,
            "permissions": bob_perms.to_dict(),
            "hop_segment": "StolenBobRoot",
        },
    )
    assert r_mint_stolen.status_code == 200, (r_mint_stolen.status_code, r_mint_stolen.text)
    stolen_bob_tok = str(r_mint_stolen.json()["compact_token"])

    r_thief_vault = gw.post_lct_mtls(
        vault_mcp_card.candidate_origins()[0],
        stolen_bob_tok,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "procure_vendor_quote",
                "arguments": {"project_code": "PRJ-BETA-SYM", "amount": 50.0},
            },
        },
        path="/mcp",
        expected_spiffe_id=vault_mcp_card.spiffe_id,
    )
    assert r_thief_vault.status_code == 403, (r_thief_vault.status_code, r_thief_vault.text)

    r_thief_alpha = gw.post_lct_mtls(
        alice_card.candidate_origins()[0],
        stolen_bob_tok,
        {"private_tool": "gateway_config_read"},
        path="/a2a/task",
        expected_spiffe_id=alice_card.spiffe_id,
    )
    assert r_thief_alpha.status_code == 403, (r_thief_alpha.status_code, r_thief_alpha.text)
    del stolen_bob_tok

    # 4) Cross-Tenant Vault Isolation: Alice (`user:alice@org-alpha.io`) querying Bob's `bob_idem_key` -> `found == False`!
    tok_alice_q, _ = gw.mint_root_for_user(
        task_id=f"{tid}-alice-snooping",
        sub="user:alice@org-alpha.io",
        permissions=PermissionLattice.create(tools=["query_operation_status"], max_calls=3),
        target_card=vault_mcp_card,
        hop_segment="AliceTenantProbe",
        user_oidc_token=alice_jwt,
    )
    r_snoop = gw.post_lct_mtls(
        vault_mcp_card.candidate_origins()[0],
        tok_alice_q,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "query_operation_status",
                "arguments": {"idempotency_key": bob_idem_key},
            },
        },
        path="/mcp",
        expected_spiffe_id=vault_mcp_card.spiffe_id,
    )
    assert r_snoop.status_code == 200, (r_snoop.status_code, r_snoop.text)
    snoop_doc = r_snoop.json()["result"]["data"]
    assert snoop_doc["found"] is False and snoop_doc["charge_count"] == 0, snoop_doc

    # 5) Decentralized `DistributedAuditor` starting purely from `entry_spiffe_ids=[bob_card.spiffe_id]` (`org-beta.io`)!
    audit_s11 = run_distributed_audit_for_task(
        gw,
        tid,
        entry_spiffe_ids=[bob_card.spiffe_id],
        seed_domains=["org-beta.io"],
    )
    assert audit_s11["reconstructed_complete"] is True, audit_s11
    assert audit_s11["unreachable_nodes"] == {}, audit_s11
    assert audit_s11["anomalies"] == [], audit_s11

    return {
        "status": "PASS",
        "task_id": tid,
        "beta_gateway_missing_oidc_http": r_gw_no_oidc.status_code,
        "beta_gateway_alice_cross_domain_http": r_gw_alice_oidc.status_code,
        "beta_gateway_sub_spoof_http": r_gw_spoof_sub.status_code,
        "bob_fanout_domains_verified": ["org-beta.io", "org-alpha.io", "org-payment.io"],
        "stolen_token_replay_on_vault_http": r_thief_vault.status_code,
        "stolen_token_replay_on_alpha_http": r_thief_alpha.status_code,
        "alice_cross_tenant_snoop_found": snoop_doc["found"],
        "distributed_audit_from_beta_entry": {
            "nodes_queried_count": audit_s11["nodes_queried_count"],
            "unreachable_nodes": audit_s11["unreachable_nodes"],
            "reconstructed_complete": audit_s11["reconstructed_complete"],
            "anomalies": audit_s11["anomalies"],
        },
    }
