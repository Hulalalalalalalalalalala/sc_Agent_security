# Milestone 9 (Platform v2) Independent Code, Cryptographic & Rehearsal QA Audit Report

- **Reviewer**: `k8s-qa-reviewer` (Independent Read-Only QA & Compliance Session)
- **Date**: 2026-11-25
- **Target Scope**: Milestone 9 — Decentralized Peer-to-Peer Workspace Assistant Platform (`Platform v2`)
- **Automated Suite**: `92/92` tests PASS in `62.02s` (`0` warnings under `-W default`)
- **QA Reproduction Suite**: [qa_milestone9_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone9_review.py) (`7/7` deterministic checks in `0.71s`, `0` warnings)
- **Verdict**: **`NEEDS_FIX`** (`1` Critical, `4` High, `1` Medium security/compliance findings; block public GitHub push until remediated and re-verified)

---

## 1. Mandatory QA Checklist Summary

| # | Checklist Boundary | Status | Summary |
| :--- | :--- | :--- | :--- |
| **1** | Automated Suite & Warnings (`run_all`) | **PASS** | `92/92` tests succeeded + benchmarks saved in `62.02s`, `0` warnings. |
| **2** | `CoAuthorizedToken` (`lctco1.`) & Dual-Principal Consent Security | **NEEDS_FIX** | Envelope cryptography, mixed-`sub` rejection on `MultiParentToken`, lattice intersection `P_req ⊓ P_owner`, DPoP + mTLS binding, and dual-domain revocation anchoring all **PASS**; however, `POST /v1/ca/mint-consent-token` is missing, peer `request_co_auth_consent` mints Bob's `RootBlock` with `owner_oidc_token=None`, and default `DELEGATION_MODE=dual` OAuth Bearer bypasses `resource_owner_sub` at `LineageSidecar` (**`[HIGH-M9-03]`**). |
| **3** | `TaskCheckpoint` & `ContinuationToken` Anti-Replay & Budget Deduction | **NEEDS_FIX** | `WorkloadIdentityRenewer` SVID renewal independence from `RootBlock.exp` **PASSES**; however, `/v1/ca/mint-continuation-token` lacks checkpoint/prior-root replay tracking (**`[CRITICAL-M9-01]`**), fails open when `prior_root_block_hash` is absent from `local_store` & fails to bind `ckpt.signer_spiffe_id` to `prior_root.delegate_spiffe_id` (**`[HIGH-M9-01]`**), and `LeafVerifier` lets a **revoked** `ContinuationToken` resurrect an expired pre-checkpoint branch (**`[HIGH-M9-02]`**). |
| **4** | Branch Idempotency & Cross-Tenant Status Lookup Security | **NEEDS_FIX** | `IdempotencyLedger` memory bound (`4,096` LRU), `(sub, key)` tenant isolation, and cross-tenant `query_operation_status` isolation **PASS**; however, `execute_once` does not verify `(operation, target, project_code, amount_usd)` equality on replay (**`[MEDIUM-M9-01]`**). |
| **5** | Decentralized `LocalAuditStore`, `DistributedAuditor`, & Untrusted Yellow Pages | **NEEDS_FIX** | `GET /v1/audit/local` JWS auth/freshness/JTI-replay/omitted-`task_id` guards and `AgentDirectoryService(registry_mode="centralized")` verification **PASS**; however, `DistributedAuditor` falsely reports `reconstructed_complete=True` when downstream participants are offline in `unreachable_nodes` and lacks `max_depth`, HTTP response size/entry bounds, and RFC1918 + mTLS 1.3 URL validation (**`[HIGH-M9-04]`**). |
| **6** | LLM `WorkspaceIntentRouter` Safety, `lctco1.` Redaction, Scale & Pre-Push Hygiene | **PASS** | `WorkspaceIntentRouter` strictly clamps prompt-injected/hallucinated plans to `parent_permissions`; `lctco1.` redaction verified across `crypto.py`, `e2e_driver.py`, `lct_multihost_cli.py`, and `push_to_github.sh`; `18` rehearsal/scale files contain `0` private keys, `0` raw JWTs, `0` raw LCT tokens; `push_to_github.sh --scope workspace --dry-run` PASS. |

---

## 2. Severity-Ranked Findings Requiring Remediation

### `[CRITICAL-M9-01]` Continuation Replay & Multi-Checkpoint Double-Spend (`domain_ca.py`, `auditor.py`)

- **Locations**:
  - [domain_ca.py](file:///Users/hulalala/Desktop/A/lineage/federation/domain_ca.py#L604-L740) (`POST /v1/ca/mint-continuation-token`)
  - [auditor.py](file:///Users/hulalala/Desktop/A/lineage/audit/auditor.py#L352-L396) (`CausalChainAuditor.reconstruct`)
- **Root Cause**:
  - `AutonomousDomainCAService` maintains zero single-use / anti-replay state for `ckpt.checkpoint_id` or `(ckpt.task_id, ckpt.prior_root_block_hash)`. Submitting the exact same signed `TaskCheckpoint` (e.g., `original_max_amount=600.0`, `consumed_amount=280.0` -> `remaining_amount=320.0`) multiple times to `/v1/ca/mint-continuation-token` returns `200 OK` every time, minting distinct `ContinuationToken`s (`jti` differs -> distinct `root_block_hash` -> independent `_QuotaTracker` quota at `LeafVerifier`).
  - Similarly, multiple distinct checkpoints referencing the same `prior_root_block_hash` can be submitted to fork a continuation chain (`R_0 -> R_1a` and `R_0 -> R_1b`).
  - `CausalChainAuditor.reconstruct` ([auditor.py](file:///Users/hulalala/Desktop/A/lineage/audit/auditor.py#L352-L396)) adds every continuation `ROOT_MINT` whose `prior_root_block_hash` is in `authorized_root_hashes` without flagging duplicate `resumes_checkpoint_id` or forked sibling continuations off the same `prior_root_block_hash`.
- **Reproduced Impact** (`test_01_reproduce_critical_m9_01_continuation_replay_double_spend`):
  - A `$600`-capped task that already spent `$280` replays its `TaskCheckpoint` twice, obtaining two valid `$320` continuation tokens that both pass `LeafVerifier.verify_request` (`$280 + $320 + $320 = $920` total spend on a `$600` root cap) with `0` audit anomalies.
- **Required Remediation**:
  1. Maintain a thread-safe bounded anti-replay ledger in `AutonomousDomainCAService` tracking consumed `checkpoint_id`s and superseded `(task_id, prior_root_block_hash)` pairs; atomically reject any second continuation mint for an already-used `checkpoint_id` or already-superseded `prior_root_block_hash` with HTTP `409` / `403` (`CONTINUATION_REPLAY_REJECTED`).
  2. In `CausalChainAuditor.reconstruct`, detect and record anomalies (`DUPLICATE_CHECKPOINT_CONTINUATION` / `FORKED_CONTINUATION_ROOT`) whenever more than one `ROOT_MINT` references the same `resumes_checkpoint_id` or `prior_root_block_hash`, setting `reconstructed_complete = False`.

---

### `[HIGH-M9-01]` Fail-Open `prior_root_block_hash` Lookup & Unbound Checkpoint Signer (`domain_ca.py`, `token.py`, `proxy.py`)

- **Locations**:
  - [domain_ca.py](file:///Users/hulalala/Desktop/A/lineage/federation/domain_ca.py#L638-L682)
  - [token.py](file:///Users/hulalala/Desktop/A/lineage/protocol/token.py#L1157-L1263) (`TaskCheckpoint.from_dict_and_verify`, `mint_continuation_root_token`)
  - [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L1687-L1709) (`LineageSidecar` `action == "sign_checkpoint"`)
- **Root Cause**:
  1. **Fail-open when `prior_root_block_hash` is not in `local_store`**: In [domain_ca.py](file:///Users/hulalala/Desktop/A/lineage/federation/domain_ca.py#L648-L657), if `ckpt.prior_root_block_hash` is absent from `self._audit_emitter.local_store.get_by_task(ckpt.task_id)` (e.g., fabricated `prior_root_block_hash`, CA restart, or ring-buffer eviction), `prior_perms` remains `None` instead of failing closed. `mint_continuation_root_token` ([token.py](file:///Users/hulalala/Desktop/A/lineage/protocol/token.py#L1221-L1254)) then trusts caller-supplied `checkpoint.original_max_amount` / `original_max_calls` verbatim and skips non-numeric lattice subset checks (`tools`, `allowed_targets`, `param_whitelist`), allowing arbitrary budget and tool escalation!
  2. **Unbound checkpoint signer authority**: `TaskCheckpoint.from_dict_and_verify` ([token.py](file:///Users/hulalala/Desktop/A/lineage/protocol/token.py#L1157-L1161)) accepts any valid `WorkloadSVID` across any federated trust domain (`self.federation_trust_resolver`), never verifying that `ckpt.signer_spiffe_id` equals the authorized entry coordinator (`delegate_spiffe_id`) of the prior `RootBlock`! In addition, `LineageSidecar` `action == "sign_checkpoint"` ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L1687-L1709)) signs raw caller-supplied `task_id`, `sub`, `original_max_amount`, and `consumed_amount` without verifying an authentic prior `LineageToken` / `RootBlock` held by `self.identity.spiffe_id`.
- **Reproduced Impact** (`test_02_reproduce_high_m9_01_unverified_prior_root_and_unbound_checkpoint_signer`):
  - An unrelated workload in `org-beta.io` signs a fake `TaskCheckpoint` for `user:alice@org-alpha.io` with `prior_root_block_hash="nonexistent-prior-root-hash-0001"` and `original_max_amount=50000.0`, and `alpha-ca` mints a valid `$50,000` `hr_salary_read` continuation `RootBlock` (`200 OK`).
- **Required Remediation**:
  1. **Fail closed on prior root verification**: `AutonomousDomainCAService` must maintain an authoritative bounded CA root-issuance ledger (and/or accept `prior_root_token` / signed `RootBlock` in the request body verified against `self.ca` with `expected_typ="lct-root+jwt"`). If the prior `RootBlock` matching `(ckpt.task_id, ckpt.sub, ckpt.prior_root_block_hash)` cannot be cryptographically verified, reject with `403 PRIOR_ROOT_NOT_VERIFIED` — never allow `prior_perms = None` in CA continuation minting!
  2. **Authoritative ceiling & signer binding**: Verify `ckpt.signer_spiffe_id == prior_root.delegate_spiffe_id`, verify `first_hop_spiffe_id == prior_root.delegate_spiffe_id`, and reject if `ckpt.original_max_amount` or `ckpt.original_max_calls` exceeds `prior_root.permissions` (using `prior_root.permissions` authoritatively for all numeric and non-numeric lattice monotonicity checks).
  3. **Harden `sign_checkpoint` in `LineageSidecar`**: Require the caller (or active/expired verified token) to supply the prior `compact_token` (`LineageToken`), verify its CA `RootBlock` signature (ignoring temporal expiry), enforce `prior_tok.root.delegate_spiffe_id == self.identity.spiffe_id`, and populate `task_id`, `sub`, `prior_root_block_hash`, `original_max_amount`, and `original_max_calls` directly from `prior_tok.root` rather than trusting raw JSON fields.

---

### `[HIGH-M9-02]` Revoked `ContinuationToken` Resurrects Expired Pre-Checkpoint Branches (`policy_verifier.py`, `token.py`)

- **Locations**:
  - [policy_verifier.py](file:///Users/hulalala/Desktop/A/lineage/verifier/policy_verifier.py#L1073-L1170) (`LeafVerifier.verify_request`, Branch 2 `MultiParentToken`)
  - [token.py](file:///Users/hulalala/Desktop/A/lineage/protocol/token.py#L635-L659) (`are_roots_continuously_linked`)
- **Root Cause**:
  1. **Revocation checked AFTER expired-branch re-anchoring**: In `LeafVerifier.verify_request` ([policy_verifier.py](file:///Users/hulalala/Desktop/A/lineage/verifier/policy_verifier.py#L1084-L1169)), Step 1 validates each parent chain with `check_revocation=False`. Step 1b (`lines 1101-1139`) immediately uses `unexpired_chains` to resurrect `expired_chains` via `are_roots_continuously_linked`, and only afterwards does Step 2 (`lines 1160-1169`) prune `revoked_chains`! Consequently, when continuation chain `R_1` (`prior_root_block_hash = hash(R_0)`) has been **explicitly revoked** (`CancelTask`), `R_1` still enters `unexpired_chains` in Step 1, resurrects expired pre-checkpoint branch `C_0` (rooted at `R_0`) in Step 1b, and is then pruned in Step 2 — leaving the expired `C_0` alive in `surviving_chains` (`200 ALLOW_DEGRADED_DAG`)!
  2. **Undirected / fork-tolerant `are_roots_continuously_linked`**: [token.py](file:///Users/hulalala/Desktop/A/lineage/protocol/token.py#L635-L659) checks undirected graph connectivity across `prior_root_block_hash` without requiring identical `(task_id, sub, issuer_trust_domain)`, strictly non-decreasing `iat` along `R_{k-1} -> R_k`, or unique successor/predecessor linearity (allowing forked sibling continuations `[R_0, R_1a, R_1b]` to pass).
- **Reproduced Impact** (`test_03_reproduce_high_m9_02_revoked_continuation_resurrects_expired_branch`):
  - Assembling a `MultiParentToken` from `[expired_R0_branch, revoked_R1_continuation_branch]` at `t = now + 20s` bypasses both expiration AND revocation, returning `allowed=True, decision="ALLOW_DEGRADED_DAG"`.
- **Required Remediation**:
  1. Check revocation on `unexpired_chains` **before** Step 1b re-anchoring (including high-risk revocation quorum sync!), so ONLY **unexpired AND unrevoked** continuation chains can anchor upstream ancestor roots; and require that every re-anchored expired root `R_old` is a strict directed ancestor (`R_old <- ... <- R_live`) of at least one surviving unrevoked live continuation chain `R_live`.
  2. Harden `are_roots_continuously_linked` to enforce a single directed linear chain (`in-degree <= 1` and `out-degree <= 1` per distinct `root_block_hash`, acyclic, matching `(task_id, sub, issuer_trust_domain)`, and `child_root.iat >= parent_root.iat`).

---

### `[HIGH-M9-03]` Co-Authorization Consent & Cross-Principal Owner Isolation Bypasses (`domain_ca.py`, `peer_apps.py`, `proxy.py`, `config_gen.py`)

- **Locations**:
  - [domain_ca.py](file:///Users/hulalala/Desktop/A/lineage/federation/domain_ca.py#L459-L602)
  - [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L958-L971) (`op == "request_co_auth_consent"`)
  - [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L661-L672), [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L1087-L1220), [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L1711-L1759)
  - [config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L1712), [config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L2334-L2408), [config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L2543-L2622)
- **Root Cause**:
  1. **Missing `POST /v1/ca/mint-consent-token` & unrestricted SA root-minting on `beta-ca`**: `AutonomousDomainCAService` has no `/v1/ca/mint-consent-token` route (`404`). Instead, [config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L2334) adds `assistant-bob` directly to `authorized_gateway_sas` on `beta-ca`, granting `assistant-bob`'s SA unrestricted `POST /v1/ca/mint-root-token` privileges to mint root tokens for **any** `@org-beta.io` user (e.g., `user:dave@org-beta.io`) and **any** owner-only tool (`hr_salary_read`, `calendar_write`, arbitrary `max_amount`) with zero CA-enforced tool allowlist! Meanwhile `assistant-bob-standby` and `assistant-carol` / `assistant-carol-standby` are omitted.
  2. **Unauthenticated peer `request_co_auth_consent`**: In [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L958-L971), when a foreign peer (e.g., Alice's assistant holding only Alice's unilateral `LineageToken`) sends `{"op": "request_co_auth_consent", "tools": ["calendar_free_busy"], ...}` with `owner_oidc_token` omitted (`None`), Bob's PeerApp calls `request_local_ca_consent(..., user_oidc_token=None)` and `beta-ca` (`require_oidc_user_token=False`) mints a genuine CA-signed `RootBlock` for `sub="user:bob@org-beta.io"` (`hop0_oidc_bridged=False`) with **zero cryptographic proof of Bob's identity or consent**!
  3. **`DELEGATION_MODE=dual` OAuth Bearer bypasses `resource_owner_sub` in `LineageSidecar`**: Workspace K8s manifests default to `DELEGATION_MODE=dual` ([config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L1712)). In `LineageSidecar._handle_inbound_oauth_request` ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L1087-L1220)), `self.resource_owner_sub` and `self._owner_protected_tools` are never checked; foreign OAuth Bearer tokens (`user:alice@org-alpha.io`) targeting `/mcp` `hr_salary_read` are forwarded straight past the sidecar boundary to `app` with `X-LCT-Decision: ALLOW_OAUTH_FLAT_SCOPE` (relying solely on Python app-layer checks and leaving any polyglot/MCP app relying on Sidecar `resource_owner_sub` unprotected).
- **Reproduced Impact** (`test_04_reproduce_high_m9_03_coauth_consent_and_dual_mode_oauth_owner_bypass`):
  - `assistant-bob`'s SA mints a `hr_salary_read` root token for `user:dave@org-beta.io` (`200 OK`); Alice unilaterally obtains Bob's signed consent token without Bob's OIDC login (`200 OK`) and reads Bob's `calendar_free_busy` as `CO_AUTHORIZED` (`200 OK`); and Alice's OAuth Bearer token passes straight through Bob's Sidecar (`ALLOW_OAUTH_FLAT_SCOPE`) on `hr_salary_read`.
- **Required Remediation**:
  1. Implement dedicated **`POST /v1/ca/mint-consent-token`** on `AutonomousDomainCAService` (and remove `assistant-bob` from `authorized_gateway_sas`!). Enforce an explicit CA policy mapping `k8s_sa -> (bound_owner_sub, allowed_consent_tools)` (configured via env, e.g. `CONSENT_ISSUER_POLICY="assistant-bob=user:bob@org-beta.io:calendar_free_busy;assistant-bob-standby=user:bob@org-beta.io:calendar_free_busy"`), reject any `sub != bound_owner_sub`, reject any tool outside `allowed_consent_tools` (`hr_salary_read`, `calendar_write` -> `403`), enforce `max_amount is None` (or `0`), and require a cryptographically verified `user_oidc_token` (or owner-signed consent JWS) matching `bound_owner_sub` whenever `oidc_verifier` is configured!
  2. Update `LineageSidecar.request_local_ca_consent` ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L1711-L1759)) to call `POST /v1/ca/mint-consent-token`, and update `WorkspaceAssistantPeerApp` (`request_co_auth_consent` in [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L958-L971)) to require valid owner consent proof (`owner_oidc_token` verified by CA, or explicit signed owner consent artifact — never minting consent on an unauthenticated foreign request!). Also ensure `e2e_driver` / `workspace_e2e.py` passes Bob's real OIDC token (from `beta-sts` / Keycloak) in Scenario 2!
  3. Enforce `self.resource_owner_sub` and `self._owner_protected_tools` inside `LineageSidecar._handle_inbound_oauth_request` ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L1130-L1195)): if `self.resource_owner_sub` is set and the target route/tool is owner-protected while `verified_jwt.canonical_lct_sub != self.resource_owner_sub`, immediately return `403 {"error": "CROSS_PRINCIPAL_DENIED", ...}` at the sidecar ingress!

---

### `[HIGH-M9-04]` `DistributedAuditor` False `reconstructed_complete=True` on Offline Participants & Missing Depth / Size / RFC1918 mTLS Guards (`distributed.py`, `auditor.py`)

- **Locations**:
  - [distributed.py](file:///Users/hulalala/Desktop/A/lineage/audit/distributed.py#L81-L224), [distributed.py](file:///Users/hulalala/Desktop/A/lineage/audit/distributed.py#L284-L419)
  - [auditor.py](file:///Users/hulalala/Desktop/A/lineage/audit/auditor.py#L728-L730)
- **Root Cause**:
  1. **False `reconstructed_complete=True` when downstream peers are offline**: `DistributedAuditor.pull_and_reconstruct` ([distributed.py](file:///Users/hulalala/Desktop/A/lineage/audit/distributed.py#L407)) sets `reconstructed_complete = rec.reconstructed_complete` without checking whether any delegated downstream workload (`target_spiffe_id` from `OUTBOUND_DELEGATE`, `first_hop_spiffe_id`, `CONVERGENCE`, or `SKIP_LEVEL_RETURN` `child_spiffe_id`) failed to respond and landed in `unreachable_nodes`! Conversely, `_extract_peer_spiffe_hints` ([distributed.py](file:///Users/hulalala/Desktop/A/lineage/audit/distributed.py#L249)) also enqueues upstream client `peer_spiffe_id` (such as `e2e-user-gateway`, seen in [workspace_platform_v2_summary.json](file:///Users/hulalala/Desktop/A/lineage/k8s/runs/20261125-m9-workspace-platform-rehearsal/workspace_platform_v2_summary.json#L238-L240)), which is not an agent hosting `/v1/audit/local`.
  2. **Missing BFS `max_depth`, HTTP response size/entry bounds, and RFC1918 + mTLS locator validation**:
     - `DistributedAuditor` has no `max_depth` BFS hop bound, no streaming byte cap (`max_response_bytes`, e.g., `1 MiB`) in `_pull_node_local_entries` ([distributed.py](file:///Users/hulalala/Desktop/A/lineage/audit/distributed.py#L202-L219)), and no `max_entries_per_node` cap.
     - `_resolve_workload_urls` / `pull_and_reconstruct` does not validate candidate URL hosts with `validate_locator_host(..., allowed_cidrs=...)` (allowing SSRF to non-RFC1918 / link-local metadata IPs if untrusted URLs/overrides are passed), and `_verify_kwarg` ([distributed.py](file:///Users/hulalala/Desktop/A/lineage/audit/distributed.py#L131)) returns `True` on `http://` URLs even when `self.mtls_bundle` is configured!
- **Reproduced Impact** (`test_05_reproduce_high_m9_04_distributed_auditor_offline_participant_and_ssrf_bounds`):
  - When `assistant-alice` delegates to `assistant-bob` (`OUTBOUND_DELEGATE`) and `assistant-bob` is offline (`127.0.0.1:9`), `res.unreachable_nodes` contains `assistant-bob`, yet `res.reconstructed_complete` is **`True`** with `anomalies == []`.
- **Required Remediation**:
  1. Distinguish **required downstream/execution participant SPIFFE IDs** (`OUTBOUND_DELEGATE.action_detail["target_spiffe_id"]`, `SKIP_LEVEL_RETURN` child, `entry_spiffe_ids`) from non-sidecar upstream client hints (e.g., skip `e2e-user-gateway` or non-registered client gateways when extracting hints from `INBOUND_AUTHZ.peer_spiffe_id`). Whenever ANY required participant workload (or required domain CA) is in `unreachable_nodes`, append an anomaly (`REQUIRED_AUDIT_NODE_UNREACHABLE:<node>`) and set **`reconstructed_complete = False`**!
  2. Add explicit `max_depth: int = 16`, `max_response_bytes: int = 1_048_576` (`1 MiB` streaming read check), and `max_entries_per_node: int = 2_000` to `DistributedAuditor`.
  3. Validate all resolved audit target hosts via `validate_locator_host(host, allowed_cidrs=self.allowed_locator_cidrs)` (defaulting to RFC1918 + `127.0.0.0/8` only when explicitly permitted for local loopback unit tests, or RFC1918-only in production multi-host mode), and when `self.mtls_bundle is not None`, enforce `https://` + `mtls_bundle.verify_for_target(..., expected_spiffe_id=spiffe_id)` on workload `/v1/audit/local` pulls (refusing plaintext `http://` workload URLs).

---

### `[MEDIUM-M9-01]` `IdempotencyLedger.execute_once` Silent Parameter-Mismatch Reuse (`peer_apps.py`)

- **Locations**:
  - [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L84-L183), [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L685-L785)
- **Root Cause**:
  - `IdempotencyRecord` ([peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L86-L95)) omits `target`, and `IdempotencyLedger.execute_once` ([peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L158-L161)) returns the cached receipt solely on `(clean_sub, clean_key) in self._records` without checking whether `(operation, target, project_code, amount_usd)` match the original committed execution.
- **Reproduced Impact** (`test_06_reproduce_medium_m9_01_idempotency_ledger_parameter_mismatch_reuse`):
  - Replaying `idempotency_key="idem-branch-001"` for `lock_joint_project` (`$950.0`, `PRJ-OTHER`) after `reserve_cloud_budget` (`$150.0`, `PRJ-ATLAS`) silently returns `200 OK` with the `$150.0` `reserve_cloud_budget` receipt instead of rejecting the parameter conflict.
- **Required Remediation**:
  - Store `target: str` on `IdempotencyRecord` (passed by all `WorkspaceVaultMCPApp` tools), and on an existing `(clean_sub, clean_key)` hit in `execute_once`, verify exact parameter match `(existing.operation == clean_op and existing.target == clean_target and existing.project_code == clean_proj and math.isclose(existing.amount_usd, clean_amt, abs_tol=1e-6))`. Raise a dedicated `IdempotencyConflictError` mapped to HTTP `409` (`IDEMPOTENCY_PARAMETER_MISMATCH`) on any mismatch.

---

## 3. Verified Positive Security Invariants & Pre-Push Hygiene

1. **Core `CoAuthorizedToken` (`lctco1.`) & `MultiParentToken` Cryptography**:
   - [token.py](file:///Users/hulalala/Desktop/A/lineage/protocol/token.py#L662-L725): `MultiParentToken` continues to strictly reject mixed `sub` principals (`TokenError`).
   - [token.py](file:///Users/hulalala/Desktop/A/lineage/protocol/token.py#L1306-L1572) & [policy_verifier.py](file:///Users/hulalala/Desktop/A/lineage/verifier/policy_verifier.py#L848-L1070): `CoAuthorizedToken` enforces distinct `[requester_sub, owner_sub]`, identical `task_id`, shared `holder_spiffe_id` + `holder_cnf_jkt` + DPoP proof + mTLS X.509 channel binding ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L511-L527)), monotonic lattice intersection `P_req ⊓ P_owner`, non-expiry of both chains, and revocation prefix + high-risk quorum checks across **both** `requester_chain` and `owner_consent_chain` trust domains.
2. **SVID Renewal Independence**:
   - [sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L686-L794): `WorkloadIdentityRenewer` refreshes only `WorkloadIdentity` and `WorkloadMTLSBundle` X.509 leaf certificates at 50% TTL, never extending immutable `RootBlock.exp` or `AttenuationBlock.exp`.
3. **Decentralized `LocalAuditStore` & Untrusted Public Yellow Pages**:
   - [logger.py](file:///Users/hulalala/Desktop/A/lineage/audit/logger.py#L211-L370): `GET /v1/audit/local` enforces `lct-audit-query+jwt` signatures, `60s` `iat` freshness, `16,384`-entry JTI anti-replay, authorized auditor allowlists, and `require_task_id=True` (`401` unauthenticated, `403` unauthorized / replayed / missing `task_id`).
   - [directory.py](file:///Users/hulalala/Desktop/A/lineage/registry/directory.py#L93-L155) & [directory.py](file:///Users/hulalala/Desktop/A/lineage/registry/directory.py#L559-L610): `AgentDirectoryService(registry_mode="centralized")` verifies CA-signed `WorkloadSVID` + `cnf.jwk` + `AgentCard` JWS + monotonic `version` anti-rollback + anti-equivocation while holding zero CA private keys, zero auth state, and zero audit logs.
4. **LLM `WorkspaceIntentRouter`, Token Redaction & Public-Repo Hygiene**:
   - [intent_router.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/intent_router.py#L94-L262): Prompt-injected/hallucinated LLM outputs are strictly clamped to `parent_permissions`.
   - `lctco1.` redaction verified in [crypto.py](file:///Users/hulalala/Desktop/A/lineage/common/crypto.py#L565-L569), [e2e_driver.py](file:///Users/hulalala/Desktop/A/lineage/k8s/e2e_driver.py#L153), [lct_multihost_cli.py](file:///Users/hulalala/Desktop/A/lineage/multihost/lct_multihost_cli.py#L83), and [push_to_github.sh](file:///Users/hulalala/Desktop/A/lineage/scripts/push_to_github.sh#L160).
   - Secret scan across all `18` files in [20261125-m9-workspace-platform-rehearsal](file:///Users/hulalala/Desktop/A/lineage/k8s/runs/20261125-m9-workspace-platform-rehearsal) and [lineage/scale/](file:///Users/hulalala/Desktop/A/lineage/scale/): `0` private keys, `0` raw JWTs, `0` raw LCT tokens; `0` `lctmh-*` containers left running; `0` modifications to `README.md`, `lab/`, `src/`, or prior `lineage/reviews/*`; `push_to_github.sh --scope workspace --dry-run` **PASS**.
