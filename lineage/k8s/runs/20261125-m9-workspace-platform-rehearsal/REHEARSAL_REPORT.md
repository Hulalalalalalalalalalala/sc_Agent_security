# Milestone 9 Live 3-Cluster Kubernetes Rehearsal Report (`20261125-m9-workspace-platform-rehearsal`)

- **Topology**: 3 autonomous Kind clusters (`lctmh-alpha` / `org-alpha.io`, `lctmh-beta` / `org-beta.io`, `lctmh-pay` / `org-payment.io`) in star gossip (`pay <-> alpha <-> beta`) with **ZERO central audit cluster (`central_audit_collector_deployed: false`)**
- **Untrusted Public Yellow Pages**: Hosted on `alpha-directory` (`registry_mode="centralized"`, `0` private keys, `0` auth state, `0` audit storage)
- **Live External Engines**:
  - Real `quay.io/keycloak/keycloak:26.5.2` (`alpha-sts`) + per-domain `FederatedOAuthSTS` (`beta-sts`, `payment-sts`)
  - Real host `Ollama qwen2.5:3b` (`0.0.0.0:11434`) driving dynamic Yellow-Pages intent routing and peer tool calls

## Scenario Results (`overall_status: PASS`)

| Scenario | Outcome | Key Measured Evidence |
| :--- | :--- | :--- |
| **1. Yellow-Pages Intent Routing + P2P 1->N Fan-Out + N->1 Vault Convergence** | **PASS** | `qwen2.5:3b` (`chatcmpl-657`, `1113.41 ms`) selected `workspace.tech_review` & `workspace.biz_procurement`; hallucinated `$5000 + $3000` clamped by `WorkspaceIntentRouter` to `$437.5 + $262.5 <= $700.0`; `2` Vault locks completed (`6266.27 ms` E2E); `DistributedAuditor` reconstructed `24` entries across `7` nodes in `189.64 ms` (`reconstructed_complete: true`). |
| **2. Cross-Principal Isolation + Dual-Principal `CoAuthorizedToken` (`lctco1.`)** | **PASS** | Unilateral foreign probes (`hr_salary_read`, `calendar_write`, `calendar_free_busy`) all blocked (`403 CROSS_PRINCIPAL_DENIED`); owner-only `hr_salary_read` consent refused (`403`); explicit `[user:alice@org-alpha.io, user:bob@org-beta.io]` co-auth returned `200 CO_AUTHORIZED` (`desensitized: true`); `VERIFIED_DUAL_PRINCIPAL_COAUTH`. |
| **3. Short-TTL Task Expiry + `TaskCheckpoint` + Remaining-Budget `ContinuationToken`** | **PASS** | Phase 1 (`$280.0`) succeeded; task token expiry returned `401 TASK_AUTH_EXPIRED` + signed `TaskCheckpoint` (`remaining_budget_usd: 320.0`); `$450 > $320` inflation attempt rejected (`403 CONTINUATION_BUDGET_EXCEEDED`); `ContinuationToken` resumed & converged `2` Vault locks (`VERIFIED_TASK_CONTINUATION`). |
| **4A. Post-Commit Timeout Drop + Standby `epoch=1` Idempotency + Zombie `403`** | **PASS** | Primary Bob committed pre-drop then stalled; Standby Bob (`epoch=1`) & Standby Carol (`epoch=1`) took over with `standby_idempotent_replay: true`, **`vault_charge_count_for_branch: 1`**, and delayed primary wakeup rejected (`403`); `VERIFIED_FAILOVER_GRAFT`. |
| **4B. 3-Tier `Alice -> Bob -> Dave` Upward Skip-Level Return** | **PASS** | `DIRECT_PARENT` while `assistant-bob` alive; genuine K8s Pod kill (`fault --kill assistant-bob --fast`) verified via mTLS `/healthz` barrier -> `Dave` delivered signed `SkipLevelReceipt` directly to `Alice` (`skip_level_results_delivered_to_alice: 1`). |
| **5. Single-Branch Degradation + OAuth vs LCT Compare + `DistributedAuditor`** | **PASS** | Canceling Carol branch degraded cleanly (`cloud-infra-escrow: 200`, `vendor-procurement-escrow: 403`, `SMOOTH_DAG_DEGRADATION_ON_REVOCATION`); `oauth_centralized` (`6822.69 ms`, `6` STS RPCs, `200` overprivilege) & `oauth_federated` (`4422.34 ms`, `6` STS RPCs, `200` overprivilege) vs `lct` (**`0` STS RPCs**, **`403 LATTICE_PERMISSION_DENIED`**); `/v1/audit/local` enforced `401` unauth / `200` valid / `403` replay; `DistributedAuditor` pulled `25` entries across `7` nodes in `181.7 ms` (`0` anomalies). |
