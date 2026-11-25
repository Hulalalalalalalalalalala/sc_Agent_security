# Milestone 9 Round-2 Live 3-Cluster Workspace Rehearsal Report (`m9-r2-clean`)

- **Run ID**: `m9-r2-clean`
- **Overall Verdict**: **`PASS`** (`6/6` live scenarios & sub-phases passed)
- **Live Topology**: `3` Kind clusters (`lctmh-alpha` with real `quay.io/keycloak/keycloak:26.5.2`, `lctmh-beta`, `lctmh-pay`), **`0` `audit` clusters** (`central_audit_collector_deployed: false`), `1` Untrusted Public Yellow Pages (`alpha-directory`, `registry_mode=centralized`), real `qwen2.5:3b` LLM (`completion_id: chatcmpl-640`, `fp_ollama`).

## Scenario & Round-2 Security Remediation Evidence

| Scenario | Task ID | Key Live Assertions Verified | Status |
| :--- | :--- | :--- | :--- |
| **1. Yellow-Pages Intent Routing + 1->N Fan-Out + N->1 Vault Convergence** | `ws-m9-r2-clean-s1-collab` | Real `qwen2.5:3b` (`3502.16 ms`), `PRJ-ATLAS` `$437.50` / `$262.50` disjoint lattice split, `2` Vault locks, `7` nodes queried (`24` entries, `reconstructed_complete: true`) | **`PASS`** |
| **2. Cross-Principal Isolation + Hardened Co-Auth Consent (`[HIGH-M9-03]`)** | `ws-m9-r2-clean-s2-coauth` | Unilateral LCT `403 CROSS_PRINCIPAL_DENIED`; `DELEGATION_MODE=dual` OAuth Bearer `403 CROSS_PRINCIPAL_DENIED`; missing Bob OIDC `401`; `assistant-bob` SA `/v1/ca/mint-root-token` `403`; owner-only tool consent refusal `403`; real Keycloak Bob OIDC `/v1/ca/mint-consent-token` -> `CoAuthorizedToken` (`lctco1.`, `200`, `VERIFIED_DUAL_PRINCIPAL_COAUTH`) | **`PASS`** |
| **3. Task Expiry -> Verified Checkpoint -> Anti-Replay Continuation (`[CRITICAL-M9-01]`, `[HIGH-M9-01]`, `[HIGH-M9-02]`)** | `ws-m9-r2-clean-s3-cont` | Phase-1 `401 TASK_AUTH_EXPIRED`; CA-verified `prior_root_token` + holder-bound `TaskCheckpoint` (`$280` consumed -> `$320` remaining); budget inflation `403 CONTINUATION_BUDGET_EXCEEDED`; checkpoint replay `409 CONTINUATION_REPLAY_REJECTED`; `2` converged Vault locks (`VERIFIED_TASK_CONTINUATION`) | **`PASS`** |
| **4A. Post-Commit Timeout Drop + Standby Idempotency + Parameter Conflict Guard (`[MEDIUM-M9-01]`)** | `ws-m9-r2-clean-s4a-idem` | Bob & Carol failover (`epoch=1`), `standby_idempotent_replay: true`, `vault_charge_count_for_branch: 1`, conflicting replay (`amount=499.0` vs `280.0`) -> `409 IDEMPOTENCY_PARAMETER_MISMATCH`, zombie primary wakeup `403` | **`PASS`** |
| **4B. 3-Tier `Alice -> Bob -> Dave` Upward Skip-Level Return** | `ws-m9-r2-clean-s4b-skip` | Alive `DIRECT_PARENT`; real `fault.sh` termination of `assistant-bob` (`replicas=0`) -> `SKIP_LEVEL_ANCESTOR` (`Dave -> Alice`, `1` result delivered) -> clean restore | **`PASS`** |
| **5. Single-Branch DAG Degradation + Dual-Mode OAuth vs LCT + Hardened `DistributedAuditor` (`[HIGH-M9-04]`)** | `ws-m9-r2-clean-s5-degrade` | `cloud-infra-escrow: 200` (`ALLOW_DEGRADED_DAG`), `vendor-procurement-escrow: 403`; OAuth (`6` STS RPCs, over-privilege `200`) vs LCT (`0` STS RPCs, `403 LATTICE_PERMISSION_DENIED`); `/v1/audit/local` unauth `401` / valid `200` / replay `403`; `DistributedAuditor` (`7` nodes queried, **`unreachable_nodes: {}`**, `25` entries, `402.17 ms`, `reconstructed_complete: true`, `0` anomalies) | **`PASS`** |
