# Milestone 10 Round-2 QA Remediation Live 3-Cluster Rehearsal Report — Complete 12-Scenario Multi-Entity Workspace Suite

- **Run ID**: `m10-r2-verified`
- **Archive Directory**: `/Users/hulalala/Desktop/A/lineage/k8s/runs/20261126-m10-r2-expanded-scenarios-rehearsal`
- **Live Clusters Deployed**:
  - `kind-lctmh-alpha` (`org-alpha.io`, `10.241.0.0/16`): `alpha-ca` (sovereign IdP trust: `alpha-sts` only), `alpha-directory` (`centralized` untrusted Yellow Pages), `alpha-revocation`, **`alpha-sts` (`quay.io/keycloak/keycloak:26.5.2`, `@org-alpha.io` principals only)**, `assistant-alice` (`2/2`), `e2e-user-gateway` (`1/1`)
  - `kind-lctmh-beta` (`org-beta.io`, `10.242.0.0/16`): `beta-ca` (sovereign IdP trust: `beta-sts` only), `beta-revocation`, `beta-sts` (`@org-beta.io` principals `bob`, `dave` only), **`beta-user-gateway` (`1/1`, mTLS 1.3 + sovereign `beta-sts` OIDC)**, `assistant-bob` (`2/2`), `assistant-bob-standby` (`2/2`), `assistant-dave` (`2/2`)
  - `kind-lctmh-pay` (`org-payment.io`, `10.243.0.0/16`): `payment-ca` (sovereign IdP trust: `payment-sts` only), `payment-revocation`, `payment-sts` (`@org-payment.io` principal `carol` only), `assistant-carol` (`2/2`), `assistant-carol-standby` (`2/2`), `assistant-vault` (`2/2`)
  - **Central Audit Collector Cluster (`lctmh-audit`)**: **NOT DEPLOYED (`central_audit_collector_deployed: false`)** — 100% decentralized local signed audit stores (`LocalAuditStore`) + stateless on-demand `DistributedAuditor` BFS pull.
- **Live LLM**: Host `Ollama qwen2.5:3b` (`http://host.docker.internal:11434/v1/chat/completions`, `completion_id: chatcmpl-35`, `250` tokens, `2990.33 ms`).

---

## Round-2 QA Security Remediations Verified Live

1. **`[CRITICAL-M10-01]` True Single-Domain Sovereign IdP Trust & Per-Issuer JWKS Binding**:
   - `alpha-ca`/`e2e-user-gateway` trust only `alpha-sts` (`org-alpha.io`); `beta-ca`/`beta-user-gateway` trust only `beta-sts` (`org-beta.io`); `payment-ca` trusts only `payment-sts` (`org-payment.io`).
   - `alice` authenticates to `alpha-sts` (`quay.io/keycloak/keycloak:26.5.2`), `bob` authenticates to `beta-sts`, and `carol` authenticates to `payment-sts`.
   - In Scenario 11, `alice`'s `alpha-sts` OIDC token presented to `beta-user-gateway` is rejected at the sovereign cryptographic issuer boundary (`401`).
2. **`[HIGH-M10-01]` Tenant & Task-Isolated Consent Wallet + Owner-Only Consent Revocation**:
   - `_consent_wallet` entries are keyed by `(sub, key)` + `task_id`, rejecting cross-principal or cross-task co-auth assembly (`403 CROSS_TENANT_OR_TASK_CONSENT_DENIED`) and foreign revocation attempts (`403 FORBIDDEN_FOREIGN_CONSENT_REVOCATION`).
3. **`[HIGH-M10-02]` Offline Lattice Required-Parameter & Target Enforcement**:
   - `PermissionLattice.check_invocation` fails closed offline when required constrainable parameters (`amount`, `target`, `project_code`, `contract_id`, `warranty_tier`, `unit_price_usd`, `max_penalty_pct`, `release_id`, `study_id`) are omitted while constrained; Vault MCP tools require explicit arguments (`400` on omission).
4. **`[HIGH-M10-03]` Exact Scanner Allowlist, Attestation JTI Replay Cache & Artifact Hash Binding**:
   - `assistant-vault` enforces exact `ALLOWED_SCANNER_SPIFFE_IDS=spiffe://org-beta.io/ns/lineage-beta/sa/assistant-dave`, `JTIReplayCache` on `lct-compliance-attestation+jwt`, and `artifact_sha256` equality in `sign_release`.
5. **`[MEDIUM-M10-01]` Unified A2A v1.0 & Top-Level JSON Tool Extraction Across LCT & Dual-Mode OAuth**:
   - Shared `_extract_inbound_tool_and_args` inspects top-level `{private_tool, tool}` and A2A v1.0 JSON-RPC `params.configuration` / `params.message.parts[].data` identically across `_handle_inbound_request` and `_handle_inbound_oauth_request`.
6. **`[MEDIUM-M10-02]` Hardened `DomainUserGatewayService`**:
   - Enforces `eff_sender_jkt = self.identity.jkt` (`403 SENDER_JKT_MISMATCH`), verifies CA signature on supplied tokens (`403 INVALID_GATEWAY_ROOT_TOKEN`), validates dispatch targets via `validate_locator_host` (`403 FORBIDDEN_DISPATCH_TARGET`), and contains `0` `verify=False` TLS paths.
7. **`[LOW-M10-01]` SVID-Signed Cohort Digests (`lct-cohort-digest+jwt`)**:
   - `cohort_aggregate_stats` returns an SVID-signed `lct-cohort-digest+jwt`, and `Shared-Vault.federated_cohort_aggregate` verifies `>= 2` distinct institution workload SPIFFE IDs (`spiffe://org-beta.io/ns/lineage-beta/sa/assistant-bob`, `spiffe://org-payment.io/ns/lineage-pay/sa/assistant-carol`) with two-phase `JTIReplayCache` commit (`cohort_digests_verified: true`).

---

## Complete 12-Scenario Live Verification Matrix (`12/12 PASS`)

| E2E Phase | Catalog ID & Domain Vertical | Key Live Security & Protocol Outcomes | Status |
| :--- | :--- | :--- | :---: |
| **Scenario 1** | **S4** (Joint Cross-Org Project) | Real `qwen2.5:3b` Yellow-Pages dynamic intent routing + 1-to-N attenuated fan-out (`TechReviewBob <= $175`, `BizProcurementCarol <= $525`) + N-to-1 `MultiParentToken` Vault convergence (`2` escrow locks, `24` decentralized audit entries, `205.4 ms`, `reconstructed_complete=true`). | **PASS** |
| **Scenario 2** | **S1** (Cross-Principal Isolation & Co-Auth) | Unilateral foreign probes (`hr_salary_read`, `calendar_write`, `calendar_free_busy`) -> `403 CROSS_PRINCIPAL_DENIED` (both LCT & OAuth dual-mode including A2A JSON-RPC envelope); missing OIDC -> `401`; `hr_salary_read` consent refusal -> `403`; sovereign `bob@org-beta.io` `beta-sts` OIDC consent -> `[user:alice@org-alpha.io, user:bob@org-beta.io]` `CoAuthorizedToken` -> `200`; `assistant-bob` SA root-mint -> `403`. | **PASS** |
| **Scenario 3** | **S9** (Long-Task Expiry & Continuation) | Short-TTL task natural expiry -> `401 TASK_AUTH_EXPIRED` + signed `TaskCheckpoint` (`$280` consumed); `$400 > $320` budget inflation -> `403 CONTINUATION_BUDGET_EXCEEDED`; checkpoint replay -> `409 CONTINUATION_REPLAY_REJECTED`; valid `$320` `ContinuationToken` completes remaining branch + `VERIFIED_TASK_CONTINUATION` DAG stitch. | **PASS** |
| **Scenario 4A** | **S10** (Post-Commit Drop & Idempotent Failover) | Primary `epoch=0` commits to Vault before simulated response drop; `Atomic Prune-and-Graft` (`epoch=1`) replays deterministic `branch_idempotency_key` -> `idempotent_replay=true`, `vault_charge_count=1`; parameter-tampered replay -> `409 IDEMPOTENCY_PARAMETER_MISMATCH`; zombie primary wakeup -> `403 LINEAGE_REVOKED`. | **PASS** |
| **Scenario 4B** | **S12** (3-Tier Skip-Level Return) | Live `kubectl scale deploy/assistant-bob --replicas=0` kills middleman Bob; `assistant-dave` automatically falls back to `SKIP_LEVEL_ANCESTOR` and delivers signed result directly to `assistant-alice`. | **PASS** |
| **Scenario 5** | **S11** (Branch Degradation, OAuth Compare & Audit) | Revoking Carol's branch degrades Vault commit smoothly (`cloud-infra-escrow=200`, `vendor-procurement-escrow=403`); OAuth centralized/federated (`6` online STS RPCs, `$950` overprivilege `200`) vs LCT (`0` online STS RPCs, `$950` -> `403 LATTICE_PERMISSION_DENIED`); `DistributedAuditor` `7` nodes queried in `205.85 ms`, `100%` complete. | **PASS** |
| **Scenario 6** | **S2** (Financial Risk — Bidirectional Ping-Pong) | Round 1 `A -> B` (`service_diag_read`: unilateral `403` -> `[alice, bob]` co-auth `200`); Round 2 reverse `B -> A` (`gateway_config_read`: OAuth `403`, unilateral `403`, `alice_private_roadmap` owner-only `403`, `[bob, alice]` reverse co-auth `200`); Round 3 `commit_joint_change` (`200`), tampered key -> `409`, post-Bob-revocation re-commit -> `403`. | **PASS** |
| **Scenario 7** | **S3** (Enterprise Legal & Procurement Redline) | 3-hop `Alice -> Bob -> Dave` (`legal_redline_review`) while `Dave -> Bob` `pricing_floor_read` is `403` blocked; Vault `commit_negotiated_contract` blocks unilateral (`403`), over-budget `$165 > $120` (`403`), omitted-parameter lattice bypass (`403`), and weak warranty `12M` (`403`), allowing compliant `[alice, bob]` (`$115`, `24M`, `max_penalty_pct=8.0` -> `200`). | **PASS** |
| **Scenario 8** | **S5** (Compliance & Release SoD) | 4-hop `Alice -> Bob -> Dave` produces signed `lct-compliance-attestation+jwt` (`spiffe://org-beta.io/ns/lineage-beta/sa/assistant-dave`); `sign_release` blocks unilateral Alice self-approval (`403`), missing attestation (`403`), cross-release replay (`403`), artifact-hash mismatch (`403`), and JTI replay (`403`), succeeding (`200`) with sovereign `carol@org-payment.io` (`payment-sts`) SoD + verified attestation. | **PASS** |
| **Scenario 9** | **S6** (Healthcare Federated Cohort Aggregation) | `export_raw_patient_records` denied (`403`) at both Hospital B and Institution C (and refused by CA consent policy `403`); SVID-signed `lct-cohort-digest+jwt` (`cohort_digests_verified=true`) aggregated across `[alice, bob]` + `[alice, carol]` (`800` total samples -> `200`), blocking forged unsigned digests (`403`) and cross-task commercial replay (`403`). | **PASS** |
| **Scenario 10** | **S7** (4-Hop Indirect Prompt Injection & Cascade) | Compromised Hop-3 (`assistant-dave`) prompt-injection probes (`reserve_cloud_budget $9999` & `hr_salary_read`) blocked offline (`403`) while legitimate `record_compliance_note` succeeds (`200`); upstream revokes Hop-2 `/TechReviewBob`, immediately invalidating BOTH Hop-2 and Dave's pre-minted cached Hop-3 token (`403 LINEAGE_REVOKED`), while Carol's sibling branch completes (`200`). | **PASS** |
| **Scenario 11** | **S8** (Symmetric `org-beta` Entry & Token Theft) | `beta-user-gateway` (`mtls-tcp :31106`) rejects missing OIDC (`401`), foreign `alpha-sts` Alice OIDC (`401` sovereign IdP boundary), foreign `sender_jkt` (`403`), and `sub` spoofing (`403`); Bob (`user:bob@org-beta.io` via `beta-sts`) orchestrates across `org-beta.io`, `org-alpha.io`, and `org-payment.io`; stolen LCT token replay blocked (`403`) on both Vault and Alpha; cross-tenant snoop returns empty; `DistributedAuditor` from `org-beta` reconstructs `8` nodes in `227.89 ms` (`100%` complete). | **PASS** |
