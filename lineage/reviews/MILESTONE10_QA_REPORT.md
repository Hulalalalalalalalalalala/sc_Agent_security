# Milestone 10 (Platform v2.1) Independent Code, Cryptographic & Compliance QA Report

- **Reviewer**: `k8s-qa-reviewer` (Independent Read-Only QA & Security Compliance Session)
- **Milestone Scope**: Platform v2.1 — Complete 12-Scenario Multi-Entity Interactive Workspace Suite across Financial Risk Control (`S2`), Enterprise Legal & Procurement (`S3`), Supply-Chain Release SoD (`S5`), Healthcare Federated Cohort Aggregation (`S6`), 4-Hop Prompt Injection & Cascading Subtree Revocation (`S7`), and Symmetric `org-beta` Entry & Stolen-Token Defense (`S8`)
- **Automated Test Execution**:
  - `python3 -W default -m lineage.tests.run_all`: **`99/99 PASS`** in `75.64s` (`0` warnings)
  - `python3 -W default -m unittest -v lineage.reviews.qa_milestone9_signoff`: **`7/7 PASS`** in `2.01s` (`0` warnings)
  - `python3 -W default -m unittest -v lineage.reviews.qa_milestone10_review`: **`8/8 PASS`** in `1.52s` (`0` warnings — reproduces all 6 findings below + verifies positive M10 invariants)
- **Pre-Push Secret Scan (`push_to_github.sh --scope workspace --dry-run`)**: **`PASS`** (`0` private keys, `0` GitHub PATs, `0` raw JWTs, `0` raw LCT wire tokens)
- **Overall Verdict**: **`NEEDS_FIX`** (`1` Critical, `3` High, `2` Medium, `1` Low)

---

## 1. Executive Summary & Positive Security Controls Verified

Milestone 10 delivers impressive functional breadth across all 12 catalog scenarios (`12/12 PASS` in [20261125-m10-expanded-scenarios-rehearsal](file:///Users/hulalala/Desktop/A/lineage/k8s/runs/20261125-m10-expanded-scenarios-rehearsal/workspace_platform_v2_summary.json)) with zero central audit collector (`central_audit_collector_deployed: false`), real `quay.io/keycloak/keycloak:26.5.2`, real `Ollama qwen2.5:3b`, clean cluster teardown, and clean pre-push secret hygiene.

Positive security invariants independently verified:
- **Least-Privilege `CONSENT_ISSUER_POLICY` & Gateway SA Isolation** ([config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L2098-L2108), [config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L2345-L2358), [config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L2720-L2732)): Zero `assistant-*` ServiceAccounts appear in `AUTHORIZED_GATEWAY_SA` or `AUTHORIZED_GATEWAY_SAS`, and owner-only tools (`hr_salary_read`, `calendar_write`, `alice_private_roadmap`, `pricing_floor_read`, `export_raw_patient_records`) are excluded from `CONSENT_ISSUER_POLICY` across all 3 CAs.
- **mTLS 1.3 Channel Binding Across All 3 Wire Formats** ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L591-L626)): `_verify_mtls_channel_binding` enforces `403 MTLS_CHANNEL_BINDING_MISMATCH` across `LineageToken`, `MultiParentToken`, and `CoAuthorizedToken`.
- **Adaptive `HIGH_RISK` Multi-Domain Revocation Sync** ([policy_verifier.py](file:///Users/hulalala/Desktop/A/lineage/verifier/policy_verifier.py#L674-L715)): Collects `issuer_trust_domain` and `visited_subjects` across all `parent_chains` (both `MultiParentToken` and `CoAuthorizedToken`) and fails closed (`503 REVOCATION_ANCHOR_UNAVAILABLE`) if sync fails.
- **Fault-Injection Gating** ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L1664-L1666), [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L2015-L2024)): `replay_cached_hop_tool` returns `403 fault_injection_disabled` unless `LCT_ENABLE_FAULT_INJECTION=true` and never serializes raw cached tokens into HTTP responses.

However, independent adversarial code review and PoC testing in [qa_milestone10_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone10_review.py) uncovered **6 actionable security defects** (`[CRITICAL-M10-01]`, `[HIGH-M10-01..03]`, `[MEDIUM-M10-01..02]`) plus `1` Low defense-in-depth item that must be remediated before public GitHub push.

---

## 2. Detailed Security & Compliance Findings

### `[CRITICAL-M10-01]` Cross-Domain OIDC IdP Trust & Unbound `(issuer -> JWKS / user-domain)` Principal Spoofing Across `beta-ca`, `payment-ca`, `beta-user-gateway`, & `OIDCTokenVerifier`
- **Locations**:
  - [bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L1254-L1290) (`role == "domain-ca"`: `_ca_oidc_jwks_urls` & `_ca_allowed_issuers`)
  - [bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L2273-L2306) (`role == "user-gateway"`: `_gw_jwks_urls` & `_gw_allowed_issuers`)
  - [client.py](file:///Users/hulalala/Desktop/A/lineage/oauth_sts/client.py#L132-L240) (`OIDCTokenVerifier`)
  - [service.py](file:///Users/hulalala/Desktop/A/lineage/oauth_sts/service.py#L411-L426) & [keycloak_realm.py](file:///Users/hulalala/Desktop/A/lineage/oauth_sts/keycloak_realm.py#L63-L67) (`DEFAULT_USER_HOME_DOMAINS`)
  - [workspace_e2e.py](file:///Users/hulalala/Desktop/A/lineage/k8s/workspace_e2e.py#L223-L228) (and lines `1006-1010`, `1238-1241`, `1396-1399`, `1544-1549`, `1866-1869`)
- **PoC**: `Milestone10QAReviewSuite.test_01_poc_critical_m10_01_cross_domain_oidc_idp_trust_and_key_confusion` in [qa_milestone10_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone10_review.py#L72-L162).
- **Root Cause & Impact (Three Interlocking Flaws)**:
  1. **Foreign-Organization IdP Sovereignty Violation**: `beta-ca` (`org-beta.io`), `beta-user-gateway` (`org-beta.io`), and `payment-ca` (`org-payment.io`) hardcode `"org-alpha.io"` (`http://alpha-oidc.lct.local/realms/lct` + `org-alpha.io` `oauth_sts` locators) into their trusted OIDC issuers and JWKS providers. Consequently, a compromised or malicious `org-alpha.io` IdP (`alpha-sts`) can unilaterally mint OIDC tokens with `lct_sub="user:bob@org-beta.io"` or `lct_sub="user:carol@org-payment.io"`, and `beta-ca` / `beta-user-gateway` / `payment-ca` accept them to mint `org-beta.io` and `org-payment.io` owner consent and root tokens — completely bypassing `beta-sts` and `payment-sts`.
  2. **Unqualified-Username Cross-Domain Escalation (`default_user_domain`)**: Any standard OIDC token issued by `alpha-sts` (`org-alpha.io`) without a custom `lct_sub` attribute (e.g., `preferred_username="operator"`) is rewritten by `OIDCTokenVerifier` ([client.py](file:///Users/hulalala/Desktop/A/lineage/oauth_sts/client.py#L233)) on `beta-ca` / `beta-user-gateway` (`default_user_domain="org-beta.io"`) into `"user:operator@org-beta.io"`, passing `beta-user-gateway`'s `@org-beta.io` check! (Also note `"dave"` is missing from `DEFAULT_USER_HOME_DOMAINS` in [keycloak_realm.py](file:///Users/hulalala/Desktop/A/lineage/oauth_sts/keycloak_realm.py#L63-L67), defaulting to `org-alpha.io` instead of `org-beta.io`.)
  3. **Shared `_keys_by_kid` Key Confusion Across Issuers**: `OIDCTokenVerifier._refresh_jwks` ([client.py](file:///Users/hulalala/Desktop/A/lineage/oauth_sts/client.py#L163-L204)) merges signing keys from all configured `jwks_urls` into one flat `self._keys_by_kid` dict without binding `kid` to its source `issuer` or restricting which `@<domain>` an issuer may assert in `lct_sub`/`sub`. Thus `alpha-sts`'s RS256 key can sign a JWT spoofing `iss = beta-sts` and `OIDCTokenVerifier` accepts it!
- **Required Remediation**:
  1. **Strict Single-Domain IdP Sovereignty on `domain-ca` & `user-gateway`**: In [bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L1254-L1290) and [bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L2273-L2306), remove `"org-alpha.io"` and `"http://alpha-oidc.lct.local/..."` when `trust_domain != "org-alpha.io"`. Each organization's `domain-ca` and `user-gateway` MUST ONLY trust its own `trust_domain`'s STS (`alpha-sts` for `org-alpha.io`, `beta-sts` for `org-beta.io`, `payment-sts` for `org-payment.io`).
  2. **Issuer-to-Key & Issuer-to-Domain Binding in `OIDCTokenVerifier`** ([client.py](file:///Users/hulalala/Desktop/A/lineage/oauth_sts/client.py#L132-L240)):
     - Bind each fetched JWKS endpoint to its corresponding issuer origin so Issuer A's key can NEVER verify a token claiming `iss == Issuer B`.
     - Enforce `allowed_user_domains` / `issuer_user_domain_map` on `OIDCTokenVerifier` (for `domain-ca` and `user-gateway`, restrict `canonical_lct_sub` strictly to `f"@{trust_domain}"`; for `OAuthSTSService` in [service.py](file:///Users/hulalala/Desktop/A/lineage/oauth_sts/service.py#L411-L426), ensure a domain STS in sovereign mode only issues principals for `self.trust_domain` unless explicitly configured as a multi-org centralized test fixture, and add `"dave": "org-beta.io"` to `DEFAULT_USER_HOME_DOMAINS`).
  3. **True Multi-Org OIDC Login in E2E & Unit Suites**: Update `gw.login_oidc_user(...)` / [workspace_e2e.py](file:///Users/hulalala/Desktop/A/lineage/k8s/workspace_e2e.py) and `_MultiDomainWorkspaceMesh` in [test_m10_expanded_scenarios.py](file:///Users/hulalala/Desktop/A/lineage/tests/test_m10_expanded_scenarios.py#L88-L116) so `alice` authenticates against `org-alpha.io`'s `alpha-sts` (Keycloak 26.5.2), `bob` authenticates against `org-beta.io`'s `beta-sts`, and `carol` authenticates against `org-payment.io`'s `payment-sts`!

---

### `[HIGH-M10-01]` Unisolated `_consent_wallet` Cross-Principal / Cross-Task Access & Unauthenticated Foreign `revoke_own_consent`
- **Locations**:
  - [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L1148) (`self._consent_wallet`)
  - [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L1224-L1238) (`_store_consent` / `_get_consent`)
  - [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L1562-L1586) (`revoke_own_consent` & `probe_peer_private_resource`)
  - [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L1668-L1697) (`request_peer_co_auth_and_read` & `call_mcp_with_wallet`)
  - [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L1883-L1931) (`revoke_consent_prefix`)
- **PoC**: `Milestone10QAReviewSuite.test_02_poc_high_m10_01_unisolated_consent_wallet_and_foreign_revoke_own_consent` in [qa_milestone10_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone10_review.py#L164-L320).
- **Root Cause & Impact**:
  1. `_consent_wallet` is a process-wide `OrderedDict[str, str]` keyed solely by raw caller-supplied `key: str` with zero `(sub, task_id)` isolation. Any foreign principal or unrelated task calling `probe_peer_private_resource` or `call_mcp_with_wallet` with `"use_consent_key"` can read/consume or overwrite (`cache_consent_key`) another user's cached owner consent token.
  2. In [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L1562-L1568), `op == "revoke_own_consent"` never checks `sub == self.owner_sub` (nor requires `owner_oidc_token`), and `LineageSidecar` `revoke_consent_prefix` ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L1883-L1906)) does not verify the active inbound caller's `sub == self.resource_owner_sub`. Any foreign LCT principal (e.g., `user:carol@org-payment.io`) can send `{"op": "revoke_own_consent", "target_task_id": tid, "prefix": bob_consent_pfx}` to `Assistant-B` (`200 OK`) and revoke Bob's consent for Alice's task without Bob's authorization!
- **Required Remediation**:
  1. Isolate `_consent_wallet` entries by `(sub, key)` storing `{"sub": sub, "task_id": task_id, "compact_token": token}`, and on `_get_consent(sub, task_id, key)` fail closed (`403 CROSS_TENANT_OR_TASK_CONSENT_DENIED`) whenever `entry["sub"] != sub` OR `entry["task_id"] != task_id` (preserving the expected `403` in Scenario 9 / `test_05` cross-task commercial replay!).
  2. In `WorkspaceAssistantPeerApp` (`op == "revoke_own_consent"`), reject `sub != self.owner_sub` with `403 FORBIDDEN_FOREIGN_CONSENT_REVOCATION`, AND in `LineageSidecar` (`action == "revoke_consent_prefix"`), verify via `request_id` (`self.active_requests`) or verified `caller_sub` / `user_oidc_token` that the revoking principal is `self.resource_owner_sub`.

---

### `[HIGH-M10-02]` Omitted-Argument Server-Default Bypass of `max_amount`, `numeric_bounds`, `param_whitelist`, & `allowed_targets`
- **Locations**:
  - [lattice.py](file:///Users/hulalala/Desktop/A/lineage/protocol/lattice.py#L300-L329) (`max_amount` & `numeric_bounds`)
  - [lattice.py](file:///Users/hulalala/Desktop/A/lineage/protocol/lattice.py#L351-L391) (`allowed_targets` & `param_whitelist`)
  - [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L808-L824) (`reserve_cloud_budget`, `procure_vendor_quote` fallback defaults)
  - [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L854-L860) (`record_compliance_note` fallback default)
  - [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L924-L934) (`commit_negotiated_contract` fallback defaults)
- **PoC**: `Milestone10QAReviewSuite.test_03_poc_high_m10_02_omitted_argument_bypass_of_lattice_bounds_and_whitelists` in [qa_milestone10_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone10_review.py#L322-L392).
- **Root Cause & Impact**:
  - `PermissionLattice.check_invocation` only validates `max_amount`, `numeric_bounds[ck]`, `param_whitelist[pkey]`, and `allowed_targets` **when the key is explicitly present in `arguments`**.
  - Meanwhile, `WorkspaceVaultMCPApp` supplies permissive server-side fallback defaults (`amount=250.0`, `project_code="PRJ-ATLAS"`, `target="cloud-infra-escrow"`, `unit_price_usd=100.0`, `max_penalty_pct=8.0`, `contract_id="NDA-DEFAULT"`, `warranty_tier="24M"`).
  - Consequently, calling `reserve_cloud_budget` or `commit_negotiated_contract` with `arguments={}` passes `LeafVerifier` (`200 OK`) even under `max_amount=10.0`, `numeric_bounds={"unit_price_usd": 50.0, "max_penalty_pct": 2.0}`, `allowed_targets=["compliance-ledger"]`, and `param_whitelist={"project_code": ["PRJ-RESTRICTED"]}`, charging `$250.0` against `"cloud-infra-escrow"` for `"PRJ-ATLAS"`!
- **Required Remediation**:
  1. **Offline Per-Tool Required-Constraint Enforcement in `PermissionLattice.check_invocation`** ([lattice.py](file:///Users/hulalala/Desktop/A/lineage/protocol/lattice.py)):
     - Define canonical tool parameter schemas (so multi-tool lattices like `["legal_redline_review", "commit_negotiated_contract"]` or `["reserve_cloud_budget", "query_operation_status"]` only require parameters applicable to the invoked `tool`!), plus canonical implicit tool targets (`reserve_cloud_budget -> "cloud-infra-escrow"`, `procure_vendor_quote -> "vendor-procurement-escrow"`, `record_compliance_note -> "compliance-ledger"`, `execute_settlement -> ...`):
       - Spend tools (`reserve_cloud_budget`, `procure_vendor_quote`, `book_flight`, `book_hotel`, `execute_settlement`): if `self.max_amount is not None`, require an explicit finite numeric spend argument (`amount` / `price` / `total`) in `args`; if `self.allowed_targets is not None`, validate explicit `target` or the tool's canonical implicit target against `self.allowed_targets`.
       - `lock_joint_project`: if `self.allowed_targets is not None`, require explicit non-empty `required_targets` (or validate default targets) as a subset of `self.allowed_targets`.
       - Constrained parameters per tool (e.g., `commit_negotiated_contract`: `contract_id`, `warranty_tier`, `unit_price_usd`, `max_penalty_pct`; `commit_joint_change`: `change_id`; `sign_release`: `release_id`; `cohort_aggregate_stats` / `federated_cohort_aggregate`: `study_id`; `reserve_cloud_budget` / `procure_vendor_quote` / `record_compliance_note` / `lock_joint_project`: `project_code`; `legal_redline_review`: `contract_id`): if a parameter belongs to the invoked tool's schema AND is constrained in `self.numeric_bounds` or `self.param_whitelist`, **reject its omission offline (`False`)** at `LeafVerifier`!
  2. **Remove Silent Financial/Contract Fallback Defaults in `WorkspaceVaultMCPApp`** ([peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L808-L935)): Require explicit `amount`, `project_code`, `contract_id`, `warranty_tier`, `unit_price_usd`, and `max_penalty_pct` on mutating Vault tools (returning `400` if omitted), while ensuring existing callers in `peer_apps.py` / tests pass explicit arguments.

---

### `[HIGH-M10-03]` Suffix-Only Scanner Check & Overridable `allowed_scanner_suffix` in `verify_compliance_attestation` Allows Cross-Domain SoD Attestation Forgery
- **Locations**:
  - [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L1933-L1988) (`action == "verify_compliance_attestation"`)
  - [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L982-L995) (`sign_release`)
- **PoC**: `Milestone10QAReviewSuite.test_04_poc_high_m10_03_suffix_only_compliance_attestation_forgery` in [qa_milestone10_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone10_review.py#L394-L454).
- **Root Cause & Impact**:
  - `verify_compliance_attestation` only checks `scanner_spiffe.endswith(allowed_suffix)` where `allowed_suffix = "/sa/assistant-dave"`. Any workload in **any** federated trust domain or namespace whose ServiceAccount ends with `/sa/assistant-dave` (e.g., `spiffe://org-alpha.io/ns/lineage-alpha/sa/assistant-dave` in Developer Alice's own organization!) holds a valid federated SVID and satisfies `.endswith("/sa/assistant-dave")`, defeating cross-organization Separation-of-Duties scanner attestation!
  - In addition, `verify_compliance_attestation` lacks `jti` anti-replay tracking and `sign_release` ignores any caller-supplied `arguments.get("artifact_sha256")` instead of verifying it matches `att_claims["artifact_sha256"]`.
- **Required Remediation**:
  1. Replace `allowed_scanner_suffix` suffix matching with an explicit allowlist of full canonical `SpiffeId` URIs (`allowed_scanner_spiffe_ids`, configurable on `LineageSidecar` / `ALLOWED_SCANNER_SPIFFE_IDS` env var and defaulting fail-closed to `frozenset({"spiffe://org-beta.io/ns/lineage-beta/sa/assistant-dave"})`), rejecting empty allowlists and cross-domain/cross-namespace lookalikes.
  2. Enforce `JTIReplayCache` on `att_claims["jti"]` (and require non-empty `jti`) inside `verify_compliance_attestation`, and in `sign_release` ([peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L982-L995)), if `arguments.get("artifact_sha256")` is provided, verify it equals `verified_att["artifact_sha256"]`.

---

### `[MEDIUM-M10-01]` Dual-Mode OAuth Inbound Sidecar Bypasses `RESOURCE_OWNER_SUB` on A2A JSON-RPC `parts[].data.private_tool`
- **Locations**:
  - [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L1178-L1209) (`_handle_inbound_oauth_request`) vs [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L728-L736) (`_handle_inbound_request`)
- **PoC**: `Milestone10QAReviewSuite.test_05_poc_medium_m10_01_oauth_dual_mode_a2a_jsonrpc_private_tool_bypass` in [qa_milestone10_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone10_review.py#L456-L545).
- **Root Cause & Impact**:
  - Unlike `_handle_inbound_request` (`lines 728-736`), `_handle_inbound_oauth_request` (`lines 1178-1193`) only checks top-level `body_json.get("private_tool")` and ignores `body_json.get("tool")` as well as standard A2A v1.0 JSON-RPC `params.message.parts[].data` (`private_tool` / `tool`).
  - A foreign OAuth Bearer caller sending `POST /a2a` with `parts: [{"data": {"private_tool": "hr_salary_read"}}]` bypasses Sidecar `403 CROSS_PRINCIPAL_DENIED` and reaches the upstream `app` container with `X-LCT-Decision: ALLOW_OAUTH_FLAT_SCOPE`.
- **Required Remediation**:
  - Extract a single shared helper `_extract_inbound_tool_and_args(norm_path, body_json)` used by both `_handle_inbound_request` and `_handle_inbound_oauth_request` so A2A JSON-RPC `parts[].data.{private_tool, tool}` and top-level `{private_tool, tool}` are enforced identically across LCT and OAuth modes.

---

### `[MEDIUM-M10-02]` `DomainUserGatewayService` Unhandled `500` on SSRF / Malformed Token, Unchecked `mtls_bundle=None` SSRF (`verify=False`), & Cross-Domain `sender_jkt` Acceptance
- **Locations**:
  - [user_gateway.py](file:///Users/hulalala/Desktop/A/lineage/federation/user_gateway.py#L293-L307) (`/v1/gateway/mint-root` `sender_jkt`)
  - [user_gateway.py](file:///Users/hulalala/Desktop/A/lineage/federation/user_gateway.py#L325-L387) (`/v1/gateway/dispatch`)
- **PoC**: `Milestone10QAReviewSuite.test_06_poc_medium_m10_02_user_gateway_500_ssrf_and_foreign_sender_jkt` in [qa_milestone10_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone10_review.py#L547-L669).
- **Root Cause & Impact**:
  1. **Unhandled `500` Exceptions**: In `/v1/gateway/dispatch`, `decode_token(compact_tok)` (`line 326`) and `validate_locator_host(...)` (`line 370`) are unguarded, returning `500 internal_error` instead of deterministic `400`/`403` JSON errors on malformed tokens or forbidden SSRF targets (`https://8.8.8.8:8443`), and `parsed` is not cryptographically verified against the local CA's public key before dialing upstream.
  2. **SSRF & Disabled TLS Verification When `mtls_bundle is None`**: When `self.mtls_bundle is None` (`lines 367-380`), `validate_locator_host` is skipped completely AND `verify=False` disables TLS verification on `https://` URLs.
  3. **Cross-Domain `sender_jkt` Acceptance on `/v1/gateway/mint-root`**: Lines `294-305` allow a foreign-domain mTLS caller (`e2e-user-gateway` in `org-alpha.io`) — or ANY unauthenticated caller when `mtls_bundle is None` — to pass `"sender_jkt": <foreign_jkt>` and obtain an `org-beta.io` `RootBlock` bound to a foreign-domain keypair!
- **Required Remediation**:
  1. In `/v1/gateway/mint-root`, strictly bind `eff_sender_jkt = self.identity.jkt` (rejecting any `req_sender_jkt != self.identity.jkt` with `403 SENDER_JKT_MISMATCH`), ensuring every `RootBlock` minted via `DomainUserGatewayService` is holder-bound to the local domain's user gateway keypair (so even a stolen token replayed by `e2e-user-gateway` against `assistant-bob` itself fails `403 DPOP_FAILED`!).
  2. In `/v1/gateway/dispatch`, wrap `decode_token` + `verify_root_block_signature_ignoring_expiry` (plus expiry check) in `try/except (TokenError, CryptoError)` -> `403 INVALID_GATEWAY_ROOT_TOKEN`, ALWAYS enforce `validate_locator_host(sp_t.hostname, allowed_cidrs=self.allowed_locator_cidrs)` (catching `LocatorError` -> `403 FORBIDDEN_DISPATCH_TARGET`, defaulting `allowed_locator_cidrs` to RFC1918 + `127.0.0.0/8` only when `mtls_bundle is None`), and reject `https://` targets when `mtls_bundle is None` instead of setting `verify=False`.

---

### `[LOW-M10-01]` Unsigned `cohort_digests` JSON Dicts in `federated_cohort_aggregate` (`S6` Defense-in-Depth)
- **Location**: [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L728-L755) (`cohort_aggregate_stats`) & [peer_apps.py](file:///Users/hulalala/Desktop/A/lineage/workspace_agents/peer_apps.py#L1035-L1090) (`federated_cohort_aggregate`).
- **Detail & Suggestion**: `federated_cohort_aggregate` properly enforces `raw_pii_present is False`, `desensitized is True`, `study_id` match, sample bounds, and `>= 2` distinct `institution` strings, but `cohort_digests` are plain unsigned JSON dicts (so a compromised orchestrator could synthesize fake institution names without querying Hospital-B and Institution-C). Having `cohort_aggregate_stats` attach a lightweight SVID-signed digest JWS (`lct-cohort-digest+jwt`) verified by `Shared-Vault`'s Sidecar against `trust_resolver` (confirming `>= 2` distinct verified institution workload SPIFFE IDs) will make Healthcare Federated Cohort Aggregation (`S6`) cryptographically tamper-evident end-to-end.

---

## 3. Re-Verification Gate for Sign-Off

Once `code-engineer` remediates `[CRITICAL-M10-01]`, `[HIGH-M10-01..03]`, `[MEDIUM-M10-01..02]` (and optionally `[LOW-M10-01]`):
1. All existing unit/integration suites (`lineage.tests.run_all`, `qa_milestone9_signoff`) + new regression tests for all 6 findings must pass with `0` warnings;
2. Execute a fresh Round-2 Milestone 10 live 3-cluster Kind rehearsal (`alpha`, `beta`, `pay`, `0` `audit` cluster, real Keycloak 26.5.2 + domain-sovereign `beta-sts` / `payment-sts` logins + real `qwen2.5:3b`) verifying `12/12` scenarios PASS, then tear down all `lctmh-*` clusters cleanly;
3. Re-run `bash lineage/scripts/push_to_github.sh --scope workspace --dry-run` (`0` secret hits).
