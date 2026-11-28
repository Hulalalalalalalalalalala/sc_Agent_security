# Milestone 11 Independent Code, Polyglot Sidecar Security & Compliance QA Report

- **Reviewer**: `k8s-qa-reviewer` (Independent Code Quality & System Compliance Session)
- **Milestone**: Milestone 11 — Real-World Open-Source `Pi` Agent (`@mariozechner/pi-agent-core@0.73.1` + `@mariozechner/pi-ai@0.73.1`) Integration Behind Unmodified Python `LineageSidecar`
- **Verification Suite**: [qa_milestone11_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone11_review.py) (`8/8 PASS`, `0` warnings)
- **Automated Baseline Executed**:
  - Node.js `Pi` Unit Suite ([test_pi_agent.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/test_pi_agent.mjs)): `3/3 PASS`
  - Python Full Regression & Benchmark Suite (`lineage.tests.run_all`): `104/104 PASS` (`0` warnings)
  - Milestone 9 + Milestone 10 Sign-Off Suites (`qa_milestone9_signoff`, `qa_milestone10_signoff`): `15/15 PASS` (`0` warnings)
  - GitHub Pre-Flight Dry-Run ([push_to_github.sh](file:///Users/hulalala/Desktop/A/lineage/scripts/push_to_github.sh)): `PASS` (`workspace` & `lineage-only`, `0` `node_modules/` staged, `0` leaked keys/tokens)
- **VERDICT**: **`NEEDS_FIX`** (`1` Critical, `2` High, `1` Medium, `1` Low)

---

## 1. Executive Summary & Verified Security Positives

Milestone 11 delivers a genuine, non-mocked integration of `@mariozechner/pi-agent-core@0.73.1` and `@mariozechner/pi-ai@0.73.1` ([package.json](file:///Users/hulalala/Desktop/A/lineage/pi_agent/package.json#L10-L14), [server.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/server.mjs#L17-L41)) running in an isolated non-root `USER node` container ([Dockerfile](file:///Users/hulalala/Desktop/A/lineage/pi_agent/Dockerfile#L20)) strictly bound to `127.0.0.1:9001` behind Python `LineageSidecar`.

### Verified Positive Invariants
1. **Real Open-Source `Pi` Agent Runtime & Zero Shell Exposure**: Confirmed `shell_tools_exposed: false` (`FORBIDDEN_SHELL_TOOL_NAMES` completely absent; only 6 workspace tools registered in [server.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/server.mjs#L616-L623)).
2. **Pod & ServiceAccount Least Privilege**: `sa/pi-assistant-alice` is excluded from `AUTHORIZED_GATEWAY_SA` (`e2e-user-gateway` only in [config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L2145), live `pi_assistant_alice_sa_mint_root_http: 403`), enforces `RESOURCE_OWNER_SUB=user:alice@org-alpha.io` ([config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L2216)), disables `automountServiceAccountToken`, withholds `lct-sa-token` and `lct-mtls-ram` from the `app` container ([config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L860-L863)), and shares `/var/run/lct-loopback/secret` at mode `0640` with `fsGroup: 2000` ([bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L635-L651)).
3. **Constant-Time Loopback Auth & Cross-Tenant/Task Wallet Checks**: Missing or forged `X-LCT-Loopback-Auth` returns `403` on both `server.mjs` ([lct_sdk.mjs](file:///Users/hulalala/Desktop/A/lineage/sdk/node/lct_sdk.mjs#L309-L320)) and `LineageSidecar` ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L1712-L1715)); cross-tenant (`user:mallory@org-alpha.io`) and cross-task reuse of `chdl-...` and `cdhdl-...` return `403 CROSS_TENANT_OR_TASK_CONSENT_DENIED` and `403 CROSS_TENANT_OR_TASK_DIGEST_DENIED` ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L2579-L2594), [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L2774-L2789)).
4. **Live 3-Cluster Rehearsal & Host Hygiene**: Audited all files in [20261128-m11-pi-agent-case-study-rehearsal](file:///Users/hulalala/Desktop/A/lineage/k8s/runs/20261128-m11-pi-agent-case-study-rehearsal/REHEARSAL_REPORT.md) (`central_audit_collector_deployed: false`, `reconstructed_complete: true`, `unreachable_nodes: {}`, `0` leaked secrets/wire tokens, `0` residual `lctmh-*` containers, `kubectl` context `kind-agent-identity-lab`, untouched `README.md`/`lab/`/`src/`/`paper/`/prior `lineage/reviews/*`).

However, our adversarial audit and empirical PoCs uncovered **5 security & compliance defects** (`1` Critical, `2` High, `1` Medium, `1` Low) across the new polyglot Sidecar boundary and `Pi` server that must be remediated before sign-off.

---

## 2. Detailed Findings & Remediation Specifications

### `[CRITICAL-M11-01]` Opaque Wallet Exfiltration & Plaintext `http://` Downgrade / SSRF Bypassing `WorkloadMTLSBundle`

- **Severity**: **Critical**
- **Locations**:
  - [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L527-L540) (`_outbound_verify_kwarg`)
  - [mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L948-L980) (`WorkloadMTLSBundle.verify_for_target`)
  - [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L2597-L2601) (`call_mcp_coauth` / `call_peer_coauth` dispatch)
  - [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L2698-L2796) (`call_tool` `raw_target_url` + `digest_handles` expansion)
  - [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L3069-L3077) (`delegate_agent` `target_url` + caller `delegate_jkt`)
  - [lct_sdk.mjs](file:///Users/hulalala/Desktop/A/lineage/sdk/node/lct_sdk.mjs#L250-L285) (`callMCPToolCoAuth` / `callPeerCoAuth` `targetUrl`)
- **Vulnerability & Empirical PoC**:
  1. **Plaintext `http://` mTLS Downgrade**: When `self._mtls_bundle is not None`, `_outbound_verify_kwarg` / `WorkloadMTLSBundle.verify_for_target` builds and returns an `ssl.SSLContext` without verifying that `target_url` uses the `https://` scheme. Because `httpx.Client(verify=ssl_ctx)` ignores `verify` on `http://` URLs, supplying any `http://...` `target_url` silently bypasses X.509/SPIFFE mTLS verification and transmits `Authorization: DPoP <compact_token>` in cleartext.
  2. **Complete Opaque Wallet Exfiltration**: `_peer_consent_wallet` (`chdl-...`) and `_cohort_digest_wallet` (`cdhdl-...`) are designed to keep raw consent tokens, `CoAuthorizedToken`s, and `digest_jws` (`lct-cohort-digest+jwt`) strictly inside `LineageSidecar` out of reach of a compromised polyglot `app` container. Yet `call_mcp_coauth`, `call_peer_coauth`, and `call_tool` with `digest_handles` accept an unverified caller-supplied `target_url` (and in `call_peer_coauth`, an arbitrary caller-supplied `delegate_jkt`). In `qa_milestone11_review.py::test_03`, with a real `WorkloadMTLSBundle` attached to `alice_sc`, a local listener at `http://127.0.0.1:<ephemeral>/mcp` invoked via `call_mcp_coauth` + `digest_handles` received `200 OK` along with **both** the raw `CoAuthorizedToken` (`requester_chain` + `owner_consent_chain`) in `Authorization` **and** the unredacted `digest_jws` in `cohort_digests` over cleartext HTTP.
- **Remediation**:
  1. In `WorkloadMTLSBundle.verify_for_target` ([mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L948-L980)) and `LineageSidecar._outbound_verify_kwarg` ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L527-L540)): whenever `mtls_bundle` is active and `target_url` is provided, strictly require `urlsplit(target_url).scheme.lower() == "https"` (raise `MTLSError` / reject with `403` on non-HTTPS URLs across all mTLS Sidecar outbound paths).
  2. Whenever opaque handles (`consent_handle` in `call_mcp_coauth` / `call_peer_coauth` / `call_tool` / `delegate_agent`, or `digest_handles` in `call_tool`) are redeemed, **forbid caller-supplied `target_url`** (`403 UNVERIFIED_TARGET_URL_FORBIDDEN_FOR_OPAQUE_HANDLE`) and require resolution exclusively through `self.directory_client` (CA-signed `AgentCard` verified by `TrustBundleResolver`, pinning `eff_spiffe_id = card.spiffe_id` and `delegate_jkt = card.jkt`). Remove `targetUrl` from `callMCPToolCoAuth` and `callPeerCoAuth` in [lct_sdk.mjs](file:///Users/hulalala/Desktop/A/lineage/sdk/node/lct_sdk.mjs#L250-L285) (and [lct_sdk.d.ts](file:///Users/hulalala/Desktop/A/lineage/sdk/node/lct_sdk.d.ts)).

---

### `[HIGH-M11-01]` Cross-Domain `owner_oidc_token` Exfiltration via Untrusted Yellow Pages Poisoning & Unchecked Peer Consent Token Binding

- **Severity**: **High**
- **Locations**:
  - [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L2335-L2560) (`request_peer_consent`)
  - [server.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/server.mjs#L192-L228) & [server.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/server.mjs#L367-L493) (`request_peer_owner_consent`, `call_peer_diagnostics`, `call_peer_private_tool`, `call_peer_cohort_stats`)
- **Vulnerability & Empirical PoC**:
  1. **Cross-Domain OIDC Bearer Exfiltration**: Under Milestone 9–11's architecture, `alpha-directory` is an **untrusted Yellow Pages registry**. In [server.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/server.mjs#L378-L385), `request_peer_owner_consent` calls `sidecar.requestPeerConsent` with `requiredSkill: peerHandshakeSkill(peerKey)` (`"workspace.tech_review"` for `bob`) and Bob's live `ownerOidcToken`, **without** passing `trustDomain: "org-beta.io"`. In [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L2364-L2373), `request_peer_consent` selects the highest-priority `AgentCard` across *all* trust domains and transmits `owner_oidc_token` over the network without checking that `owner_oidc_token`'s principal/issuer domain matches `peer_card.trust_domain`. Verified in `qa_milestone11_review.py::test_04`: registering a `priority=1` `AgentCard` signed by `assistant-carol` (`org-payment.io`) advertising `workspace.tech_review` caused `alice_sc` to transmit Bob's (`org-beta.io`) live OIDC JWT directly to `org-payment.io`!
  2. **Out-of-Scope Consent Request & Unchecked Returned Token Claims**: In [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L2376-L2380) and `L2434`, if a prompt-injected LLM requests `req_tools_hs` disjoint from `active_tok.leaf_permissions.tools`, `inter_hs.is_empty()` silently falls back to `active_tok.leaf_permissions` and still transmits `owner_oidc_token` + `req_tools_hs` to the peer instead of failing `403` locally in 0 RTT. And on response ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L2521-L2548)), `request_peer_consent` does not verify `parsed_hs_consent.task_id == active_tok.task_id`, `parsed_hs_consent.sub != active_tok.sub`, `parsed_hs_consent.root.issuer_trust_domain == peer_card.trust_domain`, or `parsed_hs_consent.holder_spiffe_id == self.identity.spiffe_id` / `holder_cnf_jkt == self.identity.jkt` before caching the handle and returning `200`.
- **Remediation**:
  1. In `request_peer_consent` ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L2335-L2560)):
     - Enforce `set(req_tools_hs).issubset(active_tok.leaf_permissions.tools)` and `not inter_hs.is_empty()` locally (`403 LATTICE_PERMISSION_DENIED`) before any network call.
     - Parse `owner_oidc` via `jws_parse_unverified(owner_oidc)` (`401` if malformed), extract the principal's home domain from `lct_sub` / `sub` / `email` (when `@<domain>` is present), and enforce `<oidc_domain> == peer_card.trust_domain` (`403 CROSS_DOMAIN_OIDC_EXFILTRATION_BLOCKED`) before sending any outbound request.
     - Verify on `parsed_hs_consent` that `task_id == active_tok.task_id`, `sub != active_tok.sub`, `root.issuer_trust_domain == peer_card.trust_domain`, `holder_spiffe_id == self.identity.spiffe_id`, and `holder_cnf_jkt == self.identity.jkt` (`403 invalid_peer_consent_token` on mismatch).
  2. In [server.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/server.mjs#L192-L228): add `peerTrustDomain(peerKey)` (`"org-beta.io"`, `"org-payment.io"`, `"org-alpha.io"`) and pass `trustDomain` / `targetTrustDomain` on `requestPeerConsent`, `callPeerDiagnostics`, `callPeerPrivateTool`, and `callPeerCohortStats` (wiring `target_trust_domain` in `lct_sdk.mjs` `callMCPTool` / `callMCPToolCoAuth`).

---

### `[HIGH-M11-02]` Inbound `op: "request_co_auth_consent"` Wire-Token Leak + `sendJson` Corruption (`"[REDACTED]"`), and Default `digest_jws` Leak on `call_mcp_coauth`

- **Severity**: **High**
- **Locations**:
  - [server.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/server.mjs#L689-L702) & [server.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/server.mjs#L1010-L1018)
  - [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L991-L1021) (`_dispatch_inbound`)
  - [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L2930-L2950) (`call_tool` / `call_mcp_coauth` `redact_digest_jws`)
- **Vulnerability & Empirical PoC**:
  1. **Inbound `request_co_auth_consent` Leak & Corruption**: `alpha-ca` configures `CONSENT_ISSUER_POLICY` for `pi-assistant-alice=user:alice@org-alpha.io:...` ([config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L2128)). However, when a peer requests Alice's co-authorization consent from `pi-assistant-alice`, `LineageSidecar._dispatch_inbound` forwards the raw `user_oidc_token` into `server.mjs:689-702`, `server.mjs` receives the raw `compact_token` from `request_local_ca_consent` (violating `server.mjs` line 6: `ZERO raw LCT/OIDC/JWS wire tokens`), **and** `startPiAgentServer`'s `sendJson` (`server.mjs:1010-1011`) passes `response` through `redactSecrets()`, overwriting `compact_token` with `"[REDACTED]"` (confirmed in `qa_milestone11_review.py::test_05`) and breaking symmetric peer co-authorization to `pi-assistant-alice` with `403 invalid_peer_consent_token`!
  2. **Default `digest_jws` Leak on `call_mcp_coauth`**: In [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L2948), `redact_digest_jws` defaults to `False` even when an opaque `consent_handle` (`call_mcp_coauth`) was used. If an LLM invokes `call_peer_private_tool` ([server.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/server.mjs#L436-L442), which omits `redactDigestJws: true`) with `tool_name="cohort_aggregate_stats"`, `LineageSidecar` returns the raw 3-part `digest_jws` (`lct-cohort-digest+jwt`) over loopback to the Node.js process.
- **Remediation**:
  1. Handle inbound `op == "request_co_auth_consent"` natively inside `LineageSidecar._dispatch_inbound` ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L990)) whenever `self._local_ca_url`, `self._sa_token_path`, and `self.resource_owner_sub` are configured (executing local CA consent minting inside `LineageSidecar` after inbound LCT + mTLS channel-binding verification, forwarding `numeric_bounds`, `allowed_targets`, `param_whitelist`, `max_calls`, and `hop_segment` without ever exposing `user_oidc_token` or `compact_token` to the upstream polyglot app container), and remove raw `request_co_auth_consent` pass-through from `server.mjs`.
  2. In [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L2948), default `redact_digest_jws` to `True` whenever an opaque `consent_handle` (`bool(raw_consent_handle)`) was used (`bool(body.get("redact_digest_jws", bool(raw_consent_handle)))`). Also enforce true LRU + TTL eviction (`move_to_end` on lookup + `created_at` TTL expiry) in `_peer_consent_wallet` and `_cohort_digest_wallet`.

---

### `[MEDIUM-M11-01]` `Pi` Server `max_turns` & One-Shot `timeout_ms` Bypassed Across `follow_up_prompts`

- **Severity**: **Medium**
- **Locations**:
  - [server.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/server.mjs#L810-L845)
  - [lct_sdk.mjs](file:///Users/hulalala/Desktop/A/lineage/sdk/node/lct_sdk.mjs#L354-L369) (`createLoopbackAgentServer`)
  - Observed live in [pi_case_study_1_fin_prompt_injection.json](file:///Users/hulalala/Desktop/A/lineage/k8s/runs/20261128-m11-pi-agent-case-study-rehearsal/pi_case_study_1_fin_prompt_injection.json#L49-L50) (`"max_turns": 6, "turns_executed": 7`)
- **Vulnerability & Empirical PoC**:
  1. In [server.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/server.mjs#L810-L841), `stepTurnsExecuted` is reset to `0` before every prompt in `followUpPrompts` instead of enforcing `turnsExecuted >= maxTurns` across the entire task request. With up to 5 `follow_up_prompts`, a task configured with `max_turns = 2` executes `6` turns (`qa_milestone11_review.py::test_06`), and in the archived CS1 live rehearsal `turns_executed` (`7`) exceeded `max_turns` (`6`).
  2. `abortTimer = setTimeout(() => { agent.abort(); }, timeoutMs)` ([server.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/server.mjs#L820-L822)) is a one-shot timer with no `timedOut` check before iterating `followUpPrompts`. Because `agent.prompt()` resolves cleanly on `agent.abort()`, if `timeoutMs` fires during `userPrompt`, `pruneAbortedTail()` runs and all remaining `followUpPrompts` execute **with no active timeout**.
  3. Additionally, `createLoopbackAgentServer` in [lct_sdk.mjs](file:///Users/hulalala/Desktop/A/lineage/sdk/node/lct_sdk.mjs#L354-L369) buffers `req.on("data", ...)` without a `2 MiB` cap (unlike `server.mjs:1049`).
- **Remediation**:
  1. Track `let timedOut = false` in `abortTimer` (`timedOut = true; agent.abort();`), enforce `if (turnsExecuted >= maxTurns || timedOut) { agent.abort(); }` on `turn_end`, and break out of `followUpPrompts` immediately if `timedOut || turnsExecuted >= maxTurns` (and raise CS1's `max_turns` in [pi_case_study_e2e.py](file:///Users/hulalala/Desktop/A/lineage/k8s/pi_case_study_e2e.py#L86) from `6` to `8` or `10` so CS1 completes within its declared `max_turns` budget).
  2. Enforce a `2 MiB` body-size limit in `createLoopbackAgentServer` ([lct_sdk.mjs](file:///Users/hulalala/Desktop/A/lineage/sdk/node/lct_sdk.mjs#L354-L369)).

---

### `[LOW-M11-01]` Incomplete Cloud LLM API-Key & Embedded JWS Redaction / Pre-Push Scanner Coverage

- **Severity**: **Low**
- **Locations**:
  - [crypto.py](file:///Users/hulalala/Desktop/A/lineage/common/crypto.py#L553-L591) (`_EMBEDDED_API_KEY_RE`, `redact_sensitive`)
  - [ollama_client.py](file:///Users/hulalala/Desktop/A/lineage/agents/ollama_client.py#L81-L86) & [ollama_client.py](file:///Users/hulalala/Desktop/A/lineage/agents/ollama_client.py#L136-L148)
  - [server.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/server.mjs#L80-L82) & [server.mjs](file:///Users/hulalala/Desktop/A/lineage/pi_agent/server.mjs#L940)
  - [push_to_github.sh](file:///Users/hulalala/Desktop/A/lineage/scripts/push_to_github.sh#L143-L146)
- **Root Cause**:
  1. `_EMBEDDED_API_KEY_RE` in `crypto.py:555`, `server.mjs:80-81`, and `push_to_github.sh:143` matches `sk-[A-Za-z0-9]{20,}` (without `_-`), missing hyphenated OpenAI-compatible provider keys such as OpenRouter (`sk-or-v1-...`), OpenAI service-account keys (`sk-svcacct-...`), Groq (`gsk_...`), xAI (`xai-...`), HuggingFace (`hf_...`), and Gemini (`AIza...`).
  2. `crypto.py:589` only redacts a 3-part JWS on whole-string match (`value.startswith("eyJ")`), leaving JWS strings embedded inside larger log/error strings unredacted in Python `redact_sensitive`.
  3. `ollama_client.py:147` calls `redact_sensitive(data)` instead of `self._scrub_secret_text(...)`, and telemetry `endpoint` / `llm_endpoint` (`ollama_client.py:137`, `server.mjs:940`) does not strip URL userinfo/query parameters (`?key=...`).
- **Remediation**:
  1. Expand `_EMBEDDED_API_KEY_RE` across `crypto.py`, `server.mjs`, and `push_to_github.sh` to cover `sk-[A-Za-z0-9_-]{20,}`, `gsk_[A-Za-z0-9_-]{20,}`, `xai-[A-Za-z0-9_-]{20,}`, `hf_[A-Za-z0-9]{20,}`, and `AIza[A-Za-z0-9_-]{30,}`, and add `_EMBEDDED_JWS_RE` substring scrubbing in `crypto.py:redact_sensitive`.
  2. Route all `OllamaError` messages through `self._scrub_secret_text` and strip URL userinfo/query parameters from `endpoint` / `llm_endpoint` telemetry fields.
