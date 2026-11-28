# Milestone 11 Round-2 Live 3-Cluster Kind Rehearsal Report (`m11-r2`) — Hardened Polyglot `Pi` Agent (`@mariozechner/pi-agent-core`) Integration

- **Run ID**: `m11-r2` (Python benchmark non-regression sanity: `m11-r2-py-sanity`)
- **Archive Directory**: `lineage/k8s/runs/20261128-m11-r2-pi-agent-rehearsal/`
- **Execution Topology**: 3 Sovereign Kind Clusters (`lctmh-alpha --with-pi-agent`, `lctmh-beta`, `lctmh-pay`), **0 Central Audit Collector** (`central_audit_collector_deployed: false`), Untrusted Yellow Pages Registry (`alpha-directory`)
- **Identity & OIDC Providers**: Real `Keycloak 26.5.2` (`alpha-sts` for `org-alpha.io`), Sovereign `beta-sts` (`org-beta.io`), Sovereign `payment-sts` (`org-payment.io`)
- **Real Agent Framework**: `@mariozechner/pi-agent-core@0.73.1` + `@mariozechner/pi-ai@0.73.1` (`Node.js v22.23.5`, non-root `USER node`, `127.0.0.1:9001`) paired with hardened Python `LineageSidecar` (`pi-assistant-alice`, `2/2 Running`, `0` restarts)
- **LLM Backend**: Host Ollama `qwen2.5:3b` (`http://host.docker.internal:11434/v1/chat/completions`, greedy `temperature=0`)

---

## 1. Round-2 Security Remediation Verifications

| QA Finding | Verified Round-2 Behavior | Status |
| --- | --- | --- |
| **`[CRITICAL-M11-01]`** | `WorkloadMTLSBundle.verify_for_target` & `LineageSidecar._outbound_verify_kwarg` enforce `https://` (`MTLSError` / `403 PLAINTEXT_HTTP_FORBIDDEN_UNDER_MTLS`); caller-supplied `target_url` / `delegate_jkt` forbidden (`403 UNVERIFIED_TARGET_URL_FORBIDDEN_FOR_OPAQUE_HANDLE`) when redeeming `consent_handle` or `digest_handles` | **VERIFIED** |
| **`[HIGH-M11-01]`** | `request_peer_consent` enforces 0-RTT lattice subset check (`403 LATTICE_PERMISSION_DENIED`), verifies `owner_oidc_token` home `@<domain>` matches `peer_card.trust_domain` before any network call (`403 CROSS_DOMAIN_OIDC_EXFILTRATION_BLOCKED`), and verifies returned `LineageToken` `task_id`/`sub`/`issuer_trust_domain`/`holder_spiffe_id`/`holder_cnf_jkt`; `server.mjs` pins explicit `peerTrustDomain` (`org-beta.io` / `org-payment.io`) | **VERIFIED** |
| **`[HIGH-M11-02]`** | Inbound `op: "request_co_auth_consent"` handled natively inside `LineageSidecar._dispatch_inbound` (live K8s `symmetric_inbound_coauth_to_pi_alice`: `200 OK`, `owner_sub = user:alice@org-alpha.io`, `holder_spiffe_id = sa/assistant-bob`); `call_mcp_coauth` defaults `redact_digest_jws = True`; wallets enforce true LRU (`move_to_end`) + `600s` TTL | **VERIFIED** |
| **`[MEDIUM-M11-01]`** | Cumulative `turns_executed <= max_turns` (`7 <= 10`) & `timed_out: false` enforced across `follow_up_prompts`; `2 MiB` body cap (`413`) in both `server.mjs` and `lct_sdk.mjs` | **VERIFIED** |
| **`[LOW-M11-01]`** | Broadened cloud key patterns (`sk-*`, `gsk_*`, `xai-*`, `hf_*`, `AIza*`), embedded 3-part JWS scrubbing in `redact_sensitive`, `OllamaError` secret scrubbing, and URL userinfo/query stripping on `endpoint` / `llm_endpoint` | **VERIFIED** |

---

## 2. Round-2 Live 3-Cluster Empirical Summary

| Case Study | Task ID | `turns_executed / max_turns` | `timed_out` | Total E2E (`ms`) | LLM ReAct (`ms`) | Sidecar mTLS + LCT + OIDC (`ms`) | DistributedAuditor |
| --- | --- | :---: | :---: | ---: | ---: | ---: | --- |
| **CS1**: Financial Risk Triage, Indirect Prompt Injection Defense & Symmetric Inbound Co-Auth | `pi-m11-r2-cs1-fin-inj` | `7 / 10` (`chatcmpl-166..236`) | `false` | `24,781.82` | `21,575.77` (`87.1%`) | `3,206.05` (`12.9%`) | `6` nodes, `17` entries, `347.32 ms`, `reconstructed_complete: true`, `anomalies: []` |
| **CS2**: Cross-Language Healthcare Federated Cohort Aggregation | `pi-m11-r2-cs2-med-fed` | `7 / 10` (`chatcmpl-127..868`) | `false` | `27,044.16` | `20,931.41` (`77.4%`) | `6,112.75` (`22.6%`) | `7` nodes, `21` entries, `934.36 ms`, `reconstructed_complete: true`, `anomalies: []` |

- **SA Zero-Privilege Probe**: `pi_assistant_alice_sa_mint_root_http = 403`
- **Symmetric Inbound Co-Auth to `pi-assistant-alice`**: `status_code = 200`, `owner_sub = "user:alice@org-alpha.io"`, `holder_spiffe_id = "spiffe://org-beta.io/ns/lineage-beta/sa/assistant-bob"`, `tools = ["commit_joint_change"]`
- **Python Non-Regression Sanity (`python_sanity/`, `m11-r2-py-sanity`)**: Scenarios `1, 6, 9` **`3/3 PASS`**
- **Immediate Cluster Teardown**: `0` active `lctmh-*` containers remaining; `kubectl` context restored to `kind-agent-identity-lab`.
