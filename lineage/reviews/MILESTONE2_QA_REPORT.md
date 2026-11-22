# Milestone 2 Independent Code Quality & Kubernetes Security QA Report (`lineage/agents/`, `lineage/k8s/`)

- **QA Reviewer**: `k8s-qa-reviewer` (Independent Read-Only Code Quality & System Compliance Session)
- **Audit Scope**:
  - Business & LLM Agents / MCP Servers: `/Users/hulalala/Desktop/A/lineage/agents/` (`ollama_client.py`, `specialist_apps.py`, `mcp_servers.py`)
  - Kubernetes Bootstrap, Manifests & E2E Driver: `/Users/hulalala/Desktop/A/lineage/k8s/` (`bootstrap_services.py`, `e2e_driver.py`, `Dockerfile`, `manifests/00..02-*.yaml`, `run-e2e-k8s-ollama.sh`, `cleanup-lineage-k8s.sh`)
  - E2E Run Evidence: `/Users/hulalala/Desktop/A/lineage/k8s/runs/20261118T142439Z/`
  - Live Cluster Inspection: `kind-agent-identity-lab` (`lineage-ctrl`, `lineage-alpha`, `lineage-beta`, `lineage-pay`, plus baseline `team1`, `keycloak`, `rossoctl-system`, `spire-system`)
- **Automated QA Verification Suite**: `/Users/hulalala/Desktop/A/lineage/reviews/qa_milestone2_review.py` (`8/8` empirical verification & boundary reproduction tests passing in `2.96s`)
- **Overall Milestone 2 Verdict**: **`NEEDS_FIX`** (**1 Critical, 2 High, 2 Medium, 1 Low**)

---

## 1. Checklist Verification Summary & Confirmed Strengths

### 1.1 Baseline Integrity, Milestone 1 Regression & Artifact Redaction (`PASS`)
1. **Zero Historical File Pollution (`test_01`)**: Verified via filesystem mtime scan against `lineage/__init__.py` that `/Users/hulalala/Desktop/A/README.md`, `/Users/hulalala/Desktop/A/lab/`, and `/Users/hulalala/Desktop/A/src/` have **0 modified files**.
2. **Zero Existing Namespace Disturbance (`test_02`)**: Live read-only `kubectl --context kind-agent-identity-lab` checks confirm all 3 Pods in `team1` (`weather-coordinator`, `weather-service-advanced`, `weather-tool-advanced`) remain `2/2 Running` with no new restarts, alongside healthy `keycloak`, `rossoctl-system`, and `spire-system` workloads. Zero cluster-scoped `ClusterRole` / `ClusterRoleBinding` / `CRD` objects were introduced by Milestone 2.
3. **Milestone 1 Regression Suite (`41/41 PASS`)**: Executed `python3 -m lineage.tests.run_all` using `/Users/hulalala/Desktop/A/src/cortex/authbridge/venv/bin/python3`; all **41/41** unit, concurrency, multi-process, and security regression tests passed cleanly (`9.70s`).
4. **Disk Artifact Redaction Compliance (`test_01`)**: Scanned all 14 files in `/Users/hulalala/Desktop/A/lineage/k8s/runs/20261118T142439Z/` (`cluster_audit_entries_redacted.json`, `scenario1..5_*.json`, `run.log`, etc.): **0 PEM private keys**, **0 raw 3-part JWS/SVID strings (`eyJ...`)**, **0 raw LCT tokens (`lct1.` / `lctm1.`)**, and **0 private JWK fields (`d`, `p`, `q`, `dp`, `dq`, `qi`)**.

### 1.2 Real Ollama (`qwen2.5:3b`) Integration & Dual-Container Socket Isolation (`PARTIAL PASS` — see `[HIGH-M2-01]`)
1. **Genuine LLM Inference & Grounded Tool Calling (`test_03`)**: Audited `lineage/agents/ollama_client.py:48-194`, `lineage/agents/specialist_apps.py:244-312, 464-533, 591-604, 725-736, 876-890`, and live `127.0.0.1:11434/v1`. All agents execute real HTTP `POST /chat/completions` against Ollama `qwen2.5:3b` (`system_fingerprint = "fp_ollama"`), parse live JSON intent plans (`OrchestratorAlphaApp`), execute OpenAI-schema `tool_calls` (`FlightSpecialistApp`, `HotelSpecialistApp`), and synthesize grounded confirmation text (`SettlementConvergerApp`) with zero mocked model responses.
2. **Live TCP Listener Boundaries & Constant-Time Loopback Secret Check (`test_02`, `test_06`)**: Read-only inspection of `/proc/net/tcp` across all 7 dual-container (`2/2`) Pods (`orchestrator-alpha`, `flight-specialist`, `hotel-specialist-primary`, `hotel-specialist-backup`, `settlement-converger`, `travel-ops-mcp`, `payment-vault-mcp`) confirmed every Pod listens strictly on:
   - `0.0.0.0:8080` (`lct-sidecar` inbound A2A/MCP listener),
   - `127.0.0.1:8081` (`lct-sidecar` outbound `/v1/proxy/call` listener),
   - `127.0.0.1:9001` (`app` business container listener).
   Both `:8081` (`lineage/sidecar/proxy.py:569-572`) and `:9001` (`lineage/agents/specialist_apps.py:28-35`, `lineage/agents/mcp_servers.py:94-100`) enforce `hmac.compare_digest` on `X-LCT-Loopback-Auth` provisioned via `emptyDir: {medium: Memory}` (`readOnly: true` on `app`).
3. **Critical Container Credential Isolation Gap Found (`[HIGH-M2-01]`)**: However, `02-data-plane-agents-and-mcp.yaml` omits `automountServiceAccountToken: false`, causing Kubernetes to mount `/var/run/secrets/kubernetes.io/serviceaccount/token` into the untrusted `app` container as well as `lct-sidecar`.

### 1.3 `FederationCAService` & Service Interface Boundary Audit (`NEEDS_FIX`)
1. **Deterministic Namespace -> Trust Domain & Control-Plane Role Mapping (`PASS`, `test_04`)**: `FederationCAService._resolve_authorized_spiffe` (`lineage/k8s/bootstrap_services.py:145-200`) computes `(trust_domain, workload_path)` strictly from the verified K8s SA subject `(k8s_ns, k8s_sa)` rather than request body parameters. A workload in `lineage-beta` can never obtain an SVID in `org-alpha.io` or `org-payment.io`, cannot impersonate `/ns/sys/sa/revocation`, and non-gateway workloads are blocked (`403 gateway_only_endpoint`) from `/v1/ca/mint-root-token` (`bootstrap_services.py:250-255`).
2. **Security & Validation Vulnerabilities Found (`NEEDS_FIX`)**: Deep boundary inspection and empirical testing (`test_05`, `test_07`, `test_08`) uncovered **1 Critical, 2 High, 2 Medium, and 1 Low** issues detailed below.

---

## 2. Detailed Findings & Required Fixes

### 2.1 CRITICAL Findings

#### [CRITICAL-M2-01] Unguarded Test/Debug Switches Exposed on Public `/a2a/task` Business Endpoints Enable SSRF, Raw LCT Token + DPoP Exfiltration, Cross-User Inbox Leakage, and Unrevoked Double-Booking / Thread-Sleep DoS
- **Locations**:
  - `lineage/agents/specialist_apps.py:408-412, 442-461` (`HotelSpecialistApp._dispatch`)
  - `lineage/agents/specialist_apps.py:606-611, 613-624, 649-661` (`SettlementConvergerApp._dispatch`)
  - `lineage/agents/specialist_apps.py:811-813, 834-836, 910-911, 930` (`OrchestratorAlphaApp._dispatch`)
  - `lineage/sidecar/proxy.py:580-598, 909-914` (`LineageSidecar._dispatch_outbound`)
  - `lineage/resilience/coordinator.py:329, 341-356` (`ResilientDelegationCoordinator.return_result_with_skip_level_fallback`)
- **Vulnerability Mechanisms & Empirical Reproduction (`test_07`)**:
  1. **Authenticated Raw Token & DPoP Exfiltration + SSRF via `override_direct_parent_url` (`specialist_apps.py:621, 835`, `coordinator.py:329-356`)**:
     Public `/a2a/task` on `orchestrator-alpha` and `settlement-converger` accepts `override_direct_parent_url` from the untrusted JSON payload and passes it as `direct_parent_return_url` into `return_result_with_skip_level_fallback`. This overrides the cryptographically attested `direct_hop.issuer_return_endpoint` without even calling `validate_clean_endpoint_url`, causing `settlement-converger`'s `lct-sidecar` to sign a live DPoP proof for `<attacker_url>/v1/task-result` and `POST` **`Authorization: DPoP lct1...`** (the raw capability token!) + `result_payload` directly to an attacker-controlled endpoint.
  2. **Arbitrary Pod-Network / Host-Ollama SSRF via `sync_hook_url` (`specialist_apps.py:606-611, 834`)**:
     `SettlementConvergerApp` unconditionally executes `httpx.post(str(sync_hook_url), ...)` from inside the `app` container (which shares Pod `127.0.0.1` and has direct network access to `http://host.docker.internal:11434/api/...` and internal `lineage-*` services) with zero URL validation or test-mode gate.
  3. **Cross-User / Cross-Task Result & Raw Token Leakage via `inspect_inbox` and `inspect_zombie_telemetry` (`specialist_apps.py:408-412, 811-813`, `sidecar/proxy.py:580-598`)**:
     `OrchestratorAlphaApp` (`tid = str(body.get("inspect_task_id", task_id))`) and `HotelSpecialistApp` (`inspect_zombie_telemetry`) trust caller-supplied `inspect_task_id` on the public `/a2a/task` endpoint, and `LineageSidecar._skip_level_results` / `_direct_results` are keyed solely by `task_id` without checking `sub` or `request_id`. In `test_07`, User **Bob** (`user:bob@org-alpha.io`, holding a token strictly for `task-bob-own`) sends `{"op": "inspect_inbox", "inspect_task_id": "task-alice-secret-skip"}` and receives `200 OK` containing **Alice's confidential `result_payload` AND Alice's unredacted `compact_lineage_token` (`lct1...`)** from `SkipLevelReceipt.to_dict()`.
  4. **Unrevoked Double-Booking, Thread-Starvation DoS & `500` Crash via `simulate_primary_zombie_delay_sec` (`specialist_apps.py:442-461, 910-911`)**:
     - When `0 < simulate_primary_zombie_delay_sec < hotel_timeout_sec` (e.g., `0.05s < 10.0s` in `test_07`), `hotel-specialist-primary` sleeps `0.05s` while its token is **still valid and unrevoked**, executes a real `reserve_hotel` booking (`200 OK`) on `travel-ops-mcp`, and then returns `503` so `orchestrator-alpha` fails over to `backup` and books a **second hotel** for the same task (`2` charges for `1` trip).
     - Passing `"simulate_primary_zombie_delay_sec": 86400` blocks worker threads for 24 hours; passing JSON string `"inf"` raises uncaught `OverflowError` (`HTTP 500` in `test_07`).
- **Required Fix**:
  1. Gate all fault-injection / synchronization hooks (`simulate_primary_zombie_delay_sec`, `sync_hook_url`, `override_direct_parent_url`, `override_airline_amount`, `override_hotel_amount`) behind an explicit opt-in environment variable (e.g., `LCT_ENABLE_E2E_FAULT_HOOKS=true`, disabled by default in `LineageSidecar` / `specialist_apps.py`) **and**:
     - Validate `sync_hook_url` and `override_direct_parent_url` via `validate_clean_endpoint_url` + strict cluster/loopback allowlist (never attach `Authorization: DPoP <compact_tok>` to an unattested `override_direct_parent_url` — if simulating unreachable direct parent in Scenario 3A, simulate transport failure locally before sending secrets over the network, or restrict override strictly to closed loopback port `http://127.0.0.1:9` when fault hooks are enabled!).
     - Validate `simulate_primary_zombie_delay_sec` and all timeout parameters (`hotel_timeout_sec`, `timeout`, `return_timeout_sec`) as finite numbers within safe bounds (e.g., `0.0 <= delay <= 30.0`, `0.1 <= timeout <= 90.0`), and require `simulate_primary_zombie_delay_sec > hotel_timeout_sec` when used via `OrchestratorAlphaApp`.
  2. Enforce strict tenant & task isolation on `inspect_inbox` / `inspect_zombie_telemetry`:
     - Store `(sub, item)` in `LineageSidecar._BoundedTaskListStore` (`_skip_level_results`, `_direct_results`) and filter by `(task_id, sub)` inside `LineageSidecar._dispatch_outbound` (`inspect_inbox`).
     - Redact `compact_lineage_token`, `child_svid`, and `jws_signature` when returning inbox views to business containers.
     - In `OrchestratorAlphaApp` and `HotelSpecialistApp`, forbid cross-user inspection (`sub` must match the target task's `sub`; if cross-task `inspect_task_id` is needed for E2E Scenarios 2A/3B, permit it only when `sub` matches the recorded task owner AND `LCT_ENABLE_E2E_FAULT_HOOKS=true`).

---

### 2.2 HIGH Findings

#### [HIGH-M2-01] Dual-Container (`2/2`) Kubernetes Pods Automount ServiceAccount JWT Into Untrusted `app` Container, Enabling `lct-sidecar` Identity Bypass
- **Location**:
  - `lineage/k8s/manifests/02-data-plane-agents-and-mcp.yaml:36-55, 153-172, 233-254, 315-336, 401-420, 481-495, 554-568`
  - `lineage/k8s/bootstrap_services.py:11-16, 225-247`
- **Vulnerability Mechanism & Live Cluster Proof (`test_02`)**:
  All 7 `2/2` Deployments omit `automountServiceAccountToken: false` on `spec.template.spec`. Live read-only inspection (`kubectl -n lineage-alpha get pod -l app=orchestrator-alpha -o jsonpath=...`) confirms `/var/run/secrets/kubernetes.io/serviceaccount` (`kube-api-access-*`) is mounted into **both** `app` and `lct-sidecar`.
  Because `app` runs in the shared Pod network namespace and `FederationCAService` (`/v1/ca/issue-workload`) authenticates callers solely by their K8s SA JWT, a compromised or prompt-injected `app` container can read `/var/run/secrets/kubernetes.io/serviceaccount/token`, generate its own `ES256` private key in RAM, call `POST http://federation-ca.lineage-ctrl.svc.cluster.local:8090/v1/ca/issue-workload` directly, obtain a valid CA-signed SPIFFE SVID for the Pod's identity, and overwrite its `AgentCard` in `directory-svc` with a higher `version` — breaking the zero-key `app` container isolation boundary.
- **Required Fix**:
  1. Set `automountServiceAccountToken: false` on `spec.template.spec` in all 7 `2/2` Deployments in `02-data-plane-agents-and-mcp.yaml` (and set dedicated projected token volume on control-plane / gateway Pods as well).
  2. Mount a dedicated projected `serviceAccountToken` volume (`audience: "lct-federation-ca"`, `expirationSeconds: 600`, plus `configMap: kube-root-ca.crt`) **only** into `lct-sidecar` (never into `app`).

---

#### [HIGH-M2-02] Incomplete Kubernetes SA JWT Claims Validation (`iss`, `aud`, `nbf`, `iat`, Mandatory Finite `exp`), Missing PoP / Replay Guard, Unbounded `ttl_seconds`, and Cross-Domain Root Minting in `FederationCAService`
- **Location**:
  - `lineage/k8s/bootstrap_services.py:79-138` (`K8sServiceAccountVerifier`)
  - `lineage/k8s/bootstrap_services.py:225-320, 333-343` (`FederationCAService._dispatch` & `bootstrap_k8s_workload_identity`)
- **Vulnerability Mechanisms & Empirical Reproduction (`test_05`)**:
  1. **Missing `iss`, `aud`, `nbf`, `iat`, and Mandatory Finite `exp` Validation (`bootstrap_services.py:128-138`)**:
     - `verify_sa_jwt` never checks `claims["iss"]` (expected `"https://kubernetes.default.svc.cluster.local"`) or `claims["aud"]` (enabling cross-audience confused-deputy forwarding of tokens minted for other services).
     - `exp = claims.get("exp"); if exp is not None and float(exp) < time.time() - 30.0:` allows tokens **omitting `exp`** OR setting `"exp": "nan"` / `"exp": "inf"` (`float("nan") < ...` is `False`) to pass expiration checks indefinitely (`200 OK` in `test_05`), and ignores `nbf` / future `iat`.
  2. **Missing Key Proof-of-Possession (PoP), Missing `jti` Anti-Replay, and Unbounded / Non-Finite `ttl_seconds` (`bootstrap_services.py:225-247`)**:
     - `/v1/ca/issue-workload` signs SVIDs for an arbitrary `public_jwk` JSON object without verifying a PoP signature from the corresponding private key and without deduplicating request `jti`s in a `JTIReplayCache`.
     - `ttl_seconds=float(body.get("ttl_seconds", 3600.0))` has no upper cap and no finite/positive validation: `"ttl_seconds": 3153600000.0` mints a **100-year SVID** (`200 OK` in `test_05`), while `"ttl_seconds": "nan"` triggers an uncaught `CryptoError` returning **`500 internal_server_error`**.
  3. **Cross-Domain Root Minting & Unverified CA Audit Injection by `lineage-alpha/e2e-user-gateway` (`bootstrap_services.py:250-320`)**:
     - Although non-gateway callers are properly blocked (`403 gateway_only_endpoint`), `e2e-user-gateway` belongs to `lineage-alpha` (`org-alpha.io`), yet lines 259-260 (`req_td = str(body.get("trust_domain", "org-alpha.io")); ca = self.cas[req_td]`) allow it to mint Root Capability Blocks (`B_0`) signed by **`org-beta.io` or `org-payment.io`** (`200 OK` in `test_05`)!
     - `/v1/ca/emit-revocation-audit` (`lines 300-319`) emits Root-CA-signed `REVOCATION_ISSUED` audit entries from raw caller JSON fields without cryptographically verifying a `RevocationService`-signed `RevocationEvent`.
     - Malformed inputs (`trust_domain="nonexistent.io"`, missing keys, invalid lattice/token parameters) raise uncaught `KeyError` / `LatticeError` / `TokenError` -> **HTTP `500`** (`test_05`).
- **Required Fix**:
  1. In `K8sServiceAccountVerifier.verify_sa_jwt`: enforce `claims.get("iss") == self.expected_issuer`, verify `self.expected_audience` is in `claims.get("aud")`, validate mandatory finite `exp = require_finite_timestamp(claims.get("exp"), "exp")`, validate `iat` and `nbf` via `require_finite_timestamp` (with 30s skew), and return `(ns, sa, exp)`.
  2. On `/v1/ca/issue-workload`: require a short-lived PoP JWS (`typ="lct-ca-pop+jwt"`) signed by the workload's generated `KeyPair` binding `public_jwk`, `sa_jwt` SHA-256 hash, `iat`, and `jti` verified via `JTIReplayCache`; clamp `ttl_seconds` via `require_finite_timestamp` to `(1.0, min(7200.0, sa_exp - now + 30.0)]`.
  3. On `/v1/ca/mint-root-token` and `/v1/ca/emit-revocation-audit`: enforce `req_td == trust_domain` (`"org-alpha.io"` for `lineage-alpha/e2e-user-gateway`), verify a `RevocationEvent` signature against `self.resolver` inside `/v1/ca/emit-revocation-audit`, validate `Host` header syntax, and catch `(KeyError, ValueError, TypeError, CryptoError, IdentityError, TokenError, LatticeError)` returning `400`/`403`.

---

### 2.3 MEDIUM Findings

#### [MEDIUM-M2-01] Unauthenticated Cluster-Wide Audit Dump (`GET /v1/audit/entries`) Exposes Cross-Tenant Payloads and Raw `SkipLevelReceipt.compact_lineage_token`
- **Location**:
  - `lineage/audit/logger.py:209, 397-406` (`AuditStreamEmitter.emit`, `AuditCollectorService._dispatch`)
  - `lineage/resilience/receipts.py:399-404` (`SkipLevelReceipt.to_dict`)
  - `lineage/k8s/bootstrap_services.py:463-470`
- **Details & Empirical Reproduction (`test_07`)**:
  While disk artifacts in `runs/20261118T142439Z/` are scrubbed by `e2e_driver._scrub_for_disk`, the in-cluster `AuditCollectorService` binds `0.0.0.0:8093` and serves `GET /v1/audit/entries` with **zero caller authentication**. Because `SkipLevelReceipt.to_dict()` embeds the raw `compact_lineage_token` (`lct1...`) and `result_payload`, any unprivileged Pod in the cluster can query `/v1/audit/entries` and harvest active `lct1...` tokens, SVIDs, and cross-tenant itinerary records (`200 OK` in `test_07`).
- **Required Fix**:
  Require caller SVID authentication on `GET /v1/audit/entries` (e.g., signed `lct-audit-query+jwt` header verified against `self.trust_resolver` and restricted to authorized auditor/gateway principals, or redact `lct1.`/`lctm1.`/`eyJ...` strings by default unless an authenticated auditor principal requests raw cryptographic verification material). Also extend `redact_sensitive()` in `lineage/common/crypto.py:512-529` to redact `lct1.` / `lctm1.` strings and `compact_lineage_token`.

---

#### [MEDIUM-M2-02] Outbound Sidecar Proxy (`/v1/proxy/call`) `task_path` / `target_url` Authority Smuggling + Missing Positive/Finite Bounds in `TravelOpsMCPApp`, `ManagedHTTPService`, and `OllamaClient`
- **Location**:
  - `lineage/sidecar/proxy.py:632, 688, 715, 745, 774, 792, 877, 913` (`LineageSidecar._dispatch_outbound`)
  - `lineage/agents/mcp_servers.py:175, 204, 268` (`TravelOpsMCPApp`, `PaymentVaultMCPApp`)
  - `lineage/common/http_utils.py:309-311` (`ManagedHTTPService._send_json`)
  - `lineage/agents/ollama_client.py:42-45` & `lineage/agents/specialist_apps.py:591-594`
- **Details & Empirical Reproduction (`test_03`, `test_06`, `test_08`)**:
  1. **Outbound `task_path` Authority Smuggling (`proxy.py:715, 792`, `test_08`)**: `_dispatch_outbound` concatenates `target_url = f"{chosen.endpoint.rstrip('/')}{task_path}"` without validating `task_path` via `validate_origin_form_target` (nor validating `target_url` on lines 632, 774). Passing `task_path="@127.0.0.1:<sink_port>/smuggled"` turns `http://127.0.0.1:9` into `http://127.0.0.1:9@127.0.0.1:<sink_port>/smuggled`, redirecting the outbound POST, task payload, and signed `DPoP` proof to an arbitrary host (`200 OK` in `test_08`)! Outbound `timeout` values are also not checked for finiteness/bounds.
  2. **Zero/Negative Booking Amount in `TravelOpsMCPApp` (`mcp_servers.py:175, 204`, `test_06`)**: `book_flight` and `reserve_hotel` accept `amount=0.0` (or negative values if `max_amount=None`), recording `charged_usd: 0.0`, and neither MCP server checks `math.isfinite(amount)` before `round(amount, 2)`. Also, `ManagedHTTPService._send_json` (`http_utils.py:309`) omits `allow_nan=False`.
  3. **JSON Parse Exception Leak in `OllamaClient` (`ollama_client.py:42`, `test_03`)**: `_extract_json_object` lets `json.JSONDecodeError` (`ValueError`) escape instead of raising `OllamaError` (converting `502` upstream LLM errors into `400 bad_request`), and `SettlementConvergerApp` (`specialist_apps.py:591`) omits `try ... except OllamaError` in `leaf_audit_and_upward_return`.
- **Required Fix**:
  Validate `task_path` with `validate_origin_form_target`, validate `target_url` scheme/netloc (forbidding `@` userinfo, fragments, non-HTTP schemes), and clamp `timeout` to finite `(0.05, 120.0]` in `LineageSidecar._dispatch_outbound`; enforce `math.isfinite(amount) and amount > 0` in `TravelOpsMCPApp` and `PaymentVaultMCPApp`; pass `allow_nan=False` in `ManagedHTTPService._send_json`; wrap `ollama_client.py:42` and `specialist_apps.py:591` in `OllamaError`.

---

### 2.4 LOW Findings

#### [LOW-M2-01] Negative-Conditional System Prompt in `SettlementConvergerApp` Induces Contradictory Text in `qwen2.5:3b` on Non-Degraded Runs + Non-Standard Wildcard Route Echo in `OrchestratorAlphaApp`
- **Location**:
  - `lineage/agents/specialist_apps.py:725-734` (`SettlementConvergerApp._dispatch`)
  - `lineage/agents/specialist_apps.py:798-803` (`OrchestratorAlphaApp._dispatch`)
  - Evidence: `lineage/k8s/runs/20261118T142439Z/scenario1_normal_dag.json:162`, `scenario4_fagin_degradation_and_isolation.json:81`
- **Details**:
  1. In `scenario1_normal_dag.json:162`, despite both `airline-escrow` (`$580`) and `hotel-escrow` (`$360`) succeeding, `qwen2.5:3b` wrote `"Flight Booking: NH-108 (charged USD 580.0) - Not executed due to null flight_booking"` because the negative conditional prompt in `specialist_apps.py:728-730` (`"If flight_booking is null, explicitly note that only the hotel settlement was executed"`) confused the 3B model. Constructing separate positive system instructions depending on whether `active_flight is None` avoids contradictory prose while keeping output 100% LLM-generated.
  2. `OrchestratorAlphaApp._dispatch` (`lines 798-803`) returns `200 OK` echoing arbitrary non-`/a2a/task` `POST` paths/queries instead of returning `404 route_not_found` consistently with the other agents (`lines 235, 399, 578`).

---

## 3. Reproduction Commands

```bash
export PATH="/Users/hulalala/Desktop/A/.tools/bin:$HOME/.docker/bin:$PATH"
cd /Users/hulalala/Desktop/A

# 1. Run Milestone 1 full regression suite (41/41 PASS)
PYTHONPATH=/Users/hulalala/Desktop/A /Users/hulalala/Desktop/A/src/cortex/authbridge/venv/bin/python3 -m lineage.tests.run_all

# 2. Run Milestone 2 independent QA verification & boundary reproduction suite (8/8 PASS)
PYTHONPATH=/Users/hulalala/Desktop/A /Users/hulalala/Desktop/A/src/cortex/authbridge/venv/bin/python3 -m unittest lineage/reviews/qa_milestone2_review.py -v
```
