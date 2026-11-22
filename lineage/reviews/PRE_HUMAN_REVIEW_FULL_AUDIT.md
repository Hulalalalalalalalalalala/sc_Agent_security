# Comprehensive Pre-Human-Review Full-Codebase Audit Report (`lineage/` M1–M4)

- **Audit Timestamp**: `2026-11-21T02:02:00+08:00`
- **Reviewer**: `k8s-qa-reviewer` (Strictly Read-Only Independent Audit Session)
- **Scope**: All 13 subpackages under `/Users/hulalala/Desktop/A/lineage/` (`common`, `identity`, `federation`, `protocol`, `registry`, `revocation`, `verifier`, `resilience`, `audit`, `a2a`, `sidecar`, `agents`, `k8s` + `tests` + `runs`)
- **Audit Posture**:
  - **Core Cryptographic, Protocol & Isolation Security**: **SOUND (0 Critical, 0 High)**
  - **Pre-Human-Review Polish Recommendation**: **`RECOMMEND_MINOR_POLISH` (`NEEDS_FIX` for 1 Medium runtime `NameError` edge case + 2 Operational post-reboot cold-start script gaps + 4 Low/Doc items)**

---

## 1. Automated Test & Standalone QA Sign-Off Suite Execution Results

All suites were executed locally with `/Users/hulalala/Desktop/A/src/cortex/authbridge/venv/bin/python3 -W default` to surface any `ResourceWarning`, socket leak, or `DeprecationWarning`.

| Suite | Command | Result | Warnings / Unhandled Exceptions | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Core & Regression Test Suite (M1–M4)** | `python3 -W default -m lineage.tests.run_all` | **PASS (`54/54` tests in `16.42s` + benchmarks in `18.37s`)** | **0 warnings, 0 unhandled exceptions** | Covers lattice, LCT/MultiParent tokens, DPoP, adaptive verifier, atomic prune-and-graft, skip-level anti-spoofing, causal auditor, A2A v1.0 JSON-RPC/SSE, mTLS 1.3 `NameConstraints`, and M2/M3/M4 security regressions. |
| **Milestone 1 Round 4 QA Sign-Off** | `python3 -W default lineage/reviews/qa_signoff_round4.py` | **PASS (`5/5` in `1.18s`)** | **0 warnings** | Pure-Python cryptographic & sidecar boundary suite. |
| **Milestone 2 QA Sign-Off** | `python3 -W default lineage/reviews/qa_milestone2_signoff.py` | **`3/4` Pure-Python PASS; `1/4` Live K8s Skipped/Refused** | **0 warnings** | `test_01`, `test_03`, `test_04` PASS; `test_02` probes live `kind-agent-identity-lab` (`127.0.0.1:56726`), currently `Exited (137)` after host Docker restart (and single-cluster `lineage-*` namespaces were cleaned in M4). |
| **Milestone 3 QA Sign-Off** | `python3 -W default lineage/reviews/qa_milestone3_signoff.py` | **`5/6` Pure-Python PASS; `1/6` Live K8s Skipped/Refused** | **0 warnings** | `test_01..test_05` PASS; `test_06` probes live single-cluster `kind-agent-identity-lab`, currently `Exited (137)`. |
| **Milestone 4 QA Sign-Off** | `python3 -W default lineage/reviews/qa_milestone4_signoff.py` | **`3/4` Static/Manifest/Evidence PASS; `1/4` Live 4-Cluster Refused** | **0 warnings** | `test_01..test_03` PASS (verifying 4-cluster manifests, NodePorts, and M4 run artifacts); `test_04` probes live `kind-*` containers, currently `Exited (137)` (not started per read-only rule). |

---

## 2. Baseline Preservation & Full-Tree Secret Hygiene Verification

1. **Baseline Immutability**:
   - Verified zero modifications across [README.md](file:///Users/hulalala/Desktop/A/README.md), `/Users/hulalala/Desktop/A/lab/`, and `/Users/hulalala/Desktop/A/src/`.
   - Read-only `docker ps -a` and `kind get clusters` confirmed all 5 Kind clusters (`agent-identity-lab`, `lct-org-alpha`, `lct-org-beta`, `lct-org-pay`, `lct-audit`) remain unmodified in `Exited (137)` state following the Docker restart ~5 hours ago.
2. **Full-Tree Secret & Token Scan (`171` files across all of `lineage/`)**:
   - Scanned every `.py`, `.sh`, `.yaml`, `.md`, `.json`, `.txt`, and `.log` file under `/Users/hulalala/Desktop/A/lineage/` (including all 5 historical `lineage/k8s/runs/*` directories, `tests/`, `manifests/`, `multicluster/`, and `reviews/`):
     - **PEM Private Keys (`-----BEGIN ... PRIVATE KEY-----`)**: **`0` hits**
     - **Private JWK `"d"` Parameters**: **`0` hits**
     - **Unredacted Compact JWS (`eyJ...`)**: **`0` hits**
     - **Wire LCT Tokens (`lct1.`, `lctm1.`, `lctmp1.`)**: **`0` live hits** (only 1 synthetic unit-test string `'lct1.dummy_token_payload_for_ath_binding'` at [test_lattice_and_protocol.py](file:///Users/hulalala/Desktop/A/lineage/tests/test_lattice_and_protocol.py#L277)).

---

## 3. Deep Static Code Audit: Findings List (`Medium` / `Operational` / `Low` / `Doc`)

### 3.1 Medium Findings (Runtime Edge-Case Defect)

#### `[MEDIUM-PRE-01]` Undefined Symbol `json` in `LineageSidecar._dispatch_inbound` Causes `NameError` (`500`) When SSE Route Receives Non-SSE Upstream JSON Error
- **File & Line**: [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L763-L769) (imports at [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L14-L28))
- **Root Cause**:
  In `LineageSidecar._dispatch_inbound`, when `wants_sse` is `True` (`Accept: text/event-stream` or JSON-RPC method `SendStreamingMessage` / `message/stream`) and the co-located `app` server returns a non-SSE `application/json` response (e.g., JSON-RPC `-32602 Invalid params`, `-32700 Parse error`, or when a client sends `Accept: text/event-stream` on `GetTask` / `CancelTask`), lines 763–769 execute:
  ```python
  if "text/event-stream" not in up_ct.lower():
      raw_b = up_resp.read()
      st_code = up_resp.status_code
      stream_ctx.__exit__(None, None, None)
      stream_client.close()
      self.active_requests.release(req_ctx.request_id)
      return st_code, json.loads(raw_b.decode("utf-8")), out_extra
  ```
  `json` is **not imported** anywhere in `lineage/sidecar/proxy.py`. An AST scope scan across all 66 Python files flagged `proxy.py:769` (`F821 undefined name 'json'`). Hitting this branch raises `NameError: name 'json' is not defined` and turns a clean JSON-RPC error response into an unhandled `500 Internal Server Error` (note: resources `stream_ctx`, `stream_client`, and `req_ctx` are already cleaned up before line 769, so nothing leaks, but the response status/body breaks).
- **Recommended Fix**:
  Import `strict_json_loads` from `lineage.common.crypto` (or `import json`) in `lineage/sidecar/proxy.py`, replace `json.loads(raw_b.decode("utf-8"))` with `strict_json_loads(raw_b)`, and add a regression test calling `SendStreamingMessage` with invalid `params` through `LineageSidecar`.

---

### 3.2 Operational / Cold-Start Findings (Post-Reboot Resilience)

#### `[OPERATIONAL-PRE-01]` `run-e2e-multicluster-ollama.sh` and `cleanup-multicluster-k8s.sh` Abort Immediately After Host/Docker Restart When `agent-identity-lab-control-plane` Is `Exited (137)`
- **Files & Lines**:
  - [run-e2e-multicluster-ollama.sh](file:///Users/hulalala/Desktop/A/lineage/k8s/run-e2e-multicluster-ollama.sh#L38-L42)
  - [cleanup-multicluster-k8s.sh](file:///Users/hulalala/Desktop/A/lineage/k8s/cleanup-multicluster-k8s.sh#L19-L21)
  - [cleanup-lineage-k8s.sh](file:///Users/hulalala/Desktop/A/lineage/k8s/cleanup-lineage-k8s.sh#L10-L13)
  - Compare with [run-e2e-k8s-ollama.sh](file:///Users/hulalala/Desktop/A/lineage/k8s/run-e2e-k8s-ollama.sh#L30-L37)
- **Root Cause**:
  - Unlike M3's `run-e2e-k8s-ollama.sh:30-34` (which checks `docker inspect -f '{{.State.Running}}' "${KIND_NAME}-control-plane"` and runs `docker start` + `kubectl wait --for=condition=Ready node/...`), M4's `run-e2e-multicluster-ollama.sh:39` immediately executes `kubectl --context "${BASELINE_CTX}" get pods -n team1 -o wide` under `set -euo pipefail`. After a macOS / Docker restart when `agent-identity-lab-control-plane` is `Exited (137)`, both `run-e2e-multicluster-ollama.sh` and `cleanup-multicluster-k8s.sh:20` fail with exit code 1 (`connection refused` on `127.0.0.1:56726`).
  - Also note: right after `docker start agent-identity-lab-control-plane`, waiting only for `node/... Ready` (`run-e2e-k8s-ollama.sh:34`) without `kubectl --context "${BASELINE_CTX}" wait --for=condition=Ready pod --all -n team1 --timeout=120s` can snapshot `team1` Pods while kubelet is still restarting their containers (`0/2` -> `2/2`).
  - *Verified good behavior*: Read-only `kind get clusters` **does** list all 4 `Exited (137)` `lct-*` clusters (`lct-org-alpha`, `lct-org-beta`, `lct-org-pay`, `lct-audit`), so `kind delete cluster --name "${cname}"` in `run-e2e-multicluster-ollama.sh:61-63` and `cleanup-multicluster-k8s.sh:11-14` cleanly removes stopped `lct-*` containers without manual intervention.
- **Recommended Fix**:
  Add a pre-flight helper to `run-e2e-multicluster-ollama.sh` and `cleanup-multicluster-k8s.sh` (and add the `team1` Pod `Ready` wait to `run-e2e-k8s-ollama.sh:35`) that starts `agent-identity-lab-control-plane` if `Exited`, waits for `node/agent-identity-lab-control-plane` `Ready`, and waits up to `120s` for `pod --all -n team1` `Ready` before snapshotting `00_team1_before.txt`.

#### `[OPERATIONAL-PRE-02]` Both E2E Runner Scripts Abort If Host `ollama serve` Is Stopped After Reboot
- **Files & Lines**:
  - [run-e2e-multicluster-ollama.sh](file:///Users/hulalala/Desktop/A/lineage/k8s/run-e2e-multicluster-ollama.sh#L43-L45)
  - [run-e2e-k8s-ollama.sh](file:///Users/hulalala/Desktop/A/lineage/k8s/run-e2e-k8s-ollama.sh#L42-L44)
- **Root Cause**:
  Both scripts execute `curl -fsS http://127.0.0.1:11434/v1/models` and immediately exit if `ollama serve` has not been started manually after a host reboot.
- **Recommended Fix**:
  Probe `http://127.0.0.1:11434/v1/models` first; if unreachable, auto-start `"${REPO_ROOT}/.tools/ollama/ollama" serve` in background (keeping default loopback `127.0.0.1:11434` binding so Ollama is not exposed on external LAN interfaces while Docker Desktop's VM still reaches it via `host.docker.internal:11434`) and poll readiness for up to `20s` before checking `qwen2.5:3b`.

---

### 3.3 Low & Documentation Polish Findings

#### `[LOW-PRE-01]` Missing `Tuple` Import in `lineage/identity/spiffe.py` Return Type Annotation
- **File & Line**: [spiffe.py](file:///Users/hulalala/Desktop/A/lineage/identity/spiffe.py#L9) & [spiffe.py](file:///Users/hulalala/Desktop/A/lineage/identity/spiffe.py#L198)
- **Detail**: `TrustDomainCA.sign_svid_for_public_jwk` annotates `-> Tuple[str, str, float, float]:` at line 198, while line 9 only imports `from typing import Any, Dict, List, Optional`. Masked at import time by `from __future__ import annotations`, but flagged by static linters (`F821`) and breaks `typing.get_type_hints()`.
- **Recommended Fix**: Add `Tuple` to `from typing import Any, Dict, List, Optional, Tuple` at `spiffe.py:9`.

#### `[LOW-PRE-02]` Secondary Token-Prefix Redaction Checks Omit `lctmp1.` (`LCT_MP_WIRE_PREFIX`)
- **Files & Lines**:
  - [e2e_driver.py](file:///Users/hulalala/Desktop/A/lineage/k8s/e2e_driver.py#L117)
  - [run-e2e-multicluster-ollama.sh](file:///Users/hulalala/Desktop/A/lineage/k8s/run-e2e-multicluster-ollama.sh#L451)
  - [run-e2e-k8s-ollama.sh](file:///Users/hulalala/Desktop/A/lineage/k8s/run-e2e-k8s-ollama.sh#L208)
- **Detail**: Primary redaction in [crypto.py](file:///Users/hulalala/Desktop/A/lineage/common/crypto.py#L412) already covers `("lct1.", "lctmp1.", "lctm1.")`, but the secondary defense-in-depth checks in `e2e_driver.py:117` and the final `grep` checks in both E2E shell scripts check `lct1.` and `lctm1.` without `lctmp1.` (defined in [token.py](file:///Users/hulalala/Desktop/A/lineage/protocol/token.py#L44)).
- **Recommended Fix**: Include `"lctmp1."` in `e2e_driver.py:117` and `\"lctmp1\.` in both shell scripts' redaction gates.

#### `[LOW-PRE-03]` Explicit `mtls_bundle.cleanup()` on SIGTERM Shutdown & Bounded Demo MCP Ledger Lists
- **Files & Lines**:
  - [bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L759-L762), [bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L793-L797), [bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L943-L947)
  - [mcp_servers.py](file:///Users/hulalala/Desktop/A/lineage/agents/mcp_servers.py#L122) & [mcp_servers.py](file:///Users/hulalala/Desktop/A/lineage/agents/mcp_servers.py#L261)
- **Detail**:
  - `WorkloadMTLSBundle` already `os.unlink()`s transient PEM files immediately after `SSLContext.load_cert_chain()` ([mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L444-L450)), leaving only an empty `lct-mtls-*` directory cleaned in `__del__`. Calling `mtls_bundle.cleanup()` explicitly after `svc.stop()` / `sidecar.stop()` in `bootstrap_services.py` (matching [e2e_driver.py](file:///Users/hulalala/Desktop/A/lineage/k8s/e2e_driver.py#L1489)) makes shutdown deterministic.
  - `TravelOpsMCPApp._bookings` and `PaymentVaultMCPApp._settlements` use plain `list` (using `collections.deque(maxlen=10_000)` bounds memory in long-running deployments, matching `JTIReplayCache`, `_QuotaTracker`, `A2ATaskStore`, `MultiParentConvergenceInbox`, and `_BoundedTaskListStore`, all of which are already strictly bounded under `threading.Lock`).

#### `[DOC-PRE-01]` Minor Identifier / Label Drift in `ARCHITECTURE.md`, `Dockerfile`, and `bootstrap_services.py`
- **Files & Lines**:
  - [ARCHITECTURE.md](file:///Users/hulalala/Desktop/A/lineage/ARCHITECTURE.md#L68): Mentions `503 peer_revocation_sync_unavailable`, whereas [service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L753) returns `503 federation_anchor_unavailable` and [policy_verifier.py](file:///Users/hulalala/Desktop/A/lineage/verifier/policy_verifier.py#L467) returns `503 REVOCATION_ANCHOR_UNAVAILABLE`.
  - [ARCHITECTURE.md](file:///Users/hulalala/Desktop/A/lineage/ARCHITECTURE.md#L70): Mentions `ResilienceCoordinator`, whereas the actual class in [coordinator.py](file:///Users/hulalala/Desktop/A/lineage/resilience/coordinator.py#L52) is `ResilientDelegationCoordinator`.
  - [ARCHITECTURE.md](file:///Users/hulalala/Desktop/A/lineage/ARCHITECTURE.md#L21-L52): Subpackage map covers M1–M3 single-cluster files and can optionally mention M4 `lineage/k8s/multicluster/` (`run-e2e-multicluster-ollama.sh` + 4-cluster topology, already documented in [K8S_DEPLOYMENT.md](file:///Users/hulalala/Desktop/A/lineage/k8s/K8S_DEPLOYMENT.md#L15-L70)).
  - [Dockerfile](file:///Users/hulalala/Desktop/A/lineage/k8s/Dockerfile#L1) & [bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L659): Header comment / CLI description still say `Milestone 2`.

---

## 4. Subpackage-by-Subpackage Security & Concurrency Audit Matrix

| Subpackage | Key Audited Files | Cryptographic, Concurrency & Resource Verdict |
| :--- | :--- | :--- |
| `common` | [crypto.py](file:///Users/hulalala/Desktop/A/lineage/common/crypto.py), [mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py), [http_utils.py](file:///Users/hulalala/Desktop/A/lineage/common/http_utils.py) | **PASS** — Canonical JSON (`allow_nan=False`), `strict_json_loads`, strict `alg`/`typ` separation, X.509 `NameConstraints(critical=True)` + `path_length=0`, immediate `os.unlink` of temp PEMs, `SO_REUSEADDR`, anti-smuggling `Host` & origin-form validation, clean SSE socket close. |
| `identity` | [spiffe.py](file:///Users/hulalala/Desktop/A/lineage/identity/spiffe.py), [trust_bundle.py](file:///Users/hulalala/Desktop/A/lineage/identity/trust_bundle.py) | **PASS** (minor `LOW-PRE-01` `Tuple` import) — Strict RFC 8732 SPIFFE URI validation, per-domain key isolation, zero cross-domain trust leakage, thread-safe `RLock` bundle rotation. |
| `federation` | [domain_ca.py](file:///Users/hulalala/Desktop/A/lineage/federation/domain_ca.py), [sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py) | **PASS** — Per-domain `AutonomousDomainCAService` enforces K8s OIDC `iss`/`aud`/`exp`/`sub`, exact namespace & control-plane SA allowlist, `lct-ca-pop+jwt` PoP with `JTIReplayCache`, and dual-port separation (`:8090` internal vs `:8490` public read-only bundle export). |
| `protocol` | [lattice.py](file:///Users/hulalala/Desktop/A/lineage/protocol/lattice.py), [token.py](file:///Users/hulalala/Desktop/A/lineage/protocol/token.py), [dpop.py](file:///Users/hulalala/Desktop/A/lineage/protocol/dpop.py) | **PASS** — Monotonic lattice meet (`⊓`), full O(depth) chain hash/signature/cycle/epoch/depth verification, cross-root/cross-task/cross-principal splicing blocked in `MultiParentToken`, RFC 9449 `ath` + `htu` + `htm` DPoP with bounded `50,000`-entry replay cache. |
| `registry` | [agent_card.py](file:///Users/hulalala/Desktop/A/lineage/registry/agent_card.py), [directory.py](file:///Users/hulalala/Desktop/A/lineage/registry/directory.py) | **PASS** — JWS-signed A2A v1.0 `AgentCard` (`a2a-agent-card+jwt`) verified against `WorkloadIdentity` SVID; monotonic version anti-rollback; mTLS 1.3 cross-domain peering with domain-scoped quarantine authority. |
| `revocation` | [trie.py](file:///Users/hulalala/Desktop/A/lineage/revocation/trie.py), [service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py) | **PASS** — Segment-boundary prefix trie (`O(|path|)`), caller jurisdiction proof via `authority_token` (`is_lineage_segment_prefix`), mTLS 1.3 peer push/pull, and strict fail-closed `503` on `HIGH_RISK` origin consistency failure. |
| `verifier` | [policy_verifier.py](file:///Users/hulalala/Desktop/A/lineage/verifier/policy_verifier.py) | **PASS** — Bounded `_QuotaTracker` (`50,000` max), escalation-only risk hints, Fagin's multi-parent union over surviving branches (`ALLOW` / `ALLOW_DEGRADED_DAG` / `403`), recipient/child role checks. |
| `resilience` | [detector.py](file:///Users/hulalala/Desktop/A/lineage/resilience/detector.py), [receipts.py](file:///Users/hulalala/Desktop/A/lineage/resilience/receipts.py), [coordinator.py](file:///Users/hulalala/Desktop/A/lineage/resilience/coordinator.py) | **PASS** — Strict atomic ordering (Prune -> Discover -> Graft at `epoch + 1`), `FailoverReceipt` cryptographically verifies `RevocationEvent` signature, `SkipLevelReceipt` enforces live mTLS `/healthz` anti-spoofing probe (`403 INTERMEDIATE_ANCESTOR_ALIVE`). |
| `audit` | [logger.py](file:///Users/hulalala/Desktop/A/lineage/audit/logger.py), [auditor.py](file:///Users/hulalala/Desktop/A/lineage/audit/auditor.py) | **PASS** — Keyless `AuditCollectorService` verifies every entry's JWS + `prev_entry_hash` chain on ingest, enforces signed auditor query JWS with `16,384`-entry replay cache, and `redact_sensitive` scrubs all wire credentials. |
| `a2a` | [models.py](file:///Users/hulalala/Desktop/A/lineage/a2a/models.py), [rpc.py](file:///Users/hulalala/Desktop/A/lineage/a2a/rpc.py) | **PASS** — Official A2A v1.0 `TaskState` machine, bounded `A2ATaskStore` (`10,000` max + TTL), cross-tenant `owner_sub` isolation (`-32003`), atomic `CancelTask` (executes cascading `revoke_subtree` hook *before* mutating state to `CANCELED`), distinct `-32700` vs `-32600` JSON-RPC codes. |
| `sidecar` | [context.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/context.py), [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py) | **PASS with `MEDIUM-PRE-01`** (`json` import at `proxy.py:769`) — `ContextVar` + `ActiveRequestStore` per-request UUID isolation (no global mutable token state), bounded `MultiParentConvergenceInbox` (`10,000` max), mTLS peer-to-LCT channel binding, loopback-only `:8081` outbound proxy. |
| `agents` | [ollama_client.py](file:///Users/hulalala/Desktop/A/lineage/agents/ollama_client.py), [mcp_servers.py](file:///Users/hulalala/Desktop/A/lineage/agents/mcp_servers.py), [specialist_apps.py](file:///Users/hulalala/Desktop/A/lineage/agents/specialist_apps.py) | **PASS** — Zero mocks (`qwen2.5:3b` via `/v1/chat/completions` with `nonfinite` JSON rejection), `127.0.0.1:9001` loopback isolation, constant-time `X-LCT-Loopback-Auth`, strict fault-injection env gate (`LCT_ENABLE_FAULT_INJECTION`) & SSRF-safe sync hook allowlist. |
| `k8s` | [bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py), [e2e_driver.py](file:///Users/hulalala/Desktop/A/lineage/k8s/e2e_driver.py), `manifests/*.yaml`, `multicluster/*.yaml`, `*.sh` | **PASS with `OPERATIONAL-PRE-01/02` & `LOW-PRE-02/03`** — Zero K8s `Secret` objects for LCT keys, `automountServiceAccountToken: false` on all `app` containers and `audit-collector`, projected `aud: lct-federation-ca` tokens on `lct-sidecar` only. |

---

## 5. Pluggability & Multi-Scheme Inventory (For Engineering Summary)

### 5.1 Switchable Modes & Pluggable Abstractions Currently Implemented
1. **Verification & Consistency Modes (`VerificationMode` in [policy_verifier.py](file:///Users/hulalala/Desktop/A/lineage/verifier/policy_verifier.py#L51-L55), runtime-configurable via `VERIFICATION_MODE` env var)**:
   - `LEAF_ONLY`: O(1) leaf block + SVID + lattice verification (benchmark baseline).
   - `LOCAL_FULL_CHAIN`: Full O(depth) chain walk + local revocation trie replica check (eventual consistency, zero sync network I/O).
   - `ADAPTIVE_RISK_ANCHORED` (default): Differentiated risk-driven consistency — local trie check for `LOW_RISK` operations; synchronous origin-domain consistency anchoring (`check_consistency()`) for `HIGH_RISK` operations, paired with configurable `fail_closed_on_high_risk: bool = True` (`503` fail-closed vs. fail-open evaluation).
2. **Configurable Risk Policy (`RiskClassifier` in [policy_verifier.py](file:///Users/hulalala/Desktop/A/lineage/verifier/policy_verifier.py#L67-L153))**:
   - Customizable `high_risk_tools`, `low_risk_tools`, `high_risk_amount_threshold`, plus monotonic caller-supplied `X-LCT-Risk-Hint: HIGH` escalation.
3. **Downward Delegation Strategies (`LineageSidecar` `delegate_agent` in [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L1035-L1160))**:
   - Direct pinned-endpoint delegation (`delegate_spiffe_id` + `delegate_jkt` + `target_url`);
   - Dynamic skill-based directory routing (`required_skill` via `AgentDirectoryClient.discover`);
   - Resilient `use_prune_and_graft=True` (`ResilientDelegationCoordinator`: 3-layer fault classification + atomic subtree revocation + substitute discovery + `epoch + 1` graft + signed `FailoverReceipt`).
4. **Upward Result Delivery Strategies ([coordinator.py](file:///Users/hulalala/Desktop/A/lineage/resilience/coordinator.py#L360-L598))**:
   - Direct parent delivery (`POST /v1/task-result`) with automatic fallback to `Authenticated Skip-Level Return` (`POST /v1/skip-level-return` + ancestor live `/healthz` verification + optional `prune_dead_intermediate`).
5. **Dual Delegation Graph Topologies ([token.py](file:///Users/hulalala/Desktop/A/lineage/protocol/token.py))**:
   - Single-chain / 1-to-N `LineageToken` (`lct1.`) and N-to-1 / M-to-N `MultiParentToken` (`lctmp1.`) with Fagin's smooth branch degradation (`ALLOW` vs. `ALLOW_DEGRADED_DAG`).
6. **Dual Signing Algorithms ([crypto.py](file:///Users/hulalala/Desktop/A/lineage/common/crypto.py#L140-L155))**:
   - `ES256` (ECDSA P-256) and `RS256` (RSA-2048) supported in `KeyPair`, `TrustDomainCA`, and JWS verifiers.
7. **Dual Agent Wire Protocols ([specialist_apps.py](file:///Users/hulalala/Desktop/A/lineage/agents/specialist_apps.py) & [rpc.py](file:///Users/hulalala/Desktop/A/lineage/a2a/rpc.py))**:
   - Official A2A v1.0 JSON-RPC 2.0 + SSE (`POST /`, `POST /a2a`, `/.well-known/agent-card.json`) alongside backwards-compatible REST (`POST /a2a/task`, `/.well-known/agent.json`).
8. **Out-of-Process Sidecar vs. Keyless Business App Separation & Multi-Topology Control Plane ([bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py))**:
   - Business `app` containers (`127.0.0.1:9001`) are crypto-agnostic and communicate via `SidecarLoopbackClient` (`127.0.0.1:8081`).
   - Control plane supports in-process HTTP test mode, single-cluster `FederationCAService` (M2), single-cluster 3-domain autonomous mTLS 1.3 (M3), and 4-cluster physical Kubernetes federation over NodePort + CoreDNS peering (M4).

### 5.2 Current Coupling Points / Non-Abstracted Boundaries
1. **In-Memory State Stores**: `LineagePrefixTrie`, `AgentDirectoryService`, `AuditCollectorService`, and `A2ATaskStore` are thread-safe RAM stores without an external persistent storage adapter (`StorageBackend` for etcd/PostgreSQL/Redis) yet.
2. **Kubernetes-Specific Bootstrap Attestor**: `K8sServiceAccountVerifier` (`bootstrap_services.py:134`) directly verifies Kubernetes OIDC Projected SA JWTs rather than sitting behind a generic `WorkloadAttestor` interface (e.g., for swapping in a native SPIRE Workload API socket attestor).
3. **LLM Client Instantiation & Reference Domain**: `OllamaClient` (`agents/ollama_client.py`) uses standard OpenAI `/v1/chat/completions` wire format (compatible with vLLM/LiteLLM/OpenAI), but `SpecialistApps` instantiate `OllamaClient` directly and embed travel/escrow domain tool schemas.
4. **Synchronous Threaded HTTP Runtime**: `ManagedHTTPService` builds on stdlib `ThreadingHTTPServer` + sync `httpx.Client` (zero external web framework footprint, thread-per-connection concurrency model).
