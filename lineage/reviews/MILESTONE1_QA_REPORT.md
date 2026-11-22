# Milestone 1 Adversarial Code Audit & Security QA Report (`lineage/`)

- **QA Inspector**: `qa-inspector` (Independent Read-Only Security & Concurrency Audit Session)
- **Audit Scope**: `/Users/hulalala/Desktop/A/lineage/` (`common/`, `identity/`, `registry/`, `protocol/`, `revocation/`, `verifier/`, `resilience/`, `audit/`, `sidecar/`, `tests/`)
- **Historical Baseline Check**: `/Users/hulalala/Desktop/A/README.md`, `/Users/hulalala/Desktop/A/lab/`, `/Users/hulalala/Desktop/A/src/`
- **Adversarial Verification Suite**: `/Users/hulalala/Desktop/A/lineage/reviews/qa_adversarial_milestone1.py` (`12/12` empirical reproduction & invariant tests executed in `2.01s`)
- **Overall Milestone 1 Verdict**: **`NEEDS_FIX`** (4 Critical, 4 High, 3 Medium, 2 Low)

---

## 1. Executive Summary & Positive Security Controls Verified

### 1.1 Historical Baseline Zero-Pollution Verification (`PASS`)
- Verified via filesystem timestamps (`find /Users/hulalala/Desktop/A/README.md /Users/hulalala/Desktop/A/lab /Users/hulalala/Desktop/A/src -newer /Users/hulalala/Desktop/A/lineage/__init__.py`): **0 files modified**.
- `README.md` (Nov 16 11:50), `lab/RESULTS.md` (Nov 16 11:50), `lab/baseline/` (Nov 15), `lab/experiments/01..03` (Nov 16–17), and `src/` (Nov 13) remain 100% intact and unpolluted.
- All `code-engineer` existing tests (`23/23` across unit, adversarial, and real multi-process `spawn` topologies) were independently executed and verified passing (`7.59s` including microbenchmarks).

### 1.2 Genuine Cryptographic & Architectural Strengths Confirmed (`PASS`)
Unlike toy prototypes, the foundational cryptography and lattice math in `lineage/` are genuinely implemented:
1. **Real Asymmetric Cryptography & Standards Interop**: `common/crypto.py` uses OpenSSL-backed `cryptography` (`SECP256R1` `ES256` with proper 64-byte `R||S` <-> ASN.1 DER conversion, and 2048-bit `RS256`), enforces canonical Base64url encoding (blocking trailing-bit malleability), rejects private JWK fields (`d`, `p`, `q`, etc.) in verification contexts, blocks `alg: none` / ES256-vs-RS256 confusion, and matches `jwcrypto` for RFC 7515 JWS and RFC 7638 `jkt` thumbprints.
2. **Federated Trust Domain Namespace Isolation**: `TrustBundleResolver.verify_workload_svid` (`identity/trust_bundle.py:184-195`) strictly resolves `kid` only within `spiffe.trust_domain`, preventing a compromised `org-beta.io` CA from issuing SVIDs for `org-alpha.io` or `org-payment.io`.
3. **Lattice Monotonicity & Anti-Cartesian DAG Evaluation**: `PermissionLattice` (`protocol/lattice.py`) properly rejects `bool`, `NaN`, `+inf`, `-inf`, negative bounds, and constraint-dropping (`None` escalation); `CompositePermission` (`protocol/lattice.py:444-496`) evaluates full per-branch call vectors disjunctively, blocking cross-branch Cartesian privilege amplification; `MultiParentToken` + `LeafVerifier._verify_multiparent_envelope_crypto` (`verifier/policy_verifier.py:390-395`) strictly reject stuffing a foreign branch delegated to `D` inside `C`'s `MultiParentToken` (`test_12`).
4. **Segment-Exact Prefix Trie & Loopback Header Overwrite**: `LineagePrefixTrie` (`revocation/trie.py`) splits on exact path segments (preventing `/B1` from colliding with `/B10`), and `LineageSidecar._dispatch_inbound` (`sidecar/proxy.py:381-389`) overwrites `X-LCT-Loopback-Auth` and `X-LCT-Request-Id` rather than forwarding external client headers to the local business app.

### 1.3 Why Milestone 1 Requires Fixes (`NEEDS_FIX`)
Deep line-by-line adversarial inspection and live execution of `lineage/reviews/qa_adversarial_milestone1.py` uncovered **4 Critical** and **4 High** security/concurrency vulnerabilities that allow an attacker or compromised peer node to bypass synchronous high-risk revocation anchoring, replay DPoP proofs across sidecars while swapping MCP tool payloads, sabotage arbitrary cross-domain tasks/coordinators via unprivileged revocation/quarantine endpoints, brick N-to-1 DAG convergence inboxes, bypass `max_calls` quotas, evade healthy parent supervision while tricking ancestors into revoking healthy parents, bypass timestamp freshness with IEEE-754 `NaN`, and spoof `VERIFIED_FAILOVER_GRAFT` / `VERIFIED_SKIP_LEVEL_MERGE` in `CausalChainAuditor`.

---

## 2. Detailed Findings & Remediation Requirements

### 2.1 CRITICAL Findings

#### [CRITICAL-01] External Caller Header `X-LCT-Risk-Hint: LOW` Bypasses Synchronous `HIGH_RISK` Revocation Anchoring & Fail-Closed Protection
- **Location**:
  - `lineage/sidecar/proxy.py:243` (`risk_hint = req.header("X-LCT-Risk-Hint")`)
  - `lineage/verifier/policy_verifier.py:84-91, 478-496` (`RiskClassifier.classify` & `LeafVerifier.verify_request`)
- **Vulnerability Mechanism**:
  `LineageSidecar._dispatch_inbound` extracts `X-LCT-Risk-Hint` directly from the untrusted external HTTP request and passes it as `explicit_risk_hint` into `LeafVerifier.verify_request`. Inside `RiskClassifier.classify` (`policy_verifier.py:86-90`):
  ```python
  if explicit_risk_hint:
      if explicit_risk_hint.upper() == "HIGH":
          return RiskTier.HIGH_RISK
      if explicit_risk_hint.upper() == "LOW":
          return RiskTier.LOW_RISK
  ```
  `explicit_risk_hint == "LOW"` returns `RiskTier.LOW_RISK` **before** checking `high_risk_tools` (`execute_payment`, `transfer_funds`, `delete_record`, etc.) or `amount >= high_risk_amount_threshold`.
- **Exploit Impact & Empirical Reproduction (`test_01`)**:
  1. When a task `/task-risk-downgrade` is revoked at `RevocationService` (before async replica polling completes), a revoked zombie agent calling `execute_payment(amount=1000.0)` with HTTP header `X-LCT-Risk-Hint: LOW` skips `revocation_replica.sync_now()` and succeeds with **`200 OK`**.
  2. When `RevocationService` is unreachable/partitioned (where normal `execute_payment(amount=2500.0)` fails closed with `503 REVOCATION_ANCHOR_UNAVAILABLE`), adding `X-LCT-Risk-Hint: LOW` bypasses fail-closed enforcement and executes the payment with **`200 OK`**.
- **Required Fix**:
  1. In `RiskClassifier.classify`, compute the intrinsic risk tier from `(method, tool, arguments)` first; allow `explicit_risk_hint == "HIGH"` only to **escalate** `LOW_RISK -> HIGH_RISK`, and **never** allow any hint to downgrade an intrinsically `HIGH_RISK` operation to `LOW_RISK`.
  2. Do not trust downgrade hints from external HTTP headers in `LineageSidecar._dispatch_inbound`.

---

#### [CRITICAL-02] DPoP `htu` Spoofing via Untrusted HTTP `Host` Header Enables Cross-Sidecar Replay, MCP Payload Swap, and Path Smuggling
- **Location**:
  - `lineage/common/http_utils.py:53-60` (`HTTPRequestContext.full_url`)
  - `lineage/sidecar/proxy.py:198, 256` (`htu=req.full_url`)
- **Vulnerability Mechanism**:
  `HTTPRequestContext.full_url` builds the expected DPoP target URI `htu` using the client-supplied `Host` header verbatim:
  ```python
  host_hdr = self.header("host")
  if host_hdr:
      return f"http://{host_hdr}{self.path}"
  ```
  Furthermore, `LineageSidecar` delegations leave `target_audience=None` by default, and each sidecar maintains an independent in-memory `JTIReplayCache`.
- **Exploit Impact & Empirical Reproduction (`test_02`)**:
  1. **Cross-Sidecar Replay + Body Swap**: Agent `C` sends `(tok, dpop_for_tool1)` to `weather-mcp` (`127.0.0.1:P1/mcp`) for `get_weather`. A compromised `weather-mcp` (or local MitM) immediately replays the exact `(tok, dpop_for_tool1)` to `payment-mcp` (`127.0.0.1:P2/mcp`) with spoofed header `Host: 127.0.0.1:P1` **and replaces the HTTP body** with `execute_payment(amount=450.0)`. `payment-mcp` reconstructs `req.full_url == "http://127.0.0.1:P1/mcp"`, accepts the DPoP proof, and executes the unauthorized payment (`200 OK`) without possessing `C`'s private key!
  2. **Cross-Path Smuggling**: Sending `Host: 127.0.0.1:P2/a2a/task?swallow=` to `/mcp` produces `req.full_url == "http://127.0.0.1:P2/a2a/task?swallow=/mcp"`. `normalize_htu()` strips `?swallow=/mcp`, allowing a DPoP proof signed for `/a2a/task` to pass verification while `LineageSidecar` dispatches `/mcp` (`200 OK`)!
- **Required Fix**:
  1. Construct `expected_htu` on `LineageSidecar` strictly from the sidecar's authoritative bound listener address / configured canonical public origin + `req.path` (never from untrusted `Host`).
  2. Validate `Host` header syntax (reject `/`, `?`, `#`, `@`, whitespace) and reject requests whose `Host` authority does not match the sidecar's configured authority.

---

#### [CRITICAL-03] Missing Authorization & Domain Scope on `RevocationService` and `AgentDirectoryService` Enables Lateral Task Sabotage & Cross-Domain Global Quarantine DoS
- **Location**:
  - `lineage/revocation/service.py:91-125, 154-196` (`_verify_caller_command`, `/v1/revoke/prefix`, `/v1/revoke/workload`)
  - `lineage/registry/directory.py:56-59, 140-168` (`register_card_direct`, `/v1/agents/quarantine`)
- **Vulnerability Mechanism**:
  Both services verify *authentication* (that the caller holds *any* valid SPIFFE SVID in *any* federated trust domain) without verifying *authorization* over the target lineage prefix or target workload SPIFFE ID.
- **Exploit Impact & Empirical Reproduction (`test_03`)**:
  An untrusted leaf workload `spiffe://org-beta.io/ns/sandbox/sa/untrusted-leaf` in partner domain `org-beta.io` can:
  1. Call `POST /v1/revoke/prefix` to tear down arbitrary tasks (`/task-alpha-secret`) or sibling/parent branches in `org-alpha.io`.
  2. Call `POST /v1/revoke/workload` at `RevocationService` to globally quarantine `org-alpha.io`'s Coordinator across all tasks.
  3. Call `POST /v1/agents/quarantine` at `AgentDirectoryService` to permanently delist `org-alpha.io`'s Coordinator and permanently block it from re-registering even with a higher `AgentCard` version!
- **Required Fix**:
  1. **`/v1/revoke/prefix`**: Require proof of lineage authority over `prefix`—either (a) the originating Trust Domain Root CA of the task, OR (b) an accompanying verified `LineageToken` proving `caller_id` is an authorized ancestor/holder of `prefix` (`caller_lineage_path` is a prefix of `target_prefix`), blocking outsiders and preventing child hops from revoking their parents or siblings.
  2. **`/v1/revoke/workload` & `/v1/agents/quarantine`**: Enforce trust-domain isolation (only a domain's own authority CA or authorized same-domain supervisor—or a verified parent delegator scoping revocation to its own task subtree—may quarantine a workload; cross-domain workloads must never globally brick foreign coordinators/tools). Add `JTIReplayCache` to command JWS verification.

---

#### [CRITICAL-04] Missing Recipient-Holder & Direct-Issuer Enforcement on Inbound Agent Routes (`/a2a/converge`, `/a2a/task`, `/v1/task-result`)
- **Location**:
  - `lineage/sidecar/proxy.py:246-263, 346-391`
  - `lineage/sidecar/context.py:106-150` (`MultiParentConvergenceInbox`)
  - `lineage/verifier/policy_verifier.py:343-360` (`_resolve_expected_dpop_jkt_single`)
- **Vulnerability Mechanism**:
  `LeafVerifier.verify_request` assumes that whenever `token.holder_spiffe_id != self.self_spiffe_id`, the caller (`token.holder_spiffe_id`) is legitimately invoking a tool at `self`. On `AgentSidecarNode` (`is_tool_server=False`), `_dispatch_inbound` sets `check_invocation_lattice=False` and **never checks that `parsed_token.holder_spiffe_id == self.identity.spiffe_id`** on `/a2a/task` or `/a2a/converge`, nor that `/v1/task-result` comes from a direct child (`hops[-1].issuer_spiffe_id == self.identity.spiffe_id`).
- **Exploit Impact & Empirical Reproduction (`test_04`)**:
  1. **Permanent DAG Convergence Poisoning DoS (`/a2a/converge`)**: Sibling agent `M` (holding `T_M` where `holder = M != C`) POSTs `T_M` to aggregator `C`'s `/a2a/converge`. `C` returns `200 OK` and appends `T_M` into `MultiParentConvergenceInbox`. When `C` subsequently tries to assemble its `MultiParentToken` for `(task_id, sub)`, `MultiParentToken.assemble_and_sign` fails with `TokenError("Parent chain holder 'M' != convergence holder 'C'")` (`400 convergence_assembly_failed`), permanently bricking legitimate `B1`/`B2` convergence!
  2. **Un-delegated Agent Handler Execution (`/a2a/task`)**: `M` (`holder = M != C`) invokes `C`'s `/a2a/task` handler with `200 OK` despite zero delegation to `C`.
  3. **Silent Parent Bypass on `/v1/task-result`**: In `A -> B1 -> C`, leaf `C` POSTs directly to `A`'s `/v1/task-result` using `T_C`, injecting a `DIRECT_PARENT` result into `A` while completely bypassing intermediate `B1` AND bypassing `SkipLevelReceipt` / `SKIP_LEVEL_ACCEPT` auditing!
- **Required Fix**:
  1. Add explicit endpoint role enforcement in `LeafVerifier.verify_request` / `LineageSidecar._dispatch_inbound`: for agent delegation/convergence endpoints (`/a2a/task`, `/a2a/converge` when `not self.is_tool_server`), strictly require `parsed_token.holder_spiffe_id == self.identity.spiffe_id` and `parsed_token.holder_cnf_jkt == self.identity.jkt` (and validate `holder_spiffe_id` inside `MultiParentConvergenceInbox.add_verified_branch`).
  2. For `/v1/task-result`, require single-chain `LineageToken` with `len(hops) >= 1`, `hops[-1].issuer_spiffe_id == self.identity.spiffe_id`, and DPoP matching `hops[-1].cnf_jkt` (`holder_cnf_jkt`).

---

### 2.2 HIGH Findings

#### [HIGH-01] Malicious Child Can Lie in `SkipLevelReceipt` to Evade Healthy Parent Supervision and Trick Ancestor `A` Into Revoking Healthy Parent `B_1`
- **Location**:
  - `lineage/resilience/coordinator.py:455-560` (`verify_and_accept_skip_level_request`)
  - `lineage/resilience/receipts.py:238-446` (`SkipLevelReceipt`)
  - `lineage/sidecar/proxy.py:187-220`
- **Vulnerability Mechanism**:
  `FailureEvidence` in `SkipLevelReceipt` is purely self-reported by child `C`. When `A` handles `/v1/skip-level-return`, `verify_and_accept_skip_level_request` performs **no liveness probe or directory status check** on the allegedly crashed intermediate `B_1` before accepting `C`'s payload and immediately calling `revocation_replica.revoke_prefix(caller=ancestor_identity, prefix=hop.lineage_path)` (`prune_dead_intermediate=True`). Additionally, `SkipLevelReceipt` lacks timestamp freshness and `receipt_id` replay checks.
- **Exploit Impact & Empirical Reproduction (`test_05`)**:
  While intermediate reviewer `B_1` is 100% alive (`GET /healthz -> 200`), rogue leaf `C` fabricates a `CRASH` `FailureEvidence`, delivers unreviewed output directly to `A` (`200 OK`), and causes `A` (acting as a confused deputy) to revoke healthy `B_1`'s subtree `/task-false-skip/A/B1` at `RevocationService`.
- **Required Fix**:
  1. In `verify_and_accept_skip_level_request`, actively probe the skipped intermediate ancestor(s)' `/healthz` endpoint (resolved via `B_0.ancestor_keys`, `hop.issuer_return_endpoint`, or `AgentDirectoryClient`) before accepting the skip-level return or pruning `B_1`. If `B_1` is reachable and healthy, reject with `403 INTERMEDIATE_ANCESTOR_ALIVE` and record a policy fault against `C`.
  2. Validate `SkipLevelReceipt.timestamp` freshness and deduplicate `receipt_id`.

---

#### [HIGH-02] `max_calls` Quota Bypassed via (A) Concurrent TOCTOU Race, (B) Offline Sibling Re-Attenuation Amplification, and (C) Multi-Branch DAG Quota Summing
- **Location**: `lineage/verifier/policy_verifier.py:111-127, 554-570, 690-735` (`_QuotaTracker` & `LeafVerifier.verify_request`)
- **Vulnerability Mechanism**:
  1. **Check-Then-Act TOCTOU Race**: `_QuotaTracker.peek_next` (lines 555, 692) and `_QuotaTracker.commit_increment` (lines 569, 733) release `_lock` while `check_invocation` / `composite.evaluate` runs, allowing concurrent threads on `max_calls=1` to read `next_idx=1` simultaneously and all succeed.
  2. **Leaf-Only Quota Tracking**: `_QuotaTracker` keys counts only on `(task_id, leaf_block_hash)` rather than tracking every block `[B_0, B_1, ..., B_k]` along the delegation chain against each block's `permissions.max_calls`.
- **Exploit Impact & Empirical Reproduction (`test_06`)**:
  - **Subtest A**: 16 concurrent requests against `max_calls=1` achieve multiple simultaneous `ALLOW` decisions.
  - **Subtest B**: Under `RootBlock` `B_0` with `max_calls=1`, `A` offline-mints 5 attenuated tokens to `C` (each has a fresh `jti` -> distinct `leaf_block_hash`); all **5 calls succeed** (`5 > 1`).
  - **Subtest C**: Two branches `B1 -> C` (`max_calls=1`) and `B2 -> C` (`max_calls=1`) under `RootBlock` `B_0` (`max_calls=1`) packaged in `MultiParentToken` succeed **2 times** (`2 > 1`).
- **Required Fix**:
  Implement an atomic `_QuotaTracker.try_consume_chain(task_id, block_quotas: Sequence[Tuple[str, int]]) -> Tuple[bool, Optional[str]]` holding `self._lock` across check-and-increment for **all blocks `[B_0, B_1, ..., B_k]`** in the chain (both single-chain and the chosen satisfying surviving chain in `MultiParentToken`), committing increments if and only if lattice checks pass and every block in the chain has remaining quota.

---

#### [HIGH-03] IEEE-754 `NaN` / `Infinity` Bypasses Timestamp Freshness in `DPoPVerifier`, `RevocationService`, `AgentDirectoryService`, and Crashes `LeafVerifier` (`CryptoError` 500)
- **Location**:
  - `lineage/common/crypto.py:407-408` (`jws_parse_unverified`)
  - `lineage/protocol/dpop.py:185-192` (`DPoPVerifier.verify_proof`)
  - `lineage/revocation/service.py:121-123` (`_verify_caller_command`)
  - `lineage/registry/directory.py:153-154` (`/v1/agents/quarantine`)
  - `lineage/protocol/token.py:190-191, 299-300, 827, 831` & `lineage/verifier/policy_verifier.py:202, 228, 548`
- **Vulnerability Mechanism**:
  Python's `json.loads()` accepts `NaN`, `Infinity`, `-Infinity` by default, and `float("nan")` parses `"nan"`. Because all IEEE-754 comparisons with `NaN` (`>`, `<`, `<=`, `>=`) evaluate to `False`:
  1. `DPoPVerifier` accepts `"iat": NaN` forever (even `now + 10 years`).
  2. `AgentDirectoryService` (`/v1/agents/quarantine`) accepts canonical JSON `"iat": "nan"` forever (`abs(time.time() - float("nan")) > 30.0` is `False`).
  3. `RevocationService` (`/v1/revoke/prefix`, `/v1/revoke/workload`) accepts `"iat": NaN` forever.
  4. `LeafVerifier.verify_request` parses `NaN` in `RootBlock.iat` via `decode_token`, skips `<`/`>` expiry checks, and throws an **uncaught `CryptoError`** at `canonical_json_bytes` (producing HTTP 500 instead of 401/403 `DENY`).
- **Empirical Reproduction**: `test_07`
- **Required Fix**:
  1. Reject non-finite constants in `json.loads` (`parse_constant` raising `ValueError`/`CryptoError`) inside `jws_parse_unverified`, `decode_token`, and `HTTPRequestContext.json`.
  2. Validate `not isinstance(v, bool) and isinstance(v, (int, float)) and math.isfinite(float(v))` on every timestamp (`iat`, `exp`, `timestamp`, `created_at`) across all modules.
  3. Catch `CryptoError` alongside `TokenError` in `LeafVerifier.verify_request`.

---

#### [HIGH-04] `CausalChainAuditor` Resilience / Multi-Parent Verification Blindspots & Unauthenticated `AuditCollectorService` Poisoning DoS
- **Location**:
  - `lineage/audit/auditor.py:238-242, 435-446, 466-520`
  - `lineage/resilience/receipts.py:227-228`
  - `lineage/audit/logger.py:301-308` (`AuditCollectorService`)
- **Vulnerability Mechanism & Empirical Reproduction (`test_08`, `test_11`)**:
  1. **Forged `FailoverReceipt` Accepted (`auditor.py:466-491`, `receipts.py:227`, `test_08`)**: `revocation_event_sig` is never cryptographically verified against `RevocationService`'s public key/SVID (any non-empty string like `"NOT_A_REAL_REVOCATION_SERVICE_SIGNATURE"` passes!), `fr.parent_spiffe_id` is not verified as an authorized delegator in `block_producers`, and `REVOCATION_ISSUED` is accepted even when logged *after* `FAILOVER_PRUNE_GRAFT` without any `RevocationService` signature.
  2. **`SkipLevelReceipt` Foreign-Root & Post-Expiry Audit Flaws (`auditor.py:498-518`, `test_11`)**: `CausalChainAuditor` checks `sr.task_id == task_id` on the receipt without checking `embedded_tok.root_block_hash == rec.root_block_hash` or `embedded_tok.sub == rec.sub`, allowing a receipt minted under a foreign domain's `RootBlock` to be classified as `VERIFIED_SKIP_LEVEL_MERGE`. Also, `verify_single_chain_full(embedded_tok)` omits `now=sr.timestamp`, causing valid historical logs audited after token TTL expiration to falsely fail!
  3. **`MultiParentToken` Partial Ancestry Walk (`auditor.py:438`, `test_11`)**: `cur_h = prod.multi_parent_hashes[0]` only follows index `0` of an upstream `MultiParentToken` producer, missing unanchored cycles (`CAUSAL_CYCLE`) or broken ancestry on `multi_parent_hashes[1:]`.
  4. **Unauthenticated `AuditCollectorService` Poisoning (`logger.py:301-308`, `test_08`)**: `POST /v1/audit/append` accepts unverified entries from anonymous callers; injecting one bogus entry into a victim `task_id` flips `reconstructed_complete` to `False` (Audit DoS).
- **Required Fix**:
  1. Embed `revocation_service_svid` + full `RevocationEvent` in `FailoverReceipt` and verify its `lct-revocation-event+jwt` signature, target match, causal parent membership in `block_producers`, and temporal/causal ordering (`prune` before `graft`).
  2. In `SKIP_LEVEL_ACCEPT` audit, verify `embedded_tok.root_block_hash == rec.root_block_hash`, `embedded_tok.sub == rec.sub`, and pass `now=sr.timestamp` to `verify_single_chain_full` (plus trace intermediate hops in `block_producers` if present).
  3. Traverse **all** `prod.multi_parent_hashes` via a worklist/BFS in `auditor.py:435-446`.
  4. Authenticate and signature-verify `AuditEntry` against `TrustBundleResolver` on ingest in `AuditCollectorService` before appending.

---

### 2.3 MEDIUM Findings

#### [MEDIUM-01] Fagin Multi-Path DAG Fails to Degrade When a Single Parent Branch Expires + Cross-Root Splicing Across Federated CAs
- **Location**: `lineage/verifier/policy_verifier.py:386-398, 595, 626-644`, `lineage/protocol/token.py:555-587`, `lineage/sidecar/context.py:131-150`
- **Details & Empirical Reproduction (`test_09`)**:
  1. **Single-Branch Expiry Kills Entire `MultiParentToken`**: When `B_1` (`ttl=1s`) expires while sibling `B_2` (`ttl=600s`) remains valid and fully authorizes `book_hotel`, `verify_single_chain_full` raises `TokenError("Hop 1 has expired")` at line 634 and `LeafVerifier` aborts the entire `MultiParentToken` (`403 INVALID_CHAIN_IN_MULTIPARENT`) instead of pruning expired `B_1` into `pruned_chains` and smoothly degrading to `B_2` (`ALLOW_DEGRADED_DAG`).
  2. **Cross-Root Splicing**: `MultiParentToken` checks `(task_id, sub)` equality across `parent_chains` without checking `chain.root_block_hash == parent_chains[0].root_block_hash` (or matching `sub`'s `@<domain>` to `issuer_trust_domain`), allowing a second federated CA (`org-beta.io`) to splice an inflated `RootBlock` (`max_amount=99999`) onto `user:alice@org-alpha.io`'s `task_id` (`max_amount=50`) while `LeafVerifier` logs only `parent_chains[0].root_block_hash`.
- **Required Fix**:
  1. Verify cryptographic signatures, links, and lattice monotonicity on every branch first (rejecting tampering/escalation with `403`), while treating purely expired branches (`exp <= ts - clock_skew`) as inactive/pruned branches alongside revoked branches so surviving unexpired branches degrade cleanly. Also filter expired chains in `MultiParentConvergenceInbox.assemble_multiparent_token`.
  2. Require `chain.root_block_hash == parent_chains[0].root_block_hash` across all `parent_chains` in `MultiParentToken`, and if `sub` ends with `@<domain>`, require `root.issuer_trust_domain == <domain>`.

---

#### [MEDIUM-02] `ResilientDelegationCoordinator` Prematurely Trips `policy_breaker_threshold` on First `401`/`403` via Artificial `while` Loop
- **Location**: `lineage/resilience/coordinator.py:166-173, 209-222`
- **Details & Empirical Reproduction (`test_10`)**:
  Even when `ThreeLayerFaultDetector(policy_breaker_threshold=3)` is configured, on the very first `401` or `403` response from a delegate, `invoke_with_prune_and_graft` executes:
  ```python
  while evidence is None:
      evidence = self.detector.record_policy_violation(...)
  ```
  pumping the violation counter in-memory without retrying HTTP, immediately tripping `POLICY_BYZANTINE` and globally quarantining `B_1` on a single transient `401`/`403`.
- **Required Fix**: Remove the `while evidence is None:` loop; only increment `record_policy_violation` once per actual failed HTTP attempt, pruning the single task branch on non-tripped `401`/`403` and issuing global workload quarantine only when `policy_breaker_threshold` genuine violations occur.

---

#### [MEDIUM-03] Unbounded Memory Growth in Long-Running Sidecars/Verifiers & Default `MultiParentToken` Downstream Lattice Truncation
- **Location**: `lineage/verifier/policy_verifier.py:116`, `lineage/sidecar/context.py:103-104`, `lineage/sidecar/proxy.py:118-119, 551-555`
- **Details**:
  1. `_QuotaTracker._counts`, `MultiParentConvergenceInbox._chains`/`_branch_payloads`, and `LineageSidecar._skip_level_results`/`_direct_results` never evict expired/old tasks (`max_entries` + TTL eviction needed, matching `JTIReplayCache`).
  2. In `LineageSidecar._dispatch_outbound` (`proxy.py:551-555`), when `active_tok` is a `MultiParentToken` and `body["permissions"]` is omitted, `attenuated_perms` defaults to `active_tok.parent_chains[0].leaf_permissions`, truncating `parent_chains[1:]` by intersecting them with branch 0's lattice.
- **Required Fix**: Add bounded `OrderedDict` + TTL eviction to all four state stores; when `permissions` is omitted during `MultiParentToken` delegation, attenuate each parent chain with its own `chain.leaf_permissions` (or add `attenuate_passthrough`).

---

### 2.4 LOW Findings

#### [LOW-01] Non-Constant-Time Loopback Secret Comparison
- **Location**: `lineage/sidecar/proxy.py:433, 823, 1103`
- **Details**: `req.header("X-LCT-Loopback-Auth") != self.loopback_secret` uses `!=` instead of `hmac.compare_digest`.
- **Required Fix**: Replace with `not hmac.compare_digest(req.header("X-LCT-Loopback-Auth") or "", self.loopback_secret)`.

#### [LOW-02] Trailing-Slash `/mcp/` Bypass on Standalone `LineageSidecar` When `is_tool_server=False`
- **Location**: `lineage/sidecar/proxy.py:238, 395`
- **Details**: `req.path == "/mcp"` does not match `"/mcp/"` if `LineageSidecar` is instantiated directly with `is_tool_server=False`, skipping `check_lattice = True` while still forwarding `req.raw_path` upstream.
- **Required Fix**: Normalize `norm_path = req.path.rstrip("/") or "/"` before matching routes (`/mcp`, `/a2a/converge`, `/v1/task-result`, `/v1/skip-level-return`).

---

## 3. Reproduction Command

```bash
cd /Users/hulalala/Desktop/A
PYTHONPATH=/Users/hulalala/Desktop/A /Users/hulalala/Desktop/A/src/cortex/authbridge/venv/bin/python3 -m unittest lineage/reviews/qa_adversarial_milestone1.py -v
```
