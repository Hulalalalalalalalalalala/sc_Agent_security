# Milestone 1 Round-2 Re-Audit & Second-Order Red-Team QA Report (`lineage/`)

- **QA Inspector**: `qa-inspector` (Independent Read-Only Security & Concurrency Audit Session)
- **Round-2 Verification Suite**: `/Users/hulalala/Desktop/A/lineage/reviews/qa_reaudit_round2.py` (`6/6` empirical checks executed in `0.71s`)
- **Round-2 Verdict**: **`NEEDS_FIX`** (**9/13** Round-1 items 100% closed & second-order clean; **5 Second-Order Bypasses** uncovered across the remaining 4 areas: **1 Critical, 3 High, 1 Medium**)

---

## 1. Anti-Tampering & Historical Baseline Verification (`PASS`)

1. **Round-1 QA Artifacts Intact**:
   - `lineage/reviews/MILESTONE1_QA_REPORT.md` (`26,740` bytes, `Nov 18 17:25`) and `lineage/reviews/qa_adversarial_milestone1.py` (`54,229` bytes, `Nov 18 17:22`) were verified untouched.
2. **Historical Baselines Zero-Polluted**:
   - `find /Users/hulalala/Desktop/A/README.md /Users/hulalala/Desktop/A/lab /Users/hulalala/Desktop/A/src -newer /Users/hulalala/Desktop/A/lineage/__init__.py` returned **0 modified files**.
3. **Full Test & Benchmark Suite Verified**:
   - `lineage.tests.run_all` (`32/32` tests including `test_security_regressions.py` + `test_multiprocess_topologies.py` + microbenchmarks) passed cleanly in `10.19s`.

---

## 2. Round-1 Defect Remediation Matrix (13 Items)

| Round-1 ID | Primary Vector Fixed? | Second-Order Audit Status | Notes |
| --- | --- | --- | --- |
| `CRITICAL-01` | Yes | **CLOSED (Clean)** | `RiskClassifier.classify` (`policy_verifier.py:100-139`) computes intrinsic risk first (including `amount`/`max_amount` & non-finite escalation); hints are strictly monotonic (`LOW -> HIGH` only). |
| `CRITICAL-02` | Yes (`Host` header) | **SECOND-ORDER BYPASS (`CRITICAL-R2-01`)** | `Host` header is validated, **but** unvalidated `req.raw_path` starting with `@host:port` smuggles RFC 3986 userinfo into `authoritative_url` and `app_upstream_url`, causing SSRF + `X-LCT-Loopback-Auth` secret exfiltration + full Sidecar bypass! |
| `CRITICAL-03` | Yes (foreign leaf) | **SECOND-ORDER BYPASS (`HIGH-R2-01`, `HIGH-R2-02`)** | (1) Unilateral offline `attenuate()` lets any low-privilege same-domain leaf globally quarantine arbitrary peers/tools; (2) Cross-domain `ca_beta` preemptively revokes `org-alpha.io` tasks & hijacks `_task_domains` (plus `task_id` Trie collision). |
| `CRITICAL-04` | Yes | **CLOSED (Clean)** | `require_recipient_self` on `/a2a/*`, `expected_holder_*` inside `MultiParentConvergenceInbox`, and `require_direct_child_issuer` on `/v1/task-result` hold cleanly. |
| `HIGH-01` | Yes (when URL set) | **SECOND-ORDER BYPASS (`MEDIUM-R2-01`)** | (1) Unvalidated `issuer_return_endpoint` allows query-smuggling SSRF during `/healthz` probing; (2) Empty `_resolve_trusted_skipped_endpoints` (`[]`) fails open without probing. |
| `HIGH-02` | Yes | **CLOSED (Clean)** | Two-phase check-before-mutate under lock across all blocks `[B_0..B_k]`; verified **zero partial mutation** when Branch 1 leaf fails quota while `B_0` + Branch 2 succeed (`test_00`). |
| `HIGH-03` | Yes | **CLOSED (Clean)** | `strict_json_loads` + `require_finite_timestamp` reject `NaN`/`±Infinity`/`bool`/`"nan"` across all JWS, tokens, services, and `LeafVerifier` returns clean `401 MALFORMED_TOKEN`. |
| `HIGH-04` | Partial | **SECOND-ORDER BYPASS (`HIGH-R2-03`)** | MultiParent DFS (`_trace_all_paths_to_root`) and `SkipLevelReceipt` root/historical checks are clean, **but**: (1) `FailoverReceipt` accepts `parent_svid` as `revocation_service_svid` (`expected_spiffe_id=None`); (2) Default `AuditCollectorService()` (`trust_resolver=None`) accepts unsigned `domain_authority` & self-signed `workload` entries! |
| `MEDIUM-01` | Yes | **CLOSED (Clean)** | Cryptographic & monotonic checks execute strictly before `TokenExpiredError`; expired + signature-tampered branch still fails whole envelope with `403 INVALID_CHAIN_IN_MULTIPARENT` (`test_00`). |
| `MEDIUM-02` | Yes | **CLOSED (Clean)** | Artificial `while` loop removed; global quarantine only fires after `policy_breaker_threshold` genuine violations. |
| `MEDIUM-03` | Yes | **CLOSED (Clean)** | `OrderedDict` TTL/LRU bounds added; `MultiParentToken.attenuate_to_delegate(requested_permissions=None)` preserves per-branch disjunctive boundaries without merging or truncating. |
| `LOW-01` | Yes | **CLOSED (Clean)** | `_constant_time_secret_match` uses `hmac.compare_digest` at all 3 loopback check sites. |
| `LOW-02` | Yes | **CLOSED (Clean)** | `norm_path = req.path.rstrip("/") or "/"` properly catches `/mcp/`. |

---

## 3. New Second-Order Vulnerabilities Uncovered in Round-2

### [CRITICAL-R2-01] Request-Target `@host:port` Userinfo Smuggling Causes DPoP `htu` Bypass, SSRF, `X-LCT-Loopback-Auth` Exfiltration, and Total Unauthenticated Sidecar Escape
- **Location**:
  - `lineage/common/http_utils.py:44-48, 65-69` (`HTTPRequestContext.__init__`, `authoritative_url`)
  - `lineage/sidecar/proxy.py:222-223, 461-475` (`_dispatch_inbound` upstream proxy forwarding)
- **Root Cause**:
  Python's `BaseHTTPRequestHandler` accepts any non-whitespace request-target in the HTTP request line (e.g., `POST @127.0.0.1:9999/mcp HTTP/1.1`), without requiring origin-form (`raw_path.startswith("/")` and `not raw_path.startswith("//")`).
  1. `req.validate_host_header()` only inspects the `Host:` header (which the attacker sets honestly to `127.0.0.1:<vault_inbound_port>`), returning `(True, "ok")`.
  2. `req.authoritative_url` concatenates `f"http://{self.authoritative_authority}{self.path}"` -> `"http://127.0.0.1:<vault_inbound_port>@127.0.0.1:<evil_port>/mcp"`. Under RFC 3986 URI parsing (`urlparse` inside `normalize_htu`), `127.0.0.1:<vault_inbound_port>@` is parsed as **`userinfo`**, and `127.0.0.1:<evil_port>` becomes the **`hostname:port`**, so `normalize_htu(auth_htu)` evaluates to `"http://127.0.0.1:<evil_port>/mcp"`, matching a DPoP proof signed for `<evil_port>`!
  3. After `get_weather` (`max_amount=0`) passes `LeafVerifier`, `LineageSidecar` executes:
     ```python
     httpx.request(
         method=req.method,
         url=f"{self.app_upstream_url}{req.raw_path}",
         headers={"X-LCT-Loopback-Auth": self.loopback_secret, ...},
     )
     ```
     Because `f"http://127.0.0.1:<app_port>@127.0.0.1:<evil_port>/mcp"` also parses `127.0.0.1:<app_port>@` as HTTP Basic Auth userinfo, `LineageSidecar` connects directly to `<evil_port>` and **hands the attacker both `self.loopback_secret` (`X-LCT-Loopback-Auth`) and the exact ephemeral `127.0.0.1:<app_port>` (in `Authorization: Basic ...`)**!
- **Exploit Impact & Empirical Reproduction (`test_r2_01`)**:
  Starting with ONLY a zero-budget `get_weather` (`max_amount=0.0`) token, `w_low` exfiltrates `vault_node`'s `X-LCT-Loopback-Auth` secret and `app_port` in a single request, then connects directly to `http://127.0.0.1:<app_port>/mcp` with **zero token, zero DPoP, zero quota, and zero audit logging** to execute `execute_payment(amount=9_999_999.0)` (`200 OK`)!
- **Required Fix**:
  1. In `ManagedHTTPService` / `HTTPRequestContext`, strictly enforce HTTP/1.1 origin-form request targets: reject (`400 Bad Request`) any `raw_path` that does not start with `"/"`, starts with `"//"`, or contains whitespace/control characters; ensure `self.path` always starts with `"/"` and never `"//"`.
  2. When `LineageSidecar` forwards to `self.app_upstream_url`, construct the target URL strictly using validated origin-form path + query (`f"{self.app_upstream_url}{req.path}" + (f"?{req.query_raw}" if req.query_raw else "")`) and verify `urlparse(fwd_url).netloc == urlparse(self.app_upstream_url).netloc` before sending `X-LCT-Loopback-Auth`!

---

### [HIGH-R2-01] Unilateral Offline `AttenuationBlock` Minting Allows Any Low-Privilege Same-Domain Agent to Globally & Permanently Quarantine Arbitrary Peer Workloads
- **Location**:
  - `lineage/revocation/service.py:262-316` (`_authorize_workload_quarantine`)
  - `lineage/registry/directory.py:227-260` (`/v1/agents/quarantine`)
- **Root Cause**:
  Both services allow any non-admin same-domain workload `caller` to issue a **global** workload quarantine against `target` whenever `caller` supplies an `authority_token` in which `d_paths[caller]` is a prefix of `d_paths[target]`.
  However, `LineageToken.attenuate()` is an **offline unilateral operation** signed exclusively by `caller`—`target` never signs, accepts, or even sees an offline-minted `AttenuationBlock`!
- **Exploit Impact & Empirical Reproduction (`test_r2_02`)**:
  A sandboxed hop-1 agent `w_low_leaf` (`org-alpha.io`) holding only a `get_weather` token unilaterally calls `t_low.attenuate(w_low_leaf, w_critical_pay_agent.spiffe_id, ...)` in memory without ever contacting `w_critical_pay_agent`, then submits that token as `authority_token` to `RevocationService` and `AgentDirectoryService`, **globally killing `w_critical_pay_agent` across all tasks and permanently banning it from re-registering**!
- **Required Fix**:
  Global workload quarantine (`WORKLOAD_QUARANTINE` and `AgentDirectoryService` quarantine) affects **all tasks cluster-wide**, not just one task branch. Restrict global workload quarantine to:
  1. Same-domain `TrustDomainCA` (`auth_mode == "domain_authority"`),
  2. Explicitly configured `authorized_admins`, OR
  3. At minimum, a **CA-attested Root Hop-0 Coordinator** (`parsed.root.delegate_spiffe_id == caller_spiffe.uri` and `parsed.root.issuer_trust_domain == caller_spiffe.trust_domain`, where the Root CA explicitly entrusted `caller` as task root coordinator in `B_0`)—**never** an arbitrary downstream leaf/intermediate hop (`hop >= 1`) unilaterally appending a dummy hop! (Downstream intermediate hops handling child faults still retain full ability to prune their own task subtree `/<task_id>/.../child` via `/v1/revoke/prefix` without globally assassinating shared workloads.)

---

### [HIGH-R2-02] Cross-Domain Preemptive Task Revocation, `_task_domains` Ownership Hijack, and Unscoped `task_id` Prefix Trie Collision
- **Location**:
  - `lineage/revocation/service.py:194-203, 240-242` (`_authorize_prefix_revocation`)
  - `lineage/revocation/trie.py:110-160, 222-254` (`LineagePrefixTrie`)
  - `lineage/verifier/policy_verifier.py:371, 806` (`trie.check_chain`)
- **Root Cause**:
  1. In `RevocationService._authorize_prefix_revocation` (`service.py:194-203`), when `auth_mode == "domain_authority"`, `known_td = self._task_domains.get(target_task_id)` is `None` for **every active task that has not been revoked yet**. Thus a foreign partner CA (`ca_beta` in `org-beta.io`) can preemptively call `/v1/revoke/prefix` on `org-alpha.io`'s active `/task-alpha-live-01`, killing the task AND locking `_task_domains["task-alpha-live-01"] = "org-beta.io"` so legitimate owner `ca_alpha` is rejected (`403 Cross-domain CA`)!
  2. In `workload` mode, `ca_beta` can mint a valid `org-beta.io` `RootBlock` reusing `task_id="task-alpha-live-02"` (`sub="user:mallory@org-beta.io"`), and `w_beta` can revoke `/task-alpha-live-02`. Because `LineagePrefixTrie` stores `/<task_id>/...` in a single unscoped namespace without binding to `root.issuer_trust_domain`, `org-beta.io`'s revocation collides with and kills `org-alpha.io`'s `"task-alpha-live-02"`!
- **Empirical Reproduction**: `test_r2_03` (both `domain_authority` hijack and `workload` cross-domain `task_id` collision reproduced).
- **Required Fix**:
  Scope prefix revocations in `RevocationEvent` and `LineagePrefixTrie` by **`trust_domain: Optional[str]`**:
  - When revoking via HTTP (`domain_authority` -> `caller_td`; `workload` with `authority_token` -> `parsed.root.issuer_trust_domain`), record `trust_domain` on `RevocationEvent` (while allowing `revoke_prefix_direct(..., trust_domain=None)` to act as a wildcard `None`/`"*"` for local direct admin/unit-test calls).
  - In `LineagePrefixTrie`, store revocations per-domain (plus wildcard `None`) and check `token.root.issuer_trust_domain` in `LeafVerifier` (`trie.check_chain(chain.lineage_path, chain.visited_subjects, trust_domain=chain.root.issuer_trust_domain)`).
  - Then `org-beta.io` (whether via `domain_authority` or `workload` mode) can ONLY ever revoke tasks rooted in `org-beta.io`, eliminating both cross-domain task sabotage and `_task_domains` ownership hijacking!

---

### [HIGH-R2-03] `FailoverReceipt` Accepts Self-Signed `RevocationEvent` via `parent_svid`, and Default `AuditCollectorService()` (`trust_resolver=None`) Allows Unauthenticated Log Poisoning
- **Location**:
  - `lineage/resilience/receipts.py:271-285` (`FailoverReceipt.from_dict_and_verify`)
  - `lineage/audit/auditor.py:486-535` (`CausalChainAuditor`)
  - `lineage/audit/logger.py:275-281, 334-352` (`AuditCollectorService`)
- **Root Cause & Empirical Reproduction (`test_r2_04`)**:
  1. **Self-Signed `RevocationService` Spoof in `FailoverReceipt` (`Subtest A`)**:
     `FailoverReceipt.from_dict_and_verify` calls `trust_resolver.verify_workload_svid(receipt.revocation_service_svid, now=eval_ts)` with `expected_spiffe_id=None`. A compromised parent `A` can pass **its own `A.workload_svid`** as `revocation_service_svid` and sign a fake `RevocationEvent` with `A`'s own keypair (`typ="lct-revocation-event+jwt"`) without ever contacting `RevocationService` (leaving zombie `B_1` unrevoked!), and `CausalChainAuditor` classifies it as `VERIFIED_FAILOVER_GRAFT` (`clean=True`)!
  2. **Unauthenticated Default `AuditCollectorService()` (`Subtest B`)**:
     In `test_multiprocess_topologies.py:94` and `test_resilience_protocols.py:71, 268`, `AuditCollectorService()` is instantiated with the default `trust_resolver=None`. Inside `_verify_entry_on_ingest` (`logger.py:334-352`), when `self.trust_resolver is None`:
     - `auth_mode == "domain_authority"` calls `jws_parse_unverified(entry.node_signature)` with **zero cryptographic signature verification**!
     - `auth_mode == "workload"` calls `jws_parse_unverified(entry.node_svid_or_domain)`, accepting any attacker-generated self-signed SVID!
     Thus an anonymous network caller can inject forged entries into `AuditCollectorService()` and flip legitimate tasks to `reconstructed_complete = False`.
- **Required Fix**:
  1. In `FailoverReceipt.from_dict_and_verify` and `CausalChainAuditor`:
     - Reject `rev_svc_claims["sub"] == receipt.parent_spiffe_id` or `rev_svc_claims["sub"] in (receipt.failed_delegate_spiffe_id, receipt.substitute_delegate_spiffe_id)`;
     - Require `rev_svc_claims["sub"]` to match an authorized revocation service identity convention (e.g., SPIFFE path containing `/revocation` or `/sa/rev`, or an optional `trusted_revocation_spiffe_ids` allowlist on `CausalChainAuditor`).
  2. In `AuditCollectorService`: require `trust_resolver: TrustBundleResolver` (pass `resolver` in `_run_audit_collector_process` in `test_multiprocess_topologies.py` and in `test_resilience_protocols.py`, and remove the unverified `jws_parse_unverified` fallback in `logger.py:334-352`!).

---

### [MEDIUM-R2-01] Unvalidated `return_endpoint` Query Smuggling SSRF & Empty-Endpoint Fail-Open in Skip-Level Liveness Probe
- **Location**:
  - `lineage/protocol/token.py:189-193, 321-323, 475-495, 816-829` (`ancestor_keys` & `issuer_return_endpoint`)
  - `lineage/resilience/coordinator.py:479-505, 577-594` (`_resolve_trusted_skipped_endpoints`, `verify_and_accept_skip_level_request`)
- **Root Cause & Empirical Reproduction (`test_r2_05`)**:
  1. **Query-Smuggling SSRF (`Subtest A`)**: Neither `RootBlock` nor `AttenuationBlock` validates `return_endpoint` / `issuer_return_endpoint` as a clean `http(s)://<host>:<port>` origin without path/query/fragment/userinfo. Setting `issuer_return_endpoint="http://127.0.0.1:<internal_port>/admin/wipe?swallow="` causes `verify_and_accept_skip_level_request` (`f"{sk_base}/healthz"`) to fire `GET /admin/wipe?swallow=/healthz` against the internal service!
  2. **Empty-Endpoint Fail-Open (`Subtest B`)**: When `trusted_urls` resolves to `[]` (e.g., `issuer_return_endpoint=None` and `directory_client=None` or lookup error), `for sk_base in trusted_urls:` performs **0 probes** and silently accepts `C`'s false crash claim even while `B_1` is alive!
- **Required Fix**:
  1. Validate every `return_endpoint` / `issuer_return_endpoint` in `token.py` and `_resolve_trusted_skipped_endpoints` (`scheme in ("http", "https")`, valid `hostname`, no `username`/`password`, no `query`/`fragment`, normalized clean origin/path).
  2. In `verify_and_accept_skip_level_request`, fail closed (`raise ResilienceError("Cannot verify liveness of skipped ancestor: no trusted endpoint attested in chain or directory")`) when `trusted_urls` is empty!

---

## 4. Reproduction Command

```bash
cd /Users/hulalala/Desktop/A
PYTHONPATH=/Users/hulalala/Desktop/A /Users/hulalala/Desktop/A/src/cortex/authbridge/venv/bin/python3 -m unittest lineage/reviews/qa_reaudit_round2.py -v
```
