# Milestone 1 — Round-3 Final Sign-Off & Third-Order Red-Team Audit Report

- **Auditor**: `qa-inspector` (Independent Security & Code Review Session)
- **Target**: `/Users/hulalala/Desktop/A/lineage/`
- **Audit Scope**: Verification of Round-1 (`13/13`) + Round-2 (`5/5`) security fixes, baseline & prior-report integrity check, and Third-Order Boundary & Parser-Differential Red-Team Probing
- **Adversarial Suite**: [qa_final_round3.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_final_round3.py) (`5/5` deterministic proof tests executed)
- **Overall Verdict**: **`NEEDS_FIX`** *(0 Critical, 2 High, 1 Medium — All 18 prior R1+R2 vectors confirmed closed; 3 third-order boundary vulnerabilities empirically reproduced)*

---

## 1. Baseline & Review-Artifact Integrity Verification

1. **Historical Baselines (`README.md`, `lab/`, `src/`)**:
   - Verified via filesystem mtime comparison (`find /Users/hulalala/Desktop/A/README.md /Users/hulalala/Desktop/A/lab /Users/hulalala/Desktop/A/src -newer /Users/hulalala/Desktop/A/lineage/__init__.py -ls`): **0 files modified** (**Zero Baseline Pollution**).
2. **Prior QA Review Artifacts (`lineage/reviews/`)**:
   - Verified untouched byte-for-byte:
     - [MILESTONE1_QA_REPORT.md](file:///Users/hulalala/Desktop/A/lineage/reviews/MILESTONE1_QA_REPORT.md) (`26,740` bytes)
     - [qa_adversarial_milestone1.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_adversarial_milestone1.py) (`54,229` bytes)
     - [MILESTONE1_QA_ROUND2_REPORT.md](file:///Users/hulalala/Desktop/A/lineage/reviews/MILESTONE1_QA_ROUND2_REPORT.md) (`16,846` bytes)
     - [qa_reaudit_round2.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_reaudit_round2.py) (`30,089` bytes)
3. **Existing Engineering Regression Suite**:
   - Independently executed `PYTHONPATH=/Users/hulalala/Desktop/A python3 -m lineage.tests.run_all`: **`37/37` unit/integration/regression tests + benchmarks passed** (`exit code 0`).

---

## 2. Verification Matrix of Prior Round-1 (13) & Round-2 (5) Fixes

| Prior ID | Fix Status on Direct Vector | Third-Order Boundary Assessment |
| :--- | :---: | :--- |
| `CRITICAL-01..04`, `HIGH-01..04`, `MEDIUM-01..03`, `LOW-01..02` (13 R1 items) | **CLOSED (13/13)** | Confirmed in `test_01_round1_all_13_attacks_blocked`. |
| `CRITICAL-R2-01` (`@host` / `//host` origin-form SSRF & loopback leak) | **CLOSED on SSRF** | `@host`, `//host`, `http://host`, `%40`, and `%2f%2f` cannot escape `app_upstream_url` host/port (**0 SSRF hits**). **HOWEVER**, single-dot segments (`/./mcp`, `/mcp/.`) and percent-encoded paths (`/%6d%63%70`) cause a parser differential between `LineageSidecar` and `httpx`/upstream -> see **`HIGH-R3-01`**. |
| `HIGH-R2-01` (Hop-1 unilateral `attenuate()` global quarantine) | **CLOSED for Hop>=1** | Hop-1/sandbox workloads and `/ns/sys/` targets are properly protected. **HOWEVER**, expired `B_0` (`except TokenExpiredError: pass`), revoked Hop-0 tasks, and **already-quarantined** Hop-0 workloads can still retaliate -> see **`MEDIUM-R3-01`**. |
| `HIGH-R2-02` (`LineagePrefixTrie` `trust_domain` isolation) | **CLOSED in Trie/Verifier** | `_wildcard_root` is unreachable over HTTP `/v1/revoke/prefix` even when `trust_domain: null` is injected; `LeafVerifier` passes `issuer_trust_domain`. **HOWEVER**, `FailoverReceipt` & `CausalChainAuditor` ignore `RevocationEvent.trust_domain` -> see **`HIGH-R3-02`**. |
| `HIGH-R2-03` (`FailoverReceipt` authoritative SVID & `AuditCollectorService` resolver) | **PARTIAL** | `AuditCollectorService` strictly requires `TrustBundleResolver` (`TypeError` otherwise), and same-domain non-`/ns/sys/sa/rev` peers cannot self-certify `RevocationEvent`. **HOWEVER**, foreign-domain `/ns/sys/sa/rev` SVIDs and cross-domain `RevocationEvent`s bypass `FailoverReceipt` -> see **`HIGH-R3-02`**. |
| `MEDIUM-R2-01` (`validate_clean_endpoint_url` & fail-closed `/healthz` probe) | **CLEANLY CLOSED** | Clean origins enforced at mint/attenuate/decode/`AgentCard`; `follow_redirects=False` blocks `302` SSRF; `liveness_probe_timeout` bounds slow responses; empty probe list fails closed (`403 SKIP_LEVEL_UNVERIFIABLE_LIVENESS`). |

---

## 3. Newly Discovered Round-3 Third-Order Defects (Must Fix Before Sign-Off)

### `[HIGH-R3-01]` Single-Dot (`/./mcp`, `/mcp/.`) & Percent-Encoded (`/%6d%63%70`) Path Differential Bypasses `/mcp` `PermissionLattice` & Quota Enforcement on Standalone `LineageSidecar`
- **Severity**: **High** *(Critical impact on standalone `LineageSidecar(is_tool_server=False)` deployments; `MCPToolSidecarNode` sets `is_tool_server=True` and is unaffected)*
- **Locations**:
  - [http_utils.py](file:///Users/hulalala/Desktop/A/lineage/common/http_utils.py#L21-L49) (`validate_origin_form_target`)
  - [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L224-L333) & [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L462-L488) (`LineageSidecar._dispatch_inbound`)
- **Root Cause**:
  1. `validate_origin_form_target` ([http_utils.py](file:///Users/hulalala/Desktop/A/lineage/common/http_utils.py#L46)) checks `".." in sp.path.split("/")`, rejecting double-dot `..`, **but permits single-dot `.` segments** (`/./mcp`, `/mcp/.`), mid-path double slashes (`/.//127.0.0.1:9999/mcp`), and percent-encoded ASCII paths (`/%6d%63%70`, `/%2e/mcp`).
  2. In `LineageSidecar._dispatch_inbound` ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L224) & [L310](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L310)), when `is_tool_server=False` (the default parameter of `LineageSidecar`), `norm_path = req.path.rstrip("/") or "/"` evaluates `"/./mcp"` to `"/./mcp"` (`!= "/mcp"`), setting `is_mcp_route = False` and **`check_lattice = False`**.
  3. An attacker `w_c` holding only `tools=["get_weather"], max_calls=1` (zero permission for `execute_payment`) offline-attenuates `get_weather` to `w_tool` using only `w_c`'s own private key, signs DPoP for `POST /./mcp`, and sends `{"method": "tools/call", "params": {"name": "execute_payment", "arguments": {"amount": 9999999}}}`.
  4. `LineageSidecar` skips `PermissionLattice` and quota checks, attaches `X-LCT-Loopback-Auth`, and calls `self._http_client.request("POST", "http://127.0.0.1:<app>/./mcp", ...)`. **`httpx` implements RFC 3986 §5.2.4 dot-segment removal and rewrites `/./mcp` and `/mcp/.` to `POST /mcp` on the wire**! Even `ManagedHTTPService` itself receives `req.path == "/mcp"` with valid `X-LCT-Loopback-Auth` and executes `execute_payment`! Moreover, `/.//host/mcp` causes `httpx` to emit a protocol-relative `POST //host/mcp` on the upstream wire, and `/%6d%63%70` bypasses `norm_path == "/mcp"` on any percent-decoding ASGI/WSGI upstream.
- **Empirical Proof**: Reproduced in `qa_final_round3.py::test_03_r3_high_01_dot_segment_and_percent_encoded_mcp_lattice_bypass` (`3/3` unauthorized `execute_payment(amount=9999999)` calls returned `HTTP 200` despite `tools=["get_weather"], max_calls=1`).
- **Required Fix**:
  1. In `validate_origin_form_target` ([http_utils.py](file:///Users/hulalala/Desktop/A/lineage/common/http_utils.py#L21-L49)):
     - Reject any empty/dot segment in `sp.path`: reject if `"//" in sp.path` or `any(seg in (".", "..") for seg in sp.path.split("/"))`.
     - Also compute `unquoted = urllib.parse.unquote(sp.path)` and reject if `"\\" in unquoted`, `"@" in unquoted`, `"//" in unquoted`, `any(ord(c) <= 0x1F or ord(c) == 0x7F for c in unquoted)`, or `any(seg in (".", "..") for seg in unquoted.split("/"))`.
  2. In `LineageSidecar._dispatch_inbound` ([proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L224) & [L462-L485](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L462-L485)):
     - Derive `norm_path = urllib.parse.unquote(req.path).rstrip("/") or "/"` so `/%6d%63%70` is always classified identically to `/mcp`.
     - Before calling `self._http_client.request(...)`, verify `httpx_url = httpx.URL(fwd_url)` has `(httpx_url.scheme, httpx_url.host, httpx_url.port) == (up_sp.scheme, up_sp.hostname, up_sp.port)` and `not httpx_url.raw_path.startswith(b"//")`.

---

### `[HIGH-R3-02]` Cross-Domain `RevocationEvent.trust_domain` & Foreign `/ns/sys/sa/rev` Confusion in `FailoverReceipt` + `CausalChainAuditor` Enables Split-Brain Prune-Before-Graft Bypass
- **Severity**: **High**
- **Locations**:
  - [receipts.py](file:///Users/hulalala/Desktop/A/lineage/resilience/receipts.py#L267-L348) (`FailoverReceipt.from_dict_and_verify`)
  - [auditor.py](file:///Users/hulalala/Desktop/A/lineage/audit/auditor.py#L250-L257) & [auditor.py](file:///Users/hulalala/Desktop/A/lineage/audit/auditor.py#L495-L545) (`CausalChainAuditor.audit`)
  - [coordinator.py](file:///Users/hulalala/Desktop/A/lineage/resilience/coordinator.py#L206-L222) (`REVOCATION_ISSUED` `action_detail`)
- **Root Cause**:
  Round-2 partitioned `LineagePrefixTrie` and `RevocationEvent` by `trust_domain` (`HIGH-R2-02`), **but `FailoverReceipt.from_dict_and_verify` and `CausalChainAuditor` never inspect `parsed_rev_ev.trust_domain`, `parsed_rev_ev.kind`, or `rev_svc_spiffe.trust_domain`!**
  1. **Sub-vector A — Colliding Foreign-Namespace `RevocationEvent` Split-Brain (bypasses even pinned `trusted_revocation_spiffe_ids`!)**:
     - An `org-alpha.io` task `task-split-01` delegates `A -> B1` at `/task-split-01/A/B1`.
     - A colluding workload in federated partner domain `org-beta.io` mints a dummy `org-beta.io` token at `/task-split-01/A/B1` and calls `org-alpha.io`'s **real** `RevocationService`, obtaining a genuinely signed `RevocationEvent(target="/task-split-01/A/B1", trust_domain="org-beta.io")`.
     - Because `trust_domain == "org-beta.io"`, `org-alpha.io`'s `/task-split-01/A/B1` remains **100% unrevoked** (`B1` continues invoking `org-alpha.io` MCP tools cleanly!).
     - Compromised `A` embeds that real `org-beta.io` `RevocationEvent` into `org-alpha.io`'s `FailoverReceipt` and grafts `B2`. Both `FailoverReceipt.from_dict_and_verify(..., trusted_revocation_spiffe_ids=[w_rev_alpha.spiffe_id])` and `CausalChainAuditor` accept it (`rep.clean == True`, `"VERIFIED_FAILOVER_GRAFT"`), violating Invariant 3 (Prune-Before-Graft)!
  2. **Sub-vector B — Foreign CA `/ns/sys/sa/rev` SVID Spoofing (`trusted_revocation_spiffe_ids=None`)**:
     - [receipts.py](file:///Users/hulalala/Desktop/A/lineage/resilience/receipts.py#L308-L316) checks `rev_svc_spiffe.path.startswith("/ns/sys/sa/rev")` without checking `rev_svc_spiffe.trust_domain`, allowing a foreign federated CA `ca_beta` (`spiffe://org-beta.io/ns/sys/sa/rev`) to sign offline fake `RevocationEvent`s for `org-alpha.io` tasks.
- **Empirical Proof**: Reproduced in `qa_final_round3.py::test_04_r3_high_02_cross_domain_revocation_event_split_brain_failover_spoof`.
- **Required Fix**:
  1. In `FailoverReceipt.from_dict_and_verify` ([receipts.py](file:///Users/hulalala/Desktop/A/lineage/resilience/receipts.py#L240-L348)):
     - Add `expected_trust_domain: Optional[str] = None` parameter; resolve `target_td = expected_trust_domain or SpiffeId.parse(receipt.parent_spiffe_id).trust_domain`.
     - Enforce `parsed_rev_ev.kind == RevocationKind.SUBTREE`.
     - Enforce `parsed_rev_ev.trust_domain == target_td` (unless `parsed_rev_ev.trust_domain is None` from an in-process wildcard test, or better: require `parsed_rev_ev.trust_domain == target_td` whenever `parsed_rev_ev.trust_domain is not None`, and when `expected_trust_domain is not None` require `parsed_rev_ev.trust_domain in (expected_trust_domain, None)`—noting HTTP `RevocationService` always sets non-None `trust_domain`).
     - When `trusted_revocation_spiffe_ids is None`, also require `rev_svc_spiffe.trust_domain == target_td`!
  2. In `CausalChainAuditor.audit` ([auditor.py](file:///Users/hulalala/Desktop/A/lineage/audit/auditor.py#L250-L257) & [L495-L545](file:///Users/hulalala/Desktop/A/lineage/audit/auditor.py#L495-L545)):
     - Extract `task_root_td = SpiffeId.parse(roots[0].node_spiffe_id).trust_domain` when `roots` is non-empty, and pass `expected_trust_domain=task_root_td` to `FailoverReceipt.from_dict_and_verify(...)`.
     - Scope `revocation_earliest_ts` by `(ev_td, target)` (recording `trust_domain` in `REVOCATION_ISSUED` `action_detail` in `coordinator.py`, falling back to `SpiffeId.parse(item.node_spiffe_id).trust_domain` if omitted) so a foreign-domain `REVOCATION_ISSUED` log entry cannot satisfy `rev_ts` for `task_root_td`!

---

### `[MEDIUM-R3-01]` Quarantined, Revoked, or Expired Hop-0 Coordinator Can Still Retaliate with Cluster-Wide Workload Quarantine
- **Severity**: **Medium**
- **Locations**:
  - [service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L279-L337) (`RevocationService._authorize_workload_quarantine`)
  - [directory.py](file:///Users/hulalala/Desktop/A/lineage/registry/directory.py#L228-L293) (`AgentDirectoryService._dispatch` `/v1/agents/quarantine`)
- **Root Cause**:
  1. `RevocationService._authorize_workload_quarantine` ([service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L309-L310)) contains `except TokenExpiredError: pass`, allowing a workload holding a 2-hour-expired `RootBlock B_0` (and even bare 0-hop `B_0`, since `len(parsed.hops) == 0` passes line 327!) to permanently quarantine active workloads cluster-wide.
  2. Neither `RevocationService` nor `AgentDirectoryService` checks whether the **caller workload itself is already quarantined** (`self.trie.check_workloads([caller_spiffe.uri])` / `reporter_spiffe.uri in self._quarantined_spiffe_ids`), nor does `RevocationService` check whether the Hop-0 root coordinate `f"/{parsed.root.task_id}/{parsed.root.hop_segment}"` was **already revoked** in `self.trie`. Consequently, even after `TrustDomainCA` revokes a compromised coordinator's task and quarantines it, the quarantined zombie coordinator can retaliate and globally quarantine healthy cluster tools/workers!
- **Empirical Proof**: Reproduced in `qa_final_round3.py::test_05_r3_medium_01_quarantined_revoked_or_expired_hop0_retaliatory_quarantine`.
- **Required Fix**:
  1. In `RevocationService._authorize_workload_quarantine` ([service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L279-L337)):
     - Reject if `self.trie.check_workloads([caller_spiffe.uri]) is not None` (quarantined callers cannot quarantine others!).
     - Remove `except TokenExpiredError: pass` so expired `authority_token`s are rejected for global workload quarantine.
     - Reject if `self.trie.check_lineage_path(f"/{parsed.root.task_id}/{parsed.root.hop_segment}", trust_domain=parsed.root.issuer_trust_domain) is not None` *(note: check the Hop-0 root coordinate `/{task_id}/{root.hop_segment}`, NOT `parsed.lineage_path`, because `ResilientDelegationCoordinator.invoke_with_prune_and_graft` legitimately prunes `/task_id/A/B1` right before quarantining `B1`!)*.
     - Require `len(parsed.hops) == 1` (`parsed.hops[0].issuer_spiffe_id == caller_spiffe.uri` and `parsed.hops[0].delegate_spiffe_id == target_spiffe.uri`) so bare un-delegated `B_0` tokens cannot quarantine arbitrary uninvolved cluster workloads without at least a signed Hop-1 delegation record.
  2. In `AgentDirectoryService` ([directory.py](file:///Users/hulalala/Desktop/A/lineage/registry/directory.py#L228-L293)):
     - Reject `/v1/agents/quarantine` (and `/v1/agents/register`) if `reporter_spiffe.uri` is already in `self._quarantined_spiffe_ids` (for `workload` auth mode).
     - Require `len(parsed_auth.hops) == 1` matching `reporter_spiffe.uri -> target_spiffe.uri` (and if an optional `revocation_trie` / `revocation_replica` is attached or checked, reject revoked Hop-0 root coordinates as well; at minimum, `AgentDirectoryService` + `RevocationService` must both reject quarantined callers, expired tokens, and 0-hop bare `B_0` tokens).
