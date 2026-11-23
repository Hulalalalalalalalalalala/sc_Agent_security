# Milestone 6 Final Independent QA Sign-Off Report — 3-Machine Multi-Host LCT Federation

- **Reviewer**: `k8s-qa-reviewer` (Independent Read-Only Code Quality & System Compliance Session)
- **Sign-Off Date**: 2026-11-24
- **Prior QA Report**: [MILESTONE6_QA_REPORT.md](file:///Users/hulalala/Desktop/A/lineage/reviews/MILESTONE6_QA_REPORT.md) (`7` findings: `2 HIGH`, `3 MEDIUM`, `2 LOW`)
- **Standalone Sign-Off Suite**: [qa_milestone6_signoff.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone6_signoff.py) (`4/4` PASS in `0.39s`, `0` warnings)
- **Live Host-NIC Rehearsal**: [20261123T183128Z-multihost-rehearsal](file:///Users/hulalala/Desktop/A/lineage/k8s/runs/20261123T183128Z-multihost-rehearsal) (`8/8` scenarios PASS, `0` secrets/tokens)
- **Final Verdict**: **`VERDICT: PASS`**

---

## 1. Line-by-Line Re-Verification of All 7 Remediations + `bootstrap_services.py` Hardening

### 1.1 `[HIGH-M6-01]` — Verified Peer Spoof Resilience, Local-Pin Eviction, & Single-Root Canonicalization (`VERIFIED`)
- **Code Inspected**: [anchors.py](file:///Users/hulalala/Desktop/A/lineage/federation/anchors.py#L73-L156), [sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L115-L303), [sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L466-L477), [sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L599-L616)
- **Verification**:
  - **Spoof / Malformed Candidate Resilience**: `_has_active_verified_pin` ([sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L115-L127)) checks whether `self._verified_domains[domain]` already matches the current local pin (`self.anchor_store.get_pin(domain)`). When a remote HTTP poll returns a forged `trust_domain`, mismatched SPKI/JWKS digest, malformed PEM, extra/duplicate JWK, or non-object JSON, `_reject_remote_candidate` ([sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L128-L137)) increments `_rejected_bundle_counts[domain]` without evicting the pin-verified peer from RAM; furthermore, lines `268-286` validate X.509 `NameConstraints` and JWKS on isolated scratch stores *before* touching live `trust_resolver` / `x509_trust_store`.
  - **Immediate Local-Pin Eviction Preserved**: `reconcile_anchor_evictions()` ([sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L138-L162)) immediately calls `_evict_peer_domain(td)` whenever the local `lct-trust-anchors` pin is deleted (`cur_pin is None` under `require_pinned_anchors`) or changed (`cur_pin != prev_anchor`).
  - **Single-Root & JWKS Canonicalization**: `extract_canonical_bundle_root_pem` ([anchors.py](file:///Users/hulalala/Desktop/A/lineage/federation/anchors.py#L73-L126)) strictly rejects `x509_roots_pem` lists of length `!= 1`, DER mismatches between `x509_root_pem` and `x509_roots_pem[0]`, and any private key headers, while `compute_bundle_trust_anchor` hashes all sorted JWK thumbprints (`",".join(jkts)`), blocking both extra-key and duplicate-key smuggling. All call sites now invoke `X509FederationTrustStore.register_domain_root_pem`.

### 1.2 `[HIGH-M6-02]` — Audit Ingest Timestamp/Capacity Integrity & Revocation Per-Instance Monotonicity (`VERIFIED`)
- **Code Inspected**: [logger.py](file:///Users/hulalala/Desktop/A/lineage/audit/logger.py#L220-L253), [logger.py](file:///Users/hulalala/Desktop/A/lineage/audit/logger.py#L385-L549), [service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L165-L370), [service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L1005-L1195), [trie.py](file:///Users/hulalala/Desktop/A/lineage/revocation/trie.py#L397-L448)
- **Verification**:
  - **Audit Timestamp & Monotonicity Bounds**: `_verify_entry_on_ingest` enforces `entry_ts <= now_ts + max_future_skew_seconds` (`30.0s`) and `entry_ts >= now_ts - max_ingest_age_seconds` (`3600.0s`), blocking retired/expired SVID replay from previous days while preserving transient offline flusher buffering; `append_direct` enforces bidirectional per-stream timestamp monotonicity (`tol = 5.0s` for both `existing_seq < stream_seq` and out-of-order `existing_seq > stream_seq`).
  - **Safe Collector Capacity Behavior**: When `max_entries` (`100_000`) or `max_streams` (`10_000`) is reached, `append_direct` fails closed (`AuditIngestError` -> HTTP `403`) rather than evicting/truncating prior entries, keeping 100% of already-ingested `GENESIS -> seq_k` hash chains intact for `CausalChainAuditor` while `AuditStreamEmitter.flush_pending` (`logger.py:239-245`) leaves unshipped entries queued in `_pending_remote`.
  - **Revocation Per-Instance Monotonicity & `(trust_domain, origin_instance_jkt, orig_ver)` Keying**:
    - Both `RevocationService.sync_from_federation_peers` and `RevocationReplicaClient.sync_now` reject version rollbacks (`peer_cur_ver < since_v`) and timestamp rollbacks (`< prev_ts - 5.0s`) within the same instance JKT, resetting cursor to `0` **only** when the peer's CA-verified `/ns/sys/sa/revocation` SVID presents a genuinely rotated `cnf.jkt` (`jkt_rotated=True`).
    - In `trie.ingest_federated_event` (`trie.py:397-448`), `origin_instance_jkt` is derived exclusively from `verify_workload_svid(ev.service_svid)` (`service.py:182-197`, enforcing `spiffe://<peer_td>/ns/sys/sa/revocation`), so non-revocation workloads cannot forge an instance JKT; replaying an already-seen `(peer_td, jkt_old, v)` after restart idempotently returns `existing` without duplicating trie/event records, while replaying a *different* payload for `(peer_td, jkt_old, v)` raises `RevocationError` (`Equivocated federated RevocationEvent`).

### 1.3 `[MEDIUM-M6-01]` — Transient & Token-Protected Scenario 3B Sync Hook (`30990`) (`VERIFIED`)
- **Code Inspected**: [config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L441-L460), [config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L1540-L1570), [lct_multihost_cli.py](file:///Users/hulalala/Desktop/A/lineage/multihost/lct_multihost_cli.py#L1131-L1218), [e2e_driver.py](file:///Users/hulalala/Desktop/A/lineage/k8s/e2e_driver.py#L762-L805), [specialist_apps.py](file:///Users/hulalala/Desktop/A/lineage/agents/specialist_apps.py#L1012-L1023), [ARCHITECTURE.md](file:///Users/hulalala/Desktop/A/lineage/ARCHITECTURE.md#L113)
- **Verification**: Default `alpha` manifests omit `Service/e2e-user-gateway-sync`; `lct_multihost_cli.py` applies it immediately before Scenario 3B and deletes it in `finally:` immediately afterward; `_sync_handler` enforces `POST /sync` and constant-time `hmac.compare_digest` on a per-run 24-byte random `X-LCT-Sync-Token` before writing `sync_marker_file`.

### 1.4 `[MEDIUM-M6-02]` — `trust fetch --expect` Constant-Time Pinning & `UNVERIFIED TOFU` Warning (`VERIFIED`)
- **Code Inspected**: [lct_multihost_cli.py](file:///Users/hulalala/Desktop/A/lineage/multihost/lct_multihost_cli.py#L331-L367), [lct_multihost_cli.py](file:///Users/hulalala/Desktop/A/lineage/multihost/lct_multihost_cli.py#L1459-L1465), [MULTIHOST_GUIDE.md](file:///Users/hulalala/Desktop/A/lineage/multihost/MULTIHOST_GUIDE.md#L167-L196)
- **Verification**: `trust fetch --expect <sha256:...>` validates format and checks `hmac.compare_digest(computed, norm_expect)` (aborting with exit code `1` and zero ConfigMap writes on mismatch); `--yes` without `--expect` emits `[SECURITY WARNING: UNVERIFIED TOFU]` to `sys.stderr`; `MULTIHOST_GUIDE.md` recommends only out-of-band `trust add` (Method A) and `trust fetch --expect` (Method B).

### 1.5 `[MEDIUM-M6-03]` — Official A2A v1.0 SSE Parsing & Terminal-State Exit Code (`VERIFIED`)
- **Code Inspected**: [lct_multihost_cli.py](file:///Users/hulalala/Desktop/A/lineage/multihost/lct_multihost_cli.py#L530-L640), [rpc.py](file:///Users/hulalala/Desktop/A/lineage/a2a/rpc.py#L691-L772)
- **Verification**: `stream_and_summarize_a2a_sse` parses `result.statusUpdate`, `result.artifactUpdate`, `result.task`, and `error` frames via `A2AClient.send_streaming_message(..., on_event=...)` (`trust_env=False`), prints live transitions to `stderr`, populates `sse_states`, `artifact_names`, `terminal_state`, and `final_event`, and exits `0` iff `terminal_state == "TASK_STATE_COMPLETED"`.

### 1.6 `[LOW-M6-01]` & `[LOW-M6-02]` — Documentation & Operational Script Hardening (`VERIFIED`)
- **Code Inspected**: [ARCHITECTURE.md](file:///Users/hulalala/Desktop/A/lineage/ARCHITECTURE.md#L113-L119), [preflight.sh](file:///Users/hulalala/Desktop/A/lineage/multihost/preflight.sh#L177-L179), [fault.sh](file:///Users/hulalala/Desktop/A/lineage/multihost/fault.sh#L52-L77)
- **Verification**: `ARCHITECTURE.md` accurately documents `readOnly: true, defaultMode: 0440, securityContext.fsGroup: 2000` and transient `30990` *(minor non-blocking prose note: `MULTIHOST_GUIDE.md:103` still mentions `0400` in background prose while all CLI commands/flags match the scripts 100%)*; `preflight.sh` uses `httpx.Client(timeout=4.0, trust_env=False)`; `fault.sh` validates `--role` against `alpha|beta|pay|audit|all` and exits `2` on invalid input.

### 1.7 Review of Unrequested Hardening in `bootstrap_services.py` (`VERIFIED SOUND`)
- **Code Inspected**: [bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L1247-L1273), [bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L1352-L1365)
- **Assessment**: Capping `rem_svid_ttl = max(5.0, min(float(svid_ttl), float(identity.expires_at - time.time())))` and checking `existing.workload_svid != identity.workload_svid` in `_card_keeper_loop` closes a subtle window where `rotate_keypair=False` (`existing.jkt == identity.jkt`) and a transient directory failure during `_on_svid_renewed` would otherwise leave an older `workload_svid` embedded in the directory `AgentCard` until `expires_at - 25s`. Thread-safe under `card_lock` and `stop_event`.

---

## 2. Test Execution, Live Rehearsal Audit, & Pre-Push Compliance Summary

| Verification Gate | Result |
|---|---|
| `python3 -W default -m lineage.tests.run_all` | **`69/69` PASS** (`32.48s` + benchmarks `34.19s`, `0` warnings, `0` exceptions) |
| `qa_milestone6_review.py` (Round 1 PoCs) | **All 3 Round-1 PoCs blocked** (`test_02`, `test_03`, `test_04` no longer reproduce; `test_01` compliance `ok`) |
| `qa_milestone6_signoff.py` (Final Sign-Off Suite) | **`4/4` PASS** (`0.39s`, `0` warnings) |
| Non-Cluster Prior Sign-Off Suites (M1 R4 `5/5`, M2 `3/3`, M3 `5/5`, M4 `3/3`, M5 `3/3`) | **`19/19` PASS** (`0` warnings) |
| Live Rehearsal ([20261123T183128Z-multihost-rehearsal](file:///Users/hulalala/Desktop/A/lineage/k8s/runs/20261123T183128Z-multihost-rehearsal)) | **`8/8` scenarios PASS**; `:30990` absent before/after Scenario 3B; wrong `--expect` left all 4 ConfigMaps `{}`; live spoofed `:31094` bundle rejected (`count=5`) while staying `200 Ready`; `05_cli_send_stream.json` populated `sse_states` + `TASK_STATE_COMPLETED` |
| Secret & Token Scan (`296` files in `lineage/` + `push_to_github.sh --dry-run` both scopes) | **`PASS`** (`409` workspace files / `296` lineage files, `0` symlinks, `0` private keys, `0` PATs, `0` raw JWTs, `0` raw LCT run tokens) |
| Host Container & Workspace Hygiene | **`0` `lctmh-*` containers**; `agent-identity-lab-control-plane` + `lct-*` remain `Exited (137)`; `0` changes to `README.md`, `lab/`, `src/`, or prior `lineage/reviews/*` |
