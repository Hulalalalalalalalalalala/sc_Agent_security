# Milestone 6 Independent QA Review Report — 3-Machine Multi-Host LCT Federation

- **Reviewer**: `k8s-qa-reviewer` (Independent Read-Only Code Quality & System Compliance Session)
- **Review Date**: 2026-11-24
- **Target Scope**: Milestone 6 (`lineage/federation/anchors.py`, `lineage/federation/sync.py`, `lineage/federation/domain_ca.py`, `lineage/multihost/*`, `lineage/scripts/multihost*`, `lineage/k8s/{bootstrap_services.py,e2e_driver.py,Dockerfile}`, `lineage/audit/logger.py`, `lineage/revocation/{service.py,trie.py}`, `lineage/sidecar/proxy.py`, `lineage/common/{crypto.py,http_utils.py,mtls.py}`, `lineage/ARCHITECTURE.md`, `lineage/README.md`, `lineage/tests/test_m6_multihost.py`, and rehearsal artifacts in [20261123T155355Z-multihost-rehearsal](file:///Users/hulalala/Desktop/A/lineage/k8s/runs/20261123T155355Z-multihost-rehearsal))
- **QA Reproduction Suite**: [qa_milestone6_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone6_review.py) (`4/4` deterministic checks & PoC reproductions passing in `0.24s`)
- **Overall Verdict**: **`VERDICT: NEEDS_FIX`** (`2 HIGH`, `3 MEDIUM`, `2 LOW`)

---

## 1. Executive Summary & Checklist Matrix

Milestone 6 delivers a well-architected multi-host LCT federation stack: disjoint per-role Kind configs, idempotent CoreDNS `hosts` patching (`update-peer-ips`), startup-order independence (`/healthz` vs `/readyz`), zero-restart mTLS 1.3 client/server hot-reload via `ssl_context_provider`, 50%-TTL SVID/X.509/AgentCard renewal, in-memory streamed K8s CA Secrets, keyless TLS 1.3 audit collection via `audit-ca`, and clean rehearsal evidence (`8/8` scenarios PASS, `0` leaked keys/tokens, `0` leftover `lctmh-*` containers).

However, under the **real untrusted LAN threat model**, independent review uncovered **2 HIGH**, **3 MEDIUM**, and **2 LOW** issues that require remediation before final Milestone 6 sign-off:

| Checklist Area | Status | Key Verification & Findings |
|---|---|---|
| **1. Automated Test Suites** | **PASS** | `python3 -W default -m lineage.tests.run_all`: **`66/66` PASS** (`34.88s`, `0` warnings). Non-cluster prior sign-off suites (`qa_signoff_round4.py` `5/5`, `qa_milestone2_signoff.py` `3/3`, `qa_milestone3_signoff.py` `5/5`, `qa_milestone4_signoff.py` `3/3`, `qa_milestone5_signoff.py` `test_02..04` + `push_to_github.sh --dry-run` secret scan): **ALL PASS**. |
| **2. Trust Bootstrap Soundness (LAN Threat Model)** | **NEEDS_FIX** | Missing/wrong pins fail closed, and JWKS thumbprint sorting blocks extra-key injection. **However**: **`[HIGH-M6-01]`** (single spoofed plain-HTTP `:30094/:31094/:32094` response evicts an *already pin-verified* peer domain from RAM -> LAN DoS; `x509_roots_pem` hashes only `roots_list[0]` and crashes with `AttributeError: register_domain_roots_pem`), **`[MEDIUM-M6-02]`** (`trust fetch` lacks `--expect` and `--yes` performs silent unverified TOFU without stderr warning), **`[LOW-M6-01]`** (`ARCHITECTURE.md` says `0400` vs `config_gen.py` `0o440` + `fsGroup: 2000`). |
| **3. Renewal & Historical Revocation / Audit Verification** | **NEEDS_FIX** | `WorkloadIdentityRenewer` reuses RAM keypairs (`rotate_keypair=False` by default), swaps `WorkloadIdentity` + `WorkloadMTLSBundle` atomically, and retries on CA outage without crashing. Federated revocation pull requires a *live* peer mTLS `X.509-SVID` + *live* top-level `default_svid` (bounding retired-key risk to authorized peers). **However**: **`[HIGH-M6-02]`** (`AuditCollectorService` on host-published server-only TLS `:30893` accepts arbitrarily back-dated and future-dated `AuditEntry` timestamps under expired/retired SVIDs without ingest-age or per-stream monotonicity bounds). |
| **4. Real-LAN Network Exposure** | **NEEDS_FIX** | Internal `:8090/:8091/:8092/:8081/:9001` and `audit-ca` are never host-published (`ClusterIP` / loopback only). Ollama LAN exposure warning & local default are clear in `MULTIHOST_GUIDE.md`. **However**: **`[MEDIUM-M6-01]`** (`alpha` permanently publishes plain-HTTP `0.0.0.0:30990` -> `e2e-user-gateway:19090`, and `s3b-sync-hook` has zero token auth, letting any LAN host prematurely trigger Scenario 3B intermediate Pod kill). |
| **5. Operational Scripts & CLI** | **NEEDS_FIX** | `teardown.sh` strictly deletes only `lctmh-*` and restores kube context; `fault.sh` handles `iptables-nft` & `iptables-legacy` idempotently; all non-CA `readinessProbe`s use `/readyz`. **However**: **`[MEDIUM-M6-03]`** (`lct_multihost_cli.py send --stream` parses `result.status` instead of A2A v1.0 `result.statusUpdate.status`, yielding `sse_states: []` and `final_event: null` in `12_cli_send_stream.json`), **`[LOW-M6-02]`** (`preflight.sh` calls `httpx.get` without `trust_env=False`; `fault.sh` does not validate `--role`). |
| **6. Rehearsal Evidence & Hygiene** | **PASS (except `12_cli_send_stream.json` SSE summary)** | All 8 scenarios (`1, 2A, 2B, 3A, 3B, 4, 5, 6`) `PASS`; host-NIC `192.168.1.6` verified across hops; 265s startup-order check shows `RESTARTS=0` and `svid_generation=4` (later `16..27`); `beta-ca` restart preserved identical anchor; `275`-file scan confirmed `0` private keys, `0` raw JWTs, `0` raw rehearsal LCT tokens; `0` `lctmh-*` containers remain; `agent-identity-lab` & `lct-*` untouched (`Exited (137)`); `0` changes to `README.md`, `lab/`, `src/`, or prior `lineage/reviews/*`. |
| **7. Documentation (`MULTIHOST_GUIDE.md`)** | **PASS (minor sync with CLI fixes)** | Per-OS steps (macOS Docker Desktop, Linux `ufw`/`firewalld`, Windows + WSL2 `netsh interface portproxy` & `New-NetFirewallRule`), NTP/clock-skew rules (`<=10s` OK, `>25s` FAIL), AP-isolation/Tailscale guidance, and troubleshooting table are comprehensive and accurate (`lineage/scripts/multihost` and `multihost.sh` both exist). |

---

## 2. Detailed Findings & Actionable Remediations

### `[HIGH-M6-01]` Unauthenticated LAN Bundle Spoofing Evicts Already Pin-Verified Peer Domains (`DoS`) + Broken `x509_roots_pem` Pinning / Missing Method

- **Files & Lines**:
  - [sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L190-L198), [sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L213-L227), [sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L241-L248), [sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L416-L420)
  - [anchors.py](file:///Users/hulalala/Desktop/A/lineage/federation/anchors.py#L75-L85)
  - [mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L358-L443)
- **Vulnerability Details**:
  1. **Single Spoofed Plain-HTTP Packet Wipes Verified Peer Trust (`LAN Eviction DoS`)**:
     `FederationBundleSyncer.start_background_refresh` polls peer `:30094/:31094/:32094/v1/federation/bundle` over **unauthenticated plain HTTP** every `2.0s` ([sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L304-L325)). Once `org-beta.io` has already been cryptographically verified against its local ConfigMap pin (`self._verified_domains["org-beta.io"] == pinned`), if a LAN attacker spoofs/races **one** HTTP response on `:31094` (wrong `trust_domain`, wrong SPKI/JWKS digest, or malformed PEM), `_verify_and_apply_bundle` calls `self._evict_peer_domain(expected_domain)` at lines `191`, `214`, and `242`. This **deletes the legitimate, pin-verified `org-beta.io` JWKS and X.509 Root CA from RAM**, breaking inbound/outbound mTLS 1.3 handshakes and flipping `/readyz` to `503` across the cluster (reproduced in `test_02` of [qa_milestone6_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone6_review.py#L131-L185)).
     - Note: Genuine operator pin removal or rotation in `lct-trust-anchors` is *already* enforced by `reconcile_anchor_evictions()` ([sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L113-L137)), which checks `cur_pin is None or cur_pin != prev_anchor`.
  2. **`x509_roots_pem` Partial-Pinning Bypass & `AttributeError` Crash**:
     In [anchors.py](file:///Users/hulalala/Desktop/A/lineage/federation/anchors.py#L76-L80), when `x509_roots_pem` is present, `compute_bundle_trust_anchor` hashes **only** `roots_list[0]`, ignoring `roots_list[1:]` and ignoring any conflicting `x509_root_pem`. Furthermore, [sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L225) and [sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L418) call `self.x509_trust_store.register_domain_roots_pem(...)`, which **does not exist** on `X509FederationTrustStore` (raising `AttributeError`).
- **Recommended Fix**:
  1. In `FederationBundleSyncer._verify_and_apply_bundle`, when a remote candidate bundle fails `trust_domain`, pin, or schema validation, **do not** evict `expected_domain` if `self._verified_domains.get(expected_domain) == pinned` (keep the existing pin-verified keys in RAM, record `_last_errors[expected_domain]`, and raise `FederationSecurityError`). Continue evicting immediately in `reconcile_anchor_evictions()` whenever the local ConfigMap pin is removed or changed.
  2. In `anchors.py` and `sync.py`, either strictly require a single X.509 root per bundle (`if "x509_roots_pem" in bundle`: require `len(roots_list) == 1` and if `"x509_root_pem"` is also present require exact PEM/DER match, then call `register_domain_root_pem`), or hash all sorted SPKIs in `x509_roots_pem` and implement `X509FederationTrustStore.register_domain_roots_pem` with full `NameConstraints` validation on every cert.

---

### `[HIGH-M6-02]` Unbounded Historical & Future `AuditEntry` Timestamps Accepted Over LAN Server-Only TLS (`:30893`) + Historical Revocation Epoch Monotonicity

- **Files & Lines**:
  - [logger.py](file:///Users/hulalala/Desktop/A/lineage/audit/logger.py#L423-L488)
  - [service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L178-L185), [service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L265-L335), [trie.py](file:///Users/hulalala/Desktop/A/lineage/revocation/trie.py#L396-L415)
- **Vulnerability Details & Checklist Item 3b Assessment**:
  1. **`AuditCollectorService` Over LAN Server-Only TLS (`:30893`)**:
     `:30893` is exposed on `0.0.0.0:30893` with `require_client_cert=False` ([bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L1035)), relying solely on JWS verification inside `_verify_entry_on_ingest` ([logger.py](file:///Users/hulalala/Desktop/A/lineage/audit/logger.py#L437-L441)):
     `verify_workload_svid(entry.node_svid_or_domain, expected_spiffe_id=entry.node_spiffe_id, now=entry.timestamp)`.
     Unlike `RevocationService`, `AuditCollectorService` enforces **neither** a future-timestamp bound (`entry.timestamp <= time.time() + 30.0`), **nor** a maximum ingest-staleness bound (`entry.timestamp >= time.time() - max_ingest_age_sec`), **nor** monotonic timestamps per `stream_id`. As reproduced in `test_03` of [qa_milestone6_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone6_review.py#L190-L246), an attacker on the LAN who obtains a retired/expired workload keypair + SVID (e.g., when `rotate_keypair_on_renewal=True` or from a terminated Pod) can `POST /v1/audit/append` back-dated `AuditEntry` streams from 24+ hours ago (or 20-minute future-dated entries under a live SVID), polluting the central `CausalChainAuditor` log.
  2. **Evaluation of Point-in-Time `now=ev.timestamp` on Historical Revocation Events (Checklist Item 3b)**:
     - *Keypair reuse vs. rotation*: Production workloads use `rotate_keypair_on_renewal=False` ([sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L348), `495`), keeping a single RAM-only ES256 keypair across SVID renewals; rotation only occurs on Pod restart or if `rotate_keypair_on_renewal=True` is explicitly passed.
     - *Origin & transport gating*: Federated revocation sync is strictly **pull-only** over mTLS 1.3 (`verify_for_target(..., expected_trust_domain=peer_td)`), AND the response envelope's `default_svid` is verified against current wall-clock time (`now=None` at [service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L269) and `1070`). Therefore, a standalone holder of a retired keypair **cannot** inject historical revocations from the LAN; even a compromised live `revocation` Pod can only cause fail-closed prefix/workload revocation (denial-of-service, never privilege escalation).
     - *Remaining hardening*: In [trie.py](file:///Users/hulalala/Desktop/A/lineage/revocation/trie.py#L404), changing `_seen_federated_origins` key from `(trust_domain, orig_ver)` to `(trust_domain, orig_ver, service_signature)` allows multiple distinct events with the same `orig_ver` even when `peer_jkt` did **not** restart, and `RevocationService._pull_federated_events_once` does not enforce monotonic `(ev.version, ev.timestamp)` within a single `peer_jkt` instance.
- **Recommended Fix**:
  1. In `AuditCollectorService.append_direct` / `_verify_entry_on_ingest`:
     - Enforce `entry.timestamp <= time.time() + 30.0` (reject future-dated entries);
     - Enforce `entry.timestamp >= time.time() - self._max_ingest_age_seconds` (configurable, e.g., default `3600.0`s so `AuditStreamEmitter`'s best-effort flusher buffer drains cleanly after transient partitions while ancient retired SVIDs are rejected);
     - Track per-`stream_id` latest timestamp/seq so `entry.timestamp` cannot jump backward arbitrarily within a stream, and bound `_entries` / `_seen_stream_seqs` capacity against LAN memory exhaustion.
  2. In `RevocationService._pull_federated_events_once` / `RevocationReplicaClient._verify_and_apply_events`, enforce strictly increasing `ev.version` and non-decreasing `ev.timestamp` (`>= prev_ts - 5.0`) within any single `peer_jkt` / `_remote_instance_jkt` epoch (allowing version reset only on verified `epoch_reset` when the instance JKT changes).

---

### `[MEDIUM-M6-01]` Permanently Published Plain-HTTP `30990` Sync-Hook Port on `alpha` Without Token Auth

- **Files & Lines**:
  - [config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L72), [config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L1520-L1563)
  - [e2e_driver.py](file:///Users/hulalala/Desktop/A/lineage/k8s/e2e_driver.py#L762-L785)
  - [ARCHITECTURE.md](file:///Users/hulalala/Desktop/A/lineage/ARCHITECTURE.md#L118)
- **Details**:
  - `ROLE_SPECS["alpha"].host_ports` permanently publishes `0.0.0.0:30990` -> `Service/e2e-user-gateway-sync` (`19090`). While `e2e-user-gateway` runs `sleep 86400` in steady state (`ECONNREFUSED`), during `e2e` Scenario 3B `ManagedHTTPService("s3b-sync-hook", ..., host="0.0.0.0", port=19090)` ([e2e_driver.py](file:///Users/hulalala/Desktop/A/lineage/k8s/e2e_driver.py#L777)) accepts **any unauthenticated plaintext HTTP request** from the LAN, immediately writing `sync_marker_file` (`READY_TO_KILL_INTERMEDIATE`) and causing the host orchestrator to kill `hotel-specialist-primary` on Machine 2 prematurely. Additionally, [ARCHITECTURE.md](file:///Users/hulalala/Desktop/A/lineage/ARCHITECTURE.md#L118) omits `30990` when listing host-published ports.
- **Recommended Fix**:
  - Mint a per-run random secret token (`secrets.token_urlsafe(24)`) in `run_scenario_3b`, pass it in `sync_hook_url` (or `X-LCT-Sync-Token`), and enforce `POST /sync` + constant-time `hmac.compare_digest` in `_sync_handler` (returning `403` without writing `sync_marker_file` on mismatch).
  - Create `Service/e2e-user-gateway-sync` dynamically only around Scenario 3B (or gate it behind `--enable-e2e-hook` / document `30990` explicitly in `ARCHITECTURE.md` and `MULTIHOST_GUIDE.md`).

---

### `[MEDIUM-M6-02]` `trust fetch --yes` Performs Silent Unverified TOFU Without `--expect` or Security Warning

- **Files & Lines**:
  - [lct_multihost_cli.py](file:///Users/hulalala/Desktop/A/lineage/multihost/lct_multihost_cli.py#L307-L346), [lct_multihost_cli.py](file:///Users/hulalala/Desktop/A/lineage/multihost/lct_multihost_cli.py#L1297-L1306)
  - [MULTIHOST_GUIDE.md](file:///Users/hulalala/Desktop/A/lineage/multihost/MULTIHOST_GUIDE.md#L185-L190)
- **Details**:
  - While `MULTIHOST_GUIDE.md:167-189` properly presents out-of-band `trust add <domain> sha256:...` as primary ("推荐方式 A"), `lct_multihost_cli.py trust fetch` has **no `--expect sha256:...` flag**, and running `trust fetch --domain ... --ip ... --yes` (used in rehearsal step `08`) silently pins an unauthenticated HTTP / `verify=False` HTTPS bundle without emitting a security warning on `stderr`.
- **Recommended Fix**:
  - Add `--expect <sha256:...>` to `trust fetch` (validating format and verifying `hmac.compare_digest(computed, norm_expect)` before writing any ConfigMap, failing closed with exit code `1` on mismatch).
  - When `--yes` is used without `--expect`, print an explicit `[SECURITY WARNING: UNVERIFIED TOFU]` message to `sys.stderr` stating that `--yes` without `--expect` trusts an unauthenticated network response on first use.

---

### `[MEDIUM-M6-03]` `lct_multihost_cli.py send --stream` Parses Wrong A2A v1.0 SSE Envelope (`sse_states: []`, `final_event: null`)

- **Files & Lines**:
  - [lct_multihost_cli.py](file:///Users/hulalala/Desktop/A/lineage/multihost/lct_multihost_cli.py#L539-L557), [lct_multihost_cli.py](file:///Users/hulalala/Desktop/A/lineage/multihost/lct_multihost_cli.py#L637)
  - Rehearsal artifact: [12_cli_send_stream.json](file:///Users/hulalala/Desktop/A/lineage/k8s/runs/20261123T155355Z-multihost-rehearsal/12_cli_send_stream.json#L5-L12)
- **Details**:
  - Official A2A v1.0 `SendStreamingMessage` SSE frames nest status transitions under `ev["result"]["statusUpdate"]["status"]["state"]` and `ev["result"]["statusUpdate"]["final"]` (as correctly asserted in [e2e_driver.py](file:///Users/hulalala/Desktop/A/lineage/k8s/e2e_driver.py#L480-L493)).
  - In [lct_multihost_cli.py](file:///Users/hulalala/Desktop/A/lineage/multihost/lct_multihost_cli.py#L541-L556), `_run_send_in_gateway` instead looks for `"status" in res_obj`, causing `sse_states` to always be `[]` and `final_event` to always be `null` (directly visible in `12_cli_send_stream.json`), and returning exit code `0` even if the streamed task ended in `TASK_STATE_FAILED` / `TASK_STATE_REJECTED`.
- **Recommended Fix**:
  - Parse `res_obj.get("statusUpdate")` and `res_obj.get("artifactUpdate")` in `_run_send_in_gateway`, record all observed `statusUpdate.status.state` values plus artifact count / final status message, and require a successful terminal state (`TASK_STATE_COMPLETED`, or `WORKING`/`INPUT_REQUIRED` when `--pause-before-settlement` is set) for exit code `0`.

---

### `[LOW-M6-01]` CA Secret Mount Mode Documentation Mismatch (`0400` in `ARCHITECTURE.md` vs `0o440` + `fsGroup: 2000` in `config_gen.py`)

- **Files & Lines**:
  - [ARCHITECTURE.md](file:///Users/hulalala/Desktop/A/lineage/ARCHITECTURE.md#L120)
  - [config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L709-L716), [config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L1124-L1138)
- **Details**:
  - `config_gen.py` mounts CA root Secrets with `defaultMode: 0o440` (`-r--r-----`, zero world/other bits) and `securityContext: {"fsGroup": 2000}`, which is the proper least-privilege Kubernetes pattern so non-root container UIDs can read the `root:2000` tmpfs projection while world permissions remain `0`. However, `ARCHITECTURE.md:120` states `0400`.
- **Recommended Fix**:
  - Update `ARCHITECTURE.md:120` to accurately document `readOnly: true, defaultMode: 0440, fsGroup: 2000` (zero world bits, isolated exclusively to the single CA Pod with zero RBAC `secrets` access in the namespace).

---

### `[LOW-M6-02]` Proxy-Bypass & Role-Validation Hardening in `preflight.sh` and `fault.sh`

- **Files & Lines**:
  - [preflight.sh](file:///Users/hulalala/Desktop/A/lineage/multihost/preflight.sh#L174-L183)
  - [fault.sh](file:///Users/hulalala/Desktop/A/lineage/multihost/fault.sh#L97-L113), [fault.sh](file:///Users/hulalala/Desktop/A/lineage/multihost/fault.sh#L169-L187)
- **Details**:
  1. `preflight.sh:177` calls `httpx.get(url, timeout=4.0)` without `trust_env=False`. On hosts with `HTTP_PROXY`/`HTTPS_PROXY` set in the environment (such as this Mac's `HTTPS_PROXY=http://127.0.0.1:10900`), `preflight.sh` routes local/LAN Ollama checks through the proxy and fails falsely.
  2. `fault.sh:97-101` splits `--role` on commas without validating role names against `alpha|beta|pay|audit` (or expanding `all`), unlike `deploy-role.sh` and `teardown.sh`.
- **Recommended Fix**:
  1. Use `with httpx.Client(timeout=4.0, trust_env=False) as c: r = c.get(url)` in `preflight.sh:177`.
  2. Validate `--role` values in `fault.sh` (`alpha|beta|pay|audit|all`, exiting `2` on invalid input before calling `docker exec`).

---

## 3. Verified Security & Architecture Invariants (Keep Intact During Fixes)

1. **Complete Host-Port Enumeration**:
   - `alpha`: `30094` (read-only CA bundle), `30491` (mTLS 1.3 `CERT_REQUIRED` directory), `30492` (mTLS 1.3 `CERT_REQUIRED` revocation), `30441` (mTLS 1.3 `CERT_REQUIRED` orchestrator), `30990` (E2E sync hook — fix per `[MEDIUM-M6-01]`).
   - `beta`: `31094` (read-only CA bundle), `31491`/`31492` (mTLS 1.3 `CERT_REQUIRED` dir/rev), `31441`/`31442`/`31443` (mTLS 1.3 `CERT_REQUIRED` specialists).
   - `pay`: `32094` (read-only CA bundle), `32491`/`32492` (mTLS 1.3 `CERT_REQUIRED` dir/rev), `32441`/`32442`/`32443` (mTLS 1.3 `CERT_REQUIRED` converger & MCP tools).
   - `audit`: `30893` (TLS 1.3 keyless `audit-collector` with JWS signature verification — harden timestamp window per `[HIGH-M6-02]`).
   - Internal `:8090`, `:8091`, `:8092`, `:8081`, `:9001`, and `audit-ca` are **never** published to host NICs (`FORBIDDEN_HOST_PORTS`).
2. **CA Key Custody & RBAC Isolation**:
   - CA keys are generated in Python memory and piped via `kubectl apply -f -` (`stdin`), never touching host disk or logs; `audit-collector` mounts zero CA keys and zero K8s SA tokens; zero `Role`/`ClusterRole` grants `secrets` access; `automountServiceAccountToken: false` is enforced on every Pod.
3. **Ollama Shared-Inference Guidance (`MULTIHOST_GUIDE.md:73-77`)**:
   - Per-machine loopback Ollama (`127.0.0.1:11434`) is recommended by default; shared LAN `OLLAMA_HOST=0.0.0.0:11434` is clearly marked optional with an explicit unauthenticated-API + host-firewall source-IP restriction warning.
