# Milestone 7 Independent QA & Security Compliance Review Report

- **Reviewer**: `k8s-qa-reviewer` (Independent Read-Only QA & Security Compliance Session)
- **Verdict**: **`NEEDS_FIX`** (`2 HIGH`, `2 MEDIUM`, `1 LOW`)
- **Automated PoC & Verification Suite**: [qa_milestone7_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone7_review.py) (`5/5` deterministic tests executed in `0.31s`, `0` warnings)
- **Full Existing Suite**: `python3 -W default -m lineage.tests.run_all` -> **`79/79` PASS** (`41.39s`, `0` warnings)

---

## 1. Executive Summary

Milestone 7's core **Identifier / Locator Separation** cryptographic architecture is well-structured and passes strong adversarial invariants:
- `SignedDomainDescriptor` enforces strict **pin-first** verification against `TrustAnchorPinStore` before X.509 certificate parsing or JWS verification ([locators.py](file:///Users/hulalala/Desktop/A/lineage/federation/locators.py#L296-L365)), supports both ES256 JWKS domains and keyless `org-audit.io` (`x509_root_es256`), blocks version rollback and same-version equivocation, and guards the local trust domain against spoofed descriptors or `trust import` overwrites.
- Workload `AgentCard` locators (agents, MCP tools, transient S3B sync hook) are cryptographically bound to the CA-issued `workload_svid` `cnf.jkt` ([agent_card.py](file:///Users/hulalala/Desktop/A/lineage/registry/agent_card.py#L478-L526)), enforce RFC1918-only CIDRs by default ([locators.py](file:///Users/hulalala/Desktop/A/lineage/common/locators.py#L24-L28)), and derive A2A v1.0 `url` and `supportedInterfaces` cleanly.
- Outbound IP-addressed TLS 1.3 enforces `expected_spiffe_id` URI SAN pinning across every code path and strips IP-literal SNI (`_IPSNISafeSSLContext` in [mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L770-L792)); disabling `check_hostname` without `expected_spiffe_id` raises `MTLSError` ([mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L510-L513), [mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L905-L908)).
- Rehearsal evidence ([20261124-131005-identity-addressing-rehearsal](file:///Users/hulalala/Desktop/A/lineage/k8s/runs/20261124-131005-identity-addressing-rehearsal)) passed `8/8` E2E scenarios with `0` leaked secrets and `push_to_github.sh --dry-run` passes in both `workspace` and `lineage-only` scopes.

However, **5 actionable defects (`2 HIGH`, `2 MEDIUM`, `1 LOW`)** will block or degrade the real 4-machine campus LAN rollout (macOS + 2× localized Chinese Windows/WSL2 + 4th machine) and must be fixed before sign-off.

---

## 2. Detailed Findings & Remediation Specifications

### `[HIGH-M7-01]` Seedless First Node (`alpha`) Deadlocks in the Documented 4-Machine Star Topology & Role Migration

- **Locations**:
  - [MULTIHOST_GUIDE.md](file:///Users/hulalala/Desktop/A/lineage/multihost/MULTIHOST_GUIDE.md#L117-L129) & [MULTIHOST_GUIDE.md](file:///Users/hulalala/Desktop/A/lineage/multihost/MULTIHOST_GUIDE.md#L198-L208)
  - [sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L189-L270) (`FederationBundleSyncer.sync_descriptors_from_seeds_and_peers`)
  - [domain_ca.py](file:///Users/hulalala/Desktop/A/lineage/federation/domain_ca.py#L259-L290) (`AutonomousDomainCAService._dispatch_federation_readonly`)
  - [bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L864-L883) (`MinimalAuditTLSCAService._dispatch_federation_ro`)
  - [directory.py](file:///Users/hulalala/Desktop/A/lineage/registry/directory.py#L413-L457) (`POST /v1/federation/descriptors` dead route on mTLS `:8491`)
  - Rehearsal workaround evidence: [00_deploy_4_roles_seeds_only.log](file:///Users/hulalala/Desktop/A/lineage/k8s/runs/20261124-131005-identity-addressing-rehearsal/00_deploy_4_roles_seeds_only.log#L562-L563) & [04_audit_migrated_trust_import.txt](file:///Users/hulalala/Desktop/A/lineage/k8s/runs/20261124-131005-identity-addressing-rehearsal/04_audit_migrated_trust_import.txt#L12)
- **Root Cause & Impact**:
  1. In [MULTIHOST_GUIDE.md](file:///Users/hulalala/Desktop/A/lineage/multihost/MULTIHOST_GUIDE.md#L117-L129), Machine 1 (`alpha`) is deployed first **without `--seed`**, while Machine 2 (`beta`), Machine 3 (`pay`), and Machine 4 (`audit`) are deployed with `--seed 10.29.77.23:30100` (`alpha`'s `ca_federation` port).
  2. `FederationBundleSyncer.sync_descriptors_from_seeds_and_peers()` ([sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L214-L266)) is **100% pull-only** (`GET /v1/federation/descriptors`). There is **zero** reverse-announce/push path:
     - `AutonomousDomainCAService._dispatch_federation_readonly` ([domain_ca.py](file:///Users/hulalala/Desktop/A/lineage/federation/domain_ca.py#L259-L264)) rejects all `POST` requests with `403 federation_endpoint_read_only`;
     - `MinimalAuditTLSCAService._dispatch_federation_ro` ([bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L864-L883)) returns `404` on `POST`;
     - Although `AgentDirectoryService` defines `POST /v1/federation/descriptors` ([directory.py](file:///Users/hulalala/Desktop/A/lineage/registry/directory.py#L413-L457)), **no caller in the codebase ever invokes it**, and `:8491` requires `CERT_REQUIRED` client mTLS — which fails at the TLS handshake (`UNKNOWN_CA`) before `alpha` has learned `beta`/`pay`'s X.509 Root CA!
  3. Consequently, when operators follow the 4-machine guide verbatim:
     - `alpha` has `seeds = []` and **never** learns `org-beta.io`, `org-payment.io`, or `org-audit.io`;
     - Because `beta`, `pay`, and `audit` all only poll `alpha`, **`beta`, `pay`, and `audit` also never learn each other** (`beta` knows only `{beta, alpha}`; `pay` knows only `{pay, alpha}`; `audit` knows only `{audit, alpha}`);
     - **All 4 machines stay permanently `NotReady` (`503` on `/readyz`)**, `0` cross-domain `AgentCard`s federate, and `status` / `send` / `e2e` fail.
     - For the same reason, in the rehearsal (`00_deploy_4_roles_seeds_only.log:562-563` and `04_audit_migrated_trust_import.txt:12`), manual reverse `seeds add` commands had to be injected to close a directed cycle.
- **Required Fix**:
  1. Expose a bounded, pin-first-verified **`POST /v1/federation/descriptors`** announce route on both `AutonomousDomainCAService._dispatch_federation_readonly` (`:8094`) and `MinimalAuditTLSCAService._dispatch_federation_ro` (`:8094`), accepting `{"descriptors": [...]}` (bounded to e.g. `<= 32` items). Each item is verified via `self.descriptor_store.ingest_raw_descriptor(item)` — unpinned or tampered descriptors are immediately rejected (`UnpinnedDomainDescriptorError` / `DescriptorVerificationError`) without being stored or re-gossiped — and newly verified descriptors invoke an optional `on_descriptor_learned` callback (e.g., `ca_audit_syncer.apply_verified_descriptor` in [bootstrap_services.py](file:///Users/hulalala/Desktop/A/lineage/k8s/bootstrap_services.py#L1104-L1136)).
  2. In `FederationBundleSyncer.sync_descriptors_from_seeds_and_peers()` ([sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L213-L269)), whenever `self.descriptor_store.export_gossip_payload()["descriptors"]` is non-empty, push (`POST <url>`) that gossip payload to remote seed/peer descriptor endpoints (excluding `self.local_ca_url`) in addition to pulling `GET <url>` (ensure `audit-collector` pulls `local_ca_url` first so its push includes `org-audit.io`'s own descriptor, and forwards any newly learned descriptors from `GET` back to `audit-ca` via `/v1/ca/learn-descriptors`).
  3. Add unit/integration tests covering: (a) the exact 4-domain **star topology** (`alpha` with `seeds=[]`; `beta`, `pay`, `audit` with `seeds=[alpha]`) converging to `4/4` domains and `is_ready() == True` on all 4 nodes; and (b) role migration (`audit` recreated on a new port with `--seed <alpha>`) converging across all peers after `trust add` without manual `seeds add` on `alpha`.

---

### `[HIGH-M7-02]` Localized Chinese Windows 10/11 + WSL2 Host LAN IP Detection Fails (`UnicodeDecodeError` + Dead `gbk` Fallback Stripping `"默认网关"`)

- **Locations**:
  - [locator_agent.py](file:///Users/hulalala/Desktop/A/lineage/multihost/locator_agent.py#L238-L281) (`_detect_wsl2_windows_host_ips`)
  - [locator_agent.py](file:///Users/hulalala/Desktop/A/lineage/multihost/locator_agent.py#L60-L77) & [locator_agent.py](file:///Users/hulalala/Desktop/A/lineage/multihost/locator_agent.py#L177-L236) (`_VIRTUAL_WIN_ADAPTER_KEYWORDS` & `parse_windows_ipconfig_lan_ips`)
  - [MULTIHOST_GUIDE.md](file:///Users/hulalala/Desktop/A/lineage/multihost/MULTIHOST_GUIDE.md#L49-L59) (WSL2 daemon lifecycle guidance)
- **Root Cause & Impact**:
  On localized Chinese Windows 10/11 hosts running WSL2 (matching the real rollout machines):
  1. `powershell.exe` is invoked with `text=True` ([locator_agent.py](file:///Users/hulalala/Desktop/A/lineage/multihost/locator_agent.py#L253-L258)) without setting `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8`. When Windows outputs CP936/GBK bytes for Chinese adapter names (`"以太网"`, `"本地连接"`), Python's strict UTF-8 Linux decoder raises `UnicodeDecodeError`, which is silently caught and discarded at line 263.
  2. Execution falls through to `ipconfig.exe` ([locator_agent.py](file:///Users/hulalala/Desktop/A/lineage/multihost/locator_agent.py#L266-L280)), which runs:
     ```python
     raw_out = proc.stdout.decode("utf-8", errors="ignore")
     if not raw_out.strip():
         raw_out = proc.stdout.decode("gbk", errors="ignore")
     ```
     Because `ipconfig.exe` output contains ASCII (`"Windows IP"`, `"IPv4"`, `"192.168.207.1"`, `"10.29.101.203"`), `decode("utf-8", errors="ignore")` is **never empty** (making line 275 unreachable dead code!) while **silently stripping all GBK Chinese characters including `"默认网关"`**!
  3. With `"默认网关"` stripped, `parse_windows_ipconfig_lan_ips` ([locator_agent.py](file:///Users/hulalala/Desktop/A/lineage/multihost/locator_agent.py#L218)) finds `gateway_ips == []` and falls back to `fallback_ips` in adapter order. Because bare `ipconfig.exe` (without `/all`) omits `Description` (`"VMware Virtual Ethernet Adapter..."`) and localized aliases are named `"以太网适配器 以太网 2:"`, a host-only VMware/Docker/Hyper-V `.1` adapter (`192.168.207.1` / `192.168.22.1`) listed before `"无线局域网适配器 WLAN:"` (`10.29.x.x`) is chosen as the primary locator! (Reproduced deterministically in `test_02` of [qa_milestone7_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone7_review.py).)
  *(Note: QuickQ `30.233.233.233` and multi-IP `183.175.x.x` adapters ARE already strictly rejected by `validate_locator_host`'s RFC1918 CIDR filter.)*
- **Required Fix**:
  1. Prepend `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ` to `ps_script`, capture raw `bytes` (`text=False`), and decode with a helper `_decode_windows_cli_bytes(raw: bytes) -> str` that tries `raw.decode("utf-8")` (strict!) first and falls back to `raw.decode("gbk", errors="replace")` for **both** `powershell.exe` and `ipconfig.exe`.
  2. Invoke `ipconfig.exe /all` and inspect `Description` / `描述` lines inside each adapter section against `_is_virtual_windows_adapter_name` (and add `"docker"` to `_VIRTUAL_WIN_ADAPTER_KEYWORDS`); also deprioritize `.1` host-only addresses behind non-`.1` gateway addresses when scoring fallback candidates.
  3. Add a brief note in [MULTIHOST_GUIDE.md](file:///Users/hulalala/Desktop/A/lineage/multihost/MULTIHOST_GUIDE.md#L49-L59) explaining WSL2 background daemon lifecycle (keep a WSL2 shell / Docker Desktop integration active during the experiment, or run `bash lineage/scripts/multihost.sh locator-agent --daemon` if WSL2 was restarted).

---

### `[MEDIUM-M7-01]` Unbounded Memory & Poll-Amplification Vectors on Untrusted Seed, Descriptor, and mDNS Channels

- **Locations**:
  - [locators.py](file:///Users/hulalala/Desktop/A/lineage/federation/locators.py#L432-L434) & [locators.py](file:///Users/hulalala/Desktop/A/lineage/federation/locators.py#L516-L526) (`DomainDescriptorStore._ignored_unpinned`, `_rejected_counts`, `_last_errors`)
  - [sync.py](file:///Users/hulalala/Desktop/A/lineage/federation/sync.py#L233-L266) (`sync_descriptors_from_seeds_and_peers`)
  - [locators.py](file:///Users/hulalala/Desktop/A/lineage/common/locators.py#L312-L335) (`SeedEndpointStore.add_dynamic_seed`) & [locator_agent.py](file:///Users/hulalala/Desktop/A/lineage/multihost/locator_agent.py#L662-L683) (`append_seed_to_local_clusters`)
- **Root Cause & Impact**:
  - `DomainDescriptorStore.ingest_raw_descriptor` records unverified `td_hint` strings directly into `self._ignored_unpinned`, `self._rejected_counts`, and `self._last_errors` with no size or key-length cap; a malicious seed returning random `trust_domain` strings grows these collections without bound.
  - `sync_descriptors_from_seeds_and_peers` reads unbounded HTTP response bodies and iterates over unbounded `payload["descriptors"]` lists.
  - `SeedEndpointStore.add_dynamic_seed` and mDNS `append_seed_to_local_clusters` have no upper bound on stored seed endpoints, allowing spoofed LAN `_lct._tcp.local.` multicast packets (when `--discover mdns` is enabled) to inject hundreds of dead RFC1918 `ip:port` entries that stall the 2s sync loop behind sequential connect timeouts.
- **Required Fix**:
  - Enforce `MAX_DESCRIPTORS_PER_MESSAGE = 32` and max HTTP response size (`<= 1 MiB`) in `sync_descriptors_from_seeds_and_peers()` and `POST /v1/federation/descriptors`.
  - Cap `_ignored_unpinned`, `_rejected_counts`, and `_last_errors` in `DomainDescriptorStore` (e.g., `<= 64` bounded keys, each truncated to `<= 128` chars).
  - Cap `SeedEndpointStore` and `append_seed_to_local_clusters` to `MAX_BOOTSTRAP_SEEDS = 32`.

---

### `[MEDIUM-M7-02]` `ConfigMap/lct-bootstrap-seeds` Key Conflict (`"seeds"` vs `"seeds.txt"`) Wipes Operator-Configured Seeds

- **Locations**:
  - [config_gen.py](file:///Users/hulalala/Desktop/A/lineage/multihost/config_gen.py#L1342) (`render_role_k8s_manifests` writes `data: {"seeds": ...}`)
  - [lct_multihost_cli.py](file:///Users/hulalala/Desktop/A/lineage/multihost/lct_multihost_cli.py#L598-L604) & [lct_multihost_cli.py](file:///Users/hulalala/Desktop/A/lineage/multihost/lct_multihost_cli.py#L619-L625) (`seeds add` / `seeds remove` writes `data: {"seeds": ...}`)
  - [locator_agent.py](file:///Users/hulalala/Desktop/A/lineage/multihost/locator_agent.py#L670-L680) (`append_seed_to_local_clusters` reads ONLY `data.get("seeds.txt", "")` and applies `data: {"seeds.txt": ...}`)
- **Root Cause & Impact**:
  When `--discover mdns` discovers a peer seed and calls `append_seed_to_local_clusters`, `kubectl apply` replaces `ConfigMap/lct-bootstrap-seeds`'s `data` map with `{"seeds.txt": ...}`, **deleting** any `--seed` endpoints configured during `deploy` under key `"seeds"`! Conversely, `multihost.sh seeds add/remove` writes `{"seeds": ...}`, wiping `"seeds.txt"`.
- **Required Fix**:
  Read existing seeds across **all** values in `(cm.get("data") or {}).values()` inside `append_seed_to_local_clusters`, and write back under the canonical key `"seeds"` matching `config_gen.py` and `lct_multihost_cli.py`.

---

### `[LOW-M7-01]` Stale M6 Flags (`--alpha-ip`), `Tailscale` Reference, & `typ` Typo in `lineage/README.md` and `lineage/ARCHITECTURE.md`

- **Locations**:
  - [README.md](file:///Users/hulalala/Desktop/A/lineage/README.md#L66-L85)
  - [ARCHITECTURE.md](file:///Users/hulalala/Desktop/A/lineage/ARCHITECTURE.md#L122)
  - [test_m7_identity_addressing.py](file:///Users/hulalala/Desktop/A/lineage/tests/test_m7_identity_addressing.py#L1286-L1294)
- **Root Cause & Impact**:
  1. [README.md](file:///Users/hulalala/Desktop/A/lineage/README.md#L66-L85) was missed during the M7 documentation rewrite: it still says `3-Machine Physical Interconnection`, mentions `Tailscale network` and `CoreDNS FQDN resolution` (line 68), gives removed `--alpha-ip <IP1> --beta-ip <IP2> --pay-ip <IP3>` commands (lines 72 & 75, which now fail with exit code `2`), and references deprecated `update-peer-ips` (line 84).
  2. [ARCHITECTURE.md](file:///Users/hulalala/Desktop/A/lineage/ARCHITECTURE.md#L122) writes `typ="lct-agent-card+jwt"` instead of the actual `typ="a2a-agent-card+jwt"` used in [agent_card.py](file:///Users/hulalala/Desktop/A/lineage/registry/agent_card.py#L389).
- **Required Fix**:
  Update Section 4 of `lineage/README.md` to match the 4-machine seeds-only + `trust import` M7 workflow (zero Tailscale / `--alpha-ip` / `update-peer-ips` references), add `lineage_root / "README.md"` to `test_10_static_audit_zero_hardcoded_peer_ips_ports_fqdns_or_tailscale`, and fix `typ="a2a-agent-card+jwt"` in `lineage/ARCHITECTURE.md:122`.

---

## 3. Mandatory 7-Point Checklist Summary

| # | Checklist Area | Status | Notes |
| :- | :--- | :--- | :--- |
| **1** | Automated Test Suites (`run_all` + M1–M6 Non-Cluster Sign-Offs) | **PASS** | `run_all`: `79/79` PASS (`0` warnings); M1 (`5/5`), M2–M4 non-cluster (`11/11`), M5 (`3/4`, only pre-git `.git` check differs), M6 (`3/4`, only `e2e_sync_hook` port `30104` vs `30990` legitimate M7 dynamic port redesign). |
| **2** | Seedless First-Node (`alpha`) Bootstrap & Convergence | **NEEDS_FIX** | **`[HIGH-M7-01]`**: Pull-only gossip deadlocks when `alpha` boots without `--seed` and `beta`/`pay`/`audit` pass `--seed <alpha>`. |
| **3** | Locator & Descriptor Cryptographic Security | **NEEDS_FIX** | Pin-first ordering, `cnf.jkt` card binding, anti-rollback/equivocation, local-domain spoof guard, and RFC1918 CIDR validation **PASS**; untrusted map/seed bounds & ConfigMap key mismatch flagged in **`[MEDIUM-M7-01]`** & **`[MEDIUM-M7-02]`**. |
| **4** | Identity-Pinned TLS 1.3 by IP & Zero IP-Literal SNI | **PASS** | Every outbound IP path pins `expected_spiffe_id`; `0` code paths allow `check_hostname=False` without SPIFFE pinning; IP-literal SNI stripped; server mTLS `CERT_REQUIRED` intact. |
| **5** | Static Audit (Zero Peer IPs/Ports/FQDNs/Tailscale) | **NEEDS_FIX** | Clean across `lineage/multihost/*`, manifests, CLI, and `MULTIHOST_GUIDE.md`; stale M6 section in `lineage/README.md:66-85` flagged in **`[LOW-M7-01]`**. |
| **6** | Real 4-Machine Operational Rollout Readiness (Mac + WSL2) | **NEEDS_FIX** | QuickQ (`30.233.233.233`) & `183.175.x.x` rejected, `--advertise-ip` & `-LocalPort 30000-32767 -Profile Any` verified; Chinese Windows GBK WSL2 bug flagged in **`[HIGH-M7-02]`**. |
| **7** | Rehearsal Evidence, Host Isolation, & Public GitHub Dry-Run | **PASS** | `38` rehearsal files audited (`8/8` E2E PASS, `0` leaked keys/JWTs/tokens); `0` `lctmh-*` containers; baseline/M4 untouched (`Exited`); `push_to_github.sh --dry-run` PASS (`workspace` & `lineage-only`). |
