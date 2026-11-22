# Milestone 3 Independent Code Quality & Security Compliance Audit Report

- **Reviewer**: `k8s-qa-reviewer` (Independent QA & Security Compliance Session)
- **Audit Scope**:
  - Milestone 3 Source Modules: [lineage/a2a/](file:///Users/hulalala/Desktop/A/lineage/a2a/), [lineage/federation/](file:///Users/hulalala/Desktop/A/lineage/federation/), [lineage/common/mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py), [lineage/common/http_utils.py](file:///Users/hulalala/Desktop/A/lineage/common/http_utils.py), [lineage/registry/](file:///Users/hulalala/Desktop/A/lineage/registry/), [lineage/revocation/](file:///Users/hulalala/Desktop/A/lineage/revocation/), [lineage/sidecar/](file:///Users/hulalala/Desktop/A/lineage/sidecar/), [lineage/verifier/policy_verifier.py](file:///Users/hulalala/Desktop/A/lineage/verifier/policy_verifier.py), [lineage/audit/auditor.py](file:///Users/hulalala/Desktop/A/lineage/audit/auditor.py), [lineage/agents/](file:///Users/hulalala/Desktop/A/lineage/agents/), [lineage/k8s/](file:///Users/hulalala/Desktop/A/lineage/k8s/)
  - Live Kubernetes Cluster: `kind-agent-identity-lab` (`18/18` LCT Pods across `lineage-ctrl`, `lineage-alpha`, `lineage-beta`, `lineage-pay` + `3/3` baseline Pods in `team1`)
  - E2E Run Evidence: [lineage/k8s/runs/20261119T091029Z/](file:///Users/hulalala/Desktop/A/lineage/k8s/runs/20261119T091029Z/)
- **Independent Verification Suite**: [qa_milestone3_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone3_review.py) (`8/8` tests executed and passing, including deterministic reproductions of all findings)
- **Overall Verdict**: **`NEEDS_FIX`** (`0` Critical, `2` High, `2` Medium, `2` Low)

---

## 1. Executive Summary & Checklist Matrix

Milestone 3 delivers a substantial architectural upgrade: genuine 3-namespace physical CA isolation (`alpha-ca`, `beta-ca`, `payment-ca`), a keyless `audit-collector`, end-to-end TLS 1.3 mutual X.509 authentication on `:8443` with zero residual private keys on `/var/run/lct-mtls-ram`, and a real-time flushed Server-Sent Events (`text/event-stream`) A2A v1.0 protocol stack integrated with live `qwen2.5:3b` tool-calling.

However, independent adversarial review uncovered **2 High-severity**, **2 Medium-severity**, and **2 Low-severity** security/protocol compliance issues that must be remediated before Milestone 3 sign-off:

| Area | Checklist Item | Status | Summary |
| :--- | :--- | :---: | :--- |
| **1. Baseline & Regression** | `README.md`, `lab/`, `src/`, `reviews/` untouched; `team1` `3/3` (`2/2 Running`) | **PASS** | `0` modified baseline files; all 12 prior review artifacts intact; `team1` Pods healthy |
| **1. Baseline & Regression** | `python3 -m lineage.tests.run_all` (`47/47`) & `runs/20261119T091029Z/` redaction | **PASS** | `47/47` pass (`15.74s`); `0` PEM private keys, `0` raw LCT/JWS tokens, `0` private JWK `"d"` fields across all 15 run files |
| **2. Official A2A v1.0** | `/.well-known/agent-card.json` schema, `SendStreamingMessage` real-time SSE, `GetTask` `(task_id, sub)` isolation | **PASS** | `protocolVersion: "1.0"`, structured `skills`, `capabilities`, `securitySchemes`, `signatures`; SSE frames empirically verified arriving incrementally mid-execution (`@0.031s`, `@0.332s`, `@0.636s`) |
| **2. Official A2A v1.0** | `CancelTask` caller lineage jurisdiction & state-transition atomicity; JSON-RPC 2.0 edge cases | **NEEDS_FIX** | **`[MEDIUM-M3-01]`** Non-atomic state flip to `CANCELED` before `cascade_revoke_hook` + missing lineage-prefix ancestry check allows sibling-branch cancellation; **`[LOW-M3-02]`** minor JSON-RPC 2.0 envelope edge cases |
| **3. 3-Domain Federation** | Physical CA isolation, keyless `audit-collector`, `/v1/federation/notify` SSRF safety, cross-domain card/event anti-spoofing | **PASS** | Live K8s verified: each CA serves only its single trust domain; `audit-collector` mounts zero SA tokens & holds zero keys; `/v1/federation/notify` ignores body/query URLs (`0` SSRF hits); foreign card smuggling & version downgrades blocked |
| **3. 3-Domain Federation** | Cross-domain `HIGH_RISK` synchronous revocation consistency & CA SA role mapping | **NEEDS_FIX** | **`[HIGH-M3-01]`** Healthy `wait_ms=0` pulls synchronously from `alpha-revocation`, **but** `sync_from_federation_peers()` silently swallows peer errors (`except Exception: continue`), causing `payment-vault-mcp` to **fail-open (`200 ALLOW`)** on revoked `HIGH_RISK` settlements during cross-domain partition/timeout; **`[LOW-M3-01]`** wildcard `-revocation` SA suffix elevation |
| **4. Bidirectional mTLS 1.3** | Live K8s `:8443` TLS 1.3 + `CERT_REQUIRED`, inbound client domain pinning, `MTLS_CHANNEL_BINDING_MISMATCH`, `/var/run/lct-mtls-ram` cleanup, `app` zero-key/zero-SA isolation | **PASS** | Live `kubectl exec` across all 7 data-plane Pods verified TLSv1.3, plain HTTP & certless TLS blocked, `mtls_ram_residual_files == []`, `app` has zero SA tokens & zero RAM key mount |
| **4. Bidirectional mTLS 1.3** | Cross-domain X.509 `NameConstraints` (outbound server MITM) & leaf `BasicConstraints`/`KeyUsage`/`ExtendedKeyUsage` checks | **NEEDS_FIX** | **`[HIGH-M3-02]`** Root CAs lack `x509.NameConstraints` and outbound clients load flat `combined_ca_pem()` without server domain pinning, allowing a compromised `beta-ca` to mint a server cert impersonating `payment-vault-mcp` / `orchestrator-alpha`; **`[MEDIUM-M3-02]`** `verify_peer_der_cert` omits mandatory `BasicConstraints(ca=False)`, `KeyUsage`, and `ExtendedKeyUsage` checks |

---

## 2. Verified Positive Controls (Code + Live Cluster)

1. **Live Cluster Isolation & Zero-Key Hygiene (`kind-agent-identity-lab`)**:
   - `lineage-alpha/alpha-ca`, `lineage-beta/beta-ca`, and `lineage-pay/payment-ca` each export strictly 1 domain (`org-alpha.io`, `org-beta.io`, `org-payment.io`) on `/v1/federation/bundle` with `any_d_field == False`, and reject cross-namespace K8s SA JWTs with `403 k8s_sa_attestation_failed`.
   - `lineage-ctrl/audit-collector` has `automountServiceAccountToken: false`, mounts neither `/var/run/secrets/kubernetes.io/serviceaccount/token` nor `/var/run/lct-sa/token`, and holds zero signing keys.
   - Across all 7 `2/2` data-plane Deployments (`orchestrator-alpha`, `flight-specialist`, `hotel-specialist-primary`, `hotel-specialist-backup`, `settlement-converger`, `travel-ops-mcp`, `payment-vault-mcp`), `kubectl exec` confirmed:
     - `[app]`: `k8s_sa=False`, `lct_sa=False`, `mtls_ram=False`
     - `[lct-sidecar]`: `k8s_default_sa=False`, `lct_sa=True` (`aud=lct-federation-ca`), `mtls_ram_residual_files=[]`
     - All 7 `:8443` Services reject plaintext HTTP, reject TLS handshakes without a client certificate (`TLSV13_ALERT_CERTIFICATE_REQUIRED`), and negotiate `TLSv1.3` with valid mTLS bundles.
2. **Real-Time A2A v1.0 SSE Streaming (`SendStreamingMessage`)**:
   - Verified in [rpc.py](file:///Users/hulalala/Desktop/A/lineage/a2a/rpc.py#L308-L455), [http_utils.py](file:///Users/hulalala/Desktop/A/lineage/common/http_utils.py#L348-L387), and [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L735-L776): `SendStreamingMessage` uses a live worker thread + `queue.Queue` + immediate `wfile.flush()` per SSE frame + streaming sidecar relay. Empirical timing in `test_02` confirmed `SUBMITTED`/`WORKING` arrive at `<0.05s`, mid-execution `artifactUpdate` arrives at `~0.31s` while `work_handler` is still running, and final `COMPLETED` (`final: true`) arrives at `~0.60s`.
3. **SSRF-Safe `/v1/federation/notify` & Cross-Domain Card/Event Signature Verification**:
   - Both [directory.py](file:///Users/hulalala/Desktop/A/lineage/registry/directory.py#L314-L316) and [service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L642-L644) ignore request bodies/queries on `POST /v1/federation/notify` and pull strictly from pre-configured `peer_directory_urls` / `peer_revocation_urls` (verified against a local SSRF canary listener in `test_03`).
   - [directory.py](file:///Users/hulalala/Desktop/A/lineage/registry/directory.py#L140-L154) and [service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L118-L152) verify that federated `AgentCard`s and `RevocationEvent`s match `expected_peer_domain` and are cryptographically signed by an SVID in that exact trust domain.

---

## 3. Detailed Findings & Required Remediations

### `[HIGH-M3-01]` Federated `HIGH_RISK` Revocation Fails Open (`200 ALLOW`) During Cross-Domain Peer Partition or Timeout

- **Locations**:
  - [lineage/revocation/service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L154-L195) (`RevocationService.sync_from_federation_peers`)
  - [lineage/revocation/service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L662-L679) (`GET /v1/events` synchronous `wait_ms == 0` handler)
  - [lineage/verifier/policy_verifier.py](file:///Users/hulalala/Desktop/A/lineage/verifier/policy_verifier.py#L580-L600) (`LeafVerifier.verify_request` `ADAPTIVE_RISK_ANCHORED` anchor check)
- **Vulnerability Details**:
  When `payment-vault-mcp` (`org-payment.io`, `VerificationMode.ADAPTIVE_RISK_ANCHORED`, `fail_closed_on_high_risk=True`) processes a `HIGH_RISK` `execute_settlement` request carrying an `org-alpha.io`-rooted LCT or `MultiParentToken`, it invokes `self.revocation_replica.sync_now(wait_ms=0)`, sending `GET /v1/events?since_version=...&wait_ms=0` to `payment-revocation`.
  In [service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L665-L667), `payment-revocation` calls `self.sync_from_federation_peers()`. While this works when all peers are healthy, `sync_from_federation_peers()` wraps every peer HTTP pull and event ingestion in `except Exception: continue` ([service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L170-L171) and [L190-L191](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L190-L191)) and silently skips `trust_domain` mismatches ([L173-L174](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L173-L174)).
  Consequently, if `org-alpha.io` revokes a task/branch on `alpha-revocation` while the cross-domain link between `payment-revocation` and `alpha-revocation` is partitioned, degraded (`>2.0s`), or returning `5xx` (while `payment-revocation` itself remains up inside `lineage-pay`), `payment-revocation` silently ignores the failure and returns **`200 OK`** with stale state to `payment-vault-mcp`. `payment-vault-mcp` then **executes the revoked `HIGH_RISK` settlement (`200 ALLOW`)**, breaking LCT's fail-closed `HIGH_RISK` revocation guarantee across trust domains.
- **Empirical Reproduction**: `Milestone3IndependentQAReviewTests.test_05_finding_high_m3_01_federated_high_risk_revocation_fail_open_on_partition` in [qa_milestone3_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone3_review.py#L421-L515).
- **Required Fix**:
  1. In [policy_verifier.py](file:///Users/hulalala/Desktop/A/lineage/verifier/policy_verifier.py#L581-L599), extract the token's root trust domain (`parsed.root.issuer_trust_domain` for `LineageToken`, or `parsed.parent_chains[0].root.issuer_trust_domain` for `MultiParentToken`, plus any foreign `visited_subjects` domains if applicable) and pass `required_trust_domain=...` into `self.revocation_replica.sync_now(wait_ms=0, required_trust_domain=...)`.
  2. In [service.py](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L154-L195) and [L662-L679](file:///Users/hulalala/Desktop/A/lineage/revocation/service.py#L662-L679):
     - Accept `?require_trust_domain=<domain>` (or `strict=1` when `wait_ms == 0`) on `GET /v1/events`.
     - Add `strict_domains: Optional[Set[str]] = None` (or `raise_on_error: bool = False`) to `sync_from_federation_peers(...)`: when syncing synchronously for a `HIGH_RISK` check (`wait_ms == 0`), if `required_trust_domain` is a foreign peer domain (or across configured peers when `strict` is requested) and the peer request fails, times out, returns a mismatched `trust_domain`, or fails cryptographic event verification (`ingest_federated_event`), raise `RevocationError` and return **`503 Service Unavailable`** (`{"error": "federation_anchor_unavailable", ...}`) from `GET /v1/events`.
     - Keep background polling (`start_federation_sync`) and `/v1/federation/notify` best-effort (`raise_on_error=False`), while ensuring synchronous `HIGH_RISK` anchoring is strictly **fail-closed (`503 REVOCATION_ANCHOR_UNAVAILABLE`)** when the authoritative origin domain cannot be reached.

---

### `[HIGH-M3-02]` Outbound mTLS Client Accepts Cross-Domain Spoofed Server Certificates (Missing X.509 `NameConstraints` & Missing Outbound Peer Domain Pinning)

- **Locations**:
  - [lineage/common/mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L80-L115) (`X509DomainAuthority.__init__` Root CA generation)
  - [lineage/common/mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L230-L266) (`X509FederationTrustStore.register_domain_root_pem`)
  - [lineage/common/mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L383-L392) (`WorkloadMTLSBundle.build_client_ssl_context`)
  - [lineage/sidecar/proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L818-L837) (`LineageSidecar._outbound_request`)
- **Vulnerability Details**:
  On the **inbound server** path ([http_utils.py](file:///Users/hulalala/Desktop/A/lineage/common/http_utils.py#L281-L295)), `LineageSidecar` calls `X509FederationTrustStore.verify_peer_der_cert`, which pins client certificates to the Root CA of their `spiffe://<domain>/...` URI SAN.
  However, on the **outbound client** path:
  1. `X509DomainAuthority.root_cert` ([mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L80-L115)) does **not** include an RFC 5280 `x509.NameConstraints(critical=True, ...)` extension restricting the URI/DNS namespaces each autonomous CA is permitted to certify.
  2. `WorkloadMTLSBundle.build_client_ssl_context` ([mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L383-L392)) loads `self.trust_store.combined_ca_pem()` — concatenating all 3 autonomous Root CAs (`alpha-ca`, `beta-ca`, `payment-ca`) into a single flat OpenSSL trust store — and outbound `httpx.Client` connections never invoke `verify_peer_der_cert` on the upstream server's certificate or scope the client `SSLContext` to the target's trust domain.
  3. **Attack Impact**: A compromised `beta-ca` (`org-beta.io`) can sign a TLS **server** leaf certificate with `DNSName("payment-vault-mcp.lineage-pay.svc.cluster.local")` / `DNSName("orchestrator-alpha.lineage-alpha.svc.cluster.local")` and `URI("spiffe://org-payment.io/...")`. Every outbound mTLS client (`LineageSidecar`, `A2AClient`, `GatewaySession`) accepts the TLS 1.3 handshake (`200 OK`) and transmits live `Authorization: DPoP <LCT>` + `DPoP` headers and request payloads to the impersonating server.
- **Empirical Reproduction**: `Milestone3IndependentQAReviewTests.test_06_finding_high_m3_02_outbound_mtls_client_trusts_cross_domain_spoofed_server_cert` in [qa_milestone3_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone3_review.py#L520-L632).
- **Required Fix (Two-Layer Defense-in-Depth)**:
  1. **RFC 5280 X.509 `NameConstraints` on Autonomous Root CAs ([mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L59-L116) & [L230-L266](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L230-L266))**:
     - Pass `allowed_dns_suffixes: Optional[Iterable[str]] = None` (e.g., `(f".{allowed_k8s_namespace}.svc.cluster.local", f".{allowed_k8s_namespace}.svc", "localhost")` in `AutonomousDomainCAService`) into `X509DomainAuthority(trust_domain, allowed_dns_suffixes=...)`.
     - Add `x509.NameConstraints(permitted_subtrees=[x509.UniformResourceIdentifier(trust_domain), ...DNSName entries...], excluded_subtrees=None)` with `critical=True` to `self.root_cert` (note per RFC 5280 §4.2.1.10 and OpenSSL 3.x: `UniformResourceIdentifier` in `NameConstraints` takes the authority host string `"org-beta.io"`, **not** `"spiffe://org-beta.io"`).
     - In `X509FederationTrustStore.register_domain_root_pem(expected_trust_domain, root_pem)`, verify that every federated Root CA carries `BasicConstraints(ca=True, path_length=0)` and critical `NameConstraints` whose `UniformResourceIdentifier` permitted subtrees only allow `expected_trust_domain` (preventing a pre-compromised peer CA from exporting an unconstrained Root CA PEM!).
  2. **Per-Domain Client `SSLContext` Pinning & Server Cert Verification ([mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L383-L392) & [proxy.py](file:///Users/hulalala/Desktop/A/lineage/sidecar/proxy.py#L818-L837))**:
     - Support `WorkloadMTLSBundle.build_client_ssl_context(check_hostname: bool = True, expected_trust_domain: Optional[str] = None)` which loads **only** `self.trust_store.domain_ca_pem(expected_trust_domain)` when the target trust domain is known!
     - In `LineageSidecar` (when delegating to a verified `AgentCard`, probing `card.endpoint/healthz`, returning results to an ancestor `spiffe_id`, or calling an MCP tool with known `target_audience` / K8s namespace domain) and `A2AClient`, select the per-domain `SSLContext` for the target's `trust_domain` **and** inspect the upstream server's peer DER certificate (e.g., via `resp.extensions["network_stream"].get_extra_info("ssl_object").getpeercert(binary_form=True)`) through `trust_store.verify_peer_der_cert(..., required_eku=ExtendedKeyUsageOID.SERVER_AUTH)`! This blocks cross-domain server impersonation even on shared `localhost` / `127.0.0.1` test endpoints.

---

### `[MEDIUM-M3-01]` A2A v1.0 `CancelTask` Mutates State Non-Atomically Before `cascade_revoke_hook` and Lacks Lineage-Prefix Ancestry Verification

- **Locations**:
  - [lineage/a2a/rpc.py](file:///Users/hulalala/Desktop/A/lineage/a2a/rpc.py#L490-L551) (`A2AServerEngine.dispatch` `CancelTask` handler)
  - [lineage/a2a/models.py](file:///Users/hulalala/Desktop/A/lineage/a2a/models.py#L455-L470) & [L635-L716](file:///Users/hulalala/Desktop/A/lineage/a2a/models.py#L635-L716) (`A2ATaskStore.create_or_submit` & `cancel_authorized`)
- **Vulnerability Details**:
  1. **Permanent State Corruption Before Authorization Check ([rpc.py](file:///Users/hulalala/Desktop/A/lineage/a2a/rpc.py#L510-L536))**:
     `self.task_store.cancel_authorized(...)` is called at line `510` — permanently setting `rec.cancel_event.set()` and `rec.task.status = TaskStatus(state=TaskState.CANCELED, ...)` ([models.py](file:///Users/hulalala/Desktop/A/lineage/a2a/models.py#L701-L715)) — **before** `self.cascade_revoke_hook(req_id, prefix_to_revoke, target_id)` runs at line `526`. When `cascade_revoke_hook` rejects an unauthorized `revokePrefix` (or fails closed because the revocation service rejected the caller), `CancelTask` returns `403` (`-32003`), yet the task in `A2ATaskStore` remains permanently stuck in `TASK_STATE_CANCELED` (`409` on any subsequent `SendMessage`).
  2. **Missing Lineage-Prefix Ancestry Check Allows Sibling-Branch Cancellation ([models.py](file:///Users/hulalala/Desktop/A/lineage/a2a/models.py#L685-L688))**:
     `A2ATaskStore.cancel_authorized` checks only `if rec.owner_sub != caller_sub:` and never verifies `is_lineage_segment_prefix(caller_lineage_path, rec.lineage_path)`. In a multi-branch workflow where two sibling branches (`Orch -> PrimaryB1 -> C` and `Orch -> SiblingB2 -> C`) share the same `(task_id, sub)` and both hold tokens addressed to `C`, the lower-privilege sibling branch `SiblingB2` can cancel `PrimaryB1`'s task on `C` (either directly or by triggering the partial failure above).
- **Empirical Reproduction**: `Milestone3IndependentQAReviewTests.test_07_finding_medium_m3_01_canceltask_atomicity_and_sibling_branch_cancel` in [qa_milestone3_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone3_review.py#L637-L742).
- **Required Fix**:
  1. Add a read-only pre-validation method on `A2ATaskStore` (e.g., `validate_cancel_request(task_id, caller_sub, caller_lineage_path, explicit_prefix)`):
     - Verify `rec.owner_sub == caller_sub` and task state is cancelable (`SUBMITTED`, `WORKING`, `INPUT_REQUIRED`, `CANCELED`, or `stagedForSettlement`).
     - Verify **lineage ancestry**: if `rec` exists and has `rec.lineage_path`, require `is_lineage_segment_prefix(caller_lineage_path, rec.lineage_path)` (only the same branch or an upstream ancestor coordinate of `rec.lineage_path` may cancel `rec`, never a disjoint sibling branch!).
     - If `explicit_prefix` is supplied, require `is_lineage_segment_prefix(caller_lineage_path, explicit_prefix)` (and `explicit_prefix == f"/{task_id}"` or `explicit_prefix.startswith(f"/{task_id}/")`).
  2. Execute `self.cascade_revoke_hook(req_id, prefix_to_revoke, target_id)` **after** `validate_cancel_request(...)` succeeds and **before** committing `self.task_store.cancel_authorized(...)`, so that any failed or unauthorized cascading revocation leaves `A2ATaskStore` completely unmodified!

---

### `[MEDIUM-M3-02]` Incomplete Leaf X.509 Extension Validation (`BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`) in `verify_peer_der_cert`

- **Location**: [lineage/common/mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L277-L330) (`X509FederationTrustStore.verify_peer_der_cert`)
- **Vulnerability Details**:
  1. At [mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L290-L295), `verify_peer_der_cert` catches `except x509.ExtensionNotFound: pass` for `BasicConstraints`, silently permitting peer certificates that omit `BasicConstraints(ca=False)`.
  2. `verify_peer_der_cert` performs **zero** validation of `x509.KeyUsage` (`digital_signature == True`, `key_cert_sign == False`) and **zero** validation of `x509.ExtendedKeyUsage` (`ExtendedKeyUsageOID.CLIENT_AUTH` for inbound client authentication, `ExtendedKeyUsageOID.SERVER_AUTH` for outbound server authentication). A certificate carrying only `EMAIL_PROTECTION` or missing `KeyUsage`/`BasicConstraints` passes `verify_peer_der_cert`.
- **Empirical Reproduction**: `Milestone3IndependentQAReviewTests.test_08_findings_medium_m3_02_and_low_m3_01_02_cert_eku_sa_suffix_and_jsonrpc` (Part A) in [qa_milestone3_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone3_review.py#L747-L785).
- **Required Fix**:
  Update `verify_peer_der_cert(self, der_bytes: bytes, required_eku: Optional[x509.ObjectIdentifier] = ExtendedKeyUsageOID.CLIENT_AUTH) -> Tuple[str, str]` in [mtls.py](file:///Users/hulalala/Desktop/A/lineage/common/mtls.py#L277-L330) to:
  - Require `x509.BasicConstraints` extension to be present (`ExtensionNotFound` -> raise `MTLSError`) and `bc.ca is False`;
  - Require `x509.KeyUsage` extension to be present (`ExtensionNotFound` -> raise `MTLSError`) with `ku.digital_signature is True` and `ku.key_cert_sign is False` and `ku.crl_sign is False`;
  - Require `x509.ExtendedKeyUsage` extension to be present (`ExtensionNotFound` -> raise `MTLSError`) and verify `required_eku in eku` when `required_eku is not None` (`CLIENT_AUTH` on inbound client verification, `SERVER_AUTH` on outbound server verification).

---

### `[LOW-M3-01]` Wildcard `-revocation` / `-directory` ServiceAccount Suffix Matching in `AutonomousDomainCAService._resolve_workload_path`

- **Location**: [lineage/federation/domain_ca.py](file:///Users/hulalala/Desktop/A/lineage/federation/domain_ca.py#L42-L45) & [L111-L122](file:///Users/hulalala/Desktop/A/lineage/federation/domain_ca.py#L111-L122)
- **Vulnerability Details**:
  `_resolve_workload_path` maps any K8s ServiceAccount matching `k8s_sa == suffix or k8s_sa.endswith(f"-{suffix}")` (`"revocation"`, `"directory"`) to the privileged system SPIFFE path `/ns/sys/sa/revocation` or `/ns/sys/sa/directory`. Any ordinary business workload SA in the namespace whose name happens to end in `-revocation` (e.g., `order-revocation`, `cart-revocation`) would be issued `spiffe://<domain>/ns/sys/sa/revocation`, which is trusted by `FailoverReceipt` and `RevocationReplicaClient` to sign authoritative `RevocationEvent`s.
- **Empirical Reproduction**: `test_08` (Part B) in [qa_milestone3_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone3_review.py#L787-L802).
- **Required Fix**:
  Remove wildcard `.endswith(f"-{suffix}")` matching in [domain_ca.py](file:///Users/hulalala/Desktop/A/lineage/federation/domain_ca.py#L119-L121). Instead, pass explicit authorized control-plane ServiceAccount names (e.g., `authorized_revocation_sa` / `authorized_directory_sa` via env vars in [01-control-plane.yaml](file:///Users/hulalala/Desktop/A/lineage/k8s/manifests/01-control-plane.yaml) and `bootstrap_services.py`, or restrict defaults strictly to exact SA names `revocation` / `directory` plus explicit `sa_path_overrides` such as `{"alpha-revocation": "/ns/sys/sa/revocation", "alpha-directory": "/ns/sys/sa/directory"}`).

---

### `[LOW-M3-02]` Minor JSON-RPC 2.0 Request Envelope Validation Edge Cases in `A2AServerEngine.dispatch`

- **Locations**:
  - [lineage/a2a/rpc.py](file:///Users/hulalala/Desktop/A/lineage/a2a/rpc.py#L135-L166)
  - [lineage/common/http_utils.py](file:///Users/hulalala/Desktop/A/lineage/common/http_utils.py#L67-L76)
- **Vulnerability Details**:
  1. Valid JSON payloads that are not JSON objects (e.g., `[]` or `"str"`) raise `ValueError("Expected JSON object body")` inside `req.json()`, which [rpc.py](file:///Users/hulalala/Desktop/A/lineage/a2a/rpc.py#L137-L142) returns as `-32700` (`Parse error`) rather than JSON-RPC 2.0 `-32600` (`Invalid Request`).
  2. [rpc.py](file:///Users/hulalala/Desktop/A/lineage/a2a/rpc.py#L144-L156) does not enforce that `id` (when present) is `str | int | None` (rejecting booleans `true`/`false`, floats, lists, or dicts per JSON-RPC 2.0 §4) and coerces non-string `method` values (e.g., `"method": 12345`) via `str(...)` into `404 -32601` (`Method not found`) instead of `400 -32600` (`Invalid Request`).
- **Empirical Reproduction**: `test_08` (Part C) in [qa_milestone3_review.py](file:///Users/hulalala/Desktop/A/lineage/reviews/qa_milestone3_review.py#L804-L837).
- **Required Fix**:
  In `A2AServerEngine.dispatch` ([rpc.py](file:///Users/hulalala/Desktop/A/lineage/a2a/rpc.py#L135-L166)):
  - Decode raw `req.body` with `json.loads` (`JSONDecodeError`/`UnicodeDecodeError` -> `400 -32700`);
  - Check `if not isinstance(body, Mapping):` -> return `400 -32600` with `id=None`;
  - Validate `id` (`rpc_id is None or (isinstance(rpc_id, (str, int)) and not isinstance(rpc_id, bool))`), returning `400 -32600` with `id=None` if invalid, and reject envelopes containing `"result"` or `"error"` alongside `"method"`;
  - Validate `isinstance(body.get("method"), str) and body["method"].strip()`, returning `400 -32600` if `method` is missing, empty, or non-string.

---

## 4. Verification Execution Log

```text
1) Baseline & Milestone 1–3 Regression Suite:
   $ PYTHONPATH=/Users/hulalala/Desktop/A /Users/hulalala/Desktop/A/src/cortex/authbridge/venv/bin/python3 -m lineage.tests.run_all
   Ran 47 tests in 15.74s — OK (0 failures)

2) Milestone 3 Independent QA & Adversarial Review Suite:
   $ PYTHONPATH=/Users/hulalala/Desktop/A /Users/hulalala/Desktop/A/src/cortex/authbridge/venv/bin/python3 -m unittest lineage/reviews/qa_milestone3_review.py -v
   Ran 8 tests in 1.220s — OK
```
