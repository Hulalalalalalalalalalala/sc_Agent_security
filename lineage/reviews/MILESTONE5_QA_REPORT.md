# Milestone 5 + Public GitHub Pre-Push Compliance & Multi-Language SDK QA Report

- **Audit Timestamp**: `2026-11-22T15:41:00+08:00`
- **Reviewer**: `k8s-qa-reviewer` (Independent Read-Only Pre-Push Audit Session)
- **Target Public Repository**: `https://github.com/Hulalalalalalalalalalala/sc_Agent_security` (**PUBLIC**)
- **VERDICT**: **`VERDICT: NEEDS_FIX`** (5 concrete pre-push & polyglot SDK hardening items identified before publishing to a public GitHub repository; automated test suite `59/59` passes with `0` warnings)

---

## 1. Executive Answer: Public-Repo Safety of `lab/` & `README.md` (`--scope workspace` vs `--scope lineage-only`)

We performed a full forensic scan across `README.md` and all `116` non-bytecode files in `lab/`:

1. **Credentials, Private Keys, and Kubernetes Secrets in `lab/`**:
   - **PEM Private Keys**: **`0`** (`keycloak-signing-public.pem` and `spire-signing-public.pem` contain `BEGIN PUBLIC KEY` only).
   - **Kubernetes `Secret` Manifests (`kind: Secret`) / OAuth Client Secrets**: **`0`** (`client-secret.txt` is 0 bytes under `federated-jwt`, and `lab-user-credentials` / `keycloak-initial-admin` were never exported to disk).
   - **Passwords**: **`0` real passwords** (only the upstream Rossoctl/Kagenti public demo fixture `"alice123"` for local `keycloak.localtest.me` appears in `lab/scripts/{run_agent_task.py,pod-auth-checks.py,inpod-exchange.sh}`).
2. **Why `--scope workspace` Needs 3 `.gitignore` Exclusions Before Public Push**:
   - **Raw Expired Lab JWT Artifacts**: [t1-expired.jwt](file:///Users/hulalala/Desktop/A/lab/reviews/2026-11-17/token-walkthrough-093330/t1-expired.jwt#L1) and [t1-signing-input.txt](file:///Users/hulalala/Desktop/A/lab/reviews/2026-11-17/token-walkthrough-093330/t1-signing-input.txt#L1) contain an unredacted RS256 Bearer JWT (`exp=1794909811`, local `keycloak.localtest.me`). Even though expired and local-only, pushing raw JWT strings to a **public** repository triggers GitHub Secret Scanning / `gitleaks` alerts (whereas `t1-decoded.json` and `a-to-b.log` are already properly redacted).
   - **Host-Specific Broken Absolute Symlink**: [lab/bin/python3](file:///Users/hulalala/Desktop/A/lab/bin/python3) is a symlink targeting `/Users/hulalala/.local/share/uv/python/cpython-3.12-macos-aarch64-none/bin/python3.12`. It is broken on every other machine, exposes a local home directory path, and caused `push_to_github.sh` (`[ -f "${full_path}" ]` follows symlinks) to miscalculate staged size as `24.52 MB` instead of ~`6.8 MB`.
   - *Informational note*: `README.md`, `lab/RESULTS.md`, and historical `lineage/k8s/runs/*/run.log` contain local path strings (`/Users/hulalala/Desktop/A/...`) in command examples/logs (no secrets).
   - **Conclusion**: Once `.gitignore` excludes `*.jwt`, `lab/reviews/**/t1-signing-input.txt`, and `lab/bin/python3` (without touching `lab/` itself!), **`--scope workspace` (`README.md` + `lab/` + `lineage/`) is 100% free of private keys, secrets, and raw tokens for public push**!
3. **Critical Package-Layout Defect Found in `--scope lineage-only`**:
   - Currently `push_to_github.sh` sets `WORK_TREE="${LINEAGE_DIR}"` when `--scope lineage-only` is selected, flattening `lineage/*` to the repo root (`common/`, `k8s/Dockerfile`, `scripts/`). That strips the top-level `lineage/` Python package directory and breaks `python3 -m lineage.tests.run_all`, `Dockerfile` (`COPY lineage/...`), and `README.md` commands (`bash lineage/scripts/...`). See **`[HIGH-M5-01]`** below.

---

## 2. Detailed Findings (`High` / `Medium` / `Low`) With Exact `file:line`

### `[HIGH-M5-01]` Public-Repo Pre-Push Exclusions (`.gitignore`), Full Staged-File JWT/Symlink Gate, & `--scope lineage-only` Package Prefix Preservation
- **Files & Lines**:
  - [.gitignore](file:///Users/hulalala/Desktop/A/.gitignore#L25-L30)
  - [push_to_github.sh](file:///Users/hulalala/Desktop/A/lineage/scripts/push_to_github.sh#L89-L105), [push_to_github.sh](file:///Users/hulalala/Desktop/A/lineage/scripts/push_to_github.sh#L126-L158), [push_to_github.sh](file:///Users/hulalala/Desktop/A/lineage/scripts/push_to_github.sh#L200-L208)
  - Read-only `lab/` artifacts caught: [t1-expired.jwt](file:///Users/hulalala/Desktop/A/lab/reviews/2026-11-17/token-walkthrough-093330/t1-expired.jwt#L1), [t1-signing-input.txt](file:///Users/hulalala/Desktop/A/lab/reviews/2026-11-17/token-walkthrough-093330/t1-signing-input.txt#L1), [lab/bin/python3](file:///Users/hulalala/Desktop/A/lab/bin/python3)
- **Required Fix**:
  1. Add `*.jwt`, `lab/reviews/**/t1-signing-input.txt`, and `lab/bin/python3` to root [`.gitignore`](file:///Users/hulalala/Desktop/A/.gitignore) (leaving `lab/` 100% untouched on disk).
  2. In [`push_to_github.sh`](file:///Users/hulalala/Desktop/A/lineage/scripts/push_to_github.sh):
     - Fix `--scope lineage-only` so `WORK_TREE="${REPO_ROOT}"` and git stages `.gitignore` + `lineage` (preserving the top-level `lineage/` package directory so `python3 -m lineage.tests.run_all`, `docker build -f lineage/k8s/Dockerfile .`, and `bash lineage/scripts/setup_deps.sh` all work after `git clone`!).
     - Extend the raw JWS/JWT & LCT wire-token scan to check **every staged file** in `STAGED_LIST` (not just `lineage/k8s/runs`) for compact 3-segment JWTs (`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), and reject broken symlinks or symlinks pointing to absolute host paths (`[ -L "${full_path}" ]`). Also guard `[ ! -L "${full_path}" ] && [ -f "${full_path}" ]` when summing file byte sizes.

---

### `[MEDIUM-M5-01]` Rust Reference Agent (`main.rs` & `lib.rs`): Pre-Auth `Content-Length` OOM Panic, Unescaped JSON Response Injection, & Silent Short-Secret Fallthrough
- **Files & Lines**:
  - [main.rs](file:///Users/hulalala/Desktop/A/lineage/sdk/rust/src/main.rs#L37-L71)
  - [lib.rs](file:///Users/hulalala/Desktop/A/lineage/sdk/rust/src/lib.rs#L47-L82)
- **Issues**:
  1. **Pre-Auth Unbounded Allocation DoS (`main.rs:51-54`)**: `let mut buf = vec![0u8; content_len];` runs *before* `verify_loopback_secret` (`main.rs:61`) with no upper bound on `content_len` (e.g., `Content-Length: 10000000000` panics/aborts the process immediately) and no header-line count bound (`main.rs:37-50`).
  2. **Unescaped JSON Interpolation & Missing Method/Path Guard (`main.rs:65-70`, `lib.rs:80-82`)**:
     - `main.rs:66-69` formats `ctx.task_id`, `ctx.sub`, and `ctx.lineage_path` into JSON without calling `json_escape`, and does not enforce `POST` on `/a2a/task`, `/a2a`, or `/`.
     - `lib.rs:80-82` (`json_escape`) only escapes `\` and `"`, omitting `\n`, `\r`, `\t`, and control chars `< 0x20` (`\u00XX`).
  3. **Short `LCT_LOOPBACK_SECRET` Silent Fallthrough (`lib.rs:48-53`)**: When `LCT_LOOPBACK_SECRET` is non-empty but `< 16` chars, `lib.rs` silently falls through to `DEFAULT_SECRET_FILE` instead of returning `Err(ErrorKind::InvalidData)`.
- **Required Fix**:
  Cap header count (e.g. `<= 128`) and `content_len` (e.g. `<= 4 * 1024 * 1024`, returning `413` on overflow), check `verify_loopback_secret` and `POST` route allowlist, make `pub fn json_escape` escape control chars (`\n`, `\r`, `\t`, `\u00XX`) and apply it in `main.rs:66-69`, and fail fast when non-empty `LCT_LOOPBACK_SECRET` has `< 16` chars.

---

### `[MEDIUM-M5-02]` Secret-Length Side-Channel Hardening (Equal-Length SHA-256 Digest Comparison) & Inline `LCT_LOOPBACK_SECRET` Length Checks Across SDKs
- **Files & Lines**:
  - Go: [sdk.go](file:///Users/hulalala/Desktop/A/lineage/sdk/go/lctsdk/sdk.go#L100-L106)
  - Node.js: [lct_sdk.mjs](file:///Users/hulalala/Desktop/A/lineage/sdk/node/lct_sdk.mjs#L26-L36)
  - Rust: [lib.rs](file:///Users/hulalala/Desktop/A/lineage/sdk/rust/src/lib.rs#L67-L78)
  - Python: [lct_sdk.py](file:///Users/hulalala/Desktop/A/lineage/sdk/python/lct_sdk.py#L27-L36)
  - Java: [LCTSidecarClient.java](file:///Users/hulalala/Desktop/A/lineage/sdk/java/LCTSidecarClient.java#L62-L66) & [LCTSidecarClient.java](file:///Users/hulalala/Desktop/A/lineage/sdk/java/LCTSidecarClient.java#L99-L101)
- **Issues**:
  1. **Length-Leak Hardening (`go`, `node`, `rust`)**:
     - Node.js (`lct_sdk.mjs:32-35`) safely avoids `crypto.timingSafeEqual` `RangeError` `500` on unequal buffer lengths, and Java (`MessageDigest.isEqual`) / Python (`hmac.compare_digest`) are safe.
     - However, Go (`sdk.go:102`: `len(provided) != len(expected)`), Node.js (`lct_sdk.mjs:32`: `bufA.length !== bufB.length`), and Rust (`lib.rs:70`: `a.len() != b.len()`) short-circuit before constant-time comparison, leaking the exact length of `expected`. Comparing 32-byte `SHA-256` digests (`crypto/sha256` + `subtle.ConstantTimeCompare` + `subtle.ConstantTimeEq` in Go; `crypto.createHash("sha256")` + `crypto.timingSafeEqual` in Node.js; and branchless length-XOR + padded byte loop in Rust `lib.rs`) eliminates secret-length timing leakage completely.
  2. **Inline `LCT_LOOPBACK_SECRET` Length Validation (`python` & `java`) + Java `jsonEscape`**:
     - `lct_sdk.py:28-30` and `LCTSidecarClient.java:63-66` return `LCT_LOOPBACK_SECRET` without enforcing `>= 16` chars inside `load_loopback_secret` / `loadLoopbackSecret` (unlike Go and Node).
     - `LCTSidecarClient.java:99-101` (`jsonEscape`) should also escape `\n`, `\r`, `\t`.

---

### `[MEDIUM-M5-03]` `lineage/pyproject.toml` Uses `where = [".."]` Outside Project Root
- **File & Line**: [pyproject.toml](file:///Users/hulalala/Desktop/A/lineage/pyproject.toml#L22-L24)
- **Issue**:
  `[tool.setuptools.packages.find]` sets `where = [".."]` inside `lineage/pyproject.toml`. In PEP 517 isolated builds (`pip install ./lineage` / `pip wheel ./lineage`), `setuptools>=68` forbids `..` escaping outside the directory containing `pyproject.toml` (and older setuptools produces an empty `UNKNOWN-0.0.0` wheel).
- **Required Fix**:
  Replace `where = [".."]` in `lineage/pyproject.toml` with `package-dir = {"lineage" = "."}` and explicit `lineage.*` subpackage declarations (or add a workspace-root `pyproject.toml` alongside `package-dir = {"lineage" = "."}` in `lineage/pyproject.toml`) and verify `pip` metadata/wheel build includes the `lineage` modules cleanly.

---

### `[LOW-M5-01]` Validate `--name`, `--skill`, and `--nodeport` Arguments in `configure_agent_lang.sh`
- **File & Line**: [configure_agent_lang.sh](file:///Users/hulalala/Desktop/A/lineage/scripts/configure_agent_lang.sh#L32-L88) & `#L155-L260`
- **Issue**:
  Path-with-spaces handling (`--target "/tmp/qa lct space dir/my go agent"`) works cleanly, and invalid `--lang` / `--domain` flags fail with exit code `2`. However, `--name`, `--skill`, and `--nodeport` are interpolated directly into `k8s-2of2-pod.yaml` without validating DNS-1123 label syntax (`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`), safe skill characters (`^[A-Za-z0-9._,-]+$`), or Kubernetes NodePort integer bounds (`30000..32767`).
- **Required Fix**:
  Add regex and integer range `[30000, 32767]` checks in `configure_agent_lang.sh` (exiting `2` on invalid values).

---

## 3. Verified Passing Items in Milestone 5

- **Full Test & Benchmark Suite (`-W default`)**: `59/59` tests passed in `34.35s` (`36.31s` total with benchmarks), **0 warnings, 0 unhandled exceptions** (including live compiled Go binary behind Python `LineageSidecar`, live Node.js v24.16.0 agent behind `LineageSidecar`, live Python SDK agent behind `LineageSidecar`, and all 5 scaffolded languages).
- **All 5 `k8s-2of2-pod.yaml` Manifests (`python`, `go`, `node`, `java`, `rust`)**: Every manifest sets `automountServiceAccountToken: false` on both `ServiceAccount` and `PodSpec`, mounts **only** `lct-loopback` (`readOnly: true`, `Memory`) into `app` (zero K8s SA tokens, zero mTLS material), and binds `app` strictly to `127.0.0.1:9001`.
- **Dual-Mode `lineage/k8s/Dockerfile`**: Confirmed `/app/.venv/bin/python3` is preserved in cached `weather_tool:pinned` mode (zero network pulls) AND automatically created via `python3 -m venv /app/.venv` + `pip install -r lineage/requirements.txt` in standalone `BASE_IMAGE=python:3.12-slim` mode.
- **Dry-Run Cleanliness & Baseline Immutability**: Both `push_to_github.sh --dry-run` invocations left **zero** `.git` or temporary state in `/Users/hulalala/Desktop/A`, and `README.md`, `lab/`, and `src/` remain 100% unmodified.
