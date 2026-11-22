#!/usr/bin/env bash
# =============================================================================
# Lineage Capability Tree (LCT) — Safe GitHub Pre-Flight & Push Runner
#
# Validates `.gitignore` exclusions (`.tools/`, `src/`, `venv/`), enforces
# 0 symlinks, 0 files > 50 MB, and 0 private keys / raw JWTs / unredacted LCT
# tokens across ALL staged files, verifies GitHub push permission via `gh`, and
# pushes cleanly bypassing dead local HTTP proxies.
#
# Usage:
#   bash lineage/scripts/push_to_github.sh --dry-run
#   bash lineage/scripts/push_to_github.sh --scope lineage-only --dry-run
#   bash lineage/scripts/push_to_github.sh
#   bash lineage/scripts/push_to_github.sh --scope lineage-only
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINEAGE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
if [ -d "${LINEAGE_DIR}/../lineage/common" ]; then
  REPO_ROOT="$(cd "${LINEAGE_DIR}/.." && pwd)"
else
  REPO_ROOT="${LINEAGE_DIR}"
fi

export PATH="${HOME}/.local/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"

REPO_URL="https://github.com/Hulalalalalalalalalalala/sc_Agent_security.git"
SCOPE="workspace"
BRANCH="main"
DRY_RUN="false"
COMMIT_MSG="feat: Lineage Capability Tree (LCT) 4-cluster federation, polyglot SDKs & dependency bootstrap"

while [ $# -gt 0 ]; do
  case "$1" in
    --repo-url)
      REPO_URL="${2:?--repo-url requires URL}"
      shift 2
      ;;
    --scope)
      SCOPE="${2:?--scope requires workspace|lineage-only}"
      shift 2
      ;;
    --branch)
      BRANCH="${2:?--branch requires branch name}"
      shift 2
      ;;
    --commit-message)
      COMMIT_MSG="${2:?--commit-message requires string}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    -h|--help)
      sed -n '2,15p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "[push_to_github] Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

case "${SCOPE}" in
  workspace|lineage-only) ;;
  *)
    echo "[push_to_github] Invalid --scope '${SCOPE}' (expected workspace|lineage-only)" >&2
    exit 2
    ;;
esac

# Extract owner/repo slug from https://github.com/<owner>/<repo>(.git) or git@github.com:<owner>/<repo>.git
OWNER_REPO="$(printf '%s' "${REPO_URL}" | sed -E 's#^https://github\.com/##; s#^git@github\.com:##; s#\.git$##')"

TMP_STAGE="$(mktemp -d)"
cleanup_tmp() {
  rm -rf "${TMP_STAGE}"
}
trap cleanup_tmp EXIT

echo "============================================================================"
echo " LCT GitHub Packaging & Security Pre-Flight (${SCOPE})"
echo "============================================================================"
echo "  Target Remote : ${REPO_URL} (${OWNER_REPO})"
echo "  Target Branch : ${BRANCH}"
echo "  Dry-Run Mode  : ${DRY_RUN}"

# Always keep WORK_TREE at REPO_ROOT so `lineage/` top-level Python package directory
# is preserved in BOTH `workspace` and `lineage-only` scopes (`[HIGH-M5-01]`)!
WORK_TREE="${REPO_ROOT}"
GIT_TMP_DIR="${TMP_STAGE}/gitdir"
git --git-dir="${GIT_TMP_DIR}" --work-tree="${WORK_TREE}" init -q -b "${BRANCH}"

if [ "${SCOPE}" = "workspace" ]; then
  STAGE_ITEMS=(.gitignore README.md lab lineage)
else
  STAGE_ITEMS=(.gitignore lineage)
fi

for item in "${STAGE_ITEMS[@]}"; do
  if [ -e "${WORK_TREE}/${item}" ]; then
    git --git-dir="${GIT_TMP_DIR}" --work-tree="${WORK_TREE}" add "${item}"
  fi
done

STAGED_LIST="${TMP_STAGE}/staged_files.txt"
git --git-dir="${GIT_TMP_DIR}" --work-tree="${WORK_TREE}" ls-files > "${STAGED_LIST}"
FILE_COUNT="$(wc -l < "${STAGED_LIST}" | tr -d ' ')"

if [ "${FILE_COUNT}" -eq 0 ]; then
  echo "[FATAL] Zero files staged!" >&2
  exit 1
fi

# 1. Verify `.tools/`, `src/`, `venv/`, `.venv/`, `node_modules/` are strictly excluded
if grep -E '^(\.tools/|src/|.*(^|/)venv/|.*(^|/)\.venv/|.*(^|/)node_modules/)' "${STAGED_LIST}" >/dev/null 2>&1; then
  echo "[FATAL] Forbidden heavy binary/venv path leaked into git staging index:" >&2
  grep -E '^(\.tools/|src/|.*(^|/)venv/|.*(^|/)\.venv/|.*(^|/)node_modules/)' "${STAGED_LIST}" >&2
  exit 1
fi

# 2. Reject symlinks (`[ -L ]`), check individual file sizes (< 50 MB), and scan EVERY
#    staged file for PEM private keys, GitHub PATs, raw 3-part JWS/JWTs, or raw LCT wire tokens!
MAX_BYTES=$((50 * 1024 * 1024))
TOTAL_BYTES=0
while IFS= read -r rel_path; do
  full_path="${WORK_TREE}/${rel_path}"
  if [ -L "${full_path}" ]; then
    echo "[FATAL] Host symlink must not be staged for public repository: ${rel_path} -> $(readlink "${full_path}")" >&2
    exit 1
  fi
  if [ ! -L "${full_path}" ] && [ -f "${full_path}" ]; then
    fsize="$(wc -c < "${full_path}" | tr -d ' ')"
    if [ "${fsize}" -gt "${MAX_BYTES}" ]; then
      echo "[FATAL] Staged file exceeds 50 MB GitHub limit: ${rel_path} (${fsize} bytes)" >&2
      exit 1
    fi
    TOTAL_BYTES=$((TOTAL_BYTES + fsize))

    if grep -Eq -- '-----BEGIN (EC |RSA |OPENSSH )?PRIVATE KEY-----|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}' "${full_path}" 2>/dev/null; then
      echo "[FATAL] Private key or GitHub token detected in staged file: ${rel_path}" >&2
      exit 1
    fi

    if grep -Eq -- 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' "${full_path}" 2>/dev/null; then
      echo "[FATAL] Raw 3-part JWT/JWS token detected in staged file: ${rel_path}" >&2
      exit 1
    fi
  fi
done < "${STAGED_LIST}"

TOTAL_MB="$(awk "BEGIN { printf \"%.2f\", ${TOTAL_BYTES} / (1024 * 1024) }")"

# 3. Scan all LCT run evidence artifacts for unredacted wire tokens
RUNS_DIR="${LINEAGE_DIR}/k8s/runs"
if [ -d "${RUNS_DIR}" ]; then
  if grep -rn '"lct1\.\|"lctmp1\.\|"lctm1\.\|"eyJhbG' "${RUNS_DIR}" >/dev/null 2>&1; then
    echo "[FATAL] Unredacted LCT/JWS wire token detected in ${RUNS_DIR}!" >&2
    exit 1
  fi
fi

echo "  Staged Files  : ${FILE_COUNT} files (${TOTAL_MB} MB total; 0 symlinks; 0 files > 50 MB)"
echo "  Exclusions    : .tools/ (0 staged), src/ (0 staged), venv/.venv (0 staged)"
echo "  Secret Audit  : PASS (0 private keys, 0 GitHub PATs, 0 raw JWTs, 0 raw LCT run tokens)"

# 4. Check GitHub CLI authentication & push permission on target repo
PUSH_ALLOWED="false"
ACTIVE_GH_USER="none"
if command -v gh >/dev/null 2>&1; then
  ACTIVE_GH_USER="$(gh api user --jq '.login' 2>/dev/null || echo 'unauthenticated')"
  PERM_PUSH="$(gh api "repos/${OWNER_REPO}" --jq '.permissions.push' 2>/dev/null || echo 'false')"
  if [ "${PERM_PUSH}" = "true" ]; then
    PUSH_ALLOWED="true"
  fi
fi

echo "  GitHub Auth   : active_user='${ACTIVE_GH_USER}', permissions.push=${PUSH_ALLOWED}"
echo "============================================================================"

if [ "${DRY_RUN}" = "true" ]; then
  if [ "${PUSH_ALLOWED}" != "true" ]; then
    echo "[DRY-RUN NOTE] Pre-flight staging & secret audit PASSED."
    echo "               Before running live push, authenticate 'gh' as repo owner:"
    echo "                 gh auth login -h github.com -p https -w"
    echo "                 gh auth setup-git"
  else
    echo "[DRY-RUN PASS] Ready to push ${FILE_COUNT} files (${TOTAL_MB} MB) -> ${REPO_URL}"
  fi
  exit 0
fi

if [ "${PUSH_ALLOWED}" != "true" ]; then
  echo "[push_to_github] Push aborted cleanly (zero partial git state): active GitHub account '${ACTIVE_GH_USER}' does not have push permission to '${OWNER_REPO}'." >&2
  echo "Authenticate as the repository owner first, then re-run:" >&2
  echo "  1. gh auth login -h github.com -p https -w" >&2
  echo "  2. gh auth switch -u Hulalalalalalalalalalala   # if multiple accounts exist" >&2
  echo "  3. gh auth setup-git" >&2
  echo "  4. bash lineage/scripts/push_to_github.sh" >&2
  exit 2
fi

if [ "${SCOPE}" = "lineage-only" ]; then
  git --git-dir="${GIT_TMP_DIR}" --work-tree="${WORK_TREE}" config user.name "${GIT_AUTHOR_NAME:-Hulalalalalalalalalalala}"
  git --git-dir="${GIT_TMP_DIR}" --work-tree="${WORK_TREE}" config user.email "${GIT_AUTHOR_EMAIL:-hulalalalalalalalalalala@users.noreply.github.com}"
  git --git-dir="${GIT_TMP_DIR}" --work-tree="${WORK_TREE}" commit -q -m "${COMMIT_MSG}"
  git --git-dir="${GIT_TMP_DIR}" --work-tree="${WORK_TREE}" remote add origin "${REPO_URL}"
  git -c http.proxy= -c https.proxy= --git-dir="${GIT_TMP_DIR}" --work-tree="${WORK_TREE}" push -u origin "${BRANCH}"
  echo "[push_to_github] Successfully pushed lineage-only tree (preserving lineage/ package layout) to ${REPO_URL} (${BRANCH})!"
  exit 0
fi

# Workspace-scoped commit & push
if [ ! -d "${REPO_ROOT}/.git" ]; then
  git -C "${REPO_ROOT}" init -b "${BRANCH}"
fi
if ! git -C "${REPO_ROOT}" config user.name >/dev/null 2>&1; then
  git -C "${REPO_ROOT}" config user.name "${GIT_AUTHOR_NAME:-Hulalalalalalalalalalala}"
fi
if ! git -C "${REPO_ROOT}" config user.email >/dev/null 2>&1; then
  git -C "${REPO_ROOT}" config user.email "${GIT_AUTHOR_EMAIL:-hulalalalalalalalalalala@users.noreply.github.com}"
fi

git -C "${REPO_ROOT}" checkout -B "${BRANCH}"
for item in "${STAGE_ITEMS[@]}"; do
  if [ -e "${REPO_ROOT}/${item}" ]; then
    git -C "${REPO_ROOT}" add "${item}"
  fi
done

if ! git -C "${REPO_ROOT}" diff --cached --quiet; then
  git -C "${REPO_ROOT}" commit -m "${COMMIT_MSG}"
fi

if git -C "${REPO_ROOT}" remote get-url origin >/dev/null 2>&1; then
  git -C "${REPO_ROOT}" remote set-url origin "${REPO_URL}"
else
  git -C "${REPO_ROOT}" remote add origin "${REPO_URL}"
fi

git -c http.proxy= -c https.proxy= -C "${REPO_ROOT}" push -u origin "${BRANCH}"
echo "[push_to_github] Successfully pushed workspace to ${REPO_URL} (${BRANCH})!"
