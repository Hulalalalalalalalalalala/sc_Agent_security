#!/usr/bin/env bash
# =============================================================================
# LCT Multi-Host Safe Teardown (`lineage/multihost/teardown.sh`)
#
# Deletes ONLY `lctmh-*` Kind clusters on the current machine (`lctmh-alpha`,
# `lctmh-beta`, `lctmh-pay`, `lctmh-audit`, or `--roles <csv>`), stops the
# host-side `locator-agent.py` daemon when no local `lctmh-*` clusters remain,
# never touches `agent-identity-lab`, `lct-org-*`, `lct-audit`, or any other
# Docker containers/images, and restores `kubectl` current-context cleanly.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINEAGE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${LINEAGE_DIR}/.." && pwd)"

export PATH="${REPO_ROOT}/.tools/bin:${HOME}/.local/bin:${HOME}/.docker/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"
export PYTHONPATH="${REPO_ROOT}:${PYTHONPATH:-}"

resolve_python() {
  if [[ -n "${LCT_PYTHON:-}" && -x "${LCT_PYTHON}" ]]; then
    echo "${LCT_PYTHON}"
    return
  fi
  for cand in \
    "${REPO_ROOT}/.venv/bin/python3" \
    "${REPO_ROOT}/src/cortex/authbridge/venv/bin/python3" \
    "$(command -v python3 2>/dev/null || true)"; do
    if [[ -n "${cand}" && -x "${cand}" ]]; then
      echo "${cand}"
      return
    fi
  done
  echo "python3"
}

ROLES_FILTER="alpha,beta,pay,audit"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --roles) ROLES_FILTER="${2:-}"; shift 2 ;;
    -h|--help)
      echo "Usage: bash lineage/multihost/teardown.sh [--roles alpha,beta,pay,audit]"
      exit 0
      ;;
    *) echo "ERROR: Unknown argument: $1" >&2; exit 2 ;;
  esac
done

ORIG_CTX="$(kubectl config current-context 2>/dev/null || true)"
PY_BIN="$(resolve_python)"

TORN_ROLES=()
for r in $(echo "${ROLES_FILTER}" | tr ',' ' '); do
  case "${r}" in
    alpha|beta|pay|audit)
      cname="lctmh-${r}"
      TORN_ROLES+=("${r}")
      if kind get clusters 2>/dev/null | grep -qx "${cname}"; then
        echo "[teardown] Deleting Kind cluster '${cname}'..."
        kind delete cluster --name "${cname}"
      else
        echo "[teardown] Kind cluster '${cname}' not present (skipped)."
      fi
      ;;
    all)
      for sub_r in alpha beta pay audit; do
        cname="lctmh-${sub_r}"
        TORN_ROLES+=("${sub_r}")
        if kind get clusters 2>/dev/null | grep -qx "${cname}"; then
          echo "[teardown] Deleting Kind cluster '${cname}'..."
          kind delete cluster --name "${cname}"
        fi
      done
      ;;
    *)
      echo "ERROR: Invalid role '${r}' in --roles" >&2
      exit 2
      ;;
  esac
done

REMAINING_LCTMH="$(kind get clusters 2>/dev/null | grep -c '^lctmh-' || true)"
if [[ "${REMAINING_LCTMH}" -eq 0 ]]; then
  echo "[teardown] Stopping host-side locator-agent daemon..."
  "${PY_BIN}" "${SCRIPT_DIR}/locator-agent.py" --stop >/dev/null 2>&1 || true
else
  for tr in ${TORN_ROLES[@]+"${TORN_ROLES[@]}"}; do
    "${PY_BIN}" "${SCRIPT_DIR}/locator-agent.py" --clear-role-ip --role "${tr}" >/dev/null 2>&1 || true
  done
fi

if kubectl config get-contexts -o name 2>/dev/null | grep -qx "kind-agent-identity-lab"; then
  kubectl config use-context "kind-agent-identity-lab" >/dev/null 2>&1 || true
elif [[ -n "${ORIG_CTX}" && "${ORIG_CTX}" != kind-lctmh-* ]] && kubectl config get-contexts -o name 2>/dev/null | grep -qx "${ORIG_CTX}"; then
  kubectl config use-context "${ORIG_CTX}" >/dev/null 2>&1 || true
fi

echo "[teardown] Completed. Active lctmh-* containers remaining: $(docker ps -a --format '{{.Names}}' | grep -c '^lctmh-' || true)"
