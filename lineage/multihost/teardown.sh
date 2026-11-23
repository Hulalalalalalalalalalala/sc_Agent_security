#!/usr/bin/env bash
# =============================================================================
# LCT Multi-Host Safe Teardown (`lineage/multihost/teardown.sh`)
#
# Deletes ONLY `lctmh-*` Kind clusters on the current machine (`lctmh-alpha`,
# `lctmh-beta`, `lctmh-pay`, `lctmh-audit`, or `--roles <csv>`).
# Never touches `agent-identity-lab`, `lct-org-*`, `lct-audit`, or any other
# Docker containers/images, and restores `kubectl` current-context cleanly.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINEAGE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${LINEAGE_DIR}/.." && pwd)"

export PATH="${REPO_ROOT}/.tools/bin:${HOME}/.local/bin:${HOME}/.docker/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"

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

for r in $(echo "${ROLES_FILTER}" | tr ',' ' '); do
  case "${r}" in
    alpha|beta|pay|audit)
      cname="lctmh-${r}"
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

if kubectl config get-contexts -o name 2>/dev/null | grep -qx "kind-agent-identity-lab"; then
  kubectl config use-context "kind-agent-identity-lab" >/dev/null 2>&1 || true
elif [[ -n "${ORIG_CTX}" && "${ORIG_CTX}" != kind-lctmh-* ]] && kubectl config get-contexts -o name 2>/dev/null | grep -qx "${ORIG_CTX}"; then
  kubectl config use-context "${ORIG_CTX}" >/dev/null 2>&1 || true
fi

echo "[teardown] Completed. Active lctmh-* containers remaining: $(docker ps -a --format '{{.Names}}' | grep -c '^lctmh-' || true)"
