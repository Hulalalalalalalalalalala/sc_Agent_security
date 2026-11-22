#!/usr/bin/env bash
# =============================================================================
# Non-Destructive Cleanup of ONLY Milestone 4 `lct-*` Kind Clusters
# Strictly preserves `kind-agent-identity-lab` (`team1`) and default kubeconfig context!
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINEAGE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
if [ -d "${LINEAGE_DIR}/../lineage/common" ]; then
  REPO_ROOT="$(cd "${LINEAGE_DIR}/.." && pwd)"
else
  REPO_ROOT="${LINEAGE_DIR}"
fi
export PATH="${HOME}/.local/bin:${REPO_ROOT}/.tools/bin:${LINEAGE_DIR}/.tools/bin:${HOME}/.docker/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"
BASELINE_CTX="kind-agent-identity-lab"

for cname in lct-org-alpha lct-org-beta lct-org-pay lct-audit; do
  if kind get clusters 2>/dev/null | grep -qx "${cname}"; then
    echo "[cleanup-multicluster] Deleting Kind cluster '${cname}'..."
    kind delete cluster --name "${cname}"
  fi
done

if docker inspect agent-identity-lab-control-plane >/dev/null 2>&1; then
  if ! docker inspect -f '{{.State.Running}}' agent-identity-lab-control-plane 2>/dev/null | grep -q true; then
    echo "[cleanup-multicluster] Starting stopped baseline container 'agent-identity-lab-control-plane'..."
    docker start agent-identity-lab-control-plane >/dev/null
  fi
  for _ in $(seq 1 90); do
    if kubectl --context "${BASELINE_CTX}" get --raw=/readyz >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  kubectl --context "${BASELINE_CTX}" wait --for=condition=Ready node/agent-identity-lab-control-plane --timeout=90s >/dev/null
  kubectl --context "${BASELINE_CTX}" wait --for=condition=Ready pod --all -n team1 --timeout=120s >/dev/null

  kubectl config use-context "${BASELINE_CTX}" >/dev/null 2>&1 || true
  echo "[cleanup-multicluster] Restored active kubectl context to '${BASELINE_CTX}'."
  echo "[cleanup-multicluster] Verifying baseline 'team1' in '${BASELINE_CTX}':"
  kubectl --context "${BASELINE_CTX}" get pods -n team1
fi
echo "[cleanup-multicluster] Done."
