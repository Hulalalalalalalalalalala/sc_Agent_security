#!/usr/bin/env bash
# Non-destructive cleanup of ONLY `lineage-*` Kubernetes namespaces inside `kind-agent-identity-lab`.
# Strictly preserves all existing namespaces (`team1`, `team2`, `keycloak`, `rossoctl-system`, `spire-*`, etc.).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINEAGE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
if [ -d "${LINEAGE_DIR}/../lineage/common" ]; then
  REPO_ROOT="$(cd "${LINEAGE_DIR}/.." && pwd)"
else
  REPO_ROOT="${LINEAGE_DIR}"
fi
export PATH="${HOME}/.local/bin:${REPO_ROOT}/.tools/bin:${LINEAGE_DIR}/.tools/bin:${HOME}/.docker/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"
KUBE_CTX="${KUBE_CTX:-kind-agent-identity-lab}"
KIND_NAME="${KIND_NAME:-agent-identity-lab}"

if docker inspect "${KIND_NAME}-control-plane" >/dev/null 2>&1; then
  if ! docker inspect -f '{{.State.Running}}' "${KIND_NAME}-control-plane" 2>/dev/null | grep -q true; then
    echo "[cleanup] Starting stopped baseline container '${KIND_NAME}-control-plane'..."
    docker start "${KIND_NAME}-control-plane" >/dev/null
  fi
  for _ in $(seq 1 90); do
    if kubectl --context "${KUBE_CTX}" get --raw=/readyz >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  kubectl --context "${KUBE_CTX}" wait --for=condition=Ready node/"${KIND_NAME}-control-plane" --timeout=90s >/dev/null
  kubectl --context "${KUBE_CTX}" wait --for=condition=Ready pod --all -n team1 --timeout=120s >/dev/null
fi

kubectl config use-context "${KUBE_CTX}" >/dev/null 2>&1 || true

echo "[cleanup] Deleting ONLY LCT namespaces (lineage-pay, lineage-beta, lineage-alpha, lineage-ctrl)..."
kubectl --context "${KUBE_CTX}" delete namespace lineage-pay lineage-beta lineage-alpha lineage-ctrl --ignore-not-found=true --wait=true

echo "[cleanup] Verifying existing baseline namespace 'team1' remains untouched:"
kubectl --context "${KUBE_CTX}" get pods -n team1
echo "[cleanup] Done."
