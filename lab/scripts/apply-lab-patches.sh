#!/usr/bin/env bash
# Apply the unit/timezone and task-correlation patches. Does not change auth.
set -euo pipefail
CTX="${CTX:-kind-agent-identity-lab}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
kubectl --context "$CTX" -n team1 create configmap lab-tool-patch \
  --from-file=patch_tool.py="$ROOT/lab/k8s/patch_tool.py" \
  --dry-run=client -o yaml | kubectl --context "$CTX" apply -f -
kubectl --context "$CTX" -n team1 create configmap lab-agent-patch \
  --from-file=patch_agent.py="$ROOT/lab/k8s/patch_agent.py" \
  --dry-run=client -o yaml | kubectl --context "$CTX" apply -f -
kubectl --context "$CTX" -n team1 patch deployment weather-tool-advanced \
  --patch-file "$ROOT/lab/k8s/weather-tool-lab.patch.yaml"
kubectl --context "$CTX" -n team1 patch deployment weather-service-advanced \
  --patch-file "$ROOT/lab/k8s/weather-agent-lab.patch.yaml"
kubectl --context "$CTX" -n team1 rollout status deployment/weather-tool-advanced --timeout=180s
kubectl --context "$CTX" -n team1 rollout status deployment/weather-service-advanced --timeout=180s
echo "lab patches applied"
