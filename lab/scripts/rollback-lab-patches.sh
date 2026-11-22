#!/usr/bin/env bash
# Roll this round's ConfigMap patches back to the previous sed-based success baseline.
set -euo pipefail
CTX="${CTX:-kind-agent-identity-lab}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
kubectl --context "$CTX" -n team1 patch deployment weather-tool-advanced --type=json -p '[
  {"op":"remove","path":"/spec/template/spec/containers/0/volumeMounts/2"},
  {"op":"remove","path":"/spec/template/spec/volumes/2"}
]' || true
kubectl --context "$CTX" -n team1 patch deployment weather-service-advanced --type=json -p '[
  {"op":"remove","path":"/spec/template/spec/containers/0/volumeMounts/2"},
  {"op":"remove","path":"/spec/template/spec/volumes/2"}
]' || true
kubectl --context "$CTX" -n team1 patch deployment weather-tool-advanced \
  --patch-file "$ROOT/lab/k8s/weather-tool-city-hint.patch.yaml"
kubectl --context "$CTX" -n team1 patch deployment weather-service-advanced \
  --patch-file "$ROOT/lab/k8s/weather-agent-answer-hint.patch.yaml"
kubectl --context "$CTX" -n team1 delete configmap lab-tool-patch lab-agent-patch --ignore-not-found
echo "rolled back to the city-hint and answer-hint commands"
