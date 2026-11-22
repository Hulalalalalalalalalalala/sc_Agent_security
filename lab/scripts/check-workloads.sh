#!/usr/bin/env bash
# Show the platform and the three weather workloads.
set -euo pipefail
CTX="${CTX:-kind-agent-identity-lab}"
export PATH="/Users/hulalala/Desktop/A/.tools/bin:${HOME}/.docker/bin:${PATH}"
echo "=== team1 workloads ==="
kubectl --context "$CTX" -n team1 get pods -l 'app.kubernetes.io/name in (weather-coordinator,weather-service-advanced,weather-tool-advanced)' -o wide
echo "=== platform ==="
kubectl --context "$CTX" -n rossoctl-system get pods
kubectl --context "$CTX" -n keycloak get pods
echo "=== routes ==="
kubectl --context "$CTX" -n team1 get cm authproxy-routes -o jsonpath='{.data.routes\.yaml}{"\n"}'
