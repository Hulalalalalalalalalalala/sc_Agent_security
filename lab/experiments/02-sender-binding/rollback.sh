#!/usr/bin/env bash
# Remove only the resources and temporary files created by experiment 02.
set -euo pipefail
CTX="${CTX:-kind-agent-identity-lab}"
export PATH="/Users/hulalala/Desktop/A/.tools/bin:${HOME}/.docker/bin:${PATH}"
kubectl --context "$CTX" -n team1 delete pod dpop-guard --ignore-not-found
kubectl --context "$CTX" -n team1 delete svc dpop-guard --ignore-not-found
kubectl --context "$CTX" -n team1 delete sa dpop-guard --ignore-not-found
kubectl --context "$CTX" -n rossoctl-system exec deploy/rossoctl-backend -c backend -- rm -rf /tmp/dpop-vendor /tmp/probe_issue.py /tmp/mcp_call.py /tmp/jwt-a /tmp/jwt-b /tmp/token-bound /tmp/token-unbound /tmp/token-t0 /tmp/lab-ny.pass /tmp/lab-lon.pass || true
kubectl --context "$CTX" -n team1 exec deploy/weather-service-advanced -c agent -- rm -rf /tmp/dpop-vendor /tmp/holder_issue.py /tmp/mcp_call.py /tmp/jwt-a /tmp/jwt-b /tmp/holder-key.json /tmp/token-bound /tmp/token-unbound /tmp/token-t0 /tmp/lab-user.pass || true
echo "experiment 02 temporary resources removed"
