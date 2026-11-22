#!/usr/bin/env bash
# Continuous exchange and same-T2 calls from two service accounts.
# Does not print tokens, JWT-SVIDs, or passwords.
set -euo pipefail
CTX="${CTX:-kind-agent-identity-lab}"
export PATH="/Users/hulalala/Desktop/A/.tools/bin:${HOME}/.docker/bin:${PATH}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
BPOD="$(kubectl --context "$CTX" -n rossoctl-system get pod -l app.kubernetes.io/name=rossoctl-backend -o jsonpath='{.items[0].metadata.name}')"
BPOD_SA="$(kubectl --context "$CTX" -n rossoctl-system get pod "$BPOD" -o jsonpath='{.spec.serviceAccountName}')"
TOOL_IP="$(kubectl --context "$CTX" -n team1 get pod -l app.kubernetes.io/name=weather-tool-advanced -o jsonpath='{.items[0].status.podIP}')"
B_SA="$(kubectl --context "$CTX" -n team1 get pod -l app.kubernetes.io/name=weather-service-advanced -o jsonpath='{.items[0].spec.serviceAccountName}')"
echo "START_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "backend_pod=$BPOD backend_sa=$BPOD_SA weather_agent_sa=$B_SA tool_ip=$TOOL_IP"

copy_svid() {
  local deploy="$1"
  local dest="$2"
  local tmp
  tmp="$(mktemp)"
  chmod 600 "$tmp"
  kubectl --context "$CTX" -n team1 exec "deploy/$deploy" -c authbridge-proxy -- cat /opt/jwt_svid.token > "$tmp"
  kubectl --context "$CTX" -n rossoctl-system exec -i "$BPOD" -c backend -- sh -c "cat > ${dest} && chmod 600 ${dest}" < "$tmp"
  rm -f "$tmp"
}
copy_svid weather-coordinator /tmp/jwt-a
copy_svid weather-service-advanced /tmp/jwt-b
kubectl --context "$CTX" -n rossoctl-system cp "$ROOT/exchange_chain.py" "$BPOD:/tmp/exchange_chain.py" -c backend
kubectl --context "$CTX" -n rossoctl-system cp "$ROOT/mcp_with_token.py" "$BPOD:/tmp/mcp_with_token.py" -c backend
kubectl --context "$CTX" -n team1 exec -i deploy/weather-service-advanced -c agent -- sh -c 'cat > /tmp/mcp_with_token.py' < "$ROOT/mcp_with_token.py"

run_one() {
  local run_id="$1"
  local user="$2"
  local pass_file="$3"
  echo "RUN_BEGIN $run_id $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- env \
    RUN_ID="$run_id" LAB_USER="$user" PASS_FILE="$pass_file" \
    /app/.venv/bin/python3 /tmp/exchange_chain.py
  local call_since
  call_since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "CALLS_FROM_BACKEND $run_id $call_since"
  kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- env \
    RUN_ID="$run_id" CALLER="rossoctl-backend" TOKEN_MODE="file" TOKEN_FILE="/tmp/holder-t2" \
    MCP_URL="http://weather-tool-advanced-mcp.team1.svc:8000/mcp" \
    /app/.venv/bin/python3 /tmp/mcp_with_token.py
  kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- env \
    RUN_ID="$run_id" CALLER="rossoctl-backend-notoken" TOKEN_MODE="none" \
    MCP_URL="http://weather-tool-advanced-mcp.team1.svc:8000/mcp" \
    /app/.venv/bin/python3 /tmp/mcp_with_token.py
  kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- env \
    RUN_ID="$run_id" CALLER="rossoctl-backend-t0" TOKEN_MODE="file" TOKEN_FILE="/tmp/holder-t0" \
    MCP_URL="http://weather-tool-advanced-mcp.team1.svc:8000/mcp" \
    /app/.venv/bin/python3 /tmp/mcp_with_token.py
  local tmp
  tmp="$(mktemp)"
  chmod 600 "$tmp"
  kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- cat /tmp/holder-t2 > "$tmp"
  kubectl --context "$CTX" -n team1 exec -i deploy/weather-service-advanced -c agent -- sh -c 'cat > /tmp/holder-t2 && chmod 600 /tmp/holder-t2' < "$tmp"
  rm -f "$tmp"
  echo "CALLS_FROM_B $run_id $(date -u +%Y-%m-%dT%H:%M:%SZ) target=http://${TOOL_IP}:8000/mcp proxy=disabled"
  kubectl --context "$CTX" -n team1 exec deploy/weather-service-advanced -c agent -- env \
    -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
    RUN_ID="$run_id" CALLER="weather-agent" TOKEN_MODE="file" TOKEN_FILE="/tmp/holder-t2" \
    MCP_URL="http://${TOOL_IP}:8000/mcp" \
    /app/.venv/bin/python3 /tmp/mcp_with_token.py
  echo "RUN_END $run_id $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "=== B sidecar during $run_id ==="
  kubectl --context "$CTX" -n team1 logs deploy/weather-service-advanced -c authbridge-proxy --since-time="$call_since" \
    | awk 'length($0)<360 && $0 !~ /eyJ/ && $0 ~ /exchanged|passthrough|rejected|authorized/ {print}' || true
  echo "=== tool auth during $run_id ==="
  kubectl --context "$CTX" -n team1 logs deploy/weather-tool-advanced -c authbridge-proxy --since-time="$call_since" \
    | awk 'length($0)<420 && $0 !~ /eyJ/ && $0 ~ /authorized|rejected|signature|audience|missing/ {print}' || true
}

run_one ny-1 lab-ny /tmp/lab-ny.pass
run_one lon-1 lab-lon /tmp/lab-lon.pass
run_one ny-2 lab-ny /tmp/lab-ny.pass

kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- rm -f /tmp/jwt-a /tmp/jwt-b /tmp/holder-t0 /tmp/holder-t2 /tmp/holder-fp /tmp/exchange_chain.py /tmp/mcp_with_token.py
kubectl --context "$CTX" -n team1 exec deploy/weather-service-advanced -c agent -- rm -f /tmp/holder-t2 /tmp/mcp_with_token.py
echo "CLEANED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
