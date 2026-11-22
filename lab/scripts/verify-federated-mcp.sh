#!/usr/bin/env bash
# Federated-jwt exchange plus a direct MCP functional test.
# Does not print JWT-SVIDs, access tokens, or passwords.
set -euo pipefail
export PATH="/Users/hulalala/Desktop/A/.tools/bin:${HOME}/.docker/bin:${PATH}"
CTX=kind-agent-identity-lab
NS=team1
ROOT="/Users/hulalala/Desktop/A/lab/scripts"
MARKER="mcp-func-$(date +%s)"

APOD=$(kubectl --context "$CTX" -n "$NS" get pod -l app.kubernetes.io/name=weather-service-advanced -o jsonpath='{.items[0].metadata.name}')
BPOD=$(kubectl --context "$CTX" -n rossoctl-system get pod -l app.kubernetes.io/name=rossoctl-backend -o jsonpath='{.items[0].metadata.name}')

secret_bytes=$(kubectl --context "$CTX" -n "$NS" exec "$APOD" -c authbridge-proxy -- wc -c /shared/client-secret.txt | awk '{print $1}')
jwt_bytes=$(kubectl --context "$CTX" -n "$NS" exec "$APOD" -c authbridge-proxy -- wc -c /opt/jwt_svid.token | awk '{print $1}')
echo "client_secret_bytes=$secret_bytes jwt_svid_bytes=$jwt_bytes marker=$MARKER"
if [ "$secret_bytes" != "0" ] || [ "${jwt_bytes:-0}" -lt 100 ]; then
  echo "FAIL identity files are not a JWT-SVID without a client secret"
  exit 1
fi

tmp=$(mktemp)
trap 'rm -f "$tmp" /tmp/exchanged-token' EXIT
kubectl --context "$CTX" -n "$NS" exec "$APOD" -c authbridge-proxy -- cat /opt/jwt_svid.token > "$tmp"
kubectl --context "$CTX" -n "$NS" cp "$tmp" "$APOD":/tmp/jwt -c agent
rm -f "$tmp"
kubectl --context "$CTX" -n "$NS" cp "$ROOT/exchange_in_agent.py" "$APOD":/tmp/exchange_in_agent.py -c agent
kubectl --context "$CTX" -n "$NS" exec "$APOD" -c agent -- python3 /tmp/exchange_in_agent.py
kubectl --context "$CTX" -n "$NS" exec "$APOD" -c agent -- rm -f /tmp/exchange_in_agent.py /tmp/user-token

kubectl --context "$CTX" -n "$NS" cp "$APOD":/tmp/exchanged /tmp/exchanged-token -c agent
kubectl --context "$CTX" -n "$NS" exec "$APOD" -c agent -- rm -f /tmp/exchanged
kubectl --context "$CTX" -n rossoctl-system cp /tmp/exchanged-token "$BPOD":/tmp/exchanged -c backend
rm -f /tmp/exchanged-token
kubectl --context "$CTX" -n rossoctl-system cp "$ROOT/mcp_functional.py" "$BPOD":/tmp/mcp_functional.py -c backend
kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- \
  env MCP_MARKER="$MARKER" /app/.venv/bin/python3 /tmp/mcp_functional.py
kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- rm -f /tmp/mcp_functional.py /tmp/exchanged || true

echo "--- tool authbridge lines for $MARKER ---"
kubectl --context "$CTX" -n "$NS" logs deploy/weather-tool-advanced -c authbridge-proxy --since=3m \
  | awk -v m="$MARKER" 'length($0)<420 && $0 !~ /eyJ/ && ($0 ~ m || $0 ~ /jwt-validation|inbound authorized|tools\/call|get_weather/) {print}' \
  | tail -40
echo "VERIFY_DONE"
