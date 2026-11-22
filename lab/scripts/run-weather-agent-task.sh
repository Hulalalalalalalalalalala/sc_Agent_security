#!/usr/bin/env bash
# Submit one A2A task to the real Weather Agent from inside the cluster.
# Prints statuses and redacted response text only.
set -euo pipefail
CTX="${CTX:-kind-agent-identity-lab}"
NS="${NS:-rossoctl-system}"
RUN_ID="${RUN_ID:-wx-$(date -u +%Y%m%dT%H%M%SZ)}"
PROMPT="${AGENT_PROMPT:-请调用天气工具查询纽约当前天气，并根据工具返回的数据回答。}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BPOD="$(kubectl --context "$CTX" -n "$NS" get pod -l app.kubernetes.io/name=rossoctl-backend -o jsonpath='{.items[0].metadata.name}')"
echo "SUBMIT_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ) RUN_ID=$RUN_ID backend=$BPOD"
kubectl --context "$CTX" -n "$NS" cp "$ROOT/lab/scripts/run_agent_task.py" "$BPOD:/tmp/run_agent_task.py" -c backend
kubectl --context "$CTX" -n "$NS" exec "$BPOD" -c backend -- env \
  RUN_ID="$RUN_ID" \
  AGENT_PROMPT="$PROMPT" \
  AGENT_URL="${AGENT_URL:-http://weather-service-advanced.team1.svc:8080/}" \
  KC_CLIENT="${KC_CLIENT:-weather-advanced-e2e}" \
  KC_USERNAME="${KC_USERNAME:-alice}" \
  KC_PASSWORD_FILE="${KC_PASSWORD_FILE:-}" \
  /app/.venv/bin/python3 /tmp/run_agent_task.py
echo "DONE_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
