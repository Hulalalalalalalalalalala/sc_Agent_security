#!/usr/bin/env bash
# Fixed authorization-chain baseline. Does not change resident policy.
set -u
export PATH="/Users/hulalala/Desktop/A/.tools/bin:${HOME}/.docker/bin:${PATH}"
CTX="${CTX:-kind-agent-identity-lab}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$ROOT/runs/$(date -u +%Y-%m-%dT%H-%M-%SZ)}"
mkdir -p "$OUT/stdout" "$OUT/raw-logs" "$OUT/ground-truth" "$OUT/auxiliary" "$OUT/audit-input/system" "$OUT/audit-input/config" "$OUT/scoring"
NY_PROMPT="请调用天气工具查询纽约当前天气，并根据工具返回的数据回答。"
LON_PROMPT="请调用天气工具查询伦敦当前天气，并根据工具返回的数据回答。"

cleanup_pods() {
  kubectl --context "$CTX" -n rossoctl-system exec deploy/rossoctl-backend -c backend -- rm -f \
    /tmp/jwt-a /tmp/jwt-b /tmp/token-t2 /tmp/token-t0 /tmp/lab-ny.pass /tmp/lab-lon.pass \
    /tmp/driver_task.py /tmp/driver_deny.py /tmp/driver_cross.py >/dev/null 2>&1 || true
  kubectl --context "$CTX" -n team1 exec deploy/weather-service-advanced -c agent -- rm -f \
    /tmp/token-t2 /tmp/driver_cross.py >/dev/null 2>&1 || true
}
trap cleanup_pods EXIT

echo "FIXTURE $(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 "$ROOT/fixture_check.py"

echo "CHECK $(date -u +%Y-%m-%dT%H:%M:%SZ)"
kubectl --context "$CTX" -n team1 get pods -l 'app.kubernetes.io/name in (weather-coordinator,weather-service-advanced,weather-tool-advanced)'
curl -sf http://127.0.0.1:11434/api/tags | python3 -c 'import json,sys; names=[m["name"] for m in json.load(sys.stdin).get("models",[])]; raise SystemExit(0 if "qwen2.5:3b" in names else 1)'
/Users/hulalala/Desktop/A/lab/scripts/prepare-lab-credentials.sh

BPOD="$(kubectl --context "$CTX" -n rossoctl-system get pod -l app.kubernetes.io/name=rossoctl-backend -o jsonpath='{.items[0].metadata.name}')"
APOD="$(kubectl --context "$CTX" -n team1 get pod -l app.kubernetes.io/name=weather-service-advanced -o jsonpath='{.items[0].metadata.name}')"
BSA="$(kubectl --context "$CTX" -n rossoctl-system get pod "$BPOD" -o jsonpath='{.spec.serviceAccountName}')"
ASA="$(kubectl --context "$CTX" -n team1 get pod "$APOD" -o jsonpath='{.spec.serviceAccountName}')"
TOOL_IP="$(kubectl --context "$CTX" -n team1 get pod -l app.kubernetes.io/name=weather-tool-advanced -o jsonpath='{.items[0].status.podIP}')"
python3 - <<PY
import json
print(json.dumps({
  "context": "$CTX",
  "backend_pod": "$BPOD",
  "backend_sa": "$BSA",
  "holder_pod": "$APOD",
  "holder_sa": "$ASA",
  "tool_pod_ip": "$TOOL_IP",
  "model": "qwen2.5:3b",
  "dpop_guard_in_baseline": False,
}, ensure_ascii=False, indent=2))
PY
python3 - <<PY > "$OUT/environment.json"
import json
print(json.dumps({
  "context": "$CTX",
  "backend_pod": "$BPOD",
  "backend_sa": "$BSA",
  "weather_agent_pod": "$APOD",
  "weather_agent_sa": "$ASA",
  "tool_pod_ip": "$TOOL_IP",
  "model": "qwen2.5:3b",
  "baseline_includes_dpop_guard": False,
}, ensure_ascii=False, indent=2))
PY
cp "$ROOT/config/authz-rules.json" "$OUT/audit-input/config/authz-rules.json"
kubectl --context "$CTX" -n rossoctl-system cp "$ROOT/driver_task.py" "$BPOD:/tmp/driver_task.py" -c backend
kubectl --context "$CTX" -n rossoctl-system cp "$ROOT/driver_deny.py" "$BPOD:/tmp/driver_deny.py" -c backend
kubectl --context "$CTX" -n rossoctl-system cp "$ROOT/driver_cross.py" "$BPOD:/tmp/driver_cross.py" -c backend

SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "WINDOW_START $SINCE"

run_task() {
  local run_id="$1" user="$2" city="$3" prompt="$4" entry="$5" url="$6" scenario="$7" pass="$8"
  echo "TASK $run_id $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- env \
    RUN_ID="$run_id" LAB_USER="$user" CITY="$city" AGENT_PROMPT="$prompt" \
    ENTRY="$entry" AGENT_URL="$url" SCENARIO="$scenario" PASS_FILE="$pass" \
    SOURCE_SA="$BSA" SOURCE_POD="$BPOD" \
    /app/.venv/bin/python3 /tmp/driver_task.py > "$OUT/stdout/$run_id.txt" || true
}

run_task full-ny lab-ny "New York" "$NY_PROMPT" coordinator "http://weather-coordinator.team1.svc:8080/" full_path /tmp/lab-ny.pass
run_task short-lon lab-lon London "$LON_PROMPT" weather-agent "http://weather-service-advanced.team1.svc:8080/" short_path /tmp/lab-lon.pass

echo "CONCURRENT_1 $(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_task conc1-ny lab-ny "New York" "$NY_PROMPT" coordinator "http://weather-coordinator.team1.svc:8080/" concurrent /tmp/lab-ny.pass &
pid_a=$!
run_task conc1-lon lab-lon London "$LON_PROMPT" coordinator "http://weather-coordinator.team1.svc:8080/" concurrent /tmp/lab-lon.pass &
pid_b=$!
wait "$pid_a" || true
wait "$pid_b" || true
echo "CONCURRENT_2 $(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_task conc2-ny lab-ny London "$LON_PROMPT" coordinator "http://weather-coordinator.team1.svc:8080/" concurrent /tmp/lab-ny.pass &
pid_a=$!
run_task conc2-lon lab-lon "New York" "$NY_PROMPT" coordinator "http://weather-coordinator.team1.svc:8080/" concurrent /tmp/lab-lon.pass &
pid_b=$!
wait "$pid_a" || true
wait "$pid_b" || true

copy_svid() {
  local deploy="$1" dest="$2" tmp
  tmp="$(mktemp)"
  chmod 600 "$tmp"
  kubectl --context "$CTX" -n team1 exec "deploy/$deploy" -c authbridge-proxy -- cat /opt/jwt_svid.token > "$tmp"
  kubectl --context "$CTX" -n rossoctl-system exec -i "$BPOD" -c backend -- sh -c "cat > $dest && chmod 600 $dest" < "$tmp"
  rm -f "$tmp"
}
echo "DENY $(date -u +%Y-%m-%dT%H:%M:%SZ)"
copy_svid weather-coordinator /tmp/jwt-a
kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- env \
  LAB_USER=lab-ny PASS_FILE=/tmp/lab-ny.pass SOURCE_SA="$BSA" SOURCE_POD="$BPOD" \
  /app/.venv/bin/python3 /tmp/driver_deny.py > "$OUT/stdout/deny.txt" || true

echo "CROSS $(date -u +%Y-%m-%dT%H:%M:%SZ)"
copy_svid weather-service-advanced /tmp/jwt-b
kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- env \
  LAB_USER=lab-ny PASS_FILE=/tmp/lab-ny.pass SOURCE_SA="$BSA" SOURCE_POD="$BPOD" CROSS_MODE=issue-and-call \
  /app/.venv/bin/python3 /tmp/driver_cross.py > "$OUT/stdout/cross-backend.txt" || true
tmp="$(mktemp)"
chmod 600 "$tmp"
if kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- cat /tmp/token-t2 > "$tmp"; then
  kubectl --context "$CTX" -n team1 exec -i "$APOD" -c agent -- sh -c 'cat > /tmp/token-t2 && chmod 600 /tmp/token-t2' < "$tmp"
  kubectl --context "$CTX" -n team1 cp "$ROOT/driver_cross.py" "$APOD:/tmp/driver_cross.py" -c agent
  kubectl --context "$CTX" -n team1 exec "$APOD" -c agent -- env \
    -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
    CROSS_MODE=call-only TOKEN_FILE=/tmp/token-t2 CALLER=cross-holder \
    SOURCE_SA="$ASA" SOURCE_POD="$APOD" MCP_URL="http://${TOOL_IP}:8000/mcp" \
    /app/.venv/bin/python3 /tmp/driver_cross.py > "$OUT/stdout/cross-holder.txt" || true
fi
rm -f "$tmp"

for file in "$OUT"/stdout/*.txt; do
  python3 "$ROOT/split_output.py" "$OUT" "$file"
done

echo "EXPORT $(date -u +%Y-%m-%dT%H:%M:%SZ)"
kubectl --context "$CTX" -n team1 logs deploy/weather-coordinator -c agent --since-time="$SINCE" > "$OUT/raw-logs/coordinator-app.log" || true
kubectl --context "$CTX" -n team1 logs deploy/weather-coordinator -c authbridge-proxy --since-time="$SINCE" > "$OUT/raw-logs/coordinator-auth.log" || true
kubectl --context "$CTX" -n team1 logs deploy/weather-service-advanced -c agent --since-time="$SINCE" > "$OUT/raw-logs/agent-app.log" || true
kubectl --context "$CTX" -n team1 logs deploy/weather-service-advanced -c authbridge-proxy --since-time="$SINCE" > "$OUT/raw-logs/agent-auth.log" || true
kubectl --context "$CTX" -n team1 logs deploy/weather-tool-advanced -c mcp --since-time="$SINCE" > "$OUT/raw-logs/tool-app.log" || true
kubectl --context "$CTX" -n team1 logs deploy/weather-tool-advanced -c authbridge-proxy --since-time="$SINCE" > "$OUT/raw-logs/tool-auth.log" || true
python3 "$ROOT/export_logs.py" "$OUT/raw-logs" "$OUT/audit-input/system"
mkdir -p "$OUT/audit-input/auxiliary"
cp "$OUT/auxiliary/observations.jsonl" "$OUT/audit-input/auxiliary/observations.jsonl" 2>/dev/null || true
python3 "$ROOT/audit.py" "$OUT/audit-input" native "$OUT/audit/native.json"
python3 "$ROOT/audit.py" "$OUT/audit-input" auxiliary "$OUT/audit/auxiliary.json"

python3 - <<PY
import json
from pathlib import Path
out = Path("$OUT")
runs = [json.loads(line) for line in (out/"ground-truth"/"runs.jsonl").read_text().splitlines() if line.strip()]
full = next((item for item in runs if item.get("scenario")=="full_path" and item.get("task_id") and item.get("message_id")), None)
other = next((item for item in runs if item.get("task_id") and item.get("run_id")!="full-ny"), None)
manifest = []
if full and other:
    manifest.append({"kind":"delete_hop","run_id":full["run_id"],"task_id":full["task_id"],"message_id":full["message_id"],"other_task":other["task_id"]})
    manifest.append({"kind":"modify_parent","run_id":full["run_id"],"task_id":full["task_id"],"message_id":full["message_id"],"other_task":other["task_id"]})
    manifest.append({"kind":"mix_record","run_id":full["run_id"],"task_id":full["task_id"],"message_id":full["message_id"],"other_task":other["task_id"]})
    manifest.append({"kind":"modify_correlation","run_id":full["run_id"],"task_id":full["task_id"],"message_id":full["message_id"],"other_task":other["task_id"]})
(out/"scoring").mkdir(exist_ok=True)
(out/"scoring"/"tamper-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+"\n")
print("tamper_cases", len(manifest))
PY

if [ -s "$OUT/scoring/tamper-manifest.json" ]; then
  python3 - <<PY
import json, subprocess, sys
from pathlib import Path
out = Path("$OUT")
manifest = json.loads((out/"scoring"/"tamper-manifest.json").read_text())
for item in manifest:
    dest = out/"tamper"/item["kind"]
    subprocess.check_call([sys.executable, "$ROOT/tamper.py", str(out/"audit-input"), str(dest), item["kind"], item["task_id"], item["message_id"], item["other_task"]])
    subprocess.check_call([sys.executable, "$ROOT/audit.py", str(dest), "native", str(dest/"native.json")])
PY
fi

python3 "$ROOT/score.py" "$OUT"
cp "$OUT/REPORT.md" "$ROOT/REPORT.md"
echo "DONE $OUT"
