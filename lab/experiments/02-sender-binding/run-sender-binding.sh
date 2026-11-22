#!/usr/bin/env bash
# Controlled-client DPoP sender-binding experiment.
# Does not print tokens, private keys, JWT-SVIDs, or passwords.
set -euo pipefail
CTX="${CTX:-kind-agent-identity-lab}"
export PATH="/Users/hulalala/Desktop/A/.tools/bin:${HOME}/.docker/bin:${PATH}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
cleanup() {
  "$ROOT/rollback.sh" || true
}
trap cleanup EXIT

echo "START_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
/Users/hulalala/Desktop/A/lab/scripts/prepare-lab-credentials.sh >/tmp/dpop-prepare.txt
cat /tmp/dpop-prepare.txt
BPOD="$(kubectl --context "$CTX" -n rossoctl-system get pod -l app.kubernetes.io/name=rossoctl-backend -o jsonpath='{.items[0].metadata.name}')"
APOD="$(kubectl --context "$CTX" -n team1 get pod -l app.kubernetes.io/name=weather-service-advanced -o jsonpath='{.items[0].metadata.name}')"
BACKEND_SA="$(kubectl --context "$CTX" -n rossoctl-system get pod "$BPOD" -o jsonpath='{.spec.serviceAccountName}')"
AGENT_SA="$(kubectl --context "$CTX" -n team1 get pod -l app.kubernetes.io/name=weather-service-advanced -o jsonpath='{.items[0].spec.serviceAccountName}')"
echo "backend_pod=$BPOD backend_sa=$BACKEND_SA holder_pod_sa=$AGENT_SA"

kubectl --context "$CTX" -n team1 delete pod dpop-guard --ignore-not-found >/dev/null
kubectl --context "$CTX" -n team1 delete svc dpop-guard --ignore-not-found >/dev/null
kubectl --context "$CTX" -n team1 apply -f - <<'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: dpop-guard
  namespace: team1
---
apiVersion: v1
kind: Service
metadata:
  name: dpop-guard
  namespace: team1
spec:
  selector:
    app: dpop-guard
  ports:
  - name: http
    port: 8080
    targetPort: 8080
---
apiVersion: v1
kind: Pod
metadata:
  name: dpop-guard
  namespace: team1
  labels:
    app: dpop-guard
    rossoctl.io/inject: disabled
spec:
  serviceAccountName: dpop-guard
  restartPolicy: Never
  containers:
  - name: guard
    image: ghcr.io/rossoctl/rossoctl/backend:v0.8.0
    imagePullPolicy: IfNotPresent
    command: ["sleep", "1800"]
EOF
kubectl --context "$CTX" -n team1 wait --for=condition=Ready pod/dpop-guard --timeout=90s
GUARD_SA="$(kubectl --context "$CTX" -n team1 get pod dpop-guard -o jsonpath='{.spec.serviceAccountName}')"
echo "guard_sa=$GUARD_SA"
kubectl --context "$CTX" -n team1 exec dpop-guard -- mkdir -p /tmp/dpop-lab
kubectl --context "$CTX" -n team1 cp "$ROOT/vendor/pydpop" dpop-guard:/tmp/dpop-lab/pydpop
kubectl --context "$CTX" -n team1 cp "$ROOT/guard.py" dpop-guard:/tmp/dpop-lab/guard.py
kubectl --context "$CTX" -n team1 exec dpop-guard -- /app/.venv/bin/python3 -c 'import os, subprocess; env=os.environ.copy(); env["PYTHONPATH"]="/tmp/dpop-lab"; log=open("/tmp/guard.log","ab",buffering=0); subprocess.Popen(["/app/.venv/bin/python3","/tmp/dpop-lab/guard.py"], cwd="/tmp/dpop-lab", env=env, stdout=log, stderr=log, start_new_session=True)'
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- /app/.venv/bin/python3 -c 'import urllib.request; print(urllib.request.urlopen("http://dpop-guard.team1.svc:8080/health", timeout=3).status)'; then
    break
  fi
  sleep 1
done

copy_svid() {
  local deploy="$1"
  local dest="$2"
  local tmp
  tmp="$(mktemp)"
  chmod 600 "$tmp"
  kubectl --context "$CTX" -n team1 exec "deploy/$deploy" -c authbridge-proxy -- cat /opt/jwt_svid.token > "$tmp"
  kubectl --context "$CTX" -n team1 exec -i "$APOD" -c agent -- sh -c "cat > $dest && chmod 600 $dest" < "$tmp"
  rm -f "$tmp"
}
copy_svid weather-coordinator /tmp/jwt-a
copy_svid weather-service-advanced /tmp/jwt-b
kubectl --context "$CTX" -n team1 exec "$APOD" -c agent -- mkdir -p /tmp/dpop-vendor
kubectl --context "$CTX" -n team1 cp "$ROOT/vendor/pydpop" "$APOD":/tmp/dpop-vendor/pydpop -c agent
kubectl --context "$CTX" -n team1 cp "$ROOT/holder_issue.py" "$APOD":/tmp/holder_issue.py -c agent
kubectl --context "$CTX" -n team1 cp "$ROOT/mcp_call.py" "$APOD":/tmp/mcp_call.py -c agent
kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- mkdir -p /tmp/dpop-vendor
kubectl --context "$CTX" -n rossoctl-system cp "$ROOT/vendor/pydpop" "$BPOD:/tmp/dpop-vendor/pydpop" -c backend
kubectl --context "$CTX" -n rossoctl-system cp "$ROOT/mcp_call.py" "$BPOD:/tmp/mcp_call.py" -c backend

copy_token() {
  local name="$1"
  local tmp
  tmp="$(mktemp)"
  chmod 600 "$tmp"
  kubectl --context "$CTX" -n team1 exec "$APOD" -c agent -- cat "/tmp/$name" > "$tmp"
  kubectl --context "$CTX" -n rossoctl-system exec -i "$BPOD" -c backend -- sh -c "cat > /tmp/$name && chmod 600 /tmp/$name" < "$tmp"
  rm -f "$tmp"
}

run_case() {
  local where="$1"
  shift
  if [ "$where" = agent ]; then
    kubectl --context "$CTX" -n team1 exec "$APOD" -c agent -- env \
      -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy "$@" \
      /app/.venv/bin/python3 /tmp/mcp_call.py
  else
    kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- env "$@" \
      /app/.venv/bin/python3 /tmp/mcp_call.py
  fi
}

run_one() {
  local run_id="$1"
  local user="$2"
  local pass_file="$3"
  local since
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "RUN_BEGIN $run_id $since user=$user"
  local ptmp
  ptmp="$(mktemp)"
  chmod 600 "$ptmp"
  kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- cat "$pass_file" > "$ptmp"
  kubectl --context "$CTX" -n team1 exec -i "$APOD" -c agent -- sh -c 'cat > /tmp/lab-user.pass && chmod 600 /tmp/lab-user.pass' < "$ptmp"
  rm -f "$ptmp"
  kubectl --context "$CTX" -n team1 exec "$APOD" -c agent -- env \
    -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
    RUN_ID="$run_id" LAB_USER="$user" PASS_FILE=/tmp/lab-user.pass \
    /app/.venv/bin/python3 /tmp/holder_issue.py
  copy_token token-bound
  copy_token token-unbound
  copy_token token-t0
  echo "CALLS $run_id $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  run_case agent RUN_ID="$run_id" CALLER=holder-b PROOF_MODE=holder KEY_FILE=/tmp/holder-key.json TOKEN_MODE=file TOKEN_FILE=/tmp/token-bound AUTH_SCHEME=DPoP MCP_URL=http://dpop-guard.team1.svc:8080/mcp
  run_case backend RUN_ID="$run_id" CALLER=copied-no-proof PROOF_MODE=none TOKEN_MODE=file TOKEN_FILE=/tmp/token-bound AUTH_SCHEME=DPoP MCP_URL=http://dpop-guard.team1.svc:8080/mcp
  run_case backend RUN_ID="$run_id" CALLER=copied-own-proof PROOF_MODE=own TOKEN_MODE=file TOKEN_FILE=/tmp/token-bound AUTH_SCHEME=DPoP MCP_URL=http://dpop-guard.team1.svc:8080/mcp
  run_case backend RUN_ID="$run_id" CALLER=unbound-with-proof PROOF_MODE=own TOKEN_MODE=file TOKEN_FILE=/tmp/token-unbound AUTH_SCHEME=DPoP MCP_URL=http://dpop-guard.team1.svc:8080/mcp
  run_case backend RUN_ID="$run_id" CALLER=no-token PROOF_MODE=none TOKEN_MODE=none AUTH_SCHEME=none MCP_URL=http://dpop-guard.team1.svc:8080/mcp
  run_case backend RUN_ID="$run_id" CALLER=raw-t0 PROOF_MODE=none TOKEN_MODE=file TOKEN_FILE=/tmp/token-t0 AUTH_SCHEME=Bearer MCP_URL=http://dpop-guard.team1.svc:8080/mcp
  echo "LEGACY_TOOL $run_id"
  run_case backend RUN_ID="$run_id" CALLER=legacy-bound PROOF_MODE=none TOKEN_MODE=file TOKEN_FILE=/tmp/token-bound AUTH_SCHEME=Bearer MCP_URL=http://weather-tool-advanced-mcp.team1.svc:8000/mcp
  run_case backend RUN_ID="$run_id" CALLER=legacy-unbound PROOF_MODE=none TOKEN_MODE=file TOKEN_FILE=/tmp/token-unbound AUTH_SCHEME=Bearer MCP_URL=http://weather-tool-advanced-mcp.team1.svc:8000/mcp
  run_case backend RUN_ID="$run_id" CALLER=legacy-none PROOF_MODE=none TOKEN_MODE=none AUTH_SCHEME=none MCP_URL=http://weather-tool-advanced-mcp.team1.svc:8000/mcp
  run_case backend RUN_ID="$run_id" CALLER=legacy-t0 PROOF_MODE=none TOKEN_MODE=file TOKEN_FILE=/tmp/token-t0 AUTH_SCHEME=Bearer MCP_URL=http://weather-tool-advanced-mcp.team1.svc:8000/mcp
  echo "=== guard during $run_id ==="
  kubectl --context "$CTX" -n team1 exec dpop-guard -- cat /tmp/guard.log | awk -v since="$since" 'length($0)<500 && $0 !~ /eyJ/ && ($0 ~ since || $0 ~ /GUARD run='"$run_id"'/)'
  echo "=== holder sidecar during $run_id ==="
  kubectl --context "$CTX" -n team1 logs "$APOD" -c authbridge-proxy --since-time="$since" | awk 'length($0)<360 && $0 !~ /eyJ/ && $0 ~ /exchanged|passthrough/'
  echo "RUN_END $run_id $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  kubectl --context "$CTX" -n team1 exec "$APOD" -c agent -- rm -f /tmp/holder-key.json /tmp/token-bound /tmp/token-unbound /tmp/token-t0 /tmp/lab-user.pass
}

run_one ny-1 lab-ny /tmp/lab-ny.pass
run_one lon-1 lab-lon /tmp/lab-lon.pass
echo "DONE_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
