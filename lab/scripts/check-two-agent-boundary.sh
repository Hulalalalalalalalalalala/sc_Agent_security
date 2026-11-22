#!/usr/bin/env bash
# Check diagnostic-port isolation and whether a new lab-ny token can call A, B, and the tool.
# Token tests read /tmp/lab-ny.pass inside rossoctl-backend. That file is not stored in git.
set -euo pipefail
CTX="${CTX:-kind-agent-identity-lab}"
export PATH="/Users/hulalala/Desktop/A/.tools/bin:${HOME}/.docker/bin:${PATH}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CIP="$(kubectl --context "$CTX" -n team1 get pod -l app.kubernetes.io/name=weather-coordinator -o jsonpath='{.items[0].status.podIP}')"
TIP="$(kubectl --context "$CTX" -n team1 get pod -l app.kubernetes.io/name=weather-tool-advanced -o jsonpath='{.items[0].status.podIP}')"
BPOD="$(kubectl --context "$CTX" -n rossoctl-system get pod -l app.kubernetes.io/name=rossoctl-backend -o jsonpath='{.items[0].metadata.name}')"
echo "coordinator_ip=$CIP tool_ip=$TIP"
kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- python3 -c "
import socket
targets=[('coordinator','$CIP',(8001,9091,9093,9094)),('tool','$TIP',(8000,8001,9091,9093,9094))]
for name,ip,ports in targets:
    for port in ports:
        s=socket.socket(); s.settimeout(2)
        try:
            s.connect((ip,port)); print('other_ns', name, port, 'open')
        except Exception as e:
            print('other_ns', name, port, type(e).__name__)
        finally:
            s.close()
"
echo "=== localhost diag ==="
kubectl --context "$CTX" -n team1 exec deploy/weather-coordinator -c authbridge-proxy -- sh -c 'wget -qS -O /dev/null http://127.0.0.1:9093/stats 2>&1 | head -1'
if kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- test -s /tmp/lab-ny.pass; then
  kubectl --context "$CTX" -n rossoctl-system cp "$ROOT/lab/scripts/direct_access_probe.py" "$BPOD:/tmp/direct_access_probe.py" -c backend
  kubectl --context "$CTX" -n rossoctl-system exec "$BPOD" -c backend -- /app/.venv/bin/python3 /tmp/direct_access_probe.py
else
  echo "token_probe_failed: /tmp/lab-ny.pass is missing inside rossoctl-backend."
  echo "That path is inside the rossoctl-backend container, not a file on the Mac."
  echo "Prepare it with: /Users/hulalala/Desktop/A/lab/scripts/prepare-lab-credentials.sh"
  exit 1
fi
