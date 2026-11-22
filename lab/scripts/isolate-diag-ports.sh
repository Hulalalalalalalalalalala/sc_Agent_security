#!/usr/bin/env bash
# Point AuthBridge diagnostic listeners at localhost and restart only the
# sidecar container. Does not delete the Pod, so the webhook does not
# regenerate the ConfigMap during this restart.
set -euo pipefail
CTX="${CTX:-kind-agent-identity-lab}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CFG="$(cat "$ROOT/lab/k8s/authbridge-loopback.yaml")"
python3 - "$CFG" << 'PY'
import json, os, subprocess, sys
cfg = sys.argv[1]
ctx = os.environ.get("CTX", "kind-agent-identity-lab")
for name in (
    "authbridge-config-weather-tool-advanced",
    "authbridge-config-weather-service-advanced",
):
    patch = {"data": {"config.yaml": cfg}}
    subprocess.check_call([
        "kubectl", "--context", ctx, "-n", "team1", "patch", "cm", name,
        "--type", "merge", "-p", json.dumps(patch),
    ])
PY
echo "configmaps patched"
# Restart sidecar containers in place. Killing PID 1 makes kubelet restart
# the container without recreating the Pod.
for deploy in weather-tool-advanced weather-service-advanced; do
  kubectl --context "$CTX" -n team1 exec "deploy/$deploy" -c authbridge-proxy -- kill 1 || true
done
echo "restart requested"
sleep 6
python3 - << 'PY'
import json, subprocess
node = "agent-identity-lab-control-plane"
for name in ("weather-tool-advanced", "weather-service-advanced"):
    raw = subprocess.check_output(["docker", "exec", node, "crictl", "pods", "--name", name, "-o", "json"])
    pid = json.loads(raw)["items"][0]["id"]
    info = json.loads(subprocess.check_output(["docker", "exec", node, "crictl", "inspectp", pid]))
    path = next(ns["path"] for ns in info["info"]["runtimeSpec"]["linux"]["namespaces"] if ns.get("type") == "network")
    script = f"""
nsenter --net={path} iptables -C INPUT -p tcp --dport 9093 ! -i lo -j REJECT --reject-with tcp-reset 2>/dev/null || \
nsenter --net={path} iptables -I INPUT 1 -p tcp --dport 9093 ! -i lo -j REJECT --reject-with tcp-reset
"""
    subprocess.check_call(["docker", "exec", node, "sh", "-c", script])
    print("9093 limited", name)
PY
echo "diagnostic ports limited"
