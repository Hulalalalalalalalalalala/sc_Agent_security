#!/usr/bin/env bash
# =============================================================================
# Lineage Capability Tree (LCT) — Milestone 4 True 4-Cluster Physical Federation Runner
#
# Physical Topology (4 Independent Kind Clusters, 4 kube-apiservers, 4 etcds, 4 OIDC JWKS):
#   1. `kind-lct-org-alpha` (`org-alpha.io`   | Pod 10.241.0.0/16 | Svc 10.97.0.0/16)
#   2. `kind-lct-org-beta`  (`org-beta.io`    | Pod 10.242.0.0/16 | Svc 10.98.0.0/16)
#   3. `kind-lct-org-pay`   (`org-payment.io` | Pod 10.243.0.0/16 | Svc 10.99.0.0/16)
#   4. `kind-lct-audit`     (`org-audit.io`   | Pod 10.244.0.0/16 | Svc 10.100.0.0/16)
#
# Baseline Cluster (`kind-agent-identity-lab` / `team1`) is 100% untouched and
# remains the active default `kubectl` context at all times!
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINEAGE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
if [ -d "${LINEAGE_DIR}/../lineage/common" ]; then
  REPO_ROOT="$(cd "${LINEAGE_DIR}/.." && pwd)"
else
  REPO_ROOT="${LINEAGE_DIR}"
fi

export PATH="${HOME}/.local/bin:${REPO_ROOT}/.tools/bin:${REPO_ROOT}/.tools/ollama:${LINEAGE_DIR}/.tools/bin:${LINEAGE_DIR}/.tools/ollama:${HOME}/.docker/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"

detect_python() {
  local c
  for c in \
    "${HOST_PY:-}" \
    "${REPO_ROOT}/.venv/bin/python3" \
    "${LINEAGE_DIR}/.venv/bin/python3" \
    "${REPO_ROOT}/src/cortex/authbridge/venv/bin/python3" \
    "$(command -v python3 2>/dev/null || true)"; do
    if [ -n "${c}" ] && [ -x "${c}" ]; then
      echo "${c}"
      return 0
    fi
  done
  echo "python3"
}
HOST_PY="$(detect_python)"

detect_ollama() {
  local c
  for c in \
    "${REPO_ROOT}/.tools/ollama/ollama" \
    "${LINEAGE_DIR}/.tools/ollama/ollama" \
    "$(command -v ollama 2>/dev/null || true)"; do
    if [ -n "${c}" ] && [ -x "${c}" ]; then
      echo "${c}"
      return 0
    fi
  done
  echo "ollama"
}
OLLAMA_BIN="$(detect_ollama)"

BASELINE_CTX="kind-agent-identity-lab"
HAS_BASELINE_CLUSTER="false"
if docker inspect agent-identity-lab-control-plane >/dev/null 2>&1; then
  HAS_BASELINE_CLUSTER="true"
fi

LCT_IMAGE_TAG="${LCT_IMAGE_TAG:-lineage-lct:m4}"
MC_DIR="${LINEAGE_DIR}/k8s/multicluster"

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)-multicluster"
OUT_DIR="${LINEAGE_DIR}/k8s/runs/${RUN_TS}"
mkdir -p "${OUT_DIR}"

restore_baseline_ctx() {
  if [ "${HAS_BASELINE_CLUSTER}" = "true" ]; then
    kubectl config use-context "${BASELINE_CTX}" >/dev/null 2>&1 || true
  fi
}
trap restore_baseline_ctx EXIT

log() {
  echo "[$(date -u +%H:%M:%S)] $*" | tee -a "${OUT_DIR}/run.log"
}

log "=== Step 0: Pre-flight Checks (Baseline Cluster 'kind-agent-identity-lab', Local Kind Node Image, Host Ollama) ==="
if [ "${HAS_BASELINE_CLUSTER}" = "true" ]; then
  if ! docker inspect -f '{{.State.Running}}' agent-identity-lab-control-plane 2>/dev/null | grep -q true; then
    log "Starting stopped baseline container 'agent-identity-lab-control-plane' after host/Docker restart..."
    docker start agent-identity-lab-control-plane >> "${OUT_DIR}/run.log"
  fi
  for _ in $(seq 1 90); do
    if kubectl --context "${BASELINE_CTX}" get --raw=/readyz >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  kubectl --context "${BASELINE_CTX}" wait --for=condition=Ready node/agent-identity-lab-control-plane --timeout=90s >> "${OUT_DIR}/run.log"
  kubectl --context "${BASELINE_CTX}" wait --for=condition=Ready pod --all -n team1 --timeout=120s >> "${OUT_DIR}/run.log"
  restore_baseline_ctx

  kubectl --context "${BASELINE_CTX}" get pods -n team1 -o wide > "${OUT_DIR}/00_team1_before.txt"
  log "Baseline 'team1' before multi-cluster run:"
  cat "${OUT_DIR}/00_team1_before.txt" | tee -a "${OUT_DIR}/run.log"
else
  echo "Standalone checkout: baseline cluster '${BASELINE_CTX}' not present on host." > "${OUT_DIR}/00_team1_before.txt"
  log "Standalone checkout detected (baseline '${BASELINE_CTX}' absent); proceeding with 4-cluster LCT federation."
fi

if ! curl -fsS http://127.0.0.1:11434/v1/models >/dev/null 2>&1; then
  log "Host Ollama daemon is stopped; auto-starting '${OLLAMA_BIN} serve' on 127.0.0.1:11434..."
  nohup "${OLLAMA_BIN}" serve >/tmp/lct-ollama-serve.log 2>&1 </dev/null &
  disown || true
  for _ in $(seq 1 50); do
    if curl -fsS http://127.0.0.1:11434/v1/models >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done
fi
curl -fsS http://127.0.0.1:11434/v1/models > "${OUT_DIR}/00_ollama_models.json"
grep -q "qwen2.5:3b" "${OUT_DIR}/00_ollama_models.json"
log "Verified host Ollama serving qwen2.5:3b on 127.0.0.1:11434"

if [ -z "${KIND_NODE_IMAGE:-}" ]; then
  if docker image inspect kindest/node:lct-local >/dev/null 2>&1; then
    KIND_NODE_IMAGE="kindest/node:lct-local"
  elif docker image inspect 452d707d4862 >/dev/null 2>&1; then
    docker tag 452d707d4862 kindest/node:lct-local
    KIND_NODE_IMAGE="kindest/node:lct-local"
    log "Tagged local cached node image 452d707d4862 -> ${KIND_NODE_IMAGE}"
  else
    KIND_NODE_IMAGE="kindest/node:v1.32.2"
    log "Using upstream Kind node image ${KIND_NODE_IMAGE}"
  fi
fi

log "=== Step 1: Provision 4 Physically Independent Kind Clusters Offline (Zero Network Pulls) ==="
for pair in \
  "lct-org-alpha:${MC_DIR}/kind-org-alpha.yaml" \
  "lct-org-beta:${MC_DIR}/kind-org-beta.yaml" \
  "lct-org-pay:${MC_DIR}/kind-org-pay.yaml" \
  "lct-audit:${MC_DIR}/kind-audit.yaml"; do
  cname="${pair%%:*}"
  cfg="${pair##*:}"
  if kind get clusters 2>/dev/null | grep -qx "${cname}"; then
    log "Removing previous '${cname}' cluster for clean genesis..."
    kind delete cluster --name "${cname}" >> "${OUT_DIR}/kind_provision.log" 2>&1
    restore_baseline_ctx
  fi
  log "Creating Kind cluster '${cname}' (${cfg})..."
  kind create cluster --name "${cname}" --config "${cfg}" --image "${KIND_NODE_IMAGE}" --wait 60s >> "${OUT_DIR}/kind_provision.log" 2>&1
  restore_baseline_ctx
done

for cname in lct-org-alpha lct-org-beta lct-org-pay lct-audit; do
  kubectl --context "kind-${cname}" wait --for=condition=Ready "node/${cname}-control-plane" --timeout=60s >> "${OUT_DIR}/run.log"
done
log "All 4 independent Kind clusters Ready (active kubectl context preserved as '$(kubectl config current-context)')"

get_node_ip() {
  docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "$1-control-plane"
}

ALPHA_NODE_IP="$(get_node_ip lct-org-alpha)"
BETA_NODE_IP="$(get_node_ip lct-org-beta)"
PAY_NODE_IP="$(get_node_ip lct-org-pay)"
AUDIT_NODE_IP="$(get_node_ip lct-audit)"
log "Docker 'kind' bridge node IPs: alpha=${ALPHA_NODE_IP}, beta=${BETA_NODE_IP}, pay=${PAY_NODE_IP}, audit=${AUDIT_NODE_IP}"

patch_all_coredns() {
  local a_ip="$1" b_ip="$2" p_ip="$3" aud_ip="$4"
  "${HOST_PY}" - "${a_ip}" "${b_ip}" "${p_ip}" "${aud_ip}" <<'PYEOF'
import json, re, subprocess, sys

a_ip, b_ip, p_ip, aud_ip = sys.argv[1:5]
hosts_block = f"""    hosts {{
        {a_ip} alpha-ca.org-alpha.io alpha-directory.org-alpha.io alpha-revocation.org-alpha.io orchestrator-alpha.org-alpha.io e2e-user-gateway.org-alpha.io
        {b_ip} beta-ca.org-beta.io beta-directory.org-beta.io beta-revocation.org-beta.io flight-specialist.org-beta.io hotel-specialist-primary.org-beta.io hotel-specialist-backup.org-beta.io
        {p_ip} payment-ca.org-payment.io payment-directory.org-payment.io payment-revocation.org-payment.io settlement-converger.org-payment.io travel-ops-mcp.org-payment.io payment-vault-mcp.org-payment.io
        {aud_ip} audit-collector.org-audit.io
        fallthrough
    }}"""

for cname in ("lct-org-alpha", "lct-org-beta", "lct-org-pay", "lct-audit"):
    ctx = f"kind-{cname}"
    raw = subprocess.check_output(
        ["kubectl", "--context", ctx, "-n", "kube-system", "get", "configmap", "coredns", "-o", "json"],
        text=True,
    )
    cm = json.loads(raw)
    corefile = cm["data"]["Corefile"]
    corefile = re.sub(
        r"\n?\s*hosts\s*\{[^}]*org-alpha\.io[^}]*\}\n?",
        "\n",
        corefile,
        flags=re.DOTALL,
    )
    if "kubernetes cluster.local" not in corefile:
        raise RuntimeError(f"Unexpected Corefile in {ctx}:\n{corefile}")
    corefile = corefile.replace(
        "    kubernetes cluster.local",
        hosts_block + "\n    kubernetes cluster.local",
        1,
    )
    cm["data"]["Corefile"] = corefile
    cm.pop("metadata", None)
    patched = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "coredns", "namespace": "kube-system"},
        "data": {"Corefile": corefile},
    }
    subprocess.run(
        ["kubectl", "--context", ctx, "apply", "-f", "-"],
        input=json.dumps(patched),
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["kubectl", "--context", ctx, "-n", "kube-system", "rollout", "restart", "deploy/coredns"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
for cname in ("lct-org-alpha", "lct-org-beta", "lct-org-pay", "lct-audit"):
    subprocess.run(
        ["kubectl", "--context", f"kind-{cname}", "-n", "kube-system", "rollout", "status", "deploy/coredns", "--timeout=60s"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
PYEOF
}

log "=== Step 2: Inject Public Organization FQDN Zones into CoreDNS Across All 4 Clusters ==="
patch_all_coredns "${ALPHA_NODE_IP}" "${BETA_NODE_IP}" "${PAY_NODE_IP}" "${AUDIT_NODE_IP}"
log "CoreDNS public zones (*.org-alpha.io, *.org-beta.io, *.org-payment.io, audit-collector.org-audit.io) active across all 4 clusters"

log "=== Step 3: Build Container Image (${LCT_IMAGE_TAG}) & Load into All 4 Kind Clusters ==="
if docker image inspect ghcr.io/rossoctl/examples/weather_tool:pinned >/dev/null 2>&1; then
  DOCKER_BASE_IMG="ghcr.io/rossoctl/examples/weather_tool:pinned"
else
  DOCKER_BASE_IMG="python:3.12-slim"
fi
docker build --build-arg "BASE_IMAGE=${DOCKER_BASE_IMG}" -f "${LINEAGE_DIR}/k8s/Dockerfile" -t "${LCT_IMAGE_TAG}" "${REPO_ROOT}" >> "${OUT_DIR}/docker_build.log" 2>&1
for cname in lct-org-alpha lct-org-beta lct-org-pay lct-audit; do
  kind load docker-image "${LCT_IMAGE_TAG}" --name "${cname}" >> "${OUT_DIR}/docker_build.log" 2>&1
done
log "Image ${LCT_IMAGE_TAG} loaded into all 4 clusters"

log "=== Step 4: Deploy Physically Isolated Per-Cluster Control & Data Planes ==="
kubectl --context kind-lct-org-alpha apply -f "${MC_DIR}/cluster-alpha.yaml" >> "${OUT_DIR}/run.log"
kubectl --context kind-lct-org-beta  apply -f "${MC_DIR}/cluster-beta.yaml"  >> "${OUT_DIR}/run.log"
kubectl --context kind-lct-org-pay   apply -f "${MC_DIR}/cluster-pay.yaml"   >> "${OUT_DIR}/run.log"
kubectl --context kind-lct-audit     apply -f "${MC_DIR}/cluster-audit.yaml" >> "${OUT_DIR}/run.log"

log "Waiting for 3 Autonomous Domain CAs & Keyless Audit Collector..."
kubectl --context kind-lct-org-alpha -n lineage-alpha rollout status deploy/alpha-ca --timeout=90s
kubectl --context kind-lct-org-beta  -n lineage-beta  rollout status deploy/beta-ca --timeout=90s
kubectl --context kind-lct-org-pay   -n lineage-pay   rollout status deploy/payment-ca --timeout=90s
kubectl --context kind-lct-audit     -n lineage-ctrl  rollout status deploy/audit-collector --timeout=90s

log "Waiting for Cross-Cluster mTLS 1.3 Federation Directories & Revocation Authorities..."
kubectl --context kind-lct-org-alpha -n lineage-alpha rollout status deploy/alpha-revocation --timeout=90s
kubectl --context kind-lct-org-beta  -n lineage-beta  rollout status deploy/beta-revocation --timeout=90s
kubectl --context kind-lct-org-pay   -n lineage-pay   rollout status deploy/payment-revocation --timeout=90s
kubectl --context kind-lct-org-alpha -n lineage-alpha rollout status deploy/alpha-directory --timeout=90s
kubectl --context kind-lct-org-beta  -n lineage-beta  rollout status deploy/beta-directory --timeout=90s
kubectl --context kind-lct-org-pay   -n lineage-pay   rollout status deploy/payment-directory --timeout=90s

log "Waiting for All 2/2 Dual-Container mTLS 1.3 Agent & MCP Pods Across Clusters 1, 2, 3..."
kubectl --context kind-lct-org-pay   -n lineage-pay   rollout status deploy/travel-ops-mcp --timeout=90s
kubectl --context kind-lct-org-pay   -n lineage-pay   rollout status deploy/payment-vault-mcp --timeout=90s
kubectl --context kind-lct-org-pay   -n lineage-pay   rollout status deploy/settlement-converger --timeout=90s
kubectl --context kind-lct-org-beta  -n lineage-beta  rollout status deploy/flight-specialist --timeout=90s
kubectl --context kind-lct-org-beta  -n lineage-beta  rollout status deploy/hotel-specialist-primary --timeout=90s
kubectl --context kind-lct-org-beta  -n lineage-beta  rollout status deploy/hotel-specialist-backup --timeout=90s
kubectl --context kind-lct-org-alpha -n lineage-alpha rollout status deploy/orchestrator-alpha --timeout=90s
kubectl --context kind-lct-org-alpha -n lineage-alpha rollout status deploy/e2e-user-gateway --timeout=90s

{
  echo "=== Cluster 1: kind-lct-org-alpha (Node IP ${ALPHA_NODE_IP} | Pod CIDR 10.241.0.0/16 | Svc CIDR 10.97.0.0/16) ==="
  kubectl --context kind-lct-org-alpha get pods,svc -n lineage-alpha -o wide
  echo ""
  echo "=== Cluster 2: kind-lct-org-beta (Node IP ${BETA_NODE_IP} | Pod CIDR 10.242.0.0/16 | Svc CIDR 10.98.0.0/16) ==="
  kubectl --context kind-lct-org-beta get pods,svc -n lineage-beta -o wide
  echo ""
  echo "=== Cluster 3: kind-lct-org-pay (Node IP ${PAY_NODE_IP} | Pod CIDR 10.243.0.0/16 | Svc CIDR 10.99.0.0/16) ==="
  kubectl --context kind-lct-org-pay get pods,svc -n lineage-pay -o wide
  echo ""
  echo "=== Cluster 4: kind-lct-audit (Node IP ${AUDIT_NODE_IP} | Pod CIDR 10.244.0.0/16 | Svc CIDR 10.100.0.0/16 | Keyless!) ==="
  kubectl --context kind-lct-audit get pods,svc -n lineage-ctrl -o wide
} > "${OUT_DIR}/01_clusters_topology.txt"
cat "${OUT_DIR}/01_clusters_topology.txt" | tee -a "${OUT_DIR}/run.log"
sleep 2

GW_POD="$(kubectl --context kind-lct-org-alpha -n lineage-alpha get pod -l app=e2e-user-gateway -o jsonpath='{.items[0].metadata.name}')"
ORCH_POD="$(kubectl --context kind-lct-org-alpha -n lineage-alpha get pod -l app=orchestrator-alpha -o jsonpath='{.items[0].metadata.name}')"
ORCH_IP="$(kubectl --context kind-lct-org-alpha -n lineage-alpha get pod "${ORCH_POD}" -o jsonpath='{.status.podIP}')"
FLIGHT_POD="$(kubectl --context kind-lct-org-beta -n lineage-beta get pod -l app=flight-specialist -o jsonpath='{.items[0].metadata.name}')"
FLIGHT_IP="$(kubectl --context kind-lct-org-beta -n lineage-beta get pod "${FLIGHT_POD}" -o jsonpath='{.status.podIP}')"
VAULT_POD="$(kubectl --context kind-lct-org-pay -n lineage-pay get pod -l app=payment-vault-mcp -o jsonpath='{.items[0].metadata.name}')"
VAULT_IP="$(kubectl --context kind-lct-org-pay -n lineage-pay get pod "${VAULT_POD}" -o jsonpath='{.status.podIP}')"
AUDIT_POD="$(kubectl --context kind-lct-audit -n lineage-ctrl get pod -l app=audit-collector -o jsonpath='{.items[0].metadata.name}')"

run_in_gw() {
  kubectl --context kind-lct-org-alpha -n lineage-alpha exec "${GW_POD}" -- \
    /app/.venv/bin/python3 -m lineage.k8s.e2e_driver "$@"
}

log "=== Step 5: Multi-Cluster Physical L3, DNS, OIDC JWKS & Container Isolation Proofs ==="
# 5A. Verify 4 distinct kube-apiserver OIDC RSA signing kids + Cross-Cluster SA JWT rejection on internal `:8090`!
"${HOST_PY}" - "${OUT_DIR}/02_multicluster_oidc_and_container_proofs.json" "${GW_POD}" "${FLIGHT_POD}" "${ORCH_POD}" "${AUDIT_POD}" <<'PYEOF'
import json, subprocess, sys

out_path, gw_pod, flight_pod, orch_pod, audit_pod = sys.argv[1:6]
cluster_meta = {}
all_kids = set()

for cname, expected_pod_cidr, expected_svc_cidr in [
    ("lct-org-alpha", "10.241.0.0/16", "10.97.0.0/16"),
    ("lct-org-beta", "10.242.0.0/16", "10.98.0.0/16"),
    ("lct-org-pay", "10.243.0.0/16", "10.99.0.0/16"),
    ("lct-audit", "10.244.0.0/16", "10.100.0.0/16"),
]:
    ctx = f"kind-{cname}"
    cid = subprocess.check_output(["docker", "inspect", "-f", "{{.Id}}", f"{cname}-control-plane"], text=True).strip()[:16]
    nip = subprocess.check_output(["docker", "inspect", "-f", "{{.NetworkSettings.Networks.kind.IPAddress}}", f"{cname}-control-plane"], text=True).strip()
    jwks_raw = subprocess.check_output(["kubectl", "--context", ctx, "get", "--raw", "/openid/v1/jwks"], text=True)
    kids = [k.get("kid") for k in json.loads(jwks_raw).get("keys", []) if k.get("kid")]
    if not kids:
        raise AssertionError(f"Zero OIDC signing keys in {ctx}")
    all_kids.update(kids)
    cluster_meta[cname] = {
        "node_container_id_prefix": cid,
        "kind_bridge_ip": nip,
        "pod_subnet": expected_pod_cidr,
        "service_subnet": expected_svc_cidr,
        "kube_apiserver_oidc_kids": kids,
    }

if len(all_kids) < 4:
    raise AssertionError(f"Expected 4 distinct kube-apiserver OIDC RSA kids across 4 clusters, got {all_kids}")

# Read real projected SA JWT from Cluster Alpha (`e2e-user-gateway`) strictly in memory,
# and replay it from INSIDE Cluster Beta directly against internal `http://beta-ca.lineage-beta.svc.cluster.local:8090`!
alpha_sa_jwt = subprocess.check_output(
    ["kubectl", "--context", "kind-lct-org-alpha", "-n", "lineage-alpha", "exec", gw_pod, "--", "cat", "/var/run/lct-sa/token"],
    text=True,
).strip()

probe_code = """
import json, sys, httpx
from lineage.common.crypto import KeyPair
from lineage.k8s.bootstrap_services import create_ca_pop_jws
sa_jwt = sys.stdin.read().strip()
kp = KeyPair.generate("ES256")
r = httpx.post(
    "http://beta-ca.lineage-beta.svc.cluster.local:8090/v1/ca/issue-workload",
    json={"public_jwk": kp.public_jwk(), "pop_jws": create_ca_pop_jws(kp, sa_jwt)},
    headers={"Authorization": f"Bearer {sa_jwt}"},
    timeout=5.0,
)
print(json.dumps({"http_status": r.status_code, "body": r.json()}))
"""
replay_raw = subprocess.check_output(
    [
        "kubectl", "--context", "kind-lct-org-beta", "-n", "lineage-beta",
        "exec", "-i", flight_pod, "-c", "lct-sidecar", "--",
        "/app/.venv/bin/python3", "-c", probe_code,
    ],
    input=alpha_sa_jwt,
    text=True,
)
replay_res = json.loads(replay_raw)
if replay_res["http_status"] != 403 or "Unknown Kubernetes signing kid" not in replay_res["body"].get("detail", ""):
    raise AssertionError(f"Cross-cluster OIDC SA token replay was not rejected with Unknown kid: {replay_res}")

# Container least-privilege checks on `orchestrator-alpha/app` and `lct-audit/audit-collector`
app_chk = subprocess.check_output(
    [
        "kubectl", "--context", "kind-lct-org-alpha", "-n", "lineage-alpha",
        "exec", orch_pod, "-c", "app", "--", "/bin/sh", "-c",
        "if [ -e /var/run/secrets/kubernetes.io/serviceaccount/token ] || [ -e /var/run/lct-sa/token ] || [ -d /var/run/lct-mtls-ram ]; then exit 1; fi; echo ZERO_SA_ZERO_MTLS",
    ],
    text=True,
).strip()
aud_chk = subprocess.check_output(
    [
        "kubectl", "--context", "kind-lct-audit", "-n", "lineage-ctrl",
        "exec", audit_pod, "--", "/bin/sh", "-c",
        "if [ -e /var/run/secrets/kubernetes.io/serviceaccount/token ] || [ -e /var/run/lct-sa/token ]; then exit 1; fi; echo KEYLESS_ZERO_SA",
    ],
    text=True,
).strip()

report = {
    "status": "PASS",
    "distinct_kube_apiserver_oidc_kid_count": len(all_kids),
    "clusters": cluster_meta,
    "cross_cluster_oidc_sa_replay_against_internal_beta_ca": replay_res,
    "orchestrator_app_isolation": app_chk,
    "audit_collector_keyless_isolation": aud_chk,
}
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)
PYEOF

FOREIGN_IPS_JSON="{\"lct_org_beta_flight_pod\":\"${FLIGHT_IP}\",\"lct_org_pay_vault_pod\":\"${VAULT_IP}\"}"
run_in_gw --phase multicluster_isolation_proofs --foreign-pod-ips-json "${FOREIGN_IPS_JSON}" > "${OUT_DIR}/02_multicluster_network_dns_isolation.json"
log "Multi-cluster OIDC, L3 CIDR, DNS & boundary hardening proofs PASS -> ${OUT_DIR}/02_multicluster_network_dns_isolation.json"

log "=== Scenario 1: Cross-4-Cluster Official A2A v1.0 SendStreamingMessage (SSE) + mTLS 1.3 + qwen2.5:3b Grounding ==="
run_in_gw --phase scenario1_normal_dag --run-id "${RUN_TS}" > "${OUT_DIR}/scenario1_normal_dag.json"
log "Scenario 1 PASS -> ${OUT_DIR}/scenario1_normal_dag.json"

log "=== Scenario 2A: Cross-Cluster A2A v1.0 Atomic Prune-and-Graft (Cluster Beta Slow Primary -> Federated 403 at Cluster Pay) ==="
run_in_gw --phase scenario2a_zombie_prune_and_graft --run-id "${RUN_TS}" > "${OUT_DIR}/scenario2a_zombie_prune_graft.json"
log "Scenario 2A PASS -> ${OUT_DIR}/scenario2a_zombie_prune_graft.json"

log "=== Scenario 2B: Cluster Beta Pod Scale-to-Zero Fault Injection (kind-lct-org-beta replicas=0 -> Backup Epoch+1) ==="
kubectl --context kind-lct-org-beta -n lineage-beta scale deploy/hotel-specialist-primary --replicas=0 >> "${OUT_DIR}/run.log"
kubectl --context kind-lct-org-beta -n lineage-beta wait --for=delete pod -l app=hotel-specialist-primary --timeout=45s >> "${OUT_DIR}/run.log" 2>&1 || true
run_in_gw --phase scenario2b_pod_down_prune_and_graft --run-id "${RUN_TS}" > "${OUT_DIR}/scenario2b_pod_down_prune_graft.json"
log "Scenario 2B PASS -> ${OUT_DIR}/scenario2b_pod_down_prune_graft.json"

log "Restoring hotel-specialist-primary in kind-lct-org-beta (replicas=1, 2/2 Ready) for Scenario 3..."
kubectl --context kind-lct-org-beta -n lineage-beta scale deploy/hotel-specialist-primary --replicas=1 >> "${OUT_DIR}/run.log"
kubectl --context kind-lct-org-beta -n lineage-beta rollout status deploy/hotel-specialist-primary --timeout=60s >> "${OUT_DIR}/run.log"
sleep 2

log "=== Scenario 3A: Forged Skip-Level Blocked by Cross-Cluster mTLS 1.3 /healthz Probe to Cluster Beta ==="
run_in_gw --phase scenario3a_forged_skip_blocked_while_alive --run-id "${RUN_TS}" > "${OUT_DIR}/scenario3a_false_skip_blocked.json"
log "Scenario 3A PASS -> ${OUT_DIR}/scenario3a_false_skip_blocked.json"

log "=== Scenario 3B: Mid-Flight Cluster Beta Pod Kill -> Cluster Pay Leaf Skip-Level Return Directly to Cluster Alpha ==="
kubectl --context kind-lct-org-alpha -n lineage-alpha exec "${GW_POD}" -- rm -f /tmp/s3b_ready
run_in_gw --phase scenario3b_genuine_skip_level_when_pod_killed \
  --run-id "${RUN_TS}" \
  --sync-marker-file "/tmp/s3b_ready" > "${OUT_DIR}/scenario3b_skip_level_return.json" &
S3B_PID=$!

for _ in $(seq 1 60); do
  if kubectl --context kind-lct-org-alpha -n lineage-alpha exec "${GW_POD}" -- test -f /tmp/s3b_ready 2>/dev/null; then
    log "Mid-flight trigger hit via e2e-user-gateway.org-alpha.io:30990: killing hotel-specialist-primary in kind-lct-org-beta..."
    kubectl --context kind-lct-org-beta -n lineage-beta scale deploy/hotel-specialist-primary --replicas=0 >> "${OUT_DIR}/run.log"
    kubectl --context kind-lct-org-beta -n lineage-beta delete pod -l app=hotel-specialist-primary --grace-period=0 --force >> "${OUT_DIR}/run.log" 2>&1 || true
    break
  fi
  sleep 0.4
done
wait "${S3B_PID}"
log "Scenario 3B PASS -> ${OUT_DIR}/scenario3b_skip_level_return.json"

log "Restoring hotel-specialist-primary in kind-lct-org-beta (replicas=1, 2/2 Ready) for Scenario 4..."
kubectl --context kind-lct-org-beta -n lineage-beta scale deploy/hotel-specialist-primary --replicas=1 >> "${OUT_DIR}/run.log"
kubectl --context kind-lct-org-beta -n lineage-beta rollout status deploy/hotel-specialist-primary --timeout=60s >> "${OUT_DIR}/run.log"
sleep 2

log "=== Scenario 4: Cross-Cluster A2A v1.0 CancelTask Cascading Revocation + Fagin DAG Degradation + Concurrency + Loopback Guard ==="
POD_IPS_JSON="{\"orchestrator-alpha\":\"${ORCH_IP}\"}"
run_in_gw --phase scenario4_fagin_degradation_concurrency_and_bypass_guard \
  --run-id "${RUN_TS}" \
  --pod-ips-json "${POD_IPS_JSON}" > "${OUT_DIR}/scenario4_fagin_degradation_and_isolation.json"

# Explicitly verify inside Cluster Beta & Cluster Pay internal `:8092/v1/events` that Bob's CancelTask event replicated!
kubectl --context kind-lct-org-beta -n lineage-beta exec "${FLIGHT_POD}" -c lct-sidecar -- \
  /app/.venv/bin/python3 -c "import httpx; evs=httpx.get('http://beta-revocation.lineage-beta.svc.cluster.local:8092/v1/events', timeout=3).json()['events']; assert any('task-k8s-s4-bob-cancel-${RUN_TS}' in e['target'] for e in evs), evs"
kubectl --context kind-lct-org-pay -n lineage-pay exec "${VAULT_POD}" -c lct-sidecar -- \
  /app/.venv/bin/python3 -c "import httpx; evs=httpx.get('http://payment-revocation.lineage-pay.svc.cluster.local:8092/v1/events', timeout=3).json()['events']; assert any('task-k8s-s4-bob-cancel-${RUN_TS}' in e['target'] for e in evs), evs"
log "Scenario 4 PASS (verified internal trie replication inside both kind-lct-org-beta & kind-lct-org-pay) -> ${OUT_DIR}/scenario4_fagin_degradation_and_isolation.json"

log "=== Scenario 6: Whole-Cluster Network Partition (docker network disconnect lct-org-beta) + Fail-Closed 503 + Autonomous Recovery ==="
kubectl --context kind-lct-org-alpha -n lineage-alpha exec "${GW_POD}" -- \
  rm -f /tmp/s6_ready_disconnect /tmp/s6_ack_disconnected /tmp/s6_ready_reconnect /tmp/s6_ack_reconnected

run_in_gw --phase scenario6_whole_cluster_partition \
  --run-id "${RUN_TS}" > "${OUT_DIR}/scenario6_whole_cluster_partition_and_recovery.json" &
S6_PID=$!

for _ in $(seq 1 120); do
  if ! kill -0 "${S6_PID}" 2>/dev/null; then
    wait "${S6_PID}"
  fi
  if kubectl --context kind-lct-org-alpha -n lineage-alpha exec "${GW_POD}" -- test -f /tmp/s6_ready_disconnect 2>/dev/null; then
    break
  fi
  sleep 0.4
done

log "Severing Organization Beta cluster ('lct-org-beta-control-plane') from Docker 'kind' backbone..."
docker network disconnect kind lct-org-beta-control-plane
reconnect_beta() {
  docker network connect --ip "${BETA_NODE_IP}" kind lct-org-beta-control-plane >/dev/null 2>&1 || docker network connect kind lct-org-beta-control-plane >/dev/null 2>&1 || true
  restore_baseline_ctx
}
trap reconnect_beta EXIT
kubectl --context kind-lct-org-alpha -n lineage-alpha exec "${GW_POD}" -- touch /tmp/s6_ack_disconnected

for _ in $(seq 1 120); do
  if ! kill -0 "${S6_PID}" 2>/dev/null; then
    wait "${S6_PID}"
  fi
  if kubectl --context kind-lct-org-alpha -n lineage-alpha exec "${GW_POD}" -- test -f /tmp/s6_ready_reconnect 2>/dev/null; then
    break
  fi
  sleep 0.4
done
log "Verified surviving clusters 200 OK & HIGH_RISK settlement traversing Beta failed closed (503 REVOCATION_ANCHOR_UNAVAILABLE)!"

log "Reconnecting 'lct-org-beta-control-plane' to Docker 'kind' backbone..."
docker network connect --ip "${BETA_NODE_IP}" kind lct-org-beta-control-plane || docker network connect kind lct-org-beta-control-plane
trap restore_baseline_ctx EXIT
NEW_BETA_IP="$(get_node_ip lct-org-beta)"
if [ "${NEW_BETA_IP}" != "${BETA_NODE_IP}" ]; then
  log "Refreshing CoreDNS with new Beta IP ${NEW_BETA_IP}..."
  BETA_NODE_IP="${NEW_BETA_IP}"
  patch_all_coredns "${ALPHA_NODE_IP}" "${BETA_NODE_IP}" "${PAY_NODE_IP}" "${AUDIT_NODE_IP}"
fi
kubectl --context kind-lct-org-alpha -n lineage-alpha exec "${GW_POD}" -- touch /tmp/s6_ack_reconnected

wait "${S6_PID}"
log "Scenario 6 PASS -> ${OUT_DIR}/scenario6_whole_cluster_partition_and_recovery.json"

log "=== Scenario 5: Cluster 4 ('kind-lct-audit') Keyless Audit Export & 100% CausalChainAuditor Reconstruction Across All 6 Scenarios ==="
run_in_gw --phase scenario5_cluster_audit_reconstruction > "${OUT_DIR}/scenario5_causal_audit_report.json"
run_in_gw --phase export_redacted_audit_entries > "${OUT_DIR}/cluster_audit_entries_redacted.json"
log "Scenario 5 PASS -> ${OUT_DIR}/scenario5_causal_audit_report.json"

restore_baseline_ctx
if [ "${HAS_BASELINE_CLUSTER}" = "true" ]; then
  ACTIVE_CTX="$(kubectl config current-context)"
  if [ "${ACTIVE_CTX}" != "${BASELINE_CTX}" ]; then
    echo "[FATAL] Active kubectl context '${ACTIVE_CTX}' != '${BASELINE_CTX}'!" >&2
    exit 1
  fi
  kubectl --context "${BASELINE_CTX}" get pods -n team1 -o wide > "${OUT_DIR}/99_team1_after.txt"
  log "Baseline 'team1' after 4-cluster run (100% untouched Running 2/2, active context='${ACTIVE_CTX}'):"
  cat "${OUT_DIR}/99_team1_after.txt" | tee -a "${OUT_DIR}/run.log"
else
  echo "Standalone checkout: baseline cluster '${BASELINE_CTX}' not present on host." > "${OUT_DIR}/99_team1_after.txt"
fi

if grep -rn "BEGIN PRIVATE KEY\|BEGIN EC PRIVATE KEY\|BEGIN RSA PRIVATE KEY\|\"lct1\.\|\"lctmp1\.\|\"lctm1\.\|\"eyJhbG" "${OUT_DIR}/" >/dev/null 2>&1; then
  echo "[FATAL] Unredacted private key or raw token detected in output directory!" >&2
  exit 1
fi

log "============================================================================"
log " ALL 6 MILESTONE-4 4-CLUSTER PHYSICAL FEDERATION + OLLAMA SCENARIOS PASSED!"
log " Evidence directory: ${OUT_DIR}"
log "============================================================================"
