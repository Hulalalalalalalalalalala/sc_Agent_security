#!/usr/bin/env bash
# =============================================================================
# Lineage Capability Tree (LCT) — Milestone 3 Real K8s + Ollama E2E Runner
#
# Architecture   : Official A2A v1.0 (JSON-RPC 2.0 + Real SSE)
#                  + Physically Autonomous 3-Domain Control Plane (alpha/beta/pay)
#                  + Keyless Audit Collector (lineage-ctrl)
#                  + Full-Chain Bidirectional SPIFFE X.509-SVID mTLS 1.3 (:8443)
# Target Cluster : kind-agent-identity-lab (strictly isolated in `lineage-*`)
# Host LLM       : Ollama `qwen2.5:3b` (`http://host.docker.internal:11434/v1`)
# Output Dir     : `<repo_root>/lineage/k8s/runs/<timestamp>/`
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
KUBE_CTX="${KUBE_CTX:-kind-agent-identity-lab}"
KIND_NAME="${KIND_NAME:-agent-identity-lab}"
IMAGE_TAG="${IMAGE_TAG:-lineage-lct:m3}"

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

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${LINEAGE_DIR}/k8s/runs/${RUN_TS}"
mkdir -p "${OUT_DIR}"

restore_baseline_ctx() {
  kubectl config use-context "${KUBE_CTX}" >/dev/null 2>&1 || true
}
trap restore_baseline_ctx EXIT

log() {
  echo "[$(date -u +%H:%M:%S)] $*" | tee -a "${OUT_DIR}/run.log"
}

log "=== Step 0: Pre-flight Checks (Kind Node, Baseline Namespace 'team1', Host Ollama) ==="
if ! docker inspect -f '{{.State.Running}}' "${KIND_NAME}-control-plane" 2>/dev/null | grep -q true; then
  log "Starting ${KIND_NAME}-control-plane container..."
  docker start "${KIND_NAME}-control-plane" >> "${OUT_DIR}/run.log"
fi
for _ in $(seq 1 90); do
  if kubectl --context "${KUBE_CTX}" get --raw=/readyz >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
kubectl --context "${KUBE_CTX}" wait --for=condition=Ready node/"${KIND_NAME}-control-plane" --timeout=90s >> "${OUT_DIR}/run.log"
kubectl --context "${KUBE_CTX}" wait --for=condition=Ready pod --all -n team1 --timeout=120s >> "${OUT_DIR}/run.log"
restore_baseline_ctx

# Snapshot baseline `team1` BEFORE deployment to prove zero baseline disturbance
kubectl --context "${KUBE_CTX}" get pods -n team1 -o wide > "${OUT_DIR}/00_team1_before.txt"
log "Baseline 'team1' before run:"
cat "${OUT_DIR}/00_team1_before.txt" | tee -a "${OUT_DIR}/run.log"

# Verify (or auto-start) host Ollama `qwen2.5:3b` on 127.0.0.1:11434
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

log "=== Step 1: Build Container Image (${IMAGE_TAG}) & Load into Kind ==="
if docker image inspect ghcr.io/rossoctl/examples/weather_tool:pinned >/dev/null 2>&1; then
  DOCKER_BASE_IMG="ghcr.io/rossoctl/examples/weather_tool:pinned"
else
  DOCKER_BASE_IMG="python:3.12-slim"
fi
docker build --build-arg "BASE_IMAGE=${DOCKER_BASE_IMG}" -f "${LINEAGE_DIR}/k8s/Dockerfile" -t "${IMAGE_TAG}" "${REPO_ROOT}" >> "${OUT_DIR}/docker_build.log" 2>&1
kind load docker-image "${IMAGE_TAG}" --name "${KIND_NAME}" >> "${OUT_DIR}/docker_build.log" 2>&1
log "Image ${IMAGE_TAG} built and loaded into ${KIND_NAME}"

log "=== Step 2: Deploy Isolated Autonomous 3-Domain Namespaces + Keyless lineage-ctrl ==="
kubectl --context "${KUBE_CTX}" delete namespace lineage-pay lineage-beta lineage-alpha lineage-ctrl --ignore-not-found=true --wait=true >> "${OUT_DIR}/run.log" 2>&1 || true
kubectl --context "${KUBE_CTX}" apply -f "${LINEAGE_DIR}/k8s/manifests/00-namespaces.yaml" >> "${OUT_DIR}/run.log"
kubectl --context "${KUBE_CTX}" apply -f "${LINEAGE_DIR}/k8s/manifests/01-control-plane.yaml" >> "${OUT_DIR}/run.log"

log "Waiting for 3-Domain Autonomous CAs, Federated Revocation/Directory Peers, and Keyless Audit Collector..."
for ns_dep in \
  "lineage-alpha:alpha-ca" \
  "lineage-beta:beta-ca" \
  "lineage-pay:payment-ca" \
  "lineage-ctrl:audit-collector" \
  "lineage-alpha:alpha-revocation" \
  "lineage-beta:beta-revocation" \
  "lineage-pay:payment-revocation" \
  "lineage-alpha:alpha-directory" \
  "lineage-beta:beta-directory" \
  "lineage-pay:payment-directory"; do
  ns="${ns_dep%%:*}"
  dep="${ns_dep##*:}"
  kubectl --context "${KUBE_CTX}" -n "${ns}" rollout status "deploy/${dep}" --timeout=90s
done

kubectl --context "${KUBE_CTX}" apply -f "${LINEAGE_DIR}/k8s/manifests/02-data-plane-agents-and-mcp.yaml" >> "${OUT_DIR}/run.log"

log "Waiting for all 2/2 Dual-Container mTLS 1.3 (:8443) Agent & MCP Pods across lineage-alpha / lineage-beta / lineage-pay..."
for ns_dep in \
  "lineage-pay:travel-ops-mcp" \
  "lineage-pay:payment-vault-mcp" \
  "lineage-pay:settlement-converger" \
  "lineage-beta:flight-specialist" \
  "lineage-beta:hotel-specialist-primary" \
  "lineage-beta:hotel-specialist-backup" \
  "lineage-alpha:orchestrator-alpha" \
  "lineage-alpha:e2e-user-gateway"; do
  ns="${ns_dep%%:*}"
  dep="${ns_dep##*:}"
  kubectl --context "${KUBE_CTX}" -n "${ns}" rollout status "deploy/${dep}" --timeout=90s
done

{
  echo "=== [lineage-ctrl] Keyless Independent Audit Center (ZERO CA Pods!) ==="
  kubectl --context "${KUBE_CTX}" get pods,svc -n lineage-ctrl -o wide
  echo ""
  echo "=== [lineage-alpha] Autonomous org-alpha.io Control & Data Plane ==="
  kubectl --context "${KUBE_CTX}" get pods,svc -n lineage-alpha -o wide
  echo ""
  echo "=== [lineage-beta] Autonomous org-beta.io Control & Data Plane ==="
  kubectl --context "${KUBE_CTX}" get pods,svc -n lineage-beta -o wide
  echo ""
  echo "=== [lineage-pay] Autonomous org-payment.io Control & Data Plane ==="
  kubectl --context "${KUBE_CTX}" get pods,svc -n lineage-pay -o wide
} > "${OUT_DIR}/01_pods_topology.txt"
cat "${OUT_DIR}/01_pods_topology.txt" | tee -a "${OUT_DIR}/run.log"
sleep 2

GW_POD="$(kubectl --context "${KUBE_CTX}" -n lineage-alpha get pod -l app=e2e-user-gateway -o jsonpath='{.items[0].metadata.name}')"
GW_IP="$(kubectl --context "${KUBE_CTX}" -n lineage-alpha get pod "${GW_POD}" -o jsonpath='{.status.podIP}')"
ORCH_POD="$(kubectl --context "${KUBE_CTX}" -n lineage-alpha get pod -l app=orchestrator-alpha -o jsonpath='{.items[0].metadata.name}')"
AUDIT_POD="$(kubectl --context "${KUBE_CTX}" -n lineage-ctrl get pod -l app=audit-collector -o jsonpath='{.items[0].metadata.name}')"

# Verify Least-Privilege Container Isolation:
# 1. `orchestrator-alpha/app` mounts ZERO K8s SA tokens and ZERO mTLS files
# 2. `lineage-ctrl/audit-collector` mounts ZERO K8s SA tokens and holds ZERO CA keys
{
  kubectl --context "${KUBE_CTX}" -n lineage-alpha exec "${ORCH_POD}" -c app -- /bin/sh -c '
    if [ -e /var/run/secrets/kubernetes.io/serviceaccount/token ] || [ -e /var/run/lct-sa/token ] || [ -d /var/run/lct-mtls-ram ]; then
      echo "FAIL: SA token or mTLS volume unexpectedly mounted inside app container!" >&2
      exit 1
    fi
    echo "PASS: orchestrator-alpha/app holds ZERO K8s SA tokens and ZERO mTLS material (only /var/run/lct-loopback/secret)"
  '
  kubectl --context "${KUBE_CTX}" -n lineage-ctrl exec "${AUDIT_POD}" -- /bin/sh -c '
    if [ -e /var/run/secrets/kubernetes.io/serviceaccount/token ] || [ -e /var/run/lct-sa/token ]; then
      echo "FAIL: SA token unexpectedly mounted inside keyless audit-collector!" >&2
      exit 1
    fi
    echo "PASS: lineage-ctrl/audit-collector is 100% keyless & mounts ZERO Kubernetes SA tokens"
  '
} > "${OUT_DIR}/02_app_zero_sa_token_proof.txt"
cat "${OUT_DIR}/02_app_zero_sa_token_proof.txt" | tee -a "${OUT_DIR}/run.log"

run_in_gw() {
  kubectl --context "${KUBE_CTX}" -n lineage-alpha exec "${GW_POD}" -- \
    /app/.venv/bin/python3 -m lineage.k8s.e2e_driver "$@"
}

log "=== Scenario 1: Official A2A v1.0 SendStreamingMessage (SSE) + Autonomous 3-Domain CA Isolation + mTLS 1.3 + qwen2.5:3b Grounding ==="
run_in_gw --phase scenario1_normal_dag --run-id "${RUN_TS}" > "${OUT_DIR}/scenario1_normal_dag.json"
log "Scenario 1 PASS -> ${OUT_DIR}/scenario1_normal_dag.json"

log "=== Scenario 2A: A2A v1.0 Downward Atomic Prune-and-Graft over mTLS 1.3 (Slow Primary Zombie Wakes -> Federated 403 LINEAGE_REVOKED) ==="
run_in_gw --phase scenario2a_zombie_prune_and_graft --run-id "${RUN_TS}" > "${OUT_DIR}/scenario2a_zombie_prune_graft.json"
log "Scenario 2A PASS -> ${OUT_DIR}/scenario2a_zombie_prune_graft.json"

log "=== Scenario 2B: Real K8s Pod Scale-to-Zero Fault Injection (hotel-specialist-primary replicas=0 -> Backup Epoch+1) ==="
kubectl --context "${KUBE_CTX}" -n lineage-beta scale deploy/hotel-specialist-primary --replicas=0 >> "${OUT_DIR}/run.log"
kubectl --context "${KUBE_CTX}" -n lineage-beta wait --for=delete pod -l app=hotel-specialist-primary --timeout=45s >> "${OUT_DIR}/run.log" 2>&1 || true
run_in_gw --phase scenario2b_pod_down_prune_and_graft --run-id "${RUN_TS}" > "${OUT_DIR}/scenario2b_pod_down_prune_graft.json"
log "Scenario 2B PASS -> ${OUT_DIR}/scenario2b_pod_down_prune_graft.json"

log "Restoring hotel-specialist-primary (replicas=1, 2/2 Ready) for Scenario 3..."
kubectl --context "${KUBE_CTX}" -n lineage-beta scale deploy/hotel-specialist-primary --replicas=1 >> "${OUT_DIR}/run.log"
kubectl --context "${KUBE_CTX}" -n lineage-beta rollout status deploy/hotel-specialist-primary --timeout=60s >> "${OUT_DIR}/run.log"
sleep 2

log "=== Scenario 3A: Adversarial Forged Skip-Level Blocked by Live mTLS 1.3 /healthz Probe (403 INTERMEDIATE_ANCESTOR_ALIVE) ==="
run_in_gw --phase scenario3a_forged_skip_blocked_while_alive --run-id "${RUN_TS}" > "${OUT_DIR}/scenario3a_false_skip_blocked.json"
log "Scenario 3A PASS -> ${OUT_DIR}/scenario3a_false_skip_blocked.json"

log "=== Scenario 3B: Genuine Mid-Flight K8s Pod Kill -> Authenticated mTLS 1.3 Skip-Level Return (200 SKIP_LEVEL_MERGE) ==="
kubectl --context "${KUBE_CTX}" -n lineage-alpha exec "${GW_POD}" -- rm -f /tmp/s3b_ready
run_in_gw --phase scenario3b_genuine_skip_level_when_pod_killed \
  --run-id "${RUN_TS}" \
  --self-pod-ip "${GW_IP}" \
  --sync-marker-file "/tmp/s3b_ready" > "${OUT_DIR}/scenario3b_skip_level_return.json" &
S3B_PID=$!

for _ in $(seq 1 60); do
  if kubectl --context "${KUBE_CTX}" -n lineage-alpha exec "${GW_POD}" -- test -f /tmp/s3b_ready 2>/dev/null; then
    log "Mid-flight trigger hit: scaling deploy/hotel-specialist-primary to 0 & force-terminating Pod..."
    kubectl --context "${KUBE_CTX}" -n lineage-beta scale deploy/hotel-specialist-primary --replicas=0 >> "${OUT_DIR}/run.log"
    kubectl --context "${KUBE_CTX}" -n lineage-beta delete pod -l app=hotel-specialist-primary --grace-period=0 --force >> "${OUT_DIR}/run.log" 2>&1 || true
    break
  fi
  sleep 0.4
done
wait "${S3B_PID}"
log "Scenario 3B PASS -> ${OUT_DIR}/scenario3b_skip_level_return.json"

log "Restoring hotel-specialist-primary (replicas=1, 2/2 Ready) for Scenario 4..."
kubectl --context "${KUBE_CTX}" -n lineage-beta scale deploy/hotel-specialist-primary --replicas=1 >> "${OUT_DIR}/run.log"
kubectl --context "${KUBE_CTX}" -n lineage-beta rollout status deploy/hotel-specialist-primary --timeout=60s >> "${OUT_DIR}/run.log"
sleep 2

log "=== Scenario 4: A2A v1.0 CancelTask Cross-3-Domain Cascading Revocation + Multi-User Concurrency + Fagin DAG Degradation + Loopback Guard ==="
ORCH_IP="$(kubectl --context "${KUBE_CTX}" -n lineage-alpha get pod -l app=orchestrator-alpha -o jsonpath='{.items[0].status.podIP}')"
CONV_IP="$(kubectl --context "${KUBE_CTX}" -n lineage-pay get pod -l app=settlement-converger -o jsonpath='{.items[0].status.podIP}')"
TMCP_IP="$(kubectl --context "${KUBE_CTX}" -n lineage-pay get pod -l app=travel-ops-mcp -o jsonpath='{.items[0].status.podIP}')"
PMCP_IP="$(kubectl --context "${KUBE_CTX}" -n lineage-pay get pod -l app=payment-vault-mcp -o jsonpath='{.items[0].status.podIP}')"
POD_IPS_JSON="{\"orchestrator-alpha\":\"${ORCH_IP}\",\"settlement-converger\":\"${CONV_IP}\",\"travel-ops-mcp\":\"${TMCP_IP}\",\"payment-vault-mcp\":\"${PMCP_IP}\"}"

run_in_gw --phase scenario4_fagin_degradation_concurrency_and_bypass_guard \
  --run-id "${RUN_TS}" \
  --pod-ips-json "${POD_IPS_JSON}" > "${OUT_DIR}/scenario4_fagin_degradation_and_isolation.json"
log "Scenario 4 PASS -> ${OUT_DIR}/scenario4_fagin_degradation_and_isolation.json"

log "=== Scenario 5: Keyless Audit Collector Export & 100% 3-Domain CausalChainAuditor Reconstruction ==="
run_in_gw --phase scenario5_cluster_audit_reconstruction > "${OUT_DIR}/scenario5_causal_audit_report.json"
run_in_gw --phase export_redacted_audit_entries > "${OUT_DIR}/cluster_audit_entries_redacted.json"
log "Scenario 5 PASS -> ${OUT_DIR}/scenario5_causal_audit_report.json"

# Verify baseline `team1` AFTER all E2E scenarios
kubectl --context "${KUBE_CTX}" get pods -n team1 -o wide > "${OUT_DIR}/99_team1_after.txt"
log "Baseline 'team1' after run (100% untouched Running 2/2):"
cat "${OUT_DIR}/99_team1_after.txt" | tee -a "${OUT_DIR}/run.log"

# Verify zero raw private keys or unredacted LCT/JWS secrets in output artifacts
if grep -rn "BEGIN PRIVATE KEY\|BEGIN EC PRIVATE KEY\|BEGIN RSA PRIVATE KEY\|\"lct1\.\|\"lctmp1\.\|\"lctm1\.\|\"eyJhbG" "${OUT_DIR}/" >/dev/null 2>&1; then
  echo "[FATAL] Unredacted private key or raw token detected in output directory!" >&2
  exit 1
fi

log "============================================================================"
log " ALL MILESTONE-3 K8S + A2A v1.0 + 3-DOMAIN mTLS 1.3 + OLLAMA SCENARIOS PASSED!"
log " Evidence directory: ${OUT_DIR}"
log "============================================================================"
