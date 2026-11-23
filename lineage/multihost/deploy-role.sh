#!/usr/bin/env bash
# =============================================================================
# LCT Multi-Host Role Deployer & CoreDNS Updater (`lineage/multihost/deploy-role.sh`)
#
# Modes:
#   1. Deploy one or more roles on this machine:
#      bash lineage/multihost/deploy-role.sh \
#        --roles alpha,audit \
#        --alpha-ip <IP1> --beta-ip <IP2> --pay-ip <IP3> [--audit-ip <IP1>] \
#        [--llm-url http://host.docker.internal:11434/v1] [--llm-model qwen2.5:3b] \
#        [--svid-ttl 1800] [--no-auto-pin-local] [--wait-all-ready]
#
#   2. Update CoreDNS peer IPs in-place after DHCP change (zero Pod redeploy):
#      bash lineage/multihost/deploy-role.sh update-peer-ips \
#        [--roles alpha,audit] --alpha-ip <IP1> --beta-ip <IP2> --pay-ip <IP3> [--audit-ip <IP1>]
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINEAGE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${LINEAGE_DIR}/.." && pwd)"

export PATH="${REPO_ROOT}/.tools/bin:${REPO_ROOT}/.tools/ollama:${HOME}/.local/bin:${HOME}/.docker/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"
export PYTHONPATH="${REPO_ROOT}:${PYTHONPATH:-}"

resolve_python() {
  if [[ -n "${LCT_PYTHON:-}" && -x "${LCT_PYTHON}" ]]; then
    echo "${LCT_PYTHON}"
    return
  fi
  for cand in \
    "${REPO_ROOT}/.venv/bin/python3" \
    "${REPO_ROOT}/src/cortex/authbridge/venv/bin/python3" \
    "$(command -v python3 2>/dev/null || true)"; do
    if [[ -n "${cand}" && -x "${cand}" ]] && "${cand}" -c "import cryptography, httpx, yaml" >/dev/null 2>&1; then
      echo "${cand}"
      return
    fi
  done
  echo "ERROR: No Python 3.11+ interpreter with cryptography, httpx, and PyYAML found." >&2
  exit 1
}

SUBCMD="deploy"
if [[ $# -gt 0 && "${1}" == "update-peer-ips" ]]; then
  SUBCMD="update-peer-ips"
  shift
fi

ROLES_SPEC=""
ALPHA_IP=""
BETA_IP=""
PAY_IP=""
AUDIT_IP=""
LLM_URL="http://host.docker.internal:11434/v1"
LLM_MODEL="qwen2.5:3b"
SVID_TTL="1800"
IMAGE_TAG="${LCT_IMAGE_TAG:-lineage-lct:m6}"
AUTO_PIN_LOCAL="true"
WAIT_ALL_READY="false"
SKIP_PREFLIGHT="false"
REGENERATE_CA="false"

usage() {
  cat <<'EOF'
Usage:
  bash lineage/multihost/deploy-role.sh [update-peer-ips] \
    --roles alpha,audit|beta|pay|all \
    --alpha-ip <IPv4> --beta-ip <IPv4> --pay-ip <IPv4> [--audit-ip <IPv4>] \
    [--llm-url http://host.docker.internal:11434/v1] [--llm-model qwen2.5:3b] \
    [--svid-ttl 1800] [--no-auto-pin-local] [--wait-all-ready] [--skip-preflight]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --roles) ROLES_SPEC="${2:-}"; shift 2 ;;
    --alpha-ip) ALPHA_IP="${2:-}"; shift 2 ;;
    --beta-ip) BETA_IP="${2:-}"; shift 2 ;;
    --pay-ip) PAY_IP="${2:-}"; shift 2 ;;
    --audit-ip) AUDIT_IP="${2:-}"; shift 2 ;;
    --llm-url) LLM_URL="${2:-}"; shift 2 ;;
    --llm-model) LLM_MODEL="${2:-}"; shift 2 ;;
    --svid-ttl) SVID_TTL="${2:-}"; shift 2 ;;
    --image) IMAGE_TAG="${2:-}"; shift 2 ;;
    --no-auto-pin-local) AUTO_PIN_LOCAL="false"; shift ;;
    --wait-all-ready) WAIT_ALL_READY="true"; shift ;;
    --skip-preflight) SKIP_PREFLIGHT="true"; shift ;;
    --regenerate-ca) REGENERATE_CA="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

PY_BIN="$(resolve_python)"

# Auto-detect active local lctmh-* roles if `update-peer-ips` omitted `--roles`
if [[ "${SUBCMD}" == "update-peer-ips" && -z "${ROLES_SPEC}" ]]; then
  detected=()
  for r in alpha beta pay audit; do
    if kind get clusters 2>/dev/null | grep -qx "lctmh-${r}"; then
      detected+=("${r}")
    fi
  done
  if [[ ${#detected[@]} -eq 0 ]]; then
    echo "ERROR: No active lctmh-* clusters found on this machine." >&2
    exit 1
  fi
  ROLES_SPEC="$(IFS=,; echo "${detected[*]}")"
fi

if [[ -z "${ROLES_SPEC}" || -z "${ALPHA_IP}" || -z "${BETA_IP}" || -z "${PAY_IP}" ]]; then
  echo "ERROR: --roles, --alpha-ip, --beta-ip, and --pay-ip are required." >&2
  usage
  exit 2
fi

VALIDATED_IPS="$("${PY_BIN}" -m lineage.multihost.config_gen validate-ips \
  --alpha-ip "${ALPHA_IP}" --beta-ip "${BETA_IP}" --pay-ip "${PAY_IP}" --audit-ip "${AUDIT_IP}")"
AUDIT_IP="$("${PY_BIN}" -c "import json,sys; print(json.loads(sys.argv[1])['audit_ip'])" "${VALIDATED_IPS}")"
ROLES_LIST="$("${PY_BIN}" -m lineage.multihost.config_gen parse-roles --roles "${ROLES_SPEC}")"

restore_kube_context() {
  local orig="${1:-}"
  if kubectl config get-contexts -o name 2>/dev/null | grep -qx "kind-agent-identity-lab"; then
    kubectl config use-context "kind-agent-identity-lab" >/dev/null 2>&1 || true
  elif [[ -n "${orig}" ]] && kubectl config get-contexts -o name 2>/dev/null | grep -qx "${orig}"; then
    kubectl config use-context "${orig}" >/dev/null 2>&1 || true
  fi
}

ORIG_KUBE_CTX="$(kubectl config current-context 2>/dev/null || true)"
trap 'restore_kube_context "${ORIG_KUBE_CTX}"' EXIT

if [[ "${SUBCMD}" == "update-peer-ips" ]]; then
  echo "[update-peer-ips] Re-patching CoreDNS across local roles (${ROLES_LIST}) -> alpha=${ALPHA_IP}, beta=${BETA_IP}, pay=${PAY_IP}, audit=${AUDIT_IP}"
  "${PY_BIN}" -m lineage.multihost.config_gen patch-coredns \
    --roles "${ROLES_SPEC}" \
    --alpha-ip "${ALPHA_IP}" --beta-ip "${BETA_IP}" --pay-ip "${PAY_IP}" --audit-ip "${AUDIT_IP}"
  echo "[update-peer-ips] CoreDNS updated and rolled out cleanly with zero workload restarts."
  exit 0
fi

if [[ "${SKIP_PREFLIGHT}" != "true" ]]; then
  bash "${SCRIPT_DIR}/preflight.sh" \
    --roles "${ROLES_SPEC}" \
    --alpha-ip "${ALPHA_IP}" --beta-ip "${BETA_IP}" --pay-ip "${PAY_IP}" --audit-ip "${AUDIT_IP}" \
    --llm-url "${LLM_URL}" --llm-model "${LLM_MODEL}"
fi

# 1. Build `lineage-lct` container image locally
if [[ -n "${BASE_IMAGE:-}" ]]; then
  DOCKER_BASE_IMG="${BASE_IMAGE}"
elif docker image inspect ghcr.io/rossoctl/examples/weather_tool:pinned >/dev/null 2>&1; then
  DOCKER_BASE_IMG="ghcr.io/rossoctl/examples/weather_tool:pinned"
else
  DOCKER_BASE_IMG="python:3.12-slim"
fi
echo "[deploy] Building image '${IMAGE_TAG}' (BASE_IMAGE=${DOCKER_BASE_IMG})..."
docker build --build-arg "BASE_IMAGE=${DOCKER_BASE_IMG}" \
  -f "${LINEAGE_DIR}/k8s/Dockerfile" -t "${IMAGE_TAG}" "${REPO_ROOT}" >/dev/null

# 2. Resolve Kind node image (support offline `kindest/node:lct-local` or registry mirror override)
KIND_IMG_ARGS=()
if [[ -n "${KIND_NODE_IMAGE:-}" ]]; then
  KIND_IMG_ARGS=(--image "${KIND_NODE_IMAGE}")
elif docker image inspect kindest/node:lct-local >/dev/null 2>&1; then
  KIND_IMG_ARGS=(--image "kindest/node:lct-local")
fi

# 3. Create requested `lctmh-*` clusters & load image
for r in ${ROLES_LIST}; do
  cname="lctmh-${r}"
  if kind get clusters 2>/dev/null | grep -qx "${cname}"; then
    echo "[deploy] Kind cluster '${cname}' already exists; reusing."
  else
    echo "[deploy] Creating Kind cluster '${cname}' with host-NIC extraPortMappings..."
    "${PY_BIN}" -m lineage.multihost.config_gen kind-config --role "${r}" | \
      kind create cluster --name "${cname}" ${KIND_IMG_ARGS[@]+"${KIND_IMG_ARGS[@]}"} --config -
  fi
  restore_kube_context "${ORIG_KUBE_CTX}"
  echo "[deploy] Loading image '${IMAGE_TAG}' into '${cname}'..."
  kind load docker-image "${IMAGE_TAG}" --name "${cname}"
done

# 4. Patch CoreDNS with explicit machine LAN/VPN IPs
echo "[deploy] Patching CoreDNS zones (*.org-alpha.io, *.org-beta.io, *.org-payment.io, audit-collector.org-audit.io)..."
"${PY_BIN}" -m lineage.multihost.config_gen patch-coredns \
  --roles "${ROLES_SPEC}" \
  --alpha-ip "${ALPHA_IP}" --beta-ip "${BETA_IP}" --pay-ip "${PAY_IP}" --audit-ip "${AUDIT_IP}"

# 5. Stream stable per-deployment CA root Secrets in memory & apply role manifests
ANCHOR_LINES=()
for r in ${ROLES_LIST}; do
  ctx="kind-lctmh-${r}"
  ns="lineage-${r}"
  regen_flag=()
  if [[ "${REGENERATE_CA}" == "true" ]]; then
    regen_flag=(--regenerate)
  fi
  anc_line="$("${PY_BIN}" -m lineage.multihost.config_gen ensure-ca-secret --role "${r}" ${regen_flag[@]+"${regen_flag[@]}"})"
  ANCHOR_LINES+=("${anc_line}")

  skip_cm_flag=()
  if kubectl --context "${ctx}" -n "${ns}" get configmap lct-trust-anchors >/dev/null 2>&1; then
    skip_cm_flag=(--skip-configmap)
  fi
  echo "[deploy] Applying manifests for role '${r}' (ns=${ns}, svid_ttl=${SVID_TTL}s)..."
  "${PY_BIN}" -m lineage.multihost.config_gen render-manifest \
    --role "${r}" \
    --image "${IMAGE_TAG}" \
    --llm-url "${LLM_URL}" \
    --llm-model "${LLM_MODEL}" \
    --svid-ttl "${SVID_TTL}" \
    ${skip_cm_flag[@]+"${skip_cm_flag[@]}"} | kubectl --context "${ctx}" apply -f - >/dev/null
done

# 6. Wait for each local role's autonomous CA to become Ready immediately (zero peer dependency)
for r in ${ROLES_LIST}; do
  ctx="kind-lctmh-${r}"
  ns="lineage-${r}"
  case "${r}" in
    alpha) ca_dep="alpha-ca" ;;
    beta)  ca_dep="beta-ca" ;;
    pay)   ca_dep="payment-ca" ;;
    audit) ca_dep="audit-ca" ;;
  esac
  echo "[deploy] Waiting for ${ca_dep} (${ctx}) to become Ready..."
  kubectl --context "${ctx}" -n "${ns}" rollout status "deploy/${ca_dep}" --timeout=90s >/dev/null
done

# 7. Optionally pin trust anchors among roles co-deployed on this same machine
if [[ "${AUTO_PIN_LOCAL}" == "true" && ${#ANCHOR_LINES[@]} -gt 1 ]]; then
  for anc_entry in "${ANCHOR_LINES[@]}"; do
    td="${anc_entry%% *}"
    anc_val="${anc_entry#* }"
    "${PY_BIN}" "${SCRIPT_DIR}/lct_multihost_cli.py" trust add "${td}" "${anc_val}" --roles "${ROLES_SPEC}" >/dev/null
  done
fi

if [[ "${WAIT_ALL_READY}" == "true" ]]; then
  echo "[deploy] Waiting for all Deployments across (${ROLES_LIST}) to reach full Ready state..."
  for r in ${ROLES_LIST}; do
    ctx="kind-lctmh-${r}"
    ns="lineage-${r}"
    kubectl --context "${ctx}" -n "${ns}" wait --for=condition=Available deployment --all --timeout=120s >/dev/null
  done
fi

echo ""
echo "============================================================================"
echo " LCT Multi-Host Deployment Summary (Roles: ${ROLES_LIST})"
echo "============================================================================"
for r in ${ROLES_LIST}; do
  ctx="kind-lctmh-${r}"
  ns="lineage-${r}"
  echo "--- Cluster: lctmh-${r} (namespace: ${ns}) ---"
  kubectl --context "${ctx}" -n "${ns}" get pods -o wide
done

echo ""
echo "============================================================================"
echo " Local Domain Trust Anchor(s) — Share Out-of-Band & Pin on Peer Machines:"
echo "============================================================================"
for anc_entry in "${ANCHOR_LINES[@]}"; do
  echo "  ${anc_entry}"
  td="${anc_entry%% *}"
  anc_val="${anc_entry#* }"
  echo "    -> Peer command: python3 lineage/multihost/lct_multihost_cli.py trust add ${td} ${anc_val}"
done
echo "============================================================================"
