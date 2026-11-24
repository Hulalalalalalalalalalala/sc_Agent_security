#!/usr/bin/env bash
# =============================================================================
# LCT Identity-Addressed Multi-Host Role Deployer (`lineage/multihost/deploy-role.sh`)
#
# Deploys one or more roles (`alpha`, `beta`, `pay`, `audit`, or `all`) on the
# current machine with ZERO peer IP flags or static port conventions:
#   - Auto-allocates conflict-free local NodePorts (overridable via `--base-port` / `--port-override`)
#   - Starts host-side `locator-agent.py --daemon` to self-detect & publish signed LAN locators
#   - Accepts untrusted bootstrap `--seed <ip:port>` hints (and optional `--discover mdns`)
#   - Prints local `<domain> <anchor>` lines and shareable `--seed <ip:port>` endpoints
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

if [[ $# -gt 0 && "${1}" == "update-peer-ips" ]]; then
  cat >&2 <<'EOF'
[DEPRECATED] `update-peer-ips` and static CoreDNS IP addressing were removed in Milestone 7.
  - Host IP changes are now detected and re-signed automatically by `locator-agent.py` (0 pod restarts).
  - Inspect signed descriptors and workload locators: `bash lineage/scripts/multihost.sh locator show`
  - Add/remove bootstrap seed endpoints: `bash lineage/scripts/multihost.sh seeds add <ip:port>`
EOF
  exit 2
fi

ROLES_SPEC=""
ADVERTISE_IP=""
DISCOVER_MODE=""
SEEDS=()
BASE_PORT=""
PORT_OVERRIDES=()
ANCHORS_OUTPUT=""
LLM_URL="http://host.docker.internal:11434/v1"
LLM_MODEL="qwen2.5:3b"
SVID_TTL="1800"
IMAGE_TAG="${LCT_IMAGE_TAG:-lineage-lct:m8}"
KEYCLOAK_IMAGE="${LCT_KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.5.2}"
STS_ENGINE="auto"
DELEGATION_MODE="dual"
OAUTH_CREDS_FILE=""
AUTO_PIN_LOCAL="true"
WAIT_ALL_READY="false"
SKIP_PREFLIGHT="false"
REGENERATE_CA="false"

usage() {
  cat <<'EOF'
Usage:
  bash lineage/multihost/deploy-role.sh \
    --roles alpha|beta|pay|audit|all \
    [--seed <peer_ip:port>]... \
    [--advertise-ip <LAN_IPv4>] \
    [--discover mdns] \
    [--sts-engine auto|keycloak|lightweight|none] [--with-keycloak] \
    [--delegation-mode dual|lct|oauth_centralized|oauth_federated] \
    [--oauth-creds-file <file>] \
    [--base-port <30000..32700>] [--port-override <slot=port>]... \
    [--anchors-output <file>] \
    [--llm-url http://host.docker.internal:11434/v1] [--llm-model qwen2.5:3b] \
    [--svid-ttl 1800] [--no-auto-pin-local] [--wait-all-ready] [--skip-preflight]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --roles) ROLES_SPEC="${2:-}"; shift 2 ;;
    --seed) SEEDS+=("${2:-}"); shift 2 ;;
    --advertise-ip) ADVERTISE_IP="${2:-}"; shift 2 ;;
    --discover) DISCOVER_MODE="${2:-}"; shift 2 ;;
    --sts-engine) STS_ENGINE="${2:-}"; shift 2 ;;
    --with-keycloak) STS_ENGINE="auto"; shift ;;
    --without-keycloak) STS_ENGINE="lightweight"; shift ;;
    --keycloak-image) KEYCLOAK_IMAGE="${2:-}"; shift 2 ;;
    --delegation-mode) DELEGATION_MODE="${2:-}"; shift 2 ;;
    --oauth-creds-file) OAUTH_CREDS_FILE="${2:-}"; shift 2 ;;
    --base-port) BASE_PORT="${2:-}"; shift 2 ;;
    --port-override) PORT_OVERRIDES+=("${2:-}"); shift 2 ;;
    --anchors-output) ANCHORS_OUTPUT="${2:-}"; shift 2 ;;
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

if [[ -z "${ROLES_SPEC}" ]]; then
  echo "ERROR: --roles is required (e.g., --roles alpha)." >&2
  usage
  exit 2
fi

PY_BIN="$(resolve_python)"
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

if [[ "${SKIP_PREFLIGHT}" != "true" ]]; then
  PF_ARGS=(--roles "${ROLES_SPEC}" --llm-url "${LLM_URL}" --llm-model "${LLM_MODEL}")
  if [[ -n "${ADVERTISE_IP}" ]]; then
    PF_ARGS+=(--advertise-ip "${ADVERTISE_IP}")
  fi
  if [[ -n "${BASE_PORT}" ]]; then
    PF_ARGS+=(--base-port "${BASE_PORT}")
  fi
  for ov in ${PORT_OVERRIDES[@]+"${PORT_OVERRIDES[@]}"}; do
    PF_ARGS+=(--port-override "${ov}")
  done
  for s in ${SEEDS[@]+"${SEEDS[@]}"}; do
    PF_ARGS+=(--seed "${s}")
  done
  bash "${SCRIPT_DIR}/preflight.sh" "${PF_ARGS[@]}"
fi

# 1. Allocate conflict-free local NodePorts per role
ALLOC_ARGS=(allocate-ports --roles "${ROLES_SPEC}" --check-host-free)
if [[ -n "${BASE_PORT}" ]]; then
  ALLOC_ARGS+=(--base-port "${BASE_PORT}")
fi
for ov in ${PORT_OVERRIDES[@]+"${PORT_OVERRIDES[@]}"}; do
  ALLOC_ARGS+=(--port-override "${ov}")
done
ALL_ROLE_PORTS_JSON="$("${PY_BIN}" -m lineage.multihost.config_gen "${ALLOC_ARGS[@]}")"

# 2. Build `lineage-lct` container image locally
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

# 3. Resolve Kind node image (support offline `kindest/node:lct-local` or registry mirror override)
KIND_IMG_ARGS=()
if [[ -n "${KIND_NODE_IMAGE:-}" ]]; then
  KIND_IMG_ARGS=(--image "${KIND_NODE_IMAGE}")
elif docker image inspect kindest/node:lct-local >/dev/null 2>&1; then
  KIND_IMG_ARGS=(--image "kindest/node:lct-local")
fi

resolve_role_sts_engine() {
  local role_name="${1}"
  if [[ "${role_name}" == "audit" ]]; then
    echo "none"
    return
  fi
  case "${STS_ENGINE}" in
    none|lightweight|keycloak)
      echo "${STS_ENGINE}"
      return
      ;;
    auto)
      if [[ "${role_name}" == "alpha" ]]; then
        if docker image inspect "${KEYCLOAK_IMAGE}" >/dev/null 2>&1; then
          echo "keycloak"
          return
        fi
        echo "[deploy] Pulling '${KEYCLOAK_IMAGE}' for alpha STS..." >&2
        if docker pull "${KEYCLOAK_IMAGE}" >/dev/null 2>&1; then
          echo "keycloak"
          return
        fi
        echo "[deploy] '${KEYCLOAK_IMAGE}' unavailable offline; falling back to lightweight RFC 8693 STS." >&2
      fi
      echo "lightweight"
      return
      ;;
    *)
      echo "ERROR: Invalid --sts-engine '${STS_ENGINE}' (expected auto|keycloak|lightweight|none)." >&2
      exit 2
      ;;
  esac
}

load_image_into_kind_cluster() {
  local img_ref="${1}"
  local cl_name="${2}"
  if kind load docker-image "${img_ref}" --name "${cl_name}" >/dev/null 2>&1; then
    return 0
  fi
  local host_arch
  host_arch="$(docker info --format '{{.Architecture}}' 2>/dev/null | sed 's/x86_64/amd64/;s/aarch64/arm64/' || echo 'amd64')"
  if docker save --platform "linux/${host_arch}" "${img_ref}" 2>/dev/null | \
     docker exec -i "${cl_name}-control-plane" ctr --namespace=k8s.io images import --snapshotter=overlayfs - >/dev/null; then
    return 0
  fi
  docker save "${img_ref}" | \
    docker exec -i "${cl_name}-control-plane" ctr --namespace=k8s.io images import - >/dev/null
}

# 4. Create requested `lctmh-*` clusters & load image(s)
declare -a RESOLVED_STS_MAP=()
for r in ${ROLES_LIST}; do
  cname="lctmh-${r}"
  r_sts_eng="$(resolve_role_sts_engine "${r}")"
  RESOLVED_STS_MAP+=("${r}=${r_sts_eng}")
  role_ports_j="$("${PY_BIN}" -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])[sys.argv[2]]))" "${ALL_ROLE_PORTS_JSON}" "${r}")"
  if kind get clusters 2>/dev/null | grep -qx "${cname}"; then
    echo "[deploy] Kind cluster '${cname}' already exists; reusing."
  else
    echo "[deploy] Creating Kind cluster '${cname}' with local extraPortMappings (${role_ports_j})..."
    "${PY_BIN}" -m lineage.multihost.config_gen kind-config --role "${r}" --ports-json "${role_ports_j}" | \
      kind create cluster --name "${cname}" ${KIND_IMG_ARGS[@]+"${KIND_IMG_ARGS[@]}"} --config -
  fi
  restore_kube_context "${ORIG_KUBE_CTX}"
  echo "[deploy] Loading image '${IMAGE_TAG}' into '${cname}'..."
  load_image_into_kind_cluster "${IMAGE_TAG}" "${cname}"
  if [[ "${r_sts_eng}" == "keycloak" ]]; then
    if ! docker image inspect "${KEYCLOAK_IMAGE}" >/dev/null 2>&1; then
      docker pull "${KEYCLOAK_IMAGE}"
    fi
    echo "[deploy] Loading Keycloak image '${KEYCLOAK_IMAGE}' into '${cname}'..."
    load_image_into_kind_cluster "${KEYCLOAK_IMAGE}" "${cname}"
  fi
done

lookup_role_sts_engine() {
  local want="${1}"
  for kv in "${RESOLVED_STS_MAP[@]}"; do
    if [[ "${kv%%=*}" == "${want}" ]]; then
      echo "${kv#*=}"
      return
    fi
  done
  echo "lightweight"
}

# 5. Ensure CoreDNS has ZERO cross-domain LCT `hosts` entries (preserving `host.docker.internal`)
"${PY_BIN}" -m lineage.multihost.config_gen sanitize-coredns --roles "${ROLES_SPEC}"

# 6. Stream stable per-deployment CA root Secrets in memory & apply role manifests
ANCHOR_LINES=()
for r in ${ROLES_LIST}; do
  ctx="kind-lctmh-${r}"
  ns="lineage-${r}"
  role_ports_j="$("${PY_BIN}" -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])[sys.argv[2]]))" "${ALL_ROLE_PORTS_JSON}" "${r}")"
  regen_flag=()
  if [[ "${REGENERATE_CA}" == "true" ]]; then
    regen_flag=(--regenerate)
  fi
  anc_line="$("${PY_BIN}" -m lineage.multihost.config_gen ensure-ca-secret --role "${r}" ${regen_flag[@]+"${regen_flag[@]}"})"
  ANCHOR_LINES+=("${anc_line}")

  r_sts_eng="$(lookup_role_sts_engine "${r}")"
  oauth_sec_args=(ensure-oauth-secret --role "${r}" --sts-engine "${r_sts_eng}")
  if [[ "${REGENERATE_CA}" == "true" ]]; then
    oauth_sec_args+=(--regenerate)
  fi
  if [[ -n "${OAUTH_CREDS_FILE}" ]]; then
    oauth_sec_args+=(--oauth-creds-file "${OAUTH_CREDS_FILE}")
  fi
  "${PY_BIN}" -m lineage.multihost.config_gen "${oauth_sec_args[@]}" >/dev/null

  skip_cm_flag=()
  if kubectl --context "${ctx}" -n "${ns}" get configmap lct-trust-anchors >/dev/null 2>&1; then
    skip_cm_flag=(--skip-configmap)
  fi
  seed_flags=()
  for s in ${SEEDS[@]+"${SEEDS[@]}"}; do
    seed_flags+=(--seed "${s}")
  done
  echo "[deploy] Applying identity-addressed manifests for role '${r}' (ns=${ns}, sts=${r_sts_eng}, mode=${DELEGATION_MODE}, svid_ttl=${SVID_TTL}s)..."
  "${PY_BIN}" -m lineage.multihost.config_gen render-manifest \
    --role "${r}" \
    --image "${IMAGE_TAG}" \
    --llm-url "${LLM_URL}" \
    --llm-model "${LLM_MODEL}" \
    --svid-ttl "${SVID_TTL}" \
    --sts-engine "${r_sts_eng}" \
    --keycloak-image "${KEYCLOAK_IMAGE}" \
    --delegation-mode "${DELEGATION_MODE}" \
    --ports-json "${role_ports_j}" \
    ${seed_flags[@]+"${seed_flags[@]}"} \
    ${skip_cm_flag[@]+"${skip_cm_flag[@]}"} | kubectl --context "${ctx}" apply -f - >/dev/null

  # If re-applying onto existing cluster (`--skip-configmap`) and `--seed` was supplied, append seeds cleanly
  if [[ ${#SEEDS[@]} -gt 0 && ${#skip_cm_flag[@]} -gt 0 ]]; then
    "${PY_BIN}" "${SCRIPT_DIR}/lct_multihost_cli.py" seeds add "${SEEDS[@]}" --roles "${r}" >/dev/null
  fi
done

# 7. Start host-side `locator-agent.py --daemon` so `ConfigMap/lct-node-locator` is populated immediately
LOC_DAEMON_ARGS=(--daemon --roles "${ROLES_SPEC}")
if [[ -n "${ADVERTISE_IP}" ]]; then
  LOC_DAEMON_ARGS+=(--advertise-ip "${ADVERTISE_IP}")
fi
if [[ -n "${DISCOVER_MODE}" ]]; then
  LOC_DAEMON_ARGS+=(--discover "${DISCOVER_MODE}")
fi
DAEMON_INFO="$("${PY_BIN}" "${SCRIPT_DIR}/locator-agent.py" "${LOC_DAEMON_ARGS[@]}")"
echo "[deploy] Host self-locator agent active: ${DAEMON_INFO}"

# 8. Wait for each local role's autonomous CA & STS to become Ready immediately (zero peer dependency)
for r in ${ROLES_LIST}; do
  ctx="kind-lctmh-${r}"
  ns="lineage-${r}"
  r_sts_eng="$(lookup_role_sts_engine "${r}")"
  case "${r}" in
    alpha) ca_dep="alpha-ca"; sts_dep="alpha-sts" ;;
    beta)  ca_dep="beta-ca";  sts_dep="beta-sts" ;;
    pay)   ca_dep="payment-ca"; sts_dep="payment-sts" ;;
    audit) ca_dep="audit-ca"; sts_dep="" ;;
  esac
  echo "[deploy] Waiting for ${ca_dep} (${ctx}) to become Ready..."
  kubectl --context "${ctx}" -n "${ns}" rollout status "deploy/${ca_dep}" --timeout=90s >/dev/null
  if [[ -n "${sts_dep}" && "${r_sts_eng}" != "none" ]]; then
    echo "[deploy] Waiting for ${sts_dep} (${r_sts_eng}, ${ctx}) to become Ready..."
    kubectl --context "${ctx}" -n "${ns}" rollout status "deploy/${sts_dep}" --timeout=150s >/dev/null
  fi
done

# 9. Optionally pin trust anchors among roles co-deployed in the same invocation
if [[ "${AUTO_PIN_LOCAL}" == "true" && ${#ANCHOR_LINES[@]} -gt 1 ]]; then
  for anc_entry in "${ANCHOR_LINES[@]}"; do
    td="${anc_entry%% *}"
    anc_val="${anc_entry#* }"
    "${PY_BIN}" "${SCRIPT_DIR}/lct_multihost_cli.py" trust add "${td}" "${anc_val}" --roles "${ROLES_SPEC}" >/dev/null
  done
fi

if [[ -n "${ANCHORS_OUTPUT}" ]]; then
  mkdir -p "$(dirname "${ANCHORS_OUTPUT}")"
  for anc_entry in "${ANCHOR_LINES[@]}"; do
    td="${anc_entry%% *}"
    if [[ -f "${ANCHORS_OUTPUT}" ]]; then
      grep -v "^${td} " "${ANCHORS_OUTPUT}" > "${ANCHORS_OUTPUT}.tmp" || true
      mv "${ANCHORS_OUTPUT}.tmp" "${ANCHORS_OUTPUT}"
    fi
    echo "${anc_entry}" >> "${ANCHORS_OUTPUT}"
  done
  echo "[deploy] Wrote local trust anchor line(s) to ${ANCHORS_OUTPUT}"
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
echo " LCT Identity-Addressed Deployment Summary (Roles: ${ROLES_LIST})"
echo "============================================================================"
for r in ${ROLES_LIST}; do
  ctx="kind-lctmh-${r}"
  ns="lineage-${r}"
  echo "--- Cluster: lctmh-${r} (namespace: ${ns}) ---"
  kubectl --context "${ctx}" -n "${ns}" get pods -o wide
done

echo ""
echo "============================================================================"
echo " Shareable Seed Endpoint(s) & Domain Trust Anchor(s) for Peer Machines:"
echo "============================================================================"
for r in ${ROLES_LIST}; do
  seed_ep="$("${PY_BIN}" - "${r}" <<'PYEOF'
import json, subprocess, sys
role = sys.argv[1]
ctx = f"kind-lctmh-{role}"
ns = f"lineage-{role}"
p = subprocess.run(["kubectl", "--context", ctx, "-n", ns, "get", "cm", "lct-node-locator", "-o", "json"], capture_output=True, text=True)
if p.returncode == 0 and p.stdout.strip():
    d = json.loads(json.loads(p.stdout).get("data", {}).get("locator.json", "{}") or "{}")
    ca_port = (d.get("ports") or {}).get("ca_federation")
    locs = d.get("locators") or []
    if ca_port and locs:
        print(f"{locs[0]['host']}:{ca_port}")
PYEOF
)"
  if [[ -n "${seed_ep}" ]]; then
    echo "  [seed:${r}] --seed ${seed_ep}"
  fi
done
for anc_entry in "${ANCHOR_LINES[@]}"; do
  echo "  ${anc_entry}"
  td="${anc_entry%% *}"
  anc_val="${anc_entry#* }"
  echo "    -> Peer pin command: bash lineage/scripts/multihost.sh trust add ${td} ${anc_val}"
done
echo "============================================================================"
