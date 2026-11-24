#!/usr/bin/env bash
# =============================================================================
# LCT Identity-Addressed Multi-Host Preflight Checker (`lineage/multihost/preflight.sh`)
#
# Validates:
#   1. Host primary LAN IPv4 auto-detection (or `--advertise-ip` override) — RFC1918 only
#   2. Docker daemon health, host CPU/RAM resources, `kind` & `kubectl` binaries
#   3. Local per-machine NodePort allocation & TCP conflict detection (`--base-port`, `--port-override`)
#   4. Local/shared Ollama endpoint reachability for `--llm-url` / `--llm-model`
#   5. Optional bootstrap `--seed <ip:port>` TCP reachability & RFC 9110 HTTP `Date` clock skew
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
  echo "ERROR: No Python 3.11+ interpreter with cryptography, httpx, and PyYAML found. Run: bash lineage/scripts/setup_deps.sh" >&2
  exit 1
}

ROLES_SPEC=""
ADVERTISE_IP=""
SEEDS=()
BASE_PORT=""
PORT_OVERRIDES=()
LLM_URL="http://host.docker.internal:11434/v1"
LLM_MODEL="qwen2.5:3b"
SKIP_LLM_CHECK="false"
REQUIRE_PEERS_UP="false"

usage() {
  cat <<'EOF'
Usage:
  bash lineage/multihost/preflight.sh \
    --roles alpha|beta|pay|audit|all \
    [--seed <peer_ip:port>]... \
    [--advertise-ip <LAN_IPv4>] \
    [--base-port <30000..32700>] [--port-override <slot=port>]... \
    [--llm-url http://host.docker.internal:11434/v1] [--llm-model qwen2.5:3b] \
    [--skip-llm-check] [--require-peers-up]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --roles) ROLES_SPEC="${2:-}"; shift 2 ;;
    --seed) SEEDS+=("${2:-}"); shift 2 ;;
    --advertise-ip) ADVERTISE_IP="${2:-}"; shift 2 ;;
    --base-port) BASE_PORT="${2:-}"; shift 2 ;;
    --port-override) PORT_OVERRIDES+=("${2:-}"); shift 2 ;;
    --llm-url) LLM_URL="${2:-}"; shift 2 ;;
    --llm-model) LLM_MODEL="${2:-}"; shift 2 ;;
    --skip-llm-check) SKIP_LLM_CHECK="true"; shift ;;
    --require-peers-up) REQUIRE_PEERS_UP="true"; shift ;;
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

# 1. Host LAN IPv4 self-detection (or --advertise-ip validation)
DETECT_ARGS=(--detect-only)
if [[ -n "${ADVERTISE_IP}" ]]; then
  DETECT_ARGS+=(--advertise-ip "${ADVERTISE_IP}")
fi
DETECTED_JSON="$("${PY_BIN}" "${SCRIPT_DIR}/locator-agent.py" "${DETECT_ARGS[@]}")"
DETECTED_SUMMARY="$("${PY_BIN}" -c "import json,sys; d=json.loads(sys.argv[1])['locators']; print(', '.join(f\"{x['host']} ({x['source']}, prio={x['priority']})\" for x in d))" "${DETECTED_JSON}")"

# 2. Dynamic local NodePort allocation & conflict check
ALLOC_ARGS=(allocate-ports --roles "${ROLES_SPEC}" --check-host-free)
if [[ -n "${BASE_PORT}" ]]; then
  ALLOC_ARGS+=(--base-port "${BASE_PORT}")
fi
for ov in ${PORT_OVERRIDES[@]+"${PORT_OVERRIDES[@]}"}; do
  ALLOC_ARGS+=(--port-override "${ov}")
done
PORTS_JSON="$("${PY_BIN}" -m lineage.multihost.config_gen "${ALLOC_ARGS[@]}")"

echo "============================================================================"
echo " LCT Identity-Addressed Multi-Host Preflight Check"
echo "============================================================================"
echo "  Local Roles     : ${ROLES_LIST}"
echo "  Self-Locator IP : ${DETECTED_SUMMARY}"
echo "  Local NodePorts : ${PORTS_JSON}"
echo "  Bootstrap Seeds : ${SEEDS[*]:-(none — initial seed node or mDNS)}"
echo "  LLM Endpoint    : ${LLM_URL} (model=${LLM_MODEL})"

# 3. Binary & Docker checks
for bin_name in docker kind kubectl; do
  if ! command -v "${bin_name}" >/dev/null 2>&1; then
    echo "[FAIL] Required CLI binary '${bin_name}' not found in PATH." >&2
    exit 1
  fi
done
echo "  [OK] Tooling    : docker, kind, kubectl present"

if ! docker info >/dev/null 2>&1; then
  echo "[FAIL] Docker daemon is not running or current user lacks socket permissions." >&2
  exit 1
fi
DOCKER_CPU_MEM="$(docker info --format 'CPUs={{.NCPU}} MemBytes={{.MemTotal}}' 2>/dev/null || echo 'unknown')"
echo "  [OK] Docker     : daemon reachable (${DOCKER_CPU_MEM})"
echo "  [OK] Ports      : local NodePorts verified conflict-free on 0.0.0.0"

# 4. Ollama LLM check (needed for alpha/beta/pay agent roles unless --skip-llm-check)
NEEDS_LLM="false"
for r in ${ROLES_LIST}; do
  if [[ "${r}" == "alpha" || "${r}" == "beta" || "${r}" == "pay" ]]; then
    NEEDS_LLM="true"
  fi
done
if [[ "${NEEDS_LLM}" == "true" && "${SKIP_LLM_CHECK}" != "true" ]]; then
  HOST_TEST_LLM_URL="${LLM_URL/host.docker.internal/127.0.0.1}"
  HOST_MODELS_URL="${HOST_TEST_LLM_URL%/}/models"
  if ! "${PY_BIN}" - "${HOST_MODELS_URL}" "${LLM_MODEL}" <<'PYEOF'
import sys, httpx
url, model = sys.argv[1], sys.argv[2]
with httpx.Client(timeout=4.0, trust_env=False) as client:
    r = client.get(url)
r.raise_for_status()
models = [m.get("id", "") for m in r.json().get("data", [])]
if model not in models and f"{model}:latest" not in models:
    print(f"WARN: Ollama reachable at {url}, but model {model!r} not in {models}", file=sys.stderr)
    sys.exit(3)
PYEOF
  then
    echo "[FAIL] Ollama endpoint '${HOST_MODELS_URL}' or model '${LLM_MODEL}' is not ready." >&2
    echo "       Start Ollama (`ollama serve`) and ensure `ollama pull ${LLM_MODEL}` has completed." >&2
    exit 1
  fi
  echo "  [OK] LLM        : ${HOST_MODELS_URL} reachable with model '${LLM_MODEL}'"
fi

# 5. Optional Seed TCP reachability & RFC 9110 HTTP Date clock-skew check
check_seed_skew_and_tcp() {
  local raw_seed="$1"
  local norm_seed
  norm_seed="$("${PY_BIN}" -c "import sys; from lineage.common.locators import normalize_seed_endpoint; print(normalize_seed_endpoint(sys.argv[1]))" "${raw_seed}")"
  local peer_ip="${norm_seed%:*}"
  local health_port="${norm_seed##*:}"
  local url="http://${peer_ip}:${health_port}"

  if "${PY_BIN}" -c "import socket,sys; s=socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1.5); s.close()" "${peer_ip}" "${health_port}" >/dev/null 2>&1; then
    local skew_json="" skew_rc=0
    set +e
    skew_json="$("${PY_BIN}" -m lineage.multihost.config_gen check-skew --url "${url}" --timeout 3.0 2>/dev/null)"
    skew_rc=$?
    set -e
    if [[ ${skew_rc} -eq 0 ]]; then
      local st skew_s
      st="$("${PY_BIN}" -c "import json,sys; print(json.loads(sys.argv[1])['status'])" "${skew_json}")"
      skew_s="$("${PY_BIN}" -c "import json,sys; print(json.loads(sys.argv[1])['skew_seconds'])" "${skew_json}")"
      if [[ "${st}" == "WARN" ]]; then
        echo "  [WARN] Clock skew vs seed (${url}): ${skew_s}s (> 10s warning threshold; sync NTP soon!)"
      else
        echo "  [OK] Seed (${url}): reachable, clock skew=${skew_s}s (<= 10s)"
      fi
    elif [[ ${skew_rc} -eq 2 ]]; then
      echo "[FAIL] Clock skew vs seed (${url}) EXCEEDS 25s DPoP/PoP safety window!" >&2
      echo "       Details: ${skew_json}" >&2
      echo "       Synchronize system clocks via NTP before federation (macOS: sudo sntp -sS time.apple.com; Linux: sudo chronyc makestep; Windows: w32tm /resync)." >&2
      exit 1
    else
      if [[ "${REQUIRE_PEERS_UP}" == "true" ]]; then
        echo "[FAIL] Seed (${url}) TCP port bound, but HTTP /healthz not ready yet (--require-peers-up)." >&2
        exit 1
      fi
      echo "  [INFO] Seed (${url}): TCP port bound, service initializing (order-independent boot)"
    fi
  else
    if [[ "${REQUIRE_PEERS_UP}" == "true" ]]; then
      echo "[FAIL] Seed (${norm_seed}) is not reachable (--require-peers-up)." >&2
      exit 1
    fi
    echo "  [INFO] Seed (${norm_seed}): not online yet (order-independent boot supported)"
  fi
}

for s in ${SEEDS[@]+"${SEEDS[@]}"}; do
  check_seed_skew_and_tcp "${s}"
done

echo "============================================================================"
echo "[PREFLIGHT PASS] Ready to deploy role(s): ${ROLES_LIST}"
echo "============================================================================"
