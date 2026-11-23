#!/usr/bin/env bash
# =============================================================================
# LCT Multi-Host Preflight Checker (`lineage/multihost/preflight.sh`)
#
# Validates:
#   1. Strict IPv4 peer parameters (`--alpha-ip`, `--beta-ip`, `--pay-ip`, `--audit-ip`)
#   2. Docker daemon health, host CPU/RAM resources, `kind` & `kubectl` binaries
#   3. Local/shared Ollama endpoint reachability for `--llm-url` / `--llm-model`
#   4. Host TCP port conflict detection (`extraPortMappings` ports per local role)
#   5. Peer TCP port reachability & RFC 9110 HTTP `Date` clock skew (`warn > 10s`, `fail > 25s`)
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
ALPHA_IP=""
BETA_IP=""
PAY_IP=""
AUDIT_IP=""
LLM_URL="http://host.docker.internal:11434/v1"
LLM_MODEL="qwen2.5:3b"
SKIP_LLM_CHECK="false"
REQUIRE_PEERS_UP="false"

usage() {
  cat <<'EOF'
Usage:
  bash lineage/multihost/preflight.sh \
    --roles alpha,audit|beta|pay|all \
    --alpha-ip <IPv4> --beta-ip <IPv4> --pay-ip <IPv4> [--audit-ip <IPv4>] \
    [--llm-url http://host.docker.internal:11434/v1] [--llm-model qwen2.5:3b] \
    [--skip-llm-check] [--require-peers-up]
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
    --skip-llm-check) SKIP_LLM_CHECK="true"; shift ;;
    --require-peers-up) REQUIRE_PEERS_UP="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "${ROLES_SPEC}" || -z "${ALPHA_IP}" || -z "${BETA_IP}" || -z "${PAY_IP}" ]]; then
  echo "ERROR: --roles, --alpha-ip, --beta-ip, and --pay-ip are required." >&2
  usage
  exit 2
fi

PY_BIN="$(resolve_python)"
VALIDATED_IPS="$("${PY_BIN}" -m lineage.multihost.config_gen validate-ips \
  --alpha-ip "${ALPHA_IP}" --beta-ip "${BETA_IP}" --pay-ip "${PAY_IP}" --audit-ip "${AUDIT_IP}")"
AUDIT_IP="$("${PY_BIN}" -c "import json,sys; print(json.loads(sys.argv[1])['audit_ip'])" "${VALIDATED_IPS}")"
ROLES_LIST="$("${PY_BIN}" -m lineage.multihost.config_gen parse-roles --roles "${ROLES_SPEC}")"
LOCAL_PORTS="$("${PY_BIN}" -m lineage.multihost.config_gen role-ports --roles "${ROLES_SPEC}")"

echo "============================================================================"
echo " LCT Multi-Host Preflight Check"
echo "============================================================================"
echo "  Local Roles   : ${ROLES_LIST}"
echo "  Machine IPs   : alpha=${ALPHA_IP}, beta=${BETA_IP}, pay=${PAY_IP}, audit=${AUDIT_IP}"
echo "  Host Ports    : ${LOCAL_PORTS}"
echo "  LLM Endpoint  : ${LLM_URL} (model=${LLM_MODEL})"

# 1. Binary & Docker checks
for bin_name in docker kind kubectl; do
  if ! command -v "${bin_name}" >/dev/null 2>&1; then
    echo "[FAIL] Required CLI binary '${bin_name}' not found in PATH." >&2
    exit 1
  fi
done
if command -v helm >/dev/null 2>&1; then
  echo "  [OK] Tooling  : docker, kind, kubectl, helm present"
else
  echo "  [OK] Tooling  : docker, kind, kubectl present (helm optional for multi-host)"
fi

if ! docker info >/dev/null 2>&1; then
  echo "[FAIL] Docker daemon is not running or current user lacks socket permissions." >&2
  exit 1
fi

DOCKER_CPU_MEM="$(docker info --format 'CPUs={{.NCPU}} MemBytes={{.MemTotal}}' 2>/dev/null || echo 'unknown')"
echo "  [OK] Docker   : daemon reachable (${DOCKER_CPU_MEM})"

# 2. Host TCP port conflict detection (allow existing lctmh-<role>-control-plane on re-run)
EXISTING_LCTMH_PORTS=""
for r in ${ROLES_LIST}; do
  cname="lctmh-${r}-control-plane"
  if docker ps --format '{{.Names}}' | grep -qx "${cname}"; then
    r_ports="$("${PY_BIN}" -m lineage.multihost.config_gen role-ports --roles "${r}")"
    EXISTING_LCTMH_PORTS="${EXISTING_LCTMH_PORTS} ${r_ports}"
  fi
done

PORT_CONFLICTS=()
for p in ${LOCAL_PORTS}; do
  if [[ " ${EXISTING_LCTMH_PORTS} " == *" ${p} "* ]]; then
    echo "  [OK] Port ${p} : already bound by active lctmh cluster container (re-entrant)"
    continue
  fi
  in_use="false"
  conflict_detail=""
  if command -v lsof >/dev/null 2>&1; then
    if conflict_detail="$(lsof -nP -iTCP:"${p}" -sTCP:LISTEN 2>/dev/null | tail -n +2)" && [[ -n "${conflict_detail}" ]]; then
      in_use="true"
    fi
  elif command -v ss >/dev/null 2>&1; then
    if conflict_detail="$(ss -ltn "sport = :${p}" 2>/dev/null | tail -n +2)" && [[ -n "${conflict_detail}" ]]; then
      in_use="true"
    fi
  fi
  if [[ "${in_use}" == "false" ]]; then
    if ! "${PY_BIN}" -c "import socket,sys; s=socket.socket(); s.bind(('0.0.0.0', int(sys.argv[1]))); s.close()" "${p}" >/dev/null 2>&1; then
      in_use="true"
      conflict_detail="socket.bind(('0.0.0.0', ${p})) failed (port already in use)"
    fi
  fi
  if [[ "${in_use}" == "true" ]]; then
    echo "[FAIL] Host TCP port ${p} is already in use:" >&2
    echo "       ${conflict_detail}" >&2
    PORT_CONFLICTS+=("${p}")
  fi
done

if [[ ${#PORT_CONFLICTS[@]} -gt 0 ]]; then
  echo "[FAIL] Preflight aborted due to host TCP port conflict(s): ${PORT_CONFLICTS[*]}" >&2
  exit 1
fi
echo "  [OK] Ports    : all requested host ports (${LOCAL_PORTS}) are available"

# 3. Ollama LLM check (needed for alpha/beta/pay agent roles unless --skip-llm-check)
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
  echo "  [OK] LLM      : ${HOST_MODELS_URL} reachable with model '${LLM_MODEL}'"
fi

# 4. Peer TCP reachability & RFC 9110 HTTP Date clock-skew check
check_peer_skew_and_tcp() {
  local role_lbl="$1" peer_ip="$2" scheme="$3" health_port="$4"
  local url="${scheme}://${peer_ip}:${health_port}"
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
        echo "  [WARN] Clock skew vs ${role_lbl} (${url}): ${skew_s}s (> 10s warning threshold; sync NTP soon!)"
      else
        echo "  [OK] Peer ${role_lbl} (${url}): reachable, clock skew=${skew_s}s (<= 10s)"
      fi
    elif [[ ${skew_rc} -eq 2 ]]; then
      echo "[FAIL] Clock skew vs ${role_lbl} (${url}) EXCEEDS 25s DPoP/PoP safety window!" >&2
      echo "       Details: ${skew_json}" >&2
      echo "       Synchronize system clocks via NTP before federation (macOS: sudo sntp -sS time.apple.com; Linux: sudo chronyc makestep; Windows: w32tm /resync)." >&2
      exit 1
    else
      if [[ "${REQUIRE_PEERS_UP}" == "true" ]]; then
        echo "[FAIL] Peer ${role_lbl} (${url}) TCP port bound, but HTTP /healthz not ready yet (--require-peers-up)." >&2
        exit 1
      fi
      echo "  [INFO] Peer ${role_lbl} (${url}): TCP port bound, service initializing (order-independent boot)"
    fi
  else
    if [[ "${REQUIRE_PEERS_UP}" == "true" ]]; then
      echo "[FAIL] Peer ${role_lbl} (${peer_ip}:${health_port}) is not reachable (--require-peers-up)." >&2
      exit 1
    fi
    echo "  [INFO] Peer ${role_lbl} (${peer_ip}:${health_port}): not online yet (order-independent boot supported)"
  fi
}

check_peer_skew_and_tcp "alpha" "${ALPHA_IP}" "http" "30094"
check_peer_skew_and_tcp "beta"  "${BETA_IP}"  "http" "31094"
check_peer_skew_and_tcp "pay"   "${PAY_IP}"   "http" "32094"
check_peer_skew_and_tcp "audit" "${AUDIT_IP}" "https" "30893"

echo "============================================================================"
echo "[PREFLIGHT PASS] Ready to deploy role(s): ${ROLES_LIST}"
echo "============================================================================"
