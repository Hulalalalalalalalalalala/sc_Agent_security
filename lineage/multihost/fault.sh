#!/usr/bin/env bash
# =============================================================================
# LCT Multi-Host Fault Injection Helper (`lineage/multihost/fault.sh`)
#
# Run on the machine hosting the target role cluster:
#   bash lineage/multihost/fault.sh --kill hotel-primary [--fast]
#   bash lineage/multihost/fault.sh --restore hotel-primary
#   bash lineage/multihost/fault.sh --partition [--role beta|pay|alpha|audit]
#   bash lineage/multihost/fault.sh --heal      [--role beta|pay|alpha|audit]
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINEAGE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${LINEAGE_DIR}/.." && pwd)"

export PATH="${REPO_ROOT}/.tools/bin:${HOME}/.local/bin:${HOME}/.docker/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"

ACTION=""
TARGET=""
ROLE_FILTER=""
FAST_KILL="false"

usage() {
  cat <<'EOF'
Usage:
  bash lineage/multihost/fault.sh --kill hotel-primary [--fast]
  bash lineage/multihost/fault.sh --restore hotel-primary
  bash lineage/multihost/fault.sh --partition [--role beta|pay|alpha|audit]
  bash lineage/multihost/fault.sh --heal [--role beta|pay|alpha|audit]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kill) ACTION="kill"; TARGET="${2:-}"; shift 2 ;;
    --restore) ACTION="restore"; TARGET="${2:-}"; shift 2 ;;
    --partition) ACTION="partition"; shift ;;
    --heal) ACTION="heal"; shift ;;
    --role) ROLE_FILTER="${2:-}"; shift 2 ;;
    --fast) FAST_KILL="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "${ACTION}" ]]; then
  usage
  exit 2
fi

VALIDATED_ROLES=""
if [[ -n "${ROLE_FILTER}" ]]; then
  if [[ "${ROLE_FILTER}" == "all" ]]; then
    VALIDATED_ROLES="alpha beta pay audit"
  else
    parsed_roles=()
    IFS=',' read -r -a raw_role_items <<<"${ROLE_FILTER}"
    for item in "${raw_role_items[@]}"; do
      r_trimmed="$(echo "${item}" | tr -d '[:space:]')"
      case "${r_trimmed}" in
        alpha|beta|pay|audit)
          parsed_roles+=("${r_trimmed}")
          ;;
        *)
          echo "ERROR: Invalid --role value '${item}' (expected alpha|beta|pay|audit|all)" >&2
          exit 2
          ;;
      esac
    done
    if [[ ${#parsed_roles[@]} -eq 0 ]]; then
      echo "ERROR: --role must not be empty (expected alpha|beta|pay|audit|all)" >&2
      exit 2
    fi
    VALIDATED_ROLES="${parsed_roles[*]}"
  fi
fi

resolve_target_deployment() {
  case "$1" in
    hotel-primary|hotel-specialist-primary)
      echo "kind-lctmh-beta lineage-beta hotel-specialist-primary"
      ;;
    flight|flight-specialist)
      echo "kind-lctmh-beta lineage-beta flight-specialist"
      ;;
    converger|settlement-converger)
      echo "kind-lctmh-pay lineage-pay settlement-converger"
      ;;
    *)
      echo "ERROR: Unsupported target '$1' (expected hotel-primary, flight-specialist, or settlement-converger)" >&2
      exit 2
      ;;
  esac
}

if [[ "${ACTION}" == "kill" ]]; then
  read -r ctx ns dep <<<"$(resolve_target_deployment "${TARGET}")"
  echo "[fault] Terminating ${dep} in ${ctx} (${ns})..."
  kubectl --context "${ctx}" -n "${ns}" scale "deploy/${dep}" --replicas=0 >/dev/null
  if [[ "${FAST_KILL}" == "true" ]]; then
    kubectl --context "${ctx}" -n "${ns}" delete pod -l "app=${dep}" --grace-period=0 --force --ignore-not-found >/dev/null 2>&1 || true
  fi
  for _ in $(seq 1 40); do
    cnt="$(kubectl --context "${ctx}" -n "${ns}" get pods -l "app=${dep}" --no-headers 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "${cnt}" == "0" ]]; then
      break
    fi
    sleep 0.3
  done
  echo "[fault] ${dep} is now offline (replicas=0)."
  exit 0
fi

if [[ "${ACTION}" == "restore" ]]; then
  read -r ctx ns dep <<<"$(resolve_target_deployment "${TARGET}")"
  echo "[fault] Restoring ${dep} in ${ctx} (${ns}) to replicas=1..."
  kubectl --context "${ctx}" -n "${ns}" scale "deploy/${dep}" --replicas=1 >/dev/null
  kubectl --context "${ctx}" -n "${ns}" rollout status "deploy/${dep}" --timeout=90s >/dev/null
  echo "[fault] ${dep} is Ready (2/2 Running)."
  exit 0
fi

resolve_partition_roles() {
  if [[ -n "${VALIDATED_ROLES}" ]]; then
    echo "${VALIDATED_ROLES}"
    return
  fi
  local found=()
  for r in beta pay alpha audit; do
    if docker ps --format '{{.Names}}' | grep -qx "lctmh-${r}-control-plane"; then
      found+=("${r}")
    fi
  done
  if [[ ${#found[@]} -eq 0 ]]; then
    echo "ERROR: No running lctmh-* cluster containers found on this machine." >&2
    exit 1
  fi
  echo "${found[*]}"
}

partition_container() {
  local cname="$1"
  docker exec "${cname}" sh -ceu '
    APPLIED=0
    for bin in iptables-nft iptables-legacy iptables /usr/sbin/iptables; do
      if command -v "$bin" >/dev/null 2>&1 && "$bin" -L >/dev/null 2>&1; then
        APPLIED=1
        if "$bin" -t mangle -L >/dev/null 2>&1; then
          "$bin" -t mangle -N LCT_MH_MANGLE 2>/dev/null || "$bin" -t mangle -F LCT_MH_MANGLE
          "$bin" -t mangle -A LCT_MH_MANGLE -p tcp --dport 30000:32767 -j DROP
          "$bin" -t mangle -A LCT_MH_MANGLE -p tcp --sport 30000:32767 -j DROP
          for mch in PREROUTING OUTPUT; do
            "$bin" -t mangle -C "$mch" -j LCT_MH_MANGLE 2>/dev/null || "$bin" -t mangle -I "$mch" 1 -j LCT_MH_MANGLE
          done
        fi
        "$bin" -N LCT_MH_PARTITION 2>/dev/null || "$bin" -F LCT_MH_PARTITION
        "$bin" -A LCT_MH_PARTITION -p tcp --dport 30000:32767 -j DROP
        "$bin" -A LCT_MH_PARTITION -p tcp --sport 30000:32767 -j DROP
        for tbl in INPUT OUTPUT FORWARD DOCKER-USER; do
          if "$bin" -L "$tbl" >/dev/null 2>&1; then
            "$bin" -C "$tbl" -j LCT_MH_PARTITION 2>/dev/null || "$bin" -I "$tbl" 1 -j LCT_MH_PARTITION
          fi
        done
      fi
    done
    if [ "$APPLIED" -eq 0 ]; then
      echo "ERROR: No usable iptables binary inside container" >&2
      exit 1
    fi
  '
}

heal_container() {
  local cname="$1"
  docker exec "${cname}" sh -ceu '
    for bin in iptables-nft iptables-legacy iptables /usr/sbin/iptables; do
      if command -v "$bin" >/dev/null 2>&1 && "$bin" -L >/dev/null 2>&1; then
        if "$bin" -t mangle -L >/dev/null 2>&1; then
          for mch in PREROUTING OUTPUT; do
            while "$bin" -t mangle -D "$mch" -j LCT_MH_MANGLE 2>/dev/null; do :; done
          done
          "$bin" -t mangle -F LCT_MH_MANGLE 2>/dev/null || true
          "$bin" -t mangle -X LCT_MH_MANGLE 2>/dev/null || true
        fi
        for tbl in INPUT OUTPUT FORWARD DOCKER-USER; do
          while "$bin" -D "$tbl" -j LCT_MH_PARTITION 2>/dev/null; do :; done
        done
        "$bin" -F LCT_MH_PARTITION 2>/dev/null || true
        "$bin" -X LCT_MH_PARTITION 2>/dev/null || true
      fi
    done
  '
}

TARGET_ROLES="$(resolve_partition_roles)"
if [[ "${ACTION}" == "partition" ]]; then
  for r in ${TARGET_ROLES}; do
    cname="lctmh-${r}-control-plane"
    echo "[fault] Severing cross-machine traffic (TCP 30000-32767) on ${cname}..."
    partition_container "${cname}"
  done
  echo "[fault] Cross-machine network partition active on: ${TARGET_ROLES}"
  exit 0
fi

if [[ "${ACTION}" == "heal" ]]; then
  for r in ${TARGET_ROLES}; do
    cname="lctmh-${r}-control-plane"
    echo "[fault] Healing cross-machine traffic on ${cname}..."
    heal_container "${cname}"
  done
  echo "[fault] Cross-machine network healed on: ${TARGET_ROLES}"
  exit 0
fi
