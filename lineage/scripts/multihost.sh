#!/usr/bin/env bash
# =============================================================================
# Unified Multi-Host Operator Entrypoint (`lineage/scripts/multihost.sh`)
#
# Subcommands:
#   preflight       -> lineage/multihost/preflight.sh
#   deploy          -> lineage/multihost/deploy-role.sh
#   update-peer-ips -> lineage/multihost/deploy-role.sh update-peer-ips
#   fault           -> lineage/multihost/fault.sh
#   teardown        -> lineage/multihost/teardown.sh
#   status|trust|send|cancel|audit|e2e -> lineage/multihost/lct_multihost_cli.py
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINEAGE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${LINEAGE_DIR}/.." && pwd)"
MH_DIR="${LINEAGE_DIR}/multihost"

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
    if [[ -n "${cand}" && -x "${cand}" ]]; then
      echo "${cand}"
      return
    fi
  done
  echo "python3"
}

if [[ $# -lt 1 ]]; then
  cat <<'EOF'
Usage:
  bash lineage/scripts/multihost.sh <subcommand> [args...]

Subcommands:
  preflight         Run host port, LLM, peer TCP, and clock-skew preflight checks
  deploy            Build image, create lctmh-* role cluster(s), and print trust anchors
  update-peer-ips   Re-patch CoreDNS peer machine IPs without redeploying workloads
  fault             Inject/heal faults (--kill/--restore hotel-primary, --partition/--heal)
  teardown          Delete only local lctmh-* clusters
  status            Inspect per-domain health, resolved machine IPs, and AgentCards
  trust             Manage SSH-style SHA-256 domain trust anchors (show / add / fetch)
  send              Send real A2A v1.0 message (--text "..." [--stream]) across Alpha->Beta->Pay
  cancel            Invoke A2A CancelTask and verify cross-machine revocation propagation
  audit             Fetch and reconstruct cryptographic CausalChainAuditor report
  e2e               Run scenarios 1, 2A, 2B, 3A, 3B, 4, 5, 6 (auto-fault local or operator prompt)
EOF
  exit 0
fi

SUB="$1"
shift

case "${SUB}" in
  preflight)
    exec bash "${MH_DIR}/preflight.sh" "$@"
    ;;
  deploy)
    exec bash "${MH_DIR}/deploy-role.sh" "$@"
    ;;
  update-peer-ips)
    exec bash "${MH_DIR}/deploy-role.sh" update-peer-ips "$@"
    ;;
  fault)
    exec bash "${MH_DIR}/fault.sh" "$@"
    ;;
  teardown)
    exec bash "${MH_DIR}/teardown.sh" "$@"
    ;;
  status|trust|send|cancel|audit|e2e)
    PY_BIN="$(resolve_python)"
    exec "${PY_BIN}" "${MH_DIR}/lct_multihost_cli.py" "${SUB}" "$@"
    ;;
  *)
    echo "ERROR: Unknown multihost subcommand '${SUB}'" >&2
    exit 2
    ;;
esac
