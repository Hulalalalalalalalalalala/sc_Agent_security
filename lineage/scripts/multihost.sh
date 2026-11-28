#!/usr/bin/env bash
# =============================================================================
# Unified Identity-Addressed Multi-Host Operator Entrypoint (`lineage/scripts/multihost.sh`)
#
# Subcommands:
#   preflight       -> lineage/multihost/preflight.sh
#   deploy          -> lineage/multihost/deploy-role.sh
#   fault           -> lineage/multihost/fault.sh
#   teardown        -> lineage/multihost/teardown.sh
#   locator-agent   -> lineage/multihost/locator-agent.py
#   status|locator|seeds|trust|send|cancel|audit|e2e|update-peer-ips
#                   -> lineage/multihost/lct_multihost_cli.py
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
  preflight         Run host LAN IP, local port, LLM, and seed clock-skew preflight checks
  deploy            Build image, create lctmh-* role cluster(s), start locator-agent, and print anchors
  locator           Inspect own + learned signed domain descriptors and workload locators (`locator show`)
  seeds             Manage untrusted bootstrap seed endpoints (`seeds list|add|remove <ip:port>`)
  trust             Manage SSH-style SHA-256 domain trust anchors (`show|add|remove|import|fetch`)
  status            Inspect per-domain health and per-hop identity -> locator resolution
  send              Send real A2A v1.0 message (--text "..." [--stream]) across Alpha->Beta->Pay
  cancel            Invoke A2A CancelTask and verify cross-machine revocation propagation
  audit             Fetch and reconstruct cryptographic CausalChainAuditor report
  fault             Inject/heal faults (--kill/--restore hotel-primary, --partition/--heal)
  e2e               Run scenarios 1, 2A, 2B, 3A, 3B, 4, 5, 6 (auto-fault local or operator prompt)
  compare           Run 6-dimension empirical comparison (oauth_centralized vs oauth_federated vs lct)
  workspace-demo    Run Platform v2 symmetric peer Workspace Assistant suite (all 5 scenarios + DistributedAuditor)
  pi-demo           Run Milestone 11 Real-World Open-Source Pi Agent (qwen2.5:3b / cloud LLM) 2-Case-Study suite
  scale-bench       Run 4/12/24-peer distributed scaling & decentralized audit benchmark
  oauth             Export/import OAuth 2.0 client credentials across machines (`export-creds`, `import-creds`)
  locator-agent     Manage host-side self-locating daemon directly (`--detect-only`, `--set-role-ip`, `--stop`)
  teardown          Delete local lctmh-* clusters and stop locator-agent
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
  fault)
    exec bash "${MH_DIR}/fault.sh" "$@"
    ;;
  teardown)
    exec bash "${MH_DIR}/teardown.sh" "$@"
    ;;
  locator-agent)
    PY_BIN="$(resolve_python)"
    exec "${PY_BIN}" "${MH_DIR}/locator-agent.py" "$@"
    ;;
  scale-bench)
    PY_BIN="$(resolve_python)"
    exec "${PY_BIN}" -m lineage.scale.distributed_benchmark "$@"
    ;;
  status|locator|seeds|trust|send|cancel|audit|e2e|compare|workspace-demo|pi-demo|oauth|update-peer-ips)
    PY_BIN="$(resolve_python)"
    exec "${PY_BIN}" "${MH_DIR}/lct_multihost_cli.py" "${SUB}" "$@"
    ;;
  *)
    echo "ERROR: Unknown multihost subcommand '${SUB}'" >&2
    exit 2
    ;;
esac
