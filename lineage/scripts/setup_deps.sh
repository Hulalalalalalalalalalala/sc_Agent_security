#!/usr/bin/env bash
# =============================================================================
# Lineage Capability Tree (LCT) — Portable Dependency & Toolchain Bootstrapper
#
# Configures local virtualenvs, polyglot SDK dependency directories (`python`,
# `go`, `node`, `java`, `rust`), and optional K8s/Ollama binaries that are
# intentionally excluded from Git via `.gitignore`.
#
# Usage:
#   bash lineage/scripts/setup_deps.sh --check
#   bash lineage/scripts/setup_deps.sh --lang python
#   bash lineage/scripts/setup_deps.sh --lang all
#   bash lineage/scripts/setup_deps.sh --install-k8s-tools
#   bash lineage/scripts/setup_deps.sh --with-baseline-src
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

MODE_CHECK="false"
TARGET_LANG="python"
FORCE_VENV="false"
INSTALL_K8S_TOOLS="false"
WITH_BASELINE_SRC="false"

while [ $# -gt 0 ]; do
  case "$1" in
    --check)
      MODE_CHECK="true"
      shift
      ;;
    --lang)
      TARGET_LANG="${2:?--lang requires python|go|node|java|rust|all}"
      shift 2
      ;;
    --force-venv)
      FORCE_VENV="true"
      shift
      ;;
    --install-k8s-tools)
      INSTALL_K8S_TOOLS="true"
      shift
      ;;
    --with-baseline-src)
      WITH_BASELINE_SRC="true"
      shift
      ;;
    -h|--help)
      sed -n '2,15p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "[setup_deps] Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

detect_active_python() {
  local c
  for c in \
    "${REPO_ROOT}/.venv/bin/python3" \
    "${LINEAGE_DIR}/.venv/bin/python3" \
    "${REPO_ROOT}/src/cortex/authbridge/venv/bin/python3" \
    "$(command -v python3 2>/dev/null || true)"; do
    if [ -n "${c}" ] && [ -x "${c}" ]; then
      echo "${c}"
      return 0
    fi
  done
  echo ""
}

has_real_javac() {
  command -v javac >/dev/null 2>&1 && javac -version >/dev/null 2>&1
}

run_check_report() {
  echo "============================================================================"
  echo " LCT Dependency & Polyglot Toolchain Status Report"
  echo "============================================================================"
  echo "  REPO_ROOT    : ${REPO_ROOT}"
  echo "  LINEAGE_DIR  : ${LINEAGE_DIR}"
  echo ""

  local py_bin
  py_bin="$(detect_active_python)"
  if [ -n "${py_bin}" ] && "${py_bin}" -c "import cryptography, httpx, yaml, jwcrypto" >/dev/null 2>&1; then
    echo "  [OK] Python LCT Runtime   : ${py_bin} ($("${py_bin}" --version 2>&1))"
  elif [ -n "${py_bin}" ]; then
    echo "  [WARN] Python Found       : ${py_bin} (missing LCT packages; run setup_deps.sh --lang python)"
  else
    echo "  [MISS] Python 3.11+       : not found"
  fi

  if command -v go >/dev/null 2>&1; then
    echo "  [OK] Go SDK Toolchain     : $(command -v go) ($(go version))"
  else
    echo "  [INFO] Go SDK Toolchain   : not installed on host (use lineage/sdk/go/Dockerfile)"
  fi

  if command -v node >/dev/null 2>&1; then
    echo "  [OK] Node.js SDK Runtime  : $(command -v node) ($(node -v))"
  else
    echo "  [INFO] Node.js Runtime    : not installed on host (use lineage/sdk/node/Dockerfile)"
  fi

  if has_real_javac; then
    echo "  [OK] Java JDK Toolchain   : $(command -v javac) ($(javac -version 2>&1))"
  else
    echo "  [INFO] Java JDK Toolchain : not installed on host (use lineage/sdk/java/Dockerfile)"
  fi

  if command -v cargo >/dev/null 2>&1; then
    echo "  [OK] Rust Cargo Toolchain : $(command -v cargo) ($(cargo --version))"
  else
    echo "  [INFO] Rust Toolchain     : not installed on host (use lineage/sdk/rust/Dockerfile)"
  fi

  echo ""
  for bin_name in docker kind kubectl helm ollama; do
    if command -v "${bin_name}" >/dev/null 2>&1; then
      echo "  [OK] K8s/LLM Binary       : ${bin_name} -> $(command -v "${bin_name}")"
    else
      echo "  [INFO] K8s/LLM Binary     : ${bin_name} not in PATH (run setup_deps.sh --install-k8s-tools)"
    fi
  done
  echo "============================================================================"
}

if [ "${MODE_CHECK}" = "true" ]; then
  run_check_report
  exit 0
fi

setup_python_deps() {
  local existing_py
  existing_py="$(detect_active_python)"
  if [ "${FORCE_VENV}" = "false" ] && [ -n "${existing_py}" ] && \
     "${existing_py}" -c "import cryptography, httpx, yaml, jwcrypto" >/dev/null 2>&1; then
    echo "[setup_deps:python] Verified ready Python environment at ${existing_py}"
    return 0
  fi

  local base_py
  base_py="$(command -v python3 || true)"
  if [ -z "${base_py}" ]; then
    echo "[setup_deps:python] ERROR: python3 (>=3.11) is required to create .venv" >&2
    exit 1
  fi
  local venv_dir="${REPO_ROOT}/.venv"
  echo "[setup_deps:python] Creating virtualenv at ${venv_dir}..."
  "${base_py}" -m venv "${venv_dir}"
  "${venv_dir}/bin/pip" install --upgrade pip >/dev/null
  "${venv_dir}/bin/pip" install -r "${LINEAGE_DIR}/requirements.txt"
  "${venv_dir}/bin/python3" -c "import cryptography, httpx, yaml, jwcrypto; print('[setup_deps:python] Verified cryptography, httpx, PyYAML, jwcrypto OK')"
}

setup_go_deps() {
  mkdir -p "${LINEAGE_DIR}/sdk/go/bin"
  if ! command -v go >/dev/null 2>&1; then
    echo "[setup_deps:go] Go toolchain not found on host; prepared ${LINEAGE_DIR}/sdk/go/bin (use lineage/sdk/go/Dockerfile for container builds)."
    return 0
  fi
  (
    cd "${LINEAGE_DIR}/sdk/go"
    go vet ./...
  )
  echo "[setup_deps:go] Verified Go module (${LINEAGE_DIR}/sdk/go/go.mod) & 'go vet ./...' OK"
}

setup_node_deps() {
  if ! command -v node >/dev/null 2>&1; then
    echo "[setup_deps:node] Node.js not found on host (use lineage/sdk/node/Dockerfile for container builds)."
    return 0
  fi
  node --check "${LINEAGE_DIR}/sdk/node/lct_sdk.mjs"
  node --check "${LINEAGE_DIR}/sdk/node/example_agent.mjs"
  echo "[setup_deps:node] Verified Node.js 18+ zero-dep ESM SDK (${LINEAGE_DIR}/sdk/node/package.json) OK"
}

setup_java_deps() {
  mkdir -p "${LINEAGE_DIR}/sdk/java/target/classes"
  if has_real_javac; then
    javac -d "${LINEAGE_DIR}/sdk/java/target/classes" "${LINEAGE_DIR}/sdk/java/LCTSidecarClient.java"
    echo "[setup_deps:java] Compiled LCTSidecarClient.java -> ${LINEAGE_DIR}/sdk/java/target/classes OK"
  else
    echo "[setup_deps:java] Prepared ${LINEAGE_DIR}/sdk/java/target/classes (host JDK absent; build via 'docker build -f lineage/sdk/java/Dockerfile lineage/sdk/java' or install Temurin JDK 17+)."
  fi
}

setup_rust_deps() {
  mkdir -p "${LINEAGE_DIR}/sdk/rust/target"
  if command -v cargo >/dev/null 2>&1; then
    cargo check --manifest-path "${LINEAGE_DIR}/sdk/rust/Cargo.toml"
    echo "[setup_deps:rust] Verified Cargo crate (${LINEAGE_DIR}/sdk/rust/Cargo.toml) OK"
  else
    echo "[setup_deps:rust] Prepared ${LINEAGE_DIR}/sdk/rust/target (host Cargo absent; build via 'docker build -f lineage/sdk/rust/Dockerfile lineage/sdk/rust' or install rustup)."
  fi
}

install_k8s_tools() {
  local tools_bin="${REPO_ROOT}/.tools/bin"
  mkdir -p "${tools_bin}"
  local os_name arch_name
  os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch_name="$(uname -m)"
  case "${arch_name}" in
    x86_64|amd64) arch_name="amd64" ;;
    arm64|aarch64) arch_name="arm64" ;;
    *) echo "[setup_deps] Unsupported architecture: ${arch_name}" >&2; exit 1 ;;
  esac

  if ! command -v kind >/dev/null 2>&1; then
    echo "[setup_deps:k8s] Downloading kind v0.33.0 (${os_name}/${arch_name}) -> ${tools_bin}/kind..."
    curl -fSL --noproxy '*' -o "${tools_bin}/kind" "https://kind.sigs.k8s.io/dl/v0.33.0/kind-${os_name}-${arch_name}"
    chmod +x "${tools_bin}/kind"
  else
    echo "[setup_deps:k8s] kind already available at $(command -v kind)"
  fi

  if ! command -v kubectl >/dev/null 2>&1; then
    echo "[setup_deps:k8s] Downloading kubectl v1.32.2 (${os_name}/${arch_name}) -> ${tools_bin}/kubectl..."
    curl -fSL --noproxy '*' -o "${tools_bin}/kubectl" "https://dl.k8s.io/release/v1.32.2/bin/${os_name}/${arch_name}/kubectl"
    chmod +x "${tools_bin}/kubectl"
  else
    echo "[setup_deps:k8s] kubectl already available at $(command -v kubectl)"
  fi

  if ! command -v helm >/dev/null 2>&1; then
    echo "[setup_deps:k8s] Downloading helm v3.22.1 (${os_name}/${arch_name}) -> ${tools_bin}/helm..."
    local tmp_helm
    tmp_helm="$(mktemp -d)"
    curl -fSL --noproxy '*' -o "${tmp_helm}/helm.tgz" "https://get.helm.sh/helm-v3.22.1-${os_name}-${arch_name}.tar.gz"
    tar -xzf "${tmp_helm}/helm.tgz" -C "${tmp_helm}"
    mv "${tmp_helm}/${os_name}-${arch_name}/helm" "${tools_bin}/helm"
    chmod +x "${tools_bin}/helm"
    rm -rf "${tmp_helm}"
  else
    echo "[setup_deps:k8s] helm already available at $(command -v helm)"
  fi

  if command -v ollama >/dev/null 2>&1; then
    echo "[setup_deps:k8s] ollama available at $(command -v ollama) (ensure 'ollama pull qwen2.5:3b' has been run)"
  else
    echo "[setup_deps:k8s] NOTE: Install Ollama from https://ollama.com and run 'ollama pull qwen2.5:3b' for live LLM E2E tests."
  fi
}

setup_baseline_src() {
  mkdir -p "${REPO_ROOT}/src"
  if [ ! -d "${REPO_ROOT}/src/rossoctl" ]; then
    echo "[setup_deps:baseline] Cloning rossoctl @ b380fffd77bddb861f774f9e7a6aef0257216a2b..."
    git -c http.proxy= -c https.proxy= clone https://github.com/rossoctl/rossoctl.git "${REPO_ROOT}/src/rossoctl"
    git -C "${REPO_ROOT}/src/rossoctl" checkout b380fffd77bddb861f774f9e7a6aef0257216a2b
  else
    echo "[setup_deps:baseline] ${REPO_ROOT}/src/rossoctl already present."
  fi

  if [ ! -d "${REPO_ROOT}/src/cortex" ]; then
    echo "[setup_deps:baseline] Cloning cortex @ 520dc8a30534303f6279f79c4af15837d1683c94..."
    git -c http.proxy= -c https.proxy= clone https://github.com/rossoctl/cortex.git "${REPO_ROOT}/src/cortex"
    git -C "${REPO_ROOT}/src/cortex" checkout 520dc8a30534303f6279f79c4af15837d1683c94
  else
    echo "[setup_deps:baseline] ${REPO_ROOT}/src/cortex already present."
  fi

  if [ ! -x "${REPO_ROOT}/src/cortex/authbridge/venv/bin/python3" ]; then
    mkdir -p "${REPO_ROOT}/src/cortex/authbridge"
    python3 -m venv "${REPO_ROOT}/src/cortex/authbridge/venv"
    "${REPO_ROOT}/src/cortex/authbridge/venv/bin/pip" install -r "${LINEAGE_DIR}/requirements.txt"
  fi
}

case "${TARGET_LANG}" in
  python) setup_python_deps ;;
  go)     setup_go_deps ;;
  node)   setup_node_deps ;;
  java)   setup_java_deps ;;
  rust)   setup_rust_deps ;;
  all)
    setup_python_deps
    setup_go_deps
    setup_node_deps
    setup_java_deps
    setup_rust_deps
    ;;
  *)
    echo "[setup_deps] Unsupported --lang '${TARGET_LANG}' (expected python|go|node|java|rust|all)" >&2
    exit 2
    ;;
esac

if [ "${INSTALL_K8S_TOOLS}" = "true" ]; then
  install_k8s_tools
fi

if [ "${WITH_BASELINE_SRC}" = "true" ]; then
  setup_baseline_src
fi

echo "[setup_deps] Completed successfully."
