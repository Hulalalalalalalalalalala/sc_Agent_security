#!/usr/bin/env bash
# =============================================================================
# Lineage Capability Tree (LCT) — Multi-Language Agent & 2/2 Pod Scaffolder
#
# Generates a ready-to-build polyglot Agent/MCP project directory (`python`,
# `go`, `node`, `java`, or `rust`) pre-wired to `lct-sidecar` (`127.0.0.1:9001`
# inbound + `127.0.0.1:8081/v1/proxy/call` outbound) with a customized K8s
# `2/2` Deployment manifest (`automountServiceAccountToken: false`).
#
# Usage:
#   bash lineage/scripts/configure_agent_lang.sh \
#     --lang go \
#     --target ./my-go-agent \
#     [--name my-go-agent] \
#     [--domain org-alpha.io] \
#     [--skill custom.go.skill] \
#     [--nodeport 30460]
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINEAGE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SDK_ROOT="${LINEAGE_DIR}/sdk"

LANG_CHOICE=""
TARGET_DIR=""
AGENT_NAME=""
TRUST_DOMAIN="org-alpha.io"
AGENT_SKILL=""
NODE_PORT="30460"

while [ $# -gt 0 ]; do
  case "$1" in
    --lang)
      LANG_CHOICE="${2:?--lang requires python|go|node|java|rust}"
      shift 2
      ;;
    --target)
      TARGET_DIR="${2:?--target requires directory path}"
      shift 2
      ;;
    --name)
      AGENT_NAME="${2:?--name requires agent name}"
      shift 2
      ;;
    --domain)
      TRUST_DOMAIN="${2:?--domain requires trust domain}"
      shift 2
      ;;
    --skill)
      AGENT_SKILL="${2:?--skill requires skill name}"
      shift 2
      ;;
    --nodeport)
      NODE_PORT="${2:?--nodeport requires integer port}"
      shift 2
      ;;
    -h|--help)
      sed -n '2,18p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "[configure_agent_lang] Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "${LANG_CHOICE}" ] || [ -z "${TARGET_DIR}" ]; then
  echo "Usage: bash lineage/scripts/configure_agent_lang.sh --lang <python|go|node|java|rust> --target <dir>" >&2
  exit 2
fi

case "${LANG_CHOICE}" in
  python|go|node|java|rust) ;;
  *)
    echo "[configure_agent_lang] Unsupported --lang '${LANG_CHOICE}' (expected python|go|node|java|rust)" >&2
    exit 2
    ;;
esac

if [ -z "${AGENT_NAME}" ]; then
  AGENT_NAME="custom-${LANG_CHOICE}-agent"
fi
if [ -z "${AGENT_SKILL}" ]; then
  AGENT_SKILL="custom.${LANG_CHOICE}.skill"
fi

# Strict validation of DNS-1123 name, skill identifier, and Kubernetes NodePort (`[LOW-M5-01]`)
if [ "${#AGENT_NAME}" -gt 63 ] || ! printf '%s' "${AGENT_NAME}" | grep -Eq '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'; then
  echo "[configure_agent_lang] Invalid --name '${AGENT_NAME}': must be a DNS-1123 label (<=63 lowercase alphanumeric or '-')" >&2
  exit 2
fi

if ! printf '%s' "${AGENT_SKILL}" | grep -Eq '^[A-Za-z0-9._,-]+$'; then
  echo "[configure_agent_lang] Invalid --skill '${AGENT_SKILL}': must match ^[A-Za-z0-9._,-]+$" >&2
  exit 2
fi

if ! printf '%s' "${NODE_PORT}" | grep -Eq '^[0-9]+$' || [ "${NODE_PORT}" -lt 30000 ] || [ "${NODE_PORT}" -gt 32767 ]; then
  echo "[configure_agent_lang] Invalid --nodeport '${NODE_PORT}': must be an integer in [30000, 32767]" >&2
  exit 2
fi

case "${TRUST_DOMAIN}" in
  org-alpha.io)
    K8S_NS="lineage-alpha"
    LOCAL_CA="http://alpha-ca.lineage-alpha.svc.cluster.local:8090"
    PEER_CAS="org-beta.io=http://beta-ca.org-beta.io:31094,org-payment.io=http://payment-ca.org-payment.io:32094"
    DIR_SVC="http://alpha-directory.lineage-alpha.svc.cluster.local:8091"
    REV_SVC="http://alpha-revocation.lineage-alpha.svc.cluster.local:8092"
    ;;
  org-beta.io)
    K8S_NS="lineage-beta"
    LOCAL_CA="http://beta-ca.lineage-beta.svc.cluster.local:8090"
    PEER_CAS="org-alpha.io=http://alpha-ca.org-alpha.io:30094,org-payment.io=http://payment-ca.org-payment.io:32094"
    DIR_SVC="http://beta-directory.lineage-beta.svc.cluster.local:8091"
    REV_SVC="http://beta-revocation.lineage-beta.svc.cluster.local:8092"
    ;;
  org-payment.io)
    K8S_NS="lineage-pay"
    LOCAL_CA="http://payment-ca.lineage-pay.svc.cluster.local:8090"
    PEER_CAS="org-alpha.io=http://alpha-ca.org-alpha.io:30094,org-beta.io=http://beta-ca.org-beta.io:31094"
    DIR_SVC="http://payment-directory.lineage-pay.svc.cluster.local:8091"
    REV_SVC="http://payment-revocation.lineage-pay.svc.cluster.local:8092"
    ;;
  *)
    echo "[configure_agent_lang] Unsupported --domain '${TRUST_DOMAIN}' (expected org-alpha.io|org-beta.io|org-payment.io)" >&2
    exit 2
    ;;
esac

mkdir -p "${TARGET_DIR}"

case "${LANG_CHOICE}" in
  python)
    cp "${SDK_ROOT}/python/requirements.txt" "${TARGET_DIR}/requirements.txt"
    cp "${SDK_ROOT}/python/lct_sdk.py" "${TARGET_DIR}/lct_sdk.py"
    cp "${SDK_ROOT}/python/example_agent.py" "${TARGET_DIR}/example_agent.py"
    cp "${SDK_ROOT}/python/Dockerfile" "${TARGET_DIR}/Dockerfile"
    ;;
  go)
    mkdir -p "${TARGET_DIR}/lctsdk" "${TARGET_DIR}/cmd/example_agent" "${TARGET_DIR}/bin"
    cp "${SDK_ROOT}/go/go.mod" "${TARGET_DIR}/go.mod"
    cp "${SDK_ROOT}/go/lctsdk/sdk.go" "${TARGET_DIR}/lctsdk/sdk.go"
    cp "${SDK_ROOT}/go/cmd/example_agent/main.go" "${TARGET_DIR}/cmd/example_agent/main.go"
    cp "${SDK_ROOT}/go/Dockerfile" "${TARGET_DIR}/Dockerfile"
    ;;
  node)
    cp "${SDK_ROOT}/node/package.json" "${TARGET_DIR}/package.json"
    cp "${SDK_ROOT}/node/lct_sdk.mjs" "${TARGET_DIR}/lct_sdk.mjs"
    cp "${SDK_ROOT}/node/lct_sdk.d.ts" "${TARGET_DIR}/lct_sdk.d.ts"
    cp "${SDK_ROOT}/node/example_agent.mjs" "${TARGET_DIR}/example_agent.mjs"
    cp "${SDK_ROOT}/node/Dockerfile" "${TARGET_DIR}/Dockerfile"
    ;;
  java)
    mkdir -p "${TARGET_DIR}/target/classes"
    cp "${SDK_ROOT}/java/pom.xml" "${TARGET_DIR}/pom.xml"
    cp "${SDK_ROOT}/java/LCTSidecarClient.java" "${TARGET_DIR}/LCTSidecarClient.java"
    cp "${SDK_ROOT}/java/Dockerfile" "${TARGET_DIR}/Dockerfile"
    ;;
  rust)
    mkdir -p "${TARGET_DIR}/src" "${TARGET_DIR}/target"
    cp "${SDK_ROOT}/rust/Cargo.toml" "${TARGET_DIR}/Cargo.toml"
    cp "${SDK_ROOT}/rust/src/lib.rs" "${TARGET_DIR}/src/lib.rs"
    cp "${SDK_ROOT}/rust/src/main.rs" "${TARGET_DIR}/src/main.rs"
    cp "${SDK_ROOT}/rust/Dockerfile" "${TARGET_DIR}/Dockerfile"
    ;;
esac

cat > "${TARGET_DIR}/k8s-2of2-pod.yaml" <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${AGENT_NAME}
  namespace: ${K8S_NS}
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${AGENT_NAME}
  namespace: ${K8S_NS}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${AGENT_NAME}
  template:
    metadata:
      labels:
        app: ${AGENT_NAME}
    spec:
      serviceAccountName: ${AGENT_NAME}
      automountServiceAccountToken: false
      volumes:
        - name: lct-loopback
          emptyDir:
            medium: Memory
        - name: lct-mtls-ram
          emptyDir:
            medium: Memory
        - name: lct-sa
          projected:
            sources:
              - serviceAccountToken:
                  path: token
                  expirationSeconds: 3600
                  audience: lct-federation-ca
      containers:
        - name: app
          image: ${AGENT_NAME}:latest
          imagePullPolicy: IfNotPresent
          env:
            - name: LCT_LOOPBACK_SECRET_FILE
              value: "/var/run/lct-loopback/secret"
            - name: APP_PORT
              value: "9001"
          volumeMounts:
            - name: lct-loopback
              mountPath: /var/run/lct-loopback
              readOnly: true
        - name: lct-sidecar
          image: lineage-lct:m4
          imagePullPolicy: IfNotPresent
          args: ["--role", "sidecar"]
          ports:
            - containerPort: 8443
              name: https-a2a
          env:
            - name: LOCAL_CA_URL
              value: "${LOCAL_CA}"
            - name: PEER_CA_URLS
              value: "${PEER_CAS}"
            - name: DIRECTORY_URL
              value: "${DIR_SVC}"
            - name: REVOCATION_URL
              value: "${REV_SVC}"
            - name: AUDIT_COLLECTOR_URL
              value: "http://audit-collector.org-audit.io:30893"
            - name: PUBLIC_ORIGIN
              value: "https://${AGENT_NAME}.${TRUST_DOMAIN}:${NODE_PORT}"
            - name: AGENT_SKILLS
              value: "${AGENT_SKILL}"
            - name: APP_PORT
              value: "9001"
            - name: SIDECAR_INBOUND_PORT
              value: "8443"
            - name: SIDECAR_OUTBOUND_PORT
              value: "8081"
            - name: LCT_MTLS_RAM_DIR
              value: "/var/run/lct-mtls-ram"
          volumeMounts:
            - name: lct-loopback
              mountPath: /var/run/lct-loopback
            - name: lct-mtls-ram
              mountPath: /var/run/lct-mtls-ram
            - name: lct-sa
              mountPath: /var/run/lct-sa
              readOnly: true
---
apiVersion: v1
kind: Service
metadata:
  name: ${AGENT_NAME}
  namespace: ${K8S_NS}
spec:
  type: NodePort
  selector:
    app: ${AGENT_NAME}
  ports:
    - name: https-a2a
      port: 8443
      targetPort: 8443
      nodePort: ${NODE_PORT}
EOF

echo "[configure_agent_lang] Scaffolded '${LANG_CHOICE}' LCT agent '${AGENT_NAME}' (${TRUST_DOMAIN}) -> ${TARGET_DIR}"
