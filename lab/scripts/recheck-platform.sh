#!/usr/bin/env bash
# Recheck the agent-identity-lab platform without printing credentials or tokens.
set -euo pipefail
export PATH="/Users/hulalala/Desktop/A/.tools/bin:${HOME}/.docker/bin:${PATH}"
CTX=kind-agent-identity-lab

echo "context=$(kubectl config current-context)"
kubectl --context "$CTX" get nodes
echo "--- not running ---"
kubectl --context "$CTX" get pods -A --no-headers | awk '$4 != "Running" && $4 != "Completed"' || true

check() {
  local url=$1
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "$url" || echo ERR)
  echo "$code $url"
}

check http://rossoctl-ui.localtest.me:8080/
check http://keycloak.localtest.me:8080/realms/rossoctl/.well-known/openid-configuration
check http://spire-oidc.localtest.me:8080/keys
check http://spire-tornjak-ui.localtest.me:8080/

echo "--- auth mode ---"
kubectl --context "$CTX" -n team1 get cm authbridge-config \
  -o jsonpath='CLIENT_AUTH_TYPE={.data.CLIENT_AUTH_TYPE} SPIRE={.data.SPIRE_ENABLED} ISSUER={.data.ISSUER}{"\n"}'
kubectl --context "$CTX" -n team1 get pods -l 'app.kubernetes.io/name in (weather-service-advanced,weather-tool-advanced)'
