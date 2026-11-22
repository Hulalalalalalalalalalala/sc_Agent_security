#!/usr/bin/env bash
# Restore the tool audience scope removed by limit-tool-audience.sh.
set -euo pipefail
CTX="${CTX:-kind-agent-identity-lab}"
kubectl --context "$CTX" -n keycloak exec keycloak-0 -- sh -c '
set -e
KC=/opt/keycloak/bin/kcadm.sh
$KC config credentials --server http://127.0.0.1:8080 --realm master --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null
TOOL_SCOPE=e49f579c-e65b-4856-b4ae-dc2936bc103e
EXCHANGE_SCOPE=b3d55aeb-f7e9-4339-a955-18a99f23776a
$KC update realms/rossoctl/default-default-client-scopes/$TOOL_SCOPE -r rossoctl
for name in weather-advanced-e2e weather-lab-user rossoctl; do
  id=$($KC get clients -r rossoctl -q clientId="$name" --fields id --format csv --noquotes | tail -n 1)
  $KC update clients/$id/default-client-scopes/$TOOL_SCOPE -r rossoctl
  $KC update clients/$id/optional-client-scopes/$EXCHANGE_SCOPE -r rossoctl
done
echo restored
$KC get realms/rossoctl/default-default-client-scopes --fields name
'
