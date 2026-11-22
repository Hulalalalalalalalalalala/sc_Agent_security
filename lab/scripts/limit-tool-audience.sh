#!/usr/bin/env bash
# Remove the tool SPIFFE audience from realm defaults and from user-facing
# clients. The Agent SPIFFE client keeps weather-tool-exchange-aud so its
# token exchange can still request that audience.
set -euo pipefail
CTX="${CTX:-kind-agent-identity-lab}"
kubectl --context "$CTX" -n keycloak exec keycloak-0 -- sh -c '
set -e
KC=/opt/keycloak/bin/kcadm.sh
$KC config credentials --server http://127.0.0.1:8080 --realm master --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null
TOOL_SCOPE=e49f579c-e65b-4856-b4ae-dc2936bc103e
EXCHANGE_SCOPE=b3d55aeb-f7e9-4339-a955-18a99f23776a
$KC delete realms/rossoctl/default-default-client-scopes/$TOOL_SCOPE >/dev/null 2>&1 || true
for name in weather-advanced-e2e weather-lab-user rossoctl; do
  id=$($KC get clients -r rossoctl -q clientId="$name" --fields id --format csv --noquotes | tail -n 1)
  echo "strip $name $id"
  $KC delete clients/$id/default-client-scopes/$TOOL_SCOPE -r rossoctl >/dev/null 2>&1 || true
  $KC delete clients/$id/optional-client-scopes/$EXCHANGE_SCOPE -r rossoctl >/dev/null 2>&1 || true
done
echo "realm defaults:"
$KC get realms/rossoctl/default-default-client-scopes --fields name
'
