#!/bin/sh
# Runs inside the agent authbridge container. Prints status and claim
# summaries only. Token files are removed before exit.
set -eu
KC=http://keycloak-service.keycloak.svc:8080
REALM=rossoctl
AGENT_ID='spiffe://localtest.me/ns/team1/sa/weather-service-advanced'
TOOL_ID='spiffe://localtest.me/ns/team1/sa/weather-tool-advanced'
JWT=$(tr -d '\n' < /opt/jwt_svid.token)

urlenc() {
  printf '%s' "$1" | sed 's/:/%3A/g; s/\//%2F/g; s/ /%20/g'
}

claims() {
  # $1 = jwt compact serialization
  p=$(printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+')
  mod=$(( ${#p} % 4 ))
  if [ "$mod" -eq 2 ]; then p="${p}=="; elif [ "$mod" -eq 3 ]; then p="${p}="; fi
  printf '%s' "$p" | base64 -d 2>/dev/null || printf '%s' "$p" | base64 -D
}

wget -qO /tmp/user.json --post-data "grant_type=password&client_id=weather-advanced-e2e&username=alice&password=alice123" \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  "$KC/realms/$REALM/protocol/openid-connect/token"
USER_TOK=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' /tmp/user.json)
if [ -z "$USER_TOK" ]; then
  echo "USER_GRANT_FAIL"
  rm -f /tmp/user.json
  exit 1
fi
echo "USER_GRANT_OK"
echo "USER_CLAIMS=$(claims "$USER_TOK" | tr -d '\n')"

cat > /tmp/ex.form <<EOF
grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=$(urlenc "$AGENT_ID")&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=${JWT}&subject_token=${USER_TOK}&subject_token_type=urn:ietf:params:oauth:token-type:access_token&audience=$(urlenc "$TOOL_ID")&requested_token_type=urn:ietf:params:oauth:token-type:access_token&scope=openid%20weather-tool-exchange-aud
EOF
if ! wget -qO /tmp/ex.json --post-file /tmp/ex.form --header 'Content-Type: application/x-www-form-urlencoded' \
  "$KC/realms/$REALM/protocol/openid-connect/token"; then
  echo "EXCHANGE_HTTP_FAIL"
fi
if grep -q '"error"' /tmp/ex.json; then
  echo "EXCHANGE_ERROR $(sed -n 's/.*"error":"\([^"]*\)".*/\1/p' /tmp/ex.json) $(sed -n 's/.*"error_description":"\([^"]*\)".*/\1/p' /tmp/ex.json)"
  rm -f /tmp/user.json /tmp/ex.json /tmp/ex.form
  exit 1
fi
EX_TOK=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' /tmp/ex.json)
echo "EXCHANGE_OK"
echo "EX_CLAIMS=$(claims "$EX_TOK" | tr -d '\n')"

mcp() {
  # $1 outfile $2 token-or-empty
  if [ -n "$2" ]; then
    wget -S -O "$1" --header "Authorization: Bearer $2" \
      --header 'Content-Type: application/json' \
      --header 'Accept: application/json, text/event-stream' \
      --post-data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"verify","version":"0.1"}}}' \
      http://weather-tool-advanced-mcp.team1.svc:8000/mcp
  else
    wget -S -O "$1" \
      --header 'Content-Type: application/json' \
      --header 'Accept: application/json, text/event-stream' \
      --post-data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"verify","version":"0.1"}}}' \
      http://weather-tool-advanced-mcp.team1.svc:8000/mcp
  fi
}

# wget -S writes headers to stderr; capture status
set +e
mcp /tmp/mcp.ok "$EX_TOK" >/tmp/mcp.ok.err 2>&1
echo "MCP_OK_EXIT=$?"
grep -m1 'HTTP/' /tmp/mcp.ok.err | tr -d '\r'
mcp /tmp/mcp.none "" >/tmp/mcp.none.err 2>&1
echo "MCP_NONE_EXIT=$?"
grep -m1 'HTTP/' /tmp/mcp.none.err | tr -d '\r'
# bad signature: flip the last character of a still-otherwise-valid token
BAD=$(printf '%s' "$EX_TOK" | sed 's/.$/A/')
mcp /tmp/mcp.bad "$BAD" >/tmp/mcp.bad.err 2>&1
echo "MCP_BADSIG_EXIT=$?"
grep -m1 'HTTP/' /tmp/mcp.bad.err | tr -d '\r'
# valid Keycloak signature, audience is the user token (agent SPIFFE), not the tool
mcp /tmp/mcp.aud "$USER_TOK" >/tmp/mcp.aud.err 2>&1
echo "MCP_WRONGAUD_EXIT=$?"
grep -m1 'HTTP/' /tmp/mcp.aud.err | tr -d '\r'
# SPIRE JWT-SVID presented as the access token: different issuer and signing key
mcp /tmp/mcp.iss "$JWT" >/tmp/mcp.iss.err 2>&1
echo "MCP_SPIREJWT_EXIT=$?"
grep -m1 'HTTP/' /tmp/mcp.iss.err | tr -d '\r'
set -e
rm -f /tmp/user.json /tmp/ex.json /tmp/ex.form /tmp/mcp.ok /tmp/mcp.ok.err /tmp/mcp.none /tmp/mcp.none.err /tmp/mcp.bad /tmp/mcp.bad.err /tmp/mcp.aud /tmp/mcp.aud.err /tmp/mcp.iss /tmp/mcp.iss.err
echo DONE
