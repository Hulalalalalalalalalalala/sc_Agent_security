#!/usr/bin/env python3
"""In-pod checks. Reads /tmp/jwt. Prints statuses and claim summaries only."""
import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

jwt = open("/tmp/jwt").read().strip()
kc = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/token"
AGENT = "spiffe://localtest.me/ns/team1/sa/weather-service-advanced"
TOOL = "spiffe://localtest.me/ns/team1/sa/weather-tool-advanced"
ATYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"


def post(url, form=None, headers=None, data=None):
    body = data if data is not None else urllib.parse.urlencode(form).encode()
    hdrs = {}
    if form is not None and data is None:
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode()
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = {"raw": raw[:120]}
            return resp.status, parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {"raw": raw[:120]}
        return exc.code, parsed


def claims(token):
    part = token.split(".")[1]
    part += "=" * ((4 - len(part) % 4) % 4)
    data = json.loads(base64.urlsafe_b64decode(part))
    out = {k: data.get(k) for k in ("iss", "sub", "aud", "scope", "exp", "iat", "azp", "typ")}
    if "act" in data:
        out["act"] = data["act"]
    return out


user = post(kc, {
    "grant_type": "password",
    "client_id": "weather-advanced-e2e",
    "username": "alice",
    "password": "alice123",
})[1]
ex_status, ex = post(kc, {
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "client_id": AGENT,
    "client_assertion_type": ATYPE,
    "client_assertion": jwt,
    "subject_token": user["access_token"],
    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "audience": TOOL,
    "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "scope": "openid weather-tool-exchange-aud",
})
print("exchange", ex_status)
if "access_token" in ex:
    print("exchange_claims", json.dumps(claims(ex["access_token"])))
    tok = ex["access_token"]
    header, payload, sig = tok.split(".")
    mid = len(sig) // 2
    sig2 = sig[:mid] + ("A" if sig[mid] != "A" else "B") + sig[mid + 1:]
    open("/tmp/badtok", "w").write(header + "." + payload + "." + sig2)
else:
    print("exchange_error", ex.get("error"), ex.get("error_description"))

# Call the Service name so the agent AuthBridge route can match.
payload = json.dumps({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "agent-proc", "version": "0"},
    },
}).encode()
req = urllib.request.Request(
    "http://weather-tool-advanced-mcp:8000/mcp",
    data=payload,
    headers={
        "Authorization": "Bearer " + user["access_token"],
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    },
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=20) as resp:
        print("agent_service_with_user", resp.status)
except urllib.error.HTTPError as exc:
    print("agent_service_with_user", exc.code)

os.remove("/tmp/jwt")
