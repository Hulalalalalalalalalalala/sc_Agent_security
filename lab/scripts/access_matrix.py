#!/usr/bin/env python3
"""Access-matrix checks. Prints statuses and selected claims only."""
import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request

KC = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/token"
TOOL = "http://weather-tool-advanced-mcp.team1.svc:8000/mcp"
TOOL_AUD = "spiffe://localtest.me/ns/team1/sa/weather-tool-advanced"


def claims(token):
    part = token.split(".")[1]
    part += "=" * ((4 - len(part) % 4) % 4)
    data = json.loads(base64.urlsafe_b64decode(part))
    aud = data.get("aud")
    if isinstance(aud, str):
        aud = [aud]
    return {
        "sub_present": bool(data.get("sub")),
        "sub": data.get("sub"),
        "azp": data.get("azp"),
        "aud": aud,
        "scope": data.get("scope"),
        "tool_aud": TOOL_AUD in (aud or []),
        "exp_minus_iat": (data.get("exp") or 0) - (data.get("iat") or 0),
    }


def grant(client, username, password, scope=None):
    form = {
        "grant_type": "password",
        "client_id": client,
        "username": username,
        "password": password,
    }
    if scope:
        form["scope"] = scope
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(KC, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.loads(resp.read().decode())
            return resp.status, body.get("access_token", ""), body.get("error")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"error": body[:160]}
        return exc.code, "", parsed.get("error") or parsed.get("error_description", "")[:160]


def mcp(token, method, params, rpc_id):
    body = {"jsonrpc": "2.0", "method": method, "id": rpc_id, "params": params}
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(TOOL, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read().decode()[:160]
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        if "eyJ" in raw:
            raw = "REDACTED"
        return exc.code, raw[:220]


INIT = {
    "protocolVersion": "2025-03-26",
    "capabilities": {},
    "clientInfo": {"name": "lab-matrix", "version": "1"},
}


def main():
    ny = open("/tmp/lab-ny.pass").read().strip()
    st, token, err = grant("weather-lab-user", "lab-ny", ny)
    print("user_grant", st, err)
    if token:
        print("user_claims", json.dumps(claims(token), ensure_ascii=False))
        open("/tmp/lab-ny.token", "w").write(token)
    st, scoped, err = grant(
        "weather-lab-user",
        "lab-ny",
        ny,
        "openid weather-tool-exchange-aud agent-team1-weather-tool-advanced-aud",
    )
    print("requested_scope", st, err)
    if scoped:
        print("requested_scope_claims", json.dumps(claims(scoped), ensure_ascii=False))
    print("direct_initialize", *mcp(token, "initialize", INIT, 1))
    print("direct_tools_list", *mcp(token, "tools/list", {}, 2))
    print("direct_tools_call", *mcp(token, "tools/call", {"name": "get_weather", "arguments": {"city": "Boston"}}, 3))
    print("missing_initialize", *mcp("", "initialize", INIT, 4))


if __name__ == "__main__":
    main()
