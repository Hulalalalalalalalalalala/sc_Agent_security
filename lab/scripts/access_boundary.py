#!/usr/bin/env python3
"""Access-boundary checks from a non-agent pod. Prints claims and statuses only."""
import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

KC = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/token"
TOOL = os.environ.get("MCP_URL", "http://weather-tool-advanced-mcp.team1.svc:8000/mcp")
AGENT = os.environ.get("AGENT_URL", "http://weather-service-advanced.team1.svc:8080/")
TOOL_AUD = "spiffe://localtest.me/ns/team1/sa/weather-tool-advanced"


def claims(token):
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    data = json.loads(base64.urlsafe_b64decode(part))
    aud = data.get("aud")
    if isinstance(aud, str):
        aud = [aud]
    return {
        "sub": data.get("sub"),
        "azp": data.get("azp"),
        "aud": aud,
        "scope": data.get("scope"),
        "tool_aud": TOOL_AUD in (aud or []),
    }


def password_grant(client, username, password):
    form = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": client,
        "username": username,
        "password": password,
    }).encode()
    req = urllib.request.Request(KC, data=form, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            token = json.loads(resp.read().decode())["access_token"]
            return resp.status, token
    except urllib.error.HTTPError as exc:
        return exc.code, ""


def mcp(token, method, params, session, rpc_id):
    body = {"jsonrpc": "2.0", "method": method}
    if rpc_id is not None:
        body["id"] = rpc_id
    if params is not None:
        body["params"] = params
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session:
        headers["Mcp-Session-Id"] = session
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(TOOL, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode()
            return resp.status, resp.headers.get("mcp-session-id"), raw[:180]
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        if "eyJ" in raw:
            raw = "REDACTED"
        return exc.code, None, raw[:240]


def init_params(name):
    return {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": name, "version": "1"},
    }


def show(label, status, token):
    print(label, "http", status)
    if token:
        info = claims(token)
        info["sub_present"] = bool(info.get("sub"))
        print(label, "claims", json.dumps(info, ensure_ascii=False))


def main():
    ny_pass = open("/tmp/lab-ny.pass").read().strip()
    lon_pass = open("/tmp/lab-lon.pass").read().strip()

    st, ny = password_grant("weather-lab-user", "lab-ny", ny_pass)
    show("lab-ny", st, ny)
    st, lon = password_grant("weather-lab-user", "lab-lon", lon_pass)
    show("lab-lon", st, lon)
    st, noaud = password_grant("weather-lab-noaud", "lab-ny", ny_pass)
    show("noaud", st, noaud)

    print("TEST2 direct initialize", *mcp(ny, "initialize", init_params("lab-direct-ny"), None, 1)[:2])
    status, session, _ = mcp(ny, "initialize", init_params("lab-direct-ny-2"), None, 1)
    print("TEST5 tools/list setup", status, "session", bool(session))
    if session:
        mcp(ny, "notifications/initialized", {}, session, None)
        list_status, _, raw = mcp(ny, "tools/list", {}, session, 2)
        print("TEST5 tools/list", list_status, "has_get_weather", "get_weather" in raw)
        call_status, _, raw = mcp(
            ny,
            "tools/call",
            {"name": "get_weather", "arguments": {"city": "Boston"}},
            session,
            3,
        )
        print("TEST5 tools/call", call_status, "is_error_text", "error" in raw.lower()[:80])

    no_status, _, no_body = mcp(noaud, "initialize", init_params("lab-noaud"), None, 1)
    print("TEST3 noaud initialize", no_status, no_body.replace("\n", " ")[:220])

    # Test 1: ordinary user through the real agent.
    prompt = "请调用天气工具查询波士顿当前天气，并根据工具返回的数据回答。"
    body = {
        "jsonrpc": "2.0",
        "id": "access-lab-ny",
        "method": "SendMessage",
        "params": {"message": {
            "messageId": "access-lab-ny-msg",
            "role": "ROLE_USER",
            "parts": [{"text": prompt}],
        }},
    }
    req = urllib.request.Request(
        AGENT,
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "A2A-Version": "1.0",
            "Authorization": "Bearer " + ny,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            raw = resp.read().decode()
            code = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        code = exc.code
    text = ""
    task = ""
    state = ""
    try:
        result = json.loads(raw)["result"]["task"]
        task = result.get("id", "")
        state = (result.get("status") or {}).get("state", "")
        parts = ((result.get("artifacts") or [{}])[0].get("parts") or [{}])
        text = parts[0].get("text", "")[:300]
    except Exception:
        text = "unparsed"
    print("TEST1 agent", code, "task", task, "state", state)
    print("TEST1 answer", text.replace("\n", " "))
    open("/tmp/lab-ny.token", "w").write(ny)
    open("/tmp/lab-lon.token", "w").write(lon)


if __name__ == "__main__":
    main()
