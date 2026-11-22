#!/usr/bin/env python3
"""Probe A, B, and the tool with one new lab-ny token. Prints claims and statuses only."""
import base64
import json
import urllib.error
import urllib.parse
import urllib.request

KC = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/token"
PASSWORD = open("/tmp/lab-ny.pass").read().strip()


def claims(token):
    part = token.split(".")[1]
    part += "=" * ((4 - len(part) % 4) % 4)
    data = json.loads(base64.urlsafe_b64decode(part))
    aud = data.get("aud")
    if isinstance(aud, str):
        aud = [aud]
    labels = []
    for item in aud or []:
        if item.endswith("/weather-coordinator"):
            labels.append("coordinator")
        elif item.endswith("/weather-service-advanced"):
            labels.append("weather-agent")
        elif item.endswith("/weather-tool-advanced"):
            labels.append("tool")
        elif item.endswith("/realms/rossoctl"):
            labels.append("realm")
        else:
            labels.append("other")
    return {"azp": data.get("azp"), "sub_present": bool(data.get("sub")), "aud": labels}


def grant():
    form = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": "weather-lab-user",
        "username": "lab-ny",
        "password": PASSWORD,
    }).encode()
    with urllib.request.urlopen(urllib.request.Request(KC, data=form), timeout=20) as resp:
        return json.loads(resp.read().decode())["access_token"]


def post_json(url, body, token, timeout):
    headers = {"Content-Type": "application/json", "Accept": "application/json", "A2A-Version": "1.0"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        if "eyJ" in raw:
            raw = "REDACTED"
        return exc.code, raw


def task_summary(raw):
    try:
        task = json.loads(raw)["result"]["task"]
        text = ((task.get("artifacts") or [{}])[0].get("parts") or [{}])[0].get("text", "")
        return task.get("id", ""), (task.get("status") or {}).get("state", ""), text[:80].replace("\n", " ")
    except Exception:
        return "", "", raw[:120].replace("\n", " ")


def main():
    token = grant()
    print("claims", json.dumps(claims(token), ensure_ascii=False))
    body = {
        "jsonrpc": "2.0",
        "id": "boundary",
        "method": "SendMessage",
        "params": {"message": {
            "messageId": "boundary-msg",
            "role": "ROLE_USER",
            "parts": [{"text": "请调用天气工具查询纽约当前天气，并根据工具返回的数据回答。"}],
        }},
    }
    for name, url in (
        ("direct_A", "http://weather-coordinator.team1.svc:8080/"),
        ("direct_B", "http://weather-service-advanced.team1.svc:8080/"),
    ):
        code, raw = post_json(url, body, token, 180)
        task, state, text = task_summary(raw)
        print(name, code, task, state, text)
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "boundary", "version": "1"}},
    }
    code, raw = post_json("http://weather-tool-advanced-mcp.team1.svc:8000/mcp", init, token, 20)
    print("direct_tool", code, raw[:140].replace("\n", " "))


if __name__ == "__main__":
    main()
