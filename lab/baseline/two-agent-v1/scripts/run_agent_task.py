#!/usr/bin/env python3
"""Submit one A2A task to the real Weather Agent. Prints statuses and text only."""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

KC = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/token"
AGENT = os.environ.get("AGENT_URL", "http://weather-service-advanced.team1.svc:8080/")
PROMPT = os.environ.get(
    "AGENT_PROMPT",
    "请调用天气工具查询纽约当前天气，并根据工具结果回答。",
)
RUN_ID = os.environ.get("RUN_ID", "agent-task")


def post(url, payload, headers):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=420) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


password = os.environ.get("KC_PASSWORD", "")
password_file = os.environ.get("KC_PASSWORD_FILE", "")
if not password and password_file:
    password = open(password_file).read().strip()
if not password:
    password = "alice123"
form = urllib.parse.urlencode({
    "grant_type": "password",
    "client_id": os.environ.get("KC_CLIENT", "weather-advanced-e2e"),
    "username": os.environ.get("KC_USERNAME", "alice"),
    "password": password,
}).encode()
req = urllib.request.Request(KC, data=form, method="POST")
try:
    with urllib.request.urlopen(req, timeout=20) as resp:
        token = json.loads(resp.read().decode())["access_token"]
        print("user_token", resp.status, "parts", token.count("."))
except urllib.error.HTTPError as exc:
    print("user_token", exc.code)
    raise SystemExit(1)

body = {
    "jsonrpc": "2.0",
    "id": RUN_ID,
    "method": "SendMessage",
    "params": {
        "message": {
            "messageId": RUN_ID + "-msg",
            "role": "ROLE_USER",
            "parts": [{"text": PROMPT}],
        }
    },
}
status, raw = post(
    AGENT,
    body,
    {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "A2A-Version": "1.0",
        "Authorization": "Bearer " + token,
    },
)
print("agent_http", status, "bytes", len(raw))
# Drop any token-like strings before printing.
redacted = []
for line in raw.splitlines():
    if "eyJ" in line or "Bearer " in line:
        continue
    redacted.append(line[:500])
text = "\n".join(redacted)
print("agent_body")
print(text[:2500])
