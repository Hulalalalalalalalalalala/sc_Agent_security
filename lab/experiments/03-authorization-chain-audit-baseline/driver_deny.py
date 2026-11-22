#!/usr/bin/env python3
"""Three configured denials. Prints TRUTH and a run-id-free SERVER line."""
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request

KC = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/token"
TOOL = "http://weather-tool-advanced-mcp.team1.svc:8000/mcp"
AGENT_A = "spiffe://localtest.me/ns/team1/sa/weather-coordinator"
AGENT_B = "spiffe://localtest.me/ns/team1/sa/weather-service-advanced"
TOOL_AUD = "spiffe://localtest.me/ns/team1/sa/weather-tool-advanced"
ATYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"


def fp(token):
    return hashlib.sha256(token.encode()).hexdigest()


def post_form(url, form, headers=None):
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        if "eyJ" in raw:
            raw = "{\"error\":\"redacted\"}"
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = {"error": "non_json"}
        return exc.code, body


def mcp(token):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "baseline-deny", "version": "1"}},
    }
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(TOOL, data=json.dumps(payload).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode()
            return resp.status, raw[:180]
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        if "eyJ" in raw:
            raw = "REDACTED"
        return exc.code, raw[:240]


def emit(run_id, scenario, status, detail, token):
    print("TRUTH " + json.dumps({
        "run_id": run_id,
        "scenario": scenario,
        "user": os.environ["LAB_USER"],
        "entry": "tool" if scenario != "deny_exchange" else "keycloak",
        "http": status,
        "error": detail[:240],
        "task_id": None,
        "source_sa": os.environ.get("SOURCE_SA", ""),
        "source_pod": os.environ.get("SOURCE_POD", ""),
    }, ensure_ascii=False))
    print("SERVER " + json.dumps({
        "class": "被测系统证据",
        "target": "keycloak" if scenario == "deny_exchange" else "tool",
        "http": status,
        "error": detail[:240],
    }, ensure_ascii=False))
    if token:
        print("AUX " + json.dumps({
            "run_id": run_id,
            "class": "辅助观测",
            "token_fp": fp(token),
            "source_sa": os.environ.get("SOURCE_SA", ""),
        }, ensure_ascii=False))


def main():
    password = open(os.environ["PASS_FILE"]).read().strip()
    status, body = post_form(KC, {
        "grant_type": "password",
        "client_id": "weather-lab-user",
        "username": os.environ["LAB_USER"],
        "password": password,
    })
    if status != 200:
        emit("deny-login", "deny_login", status, body.get("error", ""), "")
        raise SystemExit(1)
    t0 = body["access_token"]
    code, detail = mcp(t0)
    emit("deny-tool-t0", "deny_tool_direct", code, detail, t0)
    code, exchanged = post_form(KC, {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": "weather-lab-user",
        "subject_token": t0,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": TOOL_AUD,
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "scope": "openid weather-tool-exchange-aud",
    })
    desc = exchanged.get("error_description") or exchanged.get("error") or ""
    emit("deny-exchange", "deny_exchange", code, str(desc), t0)
    jwt_a = open("/tmp/jwt-a").read().strip()
    code, issued = post_form(KC, {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": AGENT_A,
        "client_assertion_type": ATYPE,
        "client_assertion": jwt_a,
        "subject_token": t0,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": AGENT_B,
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "scope": "openid agent-team1-weather-service-advanced-aud",
    })
    if code != 200 or "access_token" not in issued:
        emit("deny-audience", "deny_wrong_audience", code, issued.get("error", ""), "")
        return
    agent_token = issued["access_token"]
    code, detail = mcp(agent_token)
    emit("deny-audience", "deny_wrong_audience", code, detail, agent_token)


if __name__ == "__main__":
    main()
