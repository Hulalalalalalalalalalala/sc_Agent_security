#!/usr/bin/env python3
"""Issue one chained T2 and call the tool from this process. No DPoP."""
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request

KC = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/token"
TOOL_URL = os.environ.get("MCP_URL", "http://weather-tool-advanced-mcp.team1.svc:8000/mcp")
AGENT_A = "spiffe://localtest.me/ns/team1/sa/weather-coordinator"
AGENT_B = "spiffe://localtest.me/ns/team1/sa/weather-service-advanced"
TOOL = "spiffe://localtest.me/ns/team1/sa/weather-tool-advanced"
ATYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"


def fp(token):
    return hashlib.sha256(token.encode()).hexdigest()


def post_form(form):
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(KC, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        if "eyJ" in raw:
            raw = "{}"
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = {"error": "non_json"}
        return exc.code, body


def exchange(jwt, client, subject, audience, scope):
    return post_form({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": client,
        "client_assertion_type": ATYPE,
        "client_assertion": jwt,
        "subject_token": subject,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": audience,
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "scope": scope,
    })


def mcp(token, caller):
    def rpc(method, params, session, rpc_id):
        body = {"jsonrpc": "2.0", "method": method}
        if rpc_id is not None:
            body["id"] = rpc_id
        if params is not None:
            body["params"] = params
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if session:
            headers["Mcp-Session-Id"] = session
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(TOOL_URL, data=json.dumps(body).encode(), headers=headers, method="POST")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=20) as resp:
                raw = resp.read().decode()
                sid = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
                return resp.status, sid, raw[:180]
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode()
            if "eyJ" in raw:
                raw = "REDACTED"
            return exc.code, None, raw[:180]
    status, session, _ = rpc("initialize", {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": caller, "version": "1"},
    }, None, 1)
    if not session:
        return status, "no_session"
    rpc("notifications/initialized", {}, session, None)
    list_status, _, raw = rpc("tools/list", {}, session, 2)
    return list_status, "get_weather" if "get_weather" in raw else raw[:120]


def main():
    mode = os.environ.get("CROSS_MODE", "issue-and-call")
    if mode == "call-only":
        token = open(os.environ["TOKEN_FILE"]).read().strip()
        status, detail = mcp(token, os.environ.get("CALLER", "holder"))
        sender = os.environ.get("SOURCE_SA", "")
        print("AUX " + json.dumps({
            "run_id": "cross-ny",
            "scenario": "cross_workload_call",
            "class": "辅助观测",
            "source_sa": sender,
            "source_pod": os.environ.get("SOURCE_POD", ""),
            "token_fp": fp(token),
            "token_azp": "weather-agent",
            "token_client_matches_sender": sender == "weather-service-advanced",
        }, ensure_ascii=False))
        print("CALL " + json.dumps({
            "caller": os.environ.get("CALLER", ""),
            "source_sa": os.environ.get("SOURCE_SA", ""),
            "source_pod": os.environ.get("SOURCE_POD", ""),
            "target": TOOL_URL,
            "token_fp": fp(token),
            "http": status,
            "mcp": detail,
        }, ensure_ascii=False))
        return
    password = open(os.environ["PASS_FILE"]).read().strip()
    status, body = post_form({
        "grant_type": "password",
        "client_id": "weather-lab-user",
        "username": os.environ["LAB_USER"],
        "password": password,
    })
    if status != 200:
        print("TRUTH " + json.dumps({"run_id": "cross-ny", "scenario": "cross_workload", "error": "login_failed", "http": status}))
        raise SystemExit(1)
    t0 = body["access_token"]
    jwt_a = open("/tmp/jwt-a").read().strip()
    jwt_b = open("/tmp/jwt-b").read().strip()
    status, t1_body = exchange(jwt_a, AGENT_A, t0, AGENT_B, "openid agent-team1-weather-service-advanced-aud")
    if status != 200:
        print("TRUTH " + json.dumps({"run_id": "cross-ny", "scenario": "cross_workload", "error": "t1_failed", "http": status, "detail": t1_body.get("error")}))
        raise SystemExit(1)
    t1 = t1_body["access_token"]
    status, t2_body = exchange(jwt_b, AGENT_B, t1, TOOL, "openid weather-tool-exchange-aud")
    if status != 200:
        print("TRUTH " + json.dumps({
            "run_id": "cross-ny",
            "scenario": "cross_workload",
            "error": "t2_failed",
            "http": status,
            "detail": t2_body.get("error"),
            "t0_fp": fp(t0),
            "t1_fp": fp(t1),
            "second_input_fp": fp(t1),
            "input_equals_t1": True,
        }))
        raise SystemExit(1)
    t2 = t2_body["access_token"]
    os.umask(0o077)
    open("/tmp/token-t2", "w").write(t2)
    open("/tmp/token-t0", "w").write(t0)
    none_status, none_detail = mcp("", "cross-none")
    t0_status, t0_detail = mcp(t0, "cross-t0")
    own_status, own_detail = mcp(t2, "cross-backend")
    print("AUX " + json.dumps({
        "run_id": "cross-ny",
        "scenario": "cross_workload_call",
        "class": "辅助观测",
        "source_sa": os.environ.get("SOURCE_SA", ""),
        "source_pod": os.environ.get("SOURCE_POD", ""),
        "token_fp": fp(t2),
        "token_azp": "weather-agent",
        "token_sub": os.environ["LAB_USER"],
        "token_client_matches_sender": os.environ.get("SOURCE_SA") == "weather-service-advanced",
    }, ensure_ascii=False))
    print("TRUTH " + json.dumps({
        "run_id": "cross-ny",
        "scenario": "cross_workload",
        "user": os.environ["LAB_USER"],
        "t0_fp": fp(t0),
        "t1_fp": fp(t1),
        "second_input_fp": fp(t1),
        "input_equals_t1": True,
        "t2_fp": fp(t2),
        "backend_call": {"source_sa": os.environ.get("SOURCE_SA", ""), "http": own_status, "mcp": own_detail, "target": TOOL_URL},
        "no_token": {"http": none_status, "mcp": none_detail},
        "raw_t0": {"http": t0_status, "mcp": t0_detail},
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
