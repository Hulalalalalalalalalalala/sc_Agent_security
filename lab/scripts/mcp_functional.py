#!/usr/bin/env python3
"""Direct MCP functional test through the tool AuthBridge.

Runs in a pod that is not the weather agent, so the agent sidecar cannot
rewrite the Authorization header. Reads /tmp/exchanged. Prints protocol
results and statuses only.
"""
import json
import os
import urllib.error
import urllib.request

TOKEN_PATH = "/tmp/exchanged"
URL = os.environ.get("MCP_URL", "http://weather-tool-advanced-mcp.team1.svc:8000/mcp")
MARKER = os.environ.get("MCP_MARKER", "mcp-functional")
token = open(TOKEN_PATH).read().strip()


def parse_body(raw, content_type):
    raw = raw.strip()
    if not raw:
        return None
    if "text/event-stream" in (content_type or "") or raw.startswith("event:") or raw.startswith("data:"):
        messages = []
        for line in raw.splitlines():
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload and payload != "[DONE]":
                    messages.append(json.loads(payload))
        return messages[-1] if messages else None
    return json.loads(raw)


def rpc(method, params, session, rpc_id, auth):
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
    if auth:
        headers["Authorization"] = "Bearer " + auth
    req = urllib.request.Request(URL, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=40) as resp:
            raw = resp.read().decode()
            parsed = parse_body(raw, resp.headers.get("content-type"))
            return resp.status, resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id"), parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            parsed = parse_body(raw, exc.headers.get("content-type"))
        except Exception:
            parsed = {"raw": raw[:240]}
        return exc.code, None, parsed


status, session, init = rpc(
    "initialize",
    {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": MARKER, "version": "1"},
    },
    None,
    1,
    token,
)
print("initialize", status, "session", "yes" if session else "no")
if isinstance(init, dict):
    result = init.get("result") or {}
    print("initialize_result", json.dumps({
        "protocolVersion": result.get("protocolVersion"),
        "server": (result.get("serverInfo") or {}).get("name"),
        "error": init.get("error"),
    }, ensure_ascii=False))
else:
    print("initialize_body", init)
    raise SystemExit("INITIALIZE_FAILED")
if status != 200 or not session:
    raise SystemExit("INITIALIZE_FAILED")

note_status, _, _ = rpc("notifications/initialized", {}, session, None, token)
print("initialized_notification", note_status)

list_status, _, listed = rpc("tools/list", {}, session, 2, token)
tools = []
if isinstance(listed, dict) and isinstance(listed.get("result"), dict):
    tools = listed["result"].get("tools") or []
print("tools_list", list_status, "count", len(tools))
for tool in tools:
    schema = tool.get("inputSchema") or {}
    print("tool", json.dumps({
        "name": tool.get("name"),
        "description": tool.get("description"),
        "required": schema.get("required"),
        "properties": list((schema.get("properties") or {}).keys()),
    }, ensure_ascii=False))
if list_status != 200 or not any(t.get("name") == "get_weather" for t in tools):
    raise SystemExit("TOOLS_LIST_FAILED")

call_status, _, called = rpc(
    "tools/call",
    {"name": "get_weather", "arguments": {"city": "New York"}},
    session,
    3,
    token,
)
print("tools_call", call_status)
if isinstance(called, dict):
    if called.get("error"):
        print("tools_call_error", json.dumps(called["error"], ensure_ascii=False)[:500])
    result = called.get("result") or {}
    content = result.get("content")
    is_error = result.get("isError")
    text = ""
    if isinstance(content, list):
        text = "\n".join(str(item.get("text", "")) for item in content if isinstance(item, dict))
    elif isinstance(content, str):
        text = content
    print("tools_call_is_error", is_error)
    print("tools_call_text", text[:800])
else:
    print("tools_call_body", called)

neg_status, _, neg = rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": MARKER + "-none", "version": "1"}}, None, 4, None)
print("no_token", neg_status)

bad = token[: token.rfind(".") + 8] + ("A" if token[token.rfind(".") + 8] != "A" else "B") + token[token.rfind(".") + 9 :]
bad_status, _, _ = rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": MARKER + "-badsig", "version": "1"}}, None, 5, bad)
print("bad_signature", bad_status)
os.remove(TOKEN_PATH)
