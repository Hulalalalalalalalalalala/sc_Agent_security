#!/usr/bin/env python3
"""One MCP initialize plus tools/list. Prints status only."""
import json
import os
import urllib.error
import urllib.request

URL = os.environ["MCP_URL"]
RUN = os.environ["RUN_ID"]
CALLER = os.environ["CALLER"]
TOKEN_FILE = os.environ.get("TOKEN_FILE", "")
MODE = os.environ.get("TOKEN_MODE", "file")


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


def rpc(method, params, session, rpc_id, token):
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
    req = urllib.request.Request(URL, data=json.dumps(body).encode(), headers=headers, method="POST")
    # Do not inherit the pod HTTP proxy. The caller also clears those env vars.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=20) as resp:
            raw = resp.read().decode()
            parsed = parse_body(raw, resp.headers.get("content-type"))
            session_id = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")
            return resp.status, session_id, parsed, ""
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        if "eyJ" in raw:
            raw = "REDACTED"
        try:
            parsed = parse_body(raw, exc.headers.get("content-type"))
        except Exception:
            parsed = None
        return exc.code, None, parsed, raw[:180]


def main():
    if MODE == "none":
        token = ""
    else:
        token = open(TOKEN_FILE).read().strip()
    status, session, parsed, err = rpc(
        "initialize",
        {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": RUN + "-" + CALLER, "version": "1"},
        },
        None,
        1,
        token,
    )
    init_ok = isinstance(parsed, dict) and "result" in parsed
    print(RUN, CALLER, "initialize", status, "session", "yes" if session else "no", "ok", init_ok, err)
    if not session:
        return
    rpc("notifications/initialized", {}, session, None, token)
    list_status, _, listed, list_err = rpc("tools/list", {}, session, 2, token)
    names = []
    if isinstance(listed, dict):
        names = [item.get("name") for item in (listed.get("result") or {}).get("tools") or []]
    print(RUN, CALLER, "tools_list", list_status, "tools", names, list_err)


if __name__ == "__main__":
    main()
