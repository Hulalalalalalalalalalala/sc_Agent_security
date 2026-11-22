#!/usr/bin/env python3
"""Call MCP initialize and tools/list with an optional DPoP proof."""
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, "/tmp/dpop-vendor")
from pydpop import generate_key, generate_proof, jwk_thumbprint, private_key_from_jwk, public_jwk

URL = os.environ["MCP_URL"]
RUN = os.environ["RUN_ID"]
CALLER = os.environ["CALLER"]
MODE = os.environ.get("TOKEN_MODE", "file")
PROOF = os.environ.get("PROOF_MODE", "none")
SCHEME = os.environ.get("AUTH_SCHEME", "DPoP")


def parse_body(raw, content_type):
    raw = (raw or "").strip()
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


def load_key():
    if PROOF == "holder":
        return private_key_from_jwk(json.loads(open(os.environ["KEY_FILE"]).read()))
    if PROOF == "own":
        return generate_key("ES256")
    return None


def rpc(method, params, session, rpc_id, token, key):
    body = {"jsonrpc": "2.0", "method": method}
    if rpc_id is not None:
        body["id"] = rpc_id
    if params is not None:
        body["params"] = params
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "X-Lab-Run": RUN + ":" + CALLER,
    }
    if session:
        headers["Mcp-Session-Id"] = session
    if token and SCHEME != "none":
        headers["Authorization"] = SCHEME + " " + token
    if key is not None and token:
        headers["DPoP"] = generate_proof(
            private_key=key, htm="POST", htu=URL, access_token=token,
        )
    req = urllib.request.Request(URL, data=json.dumps(body).encode(), headers=headers, method="POST")
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
            parsed = {"raw": raw[:180]}
        return exc.code, None, parsed, raw[:180]


def main():
    token = "" if MODE == "none" else open(os.environ["TOKEN_FILE"]).read().strip()
    key = load_key()
    thumb = jwk_thumbprint(public_jwk(key)) if key is not None else "NONE"
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
        key,
    )
    init_ok = isinstance(parsed, dict) and "result" in parsed
    reason = ""
    if isinstance(parsed, dict) and "reason" in parsed:
        reason = parsed.get("stage", "") + ":" + parsed.get("reason", "")
    print(RUN, CALLER, "proof", PROOF, "proof_jkt", thumb, "initialize", status, "session", "yes" if session else "no", "ok", init_ok, reason or err)
    if not session:
        return
    rpc("notifications/initialized", {}, session, None, token, key)
    list_status, _, listed, list_err = rpc("tools/list", {}, session, 2, token, key)
    names = []
    if isinstance(listed, dict):
        names = [item.get("name") for item in (listed.get("result") or {}).get("tools") or []]
    print(RUN, CALLER, "tools_list", list_status, "tools", names, list_err)


if __name__ == "__main__":
    main()
