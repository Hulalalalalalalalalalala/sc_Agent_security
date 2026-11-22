#!/usr/bin/env python3
"""A2A coordinator. Forwards one user task to the weather agent.

The inbound Authorization header is forwarded. AuthBridge on this pod
exchanges it when the outbound host matches the weather-agent route.
"""
import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AGENT_B = os.environ.get("AGENT_B_URL", "http://weather-service-advanced:8080/")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/.well-known/agent"):
            body = json.dumps({
                "name": "weather-coordinator",
                "description": "Forwards a user A2A task to the weather agent.",
            }).encode()
            self._send(200, body)
            return
        self._send(404, b"")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        message_id = ""
        try:
            incoming = json.loads(raw)
            message_id = ((incoming.get("params") or {}).get("message") or {}).get("messageId") or ""
        except json.JSONDecodeError:
            incoming = None
        print(f"LAB_CORR hop=A message_id={message_id}", flush=True)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "A2A-Version": self.headers.get("A2A-Version", "1.0"),
        }
        authorization = self.headers.get("Authorization")
        if authorization:
            headers["Authorization"] = authorization
        request = urllib.request.Request(AGENT_B, data=raw, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                body = response.read()
                code = response.status
        except urllib.error.HTTPError as exc:
            body = exc.read()
            code = exc.code
        task_id = ""
        try:
            task_id = json.loads(body)["result"]["task"]["id"]
        except Exception:
            task_id = ""
        print(
            f"LAB_CORR hop=A message_id={message_id} upstream_task={task_id} upstream_http={code}",
            flush=True,
        )
        self._send(code, body)

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def main():
    port = int(os.environ.get("PORT", "8001"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
