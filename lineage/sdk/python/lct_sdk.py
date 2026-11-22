"""Zero-Dependency Python Sidecar Adapter for Lineage Capability Tree (LCT).

Implements the co-located `2/2` Pod loopback contract:
- Reads `/var/run/lct-loopback/secret` (`LCT_LOOPBACK_SECRET_FILE`).
- Binds business `app` strictly to `127.0.0.1:<APP_PORT>` (`9001`).
- Enforces constant-time `hmac.compare_digest` on `X-LCT-Loopback-Auth`.
- Extracts verified `X-LCT-Request-Id`, `X-LCT-Task-Id`, `X-LCT-Sub`, `X-LCT-Lineage-Path`.
- Invokes `http://127.0.0.1:8081/v1/proxy/call` for attenuated `delegate_agent` & `call_tool`.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple
import urllib.error
import urllib.request

DEFAULT_SECRET_FILE = "/var/run/lct-loopback/secret"
DEFAULT_SIDECAR_OUTBOUND_URL = "http://127.0.0.1:8081"


def load_loopback_secret(secret_file: Optional[str] = None) -> str:
    env_inline = os.environ.get("LCT_LOOPBACK_SECRET", "").strip()
    if env_inline:
        if len(env_inline) < 16:
            raise ValueError("LCT_LOOPBACK_SECRET must be at least 16 characters")
        return env_inline
    path = secret_file or os.environ.get("LCT_LOOPBACK_SECRET_FILE", DEFAULT_SECRET_FILE)
    with open(path, "r", encoding="utf-8") as fh:
        secret = fh.read().strip()
    if len(secret) < 16:
        raise ValueError(f"Loopback secret from {path!r} must be at least 16 characters")
    return secret


def verify_loopback_secret(provided: Optional[str], expected: str) -> bool:
    if not isinstance(provided, str) or not provided or not expected:
        return False
    b_prov = provided.encode("utf-8")
    b_exp = expected.encode("utf-8")
    d_prov = hashlib.sha256(b_prov).digest()
    d_exp = hashlib.sha256(b_exp).digest()
    digest_ok = hmac.compare_digest(d_prov, d_exp)
    len_ok = (len(b_prov) ^ len(b_exp)) == 0
    return bool(int(digest_ok) & int(len_ok))


@dataclass(frozen=True)
class LCTRequestContext:
    request_id: str
    task_id: str
    sub: str
    lineage_path: str
    decision: str

    @classmethod
    def from_headers(cls, headers: Mapping[str, str]) -> "LCTRequestContext":
        lower = {k.lower(): v for k, v in headers.items()}
        return cls(
            request_id=lower.get("x-lct-request-id", "").strip(),
            task_id=lower.get("x-lct-task-id", "").strip(),
            sub=lower.get("x-lct-sub", "").strip(),
            lineage_path=lower.get("x-lct-lineage-path", "").strip(),
            decision=lower.get("x-lct-decision", "ALLOW").strip(),
        )

    def to_dict(self) -> Dict[str, str]:
        return {
            "request_id": self.request_id,
            "task_id": self.task_id,
            "sub": self.sub,
            "lineage_path": self.lineage_path,
            "decision": self.decision,
        }


@dataclass(frozen=True)
class PermissionSpec:
    tools: List[str]
    methods: Optional[List[str]] = None
    max_amount: Optional[float] = None
    numeric_bounds: Optional[Dict[str, float]] = None
    allowed_scopes: Optional[List[str]] = None
    allowed_targets: Optional[List[str]] = None
    param_whitelist: Optional[Dict[str, List[str]]] = None
    max_calls: int = 10

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tools": list(self.tools),
            "methods": list(self.methods or ["initialize", "tools/call", "tools/list"]),
            "max_amount": self.max_amount,
            "numeric_bounds": dict(self.numeric_bounds or {}),
            "allowed_scopes": list(self.allowed_scopes) if self.allowed_scopes is not None else None,
            "allowed_targets": list(self.allowed_targets) if self.allowed_targets is not None else None,
            "param_whitelist": {k: list(v) for k, v in (self.param_whitelist or {}).items()},
            "max_calls": int(self.max_calls),
        }


class LCTSidecarClient:
    """Loopback HTTP client talking strictly to `127.0.0.1:8081/v1/proxy/call`."""

    def __init__(
        self,
        loopback_secret: str,
        sidecar_outbound_url: str = DEFAULT_SIDECAR_OUTBOUND_URL,
    ) -> None:
        self.loopback_secret = loopback_secret
        self.proxy_url = f"{sidecar_outbound_url.rstrip('/')}/v1/proxy/call"

    def _post_proxy(self, body: Mapping[str, Any], timeout: float = 35.0) -> Tuple[int, Dict[str, Any]]:
        raw = json.dumps(dict(body), allow_nan=False).encode("utf-8")
        req = urllib.request.Request(
            self.proxy_url,
            data=raw,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-LCT-Loopback-Auth": self.loopback_secret,
            },
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=timeout) as resp:
                resp_bytes = resp.read()
                return int(resp.status), json.loads(resp_bytes.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            err_bytes = exc.read()
            try:
                err_json = json.loads(err_bytes.decode("utf-8"))
            except Exception:
                err_json = {"error": "sidecar_http_error", "status": exc.code}
            return int(exc.code), err_json

    def call_mcp_tool(
        self,
        request_id: str,
        target_url: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        timeout: float = 25.0,
    ) -> Tuple[int, Dict[str, Any]]:
        return self._post_proxy(
            {
                "action": "call_tool",
                "request_id": request_id,
                "target_url": target_url,
                "timeout": timeout,
                "payload": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": dict(arguments)},
                },
            },
            timeout=timeout + 5.0,
        )

    def delegate_agent(
        self,
        request_id: str,
        payload: Mapping[str, Any],
        permissions: Optional[PermissionSpec] = None,
        required_skill: Optional[str] = None,
        delegate_spiffe_id: Optional[str] = None,
        delegate_jkt: Optional[str] = None,
        target_url: Optional[str] = None,
        hop_segment: Optional[str] = None,
        task_path: str = "/a2a/task",
        use_prune_and_graft: bool = False,
        timeout: float = 30.0,
    ) -> Tuple[int, Dict[str, Any]]:
        body: Dict[str, Any] = {
            "action": "delegate_agent",
            "request_id": request_id,
            "payload": dict(payload),
            "task_path": task_path,
            "use_prune_and_graft": use_prune_and_graft,
            "timeout": timeout,
        }
        if permissions is not None:
            body["permissions"] = permissions.to_dict()
        if required_skill is not None:
            body["required_skill"] = required_skill
        if delegate_spiffe_id is not None:
            body["delegate_spiffe_id"] = delegate_spiffe_id
        if delegate_jkt is not None:
            body["delegate_jkt"] = delegate_jkt
        if target_url is not None:
            body["target_url"] = target_url
        if hop_segment is not None:
            body["hop_segment"] = hop_segment
        return self._post_proxy(body, timeout=timeout + 10.0)


class LCTAgentServer:
    """Loopback-only HTTP server (`127.0.0.1:<port>`) enforcing `X-LCT-Loopback-Auth`."""

    def __init__(
        self,
        loopback_secret: str,
        handler: Callable[[LCTRequestContext, Dict[str, Any]], Tuple[int, Dict[str, Any]]],
        port: int = 9001,
        agent_name: str = "python-lct-agent",
    ) -> None:
        self.loopback_secret = loopback_secret
        self.handler = handler
        self.port = port
        self.agent_name = agent_name
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> str:
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, _fmt: str, *_args: object) -> None:
                return

            def _send_json(self, code: int, payload: Mapping[str, Any]) -> None:
                raw = json.dumps(dict(payload), allow_nan=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                if self.path == "/healthz":
                    self._send_json(200, {"status": "ok", "agent": outer.agent_name, "lang": "python"})
                    return
                self._send_json(404, {"error": "not_found"})

            def do_POST(self) -> None:
                provided = self.headers.get("X-LCT-Loopback-Auth")
                if not verify_loopback_secret(provided, outer.loopback_secret):
                    self._send_json(403, {"error": "direct_loopback_bypass_blocked"})
                    return
                if self.path not in ("/a2a/task", "/a2a", "/"):
                    self._send_json(404, {"error": "route_not_found"})
                    return
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length) if length > 0 else b"{}"
                payload = json.loads(raw_body.decode("utf-8"))
                ctx = LCTRequestContext.from_headers(dict(self.headers.items()))
                code, resp_obj = outer.handler(ctx, payload)
                self._send_json(code, resp_obj)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", self.port), _Handler)
        actual_port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{actual_port}"

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
