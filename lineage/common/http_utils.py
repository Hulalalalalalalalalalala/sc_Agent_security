"""Production-grade multi-threaded HTTP server & client helpers for LCT services."""

from __future__ import annotations

import json
import re
import socket
import ssl
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Iterable, Iterator, Mapping, Optional, Tuple, Union
from urllib.parse import parse_qs, unquote, urlparse, urlsplit

MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB max payload guard
_HOST_HEADER_RE = re.compile(r"^[A-Za-z0-9._-]+(?::[0-9]{1,5})?$")


def _reject_http_json_constant(constant: str) -> Any:
    raise ValueError(f"Non-finite JSON constant {constant!r} is forbidden")


def validate_origin_form_target(raw_path: str) -> Tuple[str, str]:
    """Enforce RFC 9112 Section 3.2.1 HTTP Origin-Form request-target.

    Strictly rejects `@` userinfo smuggling (`POST @evil:9999/mcp`), `//` scheme-relative
    authority injection, absolute-URI targets, backslashes, path dot-traversal, fragments,
    and control/whitespace characters.
    Returns `(validated_path, validated_query)`.
    """
    if not isinstance(raw_path, str) or not raw_path or len(raw_path) > 8192:
        raise ValueError(f"invalid_request_target: empty or oversized target {raw_path!r}")
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in raw_path):
        raise ValueError("invalid_request_target: control or whitespace character in target")
    if not raw_path.startswith("/") or raw_path.startswith("//") or "\\" in raw_path:
        raise ValueError(
            f"invalid_request_target: must be single-slash origin-form path, got {raw_path!r}"
        )
    sp = urlsplit(raw_path)
    if sp.scheme or sp.netloc or sp.fragment:
        raise ValueError(
            f"invalid_request_target: scheme/netloc/fragment forbidden in origin-form {raw_path!r}"
        )
    if (
        not sp.path.startswith("/")
        or "//" in sp.path
        or "@" in sp.path
        or any(seg in (".", "..") for seg in sp.path.split("/"))
    ):
        raise ValueError(
            f"invalid_request_target: userinfo '@', empty//, or dot-segment forbidden in path {sp.path!r}"
        )
    cur = sp.path
    for _ in range(4):
        nxt = unquote(cur)
        if (
            not nxt.startswith("/")
            or "//" in nxt
            or "\\" in nxt
            or "@" in nxt
            or "?" in nxt
            or "#" in nxt
            or any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in nxt)
            or any(seg in (".", "..") for seg in nxt.split("/"))
        ):
            raise ValueError(
                f"invalid_request_target: unsafe percent-encoded segment in {sp.path!r}"
            )
        if nxt == cur:
            break
        cur = nxt
    else:
        raise ValueError(
            f"invalid_request_target: excessive nested percent-encoding in {sp.path!r}"
        )
    return sp.path, sp.query


class DualReuseThreadingHTTPServer(ThreadingHTTPServer):
    """Multi-threaded HTTP/1.1 server with fast address reuse, high listen backlog, and daemon threads."""

    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


@dataclass
class SSEResponse:
    """Real-time Server-Sent Events (`text/event-stream`) streaming response."""

    frames: Iterable[Union[Dict[str, Any], str, bytes]]


RouteHandler = Callable[["HTTPRequestContext"], Tuple[int, Any, Dict[str, str]]]


def _normalize_clean_origin(origin: str) -> str:
    sp_pub = urlsplit(origin.strip())
    if (
        sp_pub.scheme not in ("http", "https")
        or not sp_pub.netloc
        or not sp_pub.hostname
        or "@" in sp_pub.netloc
        or sp_pub.path not in ("", "/")
        or sp_pub.query
        or sp_pub.fragment
    ):
        raise ValueError(f"Invalid clean HTTP origin: {origin!r}")
    return f"{sp_pub.scheme.lower()}://{sp_pub.netloc.lower()}"


class HTTPRequestContext:
    """Structured incoming HTTP/HTTPS request passed to service route handlers."""

    def __init__(
        self,
        method: str,
        raw_path: str,
        headers: Mapping[str, str],
        body: bytes,
        server_host: str,
        server_port: int,
        public_origin: Optional[str] = None,
        allowed_hosts: Tuple[str, ...] = (),
        scheme: str = "http",
        peer_spiffe_id: Optional[str] = None,
        peer_jkt: Optional[str] = None,
        tls_version: Optional[str] = None,
        tls_cipher: Optional[str] = None,
        client_ip: Optional[str] = None,
        allowed_origins: Tuple[str, ...] = (),
    ) -> None:
        self.method = method.upper()
        valid_path, valid_query = validate_origin_form_target(raw_path)
        self.raw_path = raw_path
        self.path = valid_path
        self.query_raw = valid_query
        self.query = {
            k: v[0] if len(v) == 1 else v for k, v in parse_qs(valid_query).items()
        }
        # Case-insensitive header lookup plus original dictionary
        self._headers_lower = {k.lower(): v for k, v in headers.items()}
        self.headers = dict(headers)
        self.body = body
        self.server_host = server_host
        self.server_port = server_port
        self.scheme = scheme.lower()
        self.public_origin = _normalize_clean_origin(public_origin) if public_origin else None
        self.allowed_origins = tuple(
            _normalize_clean_origin(o) for o in allowed_origins if o
        )
        self._origin_by_authority: Dict[str, str] = {}
        for orig in (*( (self.public_origin,) if self.public_origin else () ), *self.allowed_origins):
            sp_o = urlsplit(orig)
            if sp_o.netloc:
                self._origin_by_authority.setdefault(sp_o.netloc.lower(), orig)
        self.allowed_hosts = tuple(h.lower() for h in allowed_hosts if h)
        self.peer_spiffe_id = peer_spiffe_id
        self.peer_jkt = peer_jkt
        self.tls_version = tls_version
        self.tls_cipher = tls_cipher
        self.client_ip = client_ip

    def header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self._headers_lower.get(name.lower(), default)

    @property
    def authoritative_authority(self) -> str:
        if self.public_origin:
            sp = urlsplit(self.public_origin)
            return sp.netloc.lower()
        if (self.scheme == "http" and self.server_port == 80) or (
            self.scheme == "https" and self.server_port == 443
        ):
            return self.server_host.lower()
        return f"{self.server_host.lower()}:{self.server_port}"

    @property
    def authoritative_url(self) -> str:
        """Construct canonical HTTP/HTTPS target URL strictly from signed/configured server origins + path."""
        host_hdr = self.header("host")
        if (
            isinstance(host_hdr, str)
            and _HOST_HEADER_RE.match(host_hdr)
            and host_hdr.lower() in self._origin_by_authority
        ):
            return f"{self._origin_by_authority[host_hdr.lower()]}{self.path}"
        if self.public_origin:
            return f"{self.public_origin}{self.path}"
        return f"{self.scheme}://{self.authoritative_authority}{self.path}"

    @property
    def full_url(self) -> str:
        """Authoritative canonical URL (`htu` safe; never trusts unverified client `Host` header)."""
        return self.authoritative_url

    def validate_host_syntax_only(self) -> Tuple[bool, str]:
        host_hdr = self.header("host")
        if host_hdr is None:
            return True, "ok"
        if not isinstance(host_hdr, str) or not host_hdr or not _HOST_HEADER_RE.match(host_hdr):
            return False, f"Malformed or smuggled Host header: {host_hdr!r}"
        return True, "ok"

    def validate_host_header(
        self, allowed_authorities: Optional[Tuple[str, ...]] = None
    ) -> Tuple[bool, str]:
        """Validate HTTP `Host` header syntax and authority match against server listener."""
        host_hdr = self.header("host")
        if host_hdr is None:
            return True, "ok"
        if not isinstance(host_hdr, str) or not host_hdr or not _HOST_HEADER_RE.match(host_hdr):
            return False, f"Malformed or smuggled Host header: {host_hdr!r}"
        norm_host = host_hdr.lower()
        if allowed_authorities:
            permitted = tuple(a.lower() for a in allowed_authorities)
        elif self.public_origin or self._origin_by_authority:
            permitted = (
                self.authoritative_authority,
                *self._origin_by_authority.keys(),
                *self.allowed_hosts,
            )
        else:
            permitted = (
                self.authoritative_authority,
                f"localhost:{self.server_port}",
                *self.allowed_hosts,
            )
        if norm_host not in permitted:
            return (
                False,
                f"Host authority mismatch: got {norm_host!r}, expected {self.authoritative_authority!r}",
            )
        return True, "ok"

    def json(self) -> Dict[str, Any]:
        if not self.body:
            return {}
        try:
            data = json.loads(
                self.body.decode("utf-8"),
                parse_constant=_reject_http_json_constant,
            )
        except Exception as exc:
            raise ValueError(f"Invalid JSON request body: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON request body must be an object")
        return data


class ManagedHTTPService:
    """Embeddable & multiprocess-ready multi-threaded HTTP/HTTPS (mTLS + SSE) service."""

    def __init__(
        self,
        service_name: str,
        dispatcher: RouteHandler,
        host: str = "127.0.0.1",
        port: int = 0,
        public_origin: Optional[str] = None,
        allowed_hosts: Iterable[str] = (),
        allowed_origins: Iterable[str] = (),
        ssl_context: Optional[ssl.SSLContext] = None,
        ssl_context_provider: Optional[Callable[[], ssl.SSLContext]] = None,
        peer_cert_verifier: Optional[Callable[[bytes], Tuple[str, str]]] = None,
    ) -> None:
        self.service_name = service_name
        self._dispatcher = dispatcher
        self._host = host
        self._requested_port = port
        self._ssl_context = ssl_context
        self._ssl_context_provider = ssl_context_provider
        self._peer_cert_verifier = peer_cert_verifier
        self._scheme = (
            "https"
            if (ssl_context is not None or ssl_context_provider is not None)
            else "http"
        )
        self._public_origin: Optional[str] = (
            _normalize_clean_origin(public_origin) if public_origin is not None else None
        )
        self._allowed_origins: Tuple[str, ...] = tuple(
            _normalize_clean_origin(o) for o in allowed_origins if o
        )
        self._allowed_hosts = tuple(str(h).lower() for h in allowed_hosts if h)
        self._server: Optional[DualReuseThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def set_public_origins(
        self,
        primary_origin: Optional[str],
        extra_origins: Iterable[str] = (),
    ) -> None:
        """Atomically update signed public origin(s) on live host IP change without pod restart."""
        norm_primary = (
            _normalize_clean_origin(primary_origin) if primary_origin is not None else None
        )
        norm_extras = tuple(_normalize_clean_origin(o) for o in extra_origins if o)
        with self._lock:
            self._public_origin = norm_primary
            self._allowed_origins = norm_extras

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError(f"Service {self.service_name} is not started")
        return int(self._server.server_address[1])

    def set_ssl_context(self, ctx: ssl.SSLContext) -> None:
        """Atomically swap the active server `SSLContext` for subsequent TLS connections."""
        with self._lock:
            self._ssl_context = ctx
            self._scheme = "https"

    def _get_active_ssl_context(self) -> Optional[ssl.SSLContext]:
        if self._ssl_context_provider is not None:
            return self._ssl_context_provider()
        return self._ssl_context

    @property
    def base_url(self) -> str:
        return f"{self._scheme}://{self._host}:{self.port}"

    def start(self) -> str:
        with self._lock:
            if self._server is not None:
                return self.base_url

            outer = self

            class _Handler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def log_message(self, format: str, *args: Any) -> None:
                    # Suppress noisy stderr logging; structured audit log handles security events
                    return

                def _handle_any(self) -> None:
                    try:
                        peer_spiffe: Optional[str] = None
                        peer_jkt: Optional[str] = None
                        tls_ver: Optional[str] = None
                        tls_ciph: Optional[str] = None
                        client_ip: Optional[str] = (
                            str(self.client_address[0]) if self.client_address else None
                        )
                        if outer._scheme == "https" and isinstance(
                            self.connection, ssl.SSLSocket
                        ):
                            tls_ver = self.connection.version()
                            c_info = self.connection.cipher()
                            tls_ciph = c_info[0] if c_info else None
                            der_cert = self.connection.getpeercert(binary_form=True)
                            if outer._peer_cert_verifier is not None:
                                try:
                                    peer_spiffe, peer_jkt = outer._peer_cert_verifier(
                                        der_cert or b""
                                    )
                                except Exception as exc:
                                    self._send_json(
                                        403,
                                        {
                                            "error": "mtls_peer_certificate_rejected",
                                            "detail": str(exc),
                                        },
                                    )
                                    return

                        req_parts = self.requestline.split(" ")
                        if len(req_parts) != 3:
                            raise ValueError(
                                f"invalid_request_target: malformed request line {self.requestline!r}"
                            )
                        validate_origin_form_target(req_parts[1])
                        content_len_str = self.headers.get("Content-Length", "0")
                        content_len = int(content_len_str)
                        if content_len < 0 or content_len > MAX_BODY_BYTES:
                            self._send_json(
                                413,
                                {"error": "payload_too_large", "max_bytes": MAX_BODY_BYTES},
                            )
                            return
                        body = self.rfile.read(content_len) if content_len > 0 else b""
                        with outer._lock:
                            snap_pub_origin = outer._public_origin
                            snap_allowed_origins = outer._allowed_origins
                            snap_allowed_hosts = outer._allowed_hosts
                        ctx = HTTPRequestContext(
                            method=self.command,
                            raw_path=self.path,
                            headers={k: v for k, v in self.headers.items()},
                            body=body,
                            server_host=outer._host,
                            server_port=outer.port,
                            public_origin=snap_pub_origin,
                            allowed_hosts=snap_allowed_hosts,
                            allowed_origins=snap_allowed_origins,
                            scheme=outer._scheme,
                            peer_spiffe_id=peer_spiffe,
                            peer_jkt=peer_jkt,
                            tls_version=tls_ver,
                            tls_cipher=tls_ciph,
                            client_ip=client_ip,
                        )
                        status, payload, extra_headers = outer._dispatcher(ctx)
                        if isinstance(payload, SSEResponse):
                            self._send_sse(status, payload, extra_headers)
                        else:
                            self._send_json(status, payload, extra_headers)
                    except ValueError as exc:
                        err_text = str(exc)
                        err_code = (
                            "invalid_request_target"
                            if err_text.startswith("invalid_request_target")
                            else "bad_request"
                        )
                        self._send_json(400, {"error": err_code, "detail": err_text})
                    except Exception as exc:
                        self._send_json(
                            500,
                            {
                                "error": "internal_server_error",
                                "service": outer.service_name,
                                "detail": str(exc),
                            },
                        )

                def _send_sse(
                    self,
                    status: int,
                    sse_payload: SSEResponse,
                    extra_headers: Optional[Mapping[str, str]] = None,
                ) -> None:
                    self.send_response(status)
                    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "close")
                    if extra_headers:
                        for hk, hv in extra_headers.items():
                            if hk.lower() not in (
                                "content-type",
                                "content-length",
                                "transfer-encoding",
                                "connection",
                            ):
                                self.send_header(hk, hv)
                    self.end_headers()
                    self.wfile.flush()
                    if self.command == "HEAD":
                        return
                    for item in sse_payload.frames:
                        if isinstance(item, (bytes, bytearray)):
                            raw_frame = bytes(item)
                        elif isinstance(item, str):
                            txt = item if item.endswith("\n\n") else f"{item.rstrip()}\n\n"
                            raw_frame = txt.encode("utf-8")
                        else:
                            serialized = json.dumps(
                                item,
                                separators=(",", ":"),
                                ensure_ascii=False,
                                allow_nan=False,
                            )
                            raw_frame = f"data: {serialized}\n\n".encode("utf-8")
                        self.wfile.write(raw_frame)
                        self.wfile.flush()

                def _send_json(
                    self,
                    status: int,
                    payload: Any,
                    extra_headers: Optional[Mapping[str, str]] = None,
                ) -> None:
                    if isinstance(payload, (bytes, bytearray)):
                        raw = bytes(payload)
                        ctype = "application/octet-stream"
                    else:
                        raw = json.dumps(
                            payload,
                            separators=(",", ":"),
                            ensure_ascii=False,
                            allow_nan=False,
                        ).encode("utf-8")
                        ctype = "application/json; charset=utf-8"

                    self.send_response(status)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(raw)))
                    self.send_header("Connection", "close")
                    if extra_headers:
                        for hk, hv in extra_headers.items():
                            if hk.lower() not in (
                                "content-type",
                                "content-length",
                                "connection",
                            ):
                                self.send_header(hk, hv)
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(raw)

                do_GET = _handle_any
                do_POST = _handle_any
                do_PUT = _handle_any
                do_DELETE = _handle_any
                do_PATCH = _handle_any

            class _TLSReadyServer(DualReuseThreadingHTTPServer):
                def process_request_thread(
                    self, request: Any, client_address: Any
                ) -> None:
                    active_ssl_ctx = outer._get_active_ssl_context()
                    if active_ssl_ctx is not None:
                        try:
                            request.settimeout(10.0)
                            tls_sock = active_ssl_ctx.wrap_socket(
                                request, server_side=True
                            )
                            request = tls_sock
                        except Exception:
                            try:
                                request.close()
                            except Exception:
                                pass
                            return
                    super().process_request_thread(request, client_address)

            self._server = _TLSReadyServer(
                (self._host, self._requested_port), _Handler
            )
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 0.05},
                name=f"http-{self.service_name}",
                daemon=True,
            )
            self._thread.start()
            return self.base_url

    def serve_forever_blocking(self) -> None:
        """Start if needed and block current process until stopped."""
        self.start()
        if self._thread is not None:
            self._thread.join()

    def stop(self) -> None:
        with self._lock:
            if self._server is not None:
                self._server.shutdown()
                self._server.server_close()
                self._server = None
            if self._thread is not None:
                self._thread.join(timeout=3.0)
                self._thread = None


def find_free_port(host: str = "127.0.0.1") -> int:
    """Reserve and release an ephemeral local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, 0))
        return int(sock.getsockname()[1])
