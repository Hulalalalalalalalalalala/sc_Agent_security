#!/usr/bin/env python3
"""Independent DPoP-protected MCP entry.

Verifies the access token signature, expiry, issuer, and audience, then
verifies the RFC 9449 proof with pydpop and compares its thumbprint to
cnf.jkt. A request is forwarded to the existing weather tool only after
all of those checks succeed. The tool still expects a Bearer token.
"""
import hashlib
import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
from jwt import PyJWKClient

from pydpop import DPoPError, MemoryJtiStore, verify_proof

ISS = "http://keycloak.localtest.me:8080/realms/rossoctl"
JWKS = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/certs"
TOOL_AUD = "spiffe://localtest.me/ns/team1/sa/weather-tool-advanced"
UPSTREAM = os.environ.get("UPSTREAM_MCP", "http://weather-tool-advanced-mcp.team1.svc:8000/mcp")
LISTEN = os.environ.get("GUARD_LISTEN", "0.0.0.0:8080")
JTI = MemoryJtiStore(ttl=300)
JWKS_CLIENT = PyJWKClient(JWKS)


def fp(token):
    return hashlib.sha256(token.encode()).hexdigest()


def log(line):
    print(line, flush=True)


class Guard(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _send(self, status, payload, extra=None):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        extra = extra or {}
        content_type = "application/json"
        if isinstance(payload, bytes):
            content_type = "application/octet-stream"
            for key, value in extra.items():
                if key.lower() == "content-type" and value:
                    content_type = value
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, value in extra.items():
            if value and key.lower() not in ("content-type", "content-length", "connection"):
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.split("?")[0] == "/health":
            self._send(200, {"status": "ok"})
            return
        self._send(404, {"stage": "route", "reason": "not_found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        if path != "/mcp":
            self._send(404, {"stage": "route", "reason": "not_found"})
            return
        length = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(length) if length else b""
        run_id = self.headers.get("X-Lab-Run") or "-"
        host = self.headers.get("Host") or ""
        htu = "http://%s%s" % (host, path)
        decision = self._decide(body, htu, run_id)
        self._send(decision["status"], decision["payload"], decision.get("headers"))

    def _decide(self, body, htu, run_id):
        auth = self.headers.get("Authorization") or ""
        parts = auth.split(" ", 1)
        scheme = parts[0] if auth else ""
        token = parts[1].strip() if len(parts) == 2 else ""
        proof = self.headers.get("DPoP") or ""
        base = "GUARD run=%s htu=%s" % (run_id, htu)
        if not token:
            log(base + " fp=NONE stage=jwt reason=missing_token http=401 forward=no")
            return self._json(401, "jwt", "missing_token", False)
        token_fp = fp(token)
        try:
            header = jwt.get_unverified_header(token)
            alg = header.get("alg")
            if not alg or alg.lower() == "none":
                raise jwt.InvalidAlgorithmError("alg")
            key = JWKS_CLIENT.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=[alg],
                audience=TOOL_AUD,
                issuer=ISS,
                leeway=5,
            )
        except jwt.ExpiredSignatureError:
            log(base + " fp=%s stage=jwt reason=expired http=401 forward=no" % token_fp)
            return self._json(401, "jwt", "expired", False)
        except jwt.InvalidAudienceError:
            log(base + " fp=%s stage=jwt reason=audience http=401 forward=no" % token_fp)
            return self._json(401, "jwt", "audience", False)
        except jwt.InvalidIssuerError:
            log(base + " fp=%s stage=jwt reason=issuer http=401 forward=no" % token_fp)
            return self._json(401, "jwt", "issuer", False)
        except jwt.InvalidSignatureError:
            log(base + " fp=%s stage=jwt reason=signature http=401 forward=no" % token_fp)
            return self._json(401, "jwt", "signature", False)
        except jwt.InvalidTokenError as exc:
            log(base + " fp=%s stage=jwt reason=invalid http=401 forward=no detail=%s" % (token_fp, type(exc).__name__))
            return self._json(401, "jwt", "invalid", False)
        cnf = claims.get("cnf") if isinstance(claims.get("cnf"), dict) else {}
        token_jkt = cnf.get("jkt") or ""
        if not token_jkt:
            log(base + " fp=%s token_jkt=ABSENT stage=binding reason=missing_cnf http=401 forward=no jwt=ok" % token_fp)
            return self._json(401, "binding", "missing_cnf", True)
        if scheme != "DPoP":
            log(base + " fp=%s token_jkt=%s stage=binding reason=bearer_downgrade http=401 forward=no jwt=ok" % (token_fp, token_jkt))
            return self._json(401, "binding", "bearer_downgrade", True)
        if not proof:
            log(base + " fp=%s token_jkt=%s proof_jkt=ABSENT stage=binding reason=missing_proof http=401 forward=no jwt=ok" % (token_fp, token_jkt))
            return self._json(401, "binding", "missing_proof", True)
        try:
            checked = verify_proof(
                proof=proof,
                htm="POST",
                htu=htu,
                access_token=token,
                jti_store=JTI,
            )
        except DPoPError as exc:
            log(base + " fp=%s token_jkt=%s stage=binding reason=proof_invalid http=401 forward=no detail=%s" % (token_fp, token_jkt, str(exc)[:120]))
            return self._json(401, "binding", "proof_invalid", True)
        proof_jkt = checked["jwk_thumbprint"]
        if proof_jkt != token_jkt:
            log(base + " fp=%s token_jkt=%s proof_jkt=%s stage=binding reason=jkt_mismatch http=401 forward=no jwt=ok" % (token_fp, token_jkt, proof_jkt))
            return self._json(401, "binding", "jkt_mismatch", True)
        status, payload, headers = self._forward(body, token)
        log(base + " fp=%s token_jkt=%s proof_jkt=%s stage=ok reason=bound http=%s forward=yes" % (token_fp, token_jkt, proof_jkt, status))
        return {"status": status, "payload": payload, "headers": headers}

    def _forward(self, body, token):
        headers = {
            "Authorization": "Bearer " + token,
            "Content-Type": self.headers.get("Content-Type") or "application/json",
            "Accept": self.headers.get("Accept") or "application/json, text/event-stream",
        }
        session = self.headers.get("Mcp-Session-Id")
        if session:
            headers["Mcp-Session-Id"] = session
        req = urllib.request.Request(UPSTREAM, data=body, headers=headers, method="POST")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=20) as resp:
                extra = {}
                for key in ("Content-Type", "Mcp-Session-Id"):
                    value = resp.headers.get(key)
                    if value:
                        extra[key] = value
                return resp.status, resp.read(), extra
        except urllib.error.HTTPError as exc:
            extra = {}
            for key in ("Content-Type", "Mcp-Session-Id"):
                value = exc.headers.get(key) if exc.headers else None
                if value:
                    extra[key] = value
            return exc.code, exc.read(), extra

    def _json(self, status, stage, reason, jwt_ok):
        return {
            "status": status,
            "payload": {"stage": stage, "reason": reason, "jwt_ok": jwt_ok},
            "headers": {"WWW-Authenticate": 'DPoP algs="ES256", error="invalid_token"'},
        }


def main():
    host, port = LISTEN.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), Guard)
    log("guard_listen %s upstream %s" % (LISTEN, UPSTREAM))
    server.serve_forever()


if __name__ == "__main__":
    main()
