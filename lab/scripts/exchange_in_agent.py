#!/usr/bin/env python3
"""Run inside the weather-service-advanced agent container.

Reads /tmp/jwt (a JWT-SVID copied from the AuthBridge container) and writes
/tmp/exchanged (an access token). Prints claim summaries and statuses only.
"""
import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

jwt = open("/tmp/jwt").read().strip()
if jwt.count(".") != 2:
    raise SystemExit("JWT_SVID_MISSING")

kc = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/token"
AGENT = "spiffe://localtest.me/ns/team1/sa/weather-service-advanced"
TOOL = "spiffe://localtest.me/ns/team1/sa/weather-tool-advanced"
ATYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"


def post(form):
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(kc, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"error": "non_json", "error_description": body[:180]}
        return exc.code, parsed


def claims(token):
    part = token.split(".")[1]
    part += "=" * ((4 - len(part) % 4) % 4)
    data = json.loads(base64.urlsafe_b64decode(part))
    out = {k: data.get(k) for k in ("iss", "sub", "aud", "scope", "exp", "iat", "azp", "typ")}
    if "act" in data:
        out["act"] = data["act"]
    return out


status, cc = post({
    "grant_type": "client_credentials",
    "client_id": AGENT,
    "client_assertion_type": ATYPE,
    "client_assertion": jwt,
})
print("client_credentials", status, cc.get("error"), cc.get("error_description"))
if "access_token" in cc:
    print("client_credentials_claims", json.dumps(claims(cc["access_token"]), ensure_ascii=False))

status, user = post({
    "grant_type": "password",
    "client_id": "weather-advanced-e2e",
    "username": "alice",
    "password": "alice123",
})
print("user_grant", status, user.get("error"), user.get("error_description"))
if "access_token" not in user:
    raise SystemExit("USER_GRANT_FAILED")
print("user_claims", json.dumps(claims(user["access_token"]), ensure_ascii=False))
open("/tmp/user-token", "w").write(user["access_token"])

status, ex = post({
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "client_id": AGENT,
    "client_assertion_type": ATYPE,
    "client_assertion": jwt,
    "subject_token": user["access_token"],
    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "audience": TOOL,
    "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "scope": "openid weather-tool-exchange-aud",
})
print("exchange", status, ex.get("error"), ex.get("error_description"))
if "access_token" not in ex:
    raise SystemExit("EXCHANGE_FAILED")
print("exchange_claims", json.dumps(claims(ex["access_token"]), ensure_ascii=False))
open("/tmp/exchanged", "w").write(ex["access_token"])
os.remove("/tmp/jwt")
print("exchange_ready")
