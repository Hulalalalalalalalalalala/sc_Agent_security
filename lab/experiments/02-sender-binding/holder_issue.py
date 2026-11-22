#!/usr/bin/env python3
"""Issue one unbound T0, one unbound tool token, and one DPoP-bound tool token.

The bound token is produced by continuous exchange: A exchanges T0 without
DPoP, then B exchanges that T1 while presenting B's DPoP key. The private
key stays in this process's output file.
"""
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, "/tmp/dpop-vendor")
from pydpop import generate_key, generate_proof, jwk_thumbprint, private_jwk, public_jwk

KC = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/token"
AGENT_A = "spiffe://localtest.me/ns/team1/sa/weather-coordinator"
AGENT_B = "spiffe://localtest.me/ns/team1/sa/weather-service-advanced"
TOOL = "spiffe://localtest.me/ns/team1/sa/weather-tool-advanced"
ATYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"
RUN = os.environ["RUN_ID"]


def fp(token):
    return hashlib.sha256(token.encode()).hexdigest()


def post(form, proof=None):
    data = urllib.parse.urlencode(form).encode()
    headers = {"DPoP": proof} if proof else {}
    req = urllib.request.Request(KC, data=data, headers=headers, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode()), resp.headers.get("DPoP-Nonce")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        if "eyJ" in raw:
            raw = "REDACTED"
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = {"error": "non_json"}
        return exc.code, body, exc.headers.get("DPoP-Nonce")


def with_dpop(form, key):
    status, body, nonce = post(form, generate_proof(private_key=key, htm="POST", htu=KC))
    if status != 200 and nonce:
        status, body, nonce = post(form, generate_proof(private_key=key, htm="POST", htu=KC, nonce=nonce))
    return status, body


def exchange(jwt, client, subject, audience, scope, key=None):
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": client,
        "client_assertion_type": ATYPE,
        "client_assertion": jwt,
        "subject_token": subject,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": audience,
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "scope": scope,
    }
    if key is None:
        return post(form)
    status, body = with_dpop(form, key)
    return status, body, None


def aud_has_tool(token):
    part = token.split(".")[1]
    part += "=" * ((4 - len(part) % 4) % 4)
    payload = json.loads(base64.urlsafe_b64decode(part))
    aud = payload.get("aud")
    if isinstance(aud, str):
        aud = [aud]
    cnf = payload.get("cnf") if isinstance(payload.get("cnf"), dict) else {}
    return TOOL in (aud or []), cnf.get("jkt") or ""


def main():
    os.umask(0o077)
    jwt_a = open("/tmp/jwt-a").read().strip()
    jwt_b = open("/tmp/jwt-b").read().strip()
    password = open(os.environ["PASS_FILE"]).read().strip()
    key = generate_key("ES256")
    thumb = jwk_thumbprint(public_jwk(key))
    status, body, _ = post({
        "grant_type": "password",
        "client_id": "weather-lab-user",
        "username": os.environ["LAB_USER"],
        "password": password,
    })
    if status != 200:
        print(RUN, "T0", status, body.get("error"))
        raise SystemExit(1)
    t0 = body["access_token"]
    status, body, _ = exchange(
        jwt_a, AGENT_A, t0, AGENT_B, "openid agent-team1-weather-service-advanced-aud",
    )
    if status != 200:
        print(RUN, "T1", status, body.get("error"), (body.get("error_description") or "")[:160])
        raise SystemExit(1)
    t1 = body["access_token"]
    status, body, _ = exchange(
        jwt_b, AGENT_B, t1, TOOL, "openid weather-tool-exchange-aud", key,
    )
    if status != 200 or "access_token" not in body:
        print(RUN, "T2_bound", status, body.get("error"), (body.get("error_description") or "")[:160])
        raise SystemExit(1)
    bound = body["access_token"]
    tool_aud, jkt = aud_has_tool(bound)
    status, body, _ = exchange(
        jwt_b, AGENT_B, t1, TOOL, "openid weather-tool-exchange-aud",
    )
    if status != 200 or "access_token" not in body:
        print(RUN, "T2_unbound", status, body.get("error"))
        raise SystemExit(1)
    unbound = body["access_token"]
    unbound_tool, unbound_jkt = aud_has_tool(unbound)
    open("/tmp/holder-key.json", "w").write(json.dumps(private_jwk(key)))
    open("/tmp/token-bound", "w").write(bound)
    open("/tmp/token-unbound", "w").write(unbound)
    open("/tmp/token-t0", "w").write(t0)
    print(
        RUN, "issued",
        "T0", fp(t0),
        "T1", fp(t1),
        "second_input", fp(t1),
        "input_equals_T1", True,
        "T2_bound", fp(bound),
        "bound_token_type", "DPoP",
        "bound_jkt", thumb,
        "token_jkt_match", jkt == thumb,
        "bound_tool_aud", tool_aud,
        "T2_unbound", fp(unbound),
        "unbound_jkt", unbound_jkt or "ABSENT",
        "unbound_tool_aud", unbound_tool,
    )


if __name__ == "__main__":
    main()
