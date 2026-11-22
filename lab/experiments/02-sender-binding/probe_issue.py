#!/usr/bin/env python3
"""Probe whether Keycloak binds a DPoP key during JWT-SVID token exchange.

Prints statuses, fingerprints, and claim labels only.
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
from pydpop import generate_key, generate_proof, jwk_thumbprint, public_jwk

KC = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/token"
AGENT_A = "spiffe://localtest.me/ns/team1/sa/weather-coordinator"
AGENT_B = "spiffe://localtest.me/ns/team1/sa/weather-service-advanced"
TOOL = "spiffe://localtest.me/ns/team1/sa/weather-tool-advanced"
ATYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"


def fp(token):
    return hashlib.sha256(token.encode()).hexdigest()


def b64json(segment):
    segment += "=" * ((4 - len(segment) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(segment))


def labels(token):
    payload = b64json(token.split(".")[1])
    aud = payload.get("aud")
    if isinstance(aud, str):
        aud = [aud]
    names = []
    for item in aud or []:
        text = str(item)
        if text.endswith("/weather-coordinator"):
            names.append("coordinator")
        elif text.endswith("/weather-service-advanced"):
            names.append("weather-agent")
        elif text.endswith("/weather-tool-advanced"):
            names.append("tool")
        elif text.endswith("/realms/rossoctl"):
            names.append("realm")
        else:
            names.append("other")
    sub = payload.get("sub")
    if "sub" not in payload:
        sub_label = "ABSENT"
    elif sub == "87d55f09-1648-49af-ab6c-103acd884ae4":
        sub_label = "lab-ny"
    elif sub == "816acfdc-0eb3-4828-8ef0-6a7bc72a9d1e":
        sub_label = "lab-lon"
    else:
        sub_label = "UNKNOWN_SUB"
    cnf = payload.get("cnf") if isinstance(payload.get("cnf"), dict) else {}
    return {
        "sub": sub_label,
        "aud": names,
        "azp_kind": "weather-agent" if payload.get("azp") == AGENT_B else (
            "coordinator" if payload.get("azp") == AGENT_A else (
                "lab-user" if payload.get("azp") == "weather-lab-user" else "other"
            )
        ),
        "cnf_jkt": cnf.get("jkt") or "ABSENT",
        "cnf_x5t": "present" if cnf.get("x5t#S256") else "ABSENT",
        "typ": payload.get("typ"),
    }


def post(form, proof=None):
    data = urllib.parse.urlencode(form).encode()
    headers = {}
    if proof:
        headers["DPoP"] = proof
    req = urllib.request.Request(KC, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            nonce = resp.headers.get("DPoP-Nonce")
            body = json.loads(resp.read().decode())
            return resp.status, body, nonce
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        nonce = exc.headers.get("DPoP-Nonce")
        if "eyJ" in raw:
            raw = "REDACTED"
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = {"error": "non_json", "error_description": raw[:180]}
        return exc.code, body, nonce


def with_dpop(form, key, nonce=None):
    proof = generate_proof(private_key=key, htm="POST", htu=KC, nonce=nonce)
    status, body, new_nonce = post(form, proof)
    if status != 200 and new_nonce and new_nonce != nonce:
        proof = generate_proof(private_key=key, htm="POST", htu=KC, nonce=new_nonce)
        status, body, new_nonce = post(form, proof)
    return status, body, new_nonce


def show(name, status, body, key=None):
    if status != 200 or "access_token" not in body:
        desc = (body.get("error_description") or "")[:180]
        print(name, "status", status, "error", body.get("error"), "desc", desc)
        return None
    token = body["access_token"]
    info = labels(token)
    thumb = jwk_thumbprint(public_jwk(key)) if key is not None else ""
    print(
        name,
        "status", status,
        "token_type", body.get("token_type"),
        "fp", fp(token),
        "sub", info["sub"],
        "aud", info["aud"],
        "azp", info["azp_kind"],
        "cnf_jkt_match", info["cnf_jkt"] == thumb if key is not None else "n/a",
        "cnf_jkt_present", info["cnf_jkt"] != "ABSENT",
        "x5t", info["cnf_x5t"],
    )
    return token


def main():
    jwt_a = open("/tmp/jwt-a").read().strip()
    jwt_b = open("/tmp/jwt-b").read().strip()
    user = os.environ["LAB_USER"]
    password = open(os.environ["PASS_FILE"]).read().strip()
    key_b = generate_key("ES256")
    key_a = generate_key("ES256")
    status, body, _ = post({
        "grant_type": "password",
        "client_id": "weather-lab-user",
        "username": user,
        "password": password,
    })
    t0 = show("T0_unbound", status, body)
    if not t0:
        raise SystemExit(1)

    status, body, _ = with_dpop({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": AGENT_B,
        "client_assertion_type": ATYPE,
        "client_assertion": jwt_b,
        "subject_token": t0,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": TOOL,
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "scope": "openid weather-tool-exchange-aud",
    }, key_b)
    show("B_exchange_T0_with_DPoP", status, body, key_b)

    status, body, _ = with_dpop({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": AGENT_A,
        "client_assertion_type": ATYPE,
        "client_assertion": jwt_a,
        "subject_token": t0,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": AGENT_B,
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "scope": "openid agent-team1-weather-service-advanced-aud",
    }, key_a)
    t1_bound = show("A_exchange_T0_with_DPoP", status, body, key_a)
    if t1_bound:
        status, body, _ = with_dpop({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": AGENT_B,
            "client_assertion_type": ATYPE,
            "client_assertion": jwt_b,
            "subject_token": t1_bound,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": TOOL,
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": "openid weather-tool-exchange-aud",
        }, key_b)
        show("B_exchange_bound_T1", status, body, key_b)

    status, body, _ = post({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": AGENT_A,
        "client_assertion_type": ATYPE,
        "client_assertion": jwt_a,
        "subject_token": t0,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": AGENT_B,
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "scope": "openid agent-team1-weather-service-advanced-aud",
    })
    t1 = show("A_exchange_T0_without_DPoP", status, body)
    if t1:
        status, body, _ = with_dpop({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": AGENT_B,
            "client_assertion_type": ATYPE,
            "client_assertion": jwt_b,
            "subject_token": t1,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": TOOL,
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": "openid weather-tool-exchange-aud",
        }, key_b)
        show("B_exchange_unbound_T1_with_DPoP", status, body, key_b)


if __name__ == "__main__":
    main()
