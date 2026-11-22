#!/usr/bin/env python3
"""Continuous exchange T0 -> T1 -> T2. Prints fingerprints and statuses only."""
import base64
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request

KC = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/token"
AGENT_A = "spiffe://localtest.me/ns/team1/sa/weather-coordinator"
AGENT_B = "spiffe://localtest.me/ns/team1/sa/weather-service-advanced"
TOOL = "spiffe://localtest.me/ns/team1/sa/weather-tool-advanced"
ATYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"
RUN = os.environ["RUN_ID"]
USER = os.environ["LAB_USER"]


def fp(token):
    return hashlib.sha256(token.encode()).hexdigest()


def post(form):
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(KC, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode())
        except json.JSONDecodeError:
            body = {"error": "non_json"}
        return exc.code, body


def aud_labels(token):
    part = token.split(".")[1]
    part += "=" * ((4 - len(part) % 4) % 4)
    payload = json.loads(base64.urlsafe_b64decode(part))
    aud = payload.get("aud")
    if isinstance(aud, str):
        aud = [aud]
    labels = []
    for item in aud or []:
        if str(item).endswith("/weather-coordinator"):
            labels.append("coordinator")
        elif str(item).endswith("/weather-service-advanced"):
            labels.append("weather-agent")
        elif str(item).endswith("/weather-tool-advanced"):
            labels.append("tool")
        elif str(item).endswith("/realms/rossoctl"):
            labels.append("realm")
        else:
            labels.append("other")
    sub = payload.get("sub")
    if "sub" not in payload:
        sub_label = "ABSENT"
    elif sub == "87d55f09-1648-49af-ab6c-103acd884ae4":
        sub_label = "lab-ny"
    elif sub == "816acfdc-0eb3-4828-8ef0-6a7bc72a9d1e":
        sub_label = "lab-lon"
    else:
        sub_label = "UNKNOWN_SUB"
    return sub_label, labels


def exchange(jwt, client, subject, audience, scope):
    return post({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": client,
        "client_assertion_type": ATYPE,
        "client_assertion": jwt,
        "subject_token": subject,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": audience,
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "scope": scope,
    })


def main():
    jwt_a = open("/tmp/jwt-a").read().strip()
    jwt_b = open("/tmp/jwt-b").read().strip()
    password = open(os.environ["PASS_FILE"]).read().strip()
    status, body = post({
        "grant_type": "password",
        "client_id": "weather-lab-user",
        "username": USER,
        "password": password,
    })
    if status != 200 or "access_token" not in body:
        print(RUN, "T0_grant", status, body.get("error"))
        raise SystemExit(1)
    t0 = body["access_token"]
    fp0 = fp(t0)
    status, ex1 = exchange(
        jwt_a, AGENT_A, t0, AGENT_B, "openid agent-team1-weather-service-advanced-aud",
    )
    if status != 200 or "access_token" not in ex1:
        print(RUN, "T1_exchange", status, ex1.get("error"), (ex1.get("error_description") or "")[:160])
        raise SystemExit(1)
    t1 = ex1["access_token"]
    fp1 = fp(t1)
    second_input = t1
    fp_in = fp(second_input)
    status, ex2 = exchange(
        jwt_b, AGENT_B, second_input, TOOL, "openid weather-tool-exchange-aud",
    )
    t2 = ex2.get("access_token", "")
    fp2 = fp(t2) if t2 else "NONE"
    print(
        "CHAIN",
        RUN,
        "user", USER,
        "T0", fp0,
        "T1", fp1,
        "second_input", fp_in,
        "input_equals_T1", fp_in == fp1,
        "T2", fp2,
        "T2_status", status,
        "T2_error", ex2.get("error") or "",
    )
    if not t2:
        print(RUN, "continuous_exchange", "FAIL", (ex2.get("error_description") or "")[:180])
        raise SystemExit(1)
    sub0, aud0 = aud_labels(t0)
    sub1, aud1 = aud_labels(t1)
    sub2, aud2 = aud_labels(t2)
    print(RUN, "claims", "T0", sub0, aud0, "T1", sub1, aud1, "T2", sub2, aud2)
    os.umask(0o077)
    open("/tmp/holder-t0", "w").write(t0)
    open("/tmp/holder-t2", "w").write(t2)
    open("/tmp/holder-fp", "w").write(fp2)


if __name__ == "__main__":
    main()
