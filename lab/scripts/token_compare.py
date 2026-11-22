#!/usr/bin/env python3
"""Controlled comparison of access-token claims. Prints redacted fields only."""
import base64
import json
import urllib.error
import urllib.parse
import urllib.request

KC = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/token"
USERINFO = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/userinfo"
AGENT_A = "spiffe://localtest.me/ns/team1/sa/weather-coordinator"
AGENT_B = "spiffe://localtest.me/ns/team1/sa/weather-service-advanced"
TOOL = "spiffe://localtest.me/ns/team1/sa/weather-tool-advanced"
ATYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"
KNOWN = {
    "87d55f09-1648-49af-ab6c-103acd884ae4": "lab-ny",
    "816acfdc-0eb3-4828-8ef0-6a7bc72a9d1e": "lab-lon",
}


def b64(part):
    part += "=" * ((4 - len(part) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def show_aud(value):
    if isinstance(value, str):
        value = [value]
    labels = []
    for item in value or []:
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
    return labels


def show_sub(value):
    if value is None or value == "":
        return "EMPTY"
    return KNOWN.get(value, "UNKNOWN_SUB")


def show_azp(value):
    if value == "weather-lab-user":
        return "weather-lab-user"
    if value == AGENT_A:
        return "coordinator-spiffe"
    if value == AGENT_B:
        return "weather-agent-spiffe"
    return "other-azp"


def show_iss(value):
    if str(value).endswith("/realms/rossoctl"):
        return "realm-issuer"
    return "other-iss"


def summarize(label, token, token_type, expires_in):
    header = b64(token.split(".")[0])
    payload = b64(token.split(".")[1])
    fields = {}
    for name in ("iss", "sub", "aud", "azp", "scope", "iat", "exp"):
        if name not in payload:
            fields[name] = "ABSENT"
        elif name == "aud":
            fields[name] = show_aud(payload[name])
        elif name == "sub":
            fields[name] = show_sub(payload[name])
        elif name == "azp":
            fields[name] = show_azp(payload[name])
        elif name == "iss":
            fields[name] = show_iss(payload[name])
        else:
            fields[name] = payload[name]
    print(label, json.dumps({
        "response_token_type": token_type,
        "expires_in": expires_in,
        "header_typ": header.get("typ", "ABSENT"),
        "header_alg": header.get("alg", "ABSENT"),
        "payload_keys": sorted(payload),
        "sub_key_present": "sub" in payload,
        "fields": fields,
    }, ensure_ascii=False))


def post(form):
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(KC, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            parsed = json.loads(exc.read().decode())
        except json.JSONDecodeError:
            parsed = {"error": "non_json"}
        return exc.code, parsed


def userinfo(token):
    req = urllib.request.Request(USERINFO, headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, "http_error", sorted(json.loads(exc.read().decode() or "{}"))
    return resp.status, show_sub(data.get("sub")) if "sub" in data else "ABSENT", sorted(data)


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
    print("MODE controlled_reproduction")
    for user, path in (("lab-ny", "/tmp/lab-ny.pass"), ("lab-lon", "/tmp/lab-lon.pass")):
        status, body = post({
            "grant_type": "password",
            "client_id": "weather-lab-user",
            "username": user,
            "password": open(path).read().strip(),
        })
        print(user, "grant", status, body.get("error"))
        token = body["access_token"]
        summarize(user + " T0", token, body.get("token_type"), body.get("expires_in"))
        print(user, "userinfo", *userinfo(token))
        status, exchanged = exchange(
            jwt_a, AGENT_A, token, AGENT_B, "openid agent-team1-weather-service-advanced-aud",
        )
        print(user, "T1_exchange", status, exchanged.get("error"))
        if exchanged.get("access_token"):
            summarize(user + " T1", exchanged["access_token"], exchanged.get("token_type"), exchanged.get("expires_in"))
        status, exchanged = exchange(
            jwt_b, AGENT_B, token, TOOL, "openid weather-tool-exchange-aud",
        )
        print(user, "T2_exchange", status, exchanged.get("error"))
        if exchanged.get("access_token"):
            summarize(user + " T2", exchanged["access_token"], exchanged.get("token_type"), exchanged.get("expires_in"))


if __name__ == "__main__":
    main()
