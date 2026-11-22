#!/usr/bin/env python3
"""One A2A weather task. Prints TRUTH and AUX JSON only."""
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request

KC = "http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/token"
RUN = os.environ["RUN_ID"]
USER = os.environ["LAB_USER"]
URL = os.environ["AGENT_URL"]
PROMPT = os.environ["AGENT_PROMPT"]
CITY = os.environ["CITY"]
SCENARIO = os.environ["SCENARIO"]


def fp(token):
    return hashlib.sha256(token.encode()).hexdigest()


def claim_labels(token):
    part = token.split(".")[1]
    part += "=" * ((4 - len(part) % 4) % 4)
    import base64
    payload = json.loads(base64.urlsafe_b64decode(part))
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
    azp = payload.get("azp")
    if azp == "weather-lab-user":
        azp_label = "lab-user"
    elif isinstance(azp, str) and azp.endswith("/weather-coordinator"):
        azp_label = "coordinator"
    elif isinstance(azp, str) and azp.endswith("/weather-service-advanced"):
        azp_label = "weather-agent"
    else:
        azp_label = "other"
    return sub_label, names, azp_label


def post_form(form):
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(KC, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())


def find_task(obj):
    if isinstance(obj, dict):
        status = obj.get("status")
        if isinstance(status, dict) and isinstance(obj.get("id"), str):
            state = status.get("state")
            return obj.get("id"), state if isinstance(state, str) else ""
        for value in obj.values():
            found = find_task(value)
            if found[0]:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = find_task(item)
            if found[0]:
                return found
    return "", ""


def find_text(obj, out):
    if isinstance(obj, dict):
        text = obj.get("text")
        if isinstance(text, str):
            out.append(text)
        for value in obj.values():
            find_text(value, out)
    elif isinstance(obj, list):
        for item in obj:
            find_text(item, out)


def main():
    password = open(os.environ["PASS_FILE"]).read().strip()
    body = post_form({
        "grant_type": "password",
        "client_id": "weather-lab-user",
        "username": USER,
        "password": password,
    })
    token = body["access_token"]
    sub_label, aud, azp = claim_labels(token)
    message_id = RUN + "-msg"
    payload = {
        "jsonrpc": "2.0",
        "id": RUN,
        "method": "SendMessage",
        "params": {"message": {"messageId": message_id, "role": "ROLE_USER", "parts": [{"text": PROMPT}]}},
    }
    raw_body = json.dumps(payload).encode()
    req = urllib.request.Request(
        URL,
        data=raw_body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "A2A-Version": "1.0",
            "Authorization": "Bearer " + token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=420) as resp:
            status = resp.status
            raw = resp.read().decode()
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read().decode()
    parsed = None
    if "eyJ" not in raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
    task_id, state = find_task(parsed) if isinstance(parsed, dict) else ("", "")
    texts = []
    if parsed is not None:
        find_text(parsed, texts)
    answer = "\n".join(texts)[:1500]
    error = ""
    if isinstance(parsed, dict) and parsed.get("error"):
        error = json.dumps(parsed.get("error"), ensure_ascii=False)[:240]
    print("TRUTH " + json.dumps({
        "run_id": RUN,
        "scenario": SCENARIO,
        "user": USER,
        "entry": os.environ.get("ENTRY", ""),
        "message_id": message_id,
        "city": CITY,
        "http": status,
        "task_id": task_id or None,
        "task_state": state or None,
        "answer": answer,
        "error": error,
        "source_sa": os.environ.get("SOURCE_SA", ""),
        "source_pod": os.environ.get("SOURCE_POD", ""),
    }, ensure_ascii=False))
    print("AUX " + json.dumps({
        "run_id": RUN,
        "class": "辅助观测",
        "token_fp": fp(token),
        "token_sub": sub_label,
        "token_aud": aud,
        "token_azp": azp,
        "source_sa": os.environ.get("SOURCE_SA", ""),
        "source_pod": os.environ.get("SOURCE_POD", ""),
        "target": URL,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
