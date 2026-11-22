#!/usr/bin/env python3
"""Parser check only. Not a baseline measurement."""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def write_fixture(base):
    system = base / "system"
    config = base / "config"
    system.mkdir(parents=True)
    config.mkdir()
    shutil.copy(ROOT / "config" / "authz-rules.json", config / "authz-rules.json")
    (system / "coordinator-app.log").write_text(
        "LAB_CORR hop=A message_id=full-msg\n"
        "LAB_CORR hop=A message_id=full-msg upstream_task=task-full upstream_http=200\n"
    )
    (system / "agent-app.log").write_text(
        "LAB_CORR task_id=task-full context_id=c1\n"
        "LAB_CORR task_id=task-short context_id=c2\n"
    )
    (system / "tool-app.log").write_text(
        "LAB_CORR task_id=task-full method=POST path=/mcp\n"
        "LAB_CORR task_id=task-short method=POST path=/mcp\n"
    )
    (system / "agent-auth.log").write_text(
        'time=2026-11-16T00:00:00Z level=INFO msg="inbound authorized" subject=87d55f09-1648-49af-ab6c-103acd884ae4 clientID=weather-lab-user\n'
        'time=2026-11-16T00:00:01Z level=INFO msg="outbound token exchanged" host=weather-tool-advanced-mcp:8000 audience=spiffe://localtest.me/ns/team1/sa/weather-tool-advanced\n'
    )
    (system / "server-responses.jsonl").write_text("")


def run_audit(src, dest):
    subprocess.check_call([sys.executable, str(ROOT / "audit.py"), str(src), "native", str(dest)])
    return json.loads(dest.read_text())


def chain_by_key(result, key):
    for item in result["chains"]:
        if item["chain_key"] == key:
            return item
    return None


def main():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "clean"
        write_fixture(base)
        clean = run_audit(base, Path(tmp) / "clean.json")
        full = chain_by_key(clean, "message:full-msg")
        short = chain_by_key(clean, "task:task-short")
        assert full["business_status"] == "能够明确重建", full
        assert full["entities"] == ["coordinator", "weather-agent", "tool"], full
        assert full["overall_status"] == "只能部分重建"
        assert full["user_status"] == "无法判断"
        assert short["entities"] == ["weather-agent", "tool"], short
        assert "coordinator" not in short["entities"]
        assert clean["unlinked_auth_count"] == 2
        assert all(item["link_status"] == "无法判断" for item in clean["unlinked_auth"])
        cases = [
            ("delete_hop", "task-full", "full-msg", "task-short", "只能部分重建"),
            ("modify_parent", "task-full", "full-msg", "task-short", "只能部分重建"),
            ("mix_record", "task-full", "full-msg", "task-short", "存在多个可能关联"),
            ("modify_correlation", "task-full", "full-msg", "task-short", "只能部分重建"),
        ]
        for kind, task_id, message_id, other, expected in cases:
            dest = Path(tmp) / kind
            subprocess.check_call([
                sys.executable, str(ROOT / "tamper.py"), str(base), str(dest), kind, task_id, message_id, other,
            ])
            audited = run_audit(dest, Path(tmp) / (kind + ".json"))
            got = chain_by_key(audited, "message:full-msg")
            assert got["business_status"] == expected, (kind, got)
            assert got["overall_status"] != "能够明确重建"
    print("fixture_check_ok")


if __name__ == "__main__":
    main()
