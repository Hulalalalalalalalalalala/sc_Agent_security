#!/usr/bin/env python3
"""Rebuild chains from designated evidence. Does not read ground truth."""
import json
import sys
from pathlib import Path

FORBIDDEN = ("ground-truth", "tamper-manifest", "expected", "answer-key", "TRUTH")


def reject_forbidden(root):
    for path in root.rglob("*"):
        if any(part in path.name for part in FORBIDDEN):
            raise SystemExit("audit input contains forbidden file: %s" % path.name)


def load_json(path):
    return json.loads(path.read_text())


def label_subject(config, value):
    if value is None or value == "":
        return "空"
    return config["identities"]["users"].get(value, "未知主体")


def parse_logs(system):
    business = {"coordinator": [], "agent": [], "tool": []}
    auth = []
    for path in sorted(system.glob("*.log")):
        kind = "coordinator" if "coordinator" in path.name else "agent" if path.name.startswith("agent") else "tool" if path.name.startswith("tool") else ""
        for line in path.read_text(errors="replace").splitlines():
            if "eyJ" in line:
                continue
            if "LAB_CORR" in line and kind:
                item = {"file": path.name, "class": "既有应用补丁", "raw_has_task": "task_id=" in line or "upstream_task=" in line}
                if "message_id=" in line:
                    item["message_id"] = field(line, "message_id")
                    item["upstream_task"] = field(line, "upstream_task")
                    item["upstream_http"] = field(line, "upstream_http")
                    business["coordinator"].append(item)
                elif "context_id=" in line:
                    item["task_id"] = field(line, "task_id")
                    business["agent"].append(item)
                elif "method=" in line:
                    item["task_id"] = field(line, "task_id")
                    item["method"] = field(line, "method")
                    business["tool"].append(item)
            elif "auth" in path.name or "server-responses" in path.name:
                pass
            if "inbound authorized" in line or "outbound token exchanged" in line or "outbound passthrough" in line or "plugin rejected request" in line or "JWT validation failed" in line:
                auth.append({
                    "file": path.name,
                    "class": "被测系统证据",
                    "kind": kind_of(line),
                    "subject": label_subject_later(field(line, "subject")),
                    "subject_raw_present": "subject=" in line,
                    "client_id": field(line, "clientID"),
                    "host": field(line, "host"),
                    "audience": field(line, "audience"),
                    "reason": field(line, "reason") or field(line, "error"),
                    "link_status": "无法判断",
                })
    responses = system / "server-responses.jsonl"
    server = []
    if responses.exists():
        for line in responses.read_text().splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            item["class"] = "被测系统证据"
            item["link_status"] = "无法判断"
            server.append(item)
    return business, auth, server


def label_subject_later(value):
    return value


def field(line, name):
    needle = name + "="
    if needle not in line:
        return ""
    value = line.split(needle, 1)[1]
    for stop in (" ", "\t"):
        if stop in value:
            value = value.split(stop, 1)[0]
    return value.strip().strip('"')


def kind_of(line):
    if "inbound authorized" in line:
        return "inbound_authorized"
    if "outbound token exchanged" in line:
        return "outbound_exchanged"
    if "outbound passthrough" in line:
        return "outbound_passthrough"
    if "plugin rejected request" in line:
        return "rejected"
    return "jwt_validation_failed"


def merge_coordinator(rows):
    merged = {}
    order = []
    for row in rows:
        key = row.get("message_id") or ""
        if not key:
            continue
        if key not in merged:
            merged[key] = {"message_id": key, "upstream_task": "", "upstream_http": "", "file": row["file"]}
            order.append(key)
        if row.get("upstream_task"):
            current = merged[key]["upstream_task"]
            if current and current != row["upstream_task"]:
                merged[key].setdefault("upstream_conflicts", []).append(row["upstream_task"])
            else:
                merged[key]["upstream_task"] = row["upstream_task"]
                merged[key]["upstream_http"] = row.get("upstream_http") or ""
    return [merged[key] for key in order]


def status_business(entities, conflicts, complete_parts):
    if conflicts:
        return "存在多个可能关联"
    if not entities:
        return "无法判断"
    if complete_parts:
        return "能够明确重建"
    return "只能部分重建"


def overall(business_status):
    if business_status == "存在多个可能关联":
        return "存在多个可能关联"
    if business_status == "无法判断":
        return "无法判断"
    # 用户主体、认证记录和委托历史在原生日志中没有共享标识。
    return "只能部分重建"


def build_chains(business, config):
    del config
    agents = {}
    for row in business["agent"]:
        task_id = row.get("task_id") or ""
        if not task_id:
            continue
        agents.setdefault(task_id, []).append(row)
    tools = {}
    for row in business["tool"]:
        task_id = row.get("task_id") or ""
        if not task_id:
            continue
        tools.setdefault(task_id, []).append(row)
    chains = []
    used_tasks = set()
    for coord in merge_coordinator(business["coordinator"]):
        conflicts = list(coord.get("upstream_conflicts") or [])
        task_id = coord.get("upstream_task") or ""
        entities = ["coordinator"]
        notes = []
        agent_rows = agents.get(task_id) or []
        tool_rows = tools.get(task_id) or []
        if task_id:
            used_tasks.add(task_id)
            if len(agent_rows) == 1:
                entities.append("weather-agent")
            elif len(agent_rows) > 1:
                conflicts.append("同一任务有多条 Agent 记录")
                entities.append("weather-agent")
            else:
                notes.append("协调记录指向的任务在 Agent 日志中未出现")
            if len(tool_rows) >= 1:
                entities.append("tool")
            else:
                notes.append("工具日志中未出现同一任务 ID")
        else:
            notes.append("协调日志没有 upstream_task")
        complete = task_id and len(agent_rows) == 1 and len(tool_rows) >= 1 and not conflicts
        business_status = status_business(entities, conflicts, complete)
        chains.append({
            "chain_key": "message:" + coord["message_id"],
            "message_id": coord["message_id"],
            "task_id": task_id or None,
            "entities": entities,
            "business_status": business_status,
            "user_subject": "未观察到",
            "user_status": "无法判断",
            "auth_status": "无法判断",
            "delegation_status": "无法判断",
            "overall_status": overall(business_status),
            "conflicts": conflicts,
            "notes": notes,
            "association_method": "LAB_CORR 中 message_id 与 upstream_task、task_id 的字符串相等。该 ID 由应用写入，不是认证证明。",
            "evidence_class": "既有应用补丁",
        })
    for task_id, rows in agents.items():
        if task_id in used_tasks:
            continue
        tool_rows = tools.get(task_id) or []
        entities = ["weather-agent"]
        notes = ["没有协调器记录指向这个任务。审计结果不补出 A。"]
        if tool_rows:
            entities.append("tool")
        else:
            notes.append("工具日志中未出现同一任务 ID")
        complete = len(rows) == 1 and len(tool_rows) >= 1
        conflicts = ["同一任务有多条 Agent 记录"] if len(rows) > 1 else []
        business_status = status_business(entities, conflicts, complete)
        chains.append({
            "chain_key": "task:" + task_id,
            "message_id": None,
            "task_id": task_id,
            "entities": entities,
            "business_status": business_status,
            "user_subject": "未观察到",
            "user_status": "无法判断",
            "auth_status": "无法判断",
            "delegation_status": "无法判断",
            "overall_status": overall(business_status),
            "conflicts": conflicts,
            "notes": notes,
            "association_method": "Agent 与工具日志中的 task_id 相等。没有可用标识把这条链连到认证日志。",
            "evidence_class": "既有应用补丁",
        })
    return chains


def apply_subject_labels(auth, config):
    for item in auth:
        raw = item.pop("subject")
        item["subject_label"] = label_subject(config, raw)
        item.pop("subject_raw_present", None)


def auxiliary_notes(root, chains):
    path = root / "auxiliary" / "observations.jsonl"
    if not path.exists():
        return []
    notes = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        note = {
            "class": "辅助观测",
            "run_id": item.get("run_id"),
            "source_sa": item.get("source_sa"),
            "token_azp": item.get("token_azp"),
            "token_sub": item.get("token_sub"),
            "token_fp": item.get("token_fp"),
            "statement": "令牌指纹和来源工作负载只存在于测试观测。原生日志没有这些字段，不能据此把认证日志连到任务。",
        }
        if item.get("token_azp") and item.get("source_sa") and item.get("scenario") == "cross_workload_call":
            same = item.get("token_client_matches_sender")
            note["sender_matches_token_client"] = same
            note["statement"] = "辅助观测同时记录了来源 ServiceAccount 和令牌客户端。两者不一致时，只能说明测试驱动看到了差异，不能说明 AuthBridge 识别了发送方。"
        notes.append(note)
    del chains
    return notes


def analyze(root, use_auxiliary):
    reject_forbidden(root)
    config = load_json(root / "config" / "authz-rules.json")
    business, auth, server = parse_logs(root / "system")
    apply_subject_labels(auth, config)
    chains = build_chains(business, config)
    result = {
        "mode": "auxiliary" if use_auxiliary else "native",
        "chains": chains,
        "unlinked_auth_count": len(auth),
        "unlinked_auth": auth,
        "unlinked_server_responses": server,
        "auxiliary_notes": auxiliary_notes(root, chains) if use_auxiliary else [],
        "rules_consulted": [item["id"] for item in config["rules"] if item["configured"]],
        "not_configured": [item["id"] for item in config["rules"] if not item["configured"]],
    }
    return result


def main():
    root = Path(sys.argv[1])
    mode = sys.argv[2]
    out = Path(sys.argv[3])
    result = analyze(root, mode == "auxiliary")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(mode, "chains", len(result["chains"]), "unlinked_auth", result["unlinked_auth_count"])


if __name__ == "__main__":
    main()
