#!/usr/bin/env python3
"""Score auditor output against ground truth. The auditor never runs here."""
import hashlib
import json
import re
from pathlib import Path
import sys

BUSINESS = {"full_path", "short_path", "concurrent"}


def load_jsonl(path):
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def load_json(path):
    return json.loads(path.read_text())


def chain_map(audit):
    return {item["chain_key"]: item for item in audit["chains"]}


def open_meteo_objects(text):
    found = []
    for match in re.finditer(r'\{"source": "open-meteo".*?\}', text):
        try:
            obj = json.loads(match.group(0))
        except json.JSONDecodeError:
            continue
        if "temperature" in obj:
            found.append(obj)
    unique = []
    seen = set()
    for obj in found:
        key = (obj.get("temperature"), obj.get("windspeed"), obj.get("winddirection"), obj.get("weathercode"))
        if key not in seen:
            seen.add(key)
            unique.append(obj)
    return unique


def task_segment(agent_log, task_id):
    lines = agent_log.splitlines()
    indexes = [i for i, line in enumerate(lines) if "LAB_CORR" in line and "task_id=%s" % task_id in line]
    if not indexes:
        return ""
    end = len(lines)
    for index in range(indexes[0] + 1, len(lines)):
        if "LAB_CORR" in lines[index] and "task_id=%s" % task_id not in lines[index]:
            end = index
            break
    return "\n".join(lines[indexes[0]:end])


def find_weather(agent_log, task_id, answer):
    segment = task_segment(agent_log, task_id)
    if not segment:
        return None, "未观察到", "被测系统证据"
    same_line = [obj for line in segment.splitlines() if task_id in line for obj in open_meteo_objects(line)]
    if len(same_line) == 1:
        return same_line[0], "同一日志行同时含任务 ID 和工具 JSON", "被测系统证据"
    objects = open_meteo_objects(segment)
    unavailable = "temporarily unavailable" in segment or "暂时不可用" in (answer or "")
    if len(objects) > 1:
        return None, "顺序邻接区间里有多份工具 JSON，且这些行没有任务 ID，无法判断", "辅助观测"
    if len(objects) == 1:
        return objects[0], "同一进程中两条 LAB_CORR 之间的顺序邻接，不是认证关联", "辅助观测"
    if unavailable:
        return None, "工具结果是暂时不可用，没有天气 JSON", "被测系统证据"
    if open_meteo_objects(agent_log):
        return None, "工具 JSON 出现在其他日志行，那些行没有这个任务 ID", "被测系统证据"
    return None, "未观察到", "被测系统证据"


def compare_answer(answer, data):
    if not isinstance(data, dict):
        return "未观察到"
    missing = []
    seen = 0
    for key in ("temperature", "windspeed", "winddirection", "weathercode", "timezone"):
        value = data.get(key)
        if value is None:
            continue
        seen += 1
        if str(value) not in (answer or ""):
            missing.append(key)
    if seen == 0:
        return "未观察到"
    if missing:
        return "不一致:" + ",".join(missing)
    return "一致"


def classify_run(run):
    state = run.get("task_state") or ""
    answer = run.get("answer") or ""
    if run.get("scenario") in {"deny_tool_direct", "deny_exchange", "deny_wrong_audience"}:
        return "授权结果"
    if run.get("scenario") == "cross_workload":
        return "跨工作负载"
    if not run.get("task_id"):
        return "调用未完成"
    if "temporarily unavailable" in answer.lower() or "暂时不可用" in answer:
        return "工具上游失败"
    if "FAILED" in state or "失败" in answer:
        return "模型或上游失败"
    if "not found" in answer.lower():
        return "工具查询失败"
    if state and "COMPLETED" not in state:
        return "模型或上游失败"
    return "业务调用完成"


def expected_chain(run, chains):
    if run.get("entry") == "coordinator" and run.get("message_id"):
        return chains.get("message:" + run["message_id"])
    if run.get("task_id"):
        return chains.get("task:" + run["task_id"])
    return None


def business_match(run, item):
    if not item or not run.get("task_id"):
        return False
    if item.get("task_id") != run["task_id"]:
        return False
    if item.get("business_status") != "能够明确重建":
        return False
    entities = item.get("entities") or []
    if run.get("entry") == "coordinator":
        return entities == ["coordinator", "weather-agent", "tool"]
    return "coordinator" not in entities and entities == ["weather-agent", "tool"]


def wrong_link(run, chains):
    """Count a link that contradicts the driver, not a merely missing link."""
    count = 0
    if run.get("entry") == "coordinator" and run.get("message_id"):
        item = chains.get("message:" + run["message_id"])
        if item and item.get("task_id") and run.get("task_id") and item["task_id"] != run["task_id"] and item["business_status"] == "能够明确重建":
            count += 1
    if run.get("entry") != "coordinator" and run.get("task_id"):
        item = chains.get("task:" + run["task_id"])
        if item and "coordinator" in (item.get("entities") or []) and item["business_status"] == "能够明确重建":
            count += 1
    return count


def tamper_result(kind, audit, original_task, message_id):
    chains = chain_map(audit)
    item = chains.get("message:" + message_id) if message_id else None
    if item is None:
        return {"kind": kind, "result": "无法判断", "detail": "篡改后的副本里没有原来的 message_id 链"}
    accepted_original = (
        item.get("business_status") == "能够明确重建"
        and item.get("task_id") == original_task
        and "tool" in (item.get("entities") or [])
        and "coordinator" in (item.get("entities") or [])
    )
    if accepted_original:
        return {"kind": kind, "result": "错误接受", "detail": "篡改后仍把原调用链当成业务标识完整的链"}
    misleading = False
    orphan = chains.get("task:" + original_task) if original_task else None
    if kind == "modify_parent" and orphan and orphan.get("business_status") == "能够明确重建" and "coordinator" not in orphan.get("entities", []):
        misleading = True
    if item.get("business_status") == "无法判断" and not item.get("notes") and not item.get("conflicts"):
        result = "无法判断"
    else:
        result = "发现异常"
    detail = "；".join(item.get("notes") or []) or item.get("business_status")
    if misleading:
        detail += "。下游 Agent 和工具记录仍形成一条没有 A 的链，审计不能发现它本应属于被改掉的父调用。"
    return {"kind": kind, "result": result, "misleading_short_path": misleading, "detail": detail, "business_status": item.get("business_status")}


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def diagram(runs):
    full = next((item for item in runs if item.get("scenario") == "full_path" and item.get("task_id")), None)
    short = next((item for item in runs if item.get("scenario") == "short_path" and item.get("task_id")), None)
    lines = ["```mermaid", "sequenceDiagram", "  participant Driver as 测试驱动器", "  participant A as 协调器 A", "  participant B as 天气 Agent B", "  participant Tool as 工具", "  participant Auth as AuthBridge"]
    if full:
        lines.append("  Driver->>A: %s 的用户令牌" % full["run_id"])
        lines.append("  A->>B: 业务日志 upstream_task 与 B 的 task_id 相等")
        lines.append("  B->>Tool: 业务日志 task_id 相等")
    if short:
        lines.append("  Driver->>B: %s 直接进入 B，日志中没有 A" % short["run_id"])
        lines.append("  B->>Tool: 业务日志 task_id 相等")
    lines.append("  Note over Auth: 入站和交换记录没有任务 ID，不能连到某一跳")
    lines.append("```")
    return "\n".join(lines)


def main():
    out = Path(sys.argv[1])
    runs = load_jsonl(out / "ground-truth" / "runs.jsonl")
    calls = load_jsonl(out / "ground-truth" / "calls.jsonl")
    native = load_json(out / "audit" / "native.json")
    auxiliary = load_json(out / "audit" / "auxiliary.json")
    chains = chain_map(native)
    agent_log = (out / "audit-input" / "system" / "agent-app.log").read_text() if (out / "audit-input" / "system" / "agent-app.log").exists() else ""
    cases = []
    business_runs = [item for item in runs if item.get("scenario") in BUSINESS]
    business_aligned = 0
    wrong = 0
    for run in runs:
        kind = classify_run(run)
        item = expected_chain(run, chains) if run.get("scenario") in BUSINESS else None
        matched = business_match(run, item) if item else False
        if run.get("scenario") in BUSINESS and run.get("task_id"):
            if matched:
                business_aligned += 1
            wrong += wrong_link(run, chains)
        weather, weather_method, weather_class = (None, "未观察到", "被测系统证据")
        if run.get("task_id"):
            weather, weather_method, weather_class = find_weather(agent_log, run["task_id"], run.get("answer") or "")
        if run.get("scenario") not in BUSINESS:
            answer_check = "不适用"
        elif weather_method.startswith("顺序邻接区间里有多份") or weather_method.startswith("工具 JSON 出现在其他日志行"):
            answer_check = "无法判断"
        elif weather_method == "工具结果是暂时不可用，没有天气 JSON":
            answer_check = "工具上游失败"
        else:
            answer_check = compare_answer(run.get("answer") or "", weather)
        cases.append({
            "run_id": run.get("run_id"),
            "scenario": run.get("scenario"),
            "user": run.get("user"),
            "entry": run.get("entry"),
            "task_id": run.get("task_id"),
            "http": run.get("http"),
            "task_state": run.get("task_state"),
            "execution": kind,
            "business_path": None if item is None else item.get("business_status"),
            "entities": None if item is None else item.get("entities"),
            "overall_audit": None if item is None else item.get("overall_status"),
            "user_audit": None if item is None else item.get("user_status"),
            "business_ids_match_driver": matched,
            "answer_matches_tool_json": answer_check,
            "tool_json_method": weather_method,
            "tool_json_class": weather_class,
            "error": run.get("error") or "",
        })
    auth_events = native["unlinked_auth"]
    exchanges = [item for item in auth_events if item["kind"] == "outbound_exchanged"]
    linked_exchanges = [item for item in exchanges if item["link_status"] != "无法判断"]
    hop_denominator = 0
    for run in business_runs:
        if not run.get("task_id"):
            continue
        hop_denominator += 5 if run.get("entry") == "coordinator" else 3
    tamper_manifest = load_json(out / "scoring" / "tamper-manifest.json") if (out / "scoring" / "tamper-manifest.json").exists() else []
    tamper_rows = []
    for item in tamper_manifest:
        audit = load_json(out / "tamper" / item["kind"] / "native.json")
        tamper_rows.append(tamper_result(item["kind"], audit, item.get("task_id") or "", item.get("message_id") or ""))
    hashes = {"class": "外部完整性检查", "counted_as_native_detection": False, "files": {}}
    for path in sorted((out / "audit-input" / "system").glob("*.log")):
        hashes["files"][path.name] = file_hash(path)
    complete = 0
    for case in cases:
        if case["scenario"] in BUSINESS and case["overall_audit"] == "能够明确重建":
            complete += 1
    business_denominator = len([run for run in business_runs if run.get("task_id")])
    metrics = {
        "sample_limit": "本次只覆盖固定矩阵中的少量调用，不能外推成总体比例。",
        "authorization_chain_complete": {"count": complete, "denominator": business_denominator, "definition": "业务路径、用户主体、每一跳授权依据和委托历史都能明确重建"},
        "business_id_alignment": {"count": business_aligned, "denominator": business_denominator, "definition": "只表示既有 LAB_CORR 标识能够对齐，不是授权链完整重建"},
        "auth_hops_traceable": {"count": 0, "denominator": hop_denominator, "definition": "认证日志与该跳共享任务标识"},
        "exchange_unique_task_link": {"count": len(linked_exchanges), "denominator": len(exchanges), "definition": "一条交换日志只对应一个任务"},
        "wrong_cross_task_links": wrong,
        "tamper": tamper_rows,
        "unlinked_auth_events": len(auth_events),
        "cannot_judge_is_not_pass": True,
    }
    (out / "scoring").mkdir(exist_ok=True)
    (out / "scoring" / "cases.json").write_text(json.dumps(cases, ensure_ascii=False, indent=2) + "\n")
    (out / "scoring" / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2) + "\n")
    (out / "scoring" / "external-hashes.json").write_text(json.dumps(hashes, ensure_ascii=False, indent=2) + "\n")
    (out / "collector" / "hop-sheet.jsonl").parent.mkdir(exist_ok=True)
    with (out / "collector" / "hop-sheet.jsonl").open("w") as handle:
        for run in runs:
            handle.write(json.dumps(hop_row(run, chains), ensure_ascii=False) + "\n")
    report = render(out, runs, calls, cases, metrics, native, auxiliary)
    (out / "REPORT.md").write_text(report)
    print("scored", business_denominator, "business_runs")


def hop_row(run, chains):
    item = expected_chain(run, chains) if run.get("scenario") in BUSINESS else None
    return {
        "run_id": run.get("run_id"),
        "root_message_id": {"value": run.get("message_id"), "class": "实验真值", "method": "驱动器写入请求体"},
        "local_task_id": {"value": run.get("task_id") or "未观察到", "class": "实验真值", "method": "驱动器读取响应；响应中没有则未观察到"},
        "user_subject_in_token": {"value": "未观察到与这一跳共享标识的主体声明", "class": "被测系统证据"},
        "token_client": {"value": "未观察到", "class": "被测系统证据", "method": "认证日志没有任务标识，不能填到这一跳"},
        "source_sa": {"value": run.get("source_sa") or "未观察到", "class": "实验真值"},
        "business_entities_from_audit": None if item is None else item.get("entities"),
        "auth_result_traceable_to_this_run": "无法判断",
        "delegation_history": "未观察到",
    }


def render(out, runs, calls, cases, metrics, native, auxiliary):
    del auxiliary
    lines = [
        "# 授权链与可审计性基线",
        "",
        "输出目录 `%s`。" % out.name,
        "",
        "审计程序只读了 `audit-input` 里的系统日志、服务响应和固定规则。评分程序才读取实验真值。无法判断不计为通过。",
        "",
        "## 指标",
        "",
        "分母都是这次矩阵里实际产生的对象，不是估计的总体。",
        "",
        "| 指标 | 分子 | 分母 |",
        "| --- | --- | --- |",
        "| 授权链完整重建 | %s | %s |" % (metrics["authorization_chain_complete"]["count"], metrics["authorization_chain_complete"]["denominator"]),
        "| 业务标识对齐 | %s | %s |" % (metrics["business_id_alignment"]["count"], metrics["business_id_alignment"]["denominator"]),
        "| 逐跳授权可追溯 | %s | %s |" % (metrics["auth_hops_traceable"]["count"], metrics["auth_hops_traceable"]["denominator"]),
        "| 交换记录唯一关联任务 | %s | %s |" % (metrics["exchange_unique_task_link"]["count"], metrics["exchange_unique_task_link"]["denominator"]),
        "| 跨任务错误关联 | %s | 业务调用 |" % metrics["wrong_cross_task_links"],
        "",
        "授权链完整重建要求同时确定经过的实体、用户、每一跳的授权依据和委托历史。业务标识对齐只表示既有 LAB_CORR 文本能够对上，LAB_CORR 不是认证证明。",
        "",
        "## 逐案例",
        "",
        "| 运行 | 场景 | 执行 | 审计总体 | 业务标识 | 回答与工具 JSON | 工具 JSON 来源 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for case in cases:
        lines.append("| %s | %s | %s | %s | %s | %s | %s |" % (
            case["run_id"], case["scenario"], case["execution"], case["overall_audit"] or "不适用",
            case["business_path"] or "不适用", case["answer_matches_tool_json"], case["tool_json_method"],
        ))
    failed = [item["run_id"] for item in cases if item["execution"] == "工具上游失败"]
    unknown = [item["run_id"] for item in cases if item["answer_matches_tool_json"] == "无法判断"]
    matched = [item["run_id"] for item in cases if item["answer_matches_tool_json"] == "一致"]
    lines.extend([
        "",
        "工具上游失败的运行：%s。回答与唯一工具 JSON 一致的运行：%s。工具 JSON 无法按任务归属的运行：%s。归属失败是因为 JSON 所在日志行没有任务 ID，并发时又落在交错区间里。" % (
            "、".join(failed) or "无", "、".join(matched) or "无", "、".join(unknown) or "无"),
        "",
        "## 证据篡改",
        "",
    ])
    if not metrics["tamper"]:
        lines.append("没有可篡改的完整业务链，篡改测试未执行。")
    for row in metrics["tamper"]:
        lines.append("- %s：%s。%s" % (row["kind"], row["result"], row["detail"]))
    lines.extend([
        "",
        "导出文件的 SHA-256 能看出副本被改过。这是外部完整性检查，没有计入上面的发现数。原系统没有把这个摘要写进认证日志。",
        "",
        "## 未关联的认证事件",
        "",
        "窗口内认证相关日志 %s 条，其中令牌交换 %s 条。全部因为没有共享任务标识而标为无法判断。拒绝原因出现在这些日志里，包括 audience 不匹配和缺少 Authorization，但不能指认到某一次驱动器请求。" % (
            metrics["unlinked_auth_events"], metrics["exchange_unique_task_link"]["denominator"]),
        "",
        "## 时序",
        "",
        "实线只表示驱动器发起的调用，以及业务日志里能够用同一个任务 ID 串起来的跳。AuthBridge 记录画在图外，因为它们不能连到某一跳。",
        "",
        diagram(runs),
        "",
        "## 跨工作负载调用",
        "",
    ])
    cross = [item for item in runs if item.get("scenario") == "cross_workload"]
    if cross:
        lines.append("驱动器记录的后端调用 HTTP %s，MCP 结果 %s。" % (
            cross[0].get("backend_call", {}).get("http"), cross[0].get("backend_call", {}).get("mcp")))
        lines.append("缺令牌 HTTP %s，原始 T0 HTTP %s。" % (
            cross[0].get("no_token", {}).get("http"), cross[0].get("raw_t0", {}).get("http")))
    if calls:
        for call in calls:
            lines.append("来自 %s 的调用 HTTP %s，MCP 结果 %s，令牌指纹与后端调用相同：%s。" % (
                call.get("source_sa"), call.get("http"), call.get("mcp"), call.get("token_fp") == (cross[0].get("t2_fp") if cross else None)))
    lines.extend([
        "",
        "原生认证日志只能看到令牌里的 clientID。它不能表示实际发送工作负载。允许这次调用，只说明 JWT 校验通过，不说明发送方就是 B。",
        "",
        "## 能力来源",
        "",
        "- 原系统：AuthBridge 记录主体、clientID、audience、拒绝原因；Keycloak 对交换请求返回允许或拒绝。这些记录没有任务 ID。",
        "- 本轮之前已经加在常驻进程里的补丁：协调器、B 和工具日志中的 LAB_CORR。它能对齐业务标识，不能证明身份或委托。",
        "- 本轮新增：测试驱动器保存的令牌指纹、来源 ServiceAccount、脱敏证据分目录、只读证据的审计程序和评分程序。没有修改运行中的认证策略，也没有新增运行时日志补丁。",
        "",
    ])
    del native
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
