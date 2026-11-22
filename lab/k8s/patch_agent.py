#!/usr/bin/env python3
"""Idempotent in-container patch for the official weather agent.

The system prompt tells the model to quote unit and timezone fields from the
tool JSON. The executor forwards the A2A task id as a correlation header.
"""
from pathlib import Path

graph = Path("/app/src/weather_service/graph.py")
gtext = graph.read_text()
start = gtext.find('content="You are a helpful assistant')
if start < 0:
    raise SystemExit("system prompt not found")
end = gtext.find('"', start + len('content="'))
if end < 0:
    raise SystemExit("system prompt end not found")
prompt = (
    "You are a helpful assistant tasked with providing weather information. "
    "You must use the provided tools to complete your task. "
    "The tool JSON is weather data retrieved from Open-Meteo, not a direct weather-station observation. "
    "Quote time, temperature, windspeed, winddirection, is_day, and weathercode exactly. "
    "Quote temperature_unit, windspeed_unit, timezone, and utc_offset_seconds from the JSON. "
    "If timezone is null or absent, say the timezone was not provided. "
    "Do not describe the time as New York local time unless the timezone field says so. "
    "Do not convert units. Do not call the data simulated, assumed, or 模拟. "
    "Call it weather data retrieved from Open-Meteo. "
    "Do not add latitude, longitude, coordinates, or any fact that is not in the tool JSON. "
    "Never write a latitude or longitude number."
)
gtext = gtext[: start + len('content="')] + prompt + gtext[end:]
graph.write_text(gtext)

agent = Path("/app/src/weather_service/agent.py")
atext = agent.read_text()
old = """        mcp_headers = None
        if context.call_context and (context.call_context.state or {}).get("headers", {}).get("authorization"):
            mcp_headers = {"Authorization": context.call_context.state["headers"]["authorization"]}
            logger.info("Forwarding inbound Authorization header to MCP tool calls")
        else:
            logger.warning("No inbound Authorization header; MCP tool calls will be unauthenticated")
"""
new = """        mcp_headers = {}
        if context.call_context and (context.call_context.state or {}).get("headers", {}).get("authorization"):
            mcp_headers["Authorization"] = context.call_context.state["headers"]["authorization"]
            logger.info("Forwarding inbound Authorization header to MCP tool calls")
        else:
            logger.warning("No inbound Authorization header; MCP tool calls will be unauthenticated")
        task_id = getattr(context, "task_id", None)
        context_id = getattr(context, "context_id", None)
        if task_id:
            mcp_headers["X-Lab-Task-Id"] = str(task_id)
        logger.info("LAB_CORR task_id=%s context_id=%s", task_id, context_id)
"""
if old in atext:
    atext = atext.replace(old, new, 1)
elif "X-Lab-Task-Id" not in atext:
    raise SystemExit("agent header block not found")
agent.write_text(atext)
print("agent patch applied")
