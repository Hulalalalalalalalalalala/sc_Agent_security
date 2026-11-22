#!/usr/bin/env python3
"""Idempotent in-container patch for the official weather tool.

Adds the English city hint, copies Open-Meteo unit and timezone fields into
the tool result, and logs a caller-supplied task id. Does not change auth.
"""
from pathlib import Path

path = Path("/app/weather_tool.py")
text = path.read_text()

old_doc = '"""Get weather info for a city"""'
new_doc = (
    '"""Get weather info for a city. Pass city as the English place name '
    'indexed by the geocoding service, for example New York."""'
)
if old_doc in text:
    text = text.replace(old_doc, new_doc, 1)

old_ret = '        result = json.dumps(weather_data["current_weather"])'
new_ret = """        current = weather_data.get("current_weather") or {}
        units = weather_data.get("current_weather_units") or {}
        result = json.dumps(
            {
                "source": "open-meteo",
                "description": "weather data retrieved from Open-Meteo",
                "timezone": weather_data.get("timezone"),
                "utc_offset_seconds": weather_data.get("utc_offset_seconds"),
                "timezone_abbreviation": weather_data.get("timezone_abbreviation"),
                "temperature_unit": units.get("temperature"),
                "windspeed_unit": units.get("windspeed"),
                "winddirection_unit": units.get("winddirection"),
                "time": current.get("time"),
                "interval_seconds": current.get("interval"),
                "temperature": current.get("temperature"),
                "windspeed": current.get("windspeed"),
                "winddirection": current.get("winddirection"),
                "is_day": current.get("is_day"),
                "weathercode": current.get("weathercode"),
            }
        )"""
if old_ret in text:
    text = text.replace(old_ret, new_ret, 1)
elif '"source": "open-meteo"' not in text:
    raise SystemExit("weather result assignment not found")

old_mid = "    incoming_ctx = extract(dict(request.headers))\n"
new_mid = (
    "    lab_task = request.headers.get(\"x-lab-task-id\", \"\")\n"
    "    if lab_task:\n"
    "        logger.info(\"LAB_CORR task_id=%s method=%s path=%s\", lab_task, request.method, request.url.path)\n"
    "    incoming_ctx = extract(dict(request.headers))\n"
)
if "LAB_CORR" not in text:
    if old_mid not in text:
        raise SystemExit("trace middleware not found")
    text = text.replace(old_mid, new_mid, 1)

path.write_text(text)
print("tool patch applied")
