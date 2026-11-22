#!/usr/bin/env python3
"""Keep authentication, correlation, and tool-result lines. Drop tokens."""
import sys
from pathlib import Path

KEEP = (
    "LAB_CORR",
    "inbound authorized",
    "outbound token exchanged",
    "outbound passthrough",
    "plugin rejected request",
    "JWT validation failed",
    "temperature",
    "weathercode",
    "CallTool",
    "TASK_STATE",
)


def clean(line):
    if "eyJ" in line:
        return ""
    if any(item in line for item in KEEP):
        return line[:100000]
    return ""


def main():
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    dst.mkdir(parents=True, exist_ok=True)
    kept = 0
    dropped = 0
    for path in sorted(src.glob("*.log")):
        lines = []
        for line in path.read_text(errors="replace").splitlines():
            cleaned = clean(line)
            if cleaned:
                lines.append(cleaned)
                kept += 1
            else:
                dropped += 1
        (dst / path.name).write_text("\n".join(lines) + ("\n" if lines else ""))
    print("export_kept", kept, "export_dropped", dropped)


if __name__ == "__main__":
    main()
