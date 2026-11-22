#!/usr/bin/env python3
"""Split driver stdout into ground truth, auxiliary observations, and server responses."""
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
text = Path(sys.argv[2]).read_text(errors="replace") if len(sys.argv) > 2 else sys.stdin.read()
truth = out / "ground-truth"
aux = out / "auxiliary"
system = out / "audit-input" / "system"
for path in (truth, aux, system):
    path.mkdir(parents=True, exist_ok=True)
with (truth / "runs.jsonl").open("a") as runs, (truth / "calls.jsonl").open("a") as calls, (aux / "observations.jsonl").open("a") as observations, (system / "server-responses.jsonl").open("a") as server:
    for line in text.splitlines():
        if line.startswith("TRUTH "):
            runs.write(line[len("TRUTH "):] + "\n")
        elif line.startswith("AUX "):
            observations.write(line[len("AUX "):] + "\n")
        elif line.startswith("CALL "):
            calls.write(line[len("CALL "):] + "\n")
        elif line.startswith("SERVER "):
            server.write(line[len("SERVER "):] + "\n")
        else:
            if "eyJ" in line:
                continue
            with (out / "driver-notes.txt").open("a") as notes:
                notes.write(line[:500] + "\n")
