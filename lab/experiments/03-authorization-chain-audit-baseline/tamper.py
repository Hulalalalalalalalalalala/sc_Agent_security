#!/usr/bin/env python3
"""Copy exported logs and change only the copy."""
import shutil
import sys
from pathlib import Path


def main():
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    kind = sys.argv[3]
    task_id = sys.argv[4]
    message_id = sys.argv[5]
    other_task = sys.argv[6]
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    tool = dst / "system" / "tool-app.log"
    coord = dst / "system" / "coordinator-app.log"
    agent = dst / "system" / "agent-app.log"
    if kind == "delete_hop":
        lines = [line for line in tool.read_text().splitlines() if task_id not in line]
        tool.write_text("\n".join(lines) + ("\n" if lines else ""))
    elif kind == "modify_parent":
        text = coord.read_text().replace("upstream_task=%s" % task_id, "upstream_task=tampered-parent")
        coord.write_text(text)
    elif kind == "mix_record":
        with coord.open("a") as handle:
            handle.write("LAB_CORR hop=A message_id=%s upstream_task=%s upstream_http=200\n" % (message_id, other_task))
    elif kind == "modify_correlation":
        text = tool.read_text().replace("task_id=%s" % task_id, "task_id=tampered-tool-task")
        tool.write_text(text)
    else:
        raise SystemExit("unknown tamper")
    del agent
    print(kind, "copied")


if __name__ == "__main__":
    main()
