"""Runnable Reference Python Agent Behind `LineageSidecar` (`127.0.0.1:9001`)."""

from __future__ import annotations

import argparse
import signal
import threading
from typing import Any, Callable, Dict, Tuple

try:
    from lineage.sdk.python.lct_sdk import (
        DEFAULT_SIDECAR_OUTBOUND_URL,
        LCTAgentServer,
        LCTRequestContext,
        LCTSidecarClient,
        PermissionSpec,
        load_loopback_secret,
    )
except ImportError:
    from lct_sdk import (  # type: ignore[no-redef]
        DEFAULT_SIDECAR_OUTBOUND_URL,
        LCTAgentServer,
        LCTRequestContext,
        LCTSidecarClient,
        PermissionSpec,
        load_loopback_secret,
    )


def build_agent_handler(
    client: LCTSidecarClient,
) -> Callable[[LCTRequestContext, Dict[str, Any]], Tuple[int, Dict[str, Any]]]:
    def _handle(ctx: LCTRequestContext, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        op = str(body.get("op", "echo"))
        if op == "call_tool":
            st, res = client.call_mcp_tool(
                request_id=ctx.request_id,
                target_url=str(body["target_url"]),
                tool_name=str(body["tool_name"]),
                arguments=dict(body.get("arguments") or {}),
            )
            return st, {
                "lang": "python",
                "lct_context": ctx.to_dict(),
                "sidecar_result": res,
            }
        if op == "delegate_agent":
            raw_perms = body.get("permissions") or {}
            perms = PermissionSpec(
                tools=list(raw_perms.get("tools") or ["search_flight"]),
                max_amount=raw_perms.get("max_amount"),
                allowed_targets=raw_perms.get("allowed_targets"),
                param_whitelist=raw_perms.get("param_whitelist"),
                max_calls=int(raw_perms.get("max_calls", 2)),
            )
            st, res = client.delegate_agent(
                request_id=ctx.request_id,
                payload=dict(body.get("payload") or {}),
                permissions=perms,
                required_skill=body.get("required_skill"),
                delegate_spiffe_id=body.get("delegate_spiffe_id"),
                delegate_jkt=body.get("delegate_jkt"),
                target_url=body.get("target_url"),
                hop_segment=body.get("hop_segment", "PythonSubHop"),
            )
            return st, {
                "lang": "python",
                "lct_context": ctx.to_dict(),
                "sidecar_result": res,
            }
        return 200, {
            "lang": "python",
            "echo": body,
            "lct_context": ctx.to_dict(),
        }

    return _handle


def main() -> None:
    parser = argparse.ArgumentParser(description="LCT Python SDK Example Agent")
    parser.add_argument("--port", type=int, default=9001)
    parser.add_argument("--sidecar-url", default=DEFAULT_SIDECAR_OUTBOUND_URL)
    parser.add_argument("--secret-file", default=None)
    args = parser.parse_args()

    secret = load_loopback_secret(args.secret_file)
    client = LCTSidecarClient(secret, sidecar_outbound_url=args.sidecar_url)
    srv = LCTAgentServer(secret, build_agent_handler(client), port=args.port)
    url = srv.start()
    print(f"[python-lct-agent] Listening on {url}", flush=True)

    stop_ev = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop_ev.set())
    signal.signal(signal.SIGINT, lambda *_: stop_ev.set())
    try:
        stop_ev.wait()
    finally:
        srv.stop()


if __name__ == "__main__":
    main()
