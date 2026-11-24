"""Real Ollama `qwen2.5:3b` Multi-Agent Business Containers (`app` side of 2/2 Pods).

Supports 100% Official A2A (Agent2Agent) v1.0 JSON-RPC 2.0 + Real-Time SSE Streaming
(`POST /` and `POST /a2a` with `A2A-Version: 1.0`: `SendMessage`, `SendStreamingMessage`,
`GetTask`, `CancelTask` with cascading lineage revocation) as well as backwards-compatible
`POST /a2a/task`.

Every business agent binds strictly to `127.0.0.1:<app_port>` (Pod loopback only),
holds ZERO cryptographic private keys and ZERO Kubernetes ServiceAccount tokens,
verifies `X-LCT-Loopback-Auth` in constant time, and delegates all outbound LCT
attenuations, `MultiParentToken` assemblies, DPoP signing, X.509 mTLS transport,
`Atomic Prune-and-Graft`, `Authenticated Skip-Level Return`, and `CancelTask`
cascading subtree revocations to its co-located `lct-sidecar` container.
"""

from __future__ import annotations

import concurrent.futures
import hmac
import ipaddress
import json
import math
import os
import threading
import time
import uuid
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

import httpx

from lineage.a2a.models import (
    A2AAccessDeniedError,
    A2AInvalidParamsError,
    Artifact,
    Message,
    Task,
)
from lineage.a2a.rpc import (
    A2AInvocationContext,
    A2ARPCExecutionError,
    A2AServerEngine,
)
from lineage.agents.mcp_servers import canonicalize_city
from lineage.agents.ollama_client import OllamaClient, OllamaError
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.protocol.lattice import PermissionLattice

ArtifactCallback = Optional[Callable[[Artifact], None]]


def _is_fault_injection_enabled() -> bool:
    return os.environ.get("LCT_ENABLE_FAULT_INJECTION", "false").lower() == "true"


def _require_bounded_float(
    raw_val: Any,
    field_name: str,
    lo: float,
    hi: float,
    default_val: Optional[float] = None,
) -> float:
    if raw_val is None:
        if default_val is not None:
            return default_val
        raise ValueError(f"missing_{field_name}")
    if isinstance(raw_val, bool) or not isinstance(raw_val, (int, float)):
        raise ValueError(
            f"invalid_{field_name}: expected finite number in [{lo}, {hi}], got {raw_val!r}"
        )
    val = float(raw_val)
    if not math.isfinite(val) or val < lo or val > hi:
        raise ValueError(
            f"invalid_{field_name}: {val!r} outside allowed range [{lo}, {hi}]"
        )
    return val


def _validate_sync_hook_url(raw_url: Any) -> str:
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("invalid_sync_hook_url: must be a non-empty string")
    candidate = raw_url.strip()
    sp = urlsplit(candidate)
    if (
        sp.scheme != "http"
        or not sp.netloc
        or not sp.hostname
        or "@" in sp.netloc
        or sp.username is not None
        or sp.password is not None
        or sp.port != 19090
        or sp.path != "/sync"
        or sp.query != ""
        or sp.fragment != ""
    ):
        raise ValueError(
            "invalid_sync_hook_url: must match http://<gateway-host>:19090/sync"
        )
    host_l = sp.hostname.lower()
    allowed_host = (
        host_l == "e2e-user-gateway.lineage-alpha.svc.cluster.local" and sp.port == 19090
    )
    if not allowed_host and sp.port == 19090:
        try:
            ip_obj = ipaddress.ip_address(host_l)
            if any(
                ip_obj in ipaddress.ip_network(cidr)
                for cidr in (
                    "10.241.0.0/16",
                    "10.242.0.0/16",
                    "10.243.0.0/16",
                    "10.244.0.0/16",
                )
            ):
                allowed_host = True
            elif (
                host_l == "127.0.0.1"
                and os.environ.get("LCT_ALLOW_LOOPBACK_SYNC_HOOK_FOR_UNIT_TEST") == "true"
            ):
                allowed_host = True
        except ValueError:
            allowed_host = False
    if not allowed_host:
        raise ValueError(
            f"invalid_sync_hook_url: host {host_l!r}:{sp.port} is not an authorized E2E sync gateway"
        )
    return candidate


def _verify_loopback(req: HTTPRequestContext, expected_secret: str) -> bool:
    provided = req.header("X-LCT-Loopback-Auth")
    if not isinstance(provided, str) or not expected_secret:
        return False
    return hmac.compare_digest(
        provided.encode("utf-8"), expected_secret.encode("utf-8")
    )


def _raise_for_a2a_status(status: int, res_body: Dict[str, Any]) -> None:
    if status == 400:
        raise A2AInvalidParamsError(
            str(res_body.get("detail") or res_body.get("error") or res_body)
        )
    if status == 403 and res_body.get("error") in (
        "fault_injection_disabled",
        "cross_tenant_telemetry_forbidden",
    ):
        raise A2AAccessDeniedError(
            str(res_body.get("detail") or res_body.get("error"))
        )
    raise A2ARPCExecutionError(
        str(res_body.get("error") or res_body),
        http_status=status,
        data=res_body,
    )


class SidecarLoopbackClient:
    """Loopback HTTP client from co-located `app` container (`127.0.0.1`) to `lct-sidecar`."""

    def __init__(
        self,
        outbound_proxy_url: str,
        loopback_secret: str,
        default_timeout: float = 75.0,
    ) -> None:
        self.proxy_call_url = f"{outbound_proxy_url.rstrip('/')}/v1/proxy/call"
        self.loopback_secret = loopback_secret
        self.default_timeout = float(default_timeout)

    def _post(
        self, payload: Dict[str, Any], http_timeout: Optional[float] = None
    ) -> Tuple[int, Dict[str, Any]]:
        resp = httpx.post(
            self.proxy_call_url,
            json=payload,
            headers={"X-LCT-Loopback-Auth": self.loopback_secret},
            timeout=http_timeout or self.default_timeout,
            trust_env=False,
        )
        return resp.status_code, resp.json()

    def resolve_card(
        self,
        spiffe_id: Optional[str] = None,
        required_skill: Optional[str] = None,
        trust_domain: Optional[str] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        body: Dict[str, Any] = {"action": "resolve_card"}
        if spiffe_id:
            body["spiffe_id"] = spiffe_id
        if required_skill:
            body["required_skill"] = required_skill
        if trust_domain:
            body["trust_domain"] = trust_domain
        return self._post(body, http_timeout=10.0)

    def call_mcp_tool(
        self,
        request_id: str,
        mcp_url: Optional[str],
        tool_name: str,
        arguments: Mapping[str, Any],
        timeout: float = 15.0,
        required_skill: Optional[str] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        req_body: Dict[str, Any] = {
            "action": "call_tool",
            "request_id": request_id,
            "timeout": timeout,
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": dict(arguments)},
            },
        }
        clean_url = (mcp_url or "").strip()
        if clean_url.startswith("skill://"):
            req_body["required_skill"] = clean_url[len("skill://") :]
        elif clean_url:
            req_body["target_url"] = clean_url
        elif required_skill:
            req_body["required_skill"] = required_skill
        return self._post(req_body, http_timeout=timeout + 5.0)

    def call_mcp_tool_converged(
        self,
        task_id: str,
        sub: str,
        mcp_url: Optional[str],
        tool_name: str,
        arguments: Mapping[str, Any],
        timeout: float = 15.0,
        required_skill: Optional[str] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        req_body: Dict[str, Any] = {
            "action": "call_tool",
            "use_converged_multiparent": True,
            "task_id": task_id,
            "sub": sub,
            "timeout": timeout,
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": dict(arguments)},
            },
        }
        clean_url = (mcp_url or "").strip()
        if clean_url.startswith("skill://"):
            req_body["required_skill"] = clean_url[len("skill://") :]
        elif clean_url:
            req_body["target_url"] = clean_url
        elif required_skill:
            req_body["required_skill"] = required_skill
        return self._post(req_body, http_timeout=timeout + 5.0)

    def delegate_agent(
        self,
        request_id: str,
        permissions: Optional[PermissionLattice],
        payload: Mapping[str, Any],
        required_skill: str,
        task_path: str = "/a2a/task",
        hop_segment: Optional[str] = None,
        use_prune_and_graft: bool = False,
        timeout: float = 45.0,
    ) -> Tuple[int, Dict[str, Any]]:
        body: Dict[str, Any] = {
            "action": "delegate_agent",
            "request_id": request_id,
            "required_skill": required_skill,
            "payload": dict(payload),
            "task_path": task_path,
            "use_prune_and_graft": use_prune_and_graft,
            "timeout": timeout,
        }
        if permissions is not None:
            body["permissions"] = permissions.to_dict()
        if hop_segment:
            body["hop_segment"] = hop_segment
        return self._post(body, http_timeout=max(timeout * 3.0 + 10.0, 60.0))

    def delegate_a2a_send_message(
        self,
        request_id: str,
        permissions: Optional[PermissionLattice],
        text: str,
        data: Mapping[str, Any],
        required_skill: str,
        hop_segment: Optional[str] = None,
        use_prune_and_graft: bool = False,
        timeout: float = 45.0,
    ) -> Tuple[int, Dict[str, Any]]:
        """Delegate sub-task using Official A2A v1.0 JSON-RPC 2.0 `SendMessage` (`POST /a2a`)."""
        msg = Message.create_user(text=text, data=data)
        rpc_req = {
            "jsonrpc": "2.0",
            "id": f"a2a-{uuid.uuid4().hex[:10]}",
            "method": "SendMessage",
            "params": {"message": msg.to_dict()},
        }
        st, out = self.delegate_agent(
            request_id=request_id,
            permissions=permissions,
            payload=rpc_req,
            required_skill=required_skill,
            task_path="/a2a",
            hop_segment=hop_segment,
            use_prune_and_graft=use_prune_and_graft,
            timeout=timeout,
        )
        up = out.get("upstream_body")
        if isinstance(up, Mapping) and "result" in up and isinstance(up["result"], Mapping):
            raw_task = up["result"].get("task")
            if isinstance(raw_task, Mapping):
                parsed_task = Task.from_dict(raw_task)
                extracted: Dict[str, Any] = {}
                if parsed_task.status.message is not None:
                    extracted = parsed_task.status.message.extract_data()
                elif parsed_task.history:
                    extracted = parsed_task.history[-1].extract_data()
                out = dict(out)
                out["a2a_task"] = dict(raw_task)
                out["upstream_body"] = extracted
        elif isinstance(up, Mapping) and "error" in up and isinstance(up["error"], Mapping):
            err_data = up["error"].get("data")
            if isinstance(err_data, Mapping):
                out = dict(out)
                out["a2a_rpc_error"] = dict(up["error"])
                out["upstream_body"] = dict(err_data)
        return st, out

    def return_result(
        self,
        request_id: str,
        result_payload: Mapping[str, Any],
        simulate_direct_parent_unreachable: bool = False,
        timeout: float = 2.0,
    ) -> Tuple[int, Dict[str, Any]]:
        body: Dict[str, Any] = {
            "action": "return_result",
            "request_id": request_id,
            "result_payload": dict(result_payload),
            "simulate_direct_parent_unreachable": bool(
                simulate_direct_parent_unreachable
            ),
            "timeout": timeout,
        }
        return self._post(body, http_timeout=max(timeout * 4.0 + 5.0, 20.0))

    def revoke_subtree(
        self,
        request_id: str,
        prefix: Optional[str] = None,
        reason: str = "a2a_cancel_task",
    ) -> Tuple[int, Dict[str, Any]]:
        body: Dict[str, Any] = {
            "action": "revoke_subtree",
            "request_id": request_id,
            "reason": reason,
        }
        if prefix:
            body["prefix"] = prefix
        return self._post(body, http_timeout=10.0)

    def inspect_inbox(
        self, task_id: str, sub: str, caller_task_id: Optional[str] = None
    ) -> Tuple[int, Dict[str, Any]]:
        return self._post(
            {
                "action": "inspect_inbox",
                "task_id": task_id,
                "sub": sub,
                "caller_task_id": caller_task_id or task_id,
            },
            http_timeout=5.0,
        )


def _make_cascade_revoke_hook(sidecar: SidecarLoopbackClient):
    def _hook(req_id: str, prefix: str, task_id: str) -> Dict[str, Any]:
        st, out = sidecar.revoke_subtree(
            request_id=req_id,
            prefix=prefix,
            reason=f"a2a_cancel_task:{task_id}",
        )
        if st != 200:
            raise RuntimeError(f"Sidecar revoke_subtree failed ({st}): {out}")
        return dict(out.get("event") or out)

    return _hook


# =============================================================================
# 1. Flight Specialist Agent (`flight-specialist` in `lineage-beta` / `org-beta.io`)
# =============================================================================

_SEARCH_FLIGHT_TOOL_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "search_flight",
            "description": "Query available business flights and USD fares for a destination city.",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {"type": "string", "description": "Destination city name in English"}
                },
                "required": ["city"],
            },
        },
    }
]

_BOOK_FLIGHT_TOOL_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "book_flight",
            "description": "Confirm flight booking using exact flight_no and price_usd returned by search_flight.",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {"type": "string"},
                    "flight_no": {"type": "string"},
                    "amount": {"type": "number"},
                },
                "required": ["city", "flight_no", "amount"],
            },
        },
    }
]


class FlightSpecialistApp:
    """Specialist Agent B1 (`org-beta.io`): A2A v1.0 + `qwen2.5:3b` tool-calling + convergence."""

    def __init__(
        self,
        loopback_secret: str,
        sidecar_outbound_url: str,
        travel_mcp_url: Optional[str] = None,
        ollama: Optional[OllamaClient] = None,
        port: int = 9001,
    ) -> None:
        self.loopback_secret = loopback_secret
        self.sidecar = SidecarLoopbackClient(sidecar_outbound_url, loopback_secret)
        self.travel_mcp_url = (travel_mcp_url or "").strip() or "skill://mcp.travel-ops"
        self.ollama = ollama or OllamaClient()
        self.a2a_engine = A2AServerEngine(
            agent_name="flight-specialist",
            work_handler=self._a2a_work,
            cascade_revoke_hook=_make_cascade_revoke_hook(self.sidecar),
        )
        self.http = ManagedHTTPService(
            service_name="flight-specialist-app",
            dispatcher=self._dispatch,
            host="127.0.0.1",
            port=port,
        )

    def start(self) -> str:
        return self.http.start()

    def stop(self) -> None:
        self.http.stop()

    def _execute_core(
        self,
        req_id: str,
        lineage_path: str,
        body: Mapping[str, Any],
        emit_artifact: ArtifactCallback = None,
    ) -> Tuple[int, Dict[str, Any]]:
        city = canonicalize_city(body.get("city", "Tokyo"))
        raw_ovr_amt = body.get("override_book_amount")
        raw_ovr_city = body.get("override_book_city")
        if raw_ovr_amt is not None or raw_ovr_city is not None:
            if not _is_fault_injection_enabled():
                return (
                    403,
                    {
                        "error": "fault_injection_disabled",
                        "detail": "Flight booking parameter overrides require LCT_ENABLE_FAULT_INJECTION=true",
                    },
                )
        ovr_amt = (
            _require_bounded_float(raw_ovr_amt, "override_book_amount", 0.01, 1_000_000.0)
            if raw_ovr_amt is not None
            else None
        )
        ovr_city = (
            canonicalize_city(raw_ovr_city) if raw_ovr_city is not None else None
        )
        try:
            _, args1, meta1 = self.ollama.chat_tool_call(
                system_prompt="You are FlightSpecialist B1. Always invoke search_flight for the requested city.",
                user_prompt=f"Search available flights for destination city: {city}.",
                tools_schema=_SEARCH_FLIGHT_TOOL_SCHEMA,
            )
            search_city = canonicalize_city(args1.get("city", city))
            st_s, res_s = self.sidecar.call_mcp_tool(
                req_id, self.travel_mcp_url, "search_flight", {"city": search_city}
            )
            if st_s != 200:
                return st_s, {"error": "flight_search_denied", "mcp_response": res_s}
            flight_info = res_s["upstream_body"]["result"]["data"]

            _, args2, meta2 = self.ollama.chat_tool_call(
                system_prompt="You are FlightSpecialist B1. Invoke book_flight using the exact flight_no and price_usd provided.",
                user_prompt=(
                    f"search_flight returned city={flight_info['city']}, "
                    f"flight_no={flight_info['flight_no']}, price_usd={flight_info['price_usd']}. "
                    f"Book this flight now."
                ),
                tools_schema=_BOOK_FLIGHT_TOOL_SCHEMA,
            )
            eff_book_city = ovr_city if ovr_city is not None else flight_info["city"]
            eff_book_amt = ovr_amt if ovr_amt is not None else float(flight_info["price_usd"])
            st_b, res_b = self.sidecar.call_mcp_tool(
                req_id,
                self.travel_mcp_url,
                "book_flight",
                {
                    "city": eff_book_city,
                    "flight_no": str(args2.get("flight_no") or flight_info["flight_no"]),
                    "amount": eff_book_amt,
                },
            )
            if st_b != 200:
                return st_b, {"error": "flight_booking_denied", "mcp_response": res_b}
            booked = res_b["upstream_body"]["result"]["data"]

            if emit_artifact is not None:
                emit_artifact(
                    Artifact.create(
                        name="flight-booking-receipt",
                        description=f"Confirmed {booked['flight_no']} to {city}",
                        data=booked,
                    )
                )

            if body.get("skip_convergence"):
                out_single: Dict[str, Any] = {
                    "agent": "flight-specialist",
                    "lineage_path": lineage_path,
                    "flight_search": flight_info,
                    "flight_booking": booked,
                    "llm_traces": [meta1, meta2],
                }
                hop_tel_s = [
                    r["oauth_telemetry"]
                    for r in (res_s, res_b)
                    if isinstance(r, Mapping) and "oauth_telemetry" in r
                ]
                if hop_tel_s:
                    out_single["oauth_hop_telemetry"] = hop_tel_s
                return 200, out_single

            converge_perms = PermissionLattice.create(
                tools=["execute_settlement", "record_itinerary_audit"],
                max_amount=float(booked["charged_usd"]),
                allowed_targets=["airline-escrow", "audit-ledger"],
                param_whitelist={"city": [eff_book_city]},
                max_calls=2,
            )
            st_c, res_c = self.sidecar.delegate_agent(
                request_id=req_id,
                permissions=converge_perms,
                payload={"branch_data": {"branch_kind": "flight", "booking": booked}},
                required_skill="settlement.converge",
                task_path="/a2a/converge",
                hop_segment="SettlementC",
            )
            if st_c != 200:
                return st_c, {"error": "flight_convergence_failed", "detail": res_c}

            out_flight: Dict[str, Any] = {
                "agent": "flight-specialist",
                "lineage_path": lineage_path,
                "flight_search": flight_info,
                "flight_booking": booked,
                "convergence": res_c["upstream_body"],
                "llm_traces": [meta1, meta2],
            }
            hop_tel_f = [
                r["oauth_telemetry"]
                for r in (res_s, res_b, res_c)
                if isinstance(r, Mapping) and "oauth_telemetry" in r
            ]
            if hop_tel_f:
                out_flight["oauth_hop_telemetry"] = hop_tel_f
            return 200, out_flight
        except OllamaError as exc:
            return 502, {"error": "ollama_inference_error", "detail": str(exc)}

    def _a2a_work(
        self,
        inv_ctx: A2AInvocationContext,
        user_msg: Message,
        emit_artifact: Callable[[Artifact], None],
    ) -> Tuple[Message, Dict[str, Any]]:
        params = {**inv_ctx.configuration, **user_msg.extract_data()}
        if "city" not in params and user_msg.extract_text():
            params["city"] = user_msg.extract_text()
        st, out = self._execute_core(
            req_id=inv_ctx.request_id,
            lineage_path=inv_ctx.lineage_path,
            body=params,
            emit_artifact=emit_artifact,
        )
        if st != 200:
            _raise_for_a2a_status(st, out)
        bk = out["flight_booking"]
        msg = Message.create_agent(
            text=f"Booked flight {bk['flight_no']} ({bk['booking_ref']}) for ${bk['charged_usd']}.",
            data=out,
        )
        return msg, {"lineagePath": inv_ctx.lineage_path}

    def _dispatch(self, req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return 200, {"status": "ok", "agent": "flight-specialist"}, {}

        if not _verify_loopback(req, self.loopback_secret):
            return 403, {"error": "direct_loopback_bypass_blocked"}, {}

        if req.method == "POST" and req.path in ("/", "/a2a"):
            return self.a2a_engine.dispatch(req)

        if req.method != "POST" or req.path != "/a2a/task":
            return 404, {"error": "route_not_found"}, {}

        st, out = self._execute_core(
            req_id=str(req.header("X-LCT-Request-Id", "")),
            lineage_path=str(req.header("X-LCT-Lineage-Path", "")),
            body=req.json(),
        )
        return st, out, {}


# =============================================================================
# 2. Hotel Specialist Agent (`hotel-specialist-primary` & `hotel-specialist-backup`)
# =============================================================================

_SEARCH_HOTEL_TOOL_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "search_hotel",
            "description": "Query available partner hotels and total_usd rates for a destination city.",
            "parameters": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"],
            },
        },
    }
]

_RESERVE_HOTEL_TOOL_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "reserve_hotel",
            "description": "Reserve hotel room using exact hotel_id and total_usd returned by search_hotel.",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {"type": "string"},
                    "hotel_id": {"type": "string"},
                    "amount": {"type": "number"},
                },
                "required": ["city", "hotel_id", "amount"],
            },
        },
    }
]


class HotelSpecialistApp:
    """Specialist Agent B2 / B'2 (`org-beta.io`): A2A v1.0 Hotel booking, zombie proof & relay."""

    def __init__(
        self,
        loopback_secret: str,
        sidecar_outbound_url: str,
        travel_mcp_url: Optional[str] = None,
        instance_label: Optional[str] = None,
        ollama: Optional[OllamaClient] = None,
        port: int = 9001,
    ) -> None:
        self.loopback_secret = loopback_secret
        self.sidecar = SidecarLoopbackClient(sidecar_outbound_url, loopback_secret)
        self.travel_mcp_url = (travel_mcp_url or "").strip() or "skill://mcp.travel-ops"
        self.instance_label = instance_label or os.environ.get("SPECIALIST_INSTANCE", "primary")
        self.ollama = ollama or OllamaClient()
        self._lock = threading.Lock()
        self._zombie_telemetry: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self.a2a_engine = A2AServerEngine(
            agent_name=f"hotel-specialist-{self.instance_label}",
            work_handler=self._a2a_work,
            cascade_revoke_hook=_make_cascade_revoke_hook(self.sidecar),
        )
        self.http = ManagedHTTPService(
            service_name=f"hotel-specialist-{self.instance_label}-app",
            dispatcher=self._dispatch,
            host="127.0.0.1",
            port=port,
        )

    def start(self) -> str:
        return self.http.start()

    def stop(self) -> None:
        self.http.stop()

    def _execute_core(
        self,
        req_id: str,
        task_id: str,
        sub: str,
        lineage_path: str,
        body: Mapping[str, Any],
        use_a2a_v1: bool = False,
        emit_artifact: ArtifactCallback = None,
    ) -> Tuple[int, Dict[str, Any]]:
        op = str(body.get("op", "hotel_book_and_converge"))

        if op == "inspect_zombie_telemetry":
            if not _is_fault_injection_enabled():
                return (
                    403,
                    {
                        "error": "fault_injection_disabled",
                        "detail": "inspect_zombie_telemetry is disabled unless LCT_ENABLE_FAULT_INJECTION=true",
                    },
                )
            tid = str(body.get("inspect_task_id", task_id)).strip()
            with self._lock:
                rec = self._zombie_telemetry.get(tid)
                rec_copy = dict(rec) if rec is not None else None
            if rec_copy is not None and rec_copy.get("sub") != sub:
                return (
                    403,
                    {
                        "error": "cross_tenant_telemetry_forbidden",
                        "detail": "Caller subject does not match recorded task subject",
                    },
                )
            return 200, {"instance": self.instance_label, "zombie_telemetry": rec_copy}

        if op == "relay_for_upward_return":
            relay_timeout = _require_bounded_float(
                body.get("timeout"), "timeout", 0.5, 90.0, default_val=45.0
            )
            child_perms = PermissionLattice.from_dict(body["child_permissions"])
            child_payload = dict(body["child_payload"])
            if use_a2a_v1:
                st_r, out_r = self.sidecar.delegate_a2a_send_message(
                    request_id=req_id,
                    permissions=child_perms,
                    text=f"Execute leaf audit and upward return for {child_payload.get('city', 'Tokyo')}",
                    data=child_payload,
                    required_skill="settlement.converge",
                    hop_segment="LeafSettlementC",
                    timeout=relay_timeout,
                )
            else:
                st_r, out_r = self.sidecar.delegate_agent(
                    request_id=req_id,
                    permissions=child_perms,
                    payload=child_payload,
                    required_skill="settlement.converge",
                    task_path="/a2a/task",
                    hop_segment="LeafSettlementC",
                    timeout=relay_timeout,
                )
            return (
                200 if st_r == 200 else st_r,
                {
                    "relay_agent": f"hotel-specialist-{self.instance_label}",
                    "downstream_status": st_r,
                    "downstream": out_r,
                },
            )

        city = canonicalize_city(body.get("city", "Tokyo"))

        raw_zombie_delay = body.get("simulate_primary_zombie_delay_sec")
        zombie_delay = _require_bounded_float(
            raw_zombie_delay,
            "simulate_primary_zombie_delay_sec",
            0.0,
            20.0,
            default_val=0.0,
        )
        if zombie_delay > 0.0:
            if not _is_fault_injection_enabled():
                return (
                    403,
                    {
                        "error": "fault_injection_disabled",
                        "detail": "simulate_primary_zombie_delay_sec requires LCT_ENABLE_FAULT_INJECTION=true",
                    },
                )
            if self.instance_label == "primary":
                time.sleep(zombie_delay)
                st_z, res_z = self.sidecar.call_mcp_tool(
                    req_id,
                    self.travel_mcp_url,
                    "reserve_hotel",
                    {"city": city, "hotel_id": "HTL-ZOMBIE", "amount": 300.0},
                    timeout=5.0,
                )
                z_record = {
                    "task_id": task_id,
                    "sub": sub,
                    "pruned_lineage_path": lineage_path,
                    "zombie_mcp_http_status": st_z,
                    "zombie_mcp_body": res_z.get("upstream_body", res_z),
                    "recorded_at": time.time(),
                }
                with self._lock:
                    if len(self._zombie_telemetry) >= 1000:
                        self._zombie_telemetry.popitem(last=False)
                    self._zombie_telemetry[task_id] = z_record
                return (
                    503,
                    {
                        "error": "primary_stalled_and_woke_as_revoked_zombie",
                        "zombie": z_record,
                    },
                )

        try:
            _, args1, meta1 = self.ollama.chat_tool_call(
                system_prompt="You are HotelSpecialist B2. Always invoke search_hotel for the requested city.",
                user_prompt=f"Search partner hotels for destination city: {city}.",
                tools_schema=_SEARCH_HOTEL_TOOL_SCHEMA,
            )
            search_city = canonicalize_city(args1.get("city", city))
            st_s, res_s = self.sidecar.call_mcp_tool(
                req_id, self.travel_mcp_url, "search_hotel", {"city": search_city}
            )
            if st_s != 200:
                return st_s, {"error": "hotel_search_denied", "mcp_response": res_s}
            hotel_info = res_s["upstream_body"]["result"]["data"]

            _, args2, meta2 = self.ollama.chat_tool_call(
                system_prompt="You are HotelSpecialist B2. Invoke reserve_hotel using the exact hotel_id and total_usd provided.",
                user_prompt=(
                    f"search_hotel returned city={hotel_info['city']}, "
                    f"hotel_id={hotel_info['hotel_id']}, total_usd={hotel_info['total_usd']}. "
                    f"Reserve this hotel now."
                ),
                tools_schema=_RESERVE_HOTEL_TOOL_SCHEMA,
            )
            st_r, res_r = self.sidecar.call_mcp_tool(
                req_id,
                self.travel_mcp_url,
                "reserve_hotel",
                {
                    "city": hotel_info["city"],
                    "hotel_id": str(args2.get("hotel_id") or hotel_info["hotel_id"]),
                    "amount": float(hotel_info["total_usd"]),
                },
            )
            if st_r != 200:
                return st_r, {"error": "hotel_reserve_denied", "mcp_response": res_r}
            reserved = res_r["upstream_body"]["result"]["data"]

            if emit_artifact is not None:
                emit_artifact(
                    Artifact.create(
                        name="hotel-reservation-receipt",
                        description=f"Reserved {reserved['hotel_name']} ({reserved['hotel_id']})",
                        data=reserved,
                    )
                )

            converge_perms = PermissionLattice.create(
                tools=["execute_settlement", "record_itinerary_audit"],
                max_amount=float(reserved["charged_usd"]),
                allowed_targets=["hotel-escrow", "audit-ledger"],
                param_whitelist={"city": [hotel_info["city"]]},
                max_calls=2,
            )
            st_c, res_c = self.sidecar.delegate_agent(
                request_id=req_id,
                permissions=converge_perms,
                payload={"branch_data": {"branch_kind": "hotel", "reservation": reserved}},
                required_skill="settlement.converge",
                task_path="/a2a/converge",
                hop_segment="SettlementC",
            )
            if st_c != 200:
                return st_c, {"error": "hotel_convergence_failed", "detail": res_c}

            out_hotel: Dict[str, Any] = {
                "agent": f"hotel-specialist-{self.instance_label}",
                "instance_label": self.instance_label,
                "lineage_path": lineage_path,
                "hotel_search": hotel_info,
                "hotel_reservation": reserved,
                "convergence": res_c["upstream_body"],
                "llm_traces": [meta1, meta2],
            }
            hop_tel_h = [
                r["oauth_telemetry"]
                for r in (res_s, res_r, res_c)
                if isinstance(r, Mapping) and "oauth_telemetry" in r
            ]
            if hop_tel_h:
                out_hotel["oauth_hop_telemetry"] = hop_tel_h
            return 200, out_hotel
        except OllamaError as exc:
            return 502, {"error": "ollama_inference_error", "detail": str(exc)}

    def _a2a_work(
        self,
        inv_ctx: A2AInvocationContext,
        user_msg: Message,
        emit_artifact: Callable[[Artifact], None],
    ) -> Tuple[Message, Dict[str, Any]]:
        params = {**inv_ctx.configuration, **user_msg.extract_data()}
        if "city" not in params and user_msg.extract_text():
            params["city"] = user_msg.extract_text()
        st, out = self._execute_core(
            req_id=inv_ctx.request_id,
            task_id=inv_ctx.task_id,
            sub=inv_ctx.sub,
            lineage_path=inv_ctx.lineage_path,
            body=params,
            use_a2a_v1=True,
            emit_artifact=emit_artifact,
        )
        if st != 200:
            _raise_for_a2a_status(st, out)
        txt = f"Completed hotel specialist operation ({self.instance_label})."
        if "hotel_reservation" in out:
            rv = out["hotel_reservation"]
            txt = f"Reserved {rv['hotel_name']} ({rv['reservation_ref']}) for ${rv['charged_usd']}."
        return Message.create_agent(text=txt, data=out), {"instance": self.instance_label}

    def _dispatch(self, req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return (
                200,
                {"status": "ok", "agent": f"hotel-specialist-{self.instance_label}"},
                {},
            )

        if not _verify_loopback(req, self.loopback_secret):
            return 403, {"error": "direct_loopback_bypass_blocked"}, {}

        if req.method == "POST" and req.path in ("/", "/a2a"):
            return self.a2a_engine.dispatch(req)

        if req.method != "POST" or req.path != "/a2a/task":
            return 404, {"error": "route_not_found"}, {}

        st, out = self._execute_core(
            req_id=str(req.header("X-LCT-Request-Id", "")),
            task_id=str(req.header("X-LCT-Task-Id", "")),
            sub=str(req.header("X-LCT-Sub", "")),
            lineage_path=str(req.header("X-LCT-Lineage-Path", "")),
            body=req.json(),
            use_a2a_v1=False,
        )
        return st, out, {}


# =============================================================================
# 3. Settlement Converger Agent (`settlement-converger` in `lineage-pay`)
# =============================================================================


class SettlementConvergerApp:
    """Convergence Agent C (`org-payment.io`): A2A v1.0 + MultiParentToken + `qwen2.5:3b`."""

    def __init__(
        self,
        loopback_secret: str,
        sidecar_outbound_url: str,
        payment_mcp_url: Optional[str] = None,
        ollama: Optional[OllamaClient] = None,
        port: int = 9001,
    ) -> None:
        self.loopback_secret = loopback_secret
        self.sidecar = SidecarLoopbackClient(sidecar_outbound_url, loopback_secret)
        self.payment_mcp_url = (payment_mcp_url or "").strip() or "skill://mcp.payment-vault"
        self.ollama = ollama or OllamaClient()
        self.a2a_engine = A2AServerEngine(
            agent_name="settlement-converger",
            work_handler=self._a2a_work,
            cascade_revoke_hook=_make_cascade_revoke_hook(self.sidecar),
        )
        self.http = ManagedHTTPService(
            service_name="settlement-converger-app",
            dispatcher=self._dispatch,
            host="127.0.0.1",
            port=port,
        )

    def start(self) -> str:
        return self.http.start()

    def stop(self) -> None:
        self.http.stop()

    def _execute_core(
        self,
        req_id: str,
        task_id: str,
        sub: str,
        body: Mapping[str, Any],
        emit_artifact: ArtifactCallback = None,
    ) -> Tuple[int, Dict[str, Any]]:
        op = str(body.get("op", "settle_converged_dag"))

        if body.get("override_direct_parent_url") is not None:
            if not _is_fault_injection_enabled():
                return (
                    403,
                    {
                        "error": "fault_injection_disabled",
                        "detail": "override_direct_parent_url is forbidden",
                    },
                )
            return (
                400,
                {
                    "error": "unsafe_override_direct_parent_url_removed",
                    "detail": "Arbitrary direct_parent URL override is permanently removed to prevent credential exfiltration; use simulate_direct_parent_unreachable=true",
                },
            )

        if op == "leaf_audit_and_upward_return":
            sim_unreach = bool(body.get("simulate_direct_parent_unreachable", False))
            raw_hook_url = body.get("sync_hook_url")
            raw_hook_spiffe = str(body.get("sync_hook_spiffe_id") or "").strip()
            if sim_unreach or raw_hook_url or raw_hook_spiffe:
                if not _is_fault_injection_enabled():
                    return (
                        403,
                        {
                            "error": "fault_injection_disabled",
                            "detail": "Upward fault simulation hooks require LCT_ENABLE_FAULT_INJECTION=true",
                        },
                    )
            if (
                raw_hook_spiffe
                and raw_hook_spiffe != "spiffe://org-alpha.io/ns/lineage-alpha/sa/e2e-user-gateway"
            ):
                raise ValueError(
                    f"invalid_sync_hook_spiffe_id: {raw_hook_spiffe!r} is not an authorized E2E sync gateway"
                )
            clean_hook_url = (
                _validate_sync_hook_url(raw_hook_url) if raw_hook_url else None
            )
            ret_timeout = _require_bounded_float(
                body.get("return_timeout_sec"),
                "return_timeout_sec",
                0.2,
                15.0,
                default_val=1.5,
            )

            city = canonicalize_city(body.get("city", "Tokyo"))
            try:
                note_json, llm_meta = self.ollama.chat_json(
                    system_prompt="Reply strictly in JSON with key audit_tag (short string summarizing itinerary audit).",
                    user_prompt=f"Generate short itinerary audit tag for {sub}'s trip to {city}.",
                )
            except OllamaError as exc:
                return 502, {"error": "ollama_inference_error", "detail": str(exc)}

            audit_tag = str(note_json.get("audit_tag") or f"AUDIT-{city.upper()}")
            st_m, res_m = self.sidecar.call_mcp_tool(
                req_id,
                self.payment_mcp_url,
                "record_itinerary_audit",
                {"city": city, "summary_ref": audit_tag},
            )
            if st_m != 200:
                return st_m, {"error": "audit_tool_denied", "detail": res_m}
            audit_data = res_m["upstream_body"]["result"]["data"]

            hook_targets: List[str] = []
            if raw_hook_spiffe:
                deadline_rc = time.time() + 6.0
                while time.time() < deadline_rc:
                    st_rc, rc_out = self.sidecar.resolve_card(spiffe_id=raw_hook_spiffe)
                    if st_rc == 200 and (rc_out.get("candidate_origins") or []):
                        for orig in rc_out.get("candidate_origins") or []:
                            hook_targets.append(f"{str(orig).rstrip('/')}/sync")
                        break
                    time.sleep(0.3)
            if clean_hook_url:
                hook_targets.append(clean_hook_url)

            if hook_targets:
                hook_tok = str(body.get("sync_hook_token") or "")
                hook_hdrs = {"X-LCT-Sync-Token": hook_tok} if hook_tok else {}
                for h_url in hook_targets:
                    try:
                        r_hk = httpx.post(
                            h_url,
                            json={"task_id": task_id, "ready": True},
                            headers=hook_hdrs,
                            timeout=20.0,
                            follow_redirects=False,
                            trust_env=False,
                        )
                        if r_hk.status_code == 200:
                            break
                    except Exception:
                        continue

            st_ret, out_ret = self.sidecar.return_result(
                request_id=req_id,
                result_payload={
                    "leaf_agent": "settlement-converger",
                    "city": city,
                    "audit_record": audit_data,
                    "llm_trace": llm_meta,
                },
                simulate_direct_parent_unreachable=sim_unreach,
                timeout=ret_timeout,
            )
            return st_ret, out_ret

        # Default Mode: N-to-1 Multi-Parent DAG Settlement + `qwen2.5:3b` Grounded Summary
        raw_ovr_air = body.get("override_airline_amount")
        raw_ovr_htl = body.get("override_hotel_amount")
        if raw_ovr_air is not None or raw_ovr_htl is not None:
            if not _is_fault_injection_enabled():
                return (
                    403,
                    {
                        "error": "fault_injection_disabled",
                        "detail": "Settlement amount overrides require LCT_ENABLE_FAULT_INJECTION=true",
                    },
                )
        ovr_air = (
            _require_bounded_float(
                raw_ovr_air, "override_airline_amount", 0.01, 1_000_000.0
            )
            if raw_ovr_air is not None
            else None
        )
        ovr_htl = (
            _require_bounded_float(
                raw_ovr_htl, "override_hotel_amount", 0.01, 1_000_000.0
            )
            if raw_ovr_htl is not None
            else None
        )

        st_in, inbox = self.sidecar.inspect_inbox(
            task_id=task_id, sub=sub, caller_task_id=task_id
        )
        if st_in != 200:
            return st_in, inbox
        branch_map: Dict[str, dict] = inbox.get("converged_branch_payloads") or {}
        flight_booking: Optional[Dict[str, Any]] = None
        hotel_reservation: Optional[Dict[str, Any]] = None
        for b_payload in branch_map.values():
            if b_payload.get("branch_kind") == "flight":
                flight_booking = b_payload.get("booking")
            elif b_payload.get("branch_kind") == "hotel":
                hotel_reservation = b_payload.get("reservation")

        requested_targets: List[str] = list(
            body.get("requested_targets") or ["airline-escrow", "hotel-escrow"]
        )
        city = canonicalize_city(
            body.get("city")
            or (flight_booking or {}).get("city")
            or (hotel_reservation or {}).get("city")
            or "Tokyo"
        )

        settlement_outcomes: Dict[str, Any] = {}
        for target in requested_targets:
            if target == "airline-escrow":
                amt = (
                    ovr_air
                    if ovr_air is not None
                    else _require_bounded_float(
                        (flight_booking or {}).get("charged_usd"),
                        "flight_charged_usd",
                        0.01,
                        1_000_000.0,
                        default_val=580.0,
                    )
                )
                ref_id = str((flight_booking or {}).get("booking_ref") or "FLT-PENDING")
            else:
                amt = (
                    ovr_htl
                    if ovr_htl is not None
                    else _require_bounded_float(
                        (hotel_reservation or {}).get("charged_usd"),
                        "hotel_charged_usd",
                        0.01,
                        1_000_000.0,
                        default_val=360.0,
                    )
                )
                ref_id = str((hotel_reservation or {}).get("reservation_ref") or "HTL-PENDING")

            st_pay, res_pay = self.sidecar.call_mcp_tool_converged(
                task_id=task_id,
                sub=sub,
                mcp_url=self.payment_mcp_url,
                tool_name="execute_settlement",
                arguments={
                    "target": target,
                    "amount": amt,
                    "reference_id": ref_id,
                    "city": city,
                },
            )
            outcome_entry: Dict[str, Any] = {
                "http_status": st_pay,
                "response": res_pay.get("upstream_body", res_pay),
            }
            if isinstance(res_pay, Mapping) and "oauth_telemetry" in res_pay:
                outcome_entry["oauth_telemetry"] = res_pay["oauth_telemetry"]
            settlement_outcomes[target] = outcome_entry

        succeeded_settlements = {
            k: v["response"]["result"]["data"]
            for k, v in settlement_outcomes.items()
            if v["http_status"] == 200 and "result" in v["response"]
        }
        denied_settlements = {
            k: v["response"]
            for k, v in settlement_outcomes.items()
            if v["http_status"] != 200
        }

        if not succeeded_settlements and denied_settlements:
            err_status = (
                503
                if any(v["http_status"] == 503 for v in settlement_outcomes.values())
                else 403
            )
            return (
                err_status,
                {
                    "agent": "settlement-converger",
                    "task_id": task_id,
                    "sub": sub,
                    "settlement_outcomes": settlement_outcomes,
                    "denied_settlements": denied_settlements,
                },
            )

        try:
            active_flight = (
                flight_booking if "airline-escrow" in succeeded_settlements else None
            )
            active_hotel = (
                hotel_reservation if "hotel-escrow" in succeeded_settlements else None
            )
            if active_flight is not None and active_hotel is not None:
                facts_summary: Dict[str, Any] = {
                    "traveler": sub,
                    "city": city,
                    "flight_booking": active_flight,
                    "hotel_reservation": active_hotel,
                    "completed_settlements": succeeded_settlements,
                }
                synth_sys_prompt = (
                    "You are SettlementConverger C. Write a concise 2-3 sentence confirmation for "
                    "the completed flight booking, hotel reservation, and both escrow settlements in "
                    "Verified MCP JSON. Include the exact flight_no, booking_ref, hotel_id, "
                    "hotel_name, reservation_ref, settlement_id values, and exact settled_usd amounts."
                )
            elif active_hotel is not None:
                facts_summary = {
                    "traveler": sub,
                    "city": city,
                    "hotel_reservation": active_hotel,
                    "hotel_settlement": succeeded_settlements["hotel-escrow"],
                }
                synth_sys_prompt = (
                    "You are SettlementConverger C. Write a concise 2-3 sentence confirmation stating "
                    "that ONLY the hotel reservation and hotel escrow settlement were executed under "
                    "degraded authorization. Include the exact hotel_id, hotel_name, reservation_ref, "
                    "settlement_id, and exact settled_usd from Verified MCP JSON."
                )
            else:
                facts_summary = {
                    "traveler": sub,
                    "city": city,
                    "completed_settlements": succeeded_settlements,
                }
                synth_sys_prompt = (
                    "You are SettlementConverger C. Write a concise 2-3 sentence confirmation strictly "
                    "summarizing completed_settlements in Verified MCP JSON with exact settlement_id "
                    "and settled_usd values."
                )
            nl_answer, synth_meta = self.ollama.chat_text(
                system_prompt=synth_sys_prompt,
                user_prompt=f"Verified MCP JSON:\n{json.dumps(facts_summary, ensure_ascii=False)}",
            )
        except OllamaError as exc:
            return 502, {"error": "ollama_synthesis_error", "detail": str(exc)}

        out_payload = {
            "agent": "settlement-converger",
            "task_id": task_id,
            "sub": sub,
            "city": city,
            "flight_booking": flight_booking,
            "hotel_reservation": hotel_reservation,
            "settlement_outcomes": settlement_outcomes,
            "completed_settlements": succeeded_settlements,
            "final_answer": nl_answer,
            "llm_trace": synth_meta,
        }
        if emit_artifact is not None:
            emit_artifact(
                Artifact.create(
                    name="split-escrow-settlement",
                    description="Converged MultiParentToken escrow settlement receipts",
                    text=nl_answer,
                    data=succeeded_settlements,
                )
            )
        return 200, out_payload

    def _a2a_work(
        self,
        inv_ctx: A2AInvocationContext,
        user_msg: Message,
        emit_artifact: Callable[[Artifact], None],
    ) -> Tuple[Message, Dict[str, Any]]:
        params = {**inv_ctx.configuration, **user_msg.extract_data()}
        st, out = self._execute_core(
            req_id=inv_ctx.request_id,
            task_id=inv_ctx.task_id,
            sub=inv_ctx.sub,
            body=params,
            emit_artifact=emit_artifact,
        )
        if st != 200:
            _raise_for_a2a_status(st, out)
        txt = str(out.get("final_answer") or "Completed settlement convergence.")
        return Message.create_agent(text=txt, data=out), {"lineagePath": inv_ctx.lineage_path}

    def _dispatch(self, req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return 200, {"status": "ok", "agent": "settlement-converger"}, {}

        if not _verify_loopback(req, self.loopback_secret):
            return 403, {"error": "direct_loopback_bypass_blocked"}, {}

        if req.method == "POST" and req.path in ("/", "/a2a"):
            return self.a2a_engine.dispatch(req)

        if req.method != "POST" or req.path != "/a2a/task":
            return 404, {"error": "route_not_found"}, {}

        st, out = self._execute_core(
            req_id=str(req.header("X-LCT-Request-Id", "")),
            task_id=str(req.header("X-LCT-Task-Id", "")),
            sub=str(req.header("X-LCT-Sub", "")),
            body=req.json(),
        )
        return st, out, {}


# =============================================================================
# 4. Root Orchestrator Agent (`orchestrator-alpha` in `lineage-alpha`)
# =============================================================================


class OrchestratorAlphaApp:
    """Root Orchestrator A (`org-alpha.io`): A2A v1.0 + `qwen2.5:3b` planner + 1-to-N + DAG."""

    def __init__(
        self,
        loopback_secret: str,
        sidecar_outbound_url: str,
        ollama: Optional[OllamaClient] = None,
        port: int = 9001,
    ) -> None:
        self.loopback_secret = loopback_secret
        self.sidecar = SidecarLoopbackClient(sidecar_outbound_url, loopback_secret)
        self.ollama = ollama or OllamaClient()
        self.a2a_engine = A2AServerEngine(
            agent_name="orchestrator-alpha",
            work_handler=self._a2a_work,
            cascade_revoke_hook=_make_cascade_revoke_hook(self.sidecar),
        )
        self.http = ManagedHTTPService(
            service_name="orchestrator-alpha-app",
            dispatcher=self._dispatch,
            host="127.0.0.1",
            port=port,
        )

    def start(self) -> str:
        return self.http.start()

    def stop(self) -> None:
        self.http.stop()

    def _execute_core(
        self,
        req_id: str,
        task_id: str,
        sub: str,
        body: Mapping[str, Any],
        use_a2a_v1: bool = False,
        emit_artifact: ArtifactCallback = None,
    ) -> Tuple[int, Dict[str, Any]]:
        op = str(body.get("op", "plan_and_execute_trip"))

        if body.get("override_direct_parent_url") is not None:
            if not _is_fault_injection_enabled():
                return (
                    403,
                    {
                        "error": "fault_injection_disabled",
                        "detail": "override_direct_parent_url is forbidden",
                    },
                )
            return (
                400,
                {
                    "error": "unsafe_override_direct_parent_url_removed",
                    "detail": "Arbitrary direct_parent URL override is permanently removed; use simulate_direct_parent_unreachable=true",
                },
            )

        if op == "inspect_inbox":
            tid = str(body.get("inspect_task_id", task_id)).strip()
            if tid != task_id and not _is_fault_injection_enabled():
                return (
                    403,
                    {
                        "error": "fault_injection_disabled",
                        "detail": "Cross-task inspect_task_id requires LCT_ENABLE_FAULT_INJECTION=true",
                    },
                )
            return self.sidecar.inspect_inbox(tid, sub=sub, caller_task_id=task_id)

        if op == "delegate_upward_return_chain":
            sim_unreach = bool(body.get("simulate_direct_parent_unreachable", False))
            raw_hook_url = body.get("sync_hook_url")
            raw_hook_spiffe = str(body.get("sync_hook_spiffe_id") or "").strip()
            if sim_unreach or raw_hook_url or raw_hook_spiffe:
                if not _is_fault_injection_enabled():
                    return (
                        403,
                        {
                            "error": "fault_injection_disabled",
                            "detail": "Upward fault simulation hooks require LCT_ENABLE_FAULT_INJECTION=true",
                        },
                    )
            if (
                raw_hook_spiffe
                and raw_hook_spiffe != "spiffe://org-alpha.io/ns/lineage-alpha/sa/e2e-user-gateway"
            ):
                raise ValueError(
                    f"invalid_sync_hook_spiffe_id: {raw_hook_spiffe!r} is not an authorized E2E sync gateway"
                )
            clean_hook_url = (
                _validate_sync_hook_url(raw_hook_url) if raw_hook_url else None
            )
            ret_timeout = _require_bounded_float(
                body.get("return_timeout_sec"),
                "return_timeout_sec",
                0.2,
                15.0,
                default_val=1.2,
            )
            chain_timeout = _require_bounded_float(
                body.get("timeout"), "timeout", 0.5, 90.0, default_val=45.0
            )
            city = canonicalize_city(body.get("city", "Tokyo"))
            chain_perms = PermissionLattice.create(
                tools=["record_itinerary_audit"],
                max_amount=100.0,
                allowed_targets=["audit-ledger"],
                param_whitelist={"city": [city]},
                max_calls=4,
            )
            relay_payload = {
                "op": "relay_for_upward_return",
                "timeout": chain_timeout,
                "child_permissions": chain_perms.to_dict(),
                "child_payload": {
                    "op": "leaf_audit_and_upward_return",
                    "city": city,
                    "sync_hook_url": clean_hook_url,
                    "sync_hook_spiffe_id": raw_hook_spiffe,
                    "sync_hook_token": str(body.get("sync_hook_token") or ""),
                    "simulate_direct_parent_unreachable": sim_unreach,
                    "return_timeout_sec": ret_timeout,
                },
            }
            if use_a2a_v1:
                st_d, out_d = self.sidecar.delegate_a2a_send_message(
                    request_id=req_id,
                    permissions=chain_perms,
                    text=f"Relay audit chain for {city}",
                    data=relay_payload,
                    required_skill="travel.hotel",
                    hop_segment="HotelPrimaryRelay",
                    use_prune_and_graft=False,
                    timeout=chain_timeout,
                )
            else:
                st_d, out_d = self.sidecar.delegate_agent(
                    request_id=req_id,
                    permissions=chain_perms,
                    payload=relay_payload,
                    required_skill="travel.hotel",
                    hop_segment="HotelPrimaryRelay",
                    use_prune_and_graft=False,
                    timeout=chain_timeout,
                )
            return 200, {"downstream_http": st_d, "downstream": out_d}

        if op == "probe_flight_overprivilege":
            if not _is_fault_injection_enabled():
                return (
                    403,
                    {
                        "error": "fault_injection_disabled",
                        "detail": "probe_flight_overprivilege requires LCT_ENABLE_FAULT_INJECTION=true",
                    },
                )
            allowed_city = canonicalize_city(body.get("allowed_city", "Tokyo"))
            budget_cap = _require_bounded_float(
                body.get("budget_cap_usd"), "budget_cap_usd", 1.0, 1_000_000.0, default_val=650.0
            )
            attempt_amt = _require_bounded_float(
                body.get("attempt_amount_usd"), "attempt_amount_usd", 1.0, 1_000_000.0, default_val=950.0
            )
            attempt_city = canonicalize_city(body.get("attempt_city", "Paris"))
            probe_perms = PermissionLattice.create(
                tools=["search_flight", "book_flight"],
                max_amount=budget_cap,
                allowed_targets=["airline-escrow"],
                param_whitelist={"city": [allowed_city]},
                max_calls=4,
            )
            probe_payload = {
                "city": allowed_city,
                "override_book_amount": attempt_amt,
                "override_book_city": attempt_city,
                "skip_convergence": True,
            }
            st_p, out_p = self.sidecar.delegate_agent(
                request_id=req_id,
                permissions=probe_perms,
                payload=probe_payload,
                required_skill="travel.flight",
                hop_segment="FlightOverprivProbe",
                use_prune_and_graft=False,
                timeout=35.0,
            )
            return st_p, out_p

        if op == "trigger_converged_settlement":
            city = canonicalize_city(body.get("city", "Tokyo"))
            trig_perms = PermissionLattice.create(
                tools=["record_itinerary_audit"],
                max_amount=10.0,
                allowed_targets=["audit-ledger"],
                param_whitelist={"city": [city]},
                max_calls=2,
            )
            trig_data = {
                "op": "settle_converged_dag",
                "city": city,
                "requested_targets": body.get("requested_targets"),
            }
            if use_a2a_v1:
                return self.sidecar.delegate_a2a_send_message(
                    request_id=req_id,
                    permissions=trig_perms,
                    text=f"Execute converged escrow settlement for {city}",
                    data=trig_data,
                    required_skill="settlement.converge",
                    hop_segment=str(body.get("trigger_hop_segment", "SettleTrigger")),
                    timeout=45.0,
                )
            return self.sidecar.delegate_agent(
                request_id=req_id,
                permissions=trig_perms,
                payload=trig_data,
                required_skill="settlement.converge",
                hop_segment=str(body.get("trigger_hop_segment", "SettleTrigger")),
                timeout=45.0,
            )

        # Validate timeout & fault-injection parameters BEFORE invoking Ollama (`[CRITICAL-M2-01]`)
        hotel_timeout = _require_bounded_float(
            body.get("hotel_timeout_sec"),
            "hotel_timeout_sec",
            0.2,
            60.0,
            default_val=40.0,
        )
        zombie_delay = _require_bounded_float(
            body.get("simulate_primary_zombie_delay_sec"),
            "simulate_primary_zombie_delay_sec",
            0.0,
            20.0,
            default_val=0.0,
        )
        if zombie_delay > 0.0:
            if not _is_fault_injection_enabled():
                return (
                    403,
                    {
                        "error": "fault_injection_disabled",
                        "detail": "simulate_primary_zombie_delay_sec requires LCT_ENABLE_FAULT_INJECTION=true",
                    },
                )
            if zombie_delay < hotel_timeout + 0.5:
                return (
                    400,
                    {
                        "error": "invalid_zombie_delay_vs_timeout",
                        "detail": (
                            f"simulate_primary_zombie_delay_sec ({zombie_delay}) must be >= "
                            f"hotel_timeout_sec + 0.5 ({hotel_timeout + 0.5}) to prevent pre-timeout double booking"
                        ),
                    },
                )

        user_prompt = str(
            body.get("prompt")
            or "Book business travel to Tokyo with flight budget up to 650 USD and hotel budget up to 420 USD."
        )
        try:
            plan_json, plan_llm_meta = self.ollama.chat_json(
                system_prompt=(
                    "You are OrchestratorAlpha in trust domain org-alpha.io. "
                    "Parse the user's travel request and reply strictly in JSON with keys: "
                    "city (string), flight_budget_usd (number), hotel_budget_usd (number)."
                ),
                user_prompt=user_prompt,
            )
        except OllamaError as exc:
            return 502, {"error": "ollama_planning_failed", "detail": str(exc)}

        city = canonicalize_city(plan_json.get("city") or body.get("default_city", "Tokyo"))
        flight_budget = _require_bounded_float(
            plan_json.get("flight_budget_usd")
            if plan_json.get("flight_budget_usd") is not None
            else body.get("flight_budget_usd"),
            "flight_budget_usd",
            1.0,
            1_000_000.0,
            default_val=650.0,
        )
        hotel_budget = _require_bounded_float(
            plan_json.get("hotel_budget_usd")
            if plan_json.get("hotel_budget_usd") is not None
            else body.get("hotel_budget_usd"),
            "hotel_budget_usd",
            1.0,
            1_000_000.0,
            default_val=420.0,
        )

        if emit_artifact is not None:
            emit_artifact(
                Artifact.create(
                    name="orchestrator-intent-plan",
                    description="Parsed travel itinerary & differentiated budget lattice caps",
                    data={
                        "city": city,
                        "flight_budget_usd": flight_budget,
                        "hotel_budget_usd": hotel_budget,
                    },
                )
            )

        flight_perms = PermissionLattice.create(
            tools=["search_flight", "book_flight", "execute_settlement", "record_itinerary_audit"],
            max_amount=flight_budget,
            allowed_targets=["airline-escrow", "audit-ledger"],
            param_whitelist={"city": [city]},
            max_calls=4,
        )
        hotel_perms = PermissionLattice.create(
            tools=["search_hotel", "reserve_hotel", "execute_settlement", "record_itinerary_audit"],
            max_amount=hotel_budget,
            allowed_targets=["hotel-escrow", "audit-ledger"],
            param_whitelist={"city": [city]},
            max_calls=4,
        )

        def _call_flight_branch() -> Tuple[int, Dict[str, Any]]:
            if use_a2a_v1:
                return self.sidecar.delegate_a2a_send_message(
                    request_id=req_id,
                    permissions=flight_perms,
                    text=f"Search and book business flight to {city}.",
                    data={"city": city},
                    required_skill="travel.flight",
                    hop_segment="FlightB1",
                    use_prune_and_graft=False,
                    timeout=40.0,
                )
            return self.sidecar.delegate_agent(
                request_id=req_id,
                permissions=flight_perms,
                payload={"city": city},
                required_skill="travel.flight",
                hop_segment="FlightB1",
                use_prune_and_graft=False,
                timeout=40.0,
            )

        def _call_hotel_branch() -> Tuple[int, Dict[str, Any]]:
            h_data = {
                "city": city,
                "simulate_primary_zombie_delay_sec": zombie_delay,
            }
            if use_a2a_v1:
                return self.sidecar.delegate_a2a_send_message(
                    request_id=req_id,
                    permissions=hotel_perms,
                    text=f"Search and reserve partner hotel in {city}.",
                    data=h_data,
                    required_skill="travel.hotel",
                    hop_segment="HotelB2",
                    use_prune_and_graft=True,
                    timeout=hotel_timeout,
                )
            return self.sidecar.delegate_agent(
                request_id=req_id,
                permissions=hotel_perms,
                payload=h_data,
                required_skill="travel.hotel",
                hop_segment="HotelB2",
                use_prune_and_graft=True,
                timeout=hotel_timeout,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            fut_f = pool.submit(_call_flight_branch)
            fut_h = pool.submit(_call_hotel_branch)
            st_f, out_f = fut_f.result()
            st_h, out_h = fut_h.result()

        if st_f != 200 or st_h != 200:
            return (
                502,
                {
                    "error": "specialist_fanout_failed",
                    "flight_branch": {"status": st_f, "body": out_f},
                    "hotel_branch": {"status": st_h, "body": out_h},
                },
            )

        if emit_artifact is not None:
            fb = (out_f.get("upstream_body") or {}).get("flight_booking")
            hr = (out_h.get("upstream_body") or {}).get("hotel_reservation")
            if isinstance(fb, Mapping):
                emit_artifact(
                    Artifact.create(
                        name="flight-specialist-booking",
                        description="Flight booking confirmed by FlightSpecialist B1",
                        data=fb,
                    )
                )
            if isinstance(hr, Mapping):
                emit_artifact(
                    Artifact.create(
                        name="hotel-specialist-reservation",
                        description="Hotel reservation confirmed by HotelSpecialist B2",
                        data=hr,
                    )
                )

        if body.get("pause_before_settlement"):
            return (
                200,
                {
                    "stage": "CONVERGED_READY_FOR_SETTLEMENT",
                    "task_id": task_id,
                    "sub": sub,
                    "city": city,
                    "orchestrator_plan": plan_json,
                    "orchestrator_llm_trace": plan_llm_meta,
                    "flight_branch": out_f,
                    "hotel_branch": out_h,
                },
            )

        trig_perms = PermissionLattice.create(
            tools=["record_itinerary_audit"],
            max_amount=10.0,
            allowed_targets=["audit-ledger"],
            param_whitelist={"city": [city]},
            max_calls=2,
        )
        trig_payload = {
            "op": "settle_converged_dag",
            "city": city,
            "requested_targets": body.get("requested_targets"),
        }
        if use_a2a_v1:
            st_s, out_s = self.sidecar.delegate_a2a_send_message(
                request_id=req_id,
                permissions=trig_perms,
                text=f"Settle converged airline and hotel escrows for {city}",
                data=trig_payload,
                required_skill="settlement.converge",
                hop_segment="SettleTrigger",
                timeout=45.0,
            )
        else:
            st_s, out_s = self.sidecar.delegate_agent(
                request_id=req_id,
                permissions=trig_perms,
                payload=trig_payload,
                required_skill="settlement.converge",
                hop_segment="SettleTrigger",
                timeout=45.0,
            )

        if st_s == 200 and emit_artifact is not None:
            conv_up = out_s.get("upstream_body") or {}
            emit_artifact(
                Artifact.create(
                    name="settlement-convergence-summary",
                    description="Final split escrow settlement & grounded itinerary summary",
                    text=str(conv_up.get("final_answer") or ""),
                    data=conv_up.get("completed_settlements") or {},
                )
            )

        return (
            st_s,
            {
                "task_id": task_id,
                "sub": sub,
                "city": city,
                "orchestrator_plan": plan_json,
                "orchestrator_llm_trace": plan_llm_meta,
                "flight_branch": out_f,
                "hotel_branch": out_h,
                "settlement_convergence": out_s,
            },
        )

    def _a2a_work(
        self,
        inv_ctx: A2AInvocationContext,
        user_msg: Message,
        emit_artifact: Callable[[Artifact], None],
    ) -> Tuple[Message, Dict[str, Any]]:
        params = {**inv_ctx.configuration, **user_msg.extract_data()}
        if "prompt" not in params and user_msg.extract_text():
            params["prompt"] = user_msg.extract_text()
        st, out = self._execute_core(
            req_id=inv_ctx.request_id,
            task_id=inv_ctx.task_id,
            sub=inv_ctx.sub,
            body=params,
            use_a2a_v1=True,
            emit_artifact=emit_artifact,
        )
        if st != 200:
            _raise_for_a2a_status(st, out)

        extra_meta: Dict[str, Any] = {"lineagePath": inv_ctx.lineage_path}
        if out.get("stage") == "CONVERGED_READY_FOR_SETTLEMENT":
            extra_meta["stagedForSettlement"] = True
            summary_txt = f"Staged travel bookings for {out.get('city')} ready for settlement."
        elif "settlement_convergence" in out:
            conv_up = out["settlement_convergence"].get("upstream_body") or {}
            summary_txt = str(conv_up.get("final_answer") or "Completed travel workflow.")
        elif "completed_settlements" in out:
            summary_txt = str(out.get("final_answer") or "Completed settlement trigger.")
        else:
            summary_txt = "Completed orchestrator operation."
        return Message.create_agent(text=summary_txt, data=out), extra_meta

    def _dispatch(self, req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return 200, {"status": "ok", "agent": "orchestrator-alpha"}, {}

        if not _verify_loopback(req, self.loopback_secret):
            return 403, {"error": "direct_loopback_bypass_blocked"}, {}

        if req.method == "POST" and req.path in ("/", "/a2a"):
            return self.a2a_engine.dispatch(req)

        if req.method != "POST" or req.path != "/a2a/task":
            return 404, {"error": "route_not_found"}, {}

        st, out = self._execute_core(
            req_id=str(req.header("X-LCT-Request-Id", "")),
            task_id=str(req.header("X-LCT-Task-Id", "")),
            sub=str(req.header("X-LCT-Sub", "")),
            body=req.json(),
            use_a2a_v1=False,
        )
        return st, out, {}
