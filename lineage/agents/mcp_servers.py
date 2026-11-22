"""Loopback-Isolated MCP Business Servers for Travel Operations & Split Settlement.

Both MCP servers bind strictly to `127.0.0.1:<app_port>` inside their Kubernetes Pods
and enforce constant-time `X-LCT-Loopback-Auth` verification so only the co-located
`lct-sidecar` container (after full LCT + DPoP + Risk-Anchored Revocation checks) can
reach business tool handlers.
"""

from __future__ import annotations

from collections import deque
import hashlib
import hmac
import math
import threading
from typing import Any, Deque, Dict, Mapping, Optional, Tuple

from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService

FLIGHT_CATALOG: Dict[str, Dict[str, Any]] = {
    "Tokyo": {
        "flight_no": "NH-108",
        "carrier": "ANA All Nippon",
        "origin": "SFO",
        "destination": "NRT",
        "cabin": "Business",
        "price_usd": 580.0,
    },
    "London": {
        "flight_no": "BA-284",
        "carrier": "British Airways",
        "origin": "SFO",
        "destination": "LHR",
        "cabin": "Club World",
        "price_usd": 510.0,
    },
    "Paris": {
        "flight_no": "AF-065",
        "carrier": "Air France",
        "origin": "LAX",
        "destination": "CDG",
        "cabin": "Business",
        "price_usd": 490.0,
    },
    "Singapore": {
        "flight_no": "SQ-031",
        "carrier": "Singapore Airlines",
        "origin": "SFO",
        "destination": "SIN",
        "cabin": "Business",
        "price_usd": 620.0,
    },
}

HOTEL_CATALOG: Dict[str, Dict[str, Any]] = {
    "Tokyo": {
        "hotel_id": "HTL-TYO-09",
        "hotel_name": "Shinjuku Grand Palace",
        "nights": 3,
        "total_usd": 360.0,
    },
    "London": {
        "hotel_id": "HTL-LON-04",
        "hotel_name": "Westminster Savoy Suites",
        "nights": 3,
        "total_usd": 340.0,
    },
    "Paris": {
        "hotel_id": "HTL-PAR-07",
        "hotel_name": "Vendome Boutique Hotel",
        "nights": 3,
        "total_usd": 320.0,
    },
    "Singapore": {
        "hotel_id": "HTL-SIN-02",
        "hotel_name": "Marina Bay Crest",
        "nights": 3,
        "total_usd": 380.0,
    },
}


def canonicalize_city(raw_city: Any) -> str:
    s = str(raw_city or "").strip().lower()
    for city_key in FLIGHT_CATALOG:
        if city_key.lower() == s or city_key.lower() in s:
            return city_key
    return str(raw_city or "Tokyo").strip().title()


def _det_ref(prefix: str, task_id: str, sub: str, key: str) -> str:
    digest = hashlib.sha256(f"{task_id}:{sub}:{key}".encode("utf-8")).hexdigest()[:8].upper()
    return f"{prefix}-{digest}"


def _parse_positive_finite_amount(
    raw_val: Any, default_val: Optional[float] = None
) -> Optional[float]:
    val_in = default_val if raw_val is None else raw_val
    if val_in is None or isinstance(val_in, bool) or not isinstance(val_in, (int, float)):
        return None
    val = float(val_in)
    if not math.isfinite(val) or val <= 0.0 or val > 10_000_000.0:
        return None
    return val


def _verify_loopback(req: HTTPRequestContext, expected_secret: str) -> bool:
    provided = req.header("X-LCT-Loopback-Auth")
    if not isinstance(provided, str) or not expected_secret:
        return False
    return hmac.compare_digest(
        provided.encode("utf-8"), expected_secret.encode("utf-8")
    )


class TravelOpsMCPApp:
    """Protected MCP server (`travel-ops-mcp`) exposing low-risk search & high-risk booking tools."""

    def __init__(self, loopback_secret: str, port: int = 9001) -> None:
        self.loopback_secret = loopback_secret
        self._lock = threading.Lock()
        self._bookings: Deque[Dict[str, Any]] = deque(maxlen=10_000)
        self.http = ManagedHTTPService(
            service_name="travel-ops-mcp-app",
            dispatcher=self._dispatch,
            host="127.0.0.1",
            port=port,
        )

    def start(self) -> str:
        return self.http.start()

    def stop(self) -> None:
        self.http.stop()

    def _dispatch(self, req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return 200, {"status": "ok", "app": "travel-ops-mcp"}, {}

        if not _verify_loopback(req, self.loopback_secret):
            return 403, {"error": "direct_loopback_bypass_blocked"}, {}

        if req.method != "POST" or req.path != "/mcp":
            return 404, {"error": "mcp_route_not_found", "path": req.path}, {}

        body = req.json()
        rpc_id = body.get("id", 1)
        method = str(body.get("method", "tools/call"))
        if method == "tools/list":
            return (
                200,
                {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "tools": [
                            {"name": "search_flight", "risk": "LOW_RISK"},
                            {"name": "book_flight", "risk": "HIGH_RISK"},
                            {"name": "search_hotel", "risk": "LOW_RISK"},
                            {"name": "reserve_hotel", "risk": "HIGH_RISK"},
                        ]
                    },
                },
                {},
            )

        params = body.get("params") or {}
        tool_name = str(params.get("name", ""))
        args: Mapping[str, Any] = params.get("arguments") or {}
        task_id = str(req.header("X-LCT-Task-Id", "unknown"))
        sub = str(req.header("X-LCT-Sub", "unknown"))
        lineage_path = str(req.header("X-LCT-Lineage-Path", ""))
        decision = str(req.header("X-LCT-Decision", "ALLOW"))

        city = canonicalize_city(args.get("city", "Tokyo"))

        if tool_name == "search_flight":
            item = FLIGHT_CATALOG.get(city)
            if item is None:
                return 404, {"jsonrpc": "2.0", "id": rpc_id, "error": f"Unknown city {city!r}"}, {}
            out = {"city": city, **item, "lineage_decision": decision}
            return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"data": out}}, {}

        if tool_name == "book_flight":
            item = FLIGHT_CATALOG.get(city)
            if item is None:
                return 404, {"jsonrpc": "2.0", "id": rpc_id, "error": f"Unknown city {city!r}"}, {}
            amount = _parse_positive_finite_amount(
                args.get("amount"), default_val=float(item["price_usd"])
            )
            if amount is None:
                return (
                    400,
                    {"jsonrpc": "2.0", "id": rpc_id, "error": "invalid_flight_booking_amount"},
                    {},
                )
            flight_no = str(args.get("flight_no") or item["flight_no"])
            booking = {
                "booking_ref": _det_ref("FLT", task_id, sub, f"{city}:{flight_no}"),
                "city": city,
                "flight_no": item["flight_no"],
                "carrier": item["carrier"],
                "charged_usd": round(amount, 2),
                "escrow_target": "airline-escrow",
                "task_id": task_id,
                "sub": sub,
                "lineage_path": lineage_path,
                "lineage_decision": decision,
            }
            with self._lock:
                self._bookings.append(booking)
            return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"data": booking}}, {}

        if tool_name == "search_hotel":
            item = HOTEL_CATALOG.get(city)
            if item is None:
                return 404, {"jsonrpc": "2.0", "id": rpc_id, "error": f"Unknown city {city!r}"}, {}
            out = {"city": city, **item, "lineage_decision": decision}
            return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"data": out}}, {}

        if tool_name == "reserve_hotel":
            item = HOTEL_CATALOG.get(city)
            if item is None:
                return 404, {"jsonrpc": "2.0", "id": rpc_id, "error": f"Unknown city {city!r}"}, {}
            amount = _parse_positive_finite_amount(
                args.get("amount"), default_val=float(item["total_usd"])
            )
            if amount is None:
                return (
                    400,
                    {"jsonrpc": "2.0", "id": rpc_id, "error": "invalid_hotel_reservation_amount"},
                    {},
                )
            hotel_id = str(args.get("hotel_id") or item["hotel_id"])
            reservation = {
                "reservation_ref": _det_ref("HTL", task_id, sub, f"{city}:{hotel_id}"),
                "city": city,
                "hotel_id": item["hotel_id"],
                "hotel_name": item["hotel_name"],
                "nights": item["nights"],
                "charged_usd": round(amount, 2),
                "escrow_target": "hotel-escrow",
                "task_id": task_id,
                "sub": sub,
                "lineage_path": lineage_path,
                "lineage_decision": decision,
            }
            with self._lock:
                self._bookings.append(reservation)
            return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"data": reservation}}, {}

        return 404, {"jsonrpc": "2.0", "id": rpc_id, "error": f"Unknown tool {tool_name!r}"}, {}


class PaymentVaultMCPApp:
    """High-sensitivity settlement MCP server (`payment-vault-mcp`) for split escrow execution."""

    def __init__(self, loopback_secret: str, port: int = 9001) -> None:
        self.loopback_secret = loopback_secret
        self._lock = threading.Lock()
        self._settlements: Deque[Dict[str, Any]] = deque(maxlen=10_000)
        self.http = ManagedHTTPService(
            service_name="payment-vault-mcp-app",
            dispatcher=self._dispatch,
            host="127.0.0.1",
            port=port,
        )

    def start(self) -> str:
        return self.http.start()

    def stop(self) -> None:
        self.http.stop()

    def _dispatch(self, req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return 200, {"status": "ok", "app": "payment-vault-mcp"}, {}

        if not _verify_loopback(req, self.loopback_secret):
            return 403, {"error": "direct_loopback_bypass_blocked"}, {}

        if req.method != "POST" or req.path != "/mcp":
            return 404, {"error": "mcp_route_not_found", "path": req.path}, {}

        body = req.json()
        rpc_id = body.get("id", 1)
        params = body.get("params") or {}
        tool_name = str(params.get("name", ""))
        args: Mapping[str, Any] = params.get("arguments") or {}
        task_id = str(req.header("X-LCT-Task-Id", "unknown"))
        sub = str(req.header("X-LCT-Sub", "unknown"))
        lineage_path = str(req.header("X-LCT-Lineage-Path", ""))
        decision = str(req.header("X-LCT-Decision", "ALLOW"))

        if tool_name == "execute_settlement":
            target = str(args.get("target", ""))
            amount = _parse_positive_finite_amount(args.get("amount"))
            city = canonicalize_city(args.get("city", "Tokyo"))
            reference_id = str(args.get("reference_id", "REF-NONE"))
            if target not in ("airline-escrow", "hotel-escrow") or amount is None:
                return (
                    400,
                    {"jsonrpc": "2.0", "id": rpc_id, "error": "invalid_settlement_target_or_amount"},
                    {},
                )
            settlement = {
                "settlement_id": _det_ref("STL", task_id, sub, f"{target}:{reference_id}:{amount}"),
                "target": target,
                "settled_usd": round(amount, 2),
                "reference_id": reference_id,
                "city": city,
                "task_id": task_id,
                "sub": sub,
                "lineage_path": lineage_path,
                "lineage_decision": decision,
            }
            with self._lock:
                self._settlements.append(settlement)
            return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"data": settlement}}, {}

        if tool_name == "record_itinerary_audit":
            city = canonicalize_city(args.get("city", "Tokyo"))
            summary_ref = str(args.get("summary_ref", "AUDIT"))
            rec = {
                "audit_receipt_id": _det_ref("AUD", task_id, sub, f"{city}:{summary_ref}"),
                "city": city,
                "summary_ref": summary_ref,
                "task_id": task_id,
                "sub": sub,
                "lineage_decision": decision,
            }
            return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"data": rec}}, {}

        return 404, {"jsonrpc": "2.0", "id": rpc_id, "error": f"Unknown tool {tool_name!r}"}, {}
