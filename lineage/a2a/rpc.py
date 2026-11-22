"""Official A2A v1.0 JSON-RPC 2.0 + Server-Sent Events (SSE) Server Engine & Client.

Implements the 4 canonical A2A v1.0 methods over HTTP/HTTPS (`POST /` and `POST /a2a`
with mandatory `A2A-Version: 1.0` header validation):
1. `SendMessage` (`message/send`): Synchronous task execution returning `{"result": {"task": ...}}`
2. `SendStreamingMessage` (`message/stream`): Real-time `Content-Type: text/event-stream` SSE
   streaming `statusUpdate` (`SUBMITTED` -> `WORKING` -> `COMPLETED` final) & `artifactUpdate` frames
3. `GetTask` (`tasks/get`): Tenant-isolated `(task_id, sub)` task & artifact query
4. `CancelTask` (`tasks/cancel`): Atomic `TASK_STATE_CANCELED` transition + LCT cascading revocation
"""

from __future__ import annotations

import json
import queue
import ssl
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Tuple, Union

import httpx

from lineage.a2a.models import (
    A2A_PROTOCOL_VERSION,
    A2AAccessDeniedError,
    A2AInvalidParamsError,
    A2AStateTransitionError,
    A2ATaskNotFoundError,
    A2ATaskStore,
    Artifact,
    Message,
    Task,
    TaskState,
)
from lineage.common.crypto import CryptoError, strict_json_loads
from lineage.common.http_utils import HTTPRequestContext, SSEResponse
from lineage.common.mtls import WorkloadMTLSBundle
from lineage.identity.spiffe import WorkloadIdentity
from lineage.identity.trust_bundle import TrustBundleResolver
from lineage.protocol.dpop import create_dpop_proof
from lineage.registry.agent_card import AgentCard

# Standard JSON-RPC 2.0 + A2A v1.0 error codes
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
A2A_ERR_TASK_NOT_FOUND = -32001
A2A_ERR_TASK_NOT_CANCELABLE = -32002
A2A_ERR_ACCESS_DENIED = -32003
A2A_ERR_UPSTREAM_EXECUTION = -32005


class A2ARPCExecutionError(Exception):
    """Raised by an agent handler when downstream policy/LLM/revocation fails."""

    def __init__(
        self,
        message: str,
        http_status: int = 502,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.http_status = int(http_status)
        self.data = dict(data) if data is not None else {}


@dataclass(frozen=True)
class A2AInvocationContext:
    """Verified LCT + A2A per-request context passed to business agent handlers."""

    request_id: str
    task_id: str
    context_id: str
    sub: str
    lineage_path: str
    decision: str
    configuration: Dict[str, Any]
    cancel_event: threading.Event


ArtifactEmitter = Callable[[Artifact], None]
A2AWorkHandler = Callable[
    [A2AInvocationContext, Message, ArtifactEmitter],
    Tuple[Message, Dict[str, Any]],
]
CascadeRevokeHook = Callable[[str, str, str], Dict[str, Any]]


def _jsonrpc_ok(rpc_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _jsonrpc_err(
    rpc_id: Any, code: int, message: str, data: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    err_obj: Dict[str, Any] = {"code": int(code), "message": str(message)}
    if data:
        err_obj["data"] = dict(data)
    return {"jsonrpc": "2.0", "id": rpc_id, "error": err_obj}


class A2AServerEngine:
    """Official A2A v1.0 JSON-RPC 2.0 + SSE Server Dispatcher."""

    def __init__(
        self,
        agent_name: str,
        work_handler: A2AWorkHandler,
        cascade_revoke_hook: Optional[CascadeRevokeHook] = None,
        task_store: Optional[A2ATaskStore] = None,
    ) -> None:
        self.agent_name = agent_name
        self.work_handler = work_handler
        self.cascade_revoke_hook = cascade_revoke_hook
        self.task_store = task_store or A2ATaskStore()

    def dispatch(
        self, req: HTTPRequestContext
    ) -> Tuple[int, Union[Dict[str, Any], SSEResponse], Dict[str, str]]:
        resp_headers = {"A2A-Version": A2A_PROTOCOL_VERSION}

        # 1. Validate mandatory `A2A-Version: 1.0` header
        ver_hdr = (req.header("A2A-Version") or "").strip()
        if ver_hdr != A2A_PROTOCOL_VERSION:
            return (
                400,
                _jsonrpc_err(
                    None,
                    JSONRPC_INVALID_REQUEST,
                    f"Missing or unsupported A2A-Version header {ver_hdr!r}; expected '1.0'",
                ),
                resp_headers,
            )

        # 2. Strict JSON-RPC 2.0 parse (`-32700`) vs request envelope validation (`-32600`) (`[LOW-M3-02]`)
        if not req.body:
            return (
                400,
                _jsonrpc_err(None, JSONRPC_PARSE_ERROR, "Empty JSON-RPC 2.0 request body"),
                resp_headers,
            )
        try:
            body = strict_json_loads(req.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, CryptoError) as exc:
            return (
                400,
                _jsonrpc_err(None, JSONRPC_PARSE_ERROR, f"Parse error: {exc}"),
                resp_headers,
            )

        if not isinstance(body, dict):
            return (
                400,
                _jsonrpc_err(
                    None,
                    JSONRPC_INVALID_REQUEST,
                    "Invalid Request: JSON-RPC 2.0 payload must be a JSON object",
                ),
                resp_headers,
            )

        raw_id = body.get("id")
        if raw_id is not None and (
            isinstance(raw_id, bool) or not isinstance(raw_id, (str, int))
        ):
            return (
                400,
                _jsonrpc_err(
                    None,
                    JSONRPC_INVALID_REQUEST,
                    "Invalid Request: JSON-RPC 2.0 id must be string, integer, or null",
                ),
                resp_headers,
            )
        rpc_id = raw_id

        raw_method = body.get("method")
        if (
            body.get("jsonrpc") != "2.0"
            or not isinstance(raw_method, str)
            or not raw_method.strip()
            or "result" in body
            or "error" in body
        ):
            return (
                400,
                _jsonrpc_err(
                    rpc_id,
                    JSONRPC_INVALID_REQUEST,
                    "Invalid Request: requires jsonrpc='2.0', non-empty string method, and no result/error fields",
                ),
                resp_headers,
            )

        method = raw_method.strip()
        params = body.get("params")
        if params is None:
            params = {}
        if not isinstance(params, Mapping):
            return (
                400,
                _jsonrpc_err(rpc_id, JSONRPC_INVALID_PARAMS, "JSON-RPC params must be an object"),
                resp_headers,
            )

        req_id = str(req.header("X-LCT-Request-Id") or "")
        lct_task_id = str(req.header("X-LCT-Task-Id") or "").strip()
        lct_sub = str(req.header("X-LCT-Sub") or "").strip()
        lct_path = str(req.header("X-LCT-Lineage-Path") or "").strip()
        lct_decision = str(req.header("X-LCT-Decision") or "ALLOW").strip()

        if not lct_task_id or not lct_sub:
            return (
                401,
                _jsonrpc_err(rpc_id, A2A_ERR_ACCESS_DENIED, "Missing verified LCT task/subject context"),
                resp_headers,
            )

        # ---------------------------------------------------------------------
        # Method 1: `SendMessage` (`message/send`)
        # ---------------------------------------------------------------------
        if method in ("SendMessage", "message/send"):
            try:
                raw_msg = params.get("message")
                if not isinstance(raw_msg, Mapping):
                    raise A2AInvalidParamsError("SendMessage requires params.message object")
                user_msg = Message.from_dict(raw_msg)
                if user_msg.task_id and user_msg.task_id != lct_task_id:
                    return (
                        403,
                        _jsonrpc_err(
                            rpc_id,
                            A2A_ERR_ACCESS_DENIED,
                            f"Message taskId {user_msg.task_id!r} mismatches verified LCT task_id {lct_task_id!r}",
                        ),
                        resp_headers,
                    )
                config = (
                    dict(params["configuration"])
                    if isinstance(params.get("configuration"), Mapping)
                    else {}
                )
                submitted_snap, cancel_ev = self.task_store.create_or_submit(
                    task_id=lct_task_id,
                    owner_sub=lct_sub,
                    lineage_path=lct_path,
                    user_message=user_msg,
                )
                working_snap, ok_w = self.task_store.transition(
                    lct_task_id, TaskState.WORKING, allow_noop_if_canceled=True
                )
                if not ok_w:
                    return 200, _jsonrpc_ok(rpc_id, {"task": working_snap.to_dict()}), resp_headers

                inv_ctx = A2AInvocationContext(
                    request_id=req_id,
                    task_id=lct_task_id,
                    context_id=working_snap.context_id,
                    sub=lct_sub,
                    lineage_path=lct_path,
                    decision=lct_decision,
                    configuration=config,
                    cancel_event=cancel_ev,
                )

                def _emit_art(art: Artifact) -> None:
                    self.task_store.append_artifact(lct_task_id, art)

                agent_msg, extra_meta = self.work_handler(inv_ctx, user_msg, _emit_art)
                if extra_meta:
                    with self.task_store._lock:
                        rec_m = self.task_store._records.get(lct_task_id)
                        if rec_m is not None:
                            rec_m.task.metadata.update(extra_meta)

                final_snap, _ = self.task_store.transition(
                    lct_task_id,
                    TaskState.COMPLETED,
                    agent_message=agent_msg,
                    allow_noop_if_canceled=True,
                )
                return 200, _jsonrpc_ok(rpc_id, {"task": final_snap.to_dict()}), resp_headers

            except A2AInvalidParamsError as exc:
                return 400, _jsonrpc_err(rpc_id, JSONRPC_INVALID_PARAMS, str(exc)), resp_headers
            except A2AAccessDeniedError as exc:
                return 403, _jsonrpc_err(rpc_id, A2A_ERR_ACCESS_DENIED, str(exc)), resp_headers
            except A2AStateTransitionError as exc:
                return 409, _jsonrpc_err(rpc_id, A2A_ERR_TASK_NOT_CANCELABLE, str(exc)), resp_headers
            except A2ARPCExecutionError as exc:
                err_msg = Message.create_agent(text=str(exc), data=exc.data or None)
                try:
                    failed_snap, _ = self.task_store.transition(
                        lct_task_id,
                        TaskState.FAILED,
                        agent_message=err_msg,
                        allow_noop_if_canceled=True,
                    )
                    err_data = {"task": failed_snap.to_dict(), **exc.data}
                except Exception:
                    err_data = exc.data
                return (
                    exc.http_status,
                    _jsonrpc_err(rpc_id, A2A_ERR_UPSTREAM_EXECUTION, str(exc), err_data),
                    resp_headers,
                )

        # ---------------------------------------------------------------------
        # Method 2: `SendStreamingMessage` (`message/stream`) -> Live SSE!
        # ---------------------------------------------------------------------
        if method in ("SendStreamingMessage", "message/stream"):
            try:
                raw_msg = params.get("message")
                if not isinstance(raw_msg, Mapping):
                    raise A2AInvalidParamsError(
                        "SendStreamingMessage requires params.message object"
                    )
                user_msg = Message.from_dict(raw_msg)
                if user_msg.task_id and user_msg.task_id != lct_task_id:
                    return (
                        403,
                        _jsonrpc_err(
                            rpc_id,
                            A2A_ERR_ACCESS_DENIED,
                            f"Message taskId {user_msg.task_id!r} mismatches LCT task_id {lct_task_id!r}",
                        ),
                        resp_headers,
                    )
                config = (
                    dict(params["configuration"])
                    if isinstance(params.get("configuration"), Mapping)
                    else {}
                )
                submitted_snap, cancel_ev = self.task_store.create_or_submit(
                    task_id=lct_task_id,
                    owner_sub=lct_sub,
                    lineage_path=lct_path,
                    user_message=user_msg,
                )
            except A2AInvalidParamsError as exc:
                return 400, _jsonrpc_err(rpc_id, JSONRPC_INVALID_PARAMS, str(exc)), resp_headers
            except A2AAccessDeniedError as exc:
                return 403, _jsonrpc_err(rpc_id, A2A_ERR_ACCESS_DENIED, str(exc)), resp_headers
            except A2AStateTransitionError as exc:
                return 409, _jsonrpc_err(rpc_id, A2A_ERR_TASK_NOT_CANCELABLE, str(exc)), resp_headers

            event_q: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue()

            # Push initial SUBMITTED frame immediately
            event_q.put(
                _jsonrpc_ok(
                    rpc_id,
                    {
                        "statusUpdate": {
                            "taskId": submitted_snap.id,
                            "contextId": submitted_snap.context_id,
                            "status": submitted_snap.status.to_dict(),
                            "final": False,
                        }
                    },
                )
            )

            def _stream_worker() -> None:
                try:
                    working_snap, ok_w = self.task_store.transition(
                        lct_task_id, TaskState.WORKING, allow_noop_if_canceled=True
                    )
                    if not ok_w:
                        event_q.put(
                            _jsonrpc_ok(
                                rpc_id,
                                {
                                    "statusUpdate": {
                                        "taskId": working_snap.id,
                                        "contextId": working_snap.context_id,
                                        "status": working_snap.status.to_dict(),
                                        "final": True,
                                    }
                                },
                            )
                        )
                        return

                    event_q.put(
                        _jsonrpc_ok(
                            rpc_id,
                            {
                                "statusUpdate": {
                                    "taskId": working_snap.id,
                                    "contextId": working_snap.context_id,
                                    "status": working_snap.status.to_dict(),
                                    "final": False,
                                }
                            },
                        )
                    )

                    inv_ctx = A2AInvocationContext(
                        request_id=req_id,
                        task_id=lct_task_id,
                        context_id=working_snap.context_id,
                        sub=lct_sub,
                        lineage_path=lct_path,
                        decision=lct_decision,
                        configuration=config,
                        cancel_event=cancel_ev,
                    )

                    def _emit_art_stream(art: Artifact) -> None:
                        self.task_store.append_artifact(lct_task_id, art)
                        event_q.put(
                            _jsonrpc_ok(
                                rpc_id,
                                {
                                    "artifactUpdate": {
                                        "taskId": working_snap.id,
                                        "contextId": working_snap.context_id,
                                        "artifact": art.to_dict(),
                                        "append": False,
                                        "lastChunk": True,
                                    }
                                },
                            )
                        )

                    agent_msg, extra_meta = self.work_handler(
                        inv_ctx, user_msg, _emit_art_stream
                    )
                    if extra_meta:
                        with self.task_store._lock:
                            rec_m = self.task_store._records.get(lct_task_id)
                            if rec_m is not None:
                                rec_m.task.metadata.update(extra_meta)

                    final_snap, _ = self.task_store.transition(
                        lct_task_id,
                        TaskState.COMPLETED,
                        agent_message=agent_msg,
                        allow_noop_if_canceled=True,
                    )
                    event_q.put(
                        _jsonrpc_ok(
                            rpc_id,
                            {
                                "statusUpdate": {
                                    "taskId": final_snap.id,
                                    "contextId": final_snap.context_id,
                                    "status": final_snap.status.to_dict(),
                                    "final": True,
                                }
                            },
                        )
                    )
                except A2ARPCExecutionError as exc:
                    err_msg = Message.create_agent(text=str(exc), data=exc.data or None)
                    failed_snap, _ = self.task_store.transition(
                        lct_task_id,
                        TaskState.FAILED,
                        agent_message=err_msg,
                        allow_noop_if_canceled=True,
                    )
                    event_q.put(
                        _jsonrpc_ok(
                            rpc_id,
                            {
                                "statusUpdate": {
                                    "taskId": failed_snap.id,
                                    "contextId": failed_snap.context_id,
                                    "status": failed_snap.status.to_dict(),
                                    "final": True,
                                }
                            },
                        )
                    )
                except Exception as exc:
                    event_q.put(
                        _jsonrpc_err(rpc_id, A2A_ERR_UPSTREAM_EXECUTION, str(exc))
                    )
                finally:
                    event_q.put(None)

            worker_t = threading.Thread(
                target=_stream_worker, name=f"a2a-sse-{lct_task_id}", daemon=True
            )
            worker_t.start()

            def _iter_sse() -> Iterator[Dict[str, Any]]:
                while True:
                    item = event_q.get()
                    if item is None:
                        break
                    yield item

            return 200, SSEResponse(frames=_iter_sse()), resp_headers

        # ---------------------------------------------------------------------
        # Method 3: `GetTask` (`tasks/get`) — Strict `(task_id, sub)` Isolation
        # ---------------------------------------------------------------------
        if method in ("GetTask", "tasks/get"):
            target_id = str(params.get("id") or "").strip()
            if not target_id:
                return (
                    400,
                    _jsonrpc_err(rpc_id, JSONRPC_INVALID_PARAMS, "GetTask requires params.id"),
                    resp_headers,
                )
            if target_id != lct_task_id:
                return (
                    403,
                    _jsonrpc_err(
                        rpc_id,
                        A2A_ERR_ACCESS_DENIED,
                        f"Caller token scoped to task {lct_task_id!r} cannot query task {target_id!r}",
                    ),
                    resp_headers,
                )
            try:
                snap = self.task_store.get_authorized(target_id, caller_sub=lct_sub)
            except A2AAccessDeniedError as exc:
                return 403, _jsonrpc_err(rpc_id, A2A_ERR_ACCESS_DENIED, str(exc)), resp_headers
            except A2ATaskNotFoundError as exc:
                return 404, _jsonrpc_err(rpc_id, A2A_ERR_TASK_NOT_FOUND, str(exc)), resp_headers
            return 200, _jsonrpc_ok(rpc_id, {"task": snap.to_dict()}), resp_headers

        # ---------------------------------------------------------------------
        # Method 4: `CancelTask` (`tasks/cancel`) + Atomic Cascading Revocation (`[MEDIUM-M3-01]`)
        # ---------------------------------------------------------------------
        if method in ("CancelTask", "tasks/cancel"):
            target_id = str(params.get("id") or "").strip()
            if not target_id:
                return (
                    400,
                    _jsonrpc_err(rpc_id, JSONRPC_INVALID_PARAMS, "CancelTask requires params.id"),
                    resp_headers,
                )
            if target_id != lct_task_id:
                return (
                    403,
                    _jsonrpc_err(
                        rpc_id,
                        A2A_ERR_ACCESS_DENIED,
                        f"Caller token scoped to task {lct_task_id!r} cannot cancel task {target_id!r}",
                    ),
                    resp_headers,
                )
            explicit_prefix = str(params.get("revokePrefix") or "").strip()
            try:
                prefix_to_revoke = self.task_store.validate_cancel_request(
                    target_id,
                    caller_sub=lct_sub,
                    caller_lineage_path=lct_path,
                    explicit_prefix=explicit_prefix,
                )
            except A2AAccessDeniedError as exc:
                return 403, _jsonrpc_err(rpc_id, A2A_ERR_ACCESS_DENIED, str(exc)), resp_headers
            except A2ATaskNotFoundError as exc:
                return 404, _jsonrpc_err(rpc_id, A2A_ERR_TASK_NOT_FOUND, str(exc)), resp_headers
            except A2AStateTransitionError as exc:
                return 409, _jsonrpc_err(rpc_id, A2A_ERR_TASK_NOT_CANCELABLE, str(exc)), resp_headers

            # Execute cascading revocation BEFORE mutating in-memory task state (`[MEDIUM-M3-01]`)!
            rev_meta: Dict[str, Any] = {}
            if self.cascade_revoke_hook is not None and prefix_to_revoke:
                try:
                    rev_meta = self.cascade_revoke_hook(req_id, prefix_to_revoke, target_id)
                except Exception as exc:
                    return (
                        403,
                        _jsonrpc_err(
                            rpc_id,
                            A2A_ERR_ACCESS_DENIED,
                            f"Cascading lineage revocation failed during CancelTask: {exc}",
                        ),
                        resp_headers,
                    )

            try:
                canceled_snap, _ = self.task_store.cancel_authorized(
                    target_id,
                    caller_sub=lct_sub,
                    fallback_lineage_path=lct_path,
                    revocation_metadata=rev_meta,
                )
            except A2AAccessDeniedError as exc:
                return 403, _jsonrpc_err(rpc_id, A2A_ERR_ACCESS_DENIED, str(exc)), resp_headers
            except A2ATaskNotFoundError as exc:
                return 404, _jsonrpc_err(rpc_id, A2A_ERR_TASK_NOT_FOUND, str(exc)), resp_headers
            except A2AStateTransitionError as exc:
                return 409, _jsonrpc_err(rpc_id, A2A_ERR_TASK_NOT_CANCELABLE, str(exc)), resp_headers

            return (
                200,
                _jsonrpc_ok(
                    rpc_id,
                    {"task": canceled_snap.to_dict(), "revocation": rev_meta},
                ),
                resp_headers,
            )

        return (
            404,
            _jsonrpc_err(
                rpc_id,
                JSONRPC_METHOD_NOT_FOUND,
                f"Unknown A2A v1.0 JSON-RPC method: {method!r}",
            ),
            resp_headers,
        )


class A2AClient:
    """Official A2A v1.0 JSON-RPC 2.0 + SSE Client with LCT + DPoP + mTLS support."""

    def __init__(
        self,
        agent_base_url: str,
        signer: Optional[WorkloadIdentity] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        mtls_bundle: Optional[WorkloadMTLSBundle] = None,
        expected_trust_domain: Optional[str] = None,
        expected_spiffe_id: Optional[str] = None,
        rpc_path: str = "/a2a",
        timeout: float = 90.0,
    ) -> None:
        self.agent_base_url = agent_base_url.rstrip("/")
        self.signer = signer
        self.ssl_context = ssl_context
        self.mtls_bundle = mtls_bundle
        self.expected_trust_domain = expected_trust_domain
        self.expected_spiffe_id = expected_spiffe_id
        self.rpc_path = rpc_path if rpc_path.startswith("/") else f"/{rpc_path}"
        self.timeout = float(timeout)

    def _build_headers(
        self,
        url: str,
        compact_token: Optional[str],
        accept: str = "application/json",
    ) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": accept,
            "A2A-Version": A2A_PROTOCOL_VERSION,
        }
        if compact_token:
            if self.signer is None:
                raise ValueError("A2AClient requires signer WorkloadIdentity to mint DPoP proof")
            headers["Authorization"] = f"DPoP {compact_token}"
            headers["DPoP"] = create_dpop_proof(self.signer, "POST", url, compact_token)
        return headers

    def _verify_kwarg(self) -> Any:
        if self.mtls_bundle is not None:
            return self.mtls_bundle.verify_for_target(
                target_url=self.agent_base_url,
                expected_trust_domain=self.expected_trust_domain,
                expected_spiffe_id=self.expected_spiffe_id,
            )
        return self.ssl_context if self.ssl_context is not None else True

    def fetch_agent_card(
        self,
        trust_resolver: TrustBundleResolver,
        well_known_path: str = "/.well-known/agent-card.json",
    ) -> Tuple[AgentCard, Dict[str, Any]]:
        url = f"{self.agent_base_url}{well_known_path}"
        with httpx.Client(verify=self._verify_kwarg(), timeout=self.timeout) as client:
            resp = client.get(url, headers={"A2A-Version": A2A_PROTOCOL_VERSION})
            resp.raise_for_status()
            raw = resp.json()
        return AgentCard.from_dict_and_verify(raw, trust_resolver), raw

    def call_rpc(
        self,
        method: str,
        params: Mapping[str, Any],
        compact_token: Optional[str] = None,
        rpc_id: Optional[str] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        url = f"{self.agent_base_url}{self.rpc_path}"
        payload = {
            "jsonrpc": "2.0",
            "id": rpc_id or f"rpc-{uuid.uuid4().hex[:10]}",
            "method": method,
            "params": dict(params),
        }
        headers = self._build_headers(url, compact_token, accept="application/json")
        with httpx.Client(verify=self._verify_kwarg(), timeout=self.timeout) as client:
            resp = client.post(url, json=payload, headers=headers)
            return resp.status_code, resp.json()

    def send_message(
        self,
        message: Message,
        compact_token: Optional[str] = None,
        configuration: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        params: Dict[str, Any] = {"message": message.to_dict()}
        if configuration:
            params["configuration"] = dict(configuration)
        return self.call_rpc("SendMessage", params, compact_token=compact_token)

    def get_task(
        self, task_id: str, compact_token: Optional[str] = None
    ) -> Tuple[int, Dict[str, Any]]:
        return self.call_rpc("GetTask", {"id": task_id}, compact_token=compact_token)

    def cancel_task(
        self,
        task_id: str,
        compact_token: Optional[str] = None,
        revoke_prefix: Optional[str] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        params: Dict[str, Any] = {"id": task_id}
        if revoke_prefix:
            params["revokePrefix"] = revoke_prefix
        return self.call_rpc("CancelTask", params, compact_token=compact_token)

    def send_streaming_message(
        self,
        message: Message,
        compact_token: Optional[str] = None,
        configuration: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[int, str, List[Dict[str, Any]]]:
        """Invoke `SendStreamingMessage` and parse live `text/event-stream` SSE frames."""
        url = f"{self.agent_base_url}{self.rpc_path}"
        params: Dict[str, Any] = {"message": message.to_dict()}
        if configuration:
            params["configuration"] = dict(configuration)
        payload = {
            "jsonrpc": "2.0",
            "id": f"sse-{uuid.uuid4().hex[:10]}",
            "method": "SendStreamingMessage",
            "params": params,
        }
        headers = self._build_headers(url, compact_token, accept="text/event-stream")
        events: List[Dict[str, Any]] = []
        with httpx.Client(verify=self._verify_kwarg(), timeout=self.timeout) as client:
            with client.stream("POST", url, json=payload, headers=headers) as resp:
                status_code = resp.status_code
                content_type = resp.headers.get("content-type", "")
                if "text/event-stream" not in content_type.lower():
                    raw_body = resp.read().decode("utf-8", errors="replace")
                    try:
                        events.append(json.loads(raw_body))
                    except Exception:
                        events.append({"raw": raw_body})
                    return status_code, content_type, events

                for line in resp.iter_lines():
                    s = line.strip()
                    if not s or s.startswith(":"):
                        continue
                    if s.startswith("data:"):
                        data_str = s[len("data:") :].strip()
                        if data_str:
                            events.append(json.loads(data_str))
        return status_code, content_type, events
