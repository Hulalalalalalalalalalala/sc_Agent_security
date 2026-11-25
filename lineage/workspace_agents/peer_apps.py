"""Symmetric Peer-to-Peer Workspace Assistant Applications & Idempotent Vault (`peer_apps.py`)."""

from __future__ import annotations

from collections import OrderedDict
import concurrent.futures
from dataclasses import dataclass
import hmac
import math
import os
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple
import uuid

import httpx

from lineage.a2a.models import (
    A2AAccessDeniedError,
    A2AInvalidParamsError,
    Artifact,
    Message,
)
from lineage.a2a.rpc import (
    A2AInvocationContext,
    A2ARPCExecutionError,
    A2AServerEngine,
)
from lineage.agents.ollama_client import OllamaClient, OllamaError
from lineage.agents.specialist_apps import (
    _is_fault_injection_enabled,
    _require_bounded_float,
    _validate_sync_hook_url,
    _verify_loopback,
)
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.protocol.lattice import PermissionLattice
from lineage.protocol.token import compute_branch_idempotency_key
from lineage.workspace_agents.intent_router import (
    WorkspaceIntentRouter,
    canonicalize_project_code,
)

ArtifactCallback = Optional[Callable[[Artifact], None]]

_TECH_REVIEW_TOOL_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "reserve_cloud_budget",
            "description": "Reserve cloud GPU/compute budget for a collaborative project",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_code": {"type": "string"},
                    "amount": {"type": "number"},
                },
                "required": ["project_code", "amount"],
            },
        },
    }
]

_PROCUREMENT_TOOL_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "procure_vendor_quote",
            "description": "Lock SaaS/vendor procurement quote for a collaborative project",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_code": {"type": "string"},
                    "amount": {"type": "number"},
                },
                "required": ["project_code", "amount"],
            },
        },
    }
]


class IdempotencyConflictError(ValueError):
    """Raised when an `idempotency_key` is replayed with conflicting parameters."""


@dataclass
class IdempotencyRecord:
    """Stored execution receipt keyed by `(sub, branch_idempotency_key)`."""

    receipt_id: str
    sub: str
    idempotency_key: str
    operation: str
    project_code: str
    amount_usd: float
    created_at: float
    result_data: Dict[str, Any]
    target: str = ""
    charge_count: int = 1
    replay_count: int = 0

    def to_dict(self, idempotent_replay: bool = False) -> Dict[str, Any]:
        out = dict(self.result_data)
        out.update(
            {
                "receipt_id": self.receipt_id,
                "idempotency_key": self.idempotency_key,
                "idempotent_replay": idempotent_replay,
                "charge_count": self.charge_count,
                "replay_count": self.replay_count,
            }
        )
        return out


class IdempotencyLedger:
    """Bounded thread-safe idempotency & pre-takeover lookup ledger."""

    def __init__(self, max_entries: int = 10_000) -> None:
        self.max_entries = max(64, int(max_entries))
        self._lock = threading.Lock()
        self._records: "OrderedDict[Tuple[str, str], IdempotencyRecord]" = OrderedDict()
        self._total_unique_charges: int = 0

    @property
    def total_unique_charges(self) -> int:
        with self._lock:
            return self._total_unique_charges

    def query_status(self, sub: str, idempotency_key: str) -> Dict[str, Any]:
        clean_key = str(idempotency_key or "").strip()
        with self._lock:
            rec = self._records.get((str(sub), clean_key)) if clean_key else None
            if rec is None:
                return {
                    "found": False,
                    "idempotency_key": clean_key,
                    "charge_count": 0,
                    "receipt": None,
                }
            return {
                "found": True,
                "idempotency_key": clean_key,
                "charge_count": rec.charge_count,
                "replay_count": rec.replay_count,
                "receipt": rec.to_dict(idempotent_replay=True),
            }

    def execute_once(
        self,
        *,
        sub: str,
        idempotency_key: str,
        operation: str,
        project_code: str,
        amount_usd: float,
        builder_fn: Callable[[str], Dict[str, Any]],
        target: str = "",
    ) -> Tuple[Dict[str, Any], bool]:
        clean_sub = str(sub)
        clean_key = str(idempotency_key or "").strip()
        clean_op = str(operation)
        clean_target = str(target or "")
        clean_proj = str(project_code)
        clean_amt = float(amount_usd)
        with self._lock:
            if clean_key and (clean_sub, clean_key) in self._records:
                existing = self._records[(clean_sub, clean_key)]
                if (
                    existing.operation != clean_op
                    or existing.target != clean_target
                    or existing.project_code != clean_proj
                    or not math.isclose(existing.amount_usd, clean_amt, abs_tol=1e-6)
                ):
                    raise IdempotencyConflictError(
                        f"Idempotency key {clean_key!r} already bound to "
                        f"({existing.operation}, {existing.target}, {existing.project_code}, {existing.amount_usd}); "
                        f"conflicting replay ({clean_op}, {clean_target}, {clean_proj}, {clean_amt}) rejected"
                    )
                existing.replay_count += 1
                return existing.to_dict(idempotent_replay=True), True

            receipt_id = f"RCPT-{uuid.uuid4().hex[:10].upper()}"
            data = dict(builder_fn(receipt_id))
            self._total_unique_charges += 1
            rec = IdempotencyRecord(
                receipt_id=receipt_id,
                sub=clean_sub,
                idempotency_key=clean_key or f"ephemeral-{receipt_id}",
                operation=clean_op,
                project_code=clean_proj,
                amount_usd=clean_amt,
                created_at=time.time(),
                result_data=data,
                target=clean_target,
                charge_count=1,
                replay_count=0,
            )
            if clean_key:
                if len(self._records) >= self.max_entries:
                    self._records.popitem(last=False)
                self._records[(clean_sub, clean_key)] = rec
            return rec.to_dict(idempotent_replay=False), False


class WorkspaceSidecarClient:
    """Loopback client from co-located workspace `app` (`127.0.0.1`) to `lct-sidecar`."""

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

    def list_skills(self) -> List[Dict[str, Any]]:
        st, out = self._post({"action": "list_skills"}, http_timeout=10.0)
        if st != 200:
            return []
        return list(out.get("peers") or [])

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

    def sign_checkpoint(
        self,
        *,
        task_id: str,
        sub: str,
        prior_root_block_hash: str,
        original_max_amount: Optional[float],
        original_max_calls: int,
        completed_branches: Iterable[str],
        remaining_branches: Iterable[str],
        consumed_amount: float,
        consumed_calls: int,
        request_id: Optional[str] = None,
        prior_token: Optional[str] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        req_b: Dict[str, Any] = {
            "action": "sign_checkpoint",
            "task_id": task_id,
            "sub": sub,
            "prior_root_block_hash": prior_root_block_hash,
            "original_max_amount": original_max_amount,
            "original_max_calls": original_max_calls,
            "completed_branches": list(completed_branches),
            "remaining_branches": list(remaining_branches),
            "consumed_amount": consumed_amount,
            "consumed_calls": consumed_calls,
        }
        if request_id:
            req_b["request_id"] = request_id
        if prior_token:
            req_b["prior_token"] = prior_token
        return self._post(req_b, http_timeout=10.0)

    def inspect_inbox(
        self,
        task_id: str,
        sub: Optional[str] = None,
        caller_task_id: Optional[str] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        body: Dict[str, Any] = {"action": "inspect_inbox", "task_id": task_id}
        if sub is not None:
            body["sub"] = sub
        if caller_task_id is not None:
            body["caller_task_id"] = caller_task_id
        return self._post(body, http_timeout=10.0)

    def get_request_permissions(self, request_id: str) -> Optional[PermissionLattice]:
        if not request_id or request_id.startswith("req-oauth-"):
            return None
        st, out = self._post(
            {"action": "get_request_permissions", "request_id": request_id},
            http_timeout=5.0,
        )
        if (
            st == 200
            and out.get("has_lct_permissions")
            and isinstance(out.get("effective_permissions"), Mapping)
        ):
            return PermissionLattice.from_dict(out["effective_permissions"])
        return None

    def request_local_ca_consent(
        self,
        *,
        task_id: str,
        requester_sub: str,
        delegate_spiffe_id: str,
        delegate_jkt: str,
        tools: Iterable[str],
        user_oidc_token: Optional[str] = None,
        ttl_seconds: float = 120.0,
    ) -> Tuple[int, Dict[str, Any]]:
        return self._post(
            {
                "action": "request_local_ca_consent",
                "task_id": task_id,
                "requester_sub": requester_sub,
                "delegate_spiffe_id": delegate_spiffe_id,
                "delegate_jkt": delegate_jkt,
                "tools": list(tools),
                "user_oidc_token": user_oidc_token,
                "ttl_seconds": ttl_seconds,
            },
            http_timeout=12.0,
        )

    def revoke_task_lineage(
        self, request_id: str, prefix: str, reason: str = "a2a_cancel_task"
    ) -> Tuple[int, Dict[str, Any]]:
        return self._post(
            {
                "action": "revoke_subtree",
                "request_id": request_id,
                "prefix": prefix,
                "reason": reason,
            },
            http_timeout=15.0,
        )

    def call_mcp_tool(
        self,
        request_id: str,
        mcp_target: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        timeout: float = 15.0,
        idempotency_key: Optional[str] = None,
        owner_consent_token: Optional[str] = None,
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
        clean_t = (mcp_target or "").strip()
        if clean_t.startswith("skill://"):
            req_body["required_skill"] = clean_t[len("skill://") :]
        elif clean_t.startswith("spiffe://"):
            req_body["target_spiffe_id"] = clean_t
        else:
            req_body["target_url"] = clean_t
        if idempotency_key:
            req_body["idempotency_key"] = idempotency_key
        if owner_consent_token:
            req_body["owner_consent_token"] = owner_consent_token
        st, out = self._post(req_body, http_timeout=timeout + 5.0)
        if st in (500, 502, 503) and (
            "REVOCATION_ANCHOR_UNAVAILABLE" in str(out)
            or "timed out" in str(out).lower()
            or "upstream_transport_error" in str(out)
        ):
            time.sleep(1.2)
            st, out = self._post(req_body, http_timeout=timeout + 5.0)
        return st, out

    def call_mcp_tool_converged(
        self,
        task_id: str,
        sub: str,
        mcp_target: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        timeout: float = 15.0,
        idempotency_key: Optional[str] = None,
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
        clean_t = (mcp_target or "").strip()
        if clean_t.startswith("skill://"):
            req_body["required_skill"] = clean_t[len("skill://") :]
        elif clean_t.startswith("spiffe://"):
            req_body["target_spiffe_id"] = clean_t
        else:
            req_body["target_url"] = clean_t
        if idempotency_key:
            req_body["idempotency_key"] = idempotency_key
        return self._post(req_body, http_timeout=timeout + 5.0)

    def delegate_peer(
        self,
        request_id: str,
        permissions: Optional[PermissionLattice],
        payload: Mapping[str, Any],
        required_skill: Optional[str] = None,
        *,
        target_spiffe_id: Optional[str] = None,
        task_path: str = "/a2a/task",
        hop_segment: Optional[str] = None,
        logical_branch_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        owner_consent_token: Optional[str] = None,
        use_prune_and_graft: bool = True,
        timeout: float = 35.0,
    ) -> Tuple[int, Dict[str, Any]]:
        body: Dict[str, Any] = {
            "action": "delegate_agent",
            "request_id": request_id,
            "payload": dict(payload),
            "task_path": task_path,
            "use_prune_and_graft": use_prune_and_graft,
            "timeout": timeout,
        }
        if required_skill:
            body["required_skill"] = required_skill
        if target_spiffe_id:
            st_c, out_c = self.resolve_card(spiffe_id=target_spiffe_id)
            if st_c == 200 and out_c.get("candidate_origins"):
                card_d = out_c["agent_card"]
                body["delegate_spiffe_id"] = card_d["spiffe_id"]
                body["delegate_jkt"] = card_d["jkt"]
                body["target_url"] = f"{out_c['candidate_origins'][0].rstrip('/')}{task_path}"
        if permissions is not None:
            body["permissions"] = permissions.to_dict()
        if hop_segment:
            body["hop_segment"] = hop_segment
        if logical_branch_id:
            body["logical_branch_id"] = logical_branch_id
        if idempotency_key:
            body["idempotency_key"] = idempotency_key
        if owner_consent_token:
            body["owner_consent_token"] = owner_consent_token
        return self._post(body, http_timeout=max(timeout * 3.0 + 10.0, 60.0))

    def submit_converged_branch(
        self,
        request_id: str,
        permissions: PermissionLattice,
        branch_name: str,
        branch_data: Mapping[str, Any],
        required_skill: str = "workspace.vault_converge",
        hop_segment: str = "VaultConverge",
    ) -> Tuple[int, Dict[str, Any]]:
        return self.delegate_peer(
            request_id=request_id,
            permissions=permissions,
            payload={
                "branch_name": branch_name,
                "branch_data": {"branch_kind": branch_name, **dict(branch_data)},
            },
            required_skill=required_skill,
            task_path="/a2a/converge",
            hop_segment=hop_segment,
            logical_branch_id=f"converge-{branch_name}",
            use_prune_and_graft=False,
            timeout=15.0,
        )

    def return_result(
        self,
        request_id: str,
        result_payload: Mapping[str, Any],
        timeout: float = 1.5,
        simulate_direct_parent_unreachable: bool = False,
    ) -> Tuple[int, Dict[str, Any]]:
        return self._post(
            {
                "action": "return_result",
                "request_id": request_id,
                "result_payload": dict(result_payload),
                "timeout": timeout,
                "simulate_direct_parent_unreachable": simulate_direct_parent_unreachable,
            },
            http_timeout=30.0,
        )


class WorkspaceVaultMCPApp:
    """Loopback-isolated Workspace Vault (`assistant-vault`) hosting idempotent resource ledger & N->1 lock."""

    def __init__(
        self,
        loopback_secret: str,
        outbound_proxy_url: Optional[str] = None,
        ollama: Optional[OllamaClient] = None,
        vault_mcp_target: str = "skill://mcp.workspace-vault",
        port: int = 9001,
    ) -> None:
        self.loopback_secret = loopback_secret
        self.sidecar = (
            WorkspaceSidecarClient(outbound_proxy_url, loopback_secret)
            if outbound_proxy_url
            else None
        )
        self.ollama = ollama
        self.vault_mcp_target = vault_mcp_target
        self.ledger = IdempotencyLedger(max_entries=10_000)
        self._lock = threading.Lock()
        self._compliance_notes: List[Dict[str, Any]] = []
        self.http = ManagedHTTPService(
            service_name="app-workspace-vault",
            dispatcher=self._dispatch,
            host="127.0.0.1",
            port=port,
        )

    def start(self) -> str:
        return self.http.start()

    def stop(self) -> None:
        self.http.stop()

    def _execute_converged_lock(
        self,
        *,
        req_id: str,
        task_id: str,
        sub: str,
        lineage_path: str,
        body: Mapping[str, Any],
    ) -> Tuple[int, Dict[str, Any]]:
        if self.sidecar is None:
            return 500, {"error": "sidecar_client_not_configured"}
        proj_code = canonicalize_project_code(body.get("project_code"), "PRJ-ATLAS")
        st_in, inbox = self.sidecar.inspect_inbox(task_id=task_id, sub=sub)
        conv_payloads = inbox.get("converged_branch_payloads", {}) if st_in == 200 else {}

        escrow_targets = [
            ("cloud-infra-escrow", "tech_review", 280.0),
            ("vendor-procurement-escrow", "biz_procurement", 220.0),
        ]
        outcomes: Dict[str, Any] = {}
        completed_locks: List[Dict[str, Any]] = []

        by_kind: Dict[str, Dict[str, Any]] = {}
        if isinstance(conv_payloads, Mapping):
            for p_key, p_val in conv_payloads.items():
                if isinstance(p_val, Mapping):
                    bk = str(p_val.get("branch_kind") or p_key)
                    by_kind[bk] = dict(p_val)

        for target_name, b_key, default_amt in escrow_targets:
            b_info = by_kind.get(b_key) or {}
            amt = float(b_info.get("amount_usd", default_amt))
            idem = compute_branch_idempotency_key(task_id, f"lock-{target_name}")
            st_c, res_c = self.sidecar.call_mcp_tool_converged(
                task_id=task_id,
                sub=sub,
                mcp_target=self.vault_mcp_target,
                tool_name="lock_joint_project",
                arguments={
                    "project_code": proj_code,
                    "target": target_name,
                    "amount": amt,
                },
                idempotency_key=idem,
            )
            if st_c == 503:
                time.sleep(1.5)
                st_c, res_c = self.sidecar.call_mcp_tool_converged(
                    task_id=task_id,
                    sub=sub,
                    mcp_target=self.vault_mcp_target,
                    tool_name="lock_joint_project",
                    arguments={
                        "project_code": proj_code,
                        "target": target_name,
                        "amount": amt,
                    },
                    idempotency_key=idem,
                )
            outcomes[target_name] = {
                "http_status": st_c,
                "response": res_c.get("upstream_body", res_c),
                "oauth_telemetry": res_c.get("oauth_telemetry"),
            }
            if st_c == 200:
                completed_locks.append(res_c["upstream_body"]["result"]["data"])

        if not completed_locks:
            return (
                403,
                {
                    "error": "all_converged_project_locks_denied",
                    "lock_outcomes": outcomes,
                },
            )

        llm_meta: Optional[Dict[str, Any]] = None
        final_summary = (
            f"Locked {len(completed_locks)}/{len(escrow_targets)} workspace escrow branch(es) for {proj_code}."
        )
        if self.ollama is not None:
            try:
                ans_json, llm_meta = self.ollama.chat_json(
                    system_prompt=(
                        "You are WorkspaceVault Converger. Reply strictly in JSON with key "
                        "executive_summary summarizing locked project branches and any canceled branch."
                    ),
                    user_prompt=f"Project={proj_code}, outcomes={outcomes}",
                )
                final_summary = str(ans_json.get("executive_summary") or final_summary)
            except OllamaError:
                pass

        return (
            200,
            {
                "agent": "assistant-vault",
                "task_id": task_id,
                "sub": sub,
                "project_code": proj_code,
                "converged_branch_count": len(conv_payloads),
                "lock_outcomes": outcomes,
                "completed_locks": completed_locks,
                "degraded_partial_lock": len(completed_locks) < len(escrow_targets),
                "executive_summary": final_summary,
                "llm_trace": llm_meta,
            },
        )

    def _dispatch(self, req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return (
                200,
                {
                    "status": "ok",
                    "app": "assistant-vault",
                    "total_unique_charges": self.ledger.total_unique_charges,
                },
                {},
            )
        if not _verify_loopback(req, self.loopback_secret):
            return 403, {"error": "direct_pod_ip_bypass_blocked"}, {}

        task_id = req.header("X-LCT-Task-Id") or "unknown"
        sub = req.header("X-LCT-Sub") or "unknown"
        req_id = req.header("X-LCT-Request-Id") or ""
        lineage_path = req.header("X-LCT-Lineage-Path") or ""
        decision = req.header("X-LCT-Decision") or "ALLOW"
        hdr_idem = req.header("X-LCT-Idempotency-Key") or ""

        if req.method == "POST" and req.path == "/a2a/task":
            body = req.json()
            st, out = self._execute_converged_lock(
                req_id=req_id,
                task_id=task_id,
                sub=sub,
                lineage_path=lineage_path,
                body=body,
            )
            return st, out, {}

        if req.method == "POST" and req.path == "/mcp":
            body = req.json()
            rpc_id = body.get("id", 1)
            params = body.get("params") or {}
            tool_name = str(params.get("name") or "")
            args = params.get("arguments") or {}
            eff_idem = str(hdr_idem or args.get("idempotency_key") or "").strip()

            if tool_name == "query_operation_status":
                lookup_key = str(args.get("idempotency_key") or eff_idem).strip()
                st_doc = self.ledger.query_status(sub=sub, idempotency_key=lookup_key)
                return (
                    200,
                    {"jsonrpc": "2.0", "id": rpc_id, "result": {"data": st_doc}},
                    {},
                )

            if tool_name in ("reserve_cloud_budget", "procure_vendor_quote", "lock_joint_project"):
                proj_code = canonicalize_project_code(args.get("project_code"), "PRJ-ATLAS")
                amt = _require_bounded_float(args.get("amount"), "amount", 0.01, 1_000_000.0, 250.0)
                target = str(
                    args.get("target")
                    or (
                        "cloud-infra-escrow"
                        if tool_name == "reserve_cloud_budget"
                        else "vendor-procurement-escrow"
                    )
                )
                try:
                    rec_dict, replayed = self.ledger.execute_once(
                        sub=sub,
                        idempotency_key=eff_idem,
                        operation=tool_name,
                        target=target,
                        project_code=proj_code,
                        amount_usd=amt,
                        builder_fn=lambda rcpt_id: {
                            "operation": tool_name,
                            "project_code": proj_code,
                            "target": target,
                            "charged_usd": amt,
                            "task_id": task_id,
                            "sub": sub,
                            "lineage_path": lineage_path,
                            "lineage_decision": decision,
                        },
                    )
                except IdempotencyConflictError as exc:
                    return (
                        409,
                        {
                            "error": "IDEMPOTENCY_PARAMETER_MISMATCH",
                            "detail": str(exc),
                        },
                        {},
                    )
                rec_dict["total_unique_vault_charges"] = self.ledger.total_unique_charges
                return (
                    200,
                    {"jsonrpc": "2.0", "id": rpc_id, "result": {"data": rec_dict, "idempotent_replay": replayed}},
                    {},
                )

            if tool_name == "record_compliance_note":
                proj_code = canonicalize_project_code(args.get("project_code"), "PRJ-ATLAS")
                note = str(args.get("note") or "verified")[:240]
                entry = {
                    "note_id": f"CMP-{uuid.uuid4().hex[:8].upper()}",
                    "project_code": proj_code,
                    "note": note,
                    "task_id": task_id,
                    "sub": sub,
                    "lineage_path": lineage_path,
                }
                with self._lock:
                    if len(self._compliance_notes) >= 5000:
                        self._compliance_notes.pop(0)
                    self._compliance_notes.append(entry)
                return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"data": entry}}, {}

            return (
                400,
                {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32601, "message": f"Unknown vault tool {tool_name!r}"}},
                {},
            )

        return 404, {"error": "route_not_found"}, {}


class WorkspaceAssistantPeerApp:
    """Symmetric Peer Workspace Assistant (`alice` | `bob` | `carol` | `dave`).

    Every peer is an equal autonomous entity hosting:
    1. Owner-protected private workspace resources (`hr_salary_read`, `calendar_write`,
       and co-authorizable `calendar_free_busy`); and
    2. Outbound / inbound P2P collaborative project skills (`workspace.orchestrate`,
       `workspace.tech_review`, `workspace.biz_procurement`, `workspace.deep_analysis`).
    """

    def __init__(
        self,
        peer_name: str,
        owner_sub: str,
        outbound_proxy_url: str,
        loopback_secret: str,
        ollama: Optional[OllamaClient] = None,
        instance_label: str = "primary",
        vault_mcp_target: str = "skill://mcp.workspace-vault",
        port: int = 9001,
    ) -> None:
        self.peer_name = str(peer_name).strip().lower()
        self.owner_sub = str(owner_sub).strip()
        self.instance_label = str(instance_label).strip().lower()
        self.loopback_secret = loopback_secret
        self.sidecar = WorkspaceSidecarClient(outbound_proxy_url, loopback_secret)
        self.ollama = ollama
        self.intent_router = WorkspaceIntentRouter(ollama=ollama)
        self.vault_mcp_target = vault_mcp_target
        self._lock = threading.Lock()
        self._zombie_telemetry: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self.a2a_engine = A2AServerEngine(
            agent_name=f"assistant-{self.peer_name}-{self.instance_label}",
            work_handler=self._a2a_work,
            cascade_revoke_hook=self._cascade_revoke_a2a_v1,
        )
        self.http = ManagedHTTPService(
            service_name=f"app-peer-{self.peer_name}-{self.instance_label}",
            dispatcher=self._dispatch,
            host="127.0.0.1",
            port=port,
        )

    def start(self) -> str:
        return self.http.start()

    def stop(self) -> None:
        self.http.stop()

    def _cascade_revoke_a2a_v1(self, req_id: str, prefix: str, task_id: str) -> Dict[str, Any]:
        st, out = self.sidecar.revoke_task_lineage(
            request_id=req_id,
            prefix=prefix,
            reason=f"a2a_v1_cancel_task:{task_id}",
        )
        if st != 200:
            raise A2ARPCExecutionError(
                f"Failed to cascade lineage revocation for {task_id}: {out}",
                http_status=502,
                data=out,
            )
        return dict(out.get("event") or out)

    def _a2a_work(
        self,
        ctx: A2AInvocationContext,
        user_msg: Message,
        emit_artifact: ArtifactCallback,
    ) -> Tuple[Message, Dict[str, Any]]:
        body = {**ctx.configuration, **user_msg.extract_data()}
        if user_msg.extract_text() and "prompt" not in body:
            body["prompt"] = user_msg.extract_text()
        st, out = self._handle_peer_task(
            req_id=ctx.request_id,
            task_id=ctx.task_id,
            sub=ctx.sub,
            lineage_path=ctx.lineage_path,
            decision=ctx.decision or "ALLOW",
            root_block_hash="",
            co_auth_principals=(),
            idempotency_key="",
            body=body,
            emit_artifact=emit_artifact,
        )
        if st != 200:
            if st == 400:
                raise A2AInvalidParamsError(str(out.get("detail") or out.get("error") or out))
            if st == 403:
                raise A2AAccessDeniedError(str(out.get("detail") or out.get("error") or out))
            raise A2ARPCExecutionError(str(out.get("error") or out), http_status=st, data=out)
        summary = str(out.get("executive_summary") or out.get("summary") or f"{self.peer_name} completed")
        return Message.create_agent(text=summary, data=out), {"peer": self.peer_name}

    # -------------------------------------------------------------------------
    # Owner-Protected Local Private Workspace Tools (`/mcp` & A2A private ops)
    # -------------------------------------------------------------------------
    def _handle_private_tool(
        self,
        *,
        tool_name: str,
        args: Mapping[str, Any],
        sub: str,
        decision: str,
        co_auth_principals: Tuple[str, ...],
    ) -> Tuple[int, Dict[str, Any]]:
        is_owner = sub == self.owner_sub
        is_co_auth_with_owner = (
            decision == "ALLOW_CO_AUTHORIZED"
            and len(co_auth_principals) == 2
            and co_auth_principals[1] == self.owner_sub
        )

        if tool_name == "hr_salary_read":
            if not is_owner:
                return (
                    403,
                    {
                        "error": "CROSS_PRINCIPAL_DENIED",
                        "detail": f"hr_salary_read is strictly owner-only for {self.owner_sub!r}",
                    },
                )
            return (
                200,
                {
                    "owner": self.owner_sub,
                    "tool": "hr_salary_read",
                    "base_salary_usd": 195000,
                    "equity_band": "L6-Principal",
                },
            )

        if tool_name == "calendar_write":
            if not is_owner:
                return (
                    403,
                    {
                        "error": "CROSS_PRINCIPAL_DENIED",
                        "detail": f"calendar_write is strictly owner-only for {self.owner_sub!r}",
                    },
                )
            return (
                200,
                {
                    "owner": self.owner_sub,
                    "tool": "calendar_write",
                    "event_created": str(args.get("title") or "Team Sync"),
                },
            )

        if tool_name == "calendar_free_busy":
            if not (is_owner or is_co_auth_with_owner):
                return (
                    403,
                    {
                        "error": "CROSS_PRINCIPAL_DENIED",
                        "detail": (
                            f"calendar_free_busy for {self.owner_sub!r} requires owner auth or "
                            "explicit Dual-Principal CoAuthorizedToken"
                        ),
                    },
                )
            # Desensitized slots ONLY: zero private meeting titles, attendees, or notes!
            return (
                200,
                {
                    "owner": self.owner_sub,
                    "tool": "calendar_free_busy",
                    "authorization_mode": "CO_AUTHORIZED" if is_co_auth_with_owner else "OWNER_DIRECT",
                    "co_authorized_principals": list(co_auth_principals),
                    "desensitized": True,
                    "slots": [
                        {"window": "2026-12-01T09:00Z/10:30Z", "status": "BUSY"},
                        {"window": "2026-12-01T10:30Z/12:00Z", "status": "FREE"},
                        {"window": "2026-12-01T14:00Z/16:00Z", "status": "FREE"},
                    ],
                },
            )

        return 400, {"error": f"unknown_private_tool:{tool_name}"}

    # -------------------------------------------------------------------------
    # Peer Collaborative Task Execution
    # -------------------------------------------------------------------------
    def _handle_peer_task(
        self,
        *,
        req_id: str,
        task_id: str,
        sub: str,
        lineage_path: str,
        decision: str,
        root_block_hash: str,
        co_auth_principals: Tuple[str, ...],
        idempotency_key: str,
        body: Mapping[str, Any],
        emit_artifact: ArtifactCallback = None,
    ) -> Tuple[int, Dict[str, Any]]:
        op = str(body.get("op") or "").strip()

        # Shared diagnostic / inbox inspection
        if op == "inspect_zombie_telemetry":
            target_tid = str(body.get("inspect_task_id") or task_id)
            with self._lock:
                rec = self._zombie_telemetry.get(target_tid)
            return 200, {"peer": self.peer_name, "instance": self.instance_label, "zombie_telemetry": rec}

        if op == "inspect_inbox":
            target_tid = str(body.get("inspect_task_id") or task_id)
            return self.sidecar.inspect_inbox(
                task_id=target_tid, sub=sub, caller_task_id=task_id
            )

        if op == "request_co_auth_consent":
            req_tools = [str(t).strip() for t in (body.get("tools") or ()) if str(t).strip()]
            del_sid = str(body.get("delegate_spiffe_id") or "").strip()
            del_jkt = str(body.get("delegate_jkt") or "").strip()
            if not req_tools or not del_sid or not del_jkt:
                return 400, {"error": "missing_consent_parameters"}
            owner_oidc = str(body.get("user_oidc_token") or "").strip()
            if not owner_oidc:
                return (
                    401,
                    {
                        "error": "OWNER_CONSENT_PROOF_REQUIRED",
                        "detail": "owner_oidc_token (user_oidc_token) is mandatory to grant co-authorization consent",
                    },
                )
            return self.sidecar.request_local_ca_consent(
                task_id=task_id,
                requester_sub=sub,
                delegate_spiffe_id=del_sid,
                delegate_jkt=del_jkt,
                tools=req_tools,
                user_oidc_token=owner_oidc,
            )

        # Private tool invocation over A2A
        if body.get("private_tool"):
            return self._handle_private_tool(
                tool_name=str(body["private_tool"]),
                args=body.get("arguments") or {},
                sub=sub,
                decision=decision,
                co_auth_principals=co_auth_principals,
            )

        # ---------------------------------------------------------------------
        # Role: Dave (`workspace.deep_analysis` leaf for upward Skip-Level Return)
        # ---------------------------------------------------------------------
        if self.peer_name == "dave" or op == "deep_analysis_and_return":
            proj_code = canonicalize_project_code(body.get("project_code"), "PRJ-ATLAS")
            sim_unreach = bool(body.get("simulate_direct_parent_unreachable", False))
            raw_hook_url = body.get("sync_hook_url")
            raw_hook_spiffe = str(body.get("sync_hook_spiffe_id") or "").strip()
            if (sim_unreach or raw_hook_url or raw_hook_spiffe) and not _is_fault_injection_enabled():
                return 403, {"error": "fault_injection_disabled"}
            clean_hook_url = _validate_sync_hook_url(raw_hook_url) if raw_hook_url else None
            ret_timeout = _require_bounded_float(
                body.get("return_timeout_sec"), "return_timeout_sec", 0.2, 15.0, 1.5
            )

            llm_meta_d: Optional[Dict[str, Any]] = None
            note_text = f"Architecture & compliance deep-analysis verified for {proj_code}"
            if self.ollama is not None:
                try:
                    n_json, llm_meta_d = self.ollama.chat_json(
                        system_prompt="Reply strictly in JSON with key compliance_note (short string).",
                        user_prompt=f"Summarize technical compliance check for {proj_code}.",
                    )
                    note_text = str(n_json.get("compliance_note") or note_text)[:200]
                except OllamaError:
                    pass

            st_n, res_n = self.sidecar.call_mcp_tool(
                req_id,
                self.vault_mcp_target,
                "record_compliance_note",
                {"project_code": proj_code, "note": note_text},
            )
            if st_n != 200:
                return st_n, {"error": "compliance_note_denied", "detail": res_n}

            hook_targets: List[str] = []
            if raw_hook_spiffe:
                st_rc, rc_out = self.sidecar.resolve_card(spiffe_id=raw_hook_spiffe)
                if st_rc == 200:
                    for orig in rc_out.get("candidate_origins") or ():
                        hook_targets.append(f"{str(orig).rstrip('/')}/sync")
            if clean_hook_url:
                hook_targets.append(clean_hook_url)
            if hook_targets:
                hook_tok = str(body.get("sync_hook_token") or "")
                hdrs = {"X-LCT-Sync-Token": hook_tok} if hook_tok else {}
                for h_url in hook_targets:
                    try:
                        r_hk = httpx.post(
                            h_url,
                            json={"task_id": task_id, "ready": True},
                            headers=hdrs,
                            timeout=35.0,
                            trust_env=False,
                        )
                        if r_hk.status_code == 200:
                            break
                    except Exception:
                        continue

            leaf_res = {
                "peer": "assistant-dave",
                "project_code": proj_code,
                "compliance_record": res_n["upstream_body"]["result"]["data"],
                "llm_trace": llm_meta_d,
            }
            st_ret, ret_out = self.sidecar.return_result(
                request_id=req_id,
                result_payload=leaf_res,
                timeout=ret_timeout,
                simulate_direct_parent_unreachable=sim_unreach,
            )
            return (
                200 if st_ret == 200 else st_ret,
                {"leaf_result": leaf_res, "upward_return": ret_out},
            )

        # ---------------------------------------------------------------------
        # Role: Bob (`workspace.tech_review` + 3-tier relay to Dave)
        # ---------------------------------------------------------------------
        if self.peer_name == "bob" or op in ("tech_review", "relay_sub_analysis_to_dave"):
            proj_code = canonicalize_project_code(body.get("project_code"), "PRJ-ATLAS")
            if op == "relay_sub_analysis_to_dave":
                dave_perms = PermissionLattice.create(
                    tools=["record_compliance_note"],
                    max_amount=50.0,
                    allowed_targets=["compliance-ledger"],
                    param_whitelist={"project_code": [proj_code]},
                    max_calls=3,
                )
                st_d, out_d = self.sidecar.delegate_peer(
                    request_id=req_id,
                    permissions=dave_perms,
                    payload={
                        "op": "deep_analysis_and_return",
                        "project_code": proj_code,
                        "simulate_direct_parent_unreachable": bool(
                            body.get("simulate_direct_parent_unreachable", False)
                        ),
                        "return_timeout_sec": body.get("return_timeout_sec", 1.5),
                        "sync_hook_url": body.get("sync_hook_url"),
                        "sync_hook_spiffe_id": body.get("sync_hook_spiffe_id"),
                        "sync_hook_token": body.get("sync_hook_token"),
                    },
                    required_skill="workspace.deep_analysis",
                    hop_segment="DeepAnalysisDave",
                    use_prune_and_graft=False,
                    timeout=35.0,
                )
                return (
                    200 if st_d == 200 else st_d,
                    {
                        "relay_peer": f"assistant-bob-{self.instance_label}",
                        "downstream_status": st_d,
                        "downstream": out_d,
                        "upward_return": (
                            (out_d.get("upstream_body") or {}).get("upward_return")
                            if isinstance(out_d, Mapping)
                            else None
                        ),
                    },
                )

            eff_idem = str(idempotency_key or body.get("idempotency_key") or "").strip()
            req_amt = _require_bounded_float(
                body.get("override_amount_usd")
                if body.get("override_amount_usd") is not None
                else body.get("allocated_budget_usd"),
                "allocated_budget_usd",
                1.0,
                1_000_000.0,
                280.0,
            )
            eff_proj = (
                canonicalize_project_code(body.get("override_project_code"), proj_code)
                if body.get("override_project_code") is not None
                else proj_code
            )
            post_commit_drop = _require_bounded_float(
                body.get("simulate_post_commit_drop_sec"),
                "simulate_post_commit_drop_sec",
                0.0,
                20.0,
                0.0,
            )
            if post_commit_drop > 0.0 and not _is_fault_injection_enabled():
                return 403, {"error": "fault_injection_disabled"}

            # 1) Primary post-commit packet-drop + delayed zombie double-execution attempt!
            if post_commit_drop > 0.0 and self.instance_label == "primary":
                st_commit, res_commit = self.sidecar.call_mcp_tool(
                    req_id,
                    self.vault_mcp_target,
                    "reserve_cloud_budget",
                    {"project_code": eff_proj, "amount": req_amt},
                    idempotency_key=eff_idem or None,
                )
                # Simulate network response drop longer than caller's timeout so Alice prunes primary (`epoch=0`)
                # and grafts `assistant-bob-standby` (`epoch=1`) with the SAME `branch_idempotency_key`!
                time.sleep(post_commit_drop)
                # Now wake up as a zombie on `epoch=0` and attempt a SECOND uncoordinated reservation!
                st_zombie, res_zombie = self.sidecar.call_mcp_tool(
                    req_id,
                    self.vault_mcp_target,
                    "reserve_cloud_budget",
                    {"project_code": eff_proj, "amount": req_amt},
                    idempotency_key=f"zombie-unkeyed-{uuid.uuid4().hex[:8]}",
                    timeout=5.0,
                )
                z_rec = {
                    "task_id": task_id,
                    "sub": sub,
                    "pruned_lineage_path": lineage_path,
                    "initial_pre_drop_commit_status": st_commit,
                    "zombie_mcp_http_status": st_zombie,
                    "zombie_mcp_body": res_zombie.get("upstream_body", res_zombie),
                    "recorded_at": time.time(),
                }
                with self._lock:
                    if len(self._zombie_telemetry) >= 1000:
                        self._zombie_telemetry.popitem(last=False)
                    self._zombie_telemetry[task_id] = z_rec
                return 503, {"error": "simulated_post_commit_response_drop", "zombie_telemetry": z_rec}

            # 2) Pre-takeover idempotency lookup when standby (`epoch>=1`) takes over!
            pre_lookup_doc: Optional[Dict[str, Any]] = None
            if eff_idem and self.instance_label != "primary":
                st_q, res_q = self.sidecar.call_mcp_tool(
                    req_id,
                    self.vault_mcp_target,
                    "query_operation_status",
                    {"idempotency_key": eff_idem},
                    idempotency_key=eff_idem,
                )
                if st_q == 200:
                    pre_lookup_doc = res_q["upstream_body"]["result"]["data"]

            llm_traces_b: List[Dict[str, Any]] = []
            if self.ollama is not None:
                try:
                    _, _, meta_b = self.ollama.chat_tool_call(
                        system_prompt="You are Bob's Workspace Assistant. Invoke reserve_cloud_budget for the project.",
                        user_prompt=f"Reserve {req_amt} USD cloud architecture budget for project_code={eff_proj}.",
                        tools_schema=_TECH_REVIEW_TOOL_SCHEMA,
                    )
                    llm_traces_b.append(meta_b)
                except OllamaError as exc:
                    return 502, {"error": "ollama_inference_failed", "detail": str(exc)}

            st_res, res_res = self.sidecar.call_mcp_tool(
                req_id,
                self.vault_mcp_target,
                "reserve_cloud_budget",
                {"project_code": eff_proj, "amount": req_amt},
                idempotency_key=eff_idem or None,
            )
            if st_res != 200:
                return st_res, {"error": "cloud_budget_reservation_denied", "mcp_response": res_res}
            reserved_data = res_res["upstream_body"]["result"]["data"]

            if emit_artifact is not None:
                emit_artifact(
                    Artifact.create(
                        name="bob-tech-review-receipt",
                        description=f"Cloud architecture budget reserved for {eff_proj}",
                        data=reserved_data,
                    )
                )

            conv_out: Optional[Dict[str, Any]] = None
            if not body.get("skip_convergence"):
                conv_perms = PermissionLattice.create(
                    tools=["lock_joint_project"],
                    max_amount=req_amt,
                    allowed_targets=["cloud-infra-escrow"],
                    param_whitelist={"project_code": [eff_proj]},
                    max_calls=3,
                )
                st_cv, res_cv = self.sidecar.submit_converged_branch(
                    request_id=req_id,
                    permissions=conv_perms,
                    branch_name="tech_review",
                    branch_data={"project_code": eff_proj, "amount_usd": req_amt, "receipt": reserved_data},
                )
                if st_cv != 200:
                    return st_cv, {"error": "vault_convergence_submit_failed", "detail": res_cv}
                conv_out = res_cv.get("upstream_body", res_cv)

            hop_tel = [
                r["oauth_telemetry"]
                for r in (res_res,)
                if isinstance(r, Mapping) and r.get("oauth_telemetry")
            ]
            return (
                200,
                {
                    "peer": "assistant-bob",
                    "instance_label": self.instance_label,
                    "lineage_path": lineage_path,
                    "branch_idempotency_key": eff_idem,
                    "pre_takeover_lookup": pre_lookup_doc,
                    "cloud_reservation": reserved_data,
                    "convergence": conv_out,
                    "llm_traces": llm_traces_b,
                    **({"oauth_hop_telemetry": hop_tel} if hop_tel else {}),
                },
            )

        # ---------------------------------------------------------------------
        # Role: Carol (`workspace.biz_procurement`)
        # ---------------------------------------------------------------------
        if self.peer_name == "carol" or op == "biz_procurement":
            proj_code = canonicalize_project_code(body.get("project_code"), "PRJ-ATLAS")
            eff_idem_c = str(idempotency_key or body.get("idempotency_key") or "").strip()
            req_amt_c = _require_bounded_float(
                body.get("allocated_budget_usd"), "allocated_budget_usd", 1.0, 1_000_000.0, 220.0
            )
            stall_sec = _require_bounded_float(
                body.get("simulate_carol_stall_sec"), "simulate_carol_stall_sec", 0.0, 20.0, 0.0
            )
            if stall_sec > 0.0:
                if not _is_fault_injection_enabled():
                    return 403, {"error": "fault_injection_disabled"}
                if self.instance_label == "primary":
                    time.sleep(stall_sec)
                    return 503, {"error": "simulated_carol_primary_stall"}

            llm_traces_c: List[Dict[str, Any]] = []
            if self.ollama is not None:
                try:
                    _, _, meta_c = self.ollama.chat_tool_call(
                        system_prompt="You are Carol's Commercial Assistant. Invoke procure_vendor_quote for the project.",
                        user_prompt=f"Procure vendor quote for {req_amt_c} USD on project_code={proj_code}.",
                        tools_schema=_PROCUREMENT_TOOL_SCHEMA,
                    )
                    llm_traces_c.append(meta_c)
                except OllamaError as exc:
                    return 502, {"error": "ollama_inference_failed", "detail": str(exc)}

            st_p, res_p = self.sidecar.call_mcp_tool(
                req_id,
                self.vault_mcp_target,
                "procure_vendor_quote",
                {"project_code": proj_code, "amount": req_amt_c},
                idempotency_key=eff_idem_c or None,
            )
            if st_p != 200:
                return st_p, {"error": "vendor_procurement_denied", "mcp_response": res_p}
            quote_data = res_p["upstream_body"]["result"]["data"]

            if emit_artifact is not None:
                emit_artifact(
                    Artifact.create(
                        name="carol-procurement-receipt",
                        description=f"Vendor procurement quote locked for {proj_code}",
                        data=quote_data,
                    )
                )

            conv_out_c: Optional[Dict[str, Any]] = None
            if not body.get("skip_convergence"):
                conv_perms_c = PermissionLattice.create(
                    tools=["lock_joint_project"],
                    max_amount=req_amt_c,
                    allowed_targets=["vendor-procurement-escrow"],
                    param_whitelist={"project_code": [proj_code]},
                    max_calls=3,
                )
                st_cvc, res_cvc = self.sidecar.submit_converged_branch(
                    request_id=req_id,
                    permissions=conv_perms_c,
                    branch_name="biz_procurement",
                    branch_data={"project_code": proj_code, "amount_usd": req_amt_c, "receipt": quote_data},
                )
                if st_cvc != 200:
                    return st_cvc, {"error": "vault_convergence_submit_failed", "detail": res_cvc}
                conv_out_c = res_cvc.get("upstream_body", res_cvc)

            hop_tel_c = [
                r["oauth_telemetry"]
                for r in (res_p,)
                if isinstance(r, Mapping) and r.get("oauth_telemetry")
            ]
            return (
                200,
                {
                    "peer": "assistant-carol",
                    "instance_label": self.instance_label,
                    "lineage_path": lineage_path,
                    "branch_idempotency_key": eff_idem_c,
                    "vendor_quote": quote_data,
                    "convergence": conv_out_c,
                    "llm_traces": llm_traces_c,
                    **({"oauth_hop_telemetry": hop_tel_c} if hop_tel_c else {}),
                },
            )

        # ---------------------------------------------------------------------
        # Role: Alice (`workspace.orchestrate` — symmetric initiator peer)
        # ---------------------------------------------------------------------
        if op == "probe_peer_private_resource":
            target_tool = str(body.get("target_tool") or "hr_salary_read")
            consent_tok = str(body.get("owner_consent_token") or "").strip() or None
            probe_perms = PermissionLattice.create(
                tools=[target_tool],
                max_amount=100.0,
                max_calls=2,
            )
            st_pr, out_pr = self.sidecar.call_mcp_tool(
                req_id,
                str(body.get("target_peer_mcp") or "skill://workspace.bob_private"),
                target_tool,
                dict(body.get("arguments") or {}),
                owner_consent_token=consent_tok,
            )
            if st_pr == 404:
                # Fallback via A2A private_tool route on workspace.tech_review peer
                st_pr, out_pr = self.sidecar.delegate_peer(
                    request_id=req_id,
                    permissions=probe_perms,
                    payload={"private_tool": target_tool, "arguments": dict(body.get("arguments") or {})},
                    required_skill="workspace.tech_review",
                    hop_segment="BobPrivateProbe",
                    owner_consent_token=consent_tok,
                    use_prune_and_graft=False,
                )
            return st_pr, out_pr

        if op == "request_peer_co_auth_and_read":
            target_tool = str(body.get("target_tool") or "calendar_free_busy")
            target_skill = str(body.get("target_peer_skill") or "workspace.tech_review")
            target_mcp = str(body.get("target_peer_mcp") or "skill://workspace.bob_private")
            st_self, self_card = self.sidecar.resolve_card(required_skill="workspace.orchestrate")
            if st_self != 200 or not self_card.get("agent_card"):
                return 500, {"error": "self_card_resolution_failed", "detail": self_card}
            my_card = self_card["agent_card"]
            base_consent_perms = PermissionLattice.create(
                tools=[target_tool], max_amount=100.0, max_calls=3
            )
            eff_cp = self.sidecar.get_request_permissions(req_id)
            consent_perms = (
                eff_cp.intersect(base_consent_perms)
                if eff_cp is not None
                else base_consent_perms
            )
            st_c, out_c = self.sidecar.delegate_peer(
                request_id=req_id,
                permissions=consent_perms,
                payload={
                    "op": "request_co_auth_consent",
                    "tools": [target_tool],
                    "delegate_spiffe_id": my_card["spiffe_id"],
                    "delegate_jkt": my_card["jkt"],
                    "user_oidc_token": body.get("owner_oidc_token"),
                },
                required_skill=target_skill,
                hop_segment="ConsentHandshake",
                use_prune_and_graft=False,
                timeout=15.0,
            )
            if st_c != 200:
                return st_c, {"error": "peer_consent_rejected", "detail": out_c}
            up_c = out_c.get("upstream_body") or out_c
            consent_tok = str(up_c.get("compact_token") or up_c.get("token") or "").strip()
            if not consent_tok:
                return 403, {"error": "missing_consent_token", "detail": up_c}
            return self.sidecar.call_mcp_tool(
                req_id,
                target_mcp,
                target_tool,
                dict(body.get("arguments") or {}),
                owner_consent_token=consent_tok,
            )

        if op == "probe_overprivilege":
            if not _is_fault_injection_enabled():
                return 403, {"error": "fault_injection_disabled"}
            allowed_proj = canonicalize_project_code(body.get("allowed_project_code"), "PRJ-ATLAS")
            cap_usd = _require_bounded_float(body.get("budget_cap_usd"), "budget_cap_usd", 1.0, 100_000.0, 400.0)
            attempt_usd = _require_bounded_float(body.get("attempt_amount_usd"), "attempt_amount_usd", 1.0, 100_000.0, 950.0)
            attempt_proj = canonicalize_project_code(body.get("attempt_project_code"), "PRJ-ROGUE")
            p_perms = PermissionLattice.create(
                tools=["reserve_cloud_budget", "query_operation_status"],
                max_amount=cap_usd,
                allowed_targets=["cloud-infra-escrow"],
                param_whitelist={"project_code": [allowed_proj]},
                max_calls=4,
            )
            return self.sidecar.delegate_peer(
                request_id=req_id,
                permissions=p_perms,
                payload={
                    "op": "tech_review",
                    "project_code": allowed_proj,
                    "override_amount_usd": attempt_usd,
                    "override_project_code": attempt_proj,
                    "skip_convergence": True,
                },
                required_skill="workspace.tech_review",
                hop_segment="TechOverprivProbe",
                use_prune_and_graft=False,
                timeout=35.0,
            )

        if op == "relay_skip_level_analysis":
            proj_code = canonicalize_project_code(body.get("project_code"), "PRJ-ATLAS")
            relay_perms = PermissionLattice.create(
                tools=["record_compliance_note"],
                max_amount=100.0,
                allowed_targets=["compliance-ledger"],
                param_whitelist={"project_code": [proj_code]},
                max_calls=4,
            )
            st_r, out_r = self.sidecar.delegate_peer(
                request_id=req_id,
                permissions=relay_perms,
                payload={
                    "op": "relay_sub_analysis_to_dave",
                    "project_code": proj_code,
                    "simulate_direct_parent_unreachable": bool(
                        body.get("simulate_direct_parent_unreachable", False)
                    ),
                    "return_timeout_sec": body.get("return_timeout_sec", 1.2),
                    "sync_hook_url": body.get("sync_hook_url"),
                    "sync_hook_spiffe_id": body.get("sync_hook_spiffe_id"),
                    "sync_hook_token": body.get("sync_hook_token"),
                },
                required_skill="workspace.tech_review",
                target_spiffe_id=body.get("target_bob_spiffe_id"),
                hop_segment="BobRelay",
                use_prune_and_graft=False,
                timeout=40.0,
            )
            return 200, {"downstream_http": st_r, "downstream": out_r}

        if op == "trigger_converged_project_lock":
            proj_code = canonicalize_project_code(body.get("project_code"), "PRJ-ATLAS")
            base_lock_perms = PermissionLattice.create(
                tools=["lock_joint_project"],
                max_amount=500.0,
                allowed_targets=["cloud-infra-escrow", "vendor-procurement-escrow"],
                param_whitelist={"project_code": [proj_code]},
                max_calls=6,
            )
            eff_lk_perms = self.sidecar.get_request_permissions(req_id)
            lock_perms = (
                eff_lk_perms.intersect(base_lock_perms)
                if eff_lk_perms is not None
                else base_lock_perms
            )
            return self.sidecar.delegate_peer(
                request_id=req_id,
                permissions=lock_perms,
                payload={"project_code": proj_code},
                required_skill="workspace.vault_converge",
                hop_segment=str(body.get("trigger_hop_segment", "VaultLockTrigger")),
                use_prune_and_graft=False,
                timeout=35.0,
            )

        if op == "execute_phased_long_task":
            proj_code = canonicalize_project_code(body.get("project_code"), "PRJ-ATLAS")
            orig_max_amt = _require_bounded_float(
                body.get("original_max_amount"), "original_max_amount", 1.0, 100_000.0, 800.0
            )
            orig_max_calls = int(body.get("original_max_calls", 10))
            phase1_amt = _require_bounded_float(
                body.get("phase1_amount_usd"), "phase1_amount_usd", 1.0, orig_max_amt, 300.0
            )
            wait_exp_sec = _require_bounded_float(
                body.get("wait_for_expiry_sec"), "wait_for_expiry_sec", 0.0, 30.0, 2.5
            )
            p1_perms = PermissionLattice.create(
                tools=["reserve_cloud_budget", "query_operation_status", "lock_joint_project"],
                max_amount=phase1_amt,
                allowed_targets=["cloud-infra-escrow"],
                param_whitelist={"project_code": [proj_code]},
                max_calls=4,
            )
            st_p1, out_p1 = self.sidecar.delegate_peer(
                request_id=req_id,
                permissions=p1_perms,
                payload={
                    "op": "tech_review",
                    "project_code": proj_code,
                    "allocated_budget_usd": phase1_amt,
                },
                required_skill="workspace.tech_review",
                hop_segment="TechReviewBob",
                logical_branch_id="TechReviewBob",
                use_prune_and_graft=True,
                timeout=30.0,
            )
            if st_p1 != 200:
                return st_p1, {"error": "phase1_tech_review_failed", "detail": out_p1}

            if wait_exp_sec > 0.0:
                time.sleep(wait_exp_sec)

            p2_amt = min(220.0, max(1.0, orig_max_amt - phase1_amt))
            p2_perms = PermissionLattice.create(
                tools=["procure_vendor_quote", "query_operation_status", "lock_joint_project"],
                max_amount=p2_amt,
                allowed_targets=["vendor-procurement-escrow"],
                param_whitelist={"project_code": [proj_code]},
                max_calls=4,
            )
            st_p2, out_p2 = self.sidecar.delegate_peer(
                request_id=req_id,
                permissions=p2_perms,
                payload={
                    "op": "biz_procurement",
                    "project_code": proj_code,
                    "allocated_budget_usd": p2_amt,
                },
                required_skill="workspace.biz_procurement",
                hop_segment="BizProcurementCarol",
                logical_branch_id="BizProcurementCarol",
                use_prune_and_graft=True,
                timeout=30.0,
            )
            if st_p2 == 401:
                st_ck, ck_out = self.sidecar.sign_checkpoint(
                    task_id=task_id,
                    sub=sub,
                    prior_root_block_hash=str(body.get("prior_root_block_hash") or root_block_hash),
                    original_max_amount=orig_max_amt,
                    original_max_calls=orig_max_calls,
                    completed_branches=["workspace.tech_review"],
                    remaining_branches=["workspace.biz_procurement"],
                    consumed_amount=phase1_amt,
                    consumed_calls=2,
                    request_id=req_id,
                )
                return (
                    401,
                    {
                        "error": "TASK_AUTH_EXPIRED",
                        "phase1_completed": out_p1,
                        "phase2_rejection": out_p2,
                        "checkpoint": ck_out.get("checkpoint") if st_ck == 200 else None,
                    },
                )
            return 200, {"phase1": out_p1, "phase2": out_p2}

        if op == "resume_from_checkpoint":
            proj_code = canonicalize_project_code(body.get("project_code"), "PRJ-ATLAS")
            raw_rem_amt = body.get("remaining_branch_amount_usd")
            if raw_rem_amt is None:
                raw_rem_amt = body.get("phase2_amount_usd")
            rem_amt = _require_bounded_float(
                raw_rem_amt,
                "remaining_branch_amount_usd",
                1.0,
                100_000.0,
                220.0,
            )
            p2_perms_r = PermissionLattice.create(
                tools=["procure_vendor_quote", "query_operation_status", "lock_joint_project"],
                max_amount=rem_amt,
                allowed_targets=["vendor-procurement-escrow"],
                param_whitelist={"project_code": [proj_code]},
                max_calls=4,
            )
            st_r2, out_r2 = self.sidecar.delegate_peer(
                request_id=req_id,
                permissions=p2_perms_r,
                payload={
                    "op": "biz_procurement",
                    "project_code": proj_code,
                    "allocated_budget_usd": rem_amt,
                },
                required_skill="workspace.biz_procurement",
                hop_segment="BizProcurementCarolResume",
                logical_branch_id="BizProcurementCarol",
                use_prune_and_graft=True,
                timeout=30.0,
            )
            if st_r2 != 200:
                return st_r2, {"error": "continuation_branch_failed", "detail": out_r2}

            st_lk, out_lk = self._handle_peer_task(
                req_id=req_id,
                task_id=task_id,
                sub=sub,
                lineage_path=lineage_path,
                decision=decision,
                root_block_hash=root_block_hash,
                co_auth_principals=co_auth_principals,
                idempotency_key=idempotency_key,
                body={
                    "op": "trigger_converged_project_lock",
                    "project_code": proj_code,
                    "trigger_hop_segment": "VaultLockResume",
                },
                emit_artifact=emit_artifact,
            )
            return (
                st_lk,
                {
                    "resumed_branch": out_r2,
                    "converged_lock": out_lk,
                    "vault_convergence": out_lk,
                    "executive_summary": (
                        out_lk.get("upstream_body", {}).get("executive_summary")
                        if isinstance(out_lk, Mapping)
                        else "Resumed project locked"
                    ),
                },
            )

        # Default `collaborate_project`: LLM Intent Router -> Uniform Prune-and-Graft Fan-Out -> Vault Convergence!
        user_prompt = str(
            body.get("prompt")
            or "Coordinate PRJ-ATLAS cloud architecture tech review with Bob ($280) and vendor SaaS procurement with Carol ($220), then lock the joint project."
        )
        branch_timeout = _require_bounded_float(
            body.get("branch_timeout_sec"), "branch_timeout_sec", 0.3, 60.0, 35.0
        )
        post_commit_drop_sim = _require_bounded_float(
            body.get("simulate_post_commit_drop_sec"),
            "simulate_post_commit_drop_sec",
            0.0,
            20.0,
            0.0,
        )
        carol_stall_sim = _require_bounded_float(
            body.get("simulate_carol_stall_sec"),
            "simulate_carol_stall_sec",
            0.0,
            20.0,
            0.0,
        )
        if (post_commit_drop_sim > 0.0 or carol_stall_sim > 0.0) and not _is_fault_injection_enabled():
            return 403, {"error": "fault_injection_disabled"}

        default_proj = canonicalize_project_code(body.get("project_code"), "PRJ-ATLAS")
        parent_cap = PermissionLattice.create(
            tools=[
                "reserve_cloud_budget",
                "procure_vendor_quote",
                "query_operation_status",
                "lock_joint_project",
                "record_compliance_note",
            ],
            max_amount=_require_bounded_float(body.get("max_budget_usd"), "max_budget_usd", 1.0, 100_000.0, 900.0),
            allowed_targets=["cloud-infra-escrow", "vendor-procurement-escrow", "compliance-ledger"],
            param_whitelist={"project_code": [default_proj]},
            max_calls=12,
        )
        eff_in_perms = self.sidecar.get_request_permissions(req_id)
        if eff_in_perms is not None:
            parent_cap = eff_in_perms.intersect(parent_cap)
        peer_catalog = self.sidecar.list_skills()
        try:
            plan = self.intent_router.plan_collaboration(
                user_prompt=user_prompt,
                available_peers=peer_catalog,
                parent_permissions=parent_cap,
                default_project_code=default_proj,
            )
        except OllamaError as exc:
            return 502, {"error": "intent_planning_failed", "detail": str(exc)}

        if emit_artifact is not None:
            emit_artifact(
                Artifact.create(
                    name="alice-intent-plan",
                    description=plan.summary,
                    data=plan.to_dict(),
                )
            )

        def _invoke_planned_branch(b_spec: Any) -> Tuple[str, int, Dict[str, Any]]:
            b_idem = compute_branch_idempotency_key(task_id, b_spec.logical_branch_id)
            b_payload: Dict[str, Any] = {
                "project_code": plan.project_code,
                "allocated_budget_usd": min(b_spec.allocated_budget_usd, 280.0)
                if b_spec.required_skill == "workspace.tech_review"
                else min(b_spec.allocated_budget_usd, 220.0),
                "idempotency_key": b_idem,
                "skip_convergence": bool(body.get("skip_convergence", False)),
            }
            if b_spec.required_skill == "workspace.tech_review" and post_commit_drop_sim > 0.0:
                b_payload["simulate_post_commit_drop_sec"] = post_commit_drop_sim
            if b_spec.required_skill == "workspace.biz_procurement" and carol_stall_sim > 0.0:
                b_payload["simulate_carol_stall_sec"] = carol_stall_sim

            # Allow converged branch submission tool inside delegated permissions when authorized by parent
            extra_tools = {"lock_joint_project"}
            if eff_in_perms is not None:
                extra_tools = extra_tools & set(eff_in_perms.tools)
            del_perms = PermissionLattice.create(
                tools=sorted(set(b_spec.attenuated_permissions.tools) | extra_tools),
                max_amount=b_spec.attenuated_permissions.max_amount,
                allowed_targets=b_spec.attenuated_permissions.allowed_targets,
                param_whitelist={
                    k: sorted(v)
                    for k, v in dict(b_spec.attenuated_permissions.param_whitelist).items()
                },
                max_calls=min(6, eff_in_perms.max_calls if eff_in_perms is not None else 6),
            )
            st_b, out_b = self.sidecar.delegate_peer(
                request_id=req_id,
                permissions=del_perms,
                payload=b_payload,
                required_skill=b_spec.required_skill,
                hop_segment=b_spec.logical_branch_id,
                logical_branch_id=b_spec.logical_branch_id,
                idempotency_key=b_idem,
                use_prune_and_graft=True,
                timeout=branch_timeout,
            )
            return b_spec.required_skill, st_b, out_b

        branch_results: Dict[str, Dict[str, Any]] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(plan.branches))) as pool:
            futs = [pool.submit(_invoke_planned_branch, b) for b in plan.branches]
            for fut in futs:
                sk_name, st_code, res_dict = fut.result()
                branch_results[sk_name] = {"status": st_code, "body": res_dict}

        failed_branches = {k: v for k, v in branch_results.items() if v["status"] != 200}
        if failed_branches:
            first_st = next(iter(failed_branches.values()))["status"]
            return (
                first_st,
                {
                    "error": "peer_collaboration_branch_failed",
                    "intent_plan": plan.to_dict(),
                    "branches": branch_results,
                },
            )

        if body.get("pause_before_lock") or body.get("skip_convergence"):
            return (
                200,
                {
                    "peer": "assistant-alice",
                    "task_id": task_id,
                    "sub": sub,
                    "project_code": plan.project_code,
                    "paused_before_lock": True,
                    "intent_plan": plan.to_dict(),
                    "branches": branch_results,
                },
            )

        st_lock, out_lock = self._handle_peer_task(
            req_id=req_id,
            task_id=task_id,
            sub=sub,
            lineage_path=lineage_path,
            decision=decision,
            root_block_hash=root_block_hash,
            co_auth_principals=co_auth_principals,
            idempotency_key=idempotency_key,
            body={"op": "trigger_converged_project_lock", "project_code": plan.project_code},
            emit_artifact=emit_artifact,
        )
        if st_lock != 200:
            return (
                st_lock,
                {
                    "error": "vault_project_lock_failed",
                    "intent_plan": plan.to_dict(),
                    "branches": branch_results,
                    "vault_lock": out_lock,
                },
            )

        hop_tels: List[Dict[str, Any]] = []
        for b_v in branch_results.values():
            b_body = b_v.get("body") or {}
            if b_body.get("oauth_telemetry"):
                hop_tels.append(b_body["oauth_telemetry"])
            up_b = b_body.get("upstream_body") or {}
            for ht in up_b.get("oauth_hop_telemetry") or ():
                hop_tels.append(ht)
        if isinstance(out_lock, Mapping) and out_lock.get("oauth_telemetry"):
            hop_tels.append(out_lock["oauth_telemetry"])
        up_lk = (out_lock.get("upstream_body") or {}) if isinstance(out_lock, Mapping) else {}
        for oc in (up_lk.get("lock_outcomes") or {}).values():
            if isinstance(oc, Mapping) and oc.get("oauth_telemetry"):
                hop_tels.append(oc["oauth_telemetry"])

        return (
            200,
            {
                "peer": "assistant-alice",
                "task_id": task_id,
                "sub": sub,
                "project_code": plan.project_code,
                "intent_plan": plan.to_dict(),
                "branches": branch_results,
                "vault_convergence": out_lock,
                "executive_summary": up_lk.get("executive_summary", plan.summary),
                **({"oauth_hop_telemetry": hop_tels} if hop_tels else {}),
            },
        )

    def _dispatch(self, req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return (
                200,
                {
                    "status": "ok",
                    "peer": self.peer_name,
                    "owner_sub": self.owner_sub,
                    "instance": self.instance_label,
                },
                {},
            )
        if not _verify_loopback(req, self.loopback_secret):
            return 403, {"error": "direct_pod_ip_bypass_blocked"}, {}

        if req.method == "POST" and req.path in ("/", "/a2a"):
            return self.a2a_engine.dispatch(req)

        req_id = req.header("X-LCT-Request-Id") or ""
        task_id = req.header("X-LCT-Task-Id") or ""
        sub = req.header("X-LCT-Sub") or ""
        lineage_path = req.header("X-LCT-Lineage-Path") or ""
        decision = req.header("X-LCT-Decision") or "ALLOW"
        root_hash = req.header("X-LCT-Root-Block-Hash") or ""
        raw_co = req.header("X-LCT-Co-Authorized-Principals") or ""
        co_principals = tuple(s.strip() for s in raw_co.split(",") if s.strip())
        idem_hdr = req.header("X-LCT-Idempotency-Key") or ""

        if req.method == "POST" and req.path == "/mcp":
            body = req.json()
            rpc_id = body.get("id", 1)
            params = body.get("params") or {}
            t_name = str(params.get("name") or "")
            t_args = params.get("arguments") or {}
            st, data = self._handle_private_tool(
                tool_name=t_name,
                args=t_args if isinstance(t_args, Mapping) else {},
                sub=sub,
                decision=decision,
                co_auth_principals=co_principals,
            )
            if st != 200:
                return st, data, {}
            return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"data": data}}, {}

        if req.method == "POST" and req.path == "/a2a/task":
            body = req.json()
            try:
                st, out = self._handle_peer_task(
                    req_id=req_id,
                    task_id=task_id,
                    sub=sub,
                    lineage_path=lineage_path,
                    decision=decision,
                    root_block_hash=root_hash,
                    co_auth_principals=co_principals,
                    idempotency_key=idem_hdr,
                    body=body if isinstance(body, Mapping) else {},
                )
            except ValueError as exc:
                return 400, {"error": "invalid_request_parameter", "detail": str(exc)}, {}
            return st, out, {}

        return 404, {"error": "route_not_found"}, {}
