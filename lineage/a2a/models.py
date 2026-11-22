"""Official A2A (Agent2Agent) v1.0 Protocol Data Models & Tenant-Isolated Task State Machine.

Implements the official A2A v1.0 core data structures:
- `Part` (`TextPart` `{"text": ...}` and `DataPart` `{"data": ..., "metadata": ...}`)
- `Message` (`messageId`, `contextId`, `taskId`, `role` `ROLE_USER`/`ROLE_AGENT`, `parts`, `metadata`)
- `Artifact` (`artifactId`, `name`, `description`, `parts`, `metadata`)
- `TaskState` (`TASK_STATE_SUBMITTED`, `TASK_STATE_WORKING`, `TASK_STATE_INPUT_REQUIRED`,
  `TASK_STATE_AUTH_REQUIRED`, `TASK_STATE_COMPLETED`, `TASK_STATE_FAILED`, `TASK_STATE_CANCELED`)
- `Task` (`id`, `contextId`, `status`, `history`, `artifacts`, `metadata`)
- `A2ATaskStore`: Thread-safe bounded store enforcing valid state transitions and strict
  `(task_id, sub)` multi-tenant isolation.
"""

from __future__ import annotations

import copy
import datetime as dt
import enum
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

A2A_PROTOCOL_VERSION = "1.0"


class A2AError(Exception):
    """Base exception for A2A v1.0 protocol & state machine errors."""


class A2AInvalidParamsError(A2AError):
    """Raised when an A2A v1.0 message, part, or request parameter is malformed."""


class A2ATaskNotFoundError(A2AError):
    """Raised when a queried or canceled `Task` ID does not exist."""


class A2AAccessDeniedError(A2AError):
    """Raised when a caller attempts cross-tenant (`sub`) or cross-task access."""


class A2AStateTransitionError(A2AError):
    """Raised on illegal `TaskState` transition (e.g. mutating a terminal task)."""


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _is_lineage_ancestor_prefix(ancestor: str, target: str) -> bool:
    """Segment-exact lineage ancestry check (`'/t/A'` covers `'/t/A'` & `'/t/A/B'`, NOT `'/t/AB'`)."""
    a = ancestor.strip().rstrip("/")
    t = target.strip().rstrip("/")
    if not a or not t or not a.startswith("/") or not t.startswith("/"):
        return False
    return a == t or t.startswith(f"{a}/")


class TaskState(str, enum.Enum):
    SUBMITTED = "TASK_STATE_SUBMITTED"
    WORKING = "TASK_STATE_WORKING"
    INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED"
    AUTH_REQUIRED = "TASK_STATE_AUTH_REQUIRED"
    COMPLETED = "TASK_STATE_COMPLETED"
    FAILED = "TASK_STATE_FAILED"
    CANCELED = "TASK_STATE_CANCELED"


TERMINAL_TASK_STATES: FrozenSet[TaskState] = frozenset(
    {
        TaskState.COMPLETED,
        TaskState.FAILED,
        TaskState.CANCELED,
    }
)

ALLOWED_STATE_TRANSITIONS: Dict[TaskState, FrozenSet[TaskState]] = {
    TaskState.SUBMITTED: frozenset(
        {
            TaskState.WORKING,
            TaskState.INPUT_REQUIRED,
            TaskState.AUTH_REQUIRED,
            TaskState.COMPLETED,
            TaskState.FAILED,
            TaskState.CANCELED,
        }
    ),
    TaskState.WORKING: frozenset(
        {
            TaskState.WORKING,
            TaskState.INPUT_REQUIRED,
            TaskState.AUTH_REQUIRED,
            TaskState.COMPLETED,
            TaskState.FAILED,
            TaskState.CANCELED,
        }
    ),
    TaskState.INPUT_REQUIRED: frozenset(
        {
            TaskState.WORKING,
            TaskState.COMPLETED,
            TaskState.FAILED,
            TaskState.CANCELED,
        }
    ),
    TaskState.AUTH_REQUIRED: frozenset(
        {
            TaskState.WORKING,
            TaskState.COMPLETED,
            TaskState.FAILED,
            TaskState.CANCELED,
        }
    ),
    TaskState.COMPLETED: frozenset(),
    TaskState.FAILED: frozenset(),
    TaskState.CANCELED: frozenset(),
}


@dataclass(frozen=True)
class Part:
    """Official A2A v1.0 `Part` union (`TextPart` or `DataPart`)."""

    text: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        has_text = self.text is not None
        has_data = self.data is not None
        if has_text == has_data:
            raise A2AInvalidParamsError(
                "A2A Part must contain exactly one of 'text' (TextPart) or 'data' (DataPart)"
            )
        if has_text and not isinstance(self.text, str):
            raise A2AInvalidParamsError("TextPart 'text' must be a string")
        if has_data and not isinstance(self.data, dict):
            raise A2AInvalidParamsError("DataPart 'data' must be a JSON object")

    @classmethod
    def from_text(
        cls, text: str, metadata: Optional[Mapping[str, Any]] = None
    ) -> "Part":
        return cls(
            text=str(text),
            metadata=dict(metadata) if metadata is not None else None,
        )

    @classmethod
    def from_data(
        cls, data: Mapping[str, Any], metadata: Optional[Mapping[str, Any]] = None
    ) -> "Part":
        if not isinstance(data, Mapping):
            raise A2AInvalidParamsError("DataPart requires a mapping")
        return cls(
            data=copy.deepcopy(dict(data)),
            metadata=dict(metadata) if metadata is not None else None,
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if self.text is not None:
            out["text"] = self.text
        elif self.data is not None:
            out["data"] = copy.deepcopy(self.data)
        if self.metadata:
            out["metadata"] = copy.deepcopy(self.metadata)
        return out

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Part":
        if not isinstance(raw, Mapping):
            raise A2AInvalidParamsError("A2A Part must be a JSON object")
        meta = raw.get("metadata")
        if meta is not None and not isinstance(meta, Mapping):
            raise A2AInvalidParamsError("Part.metadata must be an object")
        if "text" in raw and raw["text"] is not None:
            if "data" in raw and raw["data"] is not None:
                raise A2AInvalidParamsError("Part cannot contain both 'text' and 'data'")
            if not isinstance(raw["text"], str):
                raise A2AInvalidParamsError("TextPart.text must be a string")
            return cls(
                text=raw["text"],
                metadata=dict(meta) if meta is not None else None,
            )
        if "data" in raw and raw["data"] is not None:
            if not isinstance(raw["data"], Mapping):
                raise A2AInvalidParamsError("DataPart.data must be a JSON object")
            return cls(
                data=copy.deepcopy(dict(raw["data"])),
                metadata=dict(meta) if meta is not None else None,
            )
        raise A2AInvalidParamsError("Part missing 'text' or 'data'")


VALID_ROLES = frozenset({"ROLE_USER", "ROLE_AGENT"})


@dataclass(frozen=True)
class Message:
    """Official A2A v1.0 `Message`."""

    message_id: str
    role: str
    parts: Tuple[Part, ...]
    context_id: Optional[str] = None
    task_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        if not self.message_id or not isinstance(self.message_id, str):
            raise A2AInvalidParamsError("Message.messageId must be a non-empty string")
        if self.role not in VALID_ROLES:
            raise A2AInvalidParamsError(
                f"Message.role must be one of {sorted(VALID_ROLES)}, got {self.role!r}"
            )
        if not self.parts:
            raise A2AInvalidParamsError("Message.parts must be non-empty")

    @classmethod
    def create_user(
        cls,
        text: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
        message_id: Optional[str] = None,
        context_id: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "Message":
        parts: List[Part] = []
        if text is not None:
            parts.append(Part.from_text(text))
        if data is not None:
            parts.append(Part.from_data(data))
        if not parts:
            parts.append(Part.from_text(""))
        return cls(
            message_id=message_id or f"msg-{uuid.uuid4().hex[:12]}",
            role="ROLE_USER",
            parts=tuple(parts),
            context_id=context_id,
            task_id=task_id,
            metadata=dict(metadata) if metadata is not None else None,
        )

    @classmethod
    def create_agent(
        cls,
        text: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
        message_id: Optional[str] = None,
        context_id: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "Message":
        parts: List[Part] = []
        if text is not None:
            parts.append(Part.from_text(text))
        if data is not None:
            parts.append(Part.from_data(data))
        if not parts:
            parts.append(Part.from_text("Completed"))
        return cls(
            message_id=message_id or f"msg-{uuid.uuid4().hex[:12]}",
            role="ROLE_AGENT",
            parts=tuple(parts),
            context_id=context_id,
            task_id=task_id,
            metadata=dict(metadata) if metadata is not None else None,
        )

    def extract_text(self) -> str:
        chunks = [p.text for p in self.parts if p.text is not None]
        return "\n".join(chunks).strip()

    def extract_data(self) -> Dict[str, Any]:
        merged: Dict[str, Any] = {}
        for p in self.parts:
            if p.data is not None:
                merged.update(copy.deepcopy(p.data))
        return merged

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "messageId": self.message_id,
            "role": self.role,
            "parts": [p.to_dict() for p in self.parts],
        }
        if self.context_id is not None:
            out["contextId"] = self.context_id
        if self.task_id is not None:
            out["taskId"] = self.task_id
        if self.metadata:
            out["metadata"] = copy.deepcopy(self.metadata)
        return out

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Message":
        if not isinstance(raw, Mapping):
            raise A2AInvalidParamsError("Message must be a JSON object")
        msg_id = str(raw.get("messageId") or "").strip()
        role = str(raw.get("role") or "").strip()
        parts_raw = raw.get("parts")
        if not isinstance(parts_raw, list) or not parts_raw:
            raise A2AInvalidParamsError("Message.parts must be a non-empty list")
        parts = tuple(Part.from_dict(p) for p in parts_raw)
        ctx_id = str(raw["contextId"]) if raw.get("contextId") is not None else None
        tid = str(raw["taskId"]) if raw.get("taskId") is not None else None
        meta = raw.get("metadata")
        if meta is not None and not isinstance(meta, Mapping):
            raise A2AInvalidParamsError("Message.metadata must be an object")
        return cls(
            message_id=msg_id,
            role=role,
            parts=parts,
            context_id=ctx_id,
            task_id=tid,
            metadata=dict(meta) if meta is not None else None,
        )


@dataclass(frozen=True)
class Artifact:
    """Official A2A v1.0 `Artifact`."""

    artifact_id: str
    name: str
    parts: Tuple[Part, ...]
    description: str = ""
    metadata: Optional[Dict[str, Any]] = None

    @classmethod
    def create(
        cls,
        name: str,
        data: Optional[Mapping[str, Any]] = None,
        text: Optional[str] = None,
        description: str = "",
        artifact_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "Artifact":
        parts: List[Part] = []
        if text is not None:
            parts.append(Part.from_text(text))
        if data is not None:
            parts.append(Part.from_data(data))
        if not parts:
            parts.append(Part.from_data({}))
        return cls(
            artifact_id=artifact_id or f"art-{uuid.uuid4().hex[:12]}",
            name=name,
            description=description,
            parts=tuple(parts),
            metadata=dict(metadata) if metadata is not None else None,
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "artifactId": self.artifact_id,
            "name": self.name,
            "description": self.description,
            "parts": [p.to_dict() for p in self.parts],
        }
        if self.metadata:
            out["metadata"] = copy.deepcopy(self.metadata)
        return out

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Artifact":
        if not isinstance(raw, Mapping):
            raise A2AInvalidParamsError("Artifact must be a JSON object")
        parts_raw = raw.get("parts")
        if not isinstance(parts_raw, list) or not parts_raw:
            raise A2AInvalidParamsError("Artifact.parts must be a non-empty list")
        return cls(
            artifact_id=str(raw.get("artifactId") or f"art-{uuid.uuid4().hex[:12]}"),
            name=str(raw.get("name") or "artifact"),
            description=str(raw.get("description") or ""),
            parts=tuple(Part.from_dict(p) for p in parts_raw),
            metadata=dict(raw["metadata"]) if isinstance(raw.get("metadata"), Mapping) else None,
        )


@dataclass(frozen=True)
class TaskStatus:
    """Official A2A v1.0 `TaskStatus`."""

    state: TaskState
    timestamp: str
    message: Optional[Message] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "state": self.state.value,
            "timestamp": self.timestamp,
        }
        if self.message is not None:
            out["message"] = self.message.to_dict()
        return out

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "TaskStatus":
        if not isinstance(raw, Mapping):
            raise A2AInvalidParamsError("TaskStatus must be a JSON object")
        try:
            state = TaskState(str(raw.get("state", "")))
        except ValueError as exc:
            raise A2AInvalidParamsError(f"Invalid TaskState: {raw.get('state')!r}") from exc
        msg = (
            Message.from_dict(raw["message"])
            if isinstance(raw.get("message"), Mapping)
            else None
        )
        return cls(
            state=state,
            timestamp=str(raw.get("timestamp") or utc_now_iso()),
            message=msg,
        )


@dataclass
class Task:
    """Official A2A v1.0 `Task`."""

    id: str
    context_id: str
    status: TaskStatus
    history: List[Message] = field(default_factory=list)
    artifacts: List[Artifact] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def snapshot(self) -> "Task":
        return Task(
            id=self.id,
            context_id=self.context_id,
            status=self.status,
            history=list(self.history),
            artifacts=list(self.artifacts),
            metadata=copy.deepcopy(self.metadata),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "contextId": self.context_id,
            "status": self.status.to_dict(),
            "history": [m.to_dict() for m in self.history],
            "artifacts": [a.to_dict() for a in self.artifacts],
            "metadata": copy.deepcopy(self.metadata),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Task":
        if not isinstance(raw, Mapping):
            raise A2AInvalidParamsError("Task must be a JSON object")
        return cls(
            id=str(raw["id"]),
            context_id=str(raw.get("contextId") or raw["id"]),
            status=TaskStatus.from_dict(raw["status"]),
            history=[Message.from_dict(m) for m in (raw.get("history") or [])],
            artifacts=[Artifact.from_dict(a) for a in (raw.get("artifacts") or [])],
            metadata=copy.deepcopy(dict(raw.get("metadata") or {})),
        )


@dataclass
class _StoredTaskRecord:
    task: Task
    owner_sub: str
    lineage_path: str
    cancel_event: threading.Event
    expires_at: float


class A2ATaskStore:
    """Thread-safe bounded A2A v1.0 Task state machine with `(task_id, sub)` isolation."""

    def __init__(self, ttl_seconds: float = 3600.0, max_tasks: int = 10_000) -> None:
        self.ttl_seconds = float(ttl_seconds)
        self.max_tasks = int(max_tasks)
        self._lock = threading.RLock()
        self._records: "OrderedDict[str, _StoredTaskRecord]" = OrderedDict()

    def _evict_locked(self, now_ts: float) -> None:
        while self._records:
            _, rec = next(iter(self._records.items()))
            if rec.expires_at <= now_ts:
                self._records.popitem(last=False)
            else:
                break

    def create_or_submit(
        self,
        task_id: str,
        owner_sub: str,
        lineage_path: str,
        user_message: Message,
        context_id: Optional[str] = None,
    ) -> Tuple[Task, threading.Event]:
        now_ts = time.time()
        ts_iso = utc_now_iso()
        with self._lock:
            self._evict_locked(now_ts)
            existing = self._records.get(task_id)
            if existing is not None:
                if existing.owner_sub != owner_sub:
                    raise A2AAccessDeniedError(
                        f"Task {task_id!r} belongs to another principal"
                    )
                if existing.task.status.state == TaskState.CANCELED:
                    raise A2AStateTransitionError(
                        f"Task {task_id!r} has already been canceled"
                    )
                # Multi-turn or stage-2 continuation on same task_id & owner_sub
                self._records.move_to_end(task_id)
                bound_msg = Message(
                    message_id=user_message.message_id,
                    role=user_message.role,
                    parts=user_message.parts,
                    context_id=existing.task.context_id,
                    task_id=task_id,
                    metadata=user_message.metadata,
                )
                existing.task.history.append(bound_msg)
                existing.task.status = TaskStatus(
                    state=TaskState.SUBMITTED,
                    timestamp=ts_iso,
                )
                existing.task.metadata.setdefault("stateTransitionHistory", []).append(
                    {"state": TaskState.SUBMITTED.value, "timestamp": ts_iso}
                )
                if lineage_path:
                    existing.lineage_path = lineage_path
                existing.expires_at = now_ts + self.ttl_seconds
                return existing.task.snapshot(), existing.cancel_event

            if len(self._records) >= self.max_tasks:
                self._records.popitem(last=False)

            cid = context_id or user_message.context_id or f"ctx-{task_id}"
            bound_msg = Message(
                message_id=user_message.message_id,
                role=user_message.role,
                parts=user_message.parts,
                context_id=cid,
                task_id=task_id,
                metadata=user_message.metadata,
            )
            status = TaskStatus(state=TaskState.SUBMITTED, timestamp=ts_iso)
            task = Task(
                id=task_id,
                context_id=cid,
                status=status,
                history=[bound_msg],
                artifacts=[],
                metadata={
                    "lineagePath": lineage_path,
                    "stateTransitionHistory": [
                        {"state": TaskState.SUBMITTED.value, "timestamp": ts_iso}
                    ],
                },
            )
            cancel_ev = threading.Event()
            rec = _StoredTaskRecord(
                task=task,
                owner_sub=owner_sub,
                lineage_path=lineage_path,
                cancel_event=cancel_ev,
                expires_at=now_ts + self.ttl_seconds,
            )
            self._records[task_id] = rec
            return task.snapshot(), cancel_ev

    def transition(
        self,
        task_id: str,
        new_state: TaskState,
        agent_message: Optional[Message] = None,
        allow_noop_if_canceled: bool = False,
    ) -> Tuple[Task, bool]:
        """Transition `task_id` to `new_state`, enforcing `ALLOWED_STATE_TRANSITIONS`.

        Returns `(snapshot, transitioned)`. When `allow_noop_if_canceled=True`, returns
        `(canceled_snapshot, False)` if the task was concurrently canceled mid-flight.
        """
        ts_iso = utc_now_iso()
        with self._lock:
            rec = self._records.get(task_id)
            if rec is None:
                raise A2ATaskNotFoundError(f"Unknown task_id: {task_id!r}")
            cur_state = rec.task.status.state
            if cur_state == TaskState.CANCELED and allow_noop_if_canceled:
                return rec.task.snapshot(), False
            allowed = ALLOWED_STATE_TRANSITIONS.get(cur_state, frozenset())
            if new_state not in allowed:
                raise A2AStateTransitionError(
                    f"Illegal A2A TaskState transition for {task_id!r}: {cur_state.value} -> {new_state.value}"
                )
            bound_msg: Optional[Message] = None
            if agent_message is not None:
                bound_msg = Message(
                    message_id=agent_message.message_id,
                    role=agent_message.role,
                    parts=agent_message.parts,
                    context_id=rec.task.context_id,
                    task_id=task_id,
                    metadata=agent_message.metadata,
                )
                rec.task.history.append(bound_msg)
            rec.task.status = TaskStatus(
                state=new_state,
                timestamp=ts_iso,
                message=bound_msg,
            )
            rec.task.metadata.setdefault("stateTransitionHistory", []).append(
                {"state": new_state.value, "timestamp": ts_iso}
            )
            return rec.task.snapshot(), True

    def append_artifact(self, task_id: str, artifact: Artifact) -> Task:
        with self._lock:
            rec = self._records.get(task_id)
            if rec is None:
                raise A2ATaskNotFoundError(f"Unknown task_id: {task_id!r}")
            rec.task.artifacts.append(artifact)
            return rec.task.snapshot()

    def get_authorized(self, task_id: str, caller_sub: str) -> Task:
        now_ts = time.time()
        with self._lock:
            self._evict_locked(now_ts)
            rec = self._records.get(task_id)
            if rec is None:
                raise A2ATaskNotFoundError(f"Task {task_id!r} not found")
            if rec.owner_sub != caller_sub:
                raise A2AAccessDeniedError(
                    f"Principal {caller_sub!r} is forbidden from reading task {task_id!r}"
                )
            return rec.task.snapshot()

    def validate_cancel_request(
        self,
        task_id: str,
        caller_sub: str,
        caller_lineage_path: str = "",
        explicit_prefix: str = "",
    ) -> str:
        """Read-only authorization & state pre-check prior to cascading revocation (`[MEDIUM-M3-01]`)."""
        norm_caller = caller_lineage_path.strip()
        norm_explicit = explicit_prefix.strip()
        if norm_explicit:
            if norm_explicit != f"/{task_id}" and not norm_explicit.startswith(f"/{task_id}/"):
                raise A2AAccessDeniedError(
                    f"revokePrefix {norm_explicit!r} does not belong to task {task_id!r}"
                )
            if norm_caller and not _is_lineage_ancestor_prefix(norm_caller, norm_explicit):
                raise A2AAccessDeniedError(
                    f"Caller branch {norm_caller!r} is not an ancestor of revokePrefix {norm_explicit!r}"
                )

        now_ts = time.time()
        with self._lock:
            self._evict_locked(now_ts)
            rec = self._records.get(task_id)
            if rec is None:
                if not norm_caller:
                    raise A2ATaskNotFoundError(f"Task {task_id!r} not found")
                if norm_caller != f"/{task_id}" and not norm_caller.startswith(f"/{task_id}/"):
                    raise A2AAccessDeniedError(
                        f"Caller branch {norm_caller!r} does not match task {task_id!r}"
                    )
                return norm_explicit or norm_caller

            if rec.owner_sub != caller_sub:
                raise A2AAccessDeniedError(
                    f"Principal {caller_sub!r} is forbidden from canceling task {task_id!r}"
                )
            if rec.lineage_path:
                if not norm_caller or not _is_lineage_ancestor_prefix(
                    norm_caller, rec.lineage_path
                ):
                    raise A2AAccessDeniedError(
                        f"Caller branch {norm_caller!r} is not an upstream ancestor of "
                        f"task branch {rec.lineage_path!r}"
                    )
            cur_state = rec.task.status.state
            if cur_state in (TaskState.COMPLETED, TaskState.FAILED):
                if not rec.task.metadata.get("stagedForSettlement"):
                    raise A2AStateTransitionError(
                        f"Task {task_id!r} is already in terminal state {cur_state.value}"
                    )
            return norm_explicit or rec.lineage_path or norm_caller

    def cancel_authorized(
        self,
        task_id: str,
        caller_sub: str,
        fallback_lineage_path: str = "",
        revocation_metadata: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[Task, str]:
        """Atomically mark `task_id` as `TASK_STATE_CANCELED` and return `(task, lineage_path)`."""
        now_ts = time.time()
        ts_iso = utc_now_iso()
        norm_caller = fallback_lineage_path.strip()
        with self._lock:
            self._evict_locked(now_ts)
            rec = self._records.get(task_id)
            if rec is None:
                if not norm_caller:
                    raise A2ATaskNotFoundError(f"Task {task_id!r} not found")
                # Pre-emptive / staged task cancellation before final settlement step
                cid = f"ctx-{task_id}"
                cancel_msg = Message.create_agent(
                    text=f"Task {task_id} canceled with cascading lineage revocation.",
                    context_id=cid,
                    task_id=task_id,
                )
                meta_dict: Dict[str, Any] = {
                    "lineagePath": norm_caller,
                    "stateTransitionHistory": [
                        {"state": TaskState.CANCELED.value, "timestamp": ts_iso}
                    ],
                }
                if revocation_metadata:
                    meta_dict["cascadingRevocation"] = dict(revocation_metadata)
                task = Task(
                    id=task_id,
                    context_id=cid,
                    status=TaskStatus(
                        state=TaskState.CANCELED,
                        timestamp=ts_iso,
                        message=cancel_msg,
                    ),
                    history=[cancel_msg],
                    artifacts=[],
                    metadata=meta_dict,
                )
                ev = threading.Event()
                ev.set()
                self._records[task_id] = _StoredTaskRecord(
                    task=task,
                    owner_sub=caller_sub,
                    lineage_path=norm_caller,
                    cancel_event=ev,
                    expires_at=now_ts + self.ttl_seconds,
                )
                return task.snapshot(), norm_caller

            if rec.owner_sub != caller_sub:
                raise A2AAccessDeniedError(
                    f"Principal {caller_sub!r} is forbidden from canceling task {task_id!r}"
                )
            if rec.lineage_path and norm_caller:
                if not _is_lineage_ancestor_prefix(norm_caller, rec.lineage_path):
                    raise A2AAccessDeniedError(
                        f"Caller branch {norm_caller!r} is not an upstream ancestor of "
                        f"task branch {rec.lineage_path!r}"
                    )
            cur_state = rec.task.status.state
            if cur_state == TaskState.CANCELED:
                if revocation_metadata:
                    rec.task.metadata["cascadingRevocation"] = dict(revocation_metadata)
                return rec.task.snapshot(), rec.lineage_path or norm_caller
            if cur_state in (TaskState.COMPLETED, TaskState.FAILED):
                # Allow staged multi-step workflow revocation if caller explicitly cancels staged root task
                if rec.task.metadata.get("stagedForSettlement"):
                    pass
                else:
                    raise A2AStateTransitionError(
                        f"Task {task_id!r} is already in terminal state {cur_state.value}"
                    )

            rec.cancel_event.set()
            cancel_msg = Message.create_agent(
                text=f"Task {task_id} canceled with cascading lineage revocation.",
                context_id=rec.task.context_id,
                task_id=task_id,
            )
            rec.task.history.append(cancel_msg)
            rec.task.status = TaskStatus(
                state=TaskState.CANCELED,
                timestamp=ts_iso,
                message=cancel_msg,
            )
            rec.task.metadata.setdefault("stateTransitionHistory", []).append(
                {"state": TaskState.CANCELED.value, "timestamp": ts_iso}
            )
            if revocation_metadata:
                rec.task.metadata["cascadingRevocation"] = dict(revocation_metadata)
            return rec.task.snapshot(), rec.lineage_path or norm_caller
