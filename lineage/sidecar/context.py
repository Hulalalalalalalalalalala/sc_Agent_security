"""Concurrency-Safe Request Context & Bounded Multi-Parent DAG Convergence Isolation.

Eliminates all global mutable token state:
1. `ContextVar` (`_CURRENT_CTX`) isolates synchronous/async in-process execution frames.
2. `ActiveRequestStore` maps per-request UUID `request_id` -> `RequestLineageContext`
   while an HTTP call is active between `LineageSidecar` and its local business server,
   purging immediately upon request completion.
3. `MultiParentConvergenceInbox` isolates converging N-to-1 parent branches strictly
   by `(task_id, sub)` with recipient-holder & single-root verification plus bounded
   TTL/LRU eviction.
"""

from __future__ import annotations

import contextlib
import contextvars
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple, Union

from lineage.identity.spiffe import WorkloadIdentity
from lineage.protocol.token import LineageToken, MultiParentToken, TokenError
from lineage.verifier.policy_verifier import VerificationResult

TokenUnion = Union[LineageToken, MultiParentToken]


@dataclass(frozen=True)
class RequestLineageContext:
    """Immutable verified authorization context bound to a single in-flight HTTP request."""

    request_id: str
    task_id: str
    sub: str
    compact_token: str
    parsed_token: TokenUnion
    verification: VerificationResult


_CURRENT_CTX: contextvars.ContextVar[Optional[RequestLineageContext]] = (
    contextvars.ContextVar("lct_current_request_context", default=None)
)


def get_current_lineage_context() -> Optional[RequestLineageContext]:
    return _CURRENT_CTX.get()


@contextlib.contextmanager
def lineage_context_scope(
    ctx: RequestLineageContext,
) -> Iterator[RequestLineageContext]:
    token = _CURRENT_CTX.set(ctx)
    try:
        yield ctx
    finally:
        _CURRENT_CTX.reset(token)


class ActiveRequestStore:
    """Thread-safe registry of currently active inbound requests scoped by `request_id`."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: Dict[str, RequestLineageContext] = {}

    def register(
        self,
        compact_token: str,
        parsed_token: TokenUnion,
        verification: VerificationResult,
    ) -> RequestLineageContext:
        req_id = f"req-{uuid.uuid4().hex}"
        ctx = RequestLineageContext(
            request_id=req_id,
            task_id=parsed_token.task_id,
            sub=parsed_token.sub,
            compact_token=compact_token,
            parsed_token=parsed_token,
            verification=verification,
        )
        with self._lock:
            self._active[req_id] = ctx
        return ctx

    def get(self, request_id: str) -> Optional[RequestLineageContext]:
        with self._lock:
            return self._active.get(request_id)

    def release(self, request_id: str) -> None:
        with self._lock:
            self._active.pop(request_id, None)

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._active)


class MultiParentConvergenceInbox:
    """Thread-safe bounded N-to-1 DAG branch collector isolated per `(task_id, sub)`."""

    def __init__(self, ttl_seconds: float = 1800.0, max_tasks: int = 10_000) -> None:
        self.ttl_seconds = float(ttl_seconds)
        self.max_tasks = int(max_tasks)
        self._lock = threading.Lock()
        # (task_id, sub) -> (chains_list, branch_payloads_dict, expires_at)
        self._buckets: "OrderedDict[Tuple[str, str], Tuple[List[LineageToken], Dict[str, dict], float]]" = (
            OrderedDict()
        )

    def _evict_expired_locked(self, now_ts: float) -> None:
        while self._buckets:
            _, (_, _, exp_at) = next(iter(self._buckets.items()))
            if exp_at <= now_ts:
                self._buckets.popitem(last=False)
            else:
                break

    def add_verified_branch(
        self,
        token: TokenUnion,
        branch_payload: Optional[dict] = None,
        expected_holder_spiffe_id: Optional[str] = None,
        expected_holder_jkt: Optional[str] = None,
        now: Optional[float] = None,
    ) -> int:
        """Record verified incoming chains strictly delegated to `expected_holder_spiffe_id`."""
        incoming = (
            [token]
            if isinstance(token, LineageToken)
            else list(token.parent_chains)
        )
        if not incoming:
            raise TokenError("Empty incoming branch set")

        for ch in incoming:
            if (
                expected_holder_spiffe_id is not None
                and ch.holder_spiffe_id != expected_holder_spiffe_id
            ):
                raise TokenError(
                    f"Convergence branch holder {ch.holder_spiffe_id!r} != expected recipient {expected_holder_spiffe_id!r}"
                )
            if (
                expected_holder_jkt is not None
                and ch.holder_cnf_jkt != expected_holder_jkt
            ):
                raise TokenError(
                    "Convergence branch holder_cnf_jkt does not match recipient jkt"
                )

        ts = time.time() if now is None else float(now)
        key = (token.task_id, token.sub)

        with self._lock:
            self._evict_expired_locked(ts)
            if key in self._buckets:
                bucket_chains, p_map, _ = self._buckets.pop(key)
            else:
                if len(self._buckets) >= self.max_tasks:
                    self._buckets.popitem(last=False)
                bucket_chains = []
                p_map = {}

            expected_root = (
                bucket_chains[0].root_block_hash
                if bucket_chains
                else incoming[0].root_block_hash
            )
            existing_hashes = {c.leaf_block_hash for c in bucket_chains}

            for ch in incoming:
                if ch.root_block_hash != expected_root:
                    # Restore unmodified bucket before raising
                    self._buckets[key] = (bucket_chains, p_map, ts + self.ttl_seconds)
                    raise TokenError(
                        "Cross-root splicing rejected in MultiParentConvergenceInbox"
                    )
                if ch.leaf_block_hash not in existing_hashes:
                    bucket_chains.append(ch)
                    existing_hashes.add(ch.leaf_block_hash)
                if branch_payload is not None:
                    p_map[ch.lineage_path] = dict(branch_payload)

            self._buckets[key] = (bucket_chains, p_map, ts + self.ttl_seconds)
            return len(bucket_chains)

    def assemble_multiparent_token(
        self,
        holder_identity: WorkloadIdentity,
        task_id: str,
        sub: str,
        now: Optional[float] = None,
    ) -> Tuple[MultiParentToken, Dict[str, dict]]:
        """Assemble a signed `MultiParentToken` from unexpired branches of `(task_id, sub)`."""
        ts = time.time() if now is None else float(now)
        key = (task_id, sub)
        with self._lock:
            self._evict_expired_locked(ts)
            entry = self._buckets.get(key)
            if entry is None:
                raise KeyError(
                    f"No converged parent chains found for task_id={task_id!r}, sub={sub!r}"
                )
            chains = list(entry[0])
            payloads = dict(entry[1])

        if not chains:
            raise KeyError(
                f"No converged parent chains found for task_id={task_id!r}, sub={sub!r}"
            )

        # Prefer unexpired chains if any remain; if all expired, retain so verifier emits exact expiry code
        live_chains = [
            ch
            for ch in chains
            if (ch.hops[-1].exp if ch.hops else ch.root.exp) > ts - 5.0
        ]
        selected = live_chains if live_chains else chains

        mpt = MultiParentToken.assemble_and_sign(
            holder_identity=holder_identity,
            parent_chains=selected,
            now=ts,
        )
        return mpt, payloads

    def peek_branch_payloads(
        self, task_id: str, sub: str, now: Optional[float] = None
    ) -> Dict[str, dict]:
        ts = time.time() if now is None else float(now)
        with self._lock:
            self._evict_expired_locked(ts)
            entry = self._buckets.get((task_id, sub))
            return dict(entry[1]) if entry is not None else {}
