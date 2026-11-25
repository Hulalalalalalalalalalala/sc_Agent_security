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
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, Union

from lineage.identity.spiffe import WorkloadIdentity
from lineage.protocol.token import (
    CoAuthorizedToken,
    LineageToken,
    MultiParentToken,
    TokenError,
)
from lineage.verifier.policy_verifier import VerificationResult

TokenUnion = Union[LineageToken, MultiParentToken, CoAuthorizedToken]


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

            candidate_all = list(bucket_chains) + list(incoming)
            from lineage.protocol.token import are_roots_continuously_linked

            if not are_roots_continuously_linked(candidate_all):
                self._buckets[key] = (bucket_chains, p_map, ts + self.ttl_seconds)
                raise TokenError(
                    "Cross-root splicing rejected in MultiParentConvergenceInbox"
                )
            existing_hashes = {c.leaf_block_hash for c in bucket_chains}

            for ch in incoming:
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

        # Prefer unexpired chains PLUS any pre-checkpoint chains explicitly re-anchored by a live continuation chain!
        live_chains = [
            ch
            for ch in chains
            if (ch.hops[-1].exp if ch.hops else ch.root.exp) > ts - 5.0
        ]
        if live_chains:
            prior_by_hash = {
                ch.root_block_hash: ch.root.prior_root_block_hash for ch in chains
            }
            re_anchored_roots: Set[str] = set()
            frontier = [
                ch.root.prior_root_block_hash
                for ch in live_chains
                if ch.root.prior_root_block_hash is not None
            ]
            while frontier:
                pr = frontier.pop()
                if pr and pr not in re_anchored_roots:
                    re_anchored_roots.add(pr)
                    nxt_pr = prior_by_hash.get(pr)
                    if nxt_pr:
                        frontier.append(nxt_pr)
            live_hashes = {ch.leaf_block_hash for ch in live_chains}
            selected = [
                ch
                for ch in chains
                if ch.leaf_block_hash in live_hashes
                or ch.root_block_hash in re_anchored_roots
            ]
        else:
            selected = chains

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


@dataclass(frozen=True)
class OAuthRequestContext:
    """Active request context for an inbound RFC 8693 OAuth 2.0 Bearer JWT request."""

    request_id: str
    delegation_mode: str  # 'oauth_centralized' | 'oauth_federated'
    task_id: str
    sub: str
    access_token: str
    issuer: str
    scopes: Tuple[str, ...]
    azp: str
    act: Optional[Dict[str, Any]]
    jti: str


class OAuthActiveRequestStore:
    """Thread-safe active request registry for OAuth 2.0 delegation mode."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: Dict[str, OAuthRequestContext] = {}

    def register(
        self,
        *,
        delegation_mode: str,
        task_id: str,
        sub: str,
        access_token: str,
        issuer: str,
        scopes: Tuple[str, ...],
        azp: str,
        act: Optional[Dict[str, Any]],
        jti: str,
    ) -> OAuthRequestContext:
        req_id = f"req-oauth-{uuid.uuid4().hex}"
        ctx = OAuthRequestContext(
            request_id=req_id,
            delegation_mode=delegation_mode,
            task_id=task_id,
            sub=sub,
            access_token=access_token,
            issuer=issuer,
            scopes=scopes,
            azp=azp,
            act=act,
            jti=jti,
        )
        with self._lock:
            self._active[req_id] = ctx
        return ctx

    def get(self, request_id: str) -> Optional[OAuthRequestContext]:
        with self._lock:
            return self._active.get(request_id)

    def release(self, request_id: str) -> None:
        with self._lock:
            self._active.pop(request_id, None)


class OAuthConvergenceInbox:
    """Bounded N-to-1 collector for linear RFC 8693 OAuth branches (no DAG meet/Fagin pruning)."""

    def __init__(self, ttl_seconds: float = 1800.0, max_tasks: int = 2000) -> None:
        self.ttl_seconds = float(ttl_seconds)
        self.max_tasks = int(max_tasks)
        self._lock = threading.Lock()
        # (task_id, sub) -> (list of (mode, access_token, branch_key), payloads_dict, expires_at)
        self._buckets: "OrderedDict[Tuple[str, str], Tuple[List[Tuple[str, str, str]], Dict[str, dict], float]]" = (
            OrderedDict()
        )

    def _evict_locked(self, now_ts: float) -> None:
        while self._buckets:
            _, (_, _, exp_at) = next(iter(self._buckets.items()))
            if exp_at <= now_ts:
                self._buckets.popitem(last=False)
            else:
                break

    def add_branch(
        self,
        *,
        task_id: str,
        sub: str,
        delegation_mode: str,
        access_token: str,
        branch_key: str,
        branch_payload: Optional[dict] = None,
    ) -> int:
        now_ts = time.time()
        key = (task_id, sub)
        with self._lock:
            self._evict_locked(now_ts)
            if key in self._buckets:
                tokens, payloads, _ = self._buckets.pop(key)
            else:
                if len(self._buckets) >= self.max_tasks:
                    self._buckets.popitem(last=False)
                tokens = []
                payloads = {}
            tokens.append((delegation_mode, access_token, branch_key))
            if branch_payload is not None:
                payloads[branch_key] = dict(branch_payload)
            self._buckets[key] = (tokens, payloads, now_ts + self.ttl_seconds)
            return len(tokens)

    def get_latest_token_and_payloads(
        self, task_id: str, sub: str
    ) -> Optional[Tuple[str, str, Dict[str, dict]]]:
        now_ts = time.time()
        with self._lock:
            self._evict_locked(now_ts)
            entry = self._buckets.get((task_id, sub))
            if entry is None or not entry[0]:
                return None
            mode, latest_tok, _ = entry[0][-1]
            return mode, latest_tok, dict(entry[1])

    def peek_branch_payloads(self, task_id: str, sub: str) -> Dict[str, dict]:
        now_ts = time.time()
        with self._lock:
            self._evict_locked(now_ts)
            entry = self._buckets.get((task_id, sub))
            return dict(entry[1]) if entry is not None else {}
