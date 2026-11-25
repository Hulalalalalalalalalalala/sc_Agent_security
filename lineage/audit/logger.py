"""Hash-Chained & Cryptographically Signed Structured Audit Logger & Verified HTTP Collector."""

from __future__ import annotations

import enum
import ssl
import threading
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

import httpx

from lineage.common.crypto import (
    CryptoError,
    jws_parse_unverified,
    jws_sign_compact,
    jws_verify_compact,
    redact_sensitive,
    require_finite_timestamp,
    sha256_canonical_b64url,
)
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.identity.spiffe import (
    IdentityError,
    SpiffeId,
    TrustDomainCA,
    WorkloadIdentity,
)
from lineage.identity.trust_bundle import TrustBundleResolver

_DEFAULT_AUTHORIZED_AUDITOR_PATHS: FrozenSet[str] = frozenset(
    {
        "/ns/sys/sa/audit-collector",
        "/ns/sys/sa/auditor",
        "/ns/entry/sa/test-driver",
        "/ns/lineage-alpha/sa/e2e-user-gateway",
    }
)


class AuditEventType(str, enum.Enum):
    ROOT_MINT = "ROOT_MINT"
    OUTBOUND_DELEGATE = "OUTBOUND_DELEGATE"
    INBOUND_AUTHZ = "INBOUND_AUTHZ"
    TOOL_INVOCATION = "TOOL_INVOCATION"
    REVOCATION_ISSUED = "REVOCATION_ISSUED"
    FAILOVER_PRUNE_GRAFT = "FAILOVER_PRUNE_GRAFT"
    SKIP_LEVEL_RETURN = "SKIP_LEVEL_RETURN"
    SKIP_LEVEL_ACCEPT = "SKIP_LEVEL_ACCEPT"
    AUTHZ_DENIED = "AUTHZ_DENIED"


class AuditIngestError(ValueError):
    """Raised when an incoming AuditEntry fails signature, hash, or sequence verification."""


@dataclass(frozen=True)
class AuditEntry:
    """Single immutable, forward-hash-chained, workload-signed audit log record."""

    stream_id: str
    stream_seq: int
    timestamp: float
    event_type: AuditEventType
    task_id: str
    sub: str
    node_spiffe_id: str
    auth_mode: str  # "workload" | "domain_authority"
    node_svid_or_domain: str
    lineage_path: str
    hop_index: int
    epoch: int
    root_block_hash: str
    parent_block_hash: Optional[str]
    current_block_hash: str
    multi_parent_hashes: Tuple[str, ...]
    dpop_jti: Optional[str]
    permissions_summary: Optional[Dict[str, Any]]
    action_detail: Dict[str, Any]
    decision: str
    receipt_payload: Optional[Dict[str, Any]]
    prev_entry_hash: str
    entry_hash: str
    node_signature: str

    def hashable_body(self) -> Dict[str, Any]:
        """Canonical fields committed by `entry_hash` (chained via `prev_entry_hash`)."""
        return {
            "stream_id": self.stream_id,
            "stream_seq": self.stream_seq,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "task_id": self.task_id,
            "sub": self.sub,
            "node_spiffe_id": self.node_spiffe_id,
            "auth_mode": self.auth_mode,
            "lineage_path": self.lineage_path,
            "hop_index": self.hop_index,
            "epoch": self.epoch,
            "root_block_hash": self.root_block_hash,
            "parent_block_hash": self.parent_block_hash,
            "current_block_hash": self.current_block_hash,
            "multi_parent_hashes": list(self.multi_parent_hashes),
            "dpop_jti": self.dpop_jti,
            "permissions_summary": self.permissions_summary,
            "action_detail": self.action_detail,
            "decision": self.decision,
            "receipt_payload": self.receipt_payload,
            "prev_entry_hash": self.prev_entry_hash,
        }

    def compute_expected_hash(self) -> str:
        return sha256_canonical_b64url(self.hashable_body())

    def to_dict(self) -> Dict[str, Any]:
        d = self.hashable_body()
        d["node_svid_or_domain"] = self.node_svid_or_domain
        d["entry_hash"] = self.entry_hash
        d["node_signature"] = self.node_signature
        return d

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "AuditEntry":
        try:
            ts = require_finite_timestamp(raw["timestamp"], "AuditEntry.timestamp")
        except CryptoError as exc:
            raise ValueError(str(exc)) from exc
        return cls(
            stream_id=str(raw["stream_id"]),
            stream_seq=int(raw["stream_seq"]),
            timestamp=ts,
            event_type=AuditEventType(str(raw["event_type"])),
            task_id=str(raw["task_id"]),
            sub=str(raw["sub"]),
            node_spiffe_id=str(raw["node_spiffe_id"]),
            auth_mode=str(raw["auth_mode"]),
            node_svid_or_domain=str(raw["node_svid_or_domain"]),
            lineage_path=str(raw["lineage_path"]),
            hop_index=int(raw["hop_index"]),
            epoch=int(raw["epoch"]),
            root_block_hash=str(raw["root_block_hash"]),
            parent_block_hash=str(raw["parent_block_hash"])
            if raw.get("parent_block_hash") is not None
            else None,
            current_block_hash=str(raw["current_block_hash"]),
            multi_parent_hashes=tuple(
                str(x) for x in (raw.get("multi_parent_hashes") or [])
            ),
            dpop_jti=str(raw["dpop_jti"])
            if raw.get("dpop_jti") is not None
            else None,
            permissions_summary=dict(raw["permissions_summary"])
            if isinstance(raw.get("permissions_summary"), Mapping)
            else None,
            action_detail=dict(raw.get("action_detail") or {}),
            decision=str(raw["decision"]),
            receipt_payload=dict(raw["receipt_payload"])
            if isinstance(raw.get("receipt_payload"), Mapping)
            else None,
            prev_entry_hash=str(raw["prev_entry_hash"]),
            entry_hash=str(raw["entry_hash"]),
            node_signature=str(raw["node_signature"]),
        )


class LocalAuditStore:
    """Bounded per-node signed audit log store supporting on-demand federated pull by `task_id`."""

    def __init__(
        self,
        max_entries: int = 50_000,
        max_streams: int = 10_000,
        authorized_auditors: Iterable[str] = (),
        allow_task_participant_query: bool = True,
    ) -> None:
        if max_entries <= 0 or max_streams <= 0:
            raise ValueError("max_entries and max_streams must be positive")
        self.max_entries = int(max_entries)
        self.max_streams = int(max_streams)
        self._authorized_auditors: FrozenSet[str] = frozenset(
            str(s) for s in authorized_auditors if str(s).strip()
        )
        self._allow_task_participant_query = bool(allow_task_participant_query)
        self._lock = threading.Lock()
        self._entries: Deque[AuditEntry] = deque()
        self._by_task: Dict[str, List[AuditEntry]] = {}
        self._stream_last_seq_hash: "OrderedDict[str, Tuple[int, str]]" = OrderedDict()
        self._query_replay_lock = threading.Lock()
        self._seen_query_jtis: "OrderedDict[str, float]" = OrderedDict()

    def record(self, entry: AuditEntry) -> None:
        with self._lock:
            prev_info = self._stream_last_seq_hash.get(entry.stream_id)
            if prev_info is not None:
                last_seq, last_hash = prev_info
                if entry.stream_seq != last_seq + 1 or entry.prev_entry_hash != last_hash:
                    raise AuditIngestError(
                        f"LocalAuditStore stream continuity broken on {entry.stream_id!r}: "
                        f"expected seq={last_seq + 1}/prev={last_hash!r}, got seq={entry.stream_seq}/prev={entry.prev_entry_hash!r}"
                    )
                self._stream_last_seq_hash.pop(entry.stream_id)
            else:
                if len(self._stream_last_seq_hash) >= self.max_streams:
                    self._stream_last_seq_hash.popitem(last=False)
            self._stream_last_seq_hash[entry.stream_id] = (entry.stream_seq, entry.entry_hash)

            while len(self._entries) >= self.max_entries:
                evicted = self._entries.popleft()
                t_list = self._by_task.get(evicted.task_id)
                if t_list:
                    try:
                        t_list.remove(evicted)
                    except ValueError:
                        pass
                    if not t_list:
                        self._by_task.pop(evicted.task_id, None)

            self._entries.append(entry)
            self._by_task.setdefault(entry.task_id, []).append(entry)

    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def size(self) -> int:
        return self.count()

    def get_all(self) -> List[AuditEntry]:
        with self._lock:
            return list(self._entries)

    def get_by_task(self, task_id: str) -> List[AuditEntry]:
        with self._lock:
            return list(self._by_task.get(str(task_id), ()))

    def _is_task_participant(self, task_id: str, caller_spiffe: str) -> bool:
        if not task_id or not caller_spiffe:
            return False
        with self._lock:
            entries = self._by_task.get(task_id, [])
            for item in entries:
                if item.node_spiffe_id == caller_spiffe:
                    return True
                ad = item.action_detail or {}
                for k in (
                    "delegate_spiffe_id",
                    "target_spiffe_id",
                    "peer_spiffe_id",
                    "first_hop_spiffe_id",
                    "initiator_spiffe_id",
                ):
                    if ad.get(k) == caller_spiffe:
                        return True
        return False

    def authorize_read_query(
        self,
        req: HTTPRequestContext,
        trust_resolver: TrustBundleResolver,
        require_task_id: bool = True,
    ) -> Tuple[str, str]:
        """Authenticate `GET /v1/audit/local?task_id=<id>` with anti-replay `lct-audit-query+jwt`."""
        mode = (req.header("X-LCT-Audit-Mode") or "").strip()
        auth_jws = (req.header("X-LCT-Audit-Auth") or "").strip()
        if not mode or not auth_jws:
            raise PermissionError(
                "GET /v1/audit/local requires signed X-LCT-Audit-Mode + X-LCT-Audit-Auth headers"
            )
        raw_q_task = req.query.get("task_id", "")
        if isinstance(raw_q_task, list):
            raw_q_task = raw_q_task[0] if raw_q_task else ""
        expected_task_filter = str(raw_q_task or "").strip()
        if require_task_id and not expected_task_filter:
            raise AuditIngestError("GET /v1/audit/local requires a non-empty task_id query parameter")

        now_ts = time.time()
        try:
            if mode == "domain_authority":
                domain = (req.header("X-LCT-Audit-Domain") or "").strip()
                if not domain:
                    raise AuditIngestError("Missing X-LCT-Audit-Domain header")
                _, claims = trust_resolver.verify_domain_jws(
                    auth_jws,
                    expected_trust_domain=domain,
                    expected_typ="lct-audit-query+jwt",
                )
                caller_id = f"domain:{domain}"
            elif mode == "workload":
                svid = (req.header("X-LCT-Audit-SVID") or "").strip()
                if not svid:
                    raise AuditIngestError("Missing X-LCT-Audit-SVID header")
                svid_claims = trust_resolver.verify_workload_svid(svid, now=now_ts)
                caller_spiffe = str(svid_claims["sub"])
                parsed = SpiffeId.parse(caller_spiffe)
                is_authorized = (
                    caller_spiffe in self._authorized_auditors
                    or parsed.path in _DEFAULT_AUTHORIZED_AUDITOR_PATHS
                    or parsed.path.startswith("/ns/audit/sa/")
                    or (
                        self._allow_task_participant_query
                        and bool(expected_task_filter)
                        and self._is_task_participant(expected_task_filter, caller_spiffe)
                    )
                )
                if not is_authorized:
                    raise AuditIngestError(
                        f"Workload {caller_spiffe!r} is not an authorized auditor or participant for task {expected_task_filter!r}"
                    )
                _, claims = jws_verify_compact(
                    auth_jws,
                    svid_claims["cnf"]["jwk"],
                    expected_typ="lct-audit-query+jwt",
                )
                caller_id = caller_spiffe
            else:
                raise AuditIngestError(f"Unsupported X-LCT-Audit-Mode: {mode!r}")
        except (IdentityError, CryptoError, KeyError, TypeError, ValueError) as exc:
            raise AuditIngestError(f"Local audit query authentication failed: {exc}") from exc

        iat = require_finite_timestamp(claims.get("iat"), "audit_query.iat")
        if abs(now_ts - iat) > 60.0:
            raise AuditIngestError("Audit query JWS iat outside 60s freshness window")
        jti = str(claims.get("jti") or "").strip()
        if not jti:
            raise AuditIngestError("Audit query JWS missing jti")
        if str(claims.get("task_id") or "") != expected_task_filter:
            raise AuditIngestError("Signed task_id filter mismatch with query string")

        replay_key = f"{caller_id}:{jti}"
        with self._query_replay_lock:
            while self._seen_query_jtis:
                _, exp_at = next(iter(self._seen_query_jtis.items()))
                if exp_at <= now_ts:
                    self._seen_query_jtis.popitem(last=False)
                else:
                    break
            if replay_key in self._seen_query_jtis:
                raise AuditIngestError("Replayed audit query jti rejected")
            if len(self._seen_query_jtis) >= 16_384:
                self._seen_query_jtis.popitem(last=False)
            self._seen_query_jtis[replay_key] = now_ts + 120.0

        return caller_id, expected_task_filter

    def serve_http_query(
        self,
        req: HTTPRequestContext,
        trust_resolver: TrustBundleResolver,
        node_spiffe_id: str = "",
        require_task_id: bool = True,
    ) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        try:
            _, task_filter = self.authorize_read_query(
                req, trust_resolver, require_task_id=require_task_id
            )
        except PermissionError as exc:
            return 401, {"error": "audit_auth_required", "detail": str(exc)}, {}
        except (AuditIngestError, ValueError) as exc:
            return 403, {"error": "unauthorized_auditor_principal", "detail": str(exc)}, {}

        items = self.get_by_task(task_filter) if task_filter else self.get_all()
        return (
            200,
            {
                "node_spiffe_id": node_spiffe_id,
                "task_id": task_filter,
                "count": len(items),
                "entries": [e.to_dict() for e in items],
            },
            {},
        )


def build_audit_query_headers(
    signer: WorkloadIdentity | TrustDomainCA,
    task_id: Optional[str] = None,
) -> Dict[str, str]:
    """Mint a fresh anti-replay `lct-audit-query+jwt` header set for audit pull requests."""
    query_claims = {
        "jti": f"audq-{uuid.uuid4().hex}",
        "iat": time.time(),
        "task_id": task_id or "",
    }
    if isinstance(signer, TrustDomainCA):
        q_jws = jws_sign_compact(
            payload=query_claims,
            keypair=signer.active_keypair,
            typ="lct-audit-query+jwt",
        )
        return {
            "X-LCT-Audit-Mode": "domain_authority",
            "X-LCT-Audit-Domain": signer.trust_domain,
            "X-LCT-Audit-Auth": q_jws,
        }
    q_jws = jws_sign_compact(
        payload=query_claims,
        keypair=signer.keypair,
        typ="lct-audit-query+jwt",
    )
    return {
        "X-LCT-Audit-Mode": "workload",
        "X-LCT-Audit-SVID": signer.workload_svid,
        "X-LCT-Audit-Auth": q_jws,
    }


class AuditStreamEmitter:
    """Per-node thread-safe hash-chained audit emitter with automatic secret redaction."""

    def __init__(
        self,
        signer: WorkloadIdentity | TrustDomainCA,
        collector_client: Optional["AuditCollectorClient"] = None,
        stream_id: Optional[str] = None,
        best_effort_remote: bool = False,
        max_pending_remote: int = 4096,
        local_store: Optional[LocalAuditStore] = None,
        authorized_auditors: Iterable[str] = (),
    ) -> None:
        self._signer = signer
        self._collector = collector_client
        self._best_effort_remote = bool(best_effort_remote)
        self.local_store: LocalAuditStore = (
            local_store
            if local_store is not None
            else LocalAuditStore(authorized_auditors=authorized_auditors)
        )
        if isinstance(signer, TrustDomainCA):
            self.node_spiffe_id = signer.root_authority_spiffe_id
            self.auth_mode = "domain_authority"
            self.node_svid_or_domain = signer.trust_domain
            self._keypair = signer.active_keypair
        else:
            self.node_spiffe_id = signer.spiffe_id
            self.auth_mode = "workload"
            self.node_svid_or_domain = signer.workload_svid
            self._keypair = signer.keypair

        self.stream_id = stream_id or self.node_spiffe_id
        self._lock = threading.Lock()
        self._ship_lock = threading.Lock()
        self._pending_remote: Deque[AuditEntry] = deque(maxlen=max(64, int(max_pending_remote)))
        self._flush_stop = threading.Event()
        self._flush_thread: Optional[threading.Thread] = None
        self._seq: int = 0
        self._prev_hash: str = "GENESIS"
        self._local_entries: List[AuditEntry] = []
        if self._best_effort_remote and self._collector is not None:
            self._start_background_flusher()

    def _start_background_flusher(self) -> None:
        def _loop() -> None:
            while not self._flush_stop.is_set():
                try:
                    self.flush_pending()
                except Exception:
                    pass
                self._flush_stop.wait(1.0)

        self._flush_thread = threading.Thread(
            target=_loop, name=f"audit-flush-{self.stream_id[-24:]}", daemon=True
        )
        self._flush_thread.start()

    def flush_pending(self) -> int:
        """Drain buffered entries to remote `AuditCollectorService` in strict `stream_seq` order."""
        if self._collector is None:
            return 0
        flushed = 0
        with self._ship_lock:
            while True:
                with self._lock:
                    if not self._pending_remote:
                        break
                    head = self._pending_remote[0]
                try:
                    self._collector.ship(head)
                except AuditIngestError:
                    # If collector already recorded this seq (`Duplicate or replayed`), pop & advance
                    with self._lock:
                        if self._pending_remote and self._pending_remote[0] is head:
                            self._pending_remote.popleft()
                    continue
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 403 and "Duplicate or replayed" in exc.response.text:
                        with self._lock:
                            if self._pending_remote and self._pending_remote[0] is head:
                                self._pending_remote.popleft()
                        continue
                    break
                except Exception:
                    break
                with self._lock:
                    if self._pending_remote and self._pending_remote[0] is head:
                        self._pending_remote.popleft()
                flushed += 1
        return flushed

    def stop(self) -> None:
        self._flush_stop.set()
        if self._flush_thread is not None:
            self._flush_thread.join(timeout=1.5)
            self._flush_thread = None
        try:
            self.flush_pending()
        except Exception:
            pass

    def emit(
        self,
        event_type: AuditEventType,
        task_id: str,
        sub: str,
        lineage_path: str,
        hop_index: int,
        epoch: int,
        root_block_hash: str,
        current_block_hash: str,
        decision: str,
        parent_block_hash: Optional[str] = None,
        multi_parent_hashes: Iterable[str] = (),
        dpop_jti: Optional[str] = None,
        permissions_summary: Optional[Mapping[str, Any]] = None,
        action_detail: Optional[Mapping[str, Any]] = None,
        receipt_payload: Optional[Mapping[str, Any]] = None,
        timestamp: Optional[float] = None,
    ) -> AuditEntry:
        """Append a forward-hash-chained, workload-signed entry (redacting any secrets)."""
        ts = require_finite_timestamp(
            time.time() if timestamp is None else timestamp, "timestamp"
        )
        clean_action = redact_sensitive(dict(action_detail or {}))
        clean_perms = (
            redact_sensitive(dict(permissions_summary))
            if permissions_summary is not None
            else None
        )
        receipt_dict = dict(receipt_payload) if receipt_payload is not None else None

        with self._lock:
            # Dynamically read live SVID & keypair on every emission so SVID/key renewal
            # takes effect immediately without stale SVID expiration errors!
            if isinstance(self._signer, TrustDomainCA):
                live_svid_or_domain = self._signer.trust_domain
                live_keypair = self._signer.active_keypair
            else:
                live_svid_or_domain = self._signer.workload_svid
                live_keypair = self._signer.keypair
            self.node_svid_or_domain = live_svid_or_domain
            self._keypair = live_keypair

            seq = self._seq
            prev_h = self._prev_hash

            provisional = AuditEntry(
                stream_id=self.stream_id,
                stream_seq=seq,
                timestamp=ts,
                event_type=AuditEventType(event_type),
                task_id=task_id,
                sub=sub,
                node_spiffe_id=self.node_spiffe_id,
                auth_mode=self.auth_mode,
                node_svid_or_domain=live_svid_or_domain,
                lineage_path=lineage_path,
                hop_index=int(hop_index),
                epoch=int(epoch),
                root_block_hash=root_block_hash,
                parent_block_hash=parent_block_hash,
                current_block_hash=current_block_hash,
                multi_parent_hashes=tuple(multi_parent_hashes),
                dpop_jti=dpop_jti,
                permissions_summary=clean_perms,
                action_detail=clean_action,
                decision=decision,
                receipt_payload=receipt_dict,
                prev_entry_hash=prev_h,
                entry_hash="",
                node_signature="",
            )
            entry_h = provisional.compute_expected_hash()
            sig = jws_sign_compact(
                payload={
                    "stream_id": self.stream_id,
                    "stream_seq": seq,
                    "entry_hash": entry_h,
                },
                keypair=live_keypair,
                typ="lct-audit-sig+jwt",
            )
            final_entry = AuditEntry(
                **{
                    **provisional.__dict__,
                    "entry_hash": entry_h,
                    "node_signature": sig,
                }
            )
            self._seq += 1
            self._prev_hash = entry_h
            self.local_store.record(final_entry)
            self._local_entries = self.local_store.get_all()
            if self._collector is not None and self._best_effort_remote:
                self._pending_remote.append(final_entry)

        if self._collector is not None:
            if self._best_effort_remote:
                self.flush_pending()
            else:
                self._collector.ship(final_entry)

        return final_entry

    def local_entries(self) -> List[AuditEntry]:
        return self.local_store.get_all()


class AuditCollectorService:
    """HTTP Audit Log Collector with Mandatory TrustBundle-Backed Ingest Signature Verification."""

    def __init__(
        self,
        trust_resolver: TrustBundleResolver,
        host: str = "127.0.0.1",
        port: int = 0,
        authorized_auditors: Iterable[str] = (),
        ssl_context: Optional[ssl.SSLContext] = None,
        ssl_context_provider: Optional[Callable[[], ssl.SSLContext]] = None,
        public_bundle_provider: Optional[Callable[[], Dict[str, Any]]] = None,
        descriptors_provider: Optional[Callable[[], Dict[str, Any]]] = None,
        readiness_check: Optional[Callable[[], Tuple[bool, Dict[str, Any]]]] = None,
        max_ingest_age_seconds: float = 3600.0,
        max_future_skew_seconds: float = 30.0,
        stream_timestamp_tolerance_seconds: float = 5.0,
        max_entries: int = 100_000,
        max_streams: int = 10_000,
    ) -> None:
        if not isinstance(trust_resolver, TrustBundleResolver):
            raise TypeError(
                "AuditCollectorService requires a TrustBundleResolver (unauthenticated ingest mode is forbidden)"
            )
        if max_ingest_age_seconds <= 0 or max_future_skew_seconds < 0:
            raise ValueError("max_ingest_age_seconds must be > 0 and max_future_skew_seconds >= 0")
        if max_entries <= 0 or max_streams <= 0:
            raise ValueError("max_entries and max_streams must be positive")
        self.trust_resolver = trust_resolver
        self._authorized_auditors: FrozenSet[str] = frozenset(str(s) for s in authorized_auditors if s)
        self._public_bundle_provider = public_bundle_provider
        self._descriptors_provider = descriptors_provider
        self._readiness_check = readiness_check
        self.max_ingest_age_seconds = float(max_ingest_age_seconds)
        self.max_future_skew_seconds = float(max_future_skew_seconds)
        self.stream_timestamp_tolerance_seconds = float(stream_timestamp_tolerance_seconds)
        self.max_entries = int(max_entries)
        self.max_streams = int(max_streams)
        self._lock = threading.Lock()
        self._entries: List[Dict[str, Any]] = []
        # Anti-replay / anti-overwrite index `(stream_id, stream_seq) -> entry_hash`
        self._seen_stream_seqs: Dict[Tuple[str, int], str] = {}
        self._stream_seq_timestamps: Dict[str, Dict[int, float]] = {}
        self._query_replay_lock = threading.Lock()
        self._seen_query_jtis: "OrderedDict[str, float]" = OrderedDict()
        self._http = ManagedHTTPService(
            service_name="audit-collector",
            dispatcher=self._dispatch,
            host=host,
            port=port,
            ssl_context=ssl_context,
            ssl_context_provider=ssl_context_provider,
        )

    def start(self) -> str:
        return self._http.start()

    def stop(self) -> None:
        self._http.stop()

    @property
    def base_url(self) -> str:
        return self._http.base_url

    @property
    def port(self) -> int:
        return self._http.port

    def _verify_entry_on_ingest(
        self, entry: AuditEntry, now: Optional[float] = None
    ) -> None:
        """Verify timestamp bounds, entry_hash, CA/TrustBundle signature, and stream claims."""
        now_ts = time.time() if now is None else float(now)
        try:
            entry_ts = require_finite_timestamp(entry.timestamp, "entry.timestamp")
        except (CryptoError, ValueError, TypeError) as exc:
            raise AuditIngestError(f"Invalid AuditEntry timestamp: {exc}") from exc

        if entry_ts > (now_ts + self.max_future_skew_seconds):
            raise AuditIngestError(
                f"AuditEntry timestamp {entry_ts:.3f} exceeds max future skew "
                f"({self.max_future_skew_seconds}s ahead of {now_ts:.3f})"
            )
        if entry_ts < (now_ts - self.max_ingest_age_seconds):
            raise AuditIngestError(
                f"AuditEntry timestamp {entry_ts:.3f} is older than max_ingest_age_seconds "
                f"({self.max_ingest_age_seconds}s before {now_ts:.3f})"
            )

        expected_hash = entry.compute_expected_hash()
        if entry.entry_hash != expected_hash:
            raise AuditIngestError("AuditEntry entry_hash mismatch")

        try:
            if entry.auth_mode == "domain_authority":
                _, signed_payload = self.trust_resolver.verify_domain_jws(
                    entry.node_signature,
                    expected_trust_domain=entry.node_svid_or_domain,
                    expected_typ="lct-audit-sig+jwt",
                )
            elif entry.auth_mode == "workload":
                svid_claims = self.trust_resolver.verify_workload_svid(
                    entry.node_svid_or_domain,
                    expected_spiffe_id=entry.node_spiffe_id,
                    now=entry.timestamp,
                )
                _, signed_payload = jws_verify_compact(
                    entry.node_signature,
                    svid_claims["cnf"]["jwk"],
                    expected_typ="lct-audit-sig+jwt",
                )
            else:
                raise AuditIngestError(f"Unknown auth_mode: {entry.auth_mode!r}")
        except (IdentityError, CryptoError, KeyError, TypeError) as exc:
            raise AuditIngestError(
                f"AuditEntry cryptographic verification failed: {exc}"
            ) from exc

        if (
            signed_payload.get("stream_id") != entry.stream_id
            or signed_payload.get("stream_seq") != entry.stream_seq
            or signed_payload.get("entry_hash") != entry.entry_hash
        ):
            raise AuditIngestError("Signed audit claims mismatch with entry fields")

    def append_direct(self, entry: AuditEntry) -> int:
        self._verify_entry_on_ingest(entry)
        if entry.stream_seq < 0:
            raise AuditIngestError("Negative stream_seq rejected")
        if entry.stream_seq == 0 and entry.prev_entry_hash != "GENESIS":
            raise AuditIngestError("stream_seq=0 must have prev_entry_hash='GENESIS'")
        if entry.stream_seq > 0 and entry.prev_entry_hash == "GENESIS":
            raise AuditIngestError("stream_seq>0 cannot have prev_entry_hash='GENESIS'")

        with self._lock:
            if len(self._entries) >= self.max_entries:
                raise AuditIngestError(
                    f"AuditCollectorService entry capacity limit reached ({self.max_entries})"
                )
            stream_ts_map = self._stream_seq_timestamps.get(entry.stream_id)
            if stream_ts_map is None and len(self._stream_seq_timestamps) >= self.max_streams:
                raise AuditIngestError(
                    f"AuditCollectorService stream capacity limit reached ({self.max_streams})"
                )
            seq_key = (entry.stream_id, entry.stream_seq)
            if seq_key in self._seen_stream_seqs:
                raise AuditIngestError(
                    f"Duplicate or replayed (stream_id, stream_seq)={seq_key!r} rejected"
                )
            prev_key = (entry.stream_id, entry.stream_seq - 1)
            if prev_key in self._seen_stream_seqs:
                if self._seen_stream_seqs[prev_key] != entry.prev_entry_hash:
                    raise AuditIngestError("prev_entry_hash conflicts with prior entry")
            next_key = (entry.stream_id, entry.stream_seq + 1)
            if next_key in self._seen_stream_seqs:
                # Out-of-order TCP packet arrived after seq+1; CausalChainAuditor verifies full chain
                pass

            if stream_ts_map:
                tol = self.stream_timestamp_tolerance_seconds
                for existing_seq, existing_ts in stream_ts_map.items():
                    if existing_seq < entry.stream_seq and entry.timestamp < (existing_ts - tol):
                        raise AuditIngestError(
                            f"Non-monotonic AuditEntry timestamp on stream {entry.stream_id!r}: "
                            f"seq={entry.stream_seq} ts={entry.timestamp:.3f} < prior seq={existing_seq} ts={existing_ts:.3f} - {tol}s"
                        )
                    if existing_seq > entry.stream_seq and entry.timestamp > (existing_ts + tol):
                        raise AuditIngestError(
                            f"Non-monotonic AuditEntry timestamp on stream {entry.stream_id!r}: "
                            f"seq={entry.stream_seq} ts={entry.timestamp:.3f} > later seq={existing_seq} ts={existing_ts:.3f} + {tol}s"
                        )

            if stream_ts_map is None:
                stream_ts_map = {}
                self._stream_seq_timestamps[entry.stream_id] = stream_ts_map
            stream_ts_map[entry.stream_seq] = float(entry.timestamp)
            self._seen_stream_seqs[seq_key] = entry.entry_hash
            self._entries.append(entry.to_dict())
            return len(self._entries)

    def get_all_entries(self) -> List[AuditEntry]:
        with self._lock:
            return [AuditEntry.from_dict(e) for e in self._entries]

    def _authorize_read_query(self, req: HTTPRequestContext) -> str:
        """Verify caller SVID/domain JWS signature, anti-replay `jti`, and auditor role."""
        mode = (req.header("X-LCT-Audit-Mode") or "").strip()
        auth_jws = (req.header("X-LCT-Audit-Auth") or "").strip()
        if not mode or not auth_jws:
            raise PermissionError(
                "GET /v1/audit/entries requires signed X-LCT-Audit-Mode + X-LCT-Audit-Auth headers"
            )

        now_ts = time.time()
        try:
            if mode == "domain_authority":
                domain = (req.header("X-LCT-Audit-Domain") or "").strip()
                if not domain:
                    raise AuditIngestError("Missing X-LCT-Audit-Domain header")
                _, claims = self.trust_resolver.verify_domain_jws(
                    auth_jws,
                    expected_trust_domain=domain,
                    expected_typ="lct-audit-query+jwt",
                )
                caller_id = f"domain:{domain}"
            elif mode == "workload":
                svid = (req.header("X-LCT-Audit-SVID") or "").strip()
                if not svid:
                    raise AuditIngestError("Missing X-LCT-Audit-SVID header")
                svid_claims = self.trust_resolver.verify_workload_svid(svid, now=now_ts)
                caller_spiffe = str(svid_claims["sub"])
                parsed = SpiffeId.parse(caller_spiffe)
                is_authorized = (
                    caller_spiffe in self._authorized_auditors
                    or parsed.path in _DEFAULT_AUTHORIZED_AUDITOR_PATHS
                    or parsed.path.startswith("/ns/audit/sa/")
                )
                if not is_authorized:
                    raise AuditIngestError(
                        f"Workload {caller_spiffe!r} is not an authorized cross-tenant auditor"
                    )
                _, claims = jws_verify_compact(
                    auth_jws,
                    svid_claims["cnf"]["jwk"],
                    expected_typ="lct-audit-query+jwt",
                )
                caller_id = caller_spiffe
            else:
                raise AuditIngestError(f"Unsupported X-LCT-Audit-Mode: {mode!r}")
        except (IdentityError, CryptoError, KeyError, TypeError, ValueError) as exc:
            raise AuditIngestError(f"Audit query authentication failed: {exc}") from exc

        iat = require_finite_timestamp(claims.get("iat"), "audit_query.iat")
        if abs(now_ts - iat) > 60.0:
            raise AuditIngestError("Audit query JWS iat outside 60s freshness window")
        jti = str(claims.get("jti") or "").strip()
        if not jti:
            raise AuditIngestError("Audit query JWS missing jti")

        expected_task_filter = str(req.query.get("task_id") or "")
        if str(claims.get("task_id") or "") != expected_task_filter:
            raise AuditIngestError("Signed task_id filter mismatch with query string")

        replay_key = f"{caller_id}:{jti}"
        with self._query_replay_lock:
            while self._seen_query_jtis:
                _, exp_at = next(iter(self._seen_query_jtis.items()))
                if exp_at <= now_ts:
                    self._seen_query_jtis.popitem(last=False)
                else:
                    break
            if replay_key in self._seen_query_jtis:
                raise AuditIngestError("Replayed audit query jti rejected")
            if len(self._seen_query_jtis) >= 16_384:
                self._seen_query_jtis.popitem(last=False)
            self._seen_query_jtis[replay_key] = now_ts + 120.0

        return caller_id

    def _dispatch(
        self, req: HTTPRequestContext
    ) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return 200, {"status": "ok", "count": len(self._entries)}, {}

        if req.method == "GET" and req.path == "/readyz":
            if self._readiness_check is not None:
                ok, detail = self._readiness_check()
                if not ok:
                    return 503, {"status": "not_ready", **detail}, {}
                return 200, {"status": "ready", "count": len(self._entries), **detail}, {}
            return 200, {"status": "ready", "count": len(self._entries)}, {}

        if req.method == "GET" and req.path in ("/v1/federation/bundle", "/v1/ca/bundles"):
            if self._public_bundle_provider is None:
                return 404, {"error": "bundle_not_configured"}, {}
            return 200, self._public_bundle_provider(), {}

        if req.method == "GET" and req.path == "/v1/federation/descriptors":
            if self._descriptors_provider is None:
                return 200, {"trust_domain": "org-audit.io", "descriptors": []}, {}
            return 200, self._descriptors_provider(), {}

        if req.method == "POST" and req.path == "/v1/audit/append":
            body = req.json()
            entry_raw = body.get("entry", body)
            try:
                entry = AuditEntry.from_dict(entry_raw)
                idx = self.append_direct(entry)
            except (AuditIngestError, ValueError, KeyError, TypeError) as exc:
                return 403, {"error": "audit_entry_rejected", "detail": str(exc)}, {}
            return 200, {"recorded": True, "collector_index": idx}, {}

        if req.method == "GET" and req.path == "/v1/audit/entries":
            try:
                self._authorize_read_query(req)
            except PermissionError as exc:
                return 401, {"error": "audit_auth_required", "detail": str(exc)}, {}
            except (AuditIngestError, ValueError) as exc:
                return 403, {"error": "unauthorized_auditor_principal", "detail": str(exc)}, {}

            task_filter = req.query.get("task_id")
            with self._lock:
                if task_filter:
                    items = [
                        e for e in self._entries if e.get("task_id") == task_filter
                    ]
                else:
                    items = list(self._entries)
            return 200, {"entries": items}, {}

        return 404, {"error": "route_not_found", "path": req.path}, {}


class AuditCollectorClient:
    """HTTP/HTTPS client shipping signed AuditEntry records to AuditCollectorService."""

    def __init__(
        self,
        collector_url: str = "",
        timeout: float = 3.0,
        signer: Optional[WorkloadIdentity | TrustDomainCA] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        ssl_context_provider: Optional[Callable[[], Optional[ssl.SSLContext]]] = None,
        locator_provider: Optional[Callable[[], Sequence[Any]]] = None,
        ssl_context_for_locator: Optional[Callable[[Any], Optional[ssl.SSLContext]]] = None,
    ) -> None:
        self.collector_url = (collector_url or "").strip().rstrip("/")
        self.timeout = timeout
        self.signer = signer
        self.ssl_context = ssl_context
        self.ssl_context_provider = ssl_context_provider
        self.locator_provider = locator_provider
        self.ssl_context_for_locator = ssl_context_for_locator

    def verify_kwarg(self, target_url: Optional[str] = None, locator: Any = None) -> Any:
        if locator is not None and self.ssl_context_for_locator is not None:
            ctx_loc = self.ssl_context_for_locator(locator)
            if ctx_loc is not None:
                return ctx_loc
            raise RuntimeError(
                f"TLS trust anchor / SPIFFE pin for audit locator {getattr(locator, 'origin_url', locator)!r} is not yet verified"
            )
        if self.ssl_context_provider is not None:
            ctx = self.ssl_context_provider()
            if ctx is not None:
                return ctx
            eff_url = target_url if target_url is not None else self.collector_url
            if eff_url.startswith("https://"):
                raise RuntimeError(
                    f"TLS trust anchor for audit collector {eff_url!r} is not yet verified"
                )
        if self.ssl_context is not None:
            return self.ssl_context
        return True

    def _candidate_targets(self) -> List[Tuple[str, Any]]:
        targets: List[Tuple[str, Any]] = []
        if self.locator_provider is not None:
            for loc in self.locator_provider() or ():
                orig = str(getattr(loc, "origin_url", "")).rstrip("/")
                if orig:
                    targets.append((orig, loc))
        if self.collector_url and all(u != self.collector_url for u, _ in targets):
            targets.append((self.collector_url, None))
        if not targets:
            raise RuntimeError(
                "No verified audit-collector locator or URL is currently available"
            )
        return targets

    def healthz(self) -> httpx.Response:
        last_exc: Optional[Exception] = None
        for base_url, loc in self._candidate_targets():
            try:
                with httpx.Client(
                    verify=self.verify_kwarg(base_url, loc),
                    timeout=self.timeout,
                    trust_env=False,
                ) as client:
                    return client.get(f"{base_url}/healthz")
            except Exception as exc:
                last_exc = exc
        assert last_exc is not None
        raise last_exc

    def ship(self, entry: AuditEntry) -> None:
        last_exc: Optional[Exception] = None
        for base_url, loc in self._candidate_targets():
            try:
                with httpx.Client(
                    verify=self.verify_kwarg(base_url, loc),
                    timeout=self.timeout,
                    trust_env=False,
                ) as client:
                    resp = client.post(
                        f"{base_url}/v1/audit/append",
                        json={"entry": entry.to_dict()},
                    )
                resp.raise_for_status()
                return
            except Exception as exc:
                last_exc = exc
        assert last_exc is not None
        raise last_exc

    def fetch_entries(
        self,
        task_id: Optional[str] = None,
        signer: Optional[WorkloadIdentity | TrustDomainCA] = None,
    ) -> List[AuditEntry]:
        params = {"task_id": task_id} if task_id else None
        active_signer = signer or self.signer
        last_exc: Optional[Exception] = None
        for base_url, loc in self._candidate_targets():
            headers: Dict[str, str] = {}
            if active_signer is not None:
                # Mint fresh jti per candidate attempt so locator failover never trips anti-replay!
                query_claims = {
                    "jti": f"audq-{uuid.uuid4().hex}",
                    "iat": time.time(),
                    "task_id": task_id or "",
                }
                if isinstance(active_signer, TrustDomainCA):
                    q_jws = jws_sign_compact(
                        payload=query_claims,
                        keypair=active_signer.active_keypair,
                        typ="lct-audit-query+jwt",
                    )
                    headers["X-LCT-Audit-Mode"] = "domain_authority"
                    headers["X-LCT-Audit-Domain"] = active_signer.trust_domain
                    headers["X-LCT-Audit-Auth"] = q_jws
                else:
                    q_jws = jws_sign_compact(
                        payload=query_claims,
                        keypair=active_signer.keypair,
                        typ="lct-audit-query+jwt",
                    )
                    headers["X-LCT-Audit-Mode"] = "workload"
                    headers["X-LCT-Audit-SVID"] = active_signer.workload_svid
                    headers["X-LCT-Audit-Auth"] = q_jws

            try:
                with httpx.Client(
                    verify=self.verify_kwarg(base_url, loc),
                    timeout=self.timeout,
                    trust_env=False,
                ) as client:
                    resp = client.get(
                        f"{base_url}/v1/audit/entries",
                        params=params,
                        headers=headers,
                    )
                resp.raise_for_status()
                return [AuditEntry.from_dict(e) for e in resp.json().get("entries", [])]
            except Exception as exc:
                last_exc = exc
        assert last_exc is not None
        raise last_exc
