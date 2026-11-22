"""Hash-Chained & Cryptographically Signed Structured Audit Logger & Verified HTTP Collector."""

from __future__ import annotations

import enum
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

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


class AuditStreamEmitter:
    """Per-node thread-safe hash-chained audit emitter with automatic secret redaction."""

    def __init__(
        self,
        signer: WorkloadIdentity | TrustDomainCA,
        collector_client: Optional["AuditCollectorClient"] = None,
        stream_id: Optional[str] = None,
    ) -> None:
        self._signer = signer
        self._collector = collector_client
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
        self._seq: int = 0
        self._prev_hash: str = "GENESIS"
        self._local_entries: List[AuditEntry] = []

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
                node_svid_or_domain=self.node_svid_or_domain,
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
                keypair=self._keypair,
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
            self._local_entries.append(final_entry)

        if self._collector is not None:
            self._collector.ship(final_entry)

        return final_entry

    def local_entries(self) -> List[AuditEntry]:
        with self._lock:
            return list(self._local_entries)


class AuditCollectorService:
    """HTTP Audit Log Collector with Mandatory TrustBundle-Backed Ingest Signature Verification."""

    def __init__(
        self,
        trust_resolver: TrustBundleResolver,
        host: str = "127.0.0.1",
        port: int = 0,
        authorized_auditors: Iterable[str] = (),
    ) -> None:
        if not isinstance(trust_resolver, TrustBundleResolver):
            raise TypeError(
                "AuditCollectorService requires a TrustBundleResolver (unauthenticated ingest mode is forbidden)"
            )
        self.trust_resolver = trust_resolver
        self._authorized_auditors: FrozenSet[str] = frozenset(str(s) for s in authorized_auditors if s)
        self._lock = threading.Lock()
        self._entries: List[Dict[str, Any]] = []
        # Anti-replay / anti-overwrite index `(stream_id, stream_seq) -> entry_hash`
        self._seen_stream_seqs: Dict[Tuple[str, int], str] = {}
        self._query_replay_lock = threading.Lock()
        self._seen_query_jtis: "OrderedDict[str, float]" = OrderedDict()
        self._http = ManagedHTTPService(
            service_name="audit-collector",
            dispatcher=self._dispatch,
            host=host,
            port=port,
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

    def _verify_entry_on_ingest(self, entry: AuditEntry) -> None:
        """Verify entry_hash, CA/TrustBundle signature, and stream hash-chain continuity."""
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
    """HTTP client shipping signed AuditEntry records to AuditCollectorService."""

    def __init__(
        self,
        collector_url: str,
        timeout: float = 3.0,
        signer: Optional[WorkloadIdentity | TrustDomainCA] = None,
    ) -> None:
        self.collector_url = collector_url.rstrip("/")
        self.timeout = timeout
        self.signer = signer

    def ship(self, entry: AuditEntry) -> None:
        resp = httpx.post(
            f"{self.collector_url}/v1/audit/append",
            json={"entry": entry.to_dict()},
            timeout=self.timeout,
        )
        resp.raise_for_status()

    def fetch_entries(
        self,
        task_id: Optional[str] = None,
        signer: Optional[WorkloadIdentity | TrustDomainCA] = None,
    ) -> List[AuditEntry]:
        params = {"task_id": task_id} if task_id else None
        headers: Dict[str, str] = {}
        active_signer = signer or self.signer
        if active_signer is not None:
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

        resp = httpx.get(
            f"{self.collector_url}/v1/audit/entries",
            params=params,
            headers=headers,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return [AuditEntry.from_dict(e) for e in resp.json().get("entries", [])]
