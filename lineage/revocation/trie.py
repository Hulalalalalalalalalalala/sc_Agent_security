"""Thread-safe Trust-Domain-Scoped Segment-Exact Lineage Prefix Trie (`LineagePrefixTrie`).

Supports O(depth) lookup and incremental versioned synchronization for:
1. Full-Chain Teardown (`/<task_id>`, scoped to `trust_domain` or wildcard `None`)
2. Subtree Cascading Revocation (`/<task_id>/hop1/.../hop_k`, scoped to `trust_domain` or wildcard `None`)
3. Workload Quarantine (`spiffe://...`)
"""

from __future__ import annotations

import enum
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from lineage.common.crypto import CryptoError, require_finite_timestamp
from lineage.identity.spiffe import SpiffeId
from lineage.protocol.token import validate_segment


class RevocationKind(str, enum.Enum):
    FULL_CHAIN = "FULL_CHAIN"
    SUBTREE = "SUBTREE"
    WORKLOAD_QUARANTINE = "WORKLOAD_QUARANTINE"


def parse_revocation_prefix(prefix: str) -> List[str]:
    """Parse `/<task_id>[/<seg1>...]` into validated exact segments."""
    if not isinstance(prefix, str) or not prefix.startswith("/"):
        raise ValueError(f"Revocation prefix must start with '/': {prefix!r}")
    trimmed = prefix.rstrip("/")
    if not trimmed:
        raise ValueError("Cannot revoke root '/' across all tasks")
    parts = trimmed.split("/")[1:]
    if not parts:
        raise ValueError(f"Empty revocation prefix: {prefix!r}")
    return [validate_segment(p, "revocation_segment") for p in parts]


@dataclass(frozen=True)
class RevocationEvent:
    """Immutable versioned revocation record with optional `trust_domain` & federation origin."""

    version: int
    kind: RevocationKind
    target: str  # Normalized prefix `/<task_id>[/...]` or `spiffe://...`
    reason: str
    requested_by: str
    timestamp: float
    service_signature: str = ""
    service_svid: str = ""
    trust_domain: Optional[str] = None
    origin_version: Optional[int] = None

    def core_claims(self) -> Dict[str, Any]:
        signed_ver = (
            self.origin_version if self.origin_version is not None else self.version
        )
        claims: Dict[str, Any] = {
            "version": signed_ver,
            "kind": self.kind.value,
            "target": self.target,
            "reason": self.reason,
            "requested_by": self.requested_by,
            "timestamp": self.timestamp,
        }
        if self.trust_domain is not None:
            claims["trust_domain"] = self.trust_domain
        return claims

    def to_dict(self) -> Dict[str, Any]:
        d = self.core_claims()
        d["version"] = self.version
        if self.origin_version is not None:
            d["origin_version"] = self.origin_version
        d["service_signature"] = self.service_signature
        if self.service_svid:
            d["service_svid"] = self.service_svid
        return d

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "RevocationEvent":
        try:
            ts = require_finite_timestamp(raw["timestamp"], "RevocationEvent.timestamp")
        except CryptoError as exc:
            raise ValueError(str(exc)) from exc
        td_raw = raw.get("trust_domain")
        td = str(td_raw) if td_raw is not None and str(td_raw) else None
        orig_raw = raw.get("origin_version")
        orig_ver = int(orig_raw) if orig_raw is not None else None
        return cls(
            version=int(raw["version"]),
            kind=RevocationKind(str(raw["kind"])),
            target=str(raw["target"]),
            reason=str(raw.get("reason", "")),
            requested_by=str(raw["requested_by"]),
            timestamp=ts,
            service_signature=str(raw.get("service_signature", "")),
            service_svid=str(raw.get("service_svid", "")),
            trust_domain=td,
            origin_version=orig_ver,
        )


@dataclass
class _TrieNode:
    children: Dict[str, "_TrieNode"] = field(default_factory=dict)
    revocation: Optional[RevocationEvent] = None


class LineagePrefixTrie:
    """Thread-safe trust-domain-isolated segment-exact prefix trie + workload quarantine registry."""

    def __init__(self) -> None:
        self._cond = threading.Condition(threading.RLock())
        self._wildcard_root = _TrieNode()
        self._domain_roots: Dict[str, _TrieNode] = {}
        self._quarantined_workloads: Dict[str, RevocationEvent] = {}
        self._events: List[RevocationEvent] = []
        self._seen_federated_origins: Dict[Tuple[str, int, str], RevocationEvent] = {}
        self._seen_replica_signatures: Dict[str, RevocationEvent] = {}
        self._version: int = 0

    @property
    def version(self) -> int:
        with self._cond:
            return self._version

    @staticmethod
    def _insert_into_root(
        root_node: _TrieNode, segments: List[str], event: RevocationEvent
    ) -> None:
        node = root_node
        for seg in segments:
            child = node.children.get(seg)
            if child is None:
                child = _TrieNode()
                node.children[seg] = child
            node = child
        if node.revocation is None:
            node.revocation = event

    @staticmethod
    def _match_in_root(
        root_node: _TrieNode, segments: List[str]
    ) -> Optional[RevocationEvent]:
        node = root_node
        for seg in segments:
            child = node.children.get(seg)
            if child is None:
                return None
            if child.revocation is not None:
                return child.revocation
            node = child
        return None

    def _select_target_root_locked(self, trust_domain: Optional[str]) -> _TrieNode:
        if trust_domain is None:
            return self._wildcard_root
        SpiffeId.parse(f"spiffe://{trust_domain}/authority/ca")
        root = self._domain_roots.get(trust_domain)
        if root is None:
            root = _TrieNode()
            self._domain_roots[trust_domain] = root
        return root

    def revoke_prefix(
        self,
        prefix: str,
        requested_by: str,
        reason: str = "unspecified",
        timestamp: Optional[float] = None,
        signer_fn: Optional[Any] = None,
        service_svid: str = "",
        trust_domain: Optional[str] = None,
    ) -> RevocationEvent:
        """Revoke `/<task_id>` (Full-Chain) or `/<task_id>/.../hop_k` (Subtree)."""
        segments = parse_revocation_prefix(prefix)
        norm_prefix = "/" + "/".join(segments)
        kind = (
            RevocationKind.FULL_CHAIN
            if len(segments) == 1
            else RevocationKind.SUBTREE
        )
        ts = require_finite_timestamp(
            time.time() if timestamp is None else timestamp, "timestamp"
        )

        with self._cond:
            target_root = self._select_target_root_locked(trust_domain)
            next_ver = self._version + 1
            provisional = RevocationEvent(
                version=next_ver,
                kind=kind,
                target=norm_prefix,
                reason=reason,
                requested_by=requested_by,
                timestamp=ts,
                service_signature="",
                service_svid=service_svid,
                trust_domain=trust_domain,
            )
            sig = signer_fn(provisional.core_claims()) if signer_fn else ""
            event = RevocationEvent(
                **{**provisional.__dict__, "service_signature": sig}
            )
            self._insert_into_root(target_root, segments, event)
            self._version = next_ver
            self._events.append(event)
            self._cond.notify_all()
            return event

    def quarantine_workload(
        self,
        spiffe_id: str,
        requested_by: str,
        reason: str = "workload_compromised",
        timestamp: Optional[float] = None,
        signer_fn: Optional[Any] = None,
        service_svid: str = "",
    ) -> RevocationEvent:
        """Quarantine a specific workload SPIFFE ID across all active chains."""
        spiffe = SpiffeId.parse(spiffe_id)
        ts = require_finite_timestamp(
            time.time() if timestamp is None else timestamp, "timestamp"
        )

        with self._cond:
            next_ver = self._version + 1
            provisional = RevocationEvent(
                version=next_ver,
                kind=RevocationKind.WORKLOAD_QUARANTINE,
                target=spiffe.uri,
                reason=reason,
                requested_by=requested_by,
                timestamp=ts,
                service_signature="",
                service_svid=service_svid,
                trust_domain=spiffe.trust_domain,
            )
            sig = signer_fn(provisional.core_claims()) if signer_fn else ""
            event = RevocationEvent(
                **{**provisional.__dict__, "service_signature": sig}
            )
            if spiffe.uri not in self._quarantined_workloads:
                self._quarantined_workloads[spiffe.uri] = event
            self._version = next_ver
            self._events.append(event)
            self._cond.notify_all()
            return event

    def apply_replicated_event(self, event: RevocationEvent) -> bool:
        """Apply an already-verified RevocationEvent in monotonic version order."""
        with self._cond:
            if event.version <= self._version:
                return False
            if event.version != self._version + 1:
                raise ValueError(
                    f"Out-of-order revocation event: expected v{self._version + 1}, got v{event.version}"
                )
            if event.kind in (RevocationKind.FULL_CHAIN, RevocationKind.SUBTREE):
                segments = parse_revocation_prefix(event.target)
                target_root = self._select_target_root_locked(event.trust_domain)
                self._insert_into_root(target_root, segments, event)
            elif event.kind == RevocationKind.WORKLOAD_QUARANTINE:
                spiffe = SpiffeId.parse(event.target)
                if spiffe.uri not in self._quarantined_workloads:
                    self._quarantined_workloads[spiffe.uri] = event
            else:
                raise ValueError(f"Unsupported RevocationKind: {event.kind}")

            self._version = event.version
            self._events.append(event)
            self._cond.notify_all()
            return True

    def check_lineage_path(
        self, lineage_path: str, trust_domain: Optional[str] = None
    ) -> Optional[RevocationEvent]:
        """Return matching RevocationEvent if any ancestor prefix in wildcard or `trust_domain` is revoked."""
        segments = parse_revocation_prefix(lineage_path)
        with self._cond:
            hit = self._match_in_root(self._wildcard_root, segments)
            if hit is not None:
                return hit
            if trust_domain is not None:
                d_root = self._domain_roots.get(trust_domain)
                if d_root is not None:
                    return self._match_in_root(d_root, segments)
            else:
                # When caller queries without specifying trust_domain (e.g. unit inspection),
                # also inspect domain-scoped tries if unambiguous
                for d_root in self._domain_roots.values():
                    d_hit = self._match_in_root(d_root, segments)
                    if d_hit is not None:
                        return d_hit
            return None

    def check_workloads(self, spiffe_ids: Iterable[str]) -> Optional[RevocationEvent]:
        """Return matching RevocationEvent if any workload in `spiffe_ids` is quarantined."""
        with self._cond:
            for sid in spiffe_ids:
                ev = self._quarantined_workloads.get(sid)
                if ev is not None:
                    return ev
            return None

    def check_chain(
        self,
        lineage_path: str,
        involved_spiffe_ids: Iterable[str],
        trust_domain: Optional[str] = None,
    ) -> Optional[RevocationEvent]:
        """Combined check for domain-scoped prefix revocation or workload quarantine."""
        with self._cond:
            ev = self.check_lineage_path(lineage_path, trust_domain=trust_domain)
            if ev is not None:
                return ev
            return self.check_workloads(involved_spiffe_ids)

    def events_since(
        self, since_version: int, wait_ms: int = 0
    ) -> Tuple[int, List[RevocationEvent]]:
        """Return `(current_version, events_with_version_gt_since)`."""
        with self._cond:
            if wait_ms > 0 and self._version <= since_version:
                self._cond.wait(timeout=min(wait_ms, 5000) / 1000.0)
            if since_version < 0:
                since_version = 0
            delta = self._events[since_version:]
            return self._version, list(delta)

    def local_domain_events_since(
        self, trust_domain: str, since_origin_version: int = 0
    ) -> List[RevocationEvent]:
        """Export only locally-authored events for `trust_domain` (excluding re-federated events)."""
        with self._cond:
            return [
                e
                for e in self._events
                if e.origin_version is None
                and e.trust_domain == trust_domain
                and e.version > since_origin_version
            ]

    def apply_verified_replica_event(self, event: RevocationEvent) -> bool:
        """Apply a cryptographically verified replica event (safe across upstream service restarts)."""
        with self._cond:
            if event.service_signature:
                if event.service_signature in self._seen_replica_signatures:
                    return False
            elif event.version <= self._version:
                return False

            assigned_ver = (
                event.version
                if event.version == self._version + 1
                else (self._version + 1)
            )
            stored = (
                event
                if assigned_ver == event.version
                else RevocationEvent(
                    version=assigned_ver,
                    kind=event.kind,
                    target=event.target,
                    reason=event.reason,
                    requested_by=event.requested_by,
                    timestamp=event.timestamp,
                    service_signature=event.service_signature,
                    service_svid=event.service_svid,
                    trust_domain=event.trust_domain,
                    origin_version=event.origin_version
                    if event.origin_version is not None
                    else event.version,
                )
            )
            if stored.kind in (RevocationKind.FULL_CHAIN, RevocationKind.SUBTREE):
                segments = parse_revocation_prefix(stored.target)
                target_root = self._select_target_root_locked(stored.trust_domain)
                self._insert_into_root(target_root, segments, stored)
            elif stored.kind == RevocationKind.WORKLOAD_QUARANTINE:
                spiffe = SpiffeId.parse(stored.target)
                if spiffe.uri not in self._quarantined_workloads:
                    self._quarantined_workloads[spiffe.uri] = stored
            else:
                raise ValueError(f"Unsupported RevocationKind: {stored.kind}")

            self._version = assigned_ver
            self._events.append(stored)
            if event.service_signature:
                self._seen_replica_signatures[event.service_signature] = stored
            self._cond.notify_all()
            return True

    def ingest_federated_event(
        self, event: RevocationEvent, origin_instance_jkt: str = ""
    ) -> RevocationEvent:
        """Append a cryptographically verified peer-domain RevocationEvent preserving its signature."""
        if not event.trust_domain:
            raise ValueError("Federated RevocationEvent must specify trust_domain")
        orig_ver = (
            event.origin_version if event.origin_version is not None else event.version
        )
        key = (event.trust_domain, origin_instance_jkt, orig_ver)
        with self._cond:
            existing = self._seen_federated_origins.get(key)
            if existing is not None:
                if (
                    existing.service_signature != event.service_signature
                    or existing.core_claims() != event.core_claims()
                ):
                    raise ValueError(
                        f"Equivocated federated RevocationEvent for ({event.trust_domain!r}, "
                        f"instance_jkt={origin_instance_jkt!r}, origin_version={orig_ver})"
                    )
                return existing

            next_ver = self._version + 1
            reindexed = RevocationEvent(
                version=next_ver,
                kind=event.kind,
                target=event.target,
                reason=event.reason,
                requested_by=event.requested_by,
                timestamp=event.timestamp,
                service_signature=event.service_signature,
                service_svid=event.service_svid,
                trust_domain=event.trust_domain,
                origin_version=orig_ver,
            )
            if reindexed.kind in (RevocationKind.FULL_CHAIN, RevocationKind.SUBTREE):
                segments = parse_revocation_prefix(reindexed.target)
                target_root = self._select_target_root_locked(reindexed.trust_domain)
                self._insert_into_root(target_root, segments, reindexed)
            elif reindexed.kind == RevocationKind.WORKLOAD_QUARANTINE:
                spiffe = SpiffeId.parse(reindexed.target)
                if spiffe.uri not in self._quarantined_workloads:
                    self._quarantined_workloads[spiffe.uri] = reindexed
            else:
                raise ValueError(f"Unsupported RevocationKind: {reindexed.kind}")

            self._version = next_ver
            self._events.append(reindexed)
            self._seen_federated_origins[key] = reindexed
            self._cond.notify_all()
            return reindexed
