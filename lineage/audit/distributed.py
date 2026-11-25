"""Stateless On-Demand Federated Audit Pull & Reconstruction (`DistributedAuditor`).

Eliminates centralized audit collector bottlenecks: each peer Sidecar and Domain CA
maintains only its own bounded `LocalAuditStore`. On demand for a target `task_id`,
`DistributedAuditor` executes bounded authenticated BFS discovery across participating
Domain CAs and Peer Sidecars (`GET /v1/audit/local?task_id=<id>`), resolving dynamic
locators via the Untrusted Public Yellow Pages (`AgentDirectoryClient`) and signed
`DomainDescriptorStore`, then runs full cryptographic `CausalChainAuditor` verification.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import json
import re
import ssl
import time
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

import httpx

from lineage.audit.auditor import AuditAnomaly, AuditReport, CausalChainAuditor, TaskReconstruction
from lineage.audit.logger import AuditEntry, AuditEventType, build_audit_query_headers
from lineage.common.locators import (
    DEFAULT_ALLOWED_LOCATOR_CIDRS,
    LocatorError,
    parse_allowed_locator_cidrs,
    validate_locator_host,
)
from lineage.identity.spiffe import IdentityError, SpiffeId, TrustDomainCA, WorkloadIdentity
from lineage.identity.trust_bundle import TrustBundleResolver

_K8S_INTERNAL_DNS_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.(?:svc|svc\.cluster\.local)$"
)


@dataclass
class DistributedAuditResult:
    """Structured result of an on-demand decentralized federated audit pull."""

    task_id: str
    nodes_queried: List[str]
    unreachable_nodes: Dict[str, str]
    total_entries: int
    pull_latency_ms: float
    stream_integrity_ok: bool
    reconstructed_complete: bool
    reconstruction: Optional[TaskReconstruction]
    report: AuditReport
    entries: List[AuditEntry] = field(default_factory=list)

    @property
    def anomalies(self) -> List[AuditAnomaly]:
        if self.reconstruction is not None:
            return list(self.reconstruction.anomalies)
        return list(self.report.anomalies)

    def to_dict(self) -> Dict[str, Any]:
        rec_dict: Optional[Dict[str, Any]] = None
        if self.reconstruction is not None:
            rec_dict = {
                "task_id": self.reconstruction.task_id,
                "sub": self.reconstruction.sub,
                "root_block_hash": self.reconstruction.root_block_hash,
                "reconstructed_complete": self.reconstruction.reconstructed_complete,
                "lineage_paths_observed": list(self.reconstruction.lineage_paths_observed),
                "verified_hops": self.reconstruction.verified_hops,
                "tool_invocations_verified": self.reconstruction.tool_invocations_verified,
                "resilience_classifications": list(self.reconstruction.resilience_classifications),
                "anomalies": [a.__dict__ for a in self.reconstruction.anomalies],
            }
        return {
            "mode": "decentralized_on_demand_bfs",
            "task_id": self.task_id,
            "nodes_queried": list(self.nodes_queried),
            "nodes_queried_count": len(self.nodes_queried),
            "unreachable_nodes": dict(self.unreachable_nodes),
            "total_entries": self.total_entries,
            "pull_latency_ms": round(self.pull_latency_ms, 2),
            "stream_integrity_ok": self.stream_integrity_ok,
            "reconstructed_complete": self.reconstructed_complete,
            "resilience_classifications": (
                list(self.reconstruction.resilience_classifications)
                if self.reconstruction is not None
                else []
            ),
            "reconstruction": rec_dict,
            "anomalies": [a.__dict__ for a in self.anomalies],
        }


class DistributedAuditor:
    """Stateless BFS pull auditor over per-peer `/v1/audit/local?task_id=<id>` stores."""

    def __init__(
        self,
        trust_resolver: TrustBundleResolver,
        signer: WorkloadIdentity | TrustDomainCA,
        directory_client: Optional[Any] = None,
        descriptor_store: Optional[Any] = None,
        mtls_bundle: Optional[Any] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        spiffe_url_overrides: Optional[Mapping[str, Sequence[str] | str]] = None,
        domain_ca_urls: Optional[Mapping[str, Sequence[str] | str]] = None,
        trusted_revocation_spiffe_ids: Optional[Iterable[str]] = None,
        timeout: float = 4.0,
        max_nodes: int = 64,
        max_depth: int = 16,
        max_response_bytes: int = 1_048_576,
        max_entries_per_node: int = 2_000,
        allowed_locator_cidrs: Optional[Iterable[str] | str] = None,
        allow_loopback: Optional[bool] = None,
    ) -> None:
        self.trust_resolver = trust_resolver
        self.signer = signer
        self.directory_client = directory_client
        self.descriptor_store = descriptor_store
        self.mtls_bundle = mtls_bundle
        self.ssl_context = ssl_context
        self.timeout = float(timeout)
        self.max_nodes = max(1, int(max_nodes))
        self.max_depth = max(1, int(max_depth))
        self.max_response_bytes = max(4096, int(max_response_bytes))
        self.max_entries_per_node = max(1, int(max_entries_per_node))
        self.allowed_locator_cidrs = allowed_locator_cidrs
        if allow_loopback is None:
            self.allow_loopback = mtls_bundle is None and bool(
                spiffe_url_overrides or domain_ca_urls
            )
        else:
            self.allow_loopback = bool(allow_loopback)
        self.auditor = CausalChainAuditor(
            trust_resolver,
            trusted_revocation_spiffe_ids=trusted_revocation_spiffe_ids,
        )
        self._spiffe_urls: Dict[str, List[str]] = {}
        for sid, raw_u in (spiffe_url_overrides or {}).items():
            if isinstance(raw_u, str):
                self._spiffe_urls[str(sid)] = [raw_u.rstrip("/")]
            else:
                self._spiffe_urls[str(sid)] = [str(x).rstrip("/") for x in raw_u if str(x).strip()]

        self._domain_ca_urls: Dict[str, List[str]] = {}
        for td, raw_u in (domain_ca_urls or {}).items():
            if isinstance(raw_u, str):
                self._domain_ca_urls[str(td)] = [raw_u.rstrip("/")]
            else:
                self._domain_ca_urls[str(td)] = [str(x).rstrip("/") for x in raw_u if str(x).strip()]

    def _validate_candidate_url(
        self,
        url: str,
        *,
        is_workload: bool = False,
    ) -> str:
        sp = urlsplit(str(url or "").strip())
        if sp.scheme not in ("http", "https") or not sp.hostname:
            raise LocatorError(f"Malformed audit target URL {url!r}")
        if sp.username is not None or sp.password is not None:
            raise LocatorError(f"Credentials in audit target URL {url!r} are forbidden")
        if self.mtls_bundle is not None and is_workload and sp.scheme != "https":
            raise LocatorError(
                f"Plaintext {sp.scheme}:// workload audit URL {url!r} forbidden when mTLS bundle is active"
            )
        host_l = sp.hostname.strip().lower()
        if _K8S_INTERNAL_DNS_RE.match(host_l):
            return url
        if host_l == "localhost" and self.allow_loopback:
            return url
        base_nets = [str(n) for n in parse_allowed_locator_cidrs(self.allowed_locator_cidrs or DEFAULT_ALLOWED_LOCATOR_CIDRS)]
        if self.allow_loopback and "127.0.0.0/8" not in base_nets:
            base_nets.append("127.0.0.0/8")
        validate_locator_host(
            sp.hostname,
            allowed_cidrs=base_nets,
            allow_loopback=self.allow_loopback,
        )
        return url

    def _verify_kwarg(
        self,
        url: str,
        expected_trust_domain: Optional[str] = None,
        expected_spiffe_id: Optional[str] = None,
    ) -> Any:
        if (
            expected_spiffe_id is None
            and isinstance(expected_trust_domain, str)
            and expected_trust_domain.startswith("spiffe://")
        ):
            expected_spiffe_id = expected_trust_domain
            try:
                expected_trust_domain = SpiffeId.parse(expected_spiffe_id).trust_domain
            except IdentityError:
                pass
        self._validate_candidate_url(url, is_workload=bool(expected_spiffe_id))
        if not url.startswith("https://"):
            return True
        if self.mtls_bundle is not None:
            return self.mtls_bundle.verify_for_target(
                target_url=url,
                expected_trust_domain=expected_trust_domain,
                expected_spiffe_id=expected_spiffe_id,
            )
        if self.ssl_context is not None:
            return self.ssl_context
        return True

    def _resolve_domain_ca_candidates(self, trust_domain: str) -> List[str]:
        td = str(trust_domain or "").strip().lower()
        if not td:
            return []
        urls: List[str] = list(self._domain_ca_urls.get(td, ()))
        if self.descriptor_store is not None:
            desc = self.descriptor_store.get_descriptor(td)
            if desc is not None:
                for loc in desc.get_locators("ca_bundle"):
                    orig = str(loc.origin_url).rstrip("/")
                    if orig and orig not in urls:
                        urls.append(orig)
        return urls

    def _resolve_workload_candidates(
        self,
        spiffe_id: str,
        card_cache: Dict[str, List[str]],
    ) -> List[str]:
        if spiffe_id in self._spiffe_urls:
            return list(self._spiffe_urls[spiffe_id])
        if spiffe_id in card_cache:
            return list(card_cache[spiffe_id])
        if self.directory_client is None:
            return []
        urls: List[str] = []
        try:
            card = self.directory_client.get_agent(spiffe_id)
            if card is not None:
                urls = [str(u).rstrip("/") for u in card.candidate_origins() if str(u).strip()]
        except Exception:
            pass
        if not urls:
            try:
                for card in self.directory_client.discover(only_healthy=False):
                    c_urls = [str(u).rstrip("/") for u in card.candidate_origins() if str(u).strip()]
                    card_cache[card.spiffe_id] = c_urls
                urls = list(card_cache.get(spiffe_id, ()))
            except Exception:
                pass
        card_cache[spiffe_id] = urls
        return urls

    def _pull_node_local_entries(
        self,
        node_key: str,
        candidate_urls: Sequence[str],
        task_id: str,
        expected_trust_domain: Optional[str] = None,
        expected_spiffe_id: Optional[str] = None,
    ) -> Tuple[Optional[List[AuditEntry]], Optional[str]]:
        if not candidate_urls:
            return None, "no_verified_locator"
        last_err = "unreachable"
        for base_url in candidate_urls:
            clean_base = str(base_url).rstrip("/")
            target_url = f"{clean_base}/v1/audit/local"
            hdrs = build_audit_query_headers(self.signer, task_id=task_id)
            try:
                verify_cfg = self._verify_kwarg(
                    target_url,
                    expected_trust_domain=expected_trust_domain,
                    expected_spiffe_id=expected_spiffe_id,
                )
                with httpx.Client(
                    verify=verify_cfg,
                    timeout=self.timeout,
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    with client.stream(
                        "GET",
                        target_url,
                        params={"task_id": task_id},
                        headers=hdrs,
                    ) as resp:
                        chunks: List[bytes] = []
                        total_bytes = 0
                        for chunk in resp.iter_bytes():
                            total_bytes += len(chunk)
                            if total_bytes > self.max_response_bytes:
                                raise ValueError(
                                    f"Response exceeded max_response_bytes={self.max_response_bytes}"
                                )
                            chunks.append(chunk)
                        raw_body = b"".join(chunks)
                        status_code = resp.status_code

                if status_code == 200:
                    parsed_json = json.loads(raw_body.decode("utf-8"))
                    raw_items = parsed_json.get("entries", [])
                    if not isinstance(raw_items, list):
                        raise ValueError("Malformed entries list in /v1/audit/local response")
                    if len(raw_items) > self.max_entries_per_node:
                        raise ValueError(
                            f"Node returned {len(raw_items)} entries > max_entries_per_node={self.max_entries_per_node}"
                        )
                    return [AuditEntry.from_dict(x) for x in raw_items], None
                last_err = f"HTTP {status_code}: {raw_body.decode('utf-8', errors='replace')[:160]}"
            except Exception as exc:
                last_err = f"{type(exc).__name__}: {exc}"
        return None, last_err

    @staticmethod
    def _extract_referenced_targets(
        entry: AuditEntry,
    ) -> Tuple[Set[str], Set[str], Set[str]]:
        """Return `(required_workloads, optional_workloads, referenced_trust_domains)` from `entry`.

        Upstream client hints (`INBOUND_AUTHZ.peer_spiffe_id`, e.g., non-agent user gateways)
        are deliberately NOT enqueued as downstream audit nodes (`[HIGH-M9-04]`).
        """
        req_workloads: Set[str] = set()
        opt_workloads: Set[str] = set()
        domains: Set[str] = set()

        def _add_spiffe(val: Any, *, required: bool) -> None:
            if not isinstance(val, str) or not val.startswith("spiffe://"):
                return
            try:
                parsed = SpiffeId.parse(val)
                domains.add(parsed.trust_domain)
                if (
                    not parsed.path.startswith("/authority/")
                    and not parsed.path.startswith("/ns/sys/")
                    and not parsed.path.endswith(("/sa/e2e-user-gateway", "/sa/beta-user-gateway"))
                ):
                    if required:
                        req_workloads.add(parsed.uri)
                    else:
                        opt_workloads.add(parsed.uri)
            except IdentityError:
                pass

        def _add_sub(sub_val: Any) -> None:
            if isinstance(sub_val, str) and "@" in sub_val:
                td = sub_val.rsplit("@", 1)[1].strip().lower()
                if td:
                    domains.add(td)

        _add_spiffe(entry.node_spiffe_id, required=True)
        _add_sub(entry.sub)
        ad = entry.action_detail or {}

        if entry.event_type == AuditEventType.ROOT_MINT:
            if not bool(ad.get("consent_grant")) and not bool(ad.get("co_auth_consent")):
                _add_spiffe(ad.get("first_hop_spiffe_id"), required=True)
            else:
                _add_spiffe(ad.get("first_hop_spiffe_id"), required=False)
        elif entry.event_type == AuditEventType.OUTBOUND_DELEGATE:
            _add_spiffe(ad.get("target_spiffe_id"), required=True)
            _add_spiffe(ad.get("delegate_spiffe_id"), required=True)
        else:
            _add_spiffe(ad.get("delegate_spiffe_id"), required=True)
            _add_spiffe(ad.get("target_spiffe_id"), required=True)

        _add_spiffe(ad.get("substitute_delegate_spiffe_id"), required=True)
        _add_spiffe(ad.get("failed_delegate_spiffe_id"), required=False)

        raw_co = ad.get("co_authorized_principals")
        if isinstance(raw_co, list):
            for p in raw_co:
                _add_sub(p)
        if isinstance(ad.get("trust_domain"), str) and ad.get("trust_domain"):
            domains.add(str(ad["trust_domain"]).strip().lower())

        rp = entry.receipt_payload or {}
        for rk in (
            "parent_spiffe_id",
            "substitute_delegate_spiffe_id",
            "leaf_spiffe_id",
            "child_spiffe_id",
            "target_ancestor_spiffe_id",
        ):
            _add_spiffe(rp.get(rk), required=True)
        _add_spiffe(rp.get("failed_delegate_spiffe_id"), required=False)
        for sk in (rp.get("skipped_spiffe_ids") or rp.get("skipped_ancestors") or ()):
            _add_spiffe(sk, required=False)

        opt_workloads -= req_workloads
        return req_workloads, opt_workloads, domains

    def pull_and_reconstruct(
        self,
        task_id: str,
        entry_spiffe_ids: Iterable[str] = (),
        entry_urls: Optional[Mapping[str, Sequence[str] | str]] = None,
        seed_domains: Iterable[str] = (),
        discover_all_registered_peers: bool = False,
    ) -> DistributedAuditResult:
        """Execute bounded BFS pull across CAs + peer Sidecars for `task_id` and verify DAG."""
        clean_task = str(task_id or "").strip()
        if not clean_task:
            raise ValueError("DistributedAuditor.pull_and_reconstruct requires non-empty task_id")

        t0 = time.perf_counter()
        card_cache: Dict[str, List[str]] = {}
        queue: Deque[Tuple[str, List[str], Optional[str], Optional[str], int]] = deque()
        queued_keys: Set[str] = set()
        required_nodes: Set[str] = set()
        pull_anomalies: List[AuditAnomaly] = []
        bfs_truncated = False

        def _enqueue_domain_ca(td: str, depth: int, *, required: bool = False) -> None:
            nonlocal bfs_truncated
            clean_td = str(td or "").strip().lower()
            if not clean_td:
                return
            key = f"ca:{clean_td}"
            cands = self._resolve_domain_ca_candidates(clean_td)
            if not cands:
                return
            if required:
                required_nodes.add(key)
            if key in queued_keys:
                return
            if depth > self.max_depth:
                bfs_truncated = True
                pull_anomalies.append(
                    AuditAnomaly(
                        code=f"MAX_AUDIT_BFS_DEPTH_EXCEEDED:{key}",
                        task_id=clean_task,
                        stream_id="distributed-auditor",
                        stream_seq=0,
                        detail=f"BFS depth {depth} exceeds max_depth={self.max_depth}",
                    )
                )
                return
            if len(queued_keys) >= self.max_nodes:
                if required:
                    bfs_truncated = True
                    pull_anomalies.append(
                        AuditAnomaly(
                            code=f"MAX_AUDIT_NODES_EXCEEDED:{key}",
                            task_id=clean_task,
                            stream_id="distributed-auditor",
                            stream_seq=0,
                            detail=f"Reached max_nodes={self.max_nodes} before querying {key}",
                        )
                    )
                return
            queued_keys.add(key)
            queue.append((key, cands, clean_td, None, depth))

        def _enqueue_workload(
            sid: str,
            depth: int,
            *,
            required: bool = True,
            explicit_urls: Optional[Sequence[str]] = None,
        ) -> None:
            nonlocal bfs_truncated
            try:
                parsed = SpiffeId.parse(str(sid))
            except IdentityError:
                return
            _enqueue_domain_ca(parsed.trust_domain, depth, required=required)
            if parsed.path.startswith("/authority/") or parsed.path.startswith("/ns/sys/"):
                return
            key = parsed.uri
            if required:
                required_nodes.add(key)
            if key in queued_keys:
                return
            if depth > self.max_depth:
                bfs_truncated = True
                pull_anomalies.append(
                    AuditAnomaly(
                        code=f"MAX_AUDIT_BFS_DEPTH_EXCEEDED:{key}",
                        task_id=clean_task,
                        stream_id="distributed-auditor",
                        stream_seq=0,
                        detail=f"BFS depth {depth} exceeds max_depth={self.max_depth}",
                    )
                )
                return
            if len(queued_keys) >= self.max_nodes:
                if required:
                    bfs_truncated = True
                    pull_anomalies.append(
                        AuditAnomaly(
                            code=f"MAX_AUDIT_NODES_EXCEEDED:{key}",
                            task_id=clean_task,
                            stream_id="distributed-auditor",
                            stream_seq=0,
                            detail=f"Reached max_nodes={self.max_nodes} before querying {key}",
                        )
                    )
                return
            cands = (
                [str(x).rstrip("/") for x in explicit_urls if str(x).strip()]
                if explicit_urls
                else self._resolve_workload_candidates(parsed.uri, card_cache)
            )
            queued_keys.add(key)
            queue.append((key, cands, parsed.trust_domain, parsed.uri, depth))

        # 1. Seed known domain CAs (from descriptor_store / domain_ca_urls / seed_domains)
        seed_td_set = {str(td).strip().lower() for td in seed_domains if str(td).strip()}
        for td in seed_domains:
            _enqueue_domain_ca(td, 0, required=True)
        for td in list(self._domain_ca_urls.keys()):
            _enqueue_domain_ca(td, 0, required=(td in seed_td_set))
        if self.descriptor_store is not None:
            try:
                snap = self.descriptor_store.snapshot()
                for td in snap.keys():
                    _enqueue_domain_ca(td, 0, required=(td in seed_td_set))
            except Exception:
                pass

        # 2. Seed entry workloads / explicit entry URLs
        for label, raw_u in (entry_urls or {}).items():
            u_list = [raw_u] if isinstance(raw_u, str) else list(raw_u)
            if label.startswith("spiffe://"):
                _enqueue_workload(label, 0, required=True, explicit_urls=u_list)
            elif label not in queued_keys and len(queued_keys) < self.max_nodes:
                required_nodes.add(label)
                queued_keys.add(label)
                queue.append(
                    (label, [str(x).rstrip("/") for x in u_list if str(x).strip()], None, None, 0)
                )

        for sid in entry_spiffe_ids:
            _enqueue_workload(sid, 0, required=True)

        if discover_all_registered_peers and self.directory_client is not None:
            try:
                for card in self.directory_client.discover(only_healthy=False):
                    card_cache[card.spiffe_id] = [
                        str(u).rstrip("/") for u in card.candidate_origins() if str(u).strip()
                    ]
                    _enqueue_workload(card.spiffe_id, 0, required=False)
            except Exception:
                pass

        # 3. Execute bounded BFS pull
        nodes_queried: List[str] = []
        unreachable_nodes: Dict[str, str] = {}
        deduped_entries: Dict[Tuple[str, int], AuditEntry] = {}

        while queue:
            node_key, cands, exp_td, exp_sid, cur_depth = queue.popleft()
            pulled, err = self._pull_node_local_entries(
                node_key=node_key,
                candidate_urls=cands,
                task_id=clean_task,
                expected_trust_domain=exp_td,
                expected_spiffe_id=exp_sid,
            )
            if err is not None or pulled is None:
                unreachable_nodes[node_key] = err or "unreachable"
                continue
            nodes_queried.append(node_key)
            for entry in pulled:
                if entry.task_id != clean_task:
                    continue
                deduped_entries[(entry.stream_id, entry.stream_seq)] = entry
                req_workloads, opt_workloads, ref_domains = self._extract_referenced_targets(entry)
                for r_td in sorted(ref_domains):
                    _enqueue_domain_ca(r_td, cur_depth + 1, required=True)
                for r_sid in sorted(req_workloads):
                    _enqueue_workload(r_sid, cur_depth + 1, required=True)
                for o_sid in sorted(opt_workloads):
                    _enqueue_workload(o_sid, cur_depth + 1, required=False)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        ordered_entries = sorted(
            deduped_entries.values(),
            key=lambda e: (e.timestamp, e.stream_id, e.stream_seq),
        )
        report = self.auditor.reconstruct(
            ordered_entries,
            task_id=clean_task,
            check_stream_continuity=False,
        )
        trec = report.tasks.get(clean_task)

        for unreach_key in sorted(unreachable_nodes.keys()):
            if unreach_key in required_nodes:
                pull_anomalies.append(
                    AuditAnomaly(
                        code=f"REQUIRED_AUDIT_NODE_UNREACHABLE:{unreach_key}",
                        task_id=clean_task,
                        stream_id="distributed-auditor",
                        stream_seq=0,
                        detail=f"Required audit participant {unreach_key!r} unreachable: {unreachable_nodes[unreach_key]}",
                    )
                )

        if pull_anomalies:
            report.anomalies.extend(pull_anomalies)
            if trec is not None:
                trec.anomalies.extend(pull_anomalies)
                trec.reconstructed_complete = False

        rec_ok = bool(
            trec is not None
            and trec.reconstructed_complete
            and report.stream_integrity_ok
            and not pull_anomalies
            and not bfs_truncated
        )
        return DistributedAuditResult(
            task_id=clean_task,
            nodes_queried=nodes_queried,
            unreachable_nodes=unreachable_nodes,
            total_entries=len(ordered_entries),
            pull_latency_ms=elapsed_ms,
            stream_integrity_ok=report.stream_integrity_ok,
            reconstructed_complete=rec_ok,
            reconstruction=trec,
            report=report,
            entries=ordered_entries,
        )
