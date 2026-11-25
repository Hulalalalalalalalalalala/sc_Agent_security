"""Independent Tamper-Evident Causal Chain Auditor (`CausalChainAuditor`).

Reconstructs 100% of concurrent interleaved multi-user / multi-branch authorization DAGs
purely from structured audit logs and federated public `TrustBundleResolver` keys.

Detects:
- `ENTRY_HASH_TAMPERED` / `PREV_HASH_CHAIN_BROKEN` / `STREAM_SEQ_GAP_OR_DUPLICATE`
- `NODE_SIGNATURE_INVALID`
- `MISSING_ROOT_ANCHOR`
- `CORRELATION_MISMATCH` (`modify_correlation` / `mix_record` cross-task contamination)
- `MISSING_OR_MODIFIED_PARENT_HOP` (`delete_hop` / `modify_parent` chain splicing)
- `CAUSAL_CYCLE` (cycles on ANY branch of single-chain or MultiParentToken DAGs)
- `PRIVILEGE_ESCALATION` (violation of P_{i} <= P_{i-1})
- `DPOP_REPLAY` (duplicate `dpop_jti` across distinct authorized requests)
- `ILLEGAL_FAILOVER_SPOOF` (forged `RevocationService` signature, unauthorized parent, or post-graft revocation)
- `ILLEGAL_SKIP_LEVEL_SPOOF` (foreign-root `SkipLevelReceipt` or invalid ancestry)

And cryptographically recognizes legitimate resilience transitions:
- `VERIFIED_FAILOVER_GRAFT`
- `VERIFIED_SKIP_LEVEL_MERGE`
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from lineage.audit.logger import AuditEntry, AuditEventType
from lineage.common.crypto import CryptoError, jws_verify_compact
from lineage.identity.spiffe import IdentityError, SpiffeId
from lineage.identity.trust_bundle import TrustBundleResolver
from lineage.protocol.lattice import LatticeError, PermissionLattice
from lineage.protocol.token import TokenError
from lineage.resilience.receipts import (
    FailoverReceipt,
    ResilienceError,
    SkipLevelReceipt,
)
from lineage.verifier.policy_verifier import LeafVerifier, VerificationMode


@dataclass(frozen=True)
class AuditAnomaly:
    """Structured security or integrity anomaly detected by CausalChainAuditor."""

    code: str
    task_id: str
    stream_id: str
    stream_seq: int
    detail: str


@dataclass
class TaskReconstruction:
    """Reconstructed causal authorization DAG and audit verdict for a single `task_id`."""

    task_id: str
    sub: Optional[str] = None
    root_block_hash: Optional[str] = None
    reconstructed_complete: bool = False
    lineage_paths_observed: List[str] = field(default_factory=list)
    verified_hops: int = 0
    tool_invocations_verified: int = 0
    resilience_classifications: List[str] = field(default_factory=list)
    anomalies: List[AuditAnomaly] = field(default_factory=list)


@dataclass
class AuditReport:
    """Summary report across all streams and concurrent tasks in an audit window."""

    total_entries: int
    streams_checked: int
    stream_integrity_ok: bool
    tasks: Dict[str, TaskReconstruction]
    anomalies: List[AuditAnomaly]

    @property
    def clean(self) -> bool:
        return len(self.anomalies) == 0 and all(
            t.reconstructed_complete for t in self.tasks.values()
        )

    @property
    def reconstruction_rate(self) -> Tuple[int, int]:
        """Return (reconstructed_tasks_numerator, total_tasks_denominator)."""
        total = len(self.tasks)
        ok = sum(1 for t in self.tasks.values() if t.reconstructed_complete)
        return ok, total


class CausalChainAuditor:
    """Stateless cryptographic and causal verifier for LCT audit logs."""

    def __init__(
        self,
        trust_resolver: TrustBundleResolver,
        trusted_revocation_spiffe_ids: Optional[Iterable[str]] = None,
    ) -> None:
        self.trust_resolver = trust_resolver
        self.trusted_revocation_spiffe_ids: Optional[Tuple[str, ...]] = (
            tuple(trusted_revocation_spiffe_ids)
            if trusted_revocation_spiffe_ids is not None
            else None
        )
        self._chain_verifier = LeafVerifier(
            self_spiffe_id="spiffe://auditor.local/ns/audit/sa/verifier",
            trust_resolver=trust_resolver,
            mode=VerificationMode.LOCAL_FULL_CHAIN,
        )

    def _verify_entry_signature(self, entry: AuditEntry) -> Optional[str]:
        """Verify entry_hash and node_signature against TrustBundleResolver."""
        expected_hash = entry.compute_expected_hash()
        if entry.entry_hash != expected_hash:
            return (
                f"entry_hash mismatch: expected {expected_hash!r}, got {entry.entry_hash!r}"
            )

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
                node_jwk = svid_claims["cnf"]["jwk"]
                _, signed_payload = jws_verify_compact(
                    entry.node_signature,
                    node_jwk,
                    expected_typ="lct-audit-sig+jwt",
                )
            else:
                return f"Unknown audit auth_mode: {entry.auth_mode!r}"
        except (IdentityError, CryptoError) as exc:
            return f"Cryptographic signature invalid: {exc}"

        if (
            signed_payload.get("stream_id") != entry.stream_id
            or signed_payload.get("stream_seq") != entry.stream_seq
            or signed_payload.get("entry_hash") != entry.entry_hash
        ):
            return "Signed audit header does not match (stream_id, stream_seq, entry_hash)"

        return None

    def audit(
        self,
        entries: Iterable[AuditEntry],
        check_stream_continuity: bool = True,
    ) -> AuditReport:
        all_entries = list(entries)
        anomalies: List[AuditAnomaly] = []

        # ---------------------------------------------------------------------
        # Phase 1: Per-Stream Forward SHA-256 Hash Chain & Signature Check
        # ---------------------------------------------------------------------
        by_stream: Dict[str, List[AuditEntry]] = {}
        for e in all_entries:
            by_stream.setdefault(e.stream_id, []).append(e)

        stream_ok = True
        for stream_id, s_entries in sorted(by_stream.items()):
            s_entries.sort(key=lambda x: x.stream_seq)
            expected_seq = 0
            expected_prev = "GENESIS"
            slice_prev_seq: Optional[int] = None
            slice_prev_hash: Optional[str] = None

            for item in s_entries:
                sig_err = self._verify_entry_signature(item)
                if sig_err is not None:
                    stream_ok = False
                    code = (
                        "ENTRY_HASH_TAMPERED"
                        if "entry_hash mismatch" in sig_err
                        else "NODE_SIGNATURE_INVALID"
                    )
                    anomalies.append(
                        AuditAnomaly(
                            code=code,
                            task_id=item.task_id,
                            stream_id=stream_id,
                            stream_seq=item.stream_seq,
                            detail=sig_err,
                        )
                    )

                if check_stream_continuity:
                    if item.stream_seq != expected_seq:
                        stream_ok = False
                        anomalies.append(
                            AuditAnomaly(
                                code="STREAM_SEQ_GAP_OR_DUPLICATE",
                                task_id=item.task_id,
                                stream_id=stream_id,
                                stream_seq=item.stream_seq,
                                detail=f"Expected stream_seq={expected_seq}, got {item.stream_seq} (deleted or duplicated log entry)",
                            )
                        )
                    if item.prev_entry_hash != expected_prev:
                        stream_ok = False
                        anomalies.append(
                            AuditAnomaly(
                                code="PREV_HASH_CHAIN_BROKEN",
                                task_id=item.task_id,
                                stream_id=stream_id,
                                stream_seq=item.stream_seq,
                                detail=f"prev_entry_hash={item.prev_entry_hash!r} != previous entry_hash={expected_prev!r}",
                            )
                        )
                    expected_seq = item.stream_seq + 1
                    expected_prev = item.entry_hash
                else:
                    if slice_prev_seq is not None:
                        if item.stream_seq <= slice_prev_seq:
                            stream_ok = False
                            anomalies.append(
                                AuditAnomaly(
                                    code="STREAM_SEQ_GAP_OR_DUPLICATE",
                                    task_id=item.task_id,
                                    stream_id=stream_id,
                                    stream_seq=item.stream_seq,
                                    detail=f"Duplicate/out-of-order stream_seq={item.stream_seq} after {slice_prev_seq}",
                                )
                            )
                        elif (
                            item.stream_seq == slice_prev_seq + 1
                            and item.prev_entry_hash != slice_prev_hash
                        ):
                            stream_ok = False
                            anomalies.append(
                                AuditAnomaly(
                                    code="PREV_HASH_CHAIN_BROKEN",
                                    task_id=item.task_id,
                                    stream_id=stream_id,
                                    stream_seq=item.stream_seq,
                                    detail=f"Contiguous prev_entry_hash={item.prev_entry_hash!r} != {slice_prev_hash!r}",
                                )
                            )
                    slice_prev_seq = item.stream_seq
                    slice_prev_hash = item.entry_hash

        # ---------------------------------------------------------------------
        # Phase 2: Global DPoP Replay Detection across INBOUND_AUTHZ events
        # ---------------------------------------------------------------------
        seen_dpop_jtis: Dict[str, AuditEntry] = {}
        for item in all_entries:
            if (
                item.event_type == AuditEventType.INBOUND_AUTHZ
                and item.decision.startswith("ALLOW")
                and item.dpop_jti
            ):
                if item.dpop_jti in seen_dpop_jtis:
                    first = seen_dpop_jtis[item.dpop_jti]
                    anomalies.append(
                        AuditAnomaly(
                            code="DPOP_REPLAY",
                            task_id=item.task_id,
                            stream_id=item.stream_id,
                            stream_seq=item.stream_seq,
                            detail=(
                                f"Duplicate DPoP jti={item.dpop_jti!r} already used in "
                                f"task={first.task_id!r} stream={first.stream_id!r}#{first.stream_seq}"
                            ),
                        )
                    )
                else:
                    seen_dpop_jtis[item.dpop_jti] = item

        # ---------------------------------------------------------------------
        # Phase 3: Per-Task Causal Authorization DAG Reconstruction
        # ---------------------------------------------------------------------
        by_task: Dict[str, List[AuditEntry]] = {}
        revocation_earliest_ts: Dict[Tuple[Optional[str], str], float] = {}
        for item in all_entries:
            if item.event_type == AuditEventType.REVOCATION_ISSUED:
                target = str(item.action_detail.get("target", item.lineage_path))
                raw_ev_td = item.action_detail.get("trust_domain")
                if isinstance(raw_ev_td, str) and raw_ev_td:
                    ev_td: Optional[str] = raw_ev_td
                else:
                    try:
                        ev_td = SpiffeId.parse(item.node_spiffe_id).trust_domain
                    except IdentityError:
                        ev_td = None
                rev_key = (ev_td, target)
                prev_ts = revocation_earliest_ts.get(rev_key)
                if prev_ts is None or item.timestamp < prev_ts:
                    revocation_earliest_ts[rev_key] = item.timestamp
            if item.task_id == "_SYSTEM":
                continue
            by_task.setdefault(item.task_id, []).append(item)

        task_reports: Dict[str, TaskReconstruction] = {}

        for task_id, t_entries in sorted(by_task.items()):
            t_entries.sort(key=lambda x: (x.timestamp, x.stream_seq))
            rec = TaskReconstruction(task_id=task_id)
            task_reports[task_id] = rec

            def _flag(code: str, entry: AuditEntry, detail: str) -> None:
                anom = AuditAnomaly(
                    code=code,
                    task_id=task_id,
                    stream_id=entry.stream_id,
                    stream_seq=entry.stream_seq,
                    detail=detail,
                )
                rec.anomalies.append(anom)
                anomalies.append(anom)

            # 3.1 Locate ROOT_MINT anchor(s), including verified Continuations & Dual-Principal Co-Auth
            roots = [e for e in t_entries if e.event_type == AuditEventType.ROOT_MINT]
            authorized_root_hashes: Set[str] = set()
            authorized_subs: Set[str] = set()
            root_entry_by_hash: Dict[str, AuditEntry] = {}

            co_auth_owner_subs: Set[str] = set()
            for e_scan in t_entries:
                if e_scan.decision.startswith("ALLOW"):
                    raw_cp = (e_scan.action_detail or {}).get("co_authorized_principals")
                    if isinstance(raw_cp, list) and len(raw_cp) == 2:
                        co_auth_owner_subs.add(str(raw_cp[1]))

            if not roots:
                _flag(
                    "MISSING_ROOT_ANCHOR",
                    t_entries[0],
                    f"Task {task_id!r} has no ROOT_MINT authorization anchor (possible delete_hop or modify_parent orphan)",
                )
            else:
                primary_root = roots[0]
                for cand_r in roots:
                    if not (cand_r.action_detail or {}).get("co_auth_consent") and not (
                        cand_r.action_detail or {}
                    ).get("resumes_checkpoint_id"):
                        primary_root = cand_r
                        break
                rec.root_block_hash = primary_root.current_block_hash
                rec.sub = primary_root.sub
                authorized_root_hashes.add(primary_root.current_block_hash)
                authorized_subs.add(primary_root.sub)
                root_entry_by_hash[primary_root.current_block_hash] = primary_root

                seen_continuation_ckpts: Set[str] = set()
                seen_continuation_priors: Set[str] = set()
                for r in roots:
                    if r.current_block_hash in authorized_root_hashes:
                        continue
                    r_ad = r.action_detail or {}
                    ckpt_id = str(r_ad.get("resumes_checkpoint_id") or "").strip()
                    prior_h = str(
                        r_ad.get("prior_root_block_hash") or r.parent_block_hash or ""
                    ).strip()
                    if (
                        ckpt_id
                        and prior_h in authorized_root_hashes
                        and r.sub == primary_root.sub
                    ):
                        cont_dup_or_fork = False
                        if ckpt_id in seen_continuation_ckpts:
                            cont_dup_or_fork = True
                            _flag(
                                f"DUPLICATE_CHECKPOINT_CONTINUATION:{ckpt_id}",
                                r,
                                f"Duplicate continuation ROOT_MINT replaying checkpoint {ckpt_id!r}",
                            )
                        else:
                            seen_continuation_ckpts.add(ckpt_id)

                        if prior_h in seen_continuation_priors:
                            cont_dup_or_fork = True
                            _flag(
                                f"FORKED_CONTINUATION_ROOT:{prior_h}",
                                r,
                                f"Forked sibling continuation ROOT_MINT off superseded prior root {prior_h!r}",
                            )
                        else:
                            seen_continuation_priors.add(prior_h)

                        prior_r = root_entry_by_hash.get(prior_h)
                        if (
                            prior_r is not None
                            and prior_r.permissions_summary is not None
                            and r.permissions_summary is not None
                        ):
                            try:
                                p_lat = PermissionLattice.from_dict(prior_r.permissions_summary)
                                c_lat = PermissionLattice.from_dict(r.permissions_summary)
                                c_amt = float(r_ad.get("consumed_amount", 0.0))
                                c_calls = int(r_ad.get("consumed_calls", 0))
                                if p_lat.max_amount is not None and (
                                    c_lat.max_amount is None
                                    or c_lat.max_amount > float(p_lat.max_amount) - c_amt + 1e-6
                                ):
                                    _flag(
                                        "PRIVILEGE_ESCALATION",
                                        r,
                                        f"Continuation root max_amount={c_lat.max_amount} exceeds remaining {float(p_lat.max_amount) - c_amt}",
                                    )
                                if c_lat.max_calls > int(p_lat.max_calls) - c_calls:
                                    _flag(
                                        "PRIVILEGE_ESCALATION",
                                        r,
                                        f"Continuation root max_calls={c_lat.max_calls} exceeds remaining {int(p_lat.max_calls) - c_calls}",
                                    )
                            except (LatticeError, ValueError, TypeError) as exc:
                                _flag("PRIVILEGE_ESCALATION", r, str(exc))
                        if not cont_dup_or_fork:
                            authorized_root_hashes.add(r.current_block_hash)
                            root_entry_by_hash[r.current_block_hash] = r
                            rec.resilience_classifications.append("VERIFIED_TASK_CONTINUATION")
                    elif r.sub != primary_root.sub and (
                        bool(r_ad.get("co_auth_consent")) or r.sub in co_auth_owner_subs
                    ):
                        authorized_root_hashes.add(r.current_block_hash)
                        authorized_subs.add(r.sub)
                        root_entry_by_hash[r.current_block_hash] = r
                        rec.resilience_classifications.append("VERIFIED_DUAL_PRINCIPAL_COAUTH")
                    else:
                        _flag(
                            "CORRELATION_MISMATCH",
                            r,
                            f"Multiple conflicting ROOT_MINT blocks for task {task_id!r}",
                        )

            task_root_td: Optional[str] = None
            if rec.root_block_hash and rec.root_block_hash in root_entry_by_hash:
                try:
                    task_root_td = SpiffeId.parse(
                        root_entry_by_hash[rec.root_block_hash].node_spiffe_id
                    ).trust_domain
                except IdentityError:
                    task_root_td = None

            # 3.2 Build block transition table: block_hash -> producer entry (`ROOT_MINT` or `OUTBOUND_DELEGATE`)
            block_producers: Dict[str, AuditEntry] = {}
            for r in roots:
                block_producers[r.current_block_hash] = r

            for e in t_entries:
                if (
                    e.event_type == AuditEventType.OUTBOUND_DELEGATE
                    and e.decision.startswith("ALLOW")
                ):
                    existing_prod = block_producers.get(e.current_block_hash)
                    if existing_prod is None:
                        block_producers[e.current_block_hash] = e

            verified_root_memo: Set[str] = set()

            def _trace_all_paths_to_root(
                start_hash: str,
                active_stack: Set[str],
            ) -> Tuple[bool, Optional[str], Optional[str]]:
                """Complete DFS across ALL single, Continuation, CoAuth & MultiParent branches back to ROOT_MINT."""
                if start_hash in verified_root_memo:
                    return True, None, None
                if start_hash in active_stack:
                    return (
                        False,
                        "CAUSAL_CYCLE",
                        f"Cycle in block hash ancestry at {start_hash!r}",
                    )
                if len(active_stack) > 64:
                    return (
                        False,
                        "MISSING_OR_MODIFIED_PARENT_HOP",
                        f"Ancestry depth exceeded 64 hops from {start_hash!r}",
                    )
                prod = block_producers.get(start_hash)
                if prod is None:
                    return (
                        False,
                        "MISSING_OR_MODIFIED_PARENT_HOP",
                        f"Referenced block {start_hash!r} has no valid causal producer",
                    )

                if prod.event_type == AuditEventType.ROOT_MINT and prod.hop_index == 0:
                    if authorized_root_hashes and start_hash not in authorized_root_hashes:
                        return (
                            False,
                            "CORRELATION_MISMATCH",
                            f"Ancestry reached unauthorized foreign root {start_hash!r}",
                        )
                    verified_root_memo.add(start_hash)
                    return True, None, None

                next_stack = set(active_stack)
                next_stack.add(start_hash)

                if prod.multi_parent_hashes:
                    for mph in prod.multi_parent_hashes:
                        ok, err_code, err_detail = _trace_all_paths_to_root(
                            mph, next_stack
                        )
                        if not ok:
                            return False, err_code, err_detail
                    verified_root_memo.add(start_hash)
                    return True, None, None

                if not prod.parent_block_hash:
                    return (
                        False,
                        "MISSING_OR_MODIFIED_PARENT_HOP",
                        f"Non-root block {start_hash!r} missing parent_block_hash",
                    )

                ok, err_code, err_detail = _trace_all_paths_to_root(
                    prod.parent_block_hash, next_stack
                )
                if ok:
                    verified_root_memo.add(start_hash)
                return ok, err_code, err_detail

            # 3.3 Check every entry for task correlation, lineage prefix, parent causal link, and lattice monotonicity
            observed_paths: Set[str] = set()

            for e in t_entries:
                if e.event_type != AuditEventType.REVOCATION_ISSUED:
                    if authorized_root_hashes and e.root_block_hash not in authorized_root_hashes:
                        _flag(
                            "CORRELATION_MISMATCH",
                            e,
                            f"root_block_hash {e.root_block_hash!r} not in authorized task roots {sorted(authorized_root_hashes)} (mix_record / modify_parent)",
                        )
                    if authorized_subs and e.sub not in authorized_subs:
                        _flag(
                            "CORRELATION_MISMATCH",
                            e,
                            f"Principal sub {e.sub!r} not in authorized task principals {sorted(authorized_subs)}",
                        )

                raw_paths = [p for p in e.lineage_path.split("|") if p]
                for p in raw_paths:
                    observed_paths.add(p)
                    if e.event_type == AuditEventType.REVOCATION_ISSUED:
                        if p != f"/{task_id}" and not p.startswith(f"/{task_id}/"):
                            _flag(
                                "CORRELATION_MISMATCH",
                                e,
                                f"Revocation path {p!r} does not match task {task_id!r}",
                            )
                    else:
                        if not p.startswith(f"/{task_id}/"):
                            _flag(
                                "CORRELATION_MISMATCH",
                                e,
                                f"lineage_path {p!r} does not start with '/{task_id}/' (modify_correlation / mix_record)",
                            )

                if (
                    e.event_type == AuditEventType.OUTBOUND_DELEGATE
                    and e.decision.startswith("ALLOW")
                ):
                    if e.multi_parent_hashes:
                        for mph in e.multi_parent_hashes:
                            ok_mp, code_mp, det_mp = _trace_all_paths_to_root(mph, set())
                            if not ok_mp and code_mp and det_mp:
                                _flag(code_mp, e, det_mp)
                    elif e.hop_index >= 1 and block_producers.get(e.current_block_hash) == e:
                        if not e.parent_block_hash or e.parent_block_hash not in block_producers:
                            _flag(
                                "MISSING_OR_MODIFIED_PARENT_HOP",
                                e,
                                f"Hop {e.hop_index} ({e.lineage_path}) parent_block_hash={e.parent_block_hash!r} missing from causal graph (delete_hop / modify_parent)",
                            )
                        else:
                            parent_prod = block_producers[e.parent_block_hash]
                            if parent_prod.hop_index != e.hop_index - 1:
                                _flag(
                                    "MISSING_OR_MODIFIED_PARENT_HOP",
                                    e,
                                    f"Hop index discontinuity: parent hop={parent_prod.hop_index}, child hop={e.hop_index}",
                                )
                            if not e.lineage_path.startswith(parent_prod.lineage_path + "/"):
                                _flag(
                                    "MISSING_OR_MODIFIED_PARENT_HOP",
                                    e,
                                    f"Child path {e.lineage_path!r} does not extend parent {parent_prod.lineage_path!r}",
                                )
                            if (
                                e.permissions_summary is not None
                                and parent_prod.permissions_summary is not None
                            ):
                                try:
                                    child_lat = PermissionLattice.from_dict(
                                        e.permissions_summary
                                    )
                                    parent_lat = PermissionLattice.from_dict(
                                        parent_prod.permissions_summary
                                    )
                                    viol = child_lat.explain_violation_against(parent_lat)
                                    if viol is not None:
                                        _flag(
                                            "PRIVILEGE_ESCALATION",
                                            e,
                                            f"Lattice escalation on {e.lineage_path}: {viol}",
                                        )
                                except LatticeError as exc:
                                    _flag("PRIVILEGE_ESCALATION", e, str(exc))

                # Trace INBOUND_AUTHZ (ALLOW*) and TOOL_INVOCATION (ALLOW*) across ALL branches to ROOT_MINT
                if e.event_type in (
                    AuditEventType.INBOUND_AUTHZ,
                    AuditEventType.TOOL_INVOCATION,
                ) and e.decision.startswith("ALLOW"):
                    hashes_to_trace = (
                        list(e.multi_parent_hashes)
                        if e.multi_parent_hashes
                        else [e.current_block_hash]
                    )
                    all_traced = True
                    for leaf_h in hashes_to_trace:
                        ok_t, code_t, det_t = _trace_all_paths_to_root(leaf_h, set())
                        if not ok_t:
                            all_traced = False
                            _flag(
                                code_t or "MISSING_OR_MODIFIED_PARENT_HOP",
                                e,
                                f"Event {e.event_type.value} at {e.lineage_path}: {det_t}",
                            )

                    if all_traced:
                        if e.event_type == AuditEventType.INBOUND_AUTHZ:
                            rec.verified_hops += 1
                        elif e.event_type == AuditEventType.TOOL_INVOCATION:
                            rec.tool_invocations_verified += 1
                        if (
                            e.decision == "ALLOW_DEGRADED_DAG"
                            and "SMOOTH_DAG_DEGRADATION_ON_REVOCATION"
                            not in rec.resilience_classifications
                        ):
                            rec.resilience_classifications.append(
                                "SMOOTH_DAG_DEGRADATION_ON_REVOCATION"
                            )

                # Verify cryptographic Resilience Receipts (`[HIGH-04]`)
                if e.event_type == AuditEventType.FAILOVER_PRUNE_GRAFT:
                    if not e.receipt_payload:
                        _flag("ILLEGAL_FAILOVER_SPOOF", e, "Missing FailoverReceipt")
                    else:
                        try:
                            fr = FailoverReceipt.from_dict_and_verify(
                                e.receipt_payload,
                                self.trust_resolver,
                                trusted_revocation_spiffe_ids=self.trusted_revocation_spiffe_ids,
                                expected_trust_domain=task_root_td,
                            )
                            expected_parent_coord = fr.pruned_lineage_path.rsplit("/", 1)[0]
                            # Confirm `fr.parent_spiffe_id` is an authorized causal parent in `block_producers`
                            parent_anchored = False
                            if e.parent_block_hash and e.parent_block_hash in block_producers:
                                p_entry = block_producers[e.parent_block_hash]
                                ok_p, _, _ = _trace_all_paths_to_root(
                                    e.parent_block_hash, set()
                                )
                                if (
                                    ok_p
                                    and p_entry.lineage_path == expected_parent_coord
                                    and e.node_spiffe_id == fr.parent_spiffe_id
                                ):
                                    parent_anchored = True

                            rev_ts = revocation_earliest_ts.get(
                                (task_root_td, fr.pruned_lineage_path)
                            )
                            if rev_ts is None and task_root_td is not None:
                                rev_ts = revocation_earliest_ts.get(
                                    (None, fr.pruned_lineage_path)
                                )
                            if fr.task_id != task_id:
                                _flag(
                                    "ILLEGAL_FAILOVER_SPOOF",
                                    e,
                                    "FailoverReceipt task_id mismatch",
                                )
                            elif not parent_anchored:
                                _flag(
                                    "ILLEGAL_FAILOVER_SPOOF",
                                    e,
                                    f"FailoverReceipt issuer {fr.parent_spiffe_id!r} is not a verified causal parent at {expected_parent_coord!r}",
                                )
                            elif rev_ts is None or rev_ts > e.timestamp + 0.05:
                                _flag(
                                    "ILLEGAL_FAILOVER_SPOOF",
                                    e,
                                    f"FailoverReceipt prune of {fr.pruned_lineage_path!r} missing or logged after graft",
                                )
                            else:
                                rec.resilience_classifications.append(
                                    "VERIFIED_FAILOVER_GRAFT"
                                )
                        except ResilienceError as exc:
                            _flag("ILLEGAL_FAILOVER_SPOOF", e, str(exc))

                if e.event_type == AuditEventType.SKIP_LEVEL_ACCEPT:
                    if not e.receipt_payload:
                        _flag("ILLEGAL_SKIP_LEVEL_SPOOF", e, "Missing SkipLevelReceipt")
                    else:
                        try:
                            raw_sr_ts = e.receipt_payload.get("timestamp", e.timestamp)
                            sr, embedded_tok = SkipLevelReceipt.from_dict_and_verify(
                                e.receipt_payload,
                                self.trust_resolver,
                                now=raw_sr_ts,
                            )
                            self._chain_verifier.verify_single_chain_full(
                                embedded_tok,
                                now=sr.timestamp,
                                check_revocation=False,
                            )
                            if (
                                sr.task_id != task_id
                                or sr.target_ancestor_spiffe_id != e.node_spiffe_id
                            ):
                                _flag(
                                    "ILLEGAL_SKIP_LEVEL_SPOOF",
                                    e,
                                    "SkipLevelReceipt target or task mismatch",
                                )
                            elif (
                                not authorized_root_hashes
                                or embedded_tok.root_block_hash not in authorized_root_hashes
                                or not authorized_subs
                                or embedded_tok.sub not in authorized_subs
                            ):
                                _flag(
                                    "ILLEGAL_SKIP_LEVEL_SPOOF",
                                    e,
                                    "SkipLevelReceipt embedded token root_block_hash or sub does not match task ROOT_MINT",
                                )
                            else:
                                rec.resilience_classifications.append(
                                    "VERIFIED_SKIP_LEVEL_MERGE"
                                )
                        except (ResilienceError, TokenError, CryptoError) as exc:
                            _flag("ILLEGAL_SKIP_LEVEL_SPOOF", e, str(exc))

            rec.lineage_paths_observed = sorted(observed_paths)
            task_stream_anoms = [
                a for a in anomalies if a.task_id == task_id and a not in rec.anomalies
            ]
            rec.anomalies.extend(task_stream_anoms)
            rec.reconstructed_complete = (
                len(roots) >= 1 and len(authorized_root_hashes) >= 1 and len(rec.anomalies) == 0
            )

        return AuditReport(
            total_entries=len(all_entries),
            streams_checked=len(by_stream),
            stream_integrity_ok=stream_ok,
            tasks=task_reports,
            anomalies=anomalies,
        )

    def reconstruct(
        self,
        entries: Iterable[AuditEntry],
        task_id: Optional[str] = None,
        check_stream_continuity: bool = False,
    ) -> AuditReport:
        """Reconstruct causal DAG for an on-demand federated pull slice (`task_id` optional filter)."""
        filtered = (
            [e for e in entries if e.task_id == task_id]
            if task_id
            else list(entries)
        )
        return self.audit(filtered, check_stream_continuity=check_stream_continuity)
