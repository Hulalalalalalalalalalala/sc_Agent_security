"""Autonomous Dual-Path Fault Recovery Coordinator.

Implements:
1. Downward `Atomic Prune-and-Graft`:
   - Detects Crash, Timeout, or genuine threshold-tripped Policy/Byzantine fault on child B_1
   - Atomically revokes `/<task_id>/.../B_1` at `RevocationService` using `authority_token`
   - Dynamically discovers healthy substitute B'_1 with equivalent `skill` from `AgentDirectoryService`
   - Mints `epoch + 1` attenuated branch to B'_1 and emits signed `FailoverReceipt` carrying
     the `RevocationService`-signed `RevocationEvent`
2. Upward `Authenticated Skip-Level Return`:
   - Downstream C completes sub-task, detects direct parent B_1 unreachable on return
   - Signs `SkipLevelReceipt` and delivers directly to surviving ancestor A
   - Ancestor A actively probes skipped intermediate parent(s)' `/healthz` liveness
     before accepting `SkipLevelReceipt` or pruning dead intermediate branches!
"""

from __future__ import annotations

import ssl
import time
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple
from urllib.parse import urlsplit

import httpx

from lineage.audit.logger import AuditEventType, AuditStreamEmitter
from lineage.common.http_utils import validate_origin_form_target
from lineage.common.mtls import WorkloadMTLSBundle
from lineage.identity.spiffe import WorkloadIdentity
from lineage.identity.trust_bundle import TrustBundleResolver
from lineage.protocol.dpop import DPoPError, JTIReplayCache, create_dpop_proof
from lineage.protocol.lattice import PermissionLattice
from lineage.protocol.token import (
    LineageToken,
    TokenError,
    validate_clean_endpoint_url,
)
from lineage.registry.agent_card import AgentCard
from lineage.registry.directory import AgentDirectoryClient
from lineage.resilience.detector import ThreeLayerFaultDetector
from lineage.resilience.receipts import (
    FailoverReceipt,
    FailureEvidence,
    FaultType,
    ResilienceError,
    SkipLevelReceipt,
)
from lineage.revocation.service import RevocationError, RevocationReplicaClient
from lineage.verifier.policy_verifier import LeafVerifier


class ResilientDelegationCoordinator:
    """Coordinates fault-tolerant downward delegation and upward skip-level return."""

    def __init__(
        self,
        identity: WorkloadIdentity,
        trust_resolver: TrustBundleResolver,
        directory_client: AgentDirectoryClient,
        revocation_replica: RevocationReplicaClient,
        audit_emitter: Optional[AuditStreamEmitter] = None,
        detector: Optional[ThreeLayerFaultDetector] = None,
        return_endpoint: Optional[str] = None,
        client_ssl_context: Optional[ssl.SSLContext] = None,
        mtls_bundle: Optional[WorkloadMTLSBundle] = None,
    ) -> None:
        self.identity = identity
        self.trust_resolver = trust_resolver
        self.directory_client = directory_client
        self.revocation_replica = revocation_replica
        self.audit_emitter = audit_emitter
        self.detector = detector or ThreeLayerFaultDetector()
        self.client_ssl_context = client_ssl_context
        self.mtls_bundle = mtls_bundle
        self.return_endpoint = (
            validate_clean_endpoint_url(return_endpoint, "return_endpoint")
            if return_endpoint is not None
            else None
        )

    def _verify_kwarg(
        self,
        target_url: Optional[str] = None,
        expected_spiffe_id: Optional[str] = None,
    ) -> Any:
        if self.mtls_bundle is not None:
            return self.mtls_bundle.verify_for_target(
                target_url=target_url,
                expected_spiffe_id=expected_spiffe_id,
            )
        return self.client_ssl_context if self.client_ssl_context is not None else True

    def invoke_with_prune_and_graft(
        self,
        parent_token: LineageToken,
        required_skill: str,
        attenuated_permissions: PermissionLattice,
        task_payload: Mapping[str, Any],
        primary_card: Optional[AgentCard] = None,
        task_path: str = "/a2a/task",
        timeout_seconds: float = 2.0,
        max_failovers: int = 2,
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> Tuple[Dict[str, Any], LineageToken, List[FailoverReceipt]]:
        """Delegate sub-task to a specialist; on fault, execute Atomic Prune-and-Graft."""
        attempted_spiffe_ids: Set[str] = set()
        receipts: List[FailoverReceipt] = []
        working_epoch = parent_token.current_epoch

        candidate = primary_card
        if candidate is None:
            discovered = self.directory_client.discover(
                skill=required_skill, only_healthy=True
            )
            if not discovered:
                raise ResilienceError(
                    f"No healthy agent found for skill={required_skill!r}"
                )
            candidate = discovered[0]

        for attempt_idx in range(max_failovers + 1):
            attempted_spiffe_ids.add(candidate.spiffe_id)
            seg_base = candidate.spiffe_id.rsplit("/", 1)[-1]
            hop_seg = seg_base if attempt_idx == 0 else f"{seg_base}-e{working_epoch}"

            child_token = parent_token.attenuate(
                issuer_identity=self.identity,
                delegate_spiffe_id=candidate.spiffe_id,
                delegate_jkt=candidate.jkt,
                permissions=attenuated_permissions,
                hop_segment=hop_seg,
                epoch=working_epoch,
                issuer_return_endpoint=self.return_endpoint,
            )
            compact_tok = child_token.encode_compact()
            try:
                tp_path, tp_query = validate_origin_form_target(task_path)
            except ValueError as exc:
                raise ResilienceError(f"Invalid delegation task_path {task_path!r}: {exc}") from exc
            clean_tp = tp_path + (f"?{tp_query}" if tp_query else "")
            cand_base = validate_clean_endpoint_url(candidate.endpoint, "candidate.endpoint")
            target_url = f"{cand_base.rstrip('/')}{clean_tp}"
            sp_b = urlsplit(cand_base)
            sp_t = urlsplit(target_url)
            if (sp_t.scheme, sp_t.hostname, sp_t.port) != (
                sp_b.scheme,
                sp_b.hostname,
                sp_b.port,
            ):
                raise ResilienceError(f"Target URL origin mismatch: {target_url!r}")
            dpop = create_dpop_proof(
                signer=self.identity,
                htm="POST",
                htu=target_url,
                access_token=compact_tok,
            )

            if self.audit_emitter is not None:
                self.audit_emitter.emit(
                    event_type=AuditEventType.OUTBOUND_DELEGATE,
                    task_id=child_token.task_id,
                    sub=child_token.sub,
                    lineage_path=child_token.lineage_path,
                    hop_index=child_token.depth,
                    epoch=child_token.current_epoch,
                    root_block_hash=child_token.root_block_hash,
                    parent_block_hash=child_token.parent_block_hash,
                    current_block_hash=child_token.leaf_block_hash,
                    permissions_summary=attenuated_permissions.to_dict(),
                    action_detail={
                        "delegate_spiffe_id": candidate.spiffe_id,
                        "skill": required_skill,
                        "target_url": target_url,
                    },
                    decision="ALLOW",
                )

            evidence: Optional[FailureEvidence] = None
            if self.detector.is_circuit_open(candidate.spiffe_id):
                evidence = self.detector.get_last_evidence(
                    candidate.spiffe_id
                ) or FailureEvidence(
                    failed_spiffe_id=candidate.spiffe_id,
                    failed_endpoint=target_url,
                    fault_type=FaultType.POLICY_BYZANTINE,
                    error_detail="Circuit breaker already open",
                    attempt_count=1,
                    observed_at=time.time(),
                )
            else:
                req_hdrs = {
                    "Authorization": f"DPoP {compact_tok}",
                    "DPoP": dpop,
                }
                if extra_headers:
                    req_hdrs.update({str(k): str(v) for k, v in extra_headers.items()})
                try:
                    with httpx.Client(
                        verify=self._verify_kwarg(
                            target_url=target_url,
                            expected_spiffe_id=candidate.spiffe_id,
                        ),
                        timeout=timeout_seconds,
                        follow_redirects=False,
                    ) as client:
                        resp = client.post(
                            target_url,
                            json=dict(task_payload),
                            headers=req_hdrs,
                        )
                    if 200 <= resp.status_code < 300:
                        self.detector.record_success(candidate.spiffe_id)
                        return resp.json(), child_token, receipts

                    # Record single genuine HTTP failure against detector (NO artificial while loop!)
                    evidence = self.detector.classify_http_failure(
                        spiffe_id=candidate.spiffe_id,
                        endpoint=target_url,
                        status_code=resp.status_code,
                        body_text=resp.text,
                    )
                    if evidence is None:
                        # Single transient 401/403 below `policy_breaker_threshold`:
                        # prune ONLY this task branch without tripping global quarantine!
                        evidence = FailureEvidence(
                            failed_spiffe_id=candidate.spiffe_id,
                            failed_endpoint=target_url,
                            fault_type=FaultType.CRASH,
                            error_detail=f"Transient HTTP {resp.status_code} (below policy breaker threshold): {resp.text[:160]}",
                            attempt_count=1,
                            observed_at=time.time(),
                        )
                except Exception as exc:
                    evidence = self.detector.classify_exception(
                        spiffe_id=candidate.spiffe_id,
                        endpoint=target_url,
                        exc=exc,
                    )

            assert evidence is not None

            # --- STEP 1: ATOMIC PRUNE (Presenting `authority_token` proving parent jurisdiction!) ---
            rev_ev = self.revocation_replica.revoke_prefix(
                caller=self.identity,
                prefix=child_token.lineage_path,
                reason=f"atomic_prune:{evidence.fault_type.value}",
                authority_token=compact_tok,
            )
            if self.audit_emitter is not None:
                self.audit_emitter.emit(
                    event_type=AuditEventType.REVOCATION_ISSUED,
                    task_id=child_token.task_id,
                    sub=child_token.sub,
                    lineage_path=child_token.lineage_path,
                    hop_index=child_token.depth,
                    epoch=child_token.current_epoch,
                    root_block_hash=child_token.root_block_hash,
                    parent_block_hash=child_token.parent_block_hash,
                    current_block_hash=child_token.leaf_block_hash,
                    action_detail={
                        "target": rev_ev.target,
                        "revocation_version": rev_ev.version,
                        "fault_type": evidence.fault_type.value,
                        "trust_domain": rev_ev.trust_domain,
                    },
                    decision="REVOKED",
                )

            # Only issue global workload quarantine when `policy_breaker_threshold` is genuinely tripped,
            # this node is a CA-attested Hop-0 Root Coordinator (`parent_token.depth == 0`),
            # AND candidate belongs to the same trust domain!
            if (
                parent_token.depth == 0
                and evidence.fault_type == FaultType.POLICY_BYZANTINE
                and self.detector.is_circuit_open(candidate.spiffe_id)
                and candidate.trust_domain == self.identity.trust_domain
            ):
                try:
                    self.revocation_replica.quarantine_workload(
                        caller=self.identity,
                        target_spiffe_id=candidate.spiffe_id,
                        reason="policy_circuit_breaker_tripped",
                        authority_token=compact_tok,
                    )
                    self.directory_client.quarantine(
                        reporter_identity=self.identity,
                        target_spiffe_id=candidate.spiffe_id,
                        reason="policy_circuit_breaker_tripped",
                        authority_token=compact_tok,
                    )
                except Exception:
                    pass

            if attempt_idx >= max_failovers:
                raise ResilienceError(
                    f"Exhausted max_failovers={max_failovers} for skill={required_skill!r}; last fault={evidence.to_dict()}"
                )

            # --- STEP 2: DYNAMIC SUBSTITUTE DISCOVERY ---
            substitutes = self.directory_client.discover(
                skill=required_skill,
                exclude_spiffe_ids=attempted_spiffe_ids,
                only_healthy=True,
            )
            if not substitutes:
                raise ResilienceError(
                    f"Pruned {child_token.lineage_path}, but no healthy substitute available for skill={required_skill!r}"
                )
            next_candidate = substitutes[0]

            # --- STEP 3: GRAFT AT EPOCH + 1 & EMIT SIGNED RECEIPT ---
            old_epoch = working_epoch
            working_epoch = old_epoch + 1
            next_seg_base = next_candidate.spiffe_id.rsplit("/", 1)[-1]
            planned_new_path = f"{parent_token.lineage_path}/{next_seg_base}-e{working_epoch}"

            receipt = FailoverReceipt.create_and_sign(
                parent_identity=self.identity,
                task_id=parent_token.task_id,
                pruned_lineage_path=child_token.lineage_path,
                revocation_version=rev_ev.version,
                revocation_event_sig=rev_ev.service_signature,
                failed_delegate_spiffe_id=candidate.spiffe_id,
                substitute_delegate_spiffe_id=next_candidate.spiffe_id,
                new_lineage_path=planned_new_path,
                old_epoch=old_epoch,
                new_epoch=working_epoch,
                failure_evidence=evidence,
                revocation_event=rev_ev.to_dict(),
                revocation_service_svid=rev_ev.service_svid
                or self.revocation_replica.last_service_svid,
            )
            receipts.append(receipt)

            if self.audit_emitter is not None:
                self.audit_emitter.emit(
                    event_type=AuditEventType.FAILOVER_PRUNE_GRAFT,
                    task_id=parent_token.task_id,
                    sub=parent_token.sub,
                    lineage_path=planned_new_path,
                    hop_index=parent_token.depth + 1,
                    epoch=working_epoch,
                    root_block_hash=parent_token.root_block_hash,
                    parent_block_hash=parent_token.leaf_block_hash,
                    current_block_hash=child_token.leaf_block_hash,
                    action_detail={
                        "pruned_path": child_token.lineage_path,
                        "failed_delegate": candidate.spiffe_id,
                        "substitute_delegate": next_candidate.spiffe_id,
                        "revocation_version": rev_ev.version,
                    },
                    decision="RECOVERED",
                    receipt_payload=receipt.to_dict(),
                )

            candidate = next_candidate

        raise ResilienceError("Unreachable failover loop termination")

    def return_result_with_skip_level_fallback(
        self,
        child_token: LineageToken,
        result_payload: Mapping[str, Any],
        direct_parent_return_url: Optional[str] = None,
        timeout_seconds: float = 1.5,
        simulate_direct_parent_unreachable: bool = False,
    ) -> Dict[str, Any]:
        """Deliver completed result to direct parent; if dead, execute Authenticated Skip-Level Return."""
        if not child_token.hops:
            raise ResilienceError("Root-hop agent has no upstream agent parent to skip")

        direct_hop = child_token.hops[-1]
        direct_parent_id = direct_hop.issuer_spiffe_id

        attested_bases: List[str] = []
        if direct_hop.issuer_return_endpoint:
            try:
                attested_bases.append(
                    validate_clean_endpoint_url(
                        direct_hop.issuer_return_endpoint, "issuer_return_endpoint"
                    )
                )
            except TokenError as exc:
                raise ResilienceError(f"Invalid hop issuer_return_endpoint: {exc}") from exc

        parent_card = self.directory_client.get_agent(direct_parent_id)
        if parent_card and parent_card.return_endpoint:
            try:
                card_ret = validate_clean_endpoint_url(
                    parent_card.return_endpoint, "parent_card.return_endpoint"
                )
                if card_ret not in attested_bases:
                    attested_bases.append(card_ret)
            except TokenError:
                pass

        if direct_parent_return_url is not None and str(direct_parent_return_url).strip():
            try:
                clean_override = validate_clean_endpoint_url(
                    str(direct_parent_return_url), "direct_parent_return_url"
                )
            except TokenError as exc:
                raise ResilienceError(f"Invalid direct_parent_return_url: {exc}") from exc
            if clean_override not in attested_bases:
                raise ResilienceError(
                    "Untrusted direct_parent_return_url override blocked: does not match "
                    "cryptographically attested hop or AgentCard return_endpoint"
                )
            parent_base: Optional[str] = clean_override
        else:
            parent_base = attested_bases[0] if attested_bases else None

        compact_tok = child_token.encode_compact()
        skipped_ids: List[str] = []
        primary_evidence: Optional[FailureEvidence] = None

        # 1. Try direct parent first (unless safe local unreachable simulation is requested,
        # which synthesizes local FailureEvidence WITHOUT sending any token over the network!)
        if simulate_direct_parent_unreachable:
            primary_evidence = FailureEvidence(
                failed_spiffe_id=direct_parent_id,
                failed_endpoint=parent_base or "simulated://direct-parent-unreachable",
                fault_type=FaultType.CRASH,
                error_detail="simulated_direct_parent_unreachable",
                attempt_count=1,
                observed_at=time.time(),
            )
        elif parent_base:
            base_sp = urlsplit(parent_base)
            direct_url = f"{parent_base.rstrip('/')}/v1/task-result"
            dir_sp = urlsplit(direct_url)
            if (dir_sp.scheme, dir_sp.hostname, dir_sp.port) != (
                base_sp.scheme,
                base_sp.hostname,
                base_sp.port,
            ):
                raise ResilienceError(f"Direct return URL origin mismatch: {direct_url!r}")
            dpop = create_dpop_proof(
                signer=self.identity,
                htm="POST",
                htu=direct_url,
                access_token=compact_tok,
            )
            try:
                with httpx.Client(
                    verify=self._verify_kwarg(
                        target_url=direct_url,
                        expected_spiffe_id=direct_parent_id,
                    ),
                    timeout=timeout_seconds,
                    follow_redirects=False,
                ) as client:
                    resp = client.post(
                        direct_url,
                        json={"task_id": child_token.task_id, "result": dict(result_payload)},
                        headers={
                            "Authorization": f"DPoP {compact_tok}",
                            "DPoP": dpop,
                        },
                    )
                if 200 <= resp.status_code < 300:
                    return {
                        "delivery_mode": "DIRECT_PARENT",
                        "delivered_to": direct_parent_id,
                        "response": resp.json(),
                    }
                primary_evidence = self.detector.classify_http_failure(
                    spiffe_id=direct_parent_id,
                    endpoint=direct_url,
                    status_code=resp.status_code,
                    body_text=resp.text,
                )
                if primary_evidence is None:
                    primary_evidence = FailureEvidence(
                        failed_spiffe_id=direct_parent_id,
                        failed_endpoint=direct_url,
                        fault_type=FaultType.CRASH,
                        error_detail=f"HTTP {resp.status_code}: {resp.text[:160]}",
                        attempt_count=1,
                        observed_at=time.time(),
                    )
            except Exception as exc:
                primary_evidence = self.detector.classify_exception(
                    spiffe_id=direct_parent_id,
                    endpoint=direct_url,
                    exc=exc,
                )
        else:
            primary_evidence = FailureEvidence(
                failed_spiffe_id=direct_parent_id,
                failed_endpoint="unknown",
                fault_type=FaultType.CRASH,
                error_detail="Direct parent return endpoint unavailable",
                attempt_count=1,
                observed_at=time.time(),
            )

        assert primary_evidence is not None
        skipped_ids.append(direct_parent_id)

        # 2. Walk upstream ancestors in reverse order (`ordered_delegates[:-2]` reversed)
        delegates = child_token.ordered_delegates
        upstream_candidates = list(reversed(delegates[:-2]))
        if not upstream_candidates:
            raise ResilienceError(
                f"Direct parent {direct_parent_id!r} failed and no higher ancestor exists in chain"
            )

        for anc_spiffe_id in upstream_candidates:
            anc_endpoint: Optional[str] = None
            if anc_spiffe_id in child_token.root.ancestor_keys:
                anc_endpoint = child_token.root.ancestor_keys[anc_spiffe_id].get(
                    "return_endpoint"
                )
            if not anc_endpoint:
                for h in child_token.hops:
                    if h.issuer_spiffe_id == anc_spiffe_id and h.issuer_return_endpoint:
                        anc_endpoint = h.issuer_return_endpoint
                        break
            if not anc_endpoint:
                anc_card = self.directory_client.get_agent(anc_spiffe_id)
                if anc_card:
                    anc_endpoint = anc_card.return_endpoint

            if not anc_endpoint:
                skipped_ids.append(anc_spiffe_id)
                continue

            skip_receipt = SkipLevelReceipt.create_and_sign(
                child_identity=self.identity,
                lineage_token=child_token,
                skipped_ancestors=skipped_ids,
                target_ancestor_spiffe_id=anc_spiffe_id,
                failure_evidence=primary_evidence,
                result_payload=result_payload,
            )

            skip_url = f"{anc_endpoint.rstrip('/')}/v1/skip-level-return"
            skip_dpop = create_dpop_proof(
                signer=self.identity,
                htm="POST",
                htu=skip_url,
                access_token=compact_tok,
            )

            if self.audit_emitter is not None:
                self.audit_emitter.emit(
                    event_type=AuditEventType.SKIP_LEVEL_RETURN,
                    task_id=child_token.task_id,
                    sub=child_token.sub,
                    lineage_path=child_token.lineage_path,
                    hop_index=child_token.depth,
                    epoch=child_token.current_epoch,
                    root_block_hash=child_token.root_block_hash,
                    parent_block_hash=child_token.parent_block_hash,
                    current_block_hash=child_token.leaf_block_hash,
                    action_detail={
                        "skipped_ancestors": list(skipped_ids),
                        "target_ancestor": anc_spiffe_id,
                        "result_sha256": skip_receipt.result_sha256,
                    },
                    decision="RECOVERED",
                    receipt_payload=skip_receipt.to_dict(),
                )

            try:
                with httpx.Client(
                    verify=self._verify_kwarg(
                        target_url=skip_url,
                        expected_spiffe_id=anc_spiffe_id,
                    ),
                    timeout=timeout_seconds,
                    follow_redirects=False,
                ) as client:
                    resp = client.post(
                        skip_url,
                        json={"skip_level_receipt": skip_receipt.to_dict()},
                        headers={
                            "Authorization": f"DPoP {compact_tok}",
                            "DPoP": skip_dpop,
                        },
                    )
                if 200 <= resp.status_code < 300:
                    return {
                        "delivery_mode": "SKIP_LEVEL_RETURN",
                        "delivered_to": anc_spiffe_id,
                        "skipped_ancestors": list(skipped_ids),
                        "receipt": skip_receipt.to_dict(),
                        "response": resp.json(),
                    }
            except Exception:
                pass

            skipped_ids.append(anc_spiffe_id)

        raise ResilienceError(
            f"All upstream ancestors unreachable during Skip-Level Return: skipped={skipped_ids}"
        )


def _resolve_trusted_skipped_endpoints(
    token: LineageToken,
    skipped_spiffe_id: str,
    directory_client: Optional[AgentDirectoryClient] = None,
) -> List[str]:
    """Resolve cryptographically attested clean origin endpoints for `skipped_spiffe_id`."""
    urls: List[str] = []

    def _add_clean(candidate_url: Optional[str], source_label: str) -> None:
        if not candidate_url:
            return
        try:
            clean = validate_clean_endpoint_url(str(candidate_url), source_label)
        except TokenError as exc:
            raise ResilienceError(f"Rejected unsafe endpoint in {source_label}: {exc}") from exc
        if clean not in urls:
            urls.append(clean)

    anc_info = token.root.ancestor_keys.get(skipped_spiffe_id)
    if isinstance(anc_info, Mapping) and anc_info.get("return_endpoint"):
        _add_clean(str(anc_info["return_endpoint"]), "ancestor_keys.return_endpoint")

    for hop in token.hops:
        if hop.issuer_spiffe_id == skipped_spiffe_id and hop.issuer_return_endpoint:
            _add_clean(hop.issuer_return_endpoint, "hop.issuer_return_endpoint")

    if directory_client is not None:
        try:
            card = directory_client.get_agent(skipped_spiffe_id)
            if card is not None:
                _add_clean(card.endpoint, "AgentCard.endpoint")
                _add_clean(card.return_endpoint, "AgentCard.return_endpoint")
        except ResilienceError:
            raise
        except Exception:
            pass
    return urls


def verify_and_accept_skip_level_request(
    ancestor_identity: WorkloadIdentity,
    ancestor_verifier: LeafVerifier,
    raw_receipt: Mapping[str, Any],
    dpop_proof: Optional[str],
    htm: str,
    htu: str,
    audit_emitter: Optional[AuditStreamEmitter] = None,
    revocation_replica: Optional[RevocationReplicaClient] = None,
    directory_client: Optional[AgentDirectoryClient] = None,
    receipt_replay_cache: Optional[JTIReplayCache] = None,
    max_receipt_age_seconds: float = 120.0,
    liveness_probe_timeout: float = 0.8,
    prune_dead_intermediate: bool = True,
    client_ssl_context: Optional[ssl.SSLContext] = None,
    mtls_bundle: Optional[WorkloadMTLSBundle] = None,
) -> Tuple[SkipLevelReceipt, LineageToken]:
    """Ancestor-side cryptographic & active liveness verification of `SkipLevelReceipt`."""
    now_ts = time.time()
    receipt, embedded_token = SkipLevelReceipt.from_dict_and_verify(
        raw_receipt, ancestor_verifier.trust_resolver, now=now_ts
    )

    if receipt.target_ancestor_spiffe_id != ancestor_identity.spiffe_id:
        raise ResilienceError(
            f"SkipLevelReceipt addressed to {receipt.target_ancestor_spiffe_id!r}, not self {ancestor_identity.spiffe_id!r}"
        )
    if receipt.target_ancestor_jkt != ancestor_identity.jkt:
        raise ResilienceError("SkipLevelReceipt target_ancestor_jkt mismatch with self")

    # Enforce SkipLevelReceipt timestamp freshness & anti-replay
    if receipt.timestamp > now_ts + 5.0:
        raise ResilienceError("SkipLevelReceipt timestamp is in the future")
    if now_ts - receipt.timestamp > max_receipt_age_seconds:
        raise ResilienceError("SkipLevelReceipt has expired (exceeded max_receipt_age_seconds)")

    if receipt_replay_cache is not None and not receipt_replay_cache.check_and_record(
        receipt.receipt_id, now=now_ts
    ):
        raise ResilienceError(f"SkipLevelReceipt replay detected: {receipt.receipt_id!r}")

    # 1. Verify DPoP proof proves HTTP sender is genuinely leaf holder C!
    try:
        dpop_info = ancestor_verifier.dpop_verifier.verify_proof(
            dpop_proof=dpop_proof or "",
            expected_htm=htm,
            expected_htu=htu,
            access_token=receipt.compact_lineage_token,
            expected_jkt=embedded_token.holder_cnf_jkt,
            now=now_ts,
        )
    except DPoPError as exc:
        raise ResilienceError(f"SkipLevelReceipt DPoP verification failed: {exc}") from exc

    # 2. Sync revocation state if replica attached, then verify C's full lineage back to B_0
    if revocation_replica is not None:
        try:
            revocation_replica.sync_now()
        except RevocationError:
            pass

    try:
        ancestor_verifier.verify_single_chain_full(
            embedded_token, now=now_ts, check_revocation=True
        )
    except (TokenError, RevocationError) as exc:
        raise ResilienceError(f"SkipLevelReceipt lineage rejected: {exc}") from exc

    # 3. ACTIVE LIVENESS PROBE OF SKIPPED INTERMEDIATE ANCESTORS (`[HIGH-01]` & `[MEDIUM-R2-01]`)
    # Fail closed if no trusted endpoint is attested for any skipped ancestor, and assert
    # probe_url strictly hits `<clean_origin>/healthz` with zero query/userinfo smuggling!
    for sk_id in receipt.skipped_ancestors:
        trusted_urls = _resolve_trusted_skipped_endpoints(
            embedded_token, sk_id, directory_client=directory_client
        )
        if not trusted_urls:
            raise ResilienceError(
                f"SKIP_LEVEL_UNVERIFIABLE_LIVENESS: No cryptographically attested endpoint available to probe skipped ancestor {sk_id!r}"
            )
        for sk_base in trusted_urls:
            base_sp = urlsplit(sk_base)
            probe_url = f"{sk_base}/healthz"
            probe_sp = urlsplit(probe_url)
            if (
                probe_sp.scheme != base_sp.scheme
                or probe_sp.hostname != base_sp.hostname
                or probe_sp.port != base_sp.port
                or probe_sp.username is not None
                or probe_sp.password is not None
                or probe_sp.path != "/healthz"
                or probe_sp.query != ""
                or probe_sp.fragment != ""
            ):
                raise ResilienceError(
                    f"Unsafe liveness probe URL constructed for {sk_id!r}: {probe_url!r}"
                )
            probe_verify: Any = (
                mtls_bundle.verify_for_target(
                    target_url=probe_url, expected_spiffe_id=sk_id
                )
                if mtls_bundle is not None
                else (client_ssl_context if client_ssl_context is not None else True)
            )
            try:
                with httpx.Client(
                    verify=probe_verify,
                    timeout=liveness_probe_timeout,
                    follow_redirects=False,
                ) as client:
                    probe_resp = client.get(probe_url)
                if 200 <= probe_resp.status_code < 300:
                    raise ResilienceError(
                        f"INTERMEDIATE_ANCESTOR_ALIVE: Skipped ancestor {sk_id!r} responded healthy at {probe_url}"
                    )
            except ResilienceError:
                raise
            except Exception:
                # Connection refused / timeout confirms intermediate ancestor is unreachable
                continue

    # 4. Emit SKIP_LEVEL_ACCEPT audit record BEFORE pruning dead intermediate branch
    if audit_emitter is not None:
        audit_emitter.emit(
            event_type=AuditEventType.SKIP_LEVEL_ACCEPT,
            task_id=embedded_token.task_id,
            sub=embedded_token.sub,
            lineage_path=embedded_token.lineage_path,
            hop_index=embedded_token.depth,
            epoch=embedded_token.current_epoch,
            root_block_hash=embedded_token.root_block_hash,
            parent_block_hash=embedded_token.parent_block_hash,
            current_block_hash=embedded_token.leaf_block_hash,
            dpop_jti=str(dpop_info["jti"]),
            action_detail={
                "child_spiffe_id": receipt.child_spiffe_id,
                "skipped_ancestors": list(receipt.skipped_ancestors),
                "result_sha256": receipt.result_sha256,
            },
            decision="ALLOW",
            receipt_payload=receipt.to_dict(),
        )

    # 5. Prune genuinely dead intermediate branch (presenting `authority_token`)
    if prune_dead_intermediate and revocation_replica is not None:
        dead_id = receipt.failure_evidence.failed_spiffe_id
        for hop in embedded_token.hops:
            if hop.delegate_spiffe_id == dead_id:
                try:
                    rev_ev = revocation_replica.revoke_prefix(
                        caller=ancestor_identity,
                        prefix=hop.lineage_path,
                        reason="post_skip_level_zombie_cleanup",
                        authority_token=receipt.compact_lineage_token,
                    )
                    if audit_emitter is not None:
                        audit_emitter.emit(
                            event_type=AuditEventType.REVOCATION_ISSUED,
                            task_id=embedded_token.task_id,
                            sub=embedded_token.sub,
                            lineage_path=hop.lineage_path,
                            hop_index=hop.hop_index,
                            epoch=hop.epoch,
                            root_block_hash=embedded_token.root_block_hash,
                            parent_block_hash=hop.parent_hash,
                            current_block_hash=hop.block_hash(),
                            action_detail={
                                "target": rev_ev.target,
                                "revocation_version": rev_ev.version,
                                "reason": "post_skip_level_zombie_cleanup",
                                "trust_domain": rev_ev.trust_domain,
                            },
                            decision="REVOKED",
                        )
                except Exception:
                    pass
                break

    return receipt, embedded_token
