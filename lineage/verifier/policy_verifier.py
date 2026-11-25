"""Leaf Authorization Verifier supporting 3 Modes, Atomic Chain Quotas & Exact Fagin DAG Semantics.

Modes:
1. `LEAF_ONLY`: Fragile baseline control (checks only tail block signature, expiry,
   and leaf lattice without walking ancestor chain or prefix revocation trie).
2. `LOCAL_FULL_CHAIN`: Zero remote callbacks; microsecond full-chain verification
   back to B_0, monotonic lattice check P_i <= P_{i-1}, cycle/depth limits, RFC 9449
   DPoP sender verification, atomic full-chain block quotas, and local `LineagePrefixTrie`.
3. `ADAPTIVE_RISK_ANCHORED`: Fast local full-chain path for intrinsically LOW_RISK
   operations; synchronous delta anchor pull from `RevocationService` before executing
   HIGH_RISK operations (monotonic escalation-only risk hints; fail-closed if anchor down).
"""

from __future__ import annotations

import enum
import math
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from lineage.common.crypto import (
    CryptoError,
    canonical_json_bytes,
    compute_jwk_thumbprint,
    jws_verify_compact,
    require_finite_timestamp,
)
from lineage.identity.spiffe import IdentityError, SpiffeId
from lineage.identity.trust_bundle import TrustBundleResolver
from lineage.protocol.dpop import DPoPError, DPoPVerifier
from lineage.protocol.lattice import CompositePermission
from lineage.protocol.token import (
    AttenuationBlock,
    CoAuthorizedToken,
    LineageToken,
    MultiParentToken,
    RootBlock,
    TokenError,
    TokenExpiredError,
    decode_token,
    validate_principal_domain_consistency,
    verify_lineage_token_cryptography,
)
from lineage.revocation.service import RevocationError, RevocationReplicaClient
from lineage.revocation.trie import LineagePrefixTrie


class VerificationMode(str, enum.Enum):
    LEAF_ONLY = "LEAF_ONLY"
    LOCAL_FULL_CHAIN = "LOCAL_FULL_CHAIN"
    ADAPTIVE_RISK_ANCHORED = "ADAPTIVE_RISK_ANCHORED"


class RiskTier(str, enum.Enum):
    LOW_RISK = "LOW_RISK"
    HIGH_RISK = "HIGH_RISK"


@dataclass
class RiskClassifier:
    """Monotonic policy classifier determining whether an invocation requires revocation anchoring.

    Intrinsic risk is ALWAYS computed first from `(method, tool, arguments)`.
    An `explicit_risk_hint` can ONLY escalate `LOW_RISK -> HIGH_RISK`, and can NEVER
    downgrade an intrinsically `HIGH_RISK` operation to `LOW_RISK`.
    """

    high_risk_tools: FrozenSet[str] = field(
        default_factory=lambda: frozenset(
            {
                "execute_payment",
                "execute_settlement",
                "transfer_funds",
                "book_flight",
                "book_hotel",
                "reserve_hotel",
                "write_ledger",
                "delete_record",
                "settle_order",
                "reserve_cloud_budget",
                "lock_joint_project",
                "hr_salary_read",
                "calendar_write",
                "procure_vendor_quote",
                "commit_joint_change",
                "commit_negotiated_contract",
                "sign_release",
                "federated_cohort_aggregate",
                "record_compliance_note",
                "export_raw_patient_records",
                "alice_private_roadmap",
                "pricing_floor_read",
            }
        )
    )
    read_only_methods: FrozenSet[str] = field(
        default_factory=lambda: frozenset(
            {"initialize", "tools/list", "resources/list", "resources/read", "ping"}
        )
    )
    high_risk_amount_threshold: float = 100.0

    def classify(
        self,
        method: str,
        tool: Optional[str] = None,
        arguments: Optional[Mapping[str, Any]] = None,
        explicit_risk_hint: Optional[str] = None,
    ) -> RiskTier:
        # 1. Compute intrinsic risk strictly from operation semantics
        intrinsic = RiskTier.LOW_RISK

        if tool and (
            tool in self.high_risk_tools
            or tool.startswith(
                ("pay_", "write_", "delete_", "book_", "execute_", "settle_")
            )
        ):
            intrinsic = RiskTier.HIGH_RISK
        else:
            args = arguments or {}
            if isinstance(args, Mapping):
                for amt_key in ("amount", "max_amount"):
                    if amt_key in args:
                        amt = args[amt_key]
                        if isinstance(amt, bool) or not isinstance(amt, (int, float)):
                            intrinsic = RiskTier.HIGH_RISK
                            break
                        f_amt = float(amt)
                        if not math.isfinite(f_amt) or f_amt >= self.high_risk_amount_threshold:
                            intrinsic = RiskTier.HIGH_RISK
                            break

        if intrinsic == RiskTier.HIGH_RISK:
            return RiskTier.HIGH_RISK

        # 2. Monotonic escalation-only hint: can upgrade LOW -> HIGH, never HIGH -> LOW
        if explicit_risk_hint and str(explicit_risk_hint).strip().upper() == "HIGH":
            return RiskTier.HIGH_RISK

        return RiskTier.LOW_RISK


def _chain_block_quotas(token: LineageToken) -> List[Tuple[str, int]]:
    """Extract ordered `(block_hash, max_calls)` across every block `[B_0, B_1, ..., B_k]`."""
    seen: Set[str] = set()
    quotas: List[Tuple[str, int]] = []
    r_hash = token.root.block_hash()
    seen.add(r_hash)
    quotas.append((r_hash, token.root.permissions.max_calls))
    for hop in token.hops:
        h_hash = hop.block_hash()
        if h_hash not in seen:
            seen.add(h_hash)
            quotas.append((h_hash, hop.permissions.max_calls))
    return quotas


class _QuotaTracker:
    """Thread-safe bounded atomic per-block `[B_0, ..., B_k]` invocation quota tracker."""

    def __init__(self, ttl_seconds: float = 3600.0, max_entries: int = 50_000) -> None:
        self.ttl_seconds = float(ttl_seconds)
        self.max_entries = int(max_entries)
        self._lock = threading.Lock()
        # (task_id, block_hash) -> (used_count, expires_at)
        self._counts: "OrderedDict[Tuple[str, str], Tuple[int, float]]" = OrderedDict()

    def _evict_expired_locked(self, ts: float) -> None:
        while self._counts:
            _, (_, exp_at) = next(iter(self._counts.items()))
            if exp_at <= ts:
                self._counts.popitem(last=False)
            else:
                break

    def try_consume_chain(
        self,
        task_id: str,
        block_quotas: Sequence[Tuple[str, int]],
        now: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """Atomically verify and increment `max_calls` across ALL blocks in `block_quotas`."""
        ts = time.time() if now is None else float(now)
        with self._lock:
            self._evict_expired_locked(ts)

            # Phase 1: Check every block [B_0, ..., B_k] without mutating
            for b_hash, max_calls in block_quotas:
                cur_count, _ = self._counts.get((task_id, b_hash), (0, ts + self.ttl_seconds))
                if cur_count + 1 > max_calls:
                    return (
                        False,
                        f"block {b_hash[:12]} call_index {cur_count + 1} exceeds max_calls={max_calls}",
                    )

            # Phase 2: Commit increments atomically across all blocks in chain
            exp_at = ts + self.ttl_seconds
            for b_hash, _ in block_quotas:
                key = (task_id, b_hash)
                cur_count = self._counts[key][0] if key in self._counts else 0
                if key in self._counts:
                    self._counts.pop(key)
                elif len(self._counts) >= self.max_entries:
                    self._counts.popitem(last=False)
                self._counts[key] = (cur_count + 1, exp_at)

            return True, "ok"

    def try_consume_first_satisfying_branch(
        self,
        task_id: str,
        candidate_branches: Sequence[Tuple[str, List[Tuple[str, int]]]],
        now: Optional[float] = None,
    ) -> Tuple[Optional[str], Dict[str, str]]:
        """Atomically select the first candidate branch with remaining quota on all its blocks."""
        ts = time.time() if now is None else float(now)
        failures: Dict[str, str] = {}
        with self._lock:
            self._evict_expired_locked(ts)

            for path, block_quotas in candidate_branches:
                blocked_reason: Optional[str] = None
                for b_hash, max_calls in block_quotas:
                    cur_count, _ = self._counts.get(
                        (task_id, b_hash), (0, ts + self.ttl_seconds)
                    )
                    if cur_count + 1 > max_calls:
                        blocked_reason = (
                            f"block {b_hash[:12]} call_index {cur_count + 1} exceeds max_calls={max_calls}"
                        )
                        break

                if blocked_reason is not None:
                    failures[path] = blocked_reason
                    continue

                # Found a branch where every block [B_0, ..., B_k] has remaining quota!
                exp_at = ts + self.ttl_seconds
                for b_hash, _ in block_quotas:
                    key = (task_id, b_hash)
                    cur_count = self._counts[key][0] if key in self._counts else 0
                    if key in self._counts:
                        self._counts.pop(key)
                    elif len(self._counts) >= self.max_entries:
                        self._counts.popitem(last=False)
                    self._counts[key] = (cur_count + 1, exp_at)
                return path, failures

            return None, failures


@dataclass(frozen=True)
class VerificationResult:
    """Comprehensive outcome of LCT verification for enforcement and causal auditing."""

    allowed: bool
    status_code: int
    decision: str  # ALLOW | ALLOW_DEGRADED_DAG | DENY
    reason_code: str
    detail: str
    mode: VerificationMode
    risk_tier: RiskTier
    anchored_revocation_version: Optional[int] = None
    task_id: Optional[str] = None
    sub: Optional[str] = None
    holder_spiffe_id: Optional[str] = None
    lineage_path: Optional[str] = None
    active_paths: Tuple[str, ...] = ()
    pruned_revoked_paths: Tuple[str, ...] = ()
    hop_index: int = 0
    epoch: int = 0
    root_block_hash: Optional[str] = None
    parent_block_hash: Optional[str] = None
    leaf_block_hash: Optional[str] = None
    multi_parent_hashes: Tuple[str, ...] = ()
    dpop_jti: Optional[str] = None
    effective_permissions: Optional[Dict[str, Any]] = None
    co_authorized_principals: Tuple[str, ...] = ()
    resumes_checkpoint_id: Optional[str] = None
    latency_us: float = 0.0


class LeafVerifier:
    """Cryptographic LCT Leaf Verifier supporting single-chain and Multi-Parent DAG tokens."""

    def __init__(
        self,
        self_spiffe_id: str,
        trust_resolver: TrustBundleResolver,
        self_jkt: Optional[str] = None,
        mode: VerificationMode = VerificationMode.ADAPTIVE_RISK_ANCHORED,
        local_trie: Optional[LineagePrefixTrie] = None,
        revocation_replica: Optional[RevocationReplicaClient] = None,
        dpop_verifier: Optional[DPoPVerifier] = None,
        risk_classifier: Optional[RiskClassifier] = None,
        fail_closed_on_high_risk: bool = True,
        clock_skew_seconds: float = 5.0,
    ) -> None:
        self.self_spiffe_id = self_spiffe_id
        self.self_jkt = self_jkt
        self.trust_resolver = trust_resolver
        self.mode = VerificationMode(mode)
        self.revocation_replica = revocation_replica
        self.trie = (
            local_trie
            if local_trie is not None
            else (
                revocation_replica.trie if revocation_replica else LineagePrefixTrie()
            )
        )
        self.dpop_verifier = dpop_verifier or DPoPVerifier(
            clock_skew_seconds=clock_skew_seconds
        )
        self.risk_classifier = risk_classifier or RiskClassifier()
        self.fail_closed_on_high_risk = fail_closed_on_high_risk
        self.clock_skew = float(clock_skew_seconds)
        self._quota = _QuotaTracker()

    def _verify_root_block_crypto(self, root: RootBlock, ts: float) -> None:
        validate_principal_domain_consistency(root.sub, root.issuer_trust_domain)
        try:
            _, signed_claims = self.trust_resolver.verify_domain_jws(
                root.jws_signature,
                expected_trust_domain=root.issuer_trust_domain,
                expected_typ="lct-root+jwt",
            )
        except IdentityError as exc:
            raise TokenError(f"RootBlock signature verification failed: {exc}") from exc

        if canonical_json_bytes(signed_claims) != canonical_json_bytes(root.core_claims()):
            raise TokenError("RootBlock payload tampering detected")

        expected_root_iss = f"spiffe://{root.issuer_trust_domain}/authority/root"
        expected_ca_iss = f"spiffe://{root.issuer_trust_domain}/authority/ca"
        if root.issuer_spiffe_id not in (expected_root_iss, expected_ca_iss):
            raise TokenError(f"Invalid RootBlock issuer_spiffe_id: {root.issuer_spiffe_id!r}")

        if root.iat > ts + self.clock_skew:
            raise TokenError("RootBlock iat is in the future")
        if root.exp <= ts - self.clock_skew:
            raise TokenExpiredError("RootBlock has expired")

    def _verify_hop_block_signature_only(self, hop: AttenuationBlock, ts: float) -> None:
        if hop.iat > ts + self.clock_skew:
            raise TokenError(f"Hop {hop.hop_index} iat is in the future")
        try:
            _, signed_claims = jws_verify_compact(
                hop.jws_signature, hop.issuer_jwk, expected_typ="lct-hop+jwt"
            )
        except CryptoError as exc:
            raise TokenError(
                f"Hop {hop.hop_index} signature verification failed: {exc}"
            ) from exc
        if canonical_json_bytes(signed_claims) != canonical_json_bytes(hop.core_claims()):
            raise TokenError(f"Hop {hop.hop_index} payload tampering detected")
        if hop.exp <= ts - self.clock_skew:
            raise TokenExpiredError(f"Hop {hop.hop_index} has expired")

    def verify_single_chain_full(
        self,
        token: LineageToken,
        now: Optional[float] = None,
        check_revocation: bool = True,
    ) -> None:
        """Perform full O(depth) local cryptographic & monotonic verification of a `LineageToken`."""
        ts = require_finite_timestamp(time.time() if now is None else now, "now")
        verify_lineage_token_cryptography(
            token=token,
            trust_resolver=self.trust_resolver,
            now=ts,
            clock_skew_seconds=self.clock_skew,
        )

        if check_revocation:
            rev_ev = self.trie.check_chain(
                token.lineage_path,
                token.visited_subjects,
                trust_domain=token.root.issuer_trust_domain,
            )
            if rev_ev is not None:
                raise RevocationError(
                    f"Lineage revoked via {rev_ev.kind.value} on {rev_ev.target!r} (v{rev_ev.version})"
                )

    def _resolve_expected_dpop_jkt_single(self, token: LineageToken) -> str:
        """Determine required DPoP sender key thumbprint for single-chain LCT."""
        if token.holder_spiffe_id == self.self_spiffe_id:
            if self.self_jkt is not None and token.holder_cnf_jkt != self.self_jkt:
                raise TokenError(
                    "Delegated token holder_cnf_jkt does not match recipient agent key"
                )
            if not token.hops:
                return token.root.sender_jkt
            return compute_jwk_thumbprint(token.hops[-1].issuer_jwk)

        if token.target_audience is not None and token.target_audience != self.self_spiffe_id:
            raise TokenError(
                f"Target audience mismatch: token restricted to {token.target_audience!r}, self is {self.self_spiffe_id!r}"
            )
        return token.holder_cnf_jkt

    def _verify_multiparent_envelope_crypto(
        self, mpt: MultiParentToken, ts: float
    ) -> str:
        """Verify MultiParentToken outer envelope signature, SVID, and single-root invariant."""
        signer_jkt = compute_jwk_thumbprint(mpt.signer_jwk)
        try:
            self.trust_resolver.verify_workload_svid(
                mpt.signer_svid,
                expected_spiffe_id=mpt.signer_spiffe_id,
                expected_jkt=signer_jkt,
                now=ts,
            )
            _, signed_claims = jws_verify_compact(
                mpt.jws_signature,
                mpt.signer_jwk,
                expected_typ="lct-multiparent+jwt",
            )
        except (IdentityError, CryptoError) as exc:
            raise TokenError(
                f"MultiParentToken envelope verification failed: {exc}"
            ) from exc

        if canonical_json_bytes(signed_claims) != canonical_json_bytes(mpt.core_claims()):
            raise TokenError("MultiParentToken envelope claims tampered")

        from lineage.protocol.token import are_roots_continuously_linked

        if not are_roots_continuously_linked(mpt.parent_chains):
            raise TokenError(
                "MultiParentToken cross-root splicing blocked: mismatched RootBlock hashes"
            )
        seen_paths: Set[str] = set()
        for chain in mpt.parent_chains:
            if chain.task_id != mpt.task_id or chain.sub != mpt.sub:
                raise TokenError("MultiParentToken cross-task/cross-principal mismatch")
            if (
                chain.holder_spiffe_id != mpt.holder_spiffe_id
                or chain.holder_cnf_jkt != mpt.holder_cnf_jkt
            ):
                raise TokenError("MultiParentToken parent chain holder mismatch")
            if chain.lineage_path in seen_paths:
                raise TokenError("Duplicate lineage_path in MultiParentToken")
            seen_paths.add(chain.lineage_path)

        if mpt.signer_spiffe_id == mpt.holder_spiffe_id and signer_jkt == mpt.holder_cnf_jkt:
            if (
                mpt.holder_spiffe_id == self.self_spiffe_id
                and self.self_jkt is not None
                and mpt.holder_cnf_jkt != self.self_jkt
            ):
                raise TokenError("MultiParentToken holder_cnf_jkt mismatch with self")
            for chain in mpt.parent_chains:
                if (
                    chain.target_audience is not None
                    and chain.target_audience != self.self_spiffe_id
                ):
                    raise TokenError("MultiParentToken branch audience mismatch")
            return mpt.holder_cnf_jkt

        if mpt.holder_spiffe_id == self.self_spiffe_id:
            if self.self_jkt is not None and mpt.holder_cnf_jkt != self.self_jkt:
                raise TokenError("MultiParentToken holder_cnf_jkt mismatch with self")
            for chain in mpt.parent_chains:
                if not chain.hops or chain.hops[-1].issuer_spiffe_id != mpt.signer_spiffe_id:
                    raise TokenError("MultiParentToken upstream issuer mismatch")
            return signer_jkt

        raise TokenError(
            "MultiParentToken must be signed by current holder when invoking a tool"
        )

    def _verify_coauthorized_envelope_crypto(
        self, cot: CoAuthorizedToken, ts: float
    ) -> str:
        """Verify CoAuthorizedToken outer envelope signature, SVID, and dual-principal binding."""
        signer_jkt = compute_jwk_thumbprint(cot.signer_jwk)
        try:
            self.trust_resolver.verify_workload_svid(
                cot.signer_svid,
                expected_spiffe_id=cot.signer_spiffe_id,
                expected_jkt=signer_jkt,
                now=ts,
            )
            _, signed_claims = jws_verify_compact(
                cot.jws_signature,
                cot.signer_jwk,
                expected_typ="lct-coauth+jwt",
            )
        except (IdentityError, CryptoError) as exc:
            raise TokenError(
                f"CoAuthorizedToken envelope verification failed: {exc}"
            ) from exc

        if canonical_json_bytes(signed_claims) != canonical_json_bytes(cot.core_claims()):
            raise TokenError("CoAuthorizedToken envelope claims tampered")

        if cot.requester_sub == cot.owner_sub:
            raise TokenError("CoAuthorizedToken requires two distinct principals")
        if (
            cot.requester_chain.task_id != cot.task_id
            or cot.owner_consent_chain.task_id != cot.task_id
            or cot.requester_chain.sub != cot.requester_sub
            or cot.owner_consent_chain.sub != cot.owner_sub
        ):
            raise TokenError("CoAuthorizedToken chain task_id/sub mismatch")

        for ch in cot.parent_chains:
            if (
                ch.holder_spiffe_id != cot.holder_spiffe_id
                or ch.holder_cnf_jkt != cot.holder_cnf_jkt
            ):
                raise TokenError("CoAuthorizedToken chain holder mismatch")

        if cot.signer_spiffe_id == cot.holder_spiffe_id and signer_jkt == cot.holder_cnf_jkt:
            if (
                cot.holder_spiffe_id == self.self_spiffe_id
                and self.self_jkt is not None
                and cot.holder_cnf_jkt != self.self_jkt
            ):
                raise TokenError("CoAuthorizedToken holder_cnf_jkt mismatch with self")
            for ch in cot.parent_chains:
                if ch.target_audience is not None and ch.target_audience != self.self_spiffe_id:
                    raise TokenError("CoAuthorizedToken branch audience mismatch")
            return cot.holder_cnf_jkt

        if cot.holder_spiffe_id == self.self_spiffe_id:
            if self.self_jkt is not None and cot.holder_cnf_jkt != self.self_jkt:
                raise TokenError("CoAuthorizedToken holder_cnf_jkt mismatch with self")
            for ch in cot.parent_chains:
                if not ch.hops or ch.hops[-1].issuer_spiffe_id != cot.signer_spiffe_id:
                    raise TokenError("CoAuthorizedToken upstream issuer mismatch")
            return signer_jkt

        raise TokenError(
            "CoAuthorizedToken must be signed by current holder when invoking a tool"
        )

    def verify_request(
        self,
        compact_token: str,
        dpop_proof: Optional[str],
        htm: str,
        htu: str,
        method: str = "tools/call",
        tool: Optional[str] = None,
        arguments: Optional[Mapping[str, Any]] = None,
        explicit_risk_hint: Optional[str] = None,
        require_dpop: bool = True,
        check_invocation_lattice: bool = True,
        require_recipient_self: bool = False,
        require_direct_child_issuer: bool = False,
        resource_owner_sub: Optional[str] = None,
        allowed_co_auth_tools: Optional[Iterable[str]] = None,
        now: Optional[float] = None,
    ) -> VerificationResult:
        """Verify an incoming HTTP request carrying an LCT, MultiParentToken, or CoAuthorizedToken + DPoP."""
        t0 = time.perf_counter()
        risk_tier = self.risk_classifier.classify(
            method=method,
            tool=tool,
            arguments=arguments,
            explicit_risk_hint=explicit_risk_hint,
        )

        def _finish(
            allowed: bool,
            status_code: int,
            decision: str,
            reason_code: str,
            detail: str,
            **kwargs: Any,
        ) -> VerificationResult:
            elapsed_us = (time.perf_counter() - t0) * 1_000_000.0
            return VerificationResult(
                allowed=allowed,
                status_code=status_code,
                decision=decision,
                reason_code=reason_code,
                detail=detail,
                mode=self.mode,
                risk_tier=risk_tier,
                latency_us=elapsed_us,
                **kwargs,
            )

        try:
            ts = require_finite_timestamp(time.time() if now is None else now, "now")
        except CryptoError as exc:
            return _finish(False, 401, "DENY", "MALFORMED_TIMESTAMP", str(exc))

        if not compact_token or not isinstance(compact_token, str):
            return _finish(
                False, 401, "DENY", "MISSING_TOKEN", "Missing LCT Authorization token"
            )

        try:
            parsed = decode_token(compact_token)
        except (TokenError, CryptoError) as exc:
            return _finish(False, 401, "DENY", "MALFORMED_TOKEN", str(exc))

        # --- Explicit Endpoint Role Checks (`[CRITICAL-04]`) ---
        if require_recipient_self:
            if parsed.holder_spiffe_id != self.self_spiffe_id or (
                self.self_jkt is not None and parsed.holder_cnf_jkt != self.self_jkt
            ):
                return _finish(
                    False,
                    403,
                    "DENY",
                    "RECIPIENT_HOLDER_MISMATCH",
                    f"Token holder {parsed.holder_spiffe_id!r} != recipient agent {self.self_spiffe_id!r}",
                    task_id=parsed.task_id,
                    sub=parsed.sub,
                    holder_spiffe_id=parsed.holder_spiffe_id,
                )

        if require_direct_child_issuer:
            if not isinstance(parsed, LineageToken) or len(parsed.hops) < 1:
                return _finish(
                    False,
                    403,
                    "DENY",
                    "NOT_DIRECT_CHILD_DELEGATE",
                    "Direct upward task-result requires a single-chain child LineageToken",
                    task_id=parsed.task_id,
                    sub=parsed.sub,
                    holder_spiffe_id=parsed.holder_spiffe_id,
                )
            last_hop = parsed.hops[-1]
            try:
                last_issuer_jkt = compute_jwk_thumbprint(last_hop.issuer_jwk)
            except CryptoError as exc:
                return _finish(False, 401, "DENY", "MALFORMED_TOKEN", str(exc))

            if (
                last_hop.issuer_spiffe_id != self.self_spiffe_id
                or (self.self_jkt is not None and last_issuer_jkt != self.self_jkt)
                or parsed.holder_spiffe_id == self.self_spiffe_id
            ):
                return _finish(
                    False,
                    403,
                    "DENY",
                    "NOT_DIRECT_CHILD_DELEGATE",
                    f"Caller {parsed.holder_spiffe_id!r} is not a direct child of {self.self_spiffe_id!r}; use /v1/skip-level-return",
                    task_id=parsed.task_id,
                    sub=parsed.sub,
                    holder_spiffe_id=parsed.holder_spiffe_id,
                    lineage_path=parsed.lineage_path,
                    hop_index=parsed.depth,
                    epoch=parsed.current_epoch,
                    root_block_hash=parsed.root_block_hash,
                    parent_block_hash=parsed.parent_block_hash,
                    leaf_block_hash=parsed.leaf_block_hash,
                )

        # --- Adaptive Risk-Anchored Revocation Sync (`[HIGH-M3-01]`) ---
        anchored_ver: Optional[int] = None
        if (
            self.mode == VerificationMode.ADAPTIVE_RISK_ANCHORED
            and risk_tier == RiskTier.HIGH_RISK
            and self.revocation_replica is not None
        ):
            req_domains: Set[str] = set()
            if isinstance(parsed, LineageToken):
                req_domains.add(parsed.root.issuer_trust_domain)
                for vs in parsed.visited_subjects:
                    try:
                        req_domains.add(SpiffeId.parse(vs).trust_domain)
                    except IdentityError:
                        pass
            else:
                for ch in parsed.parent_chains:
                    req_domains.add(ch.root.issuer_trust_domain)
                    for vs in ch.visited_subjects:
                        try:
                            req_domains.add(SpiffeId.parse(vs).trust_domain)
                        except IdentityError:
                            pass
            try:
                try:
                    anchored_ver = self.revocation_replica.sync_now(
                        wait_ms=0,
                        required_trust_domains=sorted(req_domains),
                    )
                except TypeError:
                    anchored_ver = self.revocation_replica.sync_now()
            except RevocationError as exc:
                if self.fail_closed_on_high_risk:
                    return _finish(
                        False,
                        503,
                        "DENY",
                        "REVOCATION_ANCHOR_UNAVAILABLE",
                        f"Fail-closed on HIGH_RISK action: {exc}",
                        task_id=parsed.task_id,
                        sub=parsed.sub,
                    )

        # =====================================================================
        # Branch 1: Single-Chain LineageToken
        # =====================================================================
        if isinstance(parsed, LineageToken):
            try:
                base_meta = {
                    "anchored_revocation_version": anchored_ver,
                    "task_id": parsed.task_id,
                    "sub": parsed.sub,
                    "holder_spiffe_id": parsed.holder_spiffe_id,
                    "lineage_path": parsed.lineage_path,
                    "hop_index": parsed.depth,
                    "epoch": parsed.current_epoch,
                    "root_block_hash": parsed.root_block_hash,
                    "parent_block_hash": parsed.parent_block_hash,
                    "leaf_block_hash": parsed.leaf_block_hash,
                    "resumes_checkpoint_id": parsed.root.resumes_checkpoint_id,
                }
                expected_dpop_jkt = self._resolve_expected_dpop_jkt_single(parsed)
            except (TokenError, CryptoError) as exc:
                return _finish(
                    False,
                    401,
                    "DENY",
                    "HOLDER_OR_AUDIENCE_ERROR",
                    str(exc),
                    task_id=parsed.task_id,
                    sub=parsed.sub,
                )

            dpop_jti: Optional[str] = None
            if require_dpop:
                try:
                    dpop_info = self.dpop_verifier.verify_proof(
                        dpop_proof=dpop_proof or "",
                        expected_htm=htm,
                        expected_htu=htu,
                        access_token=compact_token,
                        expected_jkt=expected_dpop_jkt,
                        now=ts,
                    )
                    dpop_jti = str(dpop_info["jti"])
                except DPoPError as exc:
                    dpop_st = 403 if "sender key thumbprint mismatch" in str(exc) else 401
                    return _finish(False, dpop_st, "DENY", "DPOP_FAILED", str(exc), **base_meta)

            base_meta["dpop_jti"] = dpop_jti

            if self.mode == VerificationMode.LEAF_ONLY:
                try:
                    if parsed.hops:
                        self._verify_hop_block_signature_only(parsed.hops[-1], ts)
                    else:
                        self._verify_root_block_crypto(parsed.root, ts)
                except TokenExpiredError as exc:
                    return _finish(
                        False, 401, "DENY", "TASK_AUTH_EXPIRED", str(exc), **base_meta
                    )
                except (TokenError, CryptoError) as exc:
                    return _finish(
                        False, 401, "DENY", "LEAF_SIG_INVALID", str(exc), **base_meta
                    )
            else:
                try:
                    self.verify_single_chain_full(parsed, now=ts, check_revocation=True)
                except TokenExpiredError as exc:
                    return _finish(
                        False,
                        401,
                        "DENY",
                        "TASK_AUTH_EXPIRED",
                        str(exc),
                        **base_meta,
                    )
                except (TokenError, CryptoError) as exc:
                    return _finish(
                        False,
                        403,
                        "DENY",
                        "CHAIN_VERIFICATION_FAILED",
                        str(exc),
                        **base_meta,
                    )
                except RevocationError as exc:
                    return _finish(
                        False, 403, "DENY", "LINEAGE_REVOKED", str(exc), **base_meta
                    )

            clean_owner = str(resource_owner_sub).strip() if resource_owner_sub else ""
            if clean_owner and parsed.sub != clean_owner:
                return _finish(
                    False,
                    403,
                    "DENY",
                    "CROSS_PRINCIPAL_DENIED",
                    f"Unilateral principal {parsed.sub!r} is forbidden from accessing resource owned by {clean_owner!r}",
                    **base_meta,
                )

            if check_invocation_lattice:
                # 1. Check parameter/tool/method constraints first
                ok, reason = parsed.leaf_permissions.check_invocation(
                    method=method,
                    tool=tool,
                    arguments=arguments,
                    call_index=1,
                )
                if not ok:
                    code = (
                        "QUOTA_EXCEEDED"
                        if "max_calls" in reason
                        else "LATTICE_PERMISSION_DENIED"
                    )
                    return _finish(False, 403, "DENY", code, reason, **base_meta)

                # 2. Atomically verify and consume quota across ALL blocks [B_0, ..., B_k]
                quota_blocks = (
                    [(parsed.leaf_block_hash, parsed.leaf_permissions.max_calls)]
                    if self.mode == VerificationMode.LEAF_ONLY
                    else _chain_block_quotas(parsed)
                )
                q_ok, q_reason = self._quota.try_consume_chain(
                    parsed.task_id, quota_blocks, now=ts
                )
                if not q_ok:
                    return _finish(
                        False, 403, "DENY", "QUOTA_EXCEEDED", q_reason, **base_meta
                    )

            return _finish(
                True,
                200,
                "ALLOW",
                "OK",
                "Authorized via verified single-chain LCT",
                active_paths=(parsed.lineage_path,),
                effective_permissions=parsed.leaf_permissions.to_dict(),
                **base_meta,
            )

        # =====================================================================
        # Branch 1B: Explicit Dual-Principal CoAuthorizedToken (`lctco1.`)
        # =====================================================================
        if isinstance(parsed, CoAuthorizedToken):
            try:
                co_hashes = (
                    parsed.requester_chain.leaf_block_hash,
                    parsed.owner_consent_chain.leaf_block_hash,
                )
                co_meta = {
                    "anchored_revocation_version": anchored_ver,
                    "task_id": parsed.task_id,
                    "sub": parsed.requester_sub,
                    "holder_spiffe_id": parsed.holder_spiffe_id,
                    "lineage_path": "|".join(parsed.lineage_paths),
                    "hop_index": max(c.depth for c in parsed.parent_chains),
                    "epoch": max(c.current_epoch for c in parsed.parent_chains),
                    "root_block_hash": parsed.requester_chain.root_block_hash,
                    "parent_block_hash": None,
                    "leaf_block_hash": parsed.envelope_hash,
                    "multi_parent_hashes": co_hashes,
                    "co_authorized_principals": parsed.co_authorized_principals,
                }
                expected_dpop_jkt = self._verify_coauthorized_envelope_crypto(parsed, ts)
            except (TokenError, CryptoError) as exc:
                return _finish(
                    False,
                    401,
                    "DENY",
                    "COAUTH_ENVELOPE_INVALID",
                    str(exc),
                    task_id=parsed.task_id,
                    sub=parsed.requester_sub,
                )

            dpop_jti = None
            if require_dpop:
                try:
                    dpop_info = self.dpop_verifier.verify_proof(
                        dpop_proof=dpop_proof or "",
                        expected_htm=htm,
                        expected_htu=htu,
                        access_token=compact_token,
                        expected_jkt=expected_dpop_jkt,
                        now=ts,
                    )
                    dpop_jti = str(dpop_info["jti"])
                except DPoPError as exc:
                    dpop_st = 403 if "sender key thumbprint mismatch" in str(exc) else 401
                    return _finish(False, dpop_st, "DENY", "DPOP_FAILED", str(exc), **co_meta)

            co_meta["dpop_jti"] = dpop_jti

            # Both requester_chain AND owner_consent_chain MUST be valid, unexpired, and unrevoked!
            for label, chain in (
                ("requester_chain", parsed.requester_chain),
                ("owner_consent_chain", parsed.owner_consent_chain),
            ):
                try:
                    if self.mode == VerificationMode.LEAF_ONLY:
                        if chain.hops:
                            self._verify_hop_block_signature_only(chain.hops[-1], ts)
                        else:
                            self._verify_root_block_crypto(chain.root, ts)
                    else:
                        self.verify_single_chain_full(chain, now=ts, check_revocation=True)
                except TokenExpiredError as exc:
                    return _finish(
                        False,
                        401,
                        "DENY",
                        "TASK_AUTH_EXPIRED",
                        f"{label}: {exc}",
                        **co_meta,
                    )
                except RevocationError as exc:
                    return _finish(
                        False,
                        403,
                        "DENY",
                        "LINEAGE_REVOKED",
                        f"{label}: {exc}",
                        **co_meta,
                    )
                except (TokenError, CryptoError) as exc:
                    return _finish(
                        False,
                        403,
                        "DENY",
                        "INVALID_CHAIN_IN_COAUTH",
                        f"{label} ({chain.lineage_path}): {exc}",
                        **co_meta,
                    )

            clean_owner = str(resource_owner_sub).strip() if resource_owner_sub else ""
            if clean_owner and parsed.owner_sub != clean_owner:
                return _finish(
                    False,
                    403,
                    "DENY",
                    "CROSS_PRINCIPAL_DENIED",
                    f"CoAuthorizedToken owner_sub {parsed.owner_sub!r} != resource owner {clean_owner!r}",
                    **co_meta,
                )

            if allowed_co_auth_tools is not None and tool is not None:
                co_allow_set = {str(t) for t in allowed_co_auth_tools if str(t).strip()}
                if tool not in co_allow_set:
                    return _finish(
                        False,
                        403,
                        "DENY",
                        "CROSS_PRINCIPAL_DENIED",
                        f"Tool {tool!r} is owner-only and forbidden under cross-principal co-authorization",
                        **co_meta,
                    )

            eff_perms = parsed.requester_chain.leaf_permissions.intersect(
                parsed.owner_consent_chain.leaf_permissions
            )
            if check_invocation_lattice:
                if eff_perms.is_empty():
                    return _finish(
                        False,
                        403,
                        "DENY",
                        "LATTICE_PERMISSION_DENIED",
                        "Empty permission intersection between requester and owner consent chains",
                        **co_meta,
                    )
                ok, reason = eff_perms.check_invocation(
                    method=method,
                    tool=tool,
                    arguments=arguments,
                    call_index=1,
                )
                if not ok:
                    code = (
                        "QUOTA_EXCEEDED"
                        if "max_calls" in reason
                        else "LATTICE_PERMISSION_DENIED"
                    )
                    return _finish(False, 403, "DENY", code, reason, **co_meta)

                combined_quota_blocks: List[Tuple[str, int]] = []
                seen_qb: Set[str] = set()
                for ch in parsed.parent_chains:
                    ch_qb = (
                        [(ch.leaf_block_hash, ch.leaf_permissions.max_calls)]
                        if self.mode == VerificationMode.LEAF_ONLY
                        else _chain_block_quotas(ch)
                    )
                    for bh, mc in ch_qb:
                        if bh not in seen_qb:
                            seen_qb.add(bh)
                            combined_quota_blocks.append((bh, mc))
                q_ok, q_reason = self._quota.try_consume_chain(
                    parsed.task_id, combined_quota_blocks, now=ts
                )
                if not q_ok:
                    return _finish(
                        False, 403, "DENY", "QUOTA_EXCEEDED", q_reason, **co_meta
                    )

            return _finish(
                True,
                200,
                "ALLOW_CO_AUTHORIZED",
                "OK",
                f"Authorized via verified Dual-Principal CoAuthorizedToken ({parsed.requester_sub} & {parsed.owner_sub})",
                active_paths=tuple(parsed.lineage_paths),
                effective_permissions=eff_perms.to_dict(),
                **co_meta,
            )

        # =====================================================================
        # Branch 2: Multi-Parent DAG Envelope (Fagin Multi-Path Semantics)
        # =====================================================================
        assert isinstance(parsed, MultiParentToken)
        try:
            mp_hashes = tuple(c.leaf_block_hash for c in parsed.parent_chains)
            mp_meta = {
                "anchored_revocation_version": anchored_ver,
                "task_id": parsed.task_id,
                "sub": parsed.sub,
                "holder_spiffe_id": parsed.holder_spiffe_id,
                "lineage_path": "|".join(parsed.lineage_paths),
                "hop_index": max(c.depth for c in parsed.parent_chains),
                "epoch": max(c.current_epoch for c in parsed.parent_chains),
                "root_block_hash": parsed.parent_chains[0].root_block_hash,
                "parent_block_hash": None,
                "leaf_block_hash": parsed.envelope_hash,
                "multi_parent_hashes": mp_hashes,
            }
            expected_dpop_jkt = self._verify_multiparent_envelope_crypto(parsed, ts)
        except (TokenError, CryptoError) as exc:
            return _finish(
                False,
                401,
                "DENY",
                "MULTIPARENT_ENVELOPE_INVALID",
                str(exc),
                task_id=parsed.task_id,
                sub=parsed.sub,
            )

        dpop_jti = None
        if require_dpop:
            try:
                dpop_info = self.dpop_verifier.verify_proof(
                    dpop_proof=dpop_proof or "",
                    expected_htm=htm,
                    expected_htu=htu,
                    access_token=compact_token,
                    expected_jkt=expected_dpop_jkt,
                    now=ts,
                )
                dpop_jti = str(dpop_info["jti"])
            except DPoPError as exc:
                dpop_st = 403 if "sender key thumbprint mismatch" in str(exc) else 401
                return _finish(False, dpop_st, "DENY", "DPOP_FAILED", str(exc), **mp_meta)

        mp_meta["dpop_jti"] = dpop_jti

        # 1. Verify full cryptography & monotonicity of EVERY parent chain first.
        #    Purely expired branches (`TokenExpiredError`) are collected into `expired_chains`
        #    so surviving unexpired branches degrade smoothly under Fagin's DAG semantics;
        #    forged signatures, broken links, cycles, or privilege escalations fail the whole envelope!
        unexpired_chains: List[LineageToken] = []
        expired_chains: List[LineageToken] = []

        for chain in parsed.parent_chains:
            try:
                if self.mode == VerificationMode.LEAF_ONLY:
                    if chain.hops:
                        self._verify_hop_block_signature_only(chain.hops[-1], ts)
                    else:
                        self._verify_root_block_crypto(chain.root, ts)
                else:
                    self.verify_single_chain_full(chain, now=ts, check_revocation=False)
                unexpired_chains.append(chain)
            except TokenExpiredError:
                expired_chains.append(chain)
            except (TokenError, CryptoError) as exc:
                return _finish(
                    False,
                    403,
                    "DENY",
                    "INVALID_CHAIN_IN_MULTIPARENT",
                    f"Branch {chain.lineage_path}: {exc}",
                    **mp_meta,
                )

        # 2. Partition unexpired chains into surviving vs revoked FIRST (before Step 2b
        #    re-anchoring!) so a REVOKED continuation chain can NEVER resurrect an expired
        #    pre-checkpoint branch (`[HIGH-M9-02]`).
        surviving_chains: List[LineageToken] = []
        revoked_chains: List[LineageToken] = []

        if self.mode == VerificationMode.LEAF_ONLY:
            surviving_chains = list(unexpired_chains)
        else:
            holder_quarantine = self.trie.check_workloads([parsed.holder_spiffe_id])
            if holder_quarantine is not None:
                return _finish(
                    False,
                    403,
                    "DENY",
                    "HOLDER_WORKLOAD_QUARANTINED",
                    f"Convergence holder {parsed.holder_spiffe_id} quarantined",
                    pruned_revoked_paths=tuple(parsed.lineage_paths),
                    **mp_meta,
                )

            for chain in unexpired_chains:
                rev_ev = self.trie.check_chain(
                    chain.lineage_path,
                    chain.visited_subjects,
                    trust_domain=chain.root.issuer_trust_domain,
                )
                if rev_ev is None:
                    surviving_chains.append(chain)
                else:
                    revoked_chains.append(chain)

        # 2b. Pre-checkpoint branches whose RootBlock hash is a strict directed ancestor
        #     (`R_old <- ... <- R_live`) of at least one SURVIVING UNEXPIRED & UNREVOKED
        #     CA-signed ContinuationToken remain valid after full signature, monotonicity,
        #     and revocation verification (`[HIGH-M9-02]`).
        if surviving_chains and expired_chains:
            prior_map = {
                ch.root_block_hash: ch.root.prior_root_block_hash
                for ch in parsed.parent_chains
            }
            re_anchored_roots: Set[str] = set()
            frontier_r = [
                ch.root.prior_root_block_hash
                for ch in surviving_chains
                if ch.root.prior_root_block_hash is not None
            ]
            while frontier_r:
                pr = frontier_r.pop()
                if pr and pr not in re_anchored_roots:
                    re_anchored_roots.add(pr)
                    nxt_pr = prior_map.get(pr)
                    if nxt_pr:
                        frontier_r.append(nxt_pr)
            if re_anchored_roots:
                still_expired: List[LineageToken] = []
                for exp_ch in expired_chains:
                    if exp_ch.root_block_hash in re_anchored_roots:
                        try:
                            self.verify_single_chain_full(
                                exp_ch, now=exp_ch.root.iat, check_revocation=False
                            )
                        except (TokenError, CryptoError) as exc:
                            return _finish(
                                False,
                                403,
                                "DENY",
                                "INVALID_CHAIN_IN_MULTIPARENT",
                                f"Re-anchored branch {exp_ch.lineage_path}: {exc}",
                                **mp_meta,
                            )
                        if self.mode != VerificationMode.LEAF_ONLY:
                            rev_exp = self.trie.check_chain(
                                exp_ch.lineage_path,
                                exp_ch.visited_subjects,
                                trust_domain=exp_ch.root.issuer_trust_domain,
                            )
                            if rev_exp is not None:
                                revoked_chains.append(exp_ch)
                                continue
                        surviving_chains.append(exp_ch)
                    else:
                        still_expired.append(exp_ch)
                expired_chains = still_expired

        pruned_chains = expired_chains + revoked_chains
        pruned_paths = tuple(c.lineage_path for c in pruned_chains)
        if not surviving_chains:
            reason_code = (
                "ALL_DAG_PARENT_CHAINS_REVOKED"
                if revoked_chains
                else "ALL_DAG_PARENT_CHAINS_EXPIRED"
            )
            return _finish(
                False,
                403,
                "DENY",
                reason_code,
                "All converging parent branches in MultiParentToken are revoked or expired",
                pruned_revoked_paths=pruned_paths,
                **mp_meta,
            )

        clean_owner_mp = str(resource_owner_sub).strip() if resource_owner_sub else ""
        if clean_owner_mp and parsed.sub != clean_owner_mp:
            return _finish(
                False,
                403,
                "DENY",
                "CROSS_PRINCIPAL_DENIED",
                f"Unilateral MultiParentToken principal {parsed.sub!r} is forbidden from accessing resource owned by {clean_owner_mp!r}",
                pruned_revoked_paths=pruned_paths,
                **mp_meta,
            )

        composite = CompositePermission(
            surviving_branches=tuple(
                (c.lineage_path, c.leaf_permissions) for c in surviving_chains
            )
        )

        if check_invocation_lattice:
            allowed, satisfying_paths, reasons = composite.evaluate(
                method=method,
                tool=tool,
                arguments=arguments,
            )
            if not allowed:
                pruned_would_allow = False
                if pruned_chains:
                    pruned_comp = CompositePermission(
                        surviving_branches=tuple(
                            (c.lineage_path, c.leaf_permissions) for c in pruned_chains
                        )
                    )
                    pruned_would_allow, _, _ = pruned_comp.evaluate(
                        method=method, tool=tool, arguments=arguments
                    )
                code = (
                    "REVOKED_DEPENDENCY_INSUFFICIENT_SURVIVING_PATHS"
                    if pruned_would_allow
                    else "LATTICE_PERMISSION_DENIED"
                )
                return _finish(
                    False,
                    403,
                    "DENY",
                    code,
                    f"Surviving DAG branches insufficient: {reasons}",
                    active_paths=tuple(c.lineage_path for c in surviving_chains),
                    pruned_revoked_paths=pruned_paths,
                    **mp_meta,
                )

            # Atomically consume quota across ALL blocks [B_0, ..., B_k] of the chosen satisfying branch!
            chain_by_path = {c.lineage_path: c for c in surviving_chains}
            candidate_quota_specs = [
                (
                    p,
                    [(chain_by_path[p].leaf_block_hash, chain_by_path[p].leaf_permissions.max_calls)]
                    if self.mode == VerificationMode.LEAF_ONLY
                    else _chain_block_quotas(chain_by_path[p]),
                )
                for p in satisfying_paths
            ]
            chosen_path, quota_failures = self._quota.try_consume_first_satisfying_branch(
                parsed.task_id, candidate_quota_specs, now=ts
            )
            if chosen_path is None:
                return _finish(
                    False,
                    403,
                    "DENY",
                    "QUOTA_EXCEEDED",
                    f"Quota exhausted across satisfying DAG branches: {quota_failures}",
                    active_paths=tuple(satisfying_paths),
                    pruned_revoked_paths=pruned_paths,
                    **mp_meta,
                )
            active_paths = tuple(satisfying_paths)
        else:
            active_paths = tuple(c.lineage_path for c in surviving_chains)

        decision_str = "ALLOW_DEGRADED_DAG" if pruned_chains else "ALLOW"
        return _finish(
            True,
            200,
            decision_str,
            "OK",
            f"Authorized via {len(active_paths)} surviving DAG branch(es)",
            active_paths=active_paths,
            pruned_revoked_paths=pruned_paths,
            effective_permissions={
                "effective_tools": sorted(composite.effective_tools),
                "effective_methods": sorted(composite.effective_methods),
                "surviving_paths": [c.lineage_path for c in surviving_chains],
                "pruned_paths": list(pruned_paths),
            },
            **mp_meta,
        )
