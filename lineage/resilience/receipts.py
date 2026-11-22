"""Cryptographically Signed Fault-Tolerance Receipts for LCT Autonomous Recovery.

Implements:
- `FailureEvidence`: Structured observation of Crash, Timeout, or Policy/Byzantine fault.
- `FailoverReceipt`: Proof of downward `Atomic Prune-and-Graft` carrying the full
  `RevocationService`-signed `RevocationEvent` + `revocation_service_svid` proving the
  failed branch was genuinely revoked before grafting the `epoch + 1` substitute.
- `SkipLevelReceipt`: Proof of upward `Authenticated Skip-Level Return` binding full
  `LineageToken`, `FailureEvidence`, and `result_sha256`.
"""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from lineage.common.crypto import (
    CryptoError,
    canonical_json_bytes,
    compute_jwk_thumbprint,
    jws_sign_compact,
    jws_verify_compact,
    require_finite_timestamp,
    sha256_canonical_b64url,
)
from lineage.identity.spiffe import IdentityError, SpiffeId, WorkloadIdentity
from lineage.identity.trust_bundle import TrustBundleResolver
from lineage.protocol.token import LineageToken, TokenError, decode_token
from lineage.revocation.trie import RevocationEvent, RevocationKind


class ResilienceError(Exception):
    """Raised when a fault-tolerance receipt or recovery protocol check fails."""


class FaultType(str, enum.Enum):
    CRASH = "CRASH"
    TIMEOUT = "TIMEOUT"
    POLICY_BYZANTINE = "POLICY_BYZANTINE"


@dataclass(frozen=True)
class FailureEvidence:
    """Structured witness of a peer node failure."""

    failed_spiffe_id: str
    failed_endpoint: str
    fault_type: FaultType
    error_detail: str
    attempt_count: int
    observed_at: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "failed_spiffe_id": self.failed_spiffe_id,
            "failed_endpoint": self.failed_endpoint,
            "fault_type": self.fault_type.value,
            "error_detail": self.error_detail,
            "attempt_count": self.attempt_count,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "FailureEvidence":
        if not isinstance(raw, Mapping):
            raise ResilienceError("FailureEvidence must be a mapping")
        SpiffeId.parse(str(raw["failed_spiffe_id"]))
        obs_at = require_finite_timestamp(raw["observed_at"], "FailureEvidence.observed_at")
        return cls(
            failed_spiffe_id=str(raw["failed_spiffe_id"]),
            failed_endpoint=str(raw.get("failed_endpoint", "")),
            fault_type=FaultType(str(raw["fault_type"])),
            error_detail=str(raw.get("error_detail", "")),
            attempt_count=max(1, int(raw.get("attempt_count", 1))),
            observed_at=obs_at,
        )


@dataclass(frozen=True)
class FailoverReceipt:
    """Signed cryptographic receipt attesting an Atomic Prune-and-Graft transition."""

    receipt_id: str
    task_id: str
    parent_spiffe_id: str
    parent_svid: str
    pruned_lineage_path: str
    revocation_version: int
    revocation_event_sig: str
    failed_delegate_spiffe_id: str
    substitute_delegate_spiffe_id: str
    new_lineage_path: str
    old_epoch: int
    new_epoch: int
    failure_evidence: FailureEvidence
    timestamp: float
    jws_signature: str
    revocation_event: Optional[Dict[str, Any]] = None
    revocation_service_svid: str = ""

    def core_claims(self) -> Dict[str, Any]:
        claims: Dict[str, Any] = {
            "receipt_id": self.receipt_id,
            "task_id": self.task_id,
            "parent_spiffe_id": self.parent_spiffe_id,
            "pruned_lineage_path": self.pruned_lineage_path,
            "revocation_version": self.revocation_version,
            "revocation_event_sig": self.revocation_event_sig,
            "failed_delegate_spiffe_id": self.failed_delegate_spiffe_id,
            "substitute_delegate_spiffe_id": self.substitute_delegate_spiffe_id,
            "new_lineage_path": self.new_lineage_path,
            "old_epoch": self.old_epoch,
            "new_epoch": self.new_epoch,
            "failure_evidence": self.failure_evidence.to_dict(),
            "timestamp": self.timestamp,
        }
        if self.revocation_event is not None:
            claims["revocation_event"] = self.revocation_event
        if self.revocation_service_svid:
            claims["revocation_service_svid"] = self.revocation_service_svid
        return claims

    def to_dict(self) -> Dict[str, Any]:
        d = self.core_claims()
        d["parent_svid"] = self.parent_svid
        d["jws_signature"] = self.jws_signature
        return d

    @classmethod
    def create_and_sign(
        cls,
        parent_identity: WorkloadIdentity,
        task_id: str,
        pruned_lineage_path: str,
        revocation_version: int,
        revocation_event_sig: str,
        failed_delegate_spiffe_id: str,
        substitute_delegate_spiffe_id: str,
        new_lineage_path: str,
        old_epoch: int,
        new_epoch: int,
        failure_evidence: FailureEvidence,
        revocation_event: Optional[Mapping[str, Any]] = None,
        revocation_service_svid: str = "",
        now: Optional[float] = None,
    ) -> "FailoverReceipt":
        if new_epoch != old_epoch + 1:
            raise ResilienceError(
                f"Atomic Prune-and-Graft requires new_epoch == old_epoch + 1 ({new_epoch} != {old_epoch + 1})"
            )
        rev_ver = int(revocation_version)
        if rev_ver < 1:
            raise ResilienceError("Atomic Prune-and-Graft requires revocation_version >= 1")

        if pruned_lineage_path == new_lineage_path:
            raise ResilienceError(
                "Substitute branch must have distinct lineage_path from pruned branch"
            )

        ts = require_finite_timestamp(time.time() if now is None else now, "timestamp")
        rev_ev_dict = dict(revocation_event) if revocation_event is not None else None
        resolved_svc_svid = str(
            revocation_service_svid
            or (rev_ev_dict.get("service_svid", "") if rev_ev_dict else "")
        )

        provisional = cls(
            receipt_id=f"failover-{uuid.uuid4().hex}",
            task_id=task_id,
            parent_spiffe_id=parent_identity.spiffe_id,
            parent_svid=parent_identity.workload_svid,
            pruned_lineage_path=pruned_lineage_path,
            revocation_version=rev_ver,
            revocation_event_sig=revocation_event_sig,
            failed_delegate_spiffe_id=failed_delegate_spiffe_id,
            substitute_delegate_spiffe_id=substitute_delegate_spiffe_id,
            new_lineage_path=new_lineage_path,
            old_epoch=old_epoch,
            new_epoch=new_epoch,
            failure_evidence=failure_evidence,
            timestamp=ts,
            jws_signature="",
            revocation_event=rev_ev_dict,
            revocation_service_svid=resolved_svc_svid,
        )
        sig = jws_sign_compact(
            payload=provisional.core_claims(),
            keypair=parent_identity.keypair,
            typ="lct-failover-receipt+jwt",
        )
        return cls(**{**provisional.__dict__, "jws_signature": sig})

    @classmethod
    def from_dict_and_verify(
        cls,
        raw: Mapping[str, Any],
        trust_resolver: TrustBundleResolver,
        now: Optional[float] = None,
        trusted_revocation_spiffe_ids: Optional[Iterable[str]] = None,
        expected_trust_domain: Optional[str] = None,
    ) -> "FailoverReceipt":
        if not isinstance(raw, Mapping):
            raise ResilienceError("FailoverReceipt must be a JSON object")
        try:
            receipt_ts = require_finite_timestamp(
                raw["timestamp"], "FailoverReceipt.timestamp"
            )
            eval_ts = (
                receipt_ts
                if now is None
                else require_finite_timestamp(now, "now")
            )
            parent_svid = str(raw["parent_svid"])
            parent_spiffe = SpiffeId.parse(str(raw["parent_spiffe_id"])).uri
            svid_claims = trust_resolver.verify_workload_svid(
                parent_svid, expected_spiffe_id=parent_spiffe, now=eval_ts
            )
            parent_jwk = svid_claims["cnf"]["jwk"]

            evidence = FailureEvidence.from_dict(raw["failure_evidence"])
            rev_ev_raw = raw.get("revocation_event")
            rev_ev_dict = (
                dict(rev_ev_raw) if isinstance(rev_ev_raw, Mapping) else None
            )
            rev_svc_svid = str(raw.get("revocation_service_svid", ""))

            receipt = cls(
                receipt_id=str(raw["receipt_id"]),
                task_id=str(raw["task_id"]),
                parent_spiffe_id=parent_spiffe,
                parent_svid=parent_svid,
                pruned_lineage_path=str(raw["pruned_lineage_path"]),
                revocation_version=int(raw["revocation_version"]),
                revocation_event_sig=str(raw["revocation_event_sig"]),
                failed_delegate_spiffe_id=SpiffeId.parse(
                    str(raw["failed_delegate_spiffe_id"])
                ).uri,
                substitute_delegate_spiffe_id=SpiffeId.parse(
                    str(raw["substitute_delegate_spiffe_id"])
                ).uri,
                new_lineage_path=str(raw["new_lineage_path"]),
                old_epoch=int(raw["old_epoch"]),
                new_epoch=int(raw["new_epoch"]),
                failure_evidence=evidence,
                timestamp=receipt_ts,
                jws_signature=str(raw["jws_signature"]),
                revocation_event=rev_ev_dict,
                revocation_service_svid=rev_svc_svid,
            )
            _, signed_claims = jws_verify_compact(
                receipt.jws_signature,
                parent_jwk,
                expected_typ="lct-failover-receipt+jwt",
            )
        except (KeyError, ValueError, TypeError, IdentityError, CryptoError) as exc:
            raise ResilienceError(f"Invalid FailoverReceipt: {exc}") from exc

        if canonical_json_bytes(signed_claims) != canonical_json_bytes(receipt.core_claims()):
            raise ResilienceError("FailoverReceipt payload tampering detected")
        if receipt.new_epoch != receipt.old_epoch + 1:
            raise ResilienceError("FailoverReceipt epoch increment invalid")
        if receipt.revocation_version < 1 or not receipt.revocation_event_sig:
            raise ResilienceError("FailoverReceipt missing proof of prior revocation")

        # Cryptographically verify RevocationService's signature AND authoritative identity (`[HIGH-R2-03]`)!
        if receipt.revocation_event is None or not receipt.revocation_service_svid:
            raise ResilienceError(
                "FailoverReceipt missing verifiable RevocationEvent or revocation_service_svid"
            )
        try:
            rev_svc_claims = trust_resolver.verify_workload_svid(
                receipt.revocation_service_svid, now=eval_ts
            )
            rev_svc_spiffe = SpiffeId.parse(str(rev_svc_claims["sub"]))
            rev_svc_jwk = rev_svc_claims["cnf"]["jwk"]
            parsed_rev_ev = RevocationEvent.from_dict(receipt.revocation_event)
            _, signed_rev_claims = jws_verify_compact(
                parsed_rev_ev.service_signature,
                rev_svc_jwk,
                expected_typ="lct-revocation-event+jwt",
            )
        except (IdentityError, CryptoError, ValueError, KeyError) as exc:
            raise ResilienceError(
                f"FailoverReceipt RevocationService signature verification failed: {exc}"
            ) from exc

        target_td = (
            str(expected_trust_domain)
            if expected_trust_domain
            else SpiffeId.parse(receipt.parent_spiffe_id).trust_domain
        )

        # Separation of duties: no failover participant may self-certify its own RevocationEvent!
        if rev_svc_spiffe.uri in {
            receipt.parent_spiffe_id,
            receipt.failed_delegate_spiffe_id,
            receipt.substitute_delegate_spiffe_id,
        }:
            raise ResilienceError(
                f"Self-certified RevocationEvent rejected: revocation_service_svid {rev_svc_spiffe.uri!r} cannot be a failover participant"
            )

        if trusted_revocation_spiffe_ids is not None:
            allowed_rev_ids = {
                SpiffeId.parse(str(x)).uri for x in trusted_revocation_spiffe_ids
            }
            if rev_svc_spiffe.uri not in allowed_rev_ids:
                raise ResilienceError(
                    f"Untrusted revocation_service_svid principal {rev_svc_spiffe.uri!r} not in trusted_revocation_spiffe_ids"
                )
        else:
            if rev_svc_spiffe.trust_domain != target_td or not (
                rev_svc_spiffe.path.startswith("/ns/sys/sa/rev")
                or rev_svc_spiffe.path.endswith(
                    ("/revocation", "/revocation-service", "/revocation-svc")
                )
            ):
                raise ResilienceError(
                    f"Unauthorized revocation_service_svid principal {rev_svc_spiffe.uri!r} for trust_domain {target_td!r}: "
                    "must be an authoritative same-domain system RevocationService workload"
                )

        if (
            parsed_rev_ev.service_svid
            and parsed_rev_ev.service_svid != receipt.revocation_service_svid
        ):
            raise ResilienceError(
                "FailoverReceipt embedded RevocationEvent.service_svid mismatch with revocation_service_svid"
            )

        if signed_rev_claims != parsed_rev_ev.core_claims():
            raise ResilienceError("FailoverReceipt embedded RevocationEvent claims tampered")
        if parsed_rev_ev.kind != RevocationKind.SUBTREE:
            raise ResilienceError(
                f"FailoverReceipt RevocationEvent kind must be SUBTREE, got {parsed_rev_ev.kind!r}"
            )
        if parsed_rev_ev.trust_domain != target_td:
            raise ResilienceError(
                f"FailoverReceipt RevocationEvent trust_domain mismatch: got {parsed_rev_ev.trust_domain!r}, expected {target_td!r}"
            )
        if (
            parsed_rev_ev.target != receipt.pruned_lineage_path
            or parsed_rev_ev.version != receipt.revocation_version
            or parsed_rev_ev.service_signature != receipt.revocation_event_sig
        ):
            raise ResilienceError(
                "FailoverReceipt RevocationEvent does not match pruned_lineage_path/version"
            )
        if parsed_rev_ev.timestamp > receipt.timestamp + 1.0:
            raise ResilienceError(
                "FailoverReceipt temporal violation: revocation occurred after failover graft"
            )

        prefix_req = f"/{receipt.task_id}/"
        if not receipt.pruned_lineage_path.startswith(
            prefix_req
        ) or not receipt.new_lineage_path.startswith(prefix_req):
            raise ResilienceError("FailoverReceipt lineage paths do not match task_id")
        if receipt.pruned_lineage_path == receipt.new_lineage_path:
            raise ResilienceError("FailoverReceipt new_lineage_path equals pruned_lineage_path")
        return receipt


@dataclass(frozen=True)
class SkipLevelReceipt:
    """Signed cryptographic receipt for Authenticated Skip-Level Return (C -> A skipping B_1)."""

    receipt_id: str
    task_id: str
    child_spiffe_id: str
    child_svid: str
    skipped_ancestors: Tuple[str, ...]
    target_ancestor_spiffe_id: str
    target_ancestor_jkt: str
    compact_lineage_token: str
    failure_evidence: FailureEvidence
    result_payload: Dict[str, Any]
    result_sha256: str
    timestamp: float
    jws_signature: str

    def core_claims(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "task_id": self.task_id,
            "child_spiffe_id": self.child_spiffe_id,
            "skipped_ancestors": list(self.skipped_ancestors),
            "target_ancestor_spiffe_id": self.target_ancestor_spiffe_id,
            "target_ancestor_jkt": self.target_ancestor_jkt,
            "compact_lineage_token": self.compact_lineage_token,
            "failure_evidence": self.failure_evidence.to_dict(),
            "result_sha256": self.result_sha256,
            "timestamp": self.timestamp,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.core_claims()
        d["child_svid"] = self.child_svid
        d["result_payload"] = self.result_payload
        d["jws_signature"] = self.jws_signature
        return d

    @classmethod
    def create_and_sign(
        cls,
        child_identity: WorkloadIdentity,
        lineage_token: LineageToken,
        skipped_ancestors: Iterable[str],
        target_ancestor_spiffe_id: str,
        failure_evidence: FailureEvidence,
        result_payload: Mapping[str, Any],
        now: Optional[float] = None,
    ) -> "SkipLevelReceipt":
        if lineage_token.holder_spiffe_id != child_identity.spiffe_id:
            raise ResilienceError("Child is not the holder of the supplied LineageToken")
        if lineage_token.holder_cnf_jkt != child_identity.jkt:
            raise ResilienceError("Child key jkt does not match LineageToken holder_cnf_jkt")

        skipped_tuple = tuple(SpiffeId.parse(s).uri for s in skipped_ancestors)
        if not skipped_tuple:
            raise ResilienceError("SkipLevelReceipt must specify at least one skipped ancestor")

        target_spiffe = SpiffeId.parse(target_ancestor_spiffe_id).uri
        target_jkt = resolve_verified_ancestor_jkt(lineage_token, target_spiffe)

        delegates = lineage_token.ordered_delegates
        if target_spiffe not in delegates:
            raise ResilienceError(
                f"Target ancestor {target_spiffe!r} is not on child's delegation chain {delegates}"
            )
        target_idx = delegates.index(target_spiffe)
        child_idx = len(delegates) - 1
        if target_idx >= child_idx:
            raise ResilienceError("Target ancestor must be strictly upstream of child")

        for sk in skipped_tuple:
            if sk not in delegates:
                raise ResilienceError(f"Skipped node {sk!r} is not on delegation chain")
            sk_idx = delegates.index(sk)
            if not (target_idx < sk_idx < child_idx):
                raise ResilienceError(
                    f"Skipped ancestor {sk!r} must lie strictly between {target_spiffe!r} and {child_identity.spiffe_id!r}"
                )

        res_dict = dict(result_payload)
        res_hash = sha256_canonical_b64url(res_dict)
        ts = require_finite_timestamp(time.time() if now is None else now, "timestamp")

        provisional = cls(
            receipt_id=f"skip-{uuid.uuid4().hex}",
            task_id=lineage_token.task_id,
            child_spiffe_id=child_identity.spiffe_id,
            child_svid=child_identity.workload_svid,
            skipped_ancestors=skipped_tuple,
            target_ancestor_spiffe_id=target_spiffe,
            target_ancestor_jkt=target_jkt,
            compact_lineage_token=lineage_token.encode_compact(),
            failure_evidence=failure_evidence,
            result_payload=res_dict,
            result_sha256=res_hash,
            timestamp=ts,
            jws_signature="",
        )
        sig = jws_sign_compact(
            payload=provisional.core_claims(),
            keypair=child_identity.keypair,
            typ="lct-skip-return+jwt",
        )
        return cls(**{**provisional.__dict__, "jws_signature": sig})

    @classmethod
    def from_dict_and_verify(
        cls,
        raw: Mapping[str, Any],
        trust_resolver: TrustBundleResolver,
        now: Optional[float] = None,
    ) -> Tuple["SkipLevelReceipt", LineageToken]:
        """Verify receipt signature, SVID, result hash, and ancestral topological validity."""
        if not isinstance(raw, Mapping):
            raise ResilienceError("SkipLevelReceipt must be a JSON object")
        try:
            receipt_ts = require_finite_timestamp(
                raw["timestamp"], "SkipLevelReceipt.timestamp"
            )
            eval_ts = (
                time.time()
                if now is None
                else require_finite_timestamp(now, "now")
            )
            child_spiffe = SpiffeId.parse(str(raw["child_spiffe_id"])).uri
            child_svid = str(raw["child_svid"])
            svid_claims = trust_resolver.verify_workload_svid(
                child_svid, expected_spiffe_id=child_spiffe, now=eval_ts
            )
            child_jwk = svid_claims["cnf"]["jwk"]
            child_jkt = svid_claims["cnf"]["jkt"]

            res_payload = raw.get("result_payload")
            if not isinstance(res_payload, Mapping):
                raise ResilienceError("result_payload must be a mapping")
            res_dict = dict(res_payload)
            computed_res_hash = sha256_canonical_b64url(res_dict)
            if computed_res_hash != raw.get("result_sha256"):
                raise ResilienceError("SkipLevelReceipt result_sha256 integrity mismatch")

            skipped_raw = raw.get("skipped_ancestors", [])
            if not isinstance(skipped_raw, list) or not skipped_raw:
                raise ResilienceError("SkipLevelReceipt requires non-empty skipped_ancestors")

            receipt = cls(
                receipt_id=str(raw["receipt_id"]),
                task_id=str(raw["task_id"]),
                child_spiffe_id=child_spiffe,
                child_svid=child_svid,
                skipped_ancestors=tuple(SpiffeId.parse(str(s)).uri for s in skipped_raw),
                target_ancestor_spiffe_id=SpiffeId.parse(
                    str(raw["target_ancestor_spiffe_id"])
                ).uri,
                target_ancestor_jkt=str(raw["target_ancestor_jkt"]),
                compact_lineage_token=str(raw["compact_lineage_token"]),
                failure_evidence=FailureEvidence.from_dict(raw["failure_evidence"]),
                result_payload=res_dict,
                result_sha256=computed_res_hash,
                timestamp=receipt_ts,
                jws_signature=str(raw["jws_signature"]),
            )

            _, signed_claims = jws_verify_compact(
                receipt.jws_signature,
                child_jwk,
                expected_typ="lct-skip-return+jwt",
            )
        except (KeyError, ValueError, TypeError, IdentityError, CryptoError) as exc:
            raise ResilienceError(f"Invalid SkipLevelReceipt: {exc}") from exc

        if canonical_json_bytes(signed_claims) != canonical_json_bytes(receipt.core_claims()):
            raise ResilienceError("SkipLevelReceipt payload tampering detected")

        try:
            parsed_tok = decode_token(receipt.compact_lineage_token)
        except TokenError as exc:
            raise ResilienceError(f"Invalid embedded LineageToken: {exc}") from exc

        if not isinstance(parsed_tok, LineageToken):
            raise ResilienceError("SkipLevelReceipt requires single-branch LineageToken")

        if parsed_tok.task_id != receipt.task_id:
            raise ResilienceError("SkipLevelReceipt task_id mismatch with LineageToken")
        if parsed_tok.holder_spiffe_id != child_spiffe or parsed_tok.holder_cnf_jkt != child_jkt:
            raise ResilienceError("SkipLevelReceipt signer does not match LineageToken leaf holder")

        expected_anc_jkt = resolve_verified_ancestor_jkt(
            parsed_tok, receipt.target_ancestor_spiffe_id
        )
        if receipt.target_ancestor_jkt != expected_anc_jkt:
            raise ResilienceError("Target ancestor JWK thumbprint mismatch against B_0/chain")

        delegates = parsed_tok.ordered_delegates
        target_idx = delegates.index(receipt.target_ancestor_spiffe_id)
        child_idx = len(delegates) - 1
        if target_idx >= child_idx:
            raise ResilienceError("Target ancestor is not upstream of child")
        for sk in receipt.skipped_ancestors:
            if sk not in delegates:
                raise ResilienceError(f"Skipped node {sk!r} not in lineage chain")
            sk_idx = delegates.index(sk)
            if not (target_idx < sk_idx < child_idx):
                raise ResilienceError("Invalid topological ordering of skipped_ancestors")

        if receipt.failure_evidence.failed_spiffe_id not in receipt.skipped_ancestors:
            raise ResilienceError(
                "FailureEvidence failed_spiffe_id must be one of skipped_ancestors"
            )

        return receipt, parsed_tok


def resolve_verified_ancestor_jkt(
    token: LineageToken, ancestor_spiffe_id: str
) -> str:
    """Resolve pre-authorized ancestor JWK thumbprint from B_0.ancestor_keys or chain."""
    if ancestor_spiffe_id in token.root.ancestor_keys:
        return str(token.root.ancestor_keys[ancestor_spiffe_id]["jkt"])
    if token.root.delegate_spiffe_id == ancestor_spiffe_id:
        return token.root.cnf_jkt
    for hop in token.hops:
        if hop.issuer_spiffe_id == ancestor_spiffe_id:
            return compute_jwk_thumbprint(hop.issuer_jwk)
        if hop.delegate_spiffe_id == ancestor_spiffe_id:
            return hop.cnf_jkt
    raise ResilienceError(
        f"Ancestor {ancestor_spiffe_id!r} not found in B_0.ancestor_keys or delegation chain"
    )
