"""Cryptographic Lineage Capability Tree (LCT) Tokens & Multi-Parent DAG Envelopes.

Implements:
- `RootBlock` (B_0): Root authority anchor locking `task_id`, `sub`, `max_depth`,
  root `PermissionLattice` P_0, pre-authorized `ancestor_keys`, and first-hop `cnf_jkt`.
- `AttenuationBlock` (B_i): Offline public-key chained attenuation locking `parent_hash`,
  single-segment `lineage_path` extension, monotonic lattice P_i <= P_{i-1}, `epoch`,
  cycle-free `delegate_spiffe_id`, and next-hop `cnf_jkt`.
- `LineageToken`: Single root-to-leaf delegation chain (`lct1.<b64url>`).
- `MultiParentToken`: N-to-1 / M-to-N DAG convergence envelope (`lctmp1.<b64url>`)
  binding multiple upstream `LineageToken` chains for the same `(task_id, sub, holder)`.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple, Union
from urllib.parse import urlsplit

from lineage.common.crypto import (
    CryptoError,
    b64url_decode,
    b64url_encode,
    canonical_json_bytes,
    compute_jwk_thumbprint,
    jwk_to_public_key,
    jws_sign_compact,
    jws_verify_compact,
    require_finite_timestamp,
    sha256_canonical_b64url,
    strict_json_loads,
)
from lineage.identity.spiffe import IdentityError, SpiffeId, TrustDomainCA, WorkloadIdentity
from lineage.identity.trust_bundle import TrustBundleResolver
from lineage.protocol.lattice import LatticeError, PermissionLattice

_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,128}$")

LCT_WIRE_PREFIX = "lct1."
LCT_MP_WIRE_PREFIX = "lctmp1."


class TokenError(Exception):
    """Base exception for LCT token construction or parsing errors."""


class LatticeAttenuationError(TokenError):
    """Raised when a child block attempts to expand permissions beyond its parent."""


class MaxDepthExceededError(TokenError):
    """Raised when delegation hop_index exceeds B_0.max_depth."""


class CycleDetectedError(TokenError):
    """Raised when a delegation chain revisits an already-visited subject SPIFFE ID."""


class TokenExpiredError(TokenError):
    """Raised when a cryptographically valid LCT chain has exceeded its temporal TTL."""


def validate_clean_endpoint_url(url: str, field_name: str = "return_endpoint") -> str:
    """Validate that `url` is a clean `http(s)://<host>[:<port>]` origin without path/query/fragment/userinfo."""
    if not isinstance(url, str) or not url or len(url) > 1024:
        raise TokenError(f"Invalid empty or oversized {field_name}: {url!r}")
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in url) or "\\" in url:
        raise TokenError(f"Control/whitespace/backslash forbidden in {field_name}: {url!r}")
    sp = urlsplit(url)
    if sp.scheme not in ("http", "https") or not sp.hostname:
        raise TokenError(f"Invalid scheme or hostname in {field_name}: {url!r}")
    if sp.username is not None or sp.password is not None or "@" in sp.netloc:
        raise TokenError(f"Userinfo '@' forbidden in {field_name}: {url!r}")
    if sp.query or sp.fragment:
        raise TokenError(f"Query or fragment forbidden in {field_name}: {url!r}")
    if sp.path not in ("", "/"):
        raise TokenError(
            f"Path suffix {sp.path!r} forbidden in base {field_name} (expected pure origin 'http(s)://host[:port]')"
        )
    try:
        port = sp.port
    except ValueError as exc:
        raise TokenError(f"Invalid port in {field_name}: {url!r}") from exc
    host_str = sp.hostname.lower()
    netloc = f"{host_str}:{port}" if port is not None else host_str
    return f"{sp.scheme}://{netloc}"


def validate_principal_domain_consistency(sub: str, issuer_trust_domain: str) -> str:
    """Enforce that if `sub` specifies a domain (`...@<domain>`), it matches `issuer_trust_domain`."""
    clean_sub = str(sub).strip()
    if not clean_sub:
        raise TokenError("Principal 'sub' must be non-empty")
    if "@" in clean_sub:
        sub_domain = clean_sub.rsplit("@", 1)[1].strip()
        if sub_domain != issuer_trust_domain:
            raise TokenError(
                f"Principal home-domain mismatch: sub {clean_sub!r} cannot be rooted by {issuer_trust_domain!r}"
            )
    return clean_sub


def validate_segment(seg: str, field_name: str = "segment") -> str:
    if not isinstance(seg, str) or not seg or seg in (".", ".."):
        raise TokenError(f"Invalid empty or dot {field_name}: {seg!r}")
    if "/" in seg or not _SEGMENT_RE.match(seg):
        raise TokenError(
            f"Invalid characters in {field_name} {seg!r} (must match [A-Za-z0-9._:@-]+ without '/')"
        )
    return seg


def split_lineage_path(path: str) -> List[str]:
    """Validate and split `/<task_id>/<seg0>/...` into validated path segments."""
    if not isinstance(path, str) or not path.startswith("/") or path.endswith("/"):
        raise TokenError(f"lineage_path must start with '/' and not end with '/': {path!r}")
    parts = path.split("/")[1:]
    if len(parts) < 2:
        raise TokenError(f"lineage_path must have at least /<task_id>/<hop0>: {path!r}")
    return [validate_segment(p, "lineage_path_segment") for p in parts]


@dataclass(frozen=True)
class RootBlock:
    """Root Authorization Block B_0 signed by originating Trust Domain Authority."""

    version: str
    block_type: str
    jti: str
    task_id: str
    sub: str
    issuer_spiffe_id: str
    issuer_trust_domain: str
    sender_jkt: str
    delegate_spiffe_id: str
    cnf_jkt: str
    hop_segment: str
    lineage_path: str
    max_depth: int
    epoch: int
    permissions: PermissionLattice
    ancestor_keys: Dict[str, Dict[str, Any]]
    iat: float
    exp: float
    jws_signature: str

    def core_claims(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "block_type": self.block_type,
            "jti": self.jti,
            "task_id": self.task_id,
            "sub": self.sub,
            "issuer_spiffe_id": self.issuer_spiffe_id,
            "issuer_trust_domain": self.issuer_trust_domain,
            "sender_jkt": self.sender_jkt,
            "delegate_spiffe_id": self.delegate_spiffe_id,
            "cnf_jkt": self.cnf_jkt,
            "hop_segment": self.hop_segment,
            "lineage_path": self.lineage_path,
            "max_depth": self.max_depth,
            "epoch": self.epoch,
            "permissions": self.permissions.to_dict(),
            "ancestor_keys": self.ancestor_keys,
            "iat": self.iat,
            "exp": self.exp,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.core_claims()
        d["jws_signature"] = self.jws_signature
        return d

    def block_hash(self) -> str:
        """Cryptographic SHA-256 commitment over full signed RootBlock (claims + JWS)."""
        return sha256_canonical_b64url(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "RootBlock":
        if not isinstance(raw, Mapping) or raw.get("block_type") != "ROOT":
            raise TokenError("Malformed RootBlock JSON")
        try:
            task_id = validate_segment(str(raw["task_id"]), "task_id")
            hop_segment = validate_segment(str(raw["hop_segment"]), "hop_segment")
            lineage_path = str(raw["lineage_path"])
            if lineage_path != f"/{task_id}/{hop_segment}":
                raise TokenError(
                    f"RootBlock lineage_path {lineage_path!r} != '/{task_id}/{hop_segment}'"
                )
            issuer_spiffe = SpiffeId.parse(str(raw["issuer_spiffe_id"]))
            delegate_spiffe = SpiffeId.parse(str(raw["delegate_spiffe_id"]))
            issuer_td = str(raw["issuer_trust_domain"])
            if issuer_td != issuer_spiffe.trust_domain:
                raise TokenError("RootBlock issuer_trust_domain mismatch")
            max_depth = int(raw["max_depth"])
            if isinstance(raw["max_depth"], bool) or max_depth < 1 or max_depth > 32:
                raise TokenError(f"Invalid max_depth: {max_depth}")
            epoch = int(raw.get("epoch", 0))
            if epoch < 0:
                raise TokenError("Negative epoch in RootBlock")
            anc_raw = raw.get("ancestor_keys") or {}
            if not isinstance(anc_raw, Mapping):
                raise TokenError("RootBlock ancestor_keys must be a mapping")
            anc_clean: Dict[str, Dict[str, Any]] = {}
            for anc_id, info in anc_raw.items():
                SpiffeId.parse(str(anc_id))
                if not isinstance(info, Mapping) or "public_jwk" not in info or "jkt" not in info:
                    raise TokenError(f"Invalid ancestor_keys entry for {anc_id!r}")
                calc_jkt = compute_jwk_thumbprint(info["public_jwk"])
                if calc_jkt != info["jkt"]:
                    raise TokenError(f"ancestor_keys jkt mismatch for {anc_id!r}")
                raw_ret = info.get("return_endpoint")
                clean_ret = (
                    validate_clean_endpoint_url(
                        str(raw_ret), f"ancestor_keys[{anc_id}].return_endpoint"
                    )
                    if raw_ret is not None and str(raw_ret) != ""
                    else None
                )
                anc_clean[str(anc_id)] = {
                    "jkt": calc_jkt,
                    "public_jwk": dict(info["public_jwk"]),
                    "return_endpoint": clean_ret,
                }

            clean_sub = validate_principal_domain_consistency(
                str(raw["sub"]), issuer_td
            )
            iat_val = require_finite_timestamp(raw["iat"], "RootBlock.iat")
            exp_val = require_finite_timestamp(raw["exp"], "RootBlock.exp")
            return cls(
                version=str(raw["version"]),
                block_type="ROOT",
                jti=str(raw["jti"]),
                task_id=task_id,
                sub=clean_sub,
                issuer_spiffe_id=issuer_spiffe.uri,
                issuer_trust_domain=issuer_td,
                sender_jkt=str(raw["sender_jkt"]),
                delegate_spiffe_id=delegate_spiffe.uri,
                cnf_jkt=str(raw["cnf_jkt"]),
                hop_segment=hop_segment,
                lineage_path=lineage_path,
                max_depth=max_depth,
                epoch=epoch,
                permissions=PermissionLattice.from_dict(raw["permissions"]),
                ancestor_keys=anc_clean,
                iat=iat_val,
                exp=exp_val,
                jws_signature=str(raw["jws_signature"]),
            )
        except (KeyError, ValueError, TypeError, IdentityError, LatticeError, CryptoError) as exc:
            if isinstance(exc, TokenError):
                raise
            raise TokenError(f"Invalid RootBlock structure: {exc}") from exc


@dataclass(frozen=True)
class AttenuationBlock:
    """Per-hop Public-Key Chained Attenuation Block B_i (i >= 1)."""

    block_type: str
    jti: str
    hop_index: int
    task_id: str
    parent_hash: str
    hop_segment: str
    lineage_path: str
    epoch: int
    issuer_spiffe_id: str
    issuer_jwk: Dict[str, Any]
    issuer_svid: str
    issuer_return_endpoint: Optional[str]
    delegate_spiffe_id: str
    cnf_jkt: str
    target_audience: Optional[str]
    permissions: PermissionLattice
    iat: float
    exp: float
    jws_signature: str

    def core_claims(self) -> Dict[str, Any]:
        return {
            "block_type": self.block_type,
            "jti": self.jti,
            "hop_index": self.hop_index,
            "task_id": self.task_id,
            "parent_hash": self.parent_hash,
            "hop_segment": self.hop_segment,
            "lineage_path": self.lineage_path,
            "epoch": self.epoch,
            "issuer_spiffe_id": self.issuer_spiffe_id,
            "issuer_jwk": self.issuer_jwk,
            "issuer_svid": self.issuer_svid,
            "issuer_return_endpoint": self.issuer_return_endpoint,
            "delegate_spiffe_id": self.delegate_spiffe_id,
            "cnf_jkt": self.cnf_jkt,
            "target_audience": self.target_audience,
            "permissions": self.permissions.to_dict(),
            "iat": self.iat,
            "exp": self.exp,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.core_claims()
        d["jws_signature"] = self.jws_signature
        return d

    def block_hash(self) -> str:
        """Cryptographic SHA-256 commitment over full signed AttenuationBlock."""
        return sha256_canonical_b64url(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "AttenuationBlock":
        if not isinstance(raw, Mapping) or raw.get("block_type") != "ATTENUATION":
            raise TokenError("Malformed AttenuationBlock JSON")
        try:
            task_id = validate_segment(str(raw["task_id"]), "task_id")
            hop_segment = validate_segment(str(raw["hop_segment"]), "hop_segment")
            lineage_path = str(raw["lineage_path"])
            split_lineage_path(lineage_path)
            hop_index = int(raw["hop_index"])
            if isinstance(raw["hop_index"], bool) or hop_index < 1:
                raise TokenError(f"Invalid hop_index: {hop_index}")
            epoch = int(raw["epoch"])
            if isinstance(raw["epoch"], bool) or epoch < 0:
                raise TokenError(f"Invalid epoch: {epoch}")
            issuer_spiffe = SpiffeId.parse(str(raw["issuer_spiffe_id"]))
            delegate_spiffe = SpiffeId.parse(str(raw["delegate_spiffe_id"]))
            issuer_jwk = raw["issuer_jwk"]
            if not isinstance(issuer_jwk, Mapping):
                raise TokenError("issuer_jwk must be a mapping")
            jwk_to_public_key(issuer_jwk)
            target_aud = raw.get("target_audience")
            if target_aud is not None:
                target_aud = SpiffeId.parse(str(target_aud)).uri

            raw_ret_ep = raw.get("issuer_return_endpoint")
            clean_ret_ep = (
                validate_clean_endpoint_url(str(raw_ret_ep), "issuer_return_endpoint")
                if raw_ret_ep is not None and str(raw_ret_ep) != ""
                else None
            )
            iat_val = require_finite_timestamp(raw["iat"], "AttenuationBlock.iat")
            exp_val = require_finite_timestamp(raw["exp"], "AttenuationBlock.exp")
            return cls(
                block_type="ATTENUATION",
                jti=str(raw["jti"]),
                hop_index=hop_index,
                task_id=task_id,
                parent_hash=str(raw["parent_hash"]),
                hop_segment=hop_segment,
                lineage_path=lineage_path,
                epoch=epoch,
                issuer_spiffe_id=issuer_spiffe.uri,
                issuer_jwk=dict(issuer_jwk),
                issuer_svid=str(raw["issuer_svid"]),
                issuer_return_endpoint=clean_ret_ep,
                delegate_spiffe_id=delegate_spiffe.uri,
                cnf_jkt=str(raw["cnf_jkt"]),
                target_audience=target_aud,
                permissions=PermissionLattice.from_dict(raw["permissions"]),
                iat=iat_val,
                exp=exp_val,
                jws_signature=str(raw["jws_signature"]),
            )
        except (KeyError, ValueError, TypeError, IdentityError, LatticeError, CryptoError) as exc:
            if isinstance(exc, TokenError):
                raise
            raise TokenError(f"Invalid AttenuationBlock structure: {exc}") from exc


@dataclass(frozen=True)
class LineageToken:
    """Single-chain Lineage Capability Tree token [B_0, B_1, ..., B_k]."""

    root: RootBlock
    hops: Tuple[AttenuationBlock, ...] = ()

    @property
    def task_id(self) -> str:
        return self.root.task_id

    @property
    def sub(self) -> str:
        return self.root.sub

    @property
    def depth(self) -> int:
        return len(self.hops)

    @property
    def lineage_path(self) -> str:
        return self.hops[-1].lineage_path if self.hops else self.root.lineage_path

    @property
    def current_epoch(self) -> int:
        return self.hops[-1].epoch if self.hops else self.root.epoch

    @property
    def holder_spiffe_id(self) -> str:
        return (
            self.hops[-1].delegate_spiffe_id
            if self.hops
            else self.root.delegate_spiffe_id
        )

    @property
    def holder_cnf_jkt(self) -> str:
        return self.hops[-1].cnf_jkt if self.hops else self.root.cnf_jkt

    @property
    def leaf_permissions(self) -> PermissionLattice:
        return self.hops[-1].permissions if self.hops else self.root.permissions

    @property
    def target_audience(self) -> Optional[str]:
        return self.hops[-1].target_audience if self.hops else None

    @property
    def root_block_hash(self) -> str:
        return self.root.block_hash()

    @property
    def leaf_block_hash(self) -> str:
        return self.hops[-1].block_hash() if self.hops else self.root.block_hash()

    @property
    def parent_block_hash(self) -> Optional[str]:
        return self.hops[-1].parent_hash if self.hops else None

    @property
    def visited_subjects(self) -> Set[str]:
        visited = {self.root.issuer_spiffe_id, self.root.delegate_spiffe_id}
        for h in self.hops:
            visited.add(h.issuer_spiffe_id)
            visited.add(h.delegate_spiffe_id)
        return visited

    @property
    def ordered_delegates(self) -> List[str]:
        seq = [self.root.delegate_spiffe_id]
        for h in self.hops:
            seq.append(h.delegate_spiffe_id)
        return seq

    def attenuate(
        self,
        issuer_identity: WorkloadIdentity,
        delegate_spiffe_id: str,
        delegate_jkt: str,
        permissions: PermissionLattice,
        hop_segment: Optional[str] = None,
        epoch: Optional[int] = None,
        issuer_return_endpoint: Optional[str] = None,
        target_audience: Optional[str] = None,
        ttl_seconds: Optional[float] = None,
        now: Optional[float] = None,
    ) -> "LineageToken":
        """Offline public-key attenuation appending signed block B_{k+1}."""
        if issuer_identity.spiffe_id != self.holder_spiffe_id:
            raise TokenError(
                f"Issuer {issuer_identity.spiffe_id!r} is not current holder {self.holder_spiffe_id!r}"
            )
        if issuer_identity.jkt != self.holder_cnf_jkt:
            raise TokenError("Issuer key thumbprint does not match current holder cnf_jkt")

        next_hop_index = len(self.hops) + 1
        if next_hop_index > self.root.max_depth:
            raise MaxDepthExceededError(
                f"Cannot attenuate to hop {next_hop_index}: exceeds max_depth={self.root.max_depth}"
            )

        delegate_spiffe = SpiffeId.parse(delegate_spiffe_id)
        if delegate_spiffe.uri in self.visited_subjects:
            raise CycleDetectedError(
                f"Delegation cycle detected: {delegate_spiffe.uri!r} already visited in {self.ordered_delegates}"
            )

        violation = permissions.explain_violation_against(self.leaf_permissions)
        if violation is not None:
            raise LatticeAttenuationError(
                f"Non-monotonic permission expansion blocked: {violation}"
            )

        next_epoch = self.current_epoch if epoch is None else int(epoch)
        if next_epoch < self.current_epoch:
            raise TokenError(
                f"Epoch rollback blocked: {next_epoch} < {self.current_epoch}"
            )

        resolved_seg = validate_segment(
            hop_segment if hop_segment else delegate_spiffe.default_hop_segment,
            "hop_segment",
        )
        new_lineage_path = f"{self.lineage_path}/{resolved_seg}"

        prev_exp = self.hops[-1].exp if self.hops else self.root.exp
        ts = require_finite_timestamp(time.time() if now is None else now, "now")
        new_exp = (
            min(prev_exp, ts + require_finite_timestamp(ttl_seconds, "ttl_seconds"))
            if ttl_seconds is not None
            else prev_exp
        )
        if new_exp <= ts:
            raise TokenError("Cannot attenuate expired token")

        norm_aud = SpiffeId.parse(target_audience).uri if target_audience else None
        norm_ret_ep = (
            validate_clean_endpoint_url(issuer_return_endpoint, "issuer_return_endpoint")
            if issuer_return_endpoint is not None and str(issuer_return_endpoint) != ""
            else None
        )

        provisional = AttenuationBlock(
            block_type="ATTENUATION",
            jti=f"hop-{uuid.uuid4().hex}",
            hop_index=next_hop_index,
            task_id=self.task_id,
            parent_hash=self.leaf_block_hash,
            hop_segment=resolved_seg,
            lineage_path=new_lineage_path,
            epoch=next_epoch,
            issuer_spiffe_id=issuer_identity.spiffe_id,
            issuer_jwk=issuer_identity.public_jwk(),
            issuer_svid=issuer_identity.workload_svid,
            issuer_return_endpoint=norm_ret_ep,
            delegate_spiffe_id=delegate_spiffe.uri,
            cnf_jkt=delegate_jkt,
            target_audience=norm_aud,
            permissions=permissions,
            iat=ts,
            exp=new_exp,
            jws_signature="",
        )
        sig = jws_sign_compact(
            payload=provisional.core_claims(),
            keypair=issuer_identity.keypair,
            typ="lct-hop+jwt",
        )
        signed_hop = AttenuationBlock(**{**provisional.__dict__, "jws_signature": sig})
        return LineageToken(root=self.root, hops=self.hops + (signed_hop,))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_kind": "SINGLE_CHAIN",
            "root": self.root.to_dict(),
            "hops": [h.to_dict() for h in self.hops],
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "LineageToken":
        if not isinstance(raw, Mapping) or raw.get("token_kind") != "SINGLE_CHAIN":
            raise TokenError("Malformed LineageToken JSON")
        root = RootBlock.from_dict(raw["root"])
        hops_raw = raw.get("hops", [])
        if not isinstance(hops_raw, list):
            raise TokenError("LineageToken 'hops' must be a list")
        hops = tuple(AttenuationBlock.from_dict(h) for h in hops_raw)
        return cls(root=root, hops=hops)

    def encode_compact(self) -> str:
        """Encode into HTTP-header-safe ASCII token string (`lct1.<b64url>`)."""
        return LCT_WIRE_PREFIX + b64url_encode(canonical_json_bytes(self.to_dict()))


@dataclass(frozen=True)
class MultiParentToken:
    """Multi-Parent DAG Convergence Envelope (`lctmp1.<b64url>`) for N-to-1 & M-to-N topologies.

    Binds multiple upstream attenuated `LineageToken` chains converging on the same
    `(task_id, sub, holder_spiffe_id, holder_cnf_jkt)`. Signed by `signer_spiffe_id`
    (either the holder C when invoking tools, or upstream C when forwarding attenuated
    multi-parent branches to D).
    """

    envelope_id: str
    task_id: str
    sub: str
    holder_spiffe_id: str
    holder_cnf_jkt: str
    signer_spiffe_id: str
    signer_jwk: Dict[str, Any]
    signer_svid: str
    parent_chains: Tuple[LineageToken, ...]
    created_at: float
    jws_signature: str

    def core_claims(self) -> Dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "task_id": self.task_id,
            "sub": self.sub,
            "holder_spiffe_id": self.holder_spiffe_id,
            "holder_cnf_jkt": self.holder_cnf_jkt,
            "signer_spiffe_id": self.signer_spiffe_id,
            "signer_jwk": self.signer_jwk,
            "signer_svid": self.signer_svid,
            "parent_chain_leaf_hashes": [c.leaf_block_hash for c in self.parent_chains],
            "parent_lineage_paths": [c.lineage_path for c in self.parent_chains],
            "created_at": self.created_at,
        }

    @property
    def lineage_paths(self) -> List[str]:
        return [c.lineage_path for c in self.parent_chains]

    @property
    def envelope_hash(self) -> str:
        return sha256_canonical_b64url(self.to_dict())

    @classmethod
    def assemble_and_sign(
        cls,
        holder_identity: WorkloadIdentity,
        parent_chains: Iterable[LineageToken],
        now: Optional[float] = None,
    ) -> "MultiParentToken":
        """Assemble multiple converging parent chains held by `holder_identity`."""
        chains_list = list(parent_chains)
        if not chains_list:
            raise TokenError("MultiParentToken requires at least one parent LineageToken")

        task_id = chains_list[0].task_id
        sub = chains_list[0].sub
        root_hash = chains_list[0].root_block_hash

        deduped: List[LineageToken] = []
        seen_paths: Set[str] = set()
        seen_hashes: Set[str] = set()

        for chain in chains_list:
            if chain.task_id != task_id:
                raise TokenError(
                    f"Cross-task splicing blocked in MultiParentToken: {chain.task_id!r} != {task_id!r}"
                )
            if chain.sub != sub:
                raise TokenError(
                    f"Cross-principal splicing blocked in MultiParentToken: {chain.sub!r} != {sub!r}"
                )
            if chain.root_block_hash != root_hash:
                raise TokenError(
                    "Cross-root splicing blocked in MultiParentToken: all parent chains must share identical RootBlock"
                )
            if chain.holder_spiffe_id != holder_identity.spiffe_id:
                raise TokenError(
                    f"Parent chain holder {chain.holder_spiffe_id!r} != convergence holder {holder_identity.spiffe_id!r}"
                )
            if chain.holder_cnf_jkt != holder_identity.jkt:
                raise TokenError("Parent chain cnf_jkt does not match convergence holder jkt")

            if chain.leaf_block_hash in seen_hashes:
                continue
            if chain.lineage_path in seen_paths:
                raise TokenError(
                    f"Conflicting duplicate lineage_path {chain.lineage_path!r} in MultiParentToken"
                )
            seen_hashes.add(chain.leaf_block_hash)
            seen_paths.add(chain.lineage_path)
            deduped.append(chain)

        ts = require_finite_timestamp(time.time() if now is None else now, "created_at")
        provisional = cls(
            envelope_id=f"mp-{uuid.uuid4().hex}",
            task_id=task_id,
            sub=sub,
            holder_spiffe_id=holder_identity.spiffe_id,
            holder_cnf_jkt=holder_identity.jkt,
            signer_spiffe_id=holder_identity.spiffe_id,
            signer_jwk=holder_identity.public_jwk(),
            signer_svid=holder_identity.workload_svid,
            parent_chains=tuple(deduped),
            created_at=ts,
            jws_signature="",
        )
        sig = jws_sign_compact(
            payload=provisional.core_claims(),
            keypair=holder_identity.keypair,
            typ="lct-multiparent+jwt",
        )
        return cls(**{**provisional.__dict__, "jws_signature": sig})

    def attenuate_to_delegate(
        self,
        issuer_identity: WorkloadIdentity,
        delegate_spiffe_id: str,
        delegate_jkt: str,
        requested_permissions: Optional[PermissionLattice] = None,
        hop_segment: Optional[str] = None,
        epoch: Optional[int] = None,
        issuer_return_endpoint: Optional[str] = None,
        now: Optional[float] = None,
    ) -> "MultiParentToken":
        """Propagate a Multi-Parent DAG further downstream (M-to-N topology).

        Intersects `requested_permissions` (when supplied) with each parent chain's
        leaf lattice (`P_child^(j) = P_parent^(j) ⊓ requested_permissions`), or preserves
        each branch's full `leaf_permissions` when `requested_permissions is None`.
        """
        if issuer_identity.spiffe_id != self.holder_spiffe_id:
            raise TokenError("Only current MultiParentToken holder can attenuate downstream")

        attenuated_chains: List[LineageToken] = []
        for chain in self.parent_chains:
            narrowed = (
                chain.leaf_permissions.intersect(requested_permissions)
                if requested_permissions is not None
                else chain.leaf_permissions
            )
            if narrowed.is_empty():
                continue
            attenuated_chains.append(
                chain.attenuate(
                    issuer_identity=issuer_identity,
                    delegate_spiffe_id=delegate_spiffe_id,
                    delegate_jkt=delegate_jkt,
                    permissions=narrowed,
                    hop_segment=hop_segment,
                    epoch=epoch,
                    issuer_return_endpoint=issuer_return_endpoint,
                    now=now,
                )
            )

        if not attenuated_chains:
            raise LatticeAttenuationError(
                "Requested downstream permissions have empty intersection with all parent chains"
            )

        delegate_spiffe = SpiffeId.parse(delegate_spiffe_id)
        ts = require_finite_timestamp(time.time() if now is None else now, "created_at")
        provisional = MultiParentToken(
            envelope_id=f"mp-{uuid.uuid4().hex}",
            task_id=self.task_id,
            sub=self.sub,
            holder_spiffe_id=delegate_spiffe.uri,
            holder_cnf_jkt=delegate_jkt,
            signer_spiffe_id=issuer_identity.spiffe_id,
            signer_jwk=issuer_identity.public_jwk(),
            signer_svid=issuer_identity.workload_svid,
            parent_chains=tuple(attenuated_chains),
            created_at=ts,
            jws_signature="",
        )
        sig = jws_sign_compact(
            payload=provisional.core_claims(),
            keypair=issuer_identity.keypair,
            typ="lct-multiparent+jwt",
        )
        return MultiParentToken(**{**provisional.__dict__, "jws_signature": sig})

    def rebind_as_holder(
        self, holder_identity: WorkloadIdentity, now: Optional[float] = None
    ) -> "MultiParentToken":
        """Re-sign envelope as recipient holder before invoking downstream tools."""
        return MultiParentToken.assemble_and_sign(
            holder_identity=holder_identity,
            parent_chains=self.parent_chains,
            now=now,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_kind": "MULTI_PARENT",
            "envelope_id": self.envelope_id,
            "task_id": self.task_id,
            "sub": self.sub,
            "holder_spiffe_id": self.holder_spiffe_id,
            "holder_cnf_jkt": self.holder_cnf_jkt,
            "signer_spiffe_id": self.signer_spiffe_id,
            "signer_jwk": self.signer_jwk,
            "signer_svid": self.signer_svid,
            "parent_chains": [c.to_dict() for c in self.parent_chains],
            "created_at": self.created_at,
            "jws_signature": self.jws_signature,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "MultiParentToken":
        if not isinstance(raw, Mapping) or raw.get("token_kind") != "MULTI_PARENT":
            raise TokenError("Malformed MultiParentToken JSON")
        try:
            task_id = validate_segment(str(raw["task_id"]), "task_id")
            holder_spiffe = SpiffeId.parse(str(raw["holder_spiffe_id"]))
            signer_spiffe = SpiffeId.parse(str(raw["signer_spiffe_id"]))
            signer_jwk = raw["signer_jwk"]
            if not isinstance(signer_jwk, Mapping):
                raise TokenError("signer_jwk must be a mapping")
            jwk_to_public_key(signer_jwk)
            chains_raw = raw.get("parent_chains", [])
            if not isinstance(chains_raw, list) or not chains_raw:
                raise TokenError("MultiParentToken requires non-empty parent_chains")
            chains = tuple(LineageToken.from_dict(c) for c in chains_raw)

            created_at_val = require_finite_timestamp(
                raw["created_at"], "MultiParentToken.created_at"
            )
            return cls(
                envelope_id=str(raw["envelope_id"]),
                task_id=task_id,
                sub=str(raw["sub"]),
                holder_spiffe_id=holder_spiffe.uri,
                holder_cnf_jkt=str(raw["holder_cnf_jkt"]),
                signer_spiffe_id=signer_spiffe.uri,
                signer_jwk=dict(signer_jwk),
                signer_svid=str(raw["signer_svid"]),
                parent_chains=chains,
                created_at=created_at_val,
                jws_signature=str(raw["jws_signature"]),
            )
        except (KeyError, ValueError, TypeError, IdentityError, CryptoError) as exc:
            if isinstance(exc, TokenError):
                raise
            raise TokenError(f"Invalid MultiParentToken structure: {exc}") from exc

    def encode_compact(self) -> str:
        return LCT_MP_WIRE_PREFIX + b64url_encode(canonical_json_bytes(self.to_dict()))


def mint_root_token(
    authority_ca: TrustDomainCA,
    task_id: str,
    sub: str,
    sender_jkt: str,
    first_hop_spiffe_id: str,
    first_hop_jkt: str,
    permissions: PermissionLattice,
    max_depth: int = 6,
    hop_segment: Optional[str] = None,
    first_hop_public_jwk: Optional[Mapping[str, Any]] = None,
    first_hop_return_endpoint: Optional[str] = None,
    extra_ancestor_keys: Optional[Mapping[str, Mapping[str, Any]]] = None,
    ttl_seconds: float = 1800.0,
    now: Optional[float] = None,
) -> LineageToken:
    """Mint a cryptographically signed RootBlock B_0 and return initial LineageToken."""
    valid_task = validate_segment(task_id, "task_id")
    if not sub or not str(sub).strip():
        raise TokenError("RootBlock requires non-empty originating principal 'sub'")
    clean_sub = validate_principal_domain_consistency(
        str(sub), authority_ca.trust_domain
    )
    delegate_spiffe = SpiffeId.parse(first_hop_spiffe_id)
    seg = validate_segment(
        hop_segment if hop_segment else delegate_spiffe.default_hop_segment,
        "hop_segment",
    )
    if isinstance(max_depth, bool) or max_depth < 1 or max_depth > 32:
        raise TokenError(f"max_depth must be in [1, 32], got {max_depth!r}")

    ancestors: Dict[str, Dict[str, Any]] = {}
    if extra_ancestor_keys:
        for aid, info in extra_ancestor_keys.items():
            SpiffeId.parse(aid)
            jkt_val = compute_jwk_thumbprint(info["public_jwk"])
            raw_ep = info.get("return_endpoint")
            ancestors[aid] = {
                "jkt": jkt_val,
                "public_jwk": dict(info["public_jwk"]),
                "return_endpoint": validate_clean_endpoint_url(
                    str(raw_ep), f"extra_ancestor_keys[{aid}].return_endpoint"
                )
                if raw_ep is not None and str(raw_ep) != ""
                else None,
            }
    if first_hop_public_jwk is not None:
        calc_jkt = compute_jwk_thumbprint(first_hop_public_jwk)
        if calc_jkt != first_hop_jkt:
            raise TokenError("first_hop_public_jwk thumbprint does not match first_hop_jkt")
        ancestors[delegate_spiffe.uri] = {
            "jkt": calc_jkt,
            "public_jwk": dict(first_hop_public_jwk),
            "return_endpoint": validate_clean_endpoint_url(
                first_hop_return_endpoint, "first_hop_return_endpoint"
            )
            if first_hop_return_endpoint is not None and str(first_hop_return_endpoint) != ""
            else None,
        }

    ts = require_finite_timestamp(time.time() if now is None else now, "now")
    exp = ts + require_finite_timestamp(ttl_seconds, "ttl_seconds")

    provisional = RootBlock(
        version="LCT/1.0",
        block_type="ROOT",
        jti=f"root-{uuid.uuid4().hex}",
        task_id=valid_task,
        sub=clean_sub,
        issuer_spiffe_id=authority_ca.root_authority_spiffe_id,
        issuer_trust_domain=authority_ca.trust_domain,
        sender_jkt=sender_jkt,
        delegate_spiffe_id=delegate_spiffe.uri,
        cnf_jkt=first_hop_jkt,
        hop_segment=seg,
        lineage_path=f"/{valid_task}/{seg}",
        max_depth=int(max_depth),
        epoch=0,
        permissions=permissions,
        ancestor_keys=ancestors,
        iat=ts,
        exp=exp,
        jws_signature="",
    )
    sig = jws_sign_compact(
        payload=provisional.core_claims(),
        keypair=authority_ca.active_keypair,
        typ="lct-root+jwt",
    )
    signed_root = RootBlock(**{**provisional.__dict__, "jws_signature": sig})
    return LineageToken(root=signed_root, hops=())


def decode_token(compact_token: str) -> Union[LineageToken, MultiParentToken]:
    """Decode a wire-encoded `lct1.<...>` or `lctmp1.<...>` token (structural parse only)."""
    if not isinstance(compact_token, str):
        raise TokenError("Compact token must be a string")
    try:
        if compact_token.startswith(LCT_WIRE_PREFIX):
            raw_bytes = b64url_decode(compact_token[len(LCT_WIRE_PREFIX) :])
            obj = strict_json_loads(raw_bytes)
            return LineageToken.from_dict(obj)
        if compact_token.startswith(LCT_MP_WIRE_PREFIX):
            raw_bytes = b64url_decode(compact_token[len(LCT_MP_WIRE_PREFIX) :])
            obj = strict_json_loads(raw_bytes)
            return MultiParentToken.from_dict(obj)
    except CryptoError as exc:
        raise TokenError(f"Malformed token encoding or non-finite value: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise TokenError(f"Malformed token JSON payload: {exc}") from exc

    raise TokenError("Unrecognized token prefix (expected 'lct1.' or 'lctmp1.')")


def is_lineage_segment_prefix(ancestor_prefix: str, target_prefix: str) -> bool:
    """Return True iff `ancestor_prefix` is an exact segment-boundary prefix of `target_prefix`."""
    if not ancestor_prefix.startswith("/") or not target_prefix.startswith("/"):
        return False
    a_segs = [s for s in ancestor_prefix.strip("/").split("/") if s]
    t_segs = [s for s in target_prefix.strip("/").split("/") if s]
    if not a_segs or not t_segs or len(a_segs) > len(t_segs):
        return False
    return t_segs[: len(a_segs)] == a_segs


def lineage_token_delegator_paths(token: LineageToken) -> Dict[str, str]:
    """Map each delegated workload SPIFFE ID on `token` to its exact `lineage_path`."""
    mapping: Dict[str, str] = {token.root.delegate_spiffe_id: token.root.lineage_path}
    for hop in token.hops:
        mapping[hop.delegate_spiffe_id] = hop.lineage_path
    return mapping


def verify_lineage_token_cryptography(
    token: LineageToken,
    trust_resolver: TrustBundleResolver,
    now: Optional[float] = None,
    clock_skew_seconds: float = 5.0,
) -> None:
    """Verify full O(depth) cryptographic signatures, links, cycles, depth, lattice
    monotonicity, and temporal bounds of `token` back to `RootBlock` B_0.

    Raises `TokenExpiredError` specifically if all cryptographic & structural invariants
    hold cleanly, and ONLY temporal expiration (`exp <= ts - clock_skew`) has elapsed.
    Raises `TokenError` on any signature, link, domain, cycle, depth, or lattice violation.
    """
    try:
        ts = require_finite_timestamp(time.time() if now is None else now, "now")
    except CryptoError as exc:
        raise TokenError(str(exc)) from exc

    skew = float(clock_skew_seconds)
    root = token.root

    # 1. Verify RootBlock B_0 signature & claims first (structural/crypto before expiry)
    validate_principal_domain_consistency(root.sub, root.issuer_trust_domain)
    try:
        _, signed_root_claims = trust_resolver.verify_domain_jws(
            root.jws_signature,
            expected_trust_domain=root.issuer_trust_domain,
            expected_typ="lct-root+jwt",
        )
    except IdentityError as exc:
        raise TokenError(f"RootBlock signature verification failed: {exc}") from exc

    if canonical_json_bytes(signed_root_claims) != canonical_json_bytes(root.core_claims()):
        raise TokenError("RootBlock payload tampering detected")

    expected_root_iss = f"spiffe://{root.issuer_trust_domain}/authority/root"
    expected_ca_iss = f"spiffe://{root.issuer_trust_domain}/authority/ca"
    if root.issuer_spiffe_id not in (expected_root_iss, expected_ca_iss):
        raise TokenError(f"Invalid RootBlock issuer_spiffe_id: {root.issuer_spiffe_id!r}")

    if root.iat > ts + skew:
        raise TokenError("RootBlock iat is in the future")

    expired_reason: Optional[str] = None
    if root.exp <= ts - skew:
        expired_reason = "RootBlock has expired"

    visited: Set[str] = {root.issuer_spiffe_id, root.delegate_spiffe_id}
    prev_hash = root.block_hash()
    prev_path = root.lineage_path
    prev_epoch = root.epoch
    prev_delegate = root.delegate_spiffe_id
    prev_cnf_jkt = root.cnf_jkt
    prev_perms = root.permissions
    prev_exp = root.exp

    # 2. Walk every AttenuationBlock B_1 ... B_k verifying cryptography & monotonicity first
    for idx, hop in enumerate(token.hops, start=1):
        if hop.hop_index != idx:
            raise TokenError(f"Non-sequential hop_index: expected {idx}, got {hop.hop_index}")
        if hop.hop_index > root.max_depth:
            raise TokenError(
                f"Delegation depth {hop.hop_index} exceeds max_depth={root.max_depth}"
            )
        if hop.task_id != root.task_id:
            raise TokenError(
                f"Hop {idx} task_id mismatch: {hop.task_id!r} != {root.task_id!r}"
            )
        if hop.parent_hash != prev_hash:
            raise TokenError(f"Hop {idx} parent_hash cryptographic link broken")
        expected_path = f"{prev_path}/{hop.hop_segment}"
        if hop.lineage_path != expected_path:
            raise TokenError(
                f"Hop {idx} lineage_path tampering: {hop.lineage_path!r} != {expected_path!r}"
            )
        if hop.epoch < prev_epoch:
            raise TokenError(f"Hop {idx} epoch rollback: {hop.epoch} < {prev_epoch}")
        if hop.exp > prev_exp + skew:
            raise TokenError(f"Hop {idx} expiration exceeds parent expiration")
        if hop.iat > ts + skew:
            raise TokenError(f"Hop {idx} iat is in the future")
        if hop.issuer_spiffe_id != prev_delegate:
            raise TokenError(
                f"Hop {idx} issuer {hop.issuer_spiffe_id!r} != previous delegate {prev_delegate!r}"
            )

        issuer_jkt = compute_jwk_thumbprint(hop.issuer_jwk)
        if issuer_jkt != prev_cnf_jkt:
            raise TokenError(
                f"Hop {idx} issuer_jwk thumbprint {issuer_jkt!r} != previous cnf_jkt {prev_cnf_jkt!r}"
            )

        # Verify issuer's SPIFFE SVID signature against its home domain CA
        # Check SVID at `min(ts, hop.iat + 1.0)` if checking historical expiry vs tampering,
        # then enforce SVID live expiry into `expired_reason`!
        try:
            trust_resolver.verify_workload_svid(
                hop.issuer_svid,
                expected_spiffe_id=hop.issuer_spiffe_id,
                expected_jkt=issuer_jkt,
                now=ts,
            )
        except IdentityError as exc:
            err_msg = str(exc)
            if "Workload SVID has expired" in err_msg:
                # Re-verify SVID cryptographic validity at hop issuance time before classifying as expired
                try:
                    trust_resolver.verify_workload_svid(
                        hop.issuer_svid,
                        expected_spiffe_id=hop.issuer_spiffe_id,
                        expected_jkt=issuer_jkt,
                        now=hop.iat,
                    )
                except IdentityError as inner_exc:
                    raise TokenError(
                        f"Hop {idx} issuer SVID verification failed: {inner_exc}"
                    ) from inner_exc
                if expired_reason is None:
                    expired_reason = f"Hop {idx} issuer SVID has expired"
            else:
                raise TokenError(
                    f"Hop {idx} issuer SVID verification failed: {exc}"
                ) from exc

        try:
            _, signed_hop_claims = jws_verify_compact(
                hop.jws_signature, hop.issuer_jwk, expected_typ="lct-hop+jwt"
            )
        except CryptoError as exc:
            raise TokenError(f"Hop {idx} signature verification failed: {exc}") from exc

        if canonical_json_bytes(signed_hop_claims) != canonical_json_bytes(hop.core_claims()):
            raise TokenError(f"Hop {idx} payload tampering detected")

        if hop.delegate_spiffe_id in visited:
            raise TokenError(
                f"Cycle detected at hop {idx}: {hop.delegate_spiffe_id!r} already visited"
            )
        visited.add(hop.delegate_spiffe_id)

        violation = hop.permissions.explain_violation_against(prev_perms)
        if violation is not None:
            raise TokenError(f"Privilege escalation at hop {idx}: {violation}")

        if hop.exp <= ts - skew and expired_reason is None:
            expired_reason = f"Hop {idx} has expired"

        prev_hash = hop.block_hash()
        prev_path = hop.lineage_path
        prev_epoch = hop.epoch
        prev_delegate = hop.delegate_spiffe_id
        prev_cnf_jkt = hop.cnf_jkt
        prev_perms = hop.permissions
        prev_exp = hop.exp

    if expired_reason is not None:
        raise TokenExpiredError(expired_reason)
