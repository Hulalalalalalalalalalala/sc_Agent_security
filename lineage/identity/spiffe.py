"""SPIFFE Workload Identity and independent Trust Domain Certificate Authorities."""

from __future__ import annotations

import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from lineage.common.crypto import (
    KeyPair,
    compute_jwk_thumbprint,
    jws_sign_compact,
)

_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,253}[a-z0-9])?$")
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class IdentityError(Exception):
    """Raised on invalid SPIFFE ID, SVID validation error, or domain mismatch."""


@dataclass(frozen=True)
class SpiffeId:
    """Validated RFC 8732 SPIFFE ID (`spiffe://<trust-domain>/<path>`)."""

    trust_domain: str
    path: str

    @classmethod
    def parse(cls, uri: str) -> "SpiffeId":
        if not isinstance(uri, str) or not uri.startswith("spiffe://"):
            raise IdentityError(f"SPIFFE ID must start with 'spiffe://': {uri!r}")
        parsed = urlparse(uri)
        if parsed.scheme != "spiffe" or parsed.params or parsed.query or parsed.fragment:
            raise IdentityError(f"SPIFFE ID must not contain query/fragment: {uri!r}")
        if ":" in parsed.netloc or "@" in parsed.netloc:
            raise IdentityError(f"SPIFFE trust domain must not include port/userinfo: {uri!r}")
        td = parsed.netloc
        if not td or not _TRUST_DOMAIN_RE.match(td):
            raise IdentityError(f"Invalid SPIFFE trust domain: {td!r}")
        path = parsed.path
        if not path or not path.startswith("/") or path.endswith("/"):
            raise IdentityError(f"SPIFFE ID must have a non-empty normalized path: {uri!r}")
        segments = path.split("/")[1:]
        for seg in segments:
            if not seg or seg in (".", "..") or not _PATH_SEGMENT_RE.match(seg):
                raise IdentityError(f"Invalid SPIFFE path segment {seg!r} in {uri!r}")
        return cls(trust_domain=td, path=path)

    @property
    def uri(self) -> str:
        return f"spiffe://{self.trust_domain}{self.path}"

    @property
    def default_hop_segment(self) -> str:
        """Safe deterministic leaf name suitable for lineage_path segment."""
        leaf = self.path.rsplit("/", 1)[-1]
        return re.sub(r"[^A-Za-z0-9._-]", "_", leaf)

    def __str__(self) -> str:
        return self.uri


@dataclass(frozen=True)
class WorkloadIdentity:
    """Cryptographic identity held by an Agent, Sidecar, or MCP Tool workload."""

    spiffe_id: str
    trust_domain: str
    keypair: KeyPair
    workload_svid: str
    issued_at: float
    expires_at: float
    renewal_generation: int = 0
    _lock: threading.RLock = field(
        default_factory=threading.RLock, init=False, repr=False, compare=False
    )

    def __repr__(self) -> str:
        return (
            f"WorkloadIdentity(spiffe_id={self.spiffe_id!r}, "
            f"alg={self.keypair.alg!r}, jkt={self.jkt!r}, gen={self.renewal_generation})"
        )

    @property
    def parsed_spiffe(self) -> SpiffeId:
        return SpiffeId.parse(self.spiffe_id)

    @property
    def jkt(self) -> str:
        with self._lock:
            return self.keypair.jkt

    def public_jwk(self) -> Dict[str, Any]:
        with self._lock:
            return self.keypair.public_jwk(include_kid=True)

    def update_svid(
        self,
        workload_svid: str,
        issued_at: float,
        expires_at: float,
        keypair: Optional[KeyPair] = None,
    ) -> int:
        """Atomically swap renewed in-memory SVID (and optional rotated keypair)."""
        with self._lock:
            if keypair is not None:
                object.__setattr__(self, "keypair", keypair)
            object.__setattr__(self, "workload_svid", str(workload_svid))
            object.__setattr__(self, "issued_at", float(issued_at))
            object.__setattr__(self, "expires_at", float(expires_at))
            next_gen = int(self.renewal_generation) + 1
            object.__setattr__(self, "renewal_generation", next_gen)
            return next_gen


@dataclass
class TrustDomainCA:
    """Independent organizational Trust Domain Authority (e.g. org-alpha.io, org-beta.io).

    Issues cryptographically bound Workload SVIDs and Root Authority signatures without
    relying on any centralized single-tenant IdP/Keycloak instance.
    """

    trust_domain: str
    alg: str = "ES256"
    initial_keypair: Optional[KeyPair] = field(default=None, repr=False)
    active_keypair: KeyPair = field(init=False)
    historical_public_jwks: List[Dict[str, Any]] = field(default_factory=list)
    version: int = 1

    def __post_init__(self) -> None:
        # Validate trust domain syntax via SpiffeId
        SpiffeId.parse(f"spiffe://{self.trust_domain}/authority/ca")
        if self.initial_keypair is not None:
            self.alg = self.initial_keypair.alg
            self.active_keypair = self.initial_keypair
        else:
            self.active_keypair = KeyPair.generate(
                alg=self.alg,
                kid=f"{self.trust_domain}-ca-v{self.version}",
            )

    @property
    def ca_spiffe_id(self) -> str:
        return f"spiffe://{self.trust_domain}/authority/ca"

    @property
    def root_authority_spiffe_id(self) -> str:
        return f"spiffe://{self.trust_domain}/authority/root"

    def rotate_key(self, new_alg: Optional[str] = None) -> Dict[str, Any]:
        """Rotate CA signing key while retaining previous public key in JWKS for rollover."""
        self.historical_public_jwks.append(self.active_keypair.public_jwk(include_kid=True))
        self.version += 1
        chosen_alg = new_alg or self.alg
        self.alg = chosen_alg
        self.active_keypair = KeyPair.generate(
            alg=chosen_alg,
            kid=f"{self.trust_domain}-ca-v{self.version}",
        )
        return self.export_public_bundle()

    def export_public_bundle(self) -> Dict[str, Any]:
        """Export public-only JWKS bundle for cross-domain federation (safe for IPC/HTTP)."""
        keys = [self.active_keypair.public_jwk(include_kid=True)] + list(
            self.historical_public_jwks
        )
        return {
            "trust_domain": self.trust_domain,
            "issuer": self.ca_spiffe_id,
            "version": self.version,
            "keys": keys,
        }

    def issue_workload(
        self,
        workload_path: str,
        workload_alg: str = "ES256",
        ttl_seconds: float = 3600.0,
        now: Optional[float] = None,
    ) -> WorkloadIdentity:
        """Provision a workload keypair and sign its holder-bound SPIFFE JWT-SVID."""
        if not workload_path.startswith("/"):
            workload_path = "/" + workload_path
        spiffe = SpiffeId.parse(f"spiffe://{self.trust_domain}{workload_path}")
        wl_keypair = KeyPair.generate(alg=workload_alg)
        ts = time.time() if now is None else float(now)
        exp = ts + float(ttl_seconds)

        svid_claims = {
            "iss": self.ca_spiffe_id,
            "sub": spiffe.uri,
            "trust_domain": self.trust_domain,
            "iat": ts,
            "exp": exp,
            "jti": f"svid-{uuid.uuid4().hex}",
            "cnf": {
                "jkt": compute_jwk_thumbprint(wl_keypair.public_key),
                "jwk": wl_keypair.public_jwk(include_kid=True),
            },
        }
        svid = jws_sign_compact(
            payload=svid_claims,
            keypair=self.active_keypair,
            typ="spiffe-svid+jwt",
        )
        return WorkloadIdentity(
            spiffe_id=spiffe.uri,
            trust_domain=self.trust_domain,
            keypair=wl_keypair,
            workload_svid=svid,
            issued_at=ts,
            expires_at=exp,
        )

    def sign_svid_for_public_jwk(
        self,
        workload_path: str,
        public_jwk: Dict[str, Any],
        ttl_seconds: float = 3600.0,
        now: Optional[float] = None,
    ) -> Tuple[str, str, float, float]:
        """Attest an externally generated workload public JWK (zero private key sharing!).

        Returns `(spiffe_id, workload_svid, issued_at, expires_at)`.
        """
        if not workload_path.startswith("/"):
            workload_path = "/" + workload_path
        spiffe = SpiffeId.parse(f"spiffe://{self.trust_domain}{workload_path}")
        jkt = compute_jwk_thumbprint(public_jwk)
        ts = time.time() if now is None else float(now)
        exp = ts + float(ttl_seconds)

        svid_claims = {
            "iss": self.ca_spiffe_id,
            "sub": spiffe.uri,
            "trust_domain": self.trust_domain,
            "iat": ts,
            "exp": exp,
            "jti": f"svid-{uuid.uuid4().hex}",
            "cnf": {
                "jkt": jkt,
                "jwk": dict(public_jwk),
            },
        }
        svid = jws_sign_compact(
            payload=svid_claims,
            keypair=self.active_keypair,
            typ="spiffe-svid+jwt",
        )
        return spiffe.uri, svid, ts, exp

