"""Signed Domain Descriptors & Anti-Rollback Federation Descriptor Store.

Re-exports low-level `ServiceLocator`, `SeedEndpointStore`, and `NodeLocatorWatcher`
from `lineage.common.locators` while adding cryptographic `SignedDomainDescriptor`
issuance, SHA-256 trust-anchor-bound verification, and anti-rollback gossip storage.
"""

from __future__ import annotations

from dataclasses import dataclass
import hmac
import json
from pathlib import Path
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from cryptography import x509

from lineage.common.crypto import (
    CryptoError,
    KeyPair,
    jws_sign_compact,
    jws_verify_compact,
    public_key_to_jwk,
    require_finite_timestamp,
)
from lineage.common.locators import (
    ALLOWED_TRANSPORTS,
    DEFAULT_ALLOWED_LOCATOR_CIDRS,
    MAX_BOOTSTRAP_SEEDS,
    LocatorError,
    NodeLocatorSnapshot,
    NodeLocatorWatcher,
    SeedEndpointStore,
    ServiceLocator,
    normalize_seed_endpoint,
    parse_allowed_locator_cidrs,
    seed_candidate_descriptor_urls,
    sort_and_dedup_locators,
    validate_locator_host,
)
from lineage.common.mtls import MTLSError, X509DomainAuthority, X509FederationTrustStore
from lineage.federation.anchors import (
    TrustAnchorPinError,
    TrustAnchorPinStore,
    compute_bundle_trust_anchor,
    extract_canonical_bundle_root_pem,
)
from lineage.identity.spiffe import IdentityError, SpiffeId, TrustDomainCA
from lineage.identity.trust_bundle import TrustBundleResolver

DESCRIPTOR_SERVICE_KEYS: Tuple[str, ...] = (
    "ca_bundle",
    "directory_federation",
    "revocation_federation",
    "audit_collector",
    "oauth_sts",
    "yellow_pages",
)
MAX_DESCRIPTORS_PER_MESSAGE: int = 32
MAX_DESCRIPTOR_HTTP_BYTES: int = 1_048_576  # 1 MiB strict HTTP payload ceiling
MAX_TRACKED_DESCRIPTOR_ANOMALIES: int = 64
MAX_DESCRIPTOR_DOMAIN_KEY_LEN: int = 128


class DescriptorVerificationError(Exception):
    """Raised when a `SignedDomainDescriptor` fails pin, signature, expiry, or rollback checks."""


class UnpinnedDomainDescriptorError(DescriptorVerificationError):
    """Raised when a descriptor belongs to a domain without a local trust anchor pin."""


@dataclass(frozen=True)
class SignedDomainDescriptor:
    """Domain-root-signed control-plane locator & public bundle descriptor."""

    trust_domain: str
    version: int
    issued_at: float
    expires_at: float
    trust_anchor: str
    bundle: Dict[str, Any]
    locators: Dict[str, Tuple[ServiceLocator, ...]]
    signature_mode: str
    jws_signature: str

    def core_claims(self) -> Dict[str, Any]:
        loc_dict: Dict[str, List[Dict[str, Any]]] = {}
        for k in sorted(self.locators.keys()):
            loc_dict[k] = [loc.to_dict() for loc in self.locators[k]]
        return {
            "trust_domain": self.trust_domain,
            "version": int(self.version),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "trust_anchor": self.trust_anchor,
            "bundle": self.bundle,
            "locators": loc_dict,
            "signature_mode": self.signature_mode,
        }

    def to_dict(self) -> Dict[str, Any]:
        out = self.core_claims()
        out["jws_signature"] = self.jws_signature
        return out

    def get_locators(self, service_key: str) -> Tuple[ServiceLocator, ...]:
        return self.locators.get(service_key, ())

    def is_expired(self, now: Optional[float] = None) -> bool:
        ts = time.time() if now is None else float(now)
        return self.expires_at <= ts

    @classmethod
    def _normalize_locator_map(
        cls,
        trust_domain: str,
        locators: Mapping[str, Iterable[ServiceLocator | Mapping[str, Any]]],
        allowed_cidrs: Optional[Iterable[str] | str] = None,
    ) -> Dict[str, Tuple[ServiceLocator, ...]]:
        if not isinstance(locators, Mapping) or not locators:
            raise DescriptorVerificationError("Domain descriptor locators map cannot be empty")
        norm_map: Dict[str, Tuple[ServiceLocator, ...]] = {}
        for raw_key, raw_list in locators.items():
            key = str(raw_key).strip()
            if key not in DESCRIPTOR_SERVICE_KEYS:
                raise DescriptorVerificationError(
                    f"Unknown domain descriptor service key {key!r}"
                )
            if not isinstance(raw_list, Iterable) or isinstance(raw_list, (str, bytes, Mapping)):
                raise DescriptorVerificationError(
                    f"Descriptor locators[{key!r}] must be a list of ServiceLocator objects"
                )
            parsed_items: List[ServiceLocator] = []
            for item in raw_list:
                try:
                    loc = (
                        item
                        if isinstance(item, ServiceLocator)
                        else ServiceLocator.from_dict(item, allowed_cidrs=allowed_cidrs)
                    )
                    validate_locator_host(loc.host, allowed_cidrs=allowed_cidrs)
                except LocatorError as exc:
                    raise DescriptorVerificationError(f"Invalid descriptor locator: {exc}") from exc
                if key in ("directory_federation", "revocation_federation", "audit_collector"):
                    if loc.transport not in ("mtls-tcp", "tls-tcp"):
                        raise DescriptorVerificationError(
                            f"Service {key!r} must use TLS/mTLS transport, got {loc.transport!r}"
                        )
                    if not loc.spiffe_id:
                        raise DescriptorVerificationError(
                            f"TLS service locator {key!r} ({loc.origin_url}) must bind explicit spiffe_id"
                        )
                if loc.spiffe_id is not None:
                    sp = SpiffeId.parse(loc.spiffe_id)
                    if sp.trust_domain != trust_domain:
                        raise DescriptorVerificationError(
                            f"Descriptor locator spiffe_id {loc.spiffe_id!r} mismatches descriptor domain {trust_domain!r}"
                        )
                parsed_items.append(loc)
            if parsed_items:
                norm_map[key] = sort_and_dedup_locators(parsed_items)
        if "ca_bundle" not in norm_map:
            raise DescriptorVerificationError(
                f"Domain descriptor for {trust_domain!r} must include at least one 'ca_bundle' locator"
            )
        return norm_map

    @classmethod
    def sign_with_domain_ca(
        cls,
        ca: TrustDomainCA,
        x509_root_pem: str,
        locators: Mapping[str, Iterable[ServiceLocator | Mapping[str, Any]]],
        version: int,
        ttl_seconds: float = 3600.0,
        allowed_cidrs: Optional[Iterable[str] | str] = None,
        now: Optional[float] = None,
    ) -> "SignedDomainDescriptor":
        """Sign a `SignedDomainDescriptor` for a standard JWKS+X.509 domain (`alpha`, `beta`, `pay`)."""
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise DescriptorVerificationError(f"Descriptor version must be int >= 1, got {version!r}")
        td = ca.trust_domain.strip().lower()
        bundle = ca.export_public_bundle()
        bundle["x509_root_pem"] = extract_canonical_bundle_root_pem({"x509_root_pem": x509_root_pem})
        anchor = compute_bundle_trust_anchor(bundle, allow_keyless_jwks=False)
        bundle["trust_anchor"] = anchor

        norm_locs = cls._normalize_locator_map(td, locators, allowed_cidrs=allowed_cidrs)
        ts = time.time() if now is None else float(now)
        exp = ts + max(5.0, float(ttl_seconds))

        provisional = cls(
            trust_domain=td,
            version=int(version),
            issued_at=ts,
            expires_at=exp,
            trust_anchor=anchor,
            bundle=bundle,
            locators=norm_locs,
            signature_mode="jwks_es256",
            jws_signature="",
        )
        sig = jws_sign_compact(
            payload=provisional.core_claims(),
            keypair=ca.active_keypair,
            typ="lct-domain-descriptor+jwt",
        )
        return cls(**{**provisional.__dict__, "jws_signature": sig})

    @classmethod
    def sign_with_x509_root(
        cls,
        x509_ca: X509DomainAuthority,
        locators: Mapping[str, Iterable[ServiceLocator | Mapping[str, Any]]],
        version: int,
        bundle: Optional[Mapping[str, Any]] = None,
        ttl_seconds: float = 3600.0,
        allowed_cidrs: Optional[Iterable[str] | str] = None,
        now: Optional[float] = None,
    ) -> "SignedDomainDescriptor":
        """Sign a `SignedDomainDescriptor` for keyless `org-audit.io` using its X.509 Root CA key."""
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise DescriptorVerificationError(f"Descriptor version must be int >= 1, got {version!r}")
        td = x509_ca.trust_domain.strip().lower()
        root_pem = (
            extract_canonical_bundle_root_pem(bundle)
            if bundle is not None
            else x509_ca.export_root_pem()
        )
        eff_bundle: Dict[str, Any] = {
            "trust_domain": td,
            "keys": [],
            "x509_root_pem": root_pem,
        }
        anchor = compute_bundle_trust_anchor(eff_bundle, allow_keyless_jwks=True)
        eff_bundle["trust_anchor"] = anchor

        norm_locs = cls._normalize_locator_map(td, locators, allowed_cidrs=allowed_cidrs)
        ts = time.time() if now is None else float(now)
        exp = ts + max(5.0, float(ttl_seconds))

        provisional = cls(
            trust_domain=td,
            version=int(version),
            issued_at=ts,
            expires_at=exp,
            trust_anchor=anchor,
            bundle=eff_bundle,
            locators=norm_locs,
            signature_mode="x509_root_es256",
            jws_signature="",
        )
        root_kp = KeyPair.from_private_pem(
            x509_ca.export_private_key_pem(),
            kid=f"{td}-x509-root",
        )
        sig = jws_sign_compact(
            payload=provisional.core_claims(),
            keypair=root_kp,
            typ="lct-domain-descriptor+jwt",
        )
        return cls(**{**provisional.__dict__, "jws_signature": sig})

    @classmethod
    def verify_and_parse(
        cls,
        raw: Mapping[str, Any],
        anchor_store: Optional[TrustAnchorPinStore] = None,
        require_pinned_anchors: bool = True,
        allowed_cidrs: Optional[Iterable[str] | str] = None,
        now: Optional[float] = None,
    ) -> "SignedDomainDescriptor":
        """Verify bundle pin -> X.509/JWKS validity -> root JWS signature -> locator bounds."""
        if not isinstance(raw, Mapping):
            raise DescriptorVerificationError("Domain descriptor must be a JSON object")

        td = str(raw.get("trust_domain") or "").strip().lower()
        try:
            SpiffeId.parse(f"spiffe://{td}/authority/ca")
        except IdentityError as exc:
            raise DescriptorVerificationError(f"Invalid descriptor trust_domain {td!r}: {exc}") from exc

        pinned_anchor: Optional[str] = (
            anchor_store.get_pin(td) if anchor_store is not None else None
        )
        if require_pinned_anchors and pinned_anchor is None:
            raise UnpinnedDomainDescriptorError(
                f"Domain {td!r} is not pinned in TrustAnchorPinStore (fail-closed)"
            )

        raw_bundle = raw.get("bundle")
        if not isinstance(raw_bundle, Mapping):
            raise DescriptorVerificationError(f"Descriptor for {td!r} missing 'bundle' object")
        bundle_td = str(raw_bundle.get("trust_domain") or "").strip().lower()
        if bundle_td != td:
            raise DescriptorVerificationError(
                f"Descriptor bundle trust_domain {bundle_td!r} != {td!r}"
            )

        is_keyless = td == "org-audit.io" and not (raw_bundle.get("keys") or [])
        try:
            canonical_root_pem = extract_canonical_bundle_root_pem(raw_bundle)
            computed_anchor = compute_bundle_trust_anchor(
                raw_bundle, allow_keyless_jwks=is_keyless
            )
        except TrustAnchorPinError as exc:
            raise DescriptorVerificationError(
                f"Invalid bundle in descriptor for {td!r}: {exc}"
            ) from exc

        if pinned_anchor is not None and not hmac.compare_digest(computed_anchor, pinned_anchor):
            raise DescriptorVerificationError(
                f"Trust anchor pin mismatch for {td!r}: descriptor bundle={computed_anchor}, pinned={pinned_anchor}"
            )

        claimed_anchor = str(raw.get("trust_anchor") or "").strip().lower()
        if claimed_anchor and not hmac.compare_digest(claimed_anchor, computed_anchor):
            raise DescriptorVerificationError(
                f"Descriptor claimed trust_anchor {claimed_anchor!r} != computed {computed_anchor!r}"
            )

        scratch_x509 = X509FederationTrustStore()
        scratch_resolver = TrustBundleResolver()
        try:
            scratch_x509.register_domain_root_pem(td, canonical_root_pem)
            if not is_keyless:
                scratch_resolver.register_bundle(raw_bundle)
        except (MTLSError, IdentityError, CryptoError, ValueError, TypeError) as exc:
            raise DescriptorVerificationError(
                f"Descriptor bundle cryptographic validation failed for {td!r}: {exc}"
            ) from exc

        sig_mode = str(raw.get("signature_mode") or "").strip()
        jws_sig = str(raw.get("jws_signature") or "").strip()
        if not jws_sig:
            raise DescriptorVerificationError(f"Descriptor for {td!r} missing jws_signature")

        try:
            if sig_mode == "jwks_es256":
                if is_keyless:
                    raise DescriptorVerificationError(
                        f"Keyless domain {td!r} cannot use jwks_es256 signature_mode"
                    )
                _, signed_claims = scratch_resolver.verify_domain_jws(
                    jws_sig,
                    expected_trust_domain=td,
                    expected_typ="lct-domain-descriptor+jwt",
                )
            elif sig_mode == "x509_root_es256":
                if td != "org-audit.io" or not is_keyless:
                    raise DescriptorVerificationError(
                        f"x509_root_es256 descriptor mode is restricted to keyless 'org-audit.io', got {td!r}"
                    )
                root_cert = x509.load_pem_x509_certificate(canonical_root_pem.encode("ascii"))
                root_jwk = public_key_to_jwk(root_cert.public_key())
                _, signed_claims = jws_verify_compact(
                    jws_sig,
                    root_jwk,
                    expected_typ="lct-domain-descriptor+jwt",
                )
            else:
                raise DescriptorVerificationError(
                    f"Unsupported descriptor signature_mode {sig_mode!r} for {td!r}"
                )
        except (IdentityError, CryptoError) as exc:
            raise DescriptorVerificationError(
                f"Descriptor JWS signature invalid for {td!r}: {exc}"
            ) from exc

        ver_raw = raw.get("version")
        if isinstance(ver_raw, bool) or not isinstance(ver_raw, int) or ver_raw < 1:
            raise DescriptorVerificationError(f"Invalid descriptor version {ver_raw!r}")

        try:
            iat = require_finite_timestamp(raw.get("issued_at"), "descriptor.issued_at")
            exp = require_finite_timestamp(raw.get("expires_at"), "descriptor.expires_at")
        except (CryptoError, ValueError, TypeError) as exc:
            raise DescriptorVerificationError(f"Invalid descriptor timestamps: {exc}") from exc

        ts = time.time() if now is None else float(now)
        if iat > ts + 30.0:
            raise DescriptorVerificationError(
                f"Descriptor issued_at {iat:.3f} is >30s in the future (now={ts:.3f})"
            )
        if exp <= ts:
            raise DescriptorVerificationError(
                f"Descriptor for {td!r} has expired (expires_at={exp:.3f} <= now={ts:.3f})"
            )

        raw_locs = raw.get("locators")
        if not isinstance(raw_locs, Mapping):
            raise DescriptorVerificationError("Descriptor missing locators mapping")
        norm_locs = cls._normalize_locator_map(td, raw_locs, allowed_cidrs=allowed_cidrs)

        clean_bundle = dict(raw_bundle)
        provisional = cls(
            trust_domain=td,
            version=ver_raw,
            issued_at=iat,
            expires_at=exp,
            trust_anchor=computed_anchor,
            bundle=clean_bundle,
            locators=norm_locs,
            signature_mode=sig_mode,
            jws_signature=jws_sig,
        )
        if signed_claims != provisional.core_claims():
            raise DescriptorVerificationError(
                f"Signed JWS claims mismatch outer descriptor fields for {td!r}"
            )
        return provisional


class DomainDescriptorStore:
    """Thread-safe anti-rollback store of verified `SignedDomainDescriptor`s (`own` + `learned`)."""

    def __init__(
        self,
        anchor_store: Optional[TrustAnchorPinStore] = None,
        require_pinned_anchors: bool = True,
        allowed_cidrs: Optional[Iterable[str] | str] = None,
        local_trust_domain: Optional[str] = None,
        local_trust_anchor: Optional[str] = None,
    ) -> None:
        self.anchor_store = anchor_store
        self.require_pinned_anchors = bool(require_pinned_anchors)
        self.allowed_cidrs = allowed_cidrs
        self.local_trust_domain = (
            local_trust_domain.strip().lower() if local_trust_domain else None
        )
        self.local_trust_anchor = (
            local_trust_anchor.strip() if local_trust_anchor else None
        )
        self._lock = threading.RLock()
        self._descriptors: Dict[str, SignedDomainDescriptor] = {}
        self._rejected_counts: Dict[str, int] = {}
        self._ignored_unpinned: Dict[str, float] = {}
        self._last_errors: Dict[str, str] = {}

    @staticmethod
    def _cap_domain_key(raw_key: str) -> str:
        clean = (raw_key or "malformed").strip().lower()
        return (clean or "malformed")[:MAX_DESCRIPTOR_DOMAIN_KEY_LEN]

    def _record_ignored_unpinned_locked(self, td_hint: str) -> None:
        if not td_hint:
            return
        k = self._cap_domain_key(td_hint)
        self._ignored_unpinned.pop(k, None)
        while len(self._ignored_unpinned) >= MAX_TRACKED_DESCRIPTOR_ANOMALIES:
            oldest = next(iter(self._ignored_unpinned))
            self._ignored_unpinned.pop(oldest, None)
        self._ignored_unpinned[k] = time.time()

    def _record_rejection_locked(self, td_hint: str, err_msg: str) -> None:
        k = self._cap_domain_key(td_hint)
        prev_cnt = self._rejected_counts.pop(k, 0)
        while len(self._rejected_counts) >= MAX_TRACKED_DESCRIPTOR_ANOMALIES:
            oldest = next(iter(self._rejected_counts))
            self._rejected_counts.pop(oldest, None)
        self._rejected_counts[k] = prev_cnt + 1

        self._last_errors.pop(k, None)
        while len(self._last_errors) >= MAX_TRACKED_DESCRIPTOR_ANOMALIES:
            oldest_err = next(iter(self._last_errors))
            self._last_errors.pop(oldest_err, None)
        self._last_errors[k] = str(err_msg)[:512]

    def set_local_trust_domain(
        self, trust_domain: str, trust_anchor: Optional[str] = None
    ) -> None:
        with self._lock:
            self.local_trust_domain = trust_domain.strip().lower()
            if trust_anchor:
                self.local_trust_anchor = trust_anchor.strip()

    def set_own_descriptor(self, desc: SignedDomainDescriptor) -> None:
        with self._lock:
            existing = self._descriptors.get(desc.trust_domain)
            if (
                existing is not None
                and existing.trust_anchor == desc.trust_anchor
                and desc.version < existing.version
            ):
                raise DescriptorVerificationError(
                    f"Own descriptor version rollback {desc.version} < {existing.version}"
                )
            self.local_trust_domain = desc.trust_domain
            self.local_trust_anchor = desc.trust_anchor
            self._descriptors[desc.trust_domain] = desc
            self._last_errors.pop(desc.trust_domain, None)

    def reconcile_with_pins(self) -> List[str]:
        if self.anchor_store is None:
            return []
        self.anchor_store.refresh_if_changed()
        evicted: List[str] = []
        with self._lock:
            for td, desc in list(self._descriptors.items()):
                if (
                    self.local_trust_domain
                    and self.local_trust_anchor
                    and td == self.local_trust_domain
                    and hmac.compare_digest(desc.trust_anchor, self.local_trust_anchor)
                ):
                    continue
                cur_pin = self.anchor_store.get_pin(td)
                if self.require_pinned_anchors and cur_pin is None:
                    self._descriptors.pop(td, None)
                    evicted.append(td)
                elif cur_pin is not None and not hmac.compare_digest(cur_pin, desc.trust_anchor):
                    self._descriptors.pop(td, None)
                    evicted.append(td)
        return evicted

    def ingest_raw_descriptor(
        self,
        raw: Mapping[str, Any],
        now: Optional[float] = None,
    ) -> Tuple[bool, SignedDomainDescriptor]:
        self.reconcile_with_pins()
        td_hint = (
            str(raw.get("trust_domain") or "").strip().lower()
            if isinstance(raw, Mapping)
            else "unknown"
        )
        is_verified_local_domain = bool(
            self.local_trust_domain
            and self.local_trust_anchor
            and td_hint == self.local_trust_domain
        )
        try:
            verified = SignedDomainDescriptor.verify_and_parse(
                raw,
                anchor_store=(None if is_verified_local_domain else self.anchor_store),
                require_pinned_anchors=(
                    False if is_verified_local_domain else self.require_pinned_anchors
                ),
                allowed_cidrs=self.allowed_cidrs,
                now=now,
            )
            if is_verified_local_domain and not hmac.compare_digest(
                verified.trust_anchor, str(self.local_trust_anchor)
            ):
                raise DescriptorVerificationError(
                    f"Descriptor trust_anchor mismatch for local domain {td_hint!r}: "
                    f"got {verified.trust_anchor!r}, expected {self.local_trust_anchor!r}"
                )
        except UnpinnedDomainDescriptorError:
            with self._lock:
                self._record_ignored_unpinned_locked(td_hint)
            raise
        except DescriptorVerificationError as exc:
            with self._lock:
                self._record_rejection_locked(td_hint or "malformed", str(exc))
            raise

        with self._lock:
            existing = self._descriptors.get(verified.trust_domain)
            if existing is not None and hmac.compare_digest(
                existing.trust_anchor, verified.trust_anchor
            ):
                if verified.version < existing.version:
                    msg = (
                        f"Descriptor version rollback rejected for {verified.trust_domain!r}: "
                        f"v{verified.version} < existing v{existing.version}"
                    )
                    self._record_rejection_locked(verified.trust_domain, msg)
                    raise DescriptorVerificationError(msg)
                if verified.version == existing.version:
                    if verified.core_claims() != existing.core_claims():
                        msg = (
                            f"Descriptor same-version equivocation rejected for {verified.trust_domain!r} "
                            f"at v{verified.version}"
                        )
                        self._record_rejection_locked(verified.trust_domain, msg)
                        raise DescriptorVerificationError(msg)
                    return False, existing

            self._descriptors[verified.trust_domain] = verified
            self._last_errors.pop(verified.trust_domain, None)
            self._ignored_unpinned.pop(verified.trust_domain, None)
            return True, verified

    ingest_descriptor = ingest_raw_descriptor

    def get_descriptor(
        self, trust_domain: str, include_expired: bool = False, now: Optional[float] = None
    ) -> Optional[SignedDomainDescriptor]:
        self.reconcile_with_pins()
        norm_td = trust_domain.strip().lower()
        with self._lock:
            desc = self._descriptors.get(norm_td)
        if desc is None:
            return None
        if not include_expired and desc.is_expired(now=now):
            return None
        return desc

    def all_descriptors(
        self, include_expired: bool = False, now: Optional[float] = None
    ) -> Dict[str, SignedDomainDescriptor]:
        self.reconcile_with_pins()
        ts = time.time() if now is None else float(now)
        with self._lock:
            return {
                td: d
                for td, d in sorted(self._descriptors.items())
                if include_expired or not d.is_expired(now=ts)
            }

    def get_locators(
        self, trust_domain: str, service_key: str, now: Optional[float] = None
    ) -> Tuple[ServiceLocator, ...]:
        desc = self.get_descriptor(trust_domain, include_expired=False, now=now)
        if desc is None:
            return ()
        return desc.get_locators(service_key)

    def peer_locators(
        self,
        service_key: str,
        exclude_domain: Optional[str] = None,
        now: Optional[float] = None,
    ) -> Dict[str, Tuple[ServiceLocator, ...]]:
        excl = (exclude_domain or self.local_trust_domain or "").strip().lower()
        out: Dict[str, Tuple[ServiceLocator, ...]] = {}
        for td, desc in self.all_descriptors(include_expired=False, now=now).items():
            if excl and td == excl:
                continue
            locs = desc.get_locators(service_key)
            if locs:
                out[td] = locs
        return out

    def export_gossip_payload(self, now: Optional[float] = None) -> Dict[str, Any]:
        descs = self.all_descriptors(include_expired=False, now=now)
        ordered: List[SignedDomainDescriptor] = []
        if self.local_trust_domain and self.local_trust_domain in descs:
            ordered.append(descs[self.local_trust_domain])
        for td, d in descs.items():
            if td != self.local_trust_domain:
                ordered.append(d)
                if len(ordered) >= MAX_DESCRIPTORS_PER_MESSAGE:
                    break
        return {
            "trust_domain": self.local_trust_domain,
            "descriptors": [d.to_dict() for d in ordered[:MAX_DESCRIPTORS_PER_MESSAGE]],
        }

    def diagnostics(self, now: Optional[float] = None) -> Dict[str, Any]:
        ts = time.time() if now is None else float(now)
        with self._lock:
            rejected = dict(self._rejected_counts)
            ignored = sorted(self._ignored_unpinned.keys())
            errs = dict(self._last_errors)
        descs = self.all_descriptors(include_expired=True, now=ts)
        summary: Dict[str, Any] = {}
        for td, d in descs.items():
            summary[td] = {
                "version": d.version,
                "trust_anchor": d.trust_anchor,
                "signature_mode": d.signature_mode,
                "issued_at": d.issued_at,
                "expires_at": d.expires_at,
                "remaining_ttl_sec": round(d.expires_at - ts, 2),
                "expired": d.is_expired(now=ts),
                "locators": {
                    k: [loc.to_dict() for loc in v] for k, v in d.locators.items()
                },
            }
        return {
            "descriptors": summary,
            "rejected_descriptor_counts": rejected,
            "ignored_unpinned_domains": ignored,
            "last_descriptor_errors": errs,
        }

    def load_persisted_file(self, path: str | Path) -> int:
        p = Path(path)
        if not p.is_file():
            return 0
        try:
            raw_text = p.read_text(encoding="utf-8").strip()
            if not raw_text:
                return 0
            data = json.loads(raw_text)
        except Exception:
            return 0
        items = data.get("descriptors", []) if isinstance(data, Mapping) else data
        if not isinstance(items, list):
            return 0
        loaded = 0
        for item in items[:MAX_DESCRIPTORS_PER_MESSAGE]:
            if not isinstance(item, Mapping):
                continue
            try:
                updated, _ = self.ingest_raw_descriptor(item)
                if updated:
                    loaded += 1
            except Exception:
                continue
        return loaded


def ingest_descriptor_http_request(
    req: Any,
    descriptor_store: Optional[DomainDescriptorStore],
    on_descriptor_learned: Optional[Callable[[SignedDomainDescriptor], None]] = None,
) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
    """Bounded, pin-first-verified `POST /v1/federation/descriptors` handler (`<= 1 MiB`, `<= 32` items)."""
    raw_body: bytes = getattr(req, "body", b"") or b""
    if len(raw_body) > MAX_DESCRIPTOR_HTTP_BYTES:
        return (
            413,
            {
                "error": "descriptor_payload_too_large",
                "max_bytes": MAX_DESCRIPTOR_HTTP_BYTES,
            },
            {},
        )
    try:
        body = req.json()
    except Exception as exc:
        return 400, {"error": "invalid_json", "detail": str(exc)}, {}

    if not isinstance(body, Mapping):
        return 400, {"error": "invalid_descriptor_envelope"}, {}
    raw_list = body.get("descriptors")
    if not isinstance(raw_list, list):
        return 400, {"error": "invalid_descriptors_list"}, {}
    if len(raw_list) > MAX_DESCRIPTORS_PER_MESSAGE:
        return (
            400,
            {
                "error": "too_many_descriptors",
                "max_descriptors": MAX_DESCRIPTORS_PER_MESSAGE,
            },
            {},
        )
    if descriptor_store is None:
        return 200, {"accepted": True, "learned": 0, "rejected": 0}, {}

    learned = 0
    rejected = 0
    for item in raw_list:
        if not isinstance(item, Mapping):
            rejected += 1
            continue
        try:
            updated, desc = descriptor_store.ingest_raw_descriptor(item)
            if on_descriptor_learned is not None:
                try:
                    on_descriptor_learned(desc)
                except Exception:
                    pass
            if updated:
                learned += 1
        except Exception:
            rejected += 1
    return 200, {"accepted": True, "learned": learned, "rejected": rejected}, {}
