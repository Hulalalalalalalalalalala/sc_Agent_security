"""SSH-Style Cross-Machine Trust Anchor Pinning & Hot-Reloading ConfigMap Store.

Anchor Format (one line per autonomous domain):
    `<trust_domain> sha256:<64-hex-x509-spki-sha256>:<64-hex-jwks-set-sha256|keyless>`

Security Properties:
1. Defends plain-HTTP / TOFU LAN bundle endpoints against active MITM substitution:
   `FederationBundleSyncer` computes `compute_bundle_trust_anchor(bundle)` BEFORE
   importing any JWK or X.509 Root CA PEM into `TrustBundleResolver` or
   `X509FederationTrustStore`.
2. Hot-reloads Kubernetes `ConfigMap` volume mounts (`LCT_TRUST_ANCHORS_DIR`, e.g.
   `/etc/lct-anchors`) without Pod restarts by comparing canonical file contents across
   kubelet `..data` atomic symlink swaps.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import threading
from typing import Any, Dict, Mapping, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from lineage.common.crypto import CryptoError, compute_jwk_thumbprint, sha256_hex
from lineage.common.mtls import MTLSError, compute_x509_spki_sha256_hex
from lineage.identity.spiffe import IdentityError, SpiffeId

_ANCHOR_RE = re.compile(r"^sha256:([0-9a-f]{64}):([0-9a-f]{64}|keyless)$")


class TrustAnchorPinError(Exception):
    """Raised when a remote domain bundle is unpinned (in strict mode) or mismatches its pin."""


def parse_trust_anchor_value(raw: str) -> Tuple[Optional[str], str]:
    """Parse either `'sha256:<spki>:<jwks>'` or `'<domain> sha256:<spki>:<jwks>'`.

    Returns `(optional_domain, canonical_anchor)`.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise TrustAnchorPinError("Empty trust anchor string")
    parts = raw.strip().split()
    if len(parts) == 1:
        domain = None
        anchor_str = parts[0].lower()
    elif len(parts) == 2:
        domain = parts[0].strip().lower()
        SpiffeId.parse(f"spiffe://{domain}/authority/ca")
        anchor_str = parts[1].lower()
    else:
        raise TrustAnchorPinError(
            f"Invalid trust anchor format {raw!r}: expected '[<domain>] sha256:<64hex>:<64hex|keyless>'"
        )
    if not _ANCHOR_RE.match(anchor_str):
        raise TrustAnchorPinError(
            f"Malformed trust anchor digest {anchor_str!r}: expected 'sha256:<64hex>:<64hex|keyless>'"
        )
    return domain, anchor_str


def split_trust_anchor_parts(raw: str) -> Tuple[str, str]:
    """Extract `(x509_spki_hex, jwks_set_hex_or_keyless)` from a validated anchor string."""
    _, canonical = parse_trust_anchor_value(raw)
    m = _ANCHOR_RE.match(canonical)
    if not m:
        raise TrustAnchorPinError(f"Malformed trust anchor: {raw!r}")
    return m.group(1), m.group(2)


def extract_canonical_bundle_root_pem(bundle: Mapping[str, Any]) -> str:
    """Validate and extract the single canonical X.509 Root CA PEM from a bundle.

    Enforces strict single-root canonicality (`[HIGH-M6-01]`):
    - If `x509_roots_pem` is present and non-None, it MUST be a 1-element list of PEM strings.
    - If both `x509_roots_pem` and `x509_root_pem` are present, their DER bytes MUST match.
    """
    if not isinstance(bundle, Mapping):
        raise TrustAnchorPinError("Bundle must be a JSON object")
    roots_list = bundle.get("x509_roots_pem")
    single_raw = bundle.get("x509_root_pem")

    cert_from_list: Optional[x509.Certificate] = None
    if roots_list is not None:
        if (
            not isinstance(roots_list, list)
            or len(roots_list) != 1
            or not isinstance(roots_list[0], str)
            or "BEGIN CERTIFICATE" not in roots_list[0]
        ):
            raise TrustAnchorPinError(
                "Bundle 'x509_roots_pem' must contain exactly one valid X.509 root certificate"
            )
        if "PRIVATE KEY" in roots_list[0]:
            raise TrustAnchorPinError("Private key material forbidden in x509_roots_pem")
        try:
            cert_from_list = x509.load_pem_x509_certificate(roots_list[0].encode("ascii"))
        except Exception as exc:
            raise TrustAnchorPinError(f"Invalid PEM in x509_roots_pem: {exc}") from exc

    cert_from_single: Optional[x509.Certificate] = None
    if single_raw is not None and str(single_raw).strip():
        if not isinstance(single_raw, str) or "BEGIN CERTIFICATE" not in single_raw:
            raise TrustAnchorPinError("Bundle 'x509_root_pem' is not a valid PEM certificate")
        if "PRIVATE KEY" in single_raw:
            raise TrustAnchorPinError("Private key material forbidden in x509_root_pem")
        try:
            cert_from_single = x509.load_pem_x509_certificate(single_raw.encode("ascii"))
        except Exception as exc:
            raise TrustAnchorPinError(f"Invalid PEM in x509_root_pem: {exc}") from exc

    if cert_from_list is not None and cert_from_single is not None:
        if cert_from_list.public_bytes(
            serialization.Encoding.DER
        ) != cert_from_single.public_bytes(serialization.Encoding.DER):
            raise TrustAnchorPinError(
                "Conflicting X.509 root certificates between 'x509_root_pem' and 'x509_roots_pem'"
            )

    chosen = cert_from_list or cert_from_single
    if chosen is None:
        raise TrustAnchorPinError("Bundle missing valid x509_root_pem for anchor computation")
    return chosen.public_bytes(serialization.Encoding.PEM).decode("ascii")


def compute_bundle_trust_anchor(
    bundle: Mapping[str, Any], allow_keyless_jwks: bool = False
) -> str:
    """Compute canonical `sha256:<x509_spki_hex>:<jwks_thumbprint_set_hex|keyless>` for a bundle."""
    root_pem = extract_canonical_bundle_root_pem(bundle)
    try:
        spki_hex = compute_x509_spki_sha256_hex(root_pem)
    except MTLSError as exc:
        raise TrustAnchorPinError(f"Invalid X.509 root in bundle: {exc}") from exc

    keys_raw = bundle.get("keys")
    td_hint = str(bundle.get("trust_domain") or "").strip().lower()
    if keys_raw is None or (isinstance(keys_raw, list) and len(keys_raw) == 0):
        if not allow_keyless_jwks and td_hint != "org-audit.io":
            raise TrustAnchorPinError(
                f"Bundle for {td_hint or 'domain'!r} contains zero JWKS signing keys"
            )
        jwks_part = "keyless"
    elif isinstance(keys_raw, list):
        try:
            jkts = sorted(compute_jwk_thumbprint(k) for k in keys_raw)
        except CryptoError as exc:
            raise TrustAnchorPinError(f"Invalid JWK in bundle: {exc}") from exc
        jwks_part = sha256_hex(",".join(jkts).encode("ascii"))
    else:
        raise TrustAnchorPinError("Bundle 'keys' field must be a list")

    return f"sha256:{spki_hex}:{jwks_part}"


def format_domain_trust_anchor_line(
    trust_domain: str, bundle_or_anchor: Union[Mapping[str, Any], str]
) -> str:
    """Format one-line operator anchor: `'<domain> sha256:<spki>:<jwks>'`."""
    norm_td = trust_domain.strip().lower()
    SpiffeId.parse(f"spiffe://{norm_td}/authority/ca")
    if isinstance(bundle_or_anchor, str):
        _, clean_anc = parse_trust_anchor_value(bundle_or_anchor)
        return f"{norm_td} {clean_anc}"
    return f"{norm_td} {compute_bundle_trust_anchor(bundle_or_anchor, allow_keyless_jwks=(norm_td == 'org-audit.io'))}"


def parse_env_trust_anchors(spec: str) -> Dict[str, str]:
    """Parse `'org-beta.io=sha256:...,org-payment.io=sha256:...'`."""
    out: Dict[str, str] = {}
    for item in (spec or "").split(","):
        s = item.strip()
        if not s:
            continue
        if "=" in s:
            td, val = s.split("=", 1)
            norm_td = td.strip().lower()
            SpiffeId.parse(f"spiffe://{norm_td}/authority/ca")
            emb_td, anchor = parse_trust_anchor_value(val)
            if emb_td is not None and emb_td != norm_td:
                raise TrustAnchorPinError(
                    f"Conflicting domain in anchor spec: {norm_td!r} vs {emb_td!r}"
                )
            out[norm_td] = anchor
        else:
            emb_td, anchor = parse_trust_anchor_value(s)
            if emb_td is None:
                raise TrustAnchorPinError(
                    f"Anchor entry {s!r} missing domain prefix '<domain>=sha256:...'"
                )
            out[emb_td] = anchor
    return out


class TrustAnchorPinStore:
    """Thread-safe, hot-reloading trust anchor pin store backed by memory + optional ConfigMap dir."""

    def __init__(
        self,
        initial_pins: Optional[Mapping[str, str]] = None,
        env_pins_spec: Optional[str] = None,
        pins_dir: Optional[str] = None,
        anchors_dir: Optional[str] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._manual_pins: Dict[str, str] = {}
        self._dir_pins: Dict[str, str] = {}
        eff_dir = anchors_dir if anchors_dir is not None else pins_dir
        self._pins_dir: Optional[Path] = (
            Path(eff_dir) if (eff_dir and str(eff_dir).strip()) else None
        )
        self._version: int = 0

        eff_env = env_pins_spec if env_pins_spec is not None else os.environ.get("LCT_TRUST_ANCHORS", "")
        if eff_env:
            for td, anc in parse_env_trust_anchors(eff_env).items():
                self._manual_pins[td] = anc
        if initial_pins:
            for td, raw_anc in initial_pins.items():
                norm_td = str(td).strip().lower()
                SpiffeId.parse(f"spiffe://{norm_td}/authority/ca")
                emb_td, anc = parse_trust_anchor_value(str(raw_anc))
                if emb_td is not None and emb_td != norm_td:
                    raise TrustAnchorPinError(
                        f"Anchor domain mismatch: key={norm_td!r} vs value={emb_td!r}"
                    )
                self._manual_pins[norm_td] = anc

        self.reload_if_changed()

    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    def set_pin(self, trust_domain: str, anchor: str) -> str:
        norm_td = trust_domain.strip().lower()
        try:
            SpiffeId.parse(f"spiffe://{norm_td}/authority/ca")
        except IdentityError as exc:
            raise TrustAnchorPinError(f"Invalid trust_domain {trust_domain!r}: {exc}") from exc
        emb_td, clean_anc = parse_trust_anchor_value(anchor)
        if emb_td is not None and emb_td != norm_td:
            raise TrustAnchorPinError(
                f"Anchor domain mismatch: {norm_td!r} vs {emb_td!r}"
            )
        with self._lock:
            self._dir_pins.pop(norm_td, None)
            if self._manual_pins.get(norm_td) != clean_anc:
                self._manual_pins[norm_td] = clean_anc
                self._version += 1
        return clean_anc

    def remove_pin(self, trust_domain: str) -> None:
        norm_td = trust_domain.strip().lower()
        with self._lock:
            removed_m = self._manual_pins.pop(norm_td, None) is not None
            removed_d = self._dir_pins.pop(norm_td, None) is not None
            if removed_m or removed_d:
                self._version += 1

    def reload_if_changed(self) -> bool:
        """Scan `self._pins_dir` (e.g. `/etc/lct-anchors` ConfigMap mount) and update pins if changed."""
        if self._pins_dir is None or not self._pins_dir.is_dir():
            return False
        loaded: Dict[str, str] = {}
        for entry in sorted(self._pins_dir.iterdir()):
            if entry.name.startswith(".") or not entry.is_file():
                continue
            raw_txt = entry.read_text(encoding="utf-8").strip()
            if not raw_txt:
                continue
            for line in raw_txt.splitlines():
                ls = line.strip()
                if not ls or ls.startswith("#"):
                    continue
                emb_td, anc = parse_trust_anchor_value(ls)
                target_td = emb_td if emb_td is not None else entry.name.strip().lower()
                SpiffeId.parse(f"spiffe://{target_td}/authority/ca")
                loaded[target_td] = anc
        with self._lock:
            if loaded != self._dir_pins:
                self._dir_pins = loaded
                self._version += 1
                return True
        return False

    refresh_if_changed = reload_if_changed

    def get_pin(self, trust_domain: str) -> Optional[str]:
        norm_td = trust_domain.strip().lower()
        with self._lock:
            if norm_td in self._dir_pins:
                return self._dir_pins[norm_td]
            return self._manual_pins.get(norm_td)

    def all_pins(self) -> Dict[str, str]:
        with self._lock:
            merged = dict(self._manual_pins)
            merged.update(self._dir_pins)
            return merged

    def verify_bundle(
        self,
        expected_domain: str,
        bundle: Mapping[str, Any],
        require_pin: bool = False,
        allow_keyless_jwks: bool = False,
    ) -> str:
        """Verify `bundle` against pinned anchor for `expected_domain` (fail-closed on mismatch!)."""
        norm_td = expected_domain.strip().lower()
        actual_anchor = compute_bundle_trust_anchor(
            bundle, allow_keyless_jwks=(allow_keyless_jwks or norm_td == "org-audit.io")
        )
        pinned = self.get_pin(norm_td)
        if pinned is None:
            if require_pin:
                raise TrustAnchorPinError(
                    f"Missing required trust anchor pin for {norm_td!r} (observed {actual_anchor}). "
                    f"Pin out-of-band verified anchor via: "
                    f"python3 lineage/multihost/lct_multihost_cli.py trust add {norm_td} {actual_anchor}"
                )
            return actual_anchor
        if pinned != actual_anchor:
            raise TrustAnchorPinError(
                f"TRUST ANCHOR PIN MISMATCH for {norm_td!r}: "
                f"expected pinned '{pinned}', but peer presented '{actual_anchor}'. "
                f"Connection refused (fail-closed)! Reset/update pin after out-of-band verification via: "
                f"python3 lineage/multihost/lct_multihost_cli.py trust add {norm_td} {actual_anchor}"
            )
        return actual_anchor

    verify_bundle_against_pin = verify_bundle
