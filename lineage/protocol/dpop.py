"""RFC 9449 OAuth 2.0 Demonstrating Proof-of-Possession (DPoP) Implementation.

Binds every HTTP request (`htm`, `htu`), access token hash (`ath`), timestamp (`iat`),
and unique anti-replay nonce (`jti`) to the sender's asymmetric private key (`ES256`/`RS256`).
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import OrderedDict
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlparse

from lineage.common.crypto import (
    CryptoError,
    KeyPair,
    compute_jwk_thumbprint,
    jwk_to_public_key,
    jws_parse_unverified,
    jws_sign_compact,
    jws_verify_compact,
    require_finite_timestamp,
    sha256_b64url,
)
from lineage.identity.spiffe import WorkloadIdentity


class DPoPError(Exception):
    """Raised when a DPoP proof is missing, invalid, mismatched, expired, or replayed."""


def normalize_htu(url: str) -> str:
    """Normalize HTTP URI (`htu`) per RFC 9449 Section 4.2 (strip query & fragment)."""
    if not isinstance(url, str) or not url:
        raise DPoPError("Empty HTTP target URI (htu)")
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not parsed.hostname:
        raise DPoPError(f"Invalid HTTP target URI (htu): {url!r}")
    host = parsed.hostname.lower()
    port = parsed.port
    if (scheme == "http" and port in (None, 80)) or (
        scheme == "https" and port in (None, 443)
    ):
        netloc = host
    else:
        netloc = f"{host}:{port}"
    path = parsed.path if parsed.path else "/"
    return f"{scheme}://{netloc}{path}"


class JTIReplayCache:
    """Thread-safe bounded TTL cache blocking DPoP `jti` replay attacks."""

    def __init__(self, ttl_seconds: float = 300.0, max_entries: int = 50_000) -> None:
        self.ttl_seconds = float(ttl_seconds)
        self.max_entries = int(max_entries)
        self._lock = threading.Lock()
        self._entries: "OrderedDict[str, float]" = OrderedDict()

    def check_and_record(self, jti: str, now: Optional[float] = None) -> bool:
        """Atomically return True and record `jti` if unseen; return False if replayed."""
        ts = time.time() if now is None else float(now)
        with self._lock:
            # Purge expired entries from oldest front
            while self._entries:
                oldest_jti, exp_at = next(iter(self._entries.items()))
                if exp_at <= ts:
                    self._entries.popitem(last=False)
                else:
                    break

            if jti in self._entries:
                return False

            if len(self._entries) >= self.max_entries:
                self._entries.popitem(last=False)

            self._entries[jti] = ts + self.ttl_seconds
            return True


def create_dpop_proof(
    signer: WorkloadIdentity | KeyPair,
    htm: str,
    htu: str,
    access_token: str,
    now: Optional[float] = None,
    jti: Optional[str] = None,
) -> str:
    """Create a signed RFC 9449 `dpop+jwt` proof bound to `(htm, htu, ath)`."""
    keypair = signer.keypair if isinstance(signer, WorkloadIdentity) else signer
    if not htm or not isinstance(htm, str):
        raise DPoPError("Invalid HTTP method (htm)")
    if not access_token or not isinstance(access_token, str):
        raise DPoPError("Access token required to compute DPoP 'ath'")

    norm_htu = normalize_htu(htu)
    ts = time.time() if now is None else float(now)
    proof_jti = jti if jti else f"dpop-{uuid.uuid4().hex}"
    ath = sha256_b64url(access_token.encode("ascii"))

    claims = {
        "jti": proof_jti,
        "htm": htm.upper(),
        "htu": norm_htu,
        "iat": ts,
        "ath": ath,
    }
    return jws_sign_compact(
        payload=claims,
        keypair=keypair,
        typ="dpop+jwt",
        extra_headers={"jwk": keypair.public_jwk(include_kid=True)},
    )


class DPoPVerifier:
    """RFC 9449 DPoP Proof Verifier with JWK thumbprint binding & anti-replay."""

    def __init__(
        self,
        replay_cache: Optional[JTIReplayCache] = None,
        max_iat_age_seconds: float = 120.0,
        clock_skew_seconds: float = 5.0,
    ) -> None:
        self.replay_cache = replay_cache or JTIReplayCache()
        self.max_iat_age = float(max_iat_age_seconds)
        self.clock_skew = float(clock_skew_seconds)

    def verify_proof(
        self,
        dpop_proof: str,
        expected_htm: str,
        expected_htu: str,
        access_token: str,
        expected_jkt: str,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Verify DPoP signature, `jkt` binding, `htm`, `htu`, `ath`, freshness, and `jti`."""
        if not dpop_proof or not isinstance(dpop_proof, str):
            raise DPoPError("Missing DPoP header")

        try:
            header, _, _, _ = jws_parse_unverified(dpop_proof)
        except CryptoError as exc:
            raise DPoPError(f"Malformed DPoP JWS: {exc}") from exc

        embedded_jwk = header.get("jwk")
        if not isinstance(embedded_jwk, Mapping):
            raise DPoPError("DPoP header missing embedded public 'jwk'")

        try:
            jwk_to_public_key(embedded_jwk)
            actual_jkt = compute_jwk_thumbprint(embedded_jwk)
            _, payload = jws_verify_compact(
                dpop_proof, embedded_jwk, expected_typ="dpop+jwt"
            )
        except CryptoError as exc:
            raise DPoPError(f"DPoP cryptographic verification failed: {exc}") from exc

        if actual_jkt != expected_jkt:
            raise DPoPError(
                f"DPoP sender key thumbprint mismatch: got {actual_jkt!r}, expected {expected_jkt!r}"
            )

        htm = payload.get("htm")
        if not isinstance(htm, str) or htm.upper() != expected_htm.upper():
            raise DPoPError(
                f"DPoP htm mismatch: got {htm!r}, expected {expected_htm.upper()!r}"
            )

        htu = payload.get("htu")
        if not isinstance(htu, str) or normalize_htu(htu) != normalize_htu(expected_htu):
            raise DPoPError(
                f"DPoP htu mismatch: got {htu!r}, expected {normalize_htu(expected_htu)!r}"
            )

        expected_ath = sha256_b64url(access_token.encode("ascii"))
        if payload.get("ath") != expected_ath:
            raise DPoPError("DPoP 'ath' token hash mismatch")

        try:
            ts = require_finite_timestamp(time.time() if now is None else now, "now")
            iat = require_finite_timestamp(payload.get("iat"), "iat")
        except CryptoError as exc:
            raise DPoPError(f"DPoP proof invalid timestamp: {exc}") from exc
        if iat > ts + self.clock_skew:
            raise DPoPError("DPoP proof 'iat' is in the future")
        if ts - iat > self.max_iat_age:
            raise DPoPError("DPoP proof has expired (exceeded max_iat_age)")

        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti.strip():
            raise DPoPError("DPoP proof missing 'jti'")

        if not self.replay_cache.check_and_record(jti, now=ts):
            raise DPoPError(f"DPoP replay detected for jti={jti!r}")

        return {
            "jti": jti,
            "jkt": actual_jkt,
            "htm": htm.upper(),
            "htu": normalize_htu(htu),
            "iat": float(iat),
        }
