"""Federated multi-domain Trust Bundle Resolver.

Enables offline verification of cross-organization Workload SVIDs and Root Authority
blocks while strictly enforcing Trust Domain namespace isolation (an authority in
`org-beta.io` can NEVER attest identities under `org-alpha.io` or `org-payment.io`).
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

import httpx

from lineage.common.crypto import (
    CryptoError,
    compute_jwk_thumbprint,
    jwk_to_public_key,
    jws_parse_unverified,
    jws_verify_compact,
    require_finite_timestamp,
)
from lineage.identity.spiffe import IdentityError, SpiffeId, TrustDomainCA

DEFAULT_CLOCK_SKEW_SECONDS = 5.0


class TrustBundleResolver:
    """Thread-safe federated public key bundle resolver across multiple trust domains."""

    def __init__(self, clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS) -> None:
        self._lock = threading.RLock()
        self._clock_skew = float(clock_skew_seconds)
        # trust_domain -> {kid -> public_jwk}
        self._domain_keys: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._domain_versions: Dict[str, int] = {}

    def register_domain_ca(self, ca: TrustDomainCA) -> None:
        """Register public keys from a local TrustDomainCA instance."""
        self.register_bundle(ca.export_public_bundle())

    def register_bundle(self, bundle: Mapping[str, Any]) -> None:
        """Register or update a single domain's public JWKS bundle."""
        td = str(bundle.get("trust_domain", ""))
        SpiffeId.parse(f"spiffe://{td}/authority/ca")
        keys = bundle.get("keys")
        if not isinstance(keys, list) or not keys:
            raise IdentityError(f"Trust bundle for {td!r} contains no public keys")

        parsed_map: Dict[str, Dict[str, Any]] = {}
        for jwk in keys:
            if not isinstance(jwk, Mapping):
                raise IdentityError("Invalid JWK entry in trust bundle")
            # Cryptographically validate public key & reject any leaked private fields
            try:
                jwk_to_public_key(jwk)
            except CryptoError as exc:
                raise IdentityError(f"Invalid public JWK in bundle {td!r}: {exc}") from exc
            kid = str(jwk.get("kid") or compute_jwk_thumbprint(jwk))
            clean_jwk = dict(jwk)
            clean_jwk["kid"] = kid
            parsed_map[kid] = clean_jwk

        version = int(bundle.get("version", 1))
        with self._lock:
            prev_ver = self._domain_versions.get(td, 0)
            if version < prev_ver:
                raise IdentityError(
                    f"Trust bundle rollback rejected for {td!r}: v{version} < v{prev_ver}"
                )
            self._domain_keys[td] = parsed_map
            self._domain_versions[td] = version

    def register_federation(self, bundles: Iterable[Mapping[str, Any]]) -> None:
        """Bulk-load multiple federated trust domain bundles."""
        for b in bundles:
            self.register_bundle(b)

    def fetch_and_register_remote_bundle(self, jwks_url: str, timeout: float = 3.0) -> None:
        """Fetch a domain public bundle over HTTP and register it after validation."""
        resp = httpx.get(jwks_url, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if "bundles" in data and isinstance(data["bundles"], list):
            self.register_federation(data["bundles"])
        else:
            self.register_bundle(data)

    def export_federation_bundles(self) -> List[Dict[str, Any]]:
        """Serialize all registered domain public bundles for cross-process bootstrap."""
        with self._lock:
            out: List[Dict[str, Any]] = []
            for td, key_map in sorted(self._domain_keys.items()):
                out.append(
                    {
                        "trust_domain": td,
                        "issuer": f"spiffe://{td}/authority/ca",
                        "version": self._domain_versions.get(td, 1),
                        "keys": list(key_map.values()),
                    }
                )
            return out

    @classmethod
    def from_federation_bundles(
        cls,
        bundles: Iterable[Mapping[str, Any]],
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> "TrustBundleResolver":
        resolver = cls(clock_skew_seconds=clock_skew_seconds)
        resolver.register_federation(bundles)
        return resolver

    def trusted_domains(self) -> List[str]:
        with self._lock:
            return sorted(self._domain_keys.keys())

    def get_domain_key(self, trust_domain: str, kid: str) -> Dict[str, Any]:
        with self._lock:
            domain_map = self._domain_keys.get(trust_domain)
            if not domain_map:
                raise IdentityError(f"Untrusted SPIFFE domain: {trust_domain!r}")
            jwk = domain_map.get(kid)
            if not jwk:
                raise IdentityError(
                    f"Unknown key ID {kid!r} in trust domain {trust_domain!r}"
                )
            return dict(jwk)

    def verify_domain_jws(
        self,
        compact_jws: str,
        expected_trust_domain: str,
        expected_typ: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Verify a JWS strictly against keys belonging to `expected_trust_domain`."""
        try:
            header, _, _, _ = jws_parse_unverified(compact_jws)
        except CryptoError as exc:
            raise IdentityError(f"Malformed domain JWS: {exc}") from exc

        kid = header.get("kid")
        if not kid or not isinstance(kid, str):
            raise IdentityError("Domain JWS missing 'kid' header")

        ca_jwk = self.get_domain_key(expected_trust_domain, kid)
        try:
            return jws_verify_compact(
                compact_jws, ca_jwk, expected_typ=expected_typ
            )
        except CryptoError as exc:
            raise IdentityError(
                f"Domain signature verification failed for {expected_trust_domain!r}: {exc}"
            ) from exc

    def verify_workload_svid(
        self,
        svid: str,
        expected_spiffe_id: Optional[str] = None,
        expected_jkt: Optional[str] = None,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Verify a Workload JWT-SVID against the federated Trust Bundle.

        Enforces:
        1. Valid SPIFFE ID in `sub`
        2. Namespace isolation: `svid` MUST be signed by `sub`'s own trust domain CA
        3. Temporal validity (`iat`, `exp`)
        4. Holder-of-key consistency (`cnf.jkt == thumbprint(cnf.jwk)`)
        5. Optional match against `expected_spiffe_id` and `expected_jkt`
        """
        try:
            _, unverified_payload, _, _ = jws_parse_unverified(svid)
        except CryptoError as exc:
            raise IdentityError(f"Malformed Workload SVID: {exc}") from exc

        sub = str(unverified_payload.get("sub", ""))
        spiffe = SpiffeId.parse(sub)
        if expected_spiffe_id is not None and spiffe.uri != expected_spiffe_id:
            raise IdentityError(
                f"SVID subject mismatch: expected {expected_spiffe_id!r}, got {spiffe.uri!r}"
            )

        # Verify signature strictly using ONLY `spiffe.trust_domain` keys!
        _, payload = self.verify_domain_jws(
            svid,
            expected_trust_domain=spiffe.trust_domain,
            expected_typ="spiffe-svid+jwt",
        )

        expected_iss = f"spiffe://{spiffe.trust_domain}/authority/ca"
        if payload.get("iss") != expected_iss or payload.get("trust_domain") != spiffe.trust_domain:
            raise IdentityError(
                f"Cross-domain SVID issuer mismatch for {spiffe.uri!r}: {payload.get('iss')!r}"
            )

        ts = require_finite_timestamp(time.time() if now is None else now, "now")
        try:
            iat = require_finite_timestamp(payload.get("iat"), "iat")
            exp = require_finite_timestamp(payload.get("exp"), "exp")
        except CryptoError as exc:
            raise IdentityError(f"Workload SVID invalid numeric iat/exp: {exc}") from exc
        if iat > ts + self._clock_skew:
            raise IdentityError("Workload SVID iat is in the future")
        if exp <= ts - self._clock_skew:
            raise IdentityError("Workload SVID has expired")

        cnf = payload.get("cnf")
        if not isinstance(cnf, Mapping) or "jkt" not in cnf or "jwk" not in cnf:
            raise IdentityError("Workload SVID missing cnf.jkt or cnf.jwk")

        try:
            computed_jkt = compute_jwk_thumbprint(cnf["jwk"])
        except CryptoError as exc:
            raise IdentityError(f"Invalid cnf.jwk in Workload SVID: {exc}") from exc

        if cnf["jkt"] != computed_jkt:
            raise IdentityError("Workload SVID cnf.jkt does not match cnf.jwk thumbprint")

        if expected_jkt is not None and computed_jkt != expected_jkt:
            raise IdentityError(
                f"Workload SVID jkt mismatch: expected {expected_jkt!r}, got {computed_jkt!r}"
            )

        return payload
