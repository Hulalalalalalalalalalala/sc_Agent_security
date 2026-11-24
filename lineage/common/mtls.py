"""Real SPIFFE X.509-SVID Mutual TLS (mTLS 1.3) Authority & Federated Trust Store.

Implements:
- `X509DomainAuthority`: Per-trust-domain X.509 v3 Root CA (`ECDSA P-256`) with critical
  RFC 5280 `BasicConstraints(ca=True, path_length=0)` and critical `NameConstraints`
  restricting `UniformResourceIdentifier`, `DNSName`, and `IPAddress` subtrees to the CA's
  own autonomous jurisdiction.
- `X509FederationTrustStore`: Thread-safe federated X.509 Root CA store verifying critical
  `NameConstraints` upon CA bundle import and enforcing strict leaf `BasicConstraints(ca=False)`,
  `KeyUsage`, `ExtendedKeyUsage` (`CLIENT_AUTH` / `SERVER_AUTH`), and per-domain issuer pinning.
- `WorkloadMTLSBundle`: Builds server and per-domain-pinned client `TLSv1.3` `ssl.SSLContext`
  instances with pre-HTTP handshake server certificate verification (`CheckedSSLSocket` /
  `CheckedSSLObject`) and immediate unlink of RAM-tmpfs key material.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import shutil
import ssl
import tempfile
import threading
from dataclasses import dataclass, field
import hashlib
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from lineage.common.crypto import (
    CryptoError,
    KeyPair,
    compute_jwk_thumbprint,
    jwk_to_public_key,
    public_key_to_jwk,
)
from lineage.identity.spiffe import IdentityError, SpiffeId


class MTLSError(Exception):
    """Raised on X.509-SVID issuance, domain pinning, or mTLS verification failure."""


def _is_ip_literal(host: Optional[str]) -> bool:
    if not host:
        return False
    cleaned = host.strip().strip("[]")
    if not cleaned:
        return False
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False


def _extract_spiffe_uris_from_cert(cert: x509.Certificate) -> List[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [
        u
        for u in san.get_values_for_type(x509.UniformResourceIdentifier)
        if u.startswith("spiffe://")
    ]


def _dns_matches_permitted_subtree(dns_name: str, subtree: str) -> bool:
    """RFC 5280 §4.2.1.10 DNSName NameConstraints matching."""
    dn = dns_name.strip().lower().rstrip(".")
    st = subtree.strip().lower().rstrip(".")
    if not dn or not st:
        return False
    if st.startswith("."):
        # Leading period matches one or more labels preceding the suffix
        return dn.endswith(st) and len(dn) > len(st)
    return dn == st or dn.endswith(f".{st}")


def compute_x509_spki_sha256_hex(cert_pem: str) -> str:
    """Compute lowercase SHA-256 hex digest of X.509 SubjectPublicKeyInfo (DER)."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.strip().encode("ascii"))
    except Exception as exc:
        raise MTLSError(f"Invalid X.509 certificate PEM for SPKI hash: {exc}") from exc
    spki_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


class X509DomainAuthority:
    """In-memory X.509 v3 Root CA scoped strictly to a single SPIFFE `trust_domain`."""

    def __init__(
        self,
        trust_domain: str,
        ttl_days: int = 365,
        allowed_dns_suffixes: Optional[Iterable[str]] = None,
        private_key_pem: Optional[str] = None,
        root_cert_pem: Optional[str] = None,
    ) -> None:
        SpiffeId.parse(f"spiffe://{trust_domain}/authority/x509-ca")
        self.trust_domain = trust_domain.strip().lower()
        self.ca_spiffe_id = f"spiffe://{self.trust_domain}/authority/x509-ca"

        if private_key_pem is not None and root_cert_pem is not None:
            loaded_priv = serialization.load_pem_private_key(
                private_key_pem.strip().encode("ascii"), password=None
            )
            if not isinstance(loaded_priv, ec.EllipticCurvePrivateKey):
                raise MTLSError("Persisted X509DomainAuthority private key must be ECDSA P-256")
            loaded_cert = x509.load_pem_x509_certificate(root_cert_pem.strip().encode("ascii"))
            pub_a = loaded_priv.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_b = loaded_cert.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if pub_a != pub_b:
                raise MTLSError("Persisted X.509 Root CA private key does not match root_cert_pem")
            nc_ext = loaded_cert.extensions.get_extension_for_class(x509.NameConstraints)
            if not nc_ext.critical:
                raise MTLSError("Persisted X.509 Root CA NameConstraints must be critical")
            dns_from_cert = [
                g.value.strip().lower()
                for g in (nc_ext.value.permitted_subtrees or [])
                if isinstance(g, x509.DNSName)
            ]
            self._private_key = loaded_priv
            self.root_cert = loaded_cert
            self.allowed_dns_suffixes = tuple(dns_from_cert)
            return

        self._private_key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.timezone.utc)

        raw_dns = (
            list(allowed_dns_suffixes)
            if allowed_dns_suffixes is not None
            else [f".{self.trust_domain}", self.trust_domain, "localhost"]
        )
        norm_dns: List[str] = []
        for entry in raw_dns:
            s = str(entry).strip().lower()
            if s and s not in norm_dns:
                norm_dns.append(s)
        if "localhost" not in norm_dns:
            norm_dns.append("localhost")
        self.allowed_dns_suffixes: Tuple[str, ...] = tuple(norm_dns)

        permitted_subtrees: List[x509.GeneralName] = [
            x509.UniformResourceIdentifier(self.trust_domain),
            *(x509.DNSName(d) for d in self.allowed_dns_suffixes),
            x509.IPAddress(ipaddress.ip_network("127.0.0.1/32")),
            x509.IPAddress(ipaddress.ip_network("::1/128")),
        ]

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.trust_domain),
                x509.NameAttribute(
                    NameOID.COMMON_NAME, f"{self.trust_domain} LCT Autonomous Root CA"
                ),
            ]
        )
        ski = x509.SubjectKeyIdentifier.from_public_key(self._private_key.public_key())
        self.root_cert: x509.Certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=int(ttl_days)))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.NameConstraints(
                    permitted_subtrees=permitted_subtrees,
                    excluded_subtrees=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(self.ca_spiffe_id)]
                ),
                critical=False,
            )
            .add_extension(ski, critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
                critical=False,
            )
            .sign(private_key=self._private_key, algorithm=hashes.SHA256())
        )

    def export_root_pem(self) -> str:
        """Export public X.509 Root CA certificate PEM (contains zero private key material)."""
        return self.root_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def export_private_key_pem(self) -> str:
        """Export PKCS#8 PEM strictly for streaming into an isolated K8s CA Secret."""
        return (
            self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            .decode("ascii")
        )

    def issue_x509_svid(
        self,
        spiffe_id: str,
        public_jwk: Mapping[str, object],
        dns_names: Iterable[str] = (),
        ip_addresses: Iterable[str] = ("127.0.0.1",),
        ttl_seconds: float = 1800.0,
    ) -> str:
        """Sign a leaf X.509-SVID for `spiffe_id` strictly within `self.trust_domain`."""
        try:
            parsed = SpiffeId.parse(spiffe_id)
        except IdentityError as exc:
            raise MTLSError(f"Invalid SPIFFE ID for X.509-SVID: {exc}") from exc

        if parsed.trust_domain != self.trust_domain:
            raise MTLSError(
                f"Domain CA {self.trust_domain!r} refuses to sign X.509-SVID for foreign domain {parsed.trust_domain!r}"
            )

        try:
            pub_key, _ = jwk_to_public_key(public_jwk)
        except CryptoError as exc:
            raise MTLSError(f"Invalid public_jwk for X.509-SVID: {exc}") from exc

        if ttl_seconds < 1.0 or ttl_seconds > 86400.0:
            raise MTLSError(f"Invalid X.509-SVID ttl_seconds: {ttl_seconds}")

        san_entries: List[x509.GeneralName] = [
            x509.UniformResourceIdentifier(parsed.uri)
        ]
        seen_dns = set()
        for d in dns_names:
            ds = str(d).strip().lower()
            if not ds or ds in seen_dns:
                continue
            if not any(
                _dns_matches_permitted_subtree(ds, sub)
                for sub in self.allowed_dns_suffixes
            ):
                raise MTLSError(
                    f"DNS SAN {ds!r} violates NameConstraints {self.allowed_dns_suffixes!r} of CA {self.trust_domain!r}"
                )
            seen_dns.add(ds)
            san_entries.append(x509.DNSName(ds))

        seen_ip = set()
        for ip_raw in ip_addresses:
            ips = str(ip_raw).strip()
            if not ips or ips in seen_ip:
                continue
            seen_ip.add(ips)
            try:
                ip_obj = ipaddress.ip_address(ips)
            except ValueError as exc:
                raise MTLSError(f"Invalid IP SAN {ips!r}: {exc}") from exc
            if not ip_obj.is_loopback:
                raise MTLSError(
                    f"Non-loopback IP SAN {ips!r} violates NameConstraints of CA {self.trust_domain!r}"
                )
            san_entries.append(x509.IPAddress(ip_obj))

        now = dt.datetime.now(dt.timezone.utc)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.trust_domain),
                x509.NameAttribute(NameOID.COMMON_NAME, parsed.uri),
            ]
        )
        leaf_ski = x509.SubjectKeyIdentifier.from_public_key(pub_key)
        ca_ski = self.root_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value

        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.root_cert.subject)
            .public_key(pub_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(seconds=30))
            .not_valid_after(now + dt.timedelta(seconds=float(ttl_seconds)))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
                ),
                critical=False,
            )
            .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
            .add_extension(leaf_ski, critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                critical=False,
            )
            .sign(private_key=self._private_key, algorithm=hashes.SHA256())
        )
        return leaf_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


class X509FederationTrustStore:
    """Thread-safe federated X.509 Root CA store with NameConstraints & per-domain pinning."""

    _K8S_NS_DOMAIN_HINTS: Dict[str, str] = {
        "lineage-alpha": "org-alpha.io",
        "lineage-beta": "org-beta.io",
        "lineage-pay": "org-payment.io",
        "lineage-ctrl": "org-audit.io",
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._domain_roots: Dict[str, x509.Certificate] = {}
        self._domain_pems: Dict[str, str] = {}
        self._domain_dns_subtrees: Dict[str, Tuple[str, ...]] = {}
        self._version: int = 0
        self._server_verify_ctx_cache: Dict[Tuple[str, bool, Optional[str], int], ssl.SSLContext] = {}

    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    def register_domain_root_pem(self, expected_trust_domain: str, root_pem: str) -> None:
        """Validate (including critical `NameConstraints`) and pin a domain's X.509 Root CA."""
        norm_td = expected_trust_domain.strip().lower()
        SpiffeId.parse(f"spiffe://{norm_td}/authority/x509-ca")
        if not isinstance(root_pem, str) or "BEGIN CERTIFICATE" not in root_pem:
            raise MTLSError(f"Missing X.509 Root CA PEM for {norm_td!r}")
        if "PRIVATE KEY" in root_pem:
            raise MTLSError("Private key material must NEVER appear in federation X.509 bundle")

        try:
            cert = x509.load_pem_x509_certificate(root_pem.encode("ascii"))
        except Exception as exc:
            raise MTLSError(f"Malformed X.509 Root CA PEM for {norm_td!r}: {exc}") from exc

        try:
            bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound as exc:
            raise MTLSError("X.509 Root CA missing BasicConstraints") from exc
        if not bc_ext.critical or not bc_ext.value.ca or bc_ext.value.path_length != 0:
            raise MTLSError(
                "Federated X.509 Root CA must assert critical BasicConstraints(ca=True, path_length=0)"
            )

        # Enforce critical RFC 5280 NameConstraints (`[HIGH-M3-02]`)
        try:
            nc_ext = cert.extensions.get_extension_for_class(x509.NameConstraints)
        except x509.ExtensionNotFound as exc:
            raise MTLSError(
                f"Federated X.509 Root CA for {norm_td!r} missing mandatory critical NameConstraints"
            ) from exc
        if not nc_ext.critical:
            raise MTLSError(
                f"Federated X.509 Root CA NameConstraints for {norm_td!r} must be marked critical"
            )
        permitted = nc_ext.value.permitted_subtrees or []
        uri_subtrees = [
            u.value.strip().lower()
            for u in permitted
            if isinstance(u, x509.UniformResourceIdentifier)
        ]
        if not uri_subtrees or any(u != norm_td for u in uri_subtrees):
            raise MTLSError(
                f"Federated X.509 Root CA NameConstraints URI subtrees {uri_subtrees!r} "
                f"must strictly equal [{norm_td!r}]"
            )
        dns_subtrees = [
            d.value.strip().lower()
            for d in permitted
            if isinstance(d, x509.DNSName)
        ]
        if not dns_subtrees or any(d in ("", ".") for d in dns_subtrees):
            raise MTLSError(
                f"Federated X.509 Root CA for {norm_td!r} has missing or wildcard DNS NameConstraints"
            )

        spiffe_uris = _extract_spiffe_uris_from_cert(cert)
        expected_ca_uri = f"spiffe://{norm_td}/authority/x509-ca"
        if spiffe_uris != [expected_ca_uri]:
            raise MTLSError(
                f"X.509 Root CA SAN {spiffe_uris!r} does not match expected {expected_ca_uri!r}"
            )

        try:
            cert.verify_directly_issued_by(cert)
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise MTLSError(f"X.509 Root CA self-signature invalid: {exc}") from exc

        norm_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        with self._lock:
            # Ensure no non-localhost DNS subtree collides with an already-registered peer domain
            for other_td, other_dns in self._domain_dns_subtrees.items():
                if other_td == norm_td:
                    continue
                overlap = (set(dns_subtrees) & set(other_dns)) - {"localhost"}
                if overlap:
                    raise MTLSError(
                        f"Cross-domain DNS NameConstraints collision between {norm_td!r} "
                        f"and {other_td!r}: {sorted(overlap)!r}"
                    )
            changed = self._domain_pems.get(norm_td) != norm_pem
            self._domain_roots[norm_td] = cert
            self._domain_pems[norm_td] = norm_pem
            self._domain_dns_subtrees[norm_td] = tuple(dns_subtrees)
            if changed:
                self._version += 1
                self._server_verify_ctx_cache.clear()

    def export_domain_pems(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._domain_pems)

    def domain_ca_pem(self, trust_domain: str) -> str:
        """Return ONLY the single X.509 Root CA PEM for `trust_domain`."""
        norm_td = trust_domain.strip().lower()
        with self._lock:
            pem = self._domain_pems.get(norm_td)
        if not pem:
            raise MTLSError(f"Trust domain {norm_td!r} is not registered in X509FederationTrustStore")
        return pem

    def has_domain(self, trust_domain: str) -> bool:
        norm_td = trust_domain.strip().lower()
        with self._lock:
            return norm_td in self._domain_pems

    def evict_domain(self, trust_domain: str) -> None:
        """Evict a domain Root CA and bump store version to invalidate cached SSLContexts."""
        norm_td = trust_domain.strip().lower()
        with self._lock:
            removed = False
            if norm_td in self._domain_roots:
                self._domain_roots.pop(norm_td, None)
                removed = True
            if norm_td in self._domain_pems:
                self._domain_pems.pop(norm_td, None)
                removed = True
            self._domain_dns_subtrees.pop(norm_td, None)
            if removed:
                self._version += 1
                self._server_verify_ctx_cache.clear()

    def build_server_verify_ssl_context(
        self,
        expected_trust_domain: str,
        check_hostname: bool = True,
        expected_spiffe_id: Optional[str] = None,
    ) -> ssl.SSLContext:
        """Build a TLS 1.3 client `SSLContext` authenticating server cert against `expected_trust_domain`
        (without presenting a client cert — used for keyless TLS 1.3 `audit-collector` transport).
        """
        norm_td = expected_trust_domain.strip().lower()
        norm_spiffe: Optional[str] = None
        if expected_spiffe_id:
            parsed_sp = SpiffeId.parse(expected_spiffe_id)
            if parsed_sp.trust_domain != norm_td:
                raise MTLSError(
                    f"expected_spiffe_id {parsed_sp.uri!r} mismatches expected_trust_domain {norm_td!r}"
                )
            norm_spiffe = parsed_sp.uri
        if not check_hostname and not norm_spiffe:
            raise MTLSError(
                "TLS check_hostname=False is strictly forbidden without explicit expected_spiffe_id pinning"
            )
        with self._lock:
            ver = self._version
            cache_key = (norm_td, bool(check_hostname), norm_spiffe, ver)
            cached = self._server_verify_ctx_cache.get(cache_key)
            if cached is not None:
                return cached
            cadata = self.domain_ca_pem(norm_td)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = (
            ssl.TLSVersion.TLSv1_3 if getattr(ssl, "HAS_TLSv1_3", False) else ssl.TLSVersion.TLSv1_2
        )
        ctx.check_hostname = check_hostname
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cadata=cadata)
        _attach_peer_verification_hooks(
            ctx,
            self,
            required_eku=ExtendedKeyUsageOID.SERVER_AUTH,
            pinned_trust_domain=norm_td,
            pinned_spiffe_id=norm_spiffe,
            is_client=True,
        )
        with self._lock:
            if self._version == ver:
                self._server_verify_ctx_cache[cache_key] = ctx
        return ctx

    def combined_ca_pem(self) -> str:
        with self._lock:
            if not self._domain_pems:
                raise MTLSError("X509FederationTrustStore contains zero trusted Root CAs")
            return "\n".join(self._domain_pems[td] for td in sorted(self._domain_pems))

    def infer_trust_domain_from_hostname(self, hostname: Optional[str]) -> Optional[str]:
        """Infer authoritative trust domain for a non-localhost hostname (`<svc>.<ns>.svc...`)."""
        if not hostname:
            return None
        h = hostname.strip().lower().rstrip(".")
        if not h or h in ("localhost", "127.0.0.1", "::1"):
            return None
        with self._lock:
            matches = set()
            for td, subtrees in self._domain_dns_subtrees.items():
                for sub in subtrees:
                    if sub == "localhost":
                        continue
                    if _dns_matches_permitted_subtree(h, sub):
                        matches.add(td)
            if len(matches) == 1:
                return next(iter(matches))
            # Check standard K8s namespace convention `<svc>.<ns>.svc(.cluster.local)`
            parts = h.split(".")
            if len(parts) >= 3 and parts[2] == "svc":
                hinted = self._K8S_NS_DOMAIN_HINTS.get(parts[1])
                if hinted and hinted in self._domain_roots:
                    return hinted
        return None

    def verify_peer_der_cert(
        self,
        der_bytes: bytes,
        expected_trust_domain: Optional[str] = None,
        expected_spiffe_id: Optional[str] = None,
        required_eku: Optional[x509.ObjectIdentifier] = ExtendedKeyUsageOID.CLIENT_AUTH,
    ) -> Tuple[str, str]:
        """Verify peer leaf DER X.509-SVID extensions, EKU, and domain-pinned Root CA.

        Enforces `[HIGH-M3-02]` and `[MEDIUM-M3-02]`:
        - Mandatory `BasicConstraints(ca=False)`
        - Mandatory `KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False)`
        - Mandatory `ExtendedKeyUsage` containing `required_eku` (`CLIENT_AUTH` or `SERVER_AUTH`)
        - Single `spiffe://` URI SAN matching `expected_trust_domain` / `expected_spiffe_id`
        - Direct cryptographic signature from that exact `spiffe.trust_domain`'s Root CA
        """
        if not der_bytes:
            raise MTLSError("Missing peer X.509 client/server certificate")
        try:
            leaf = x509.load_der_x509_certificate(der_bytes)
        except Exception as exc:
            raise MTLSError(f"Invalid peer DER certificate: {exc}") from exc

        try:
            bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound as exc:
            raise MTLSError("Peer X.509-SVID missing mandatory BasicConstraints extension") from exc
        if bc.ca is not False:
            raise MTLSError("CA certificate cannot be used directly as a peer workload leaf")

        try:
            ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound as exc:
            raise MTLSError("Peer X.509-SVID missing mandatory KeyUsage extension") from exc
        if not ku.digital_signature or ku.key_cert_sign or ku.crl_sign:
            raise MTLSError(
                "Peer X.509-SVID KeyUsage must assert digital_signature=True and key_cert_sign=False, crl_sign=False"
            )

        try:
            eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound as exc:
            raise MTLSError("Peer X.509-SVID missing mandatory ExtendedKeyUsage extension") from exc
        if required_eku is not None and required_eku not in eku:
            raise MTLSError(
                f"Peer X.509-SVID ExtendedKeyUsage missing required {required_eku.dotted_string}"
            )

        uris = _extract_spiffe_uris_from_cert(leaf)
        if len(uris) != 1:
            raise MTLSError(
                f"Workload X.509-SVID must contain exactly one spiffe:// URI SAN, got {uris!r}"
            )
        try:
            spiffe = SpiffeId.parse(uris[0])
        except IdentityError as exc:
            raise MTLSError(f"Invalid SPIFFE URI in peer X.509-SVID: {exc}") from exc

        if expected_trust_domain is not None and spiffe.trust_domain != expected_trust_domain.strip().lower():
            raise MTLSError(
                f"Peer X.509-SVID domain {spiffe.trust_domain!r} != expected target domain {expected_trust_domain!r}"
            )
        if expected_spiffe_id is not None and spiffe.uri != expected_spiffe_id:
            raise MTLSError(
                f"Peer X.509-SVID {spiffe.uri!r} != expected workload SPIFFE ID {expected_spiffe_id!r}"
            )

        with self._lock:
            domain_root = self._domain_roots.get(spiffe.trust_domain)
            allowed_dns = self._domain_dns_subtrees.get(spiffe.trust_domain, ())
        if domain_root is None:
            raise MTLSError(
                f"Peer X.509-SVID trust domain {spiffe.trust_domain!r} is not federated"
            )

        try:
            leaf.verify_directly_issued_by(domain_root)
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise MTLSError(
                f"Cross-domain X.509 spoofing or invalid signature blocked for {spiffe.uri!r}: {exc}"
            ) from exc

        # Defense-in-depth DNS SAN subtree check against the pinned domain Root CA
        if allowed_dns:
            try:
                san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                for dns_val in san.get_values_for_type(x509.DNSName):
                    if not any(_dns_matches_permitted_subtree(dns_val, sub) for sub in allowed_dns):
                        raise MTLSError(
                            f"Peer X.509-SVID DNS SAN {dns_val!r} violates domain {spiffe.trust_domain!r} NameConstraints"
                        )
            except x509.ExtensionNotFound:
                pass

        now = dt.datetime.now(dt.timezone.utc)
        if now < leaf.not_valid_before_utc - dt.timedelta(seconds=10):
            raise MTLSError("Peer X.509-SVID is not yet valid")
        if now > leaf.not_valid_after_utc + dt.timedelta(seconds=10):
            raise MTLSError("Peer X.509-SVID has expired")

        pub_jwk = public_key_to_jwk(leaf.public_key())
        jkt = compute_jwk_thumbprint(pub_jwk)
        return spiffe.uri, jkt


def _load_keypair_into_ssl_context(
    ctx: ssl.SSLContext, leaf_cert_pem: str, keypair: KeyPair
) -> None:
    """Load `(leaf_cert_pem, keypair)` via in-memory tmpfs (`emptyDir: Memory` or `/dev/shm`) with `0600` mode and immediate unlink."""
    env_ram = os.environ.get("LCT_MTLS_RAM_DIR", "").strip()
    if env_ram and os.path.isdir(env_ram) and os.access(env_ram, os.W_OK):
        ram_base: Optional[str] = env_ram
    elif os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK):
        ram_base = "/dev/shm"
    else:
        ram_base = None
    tmpdir = tempfile.mkdtemp(prefix="lct-mtls-", dir=ram_base)
    os.chmod(tmpdir, 0o700)
    cert_path = os.path.join(tmpdir, "svid.pem")
    key_path = os.path.join(tmpdir, "key.pem")
    try:
        fd_c = os.open(cert_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd_c, "w", encoding="ascii") as fc:
            fc.write(leaf_cert_pem)
        key_bytes = keypair._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        fd_k = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd_k, "wb") as fk:
            fk.write(key_bytes)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _attach_peer_verification_hooks(
    ctx: ssl.SSLContext,
    trust_store: X509FederationTrustStore,
    required_eku: x509.ObjectIdentifier,
    pinned_trust_domain: Optional[str] = None,
    pinned_spiffe_id: Optional[str] = None,
    is_client: bool = True,
) -> None:
    """Attach `do_handshake()` post-check enforcing domain pinning & EKU BEFORE any HTTP data flows."""
    base_sock_cls = ctx.sslsocket_class
    base_obj_cls = ctx.sslobject_class

    def _check_der(der: Optional[bytes], server_hostname: Optional[str]) -> None:
        if not der:
            raise ssl.SSLCertVerificationError("Peer did not present an X.509-SVID certificate")
        eff_td = pinned_trust_domain
        if eff_td is None and is_client:
            eff_td = trust_store.infer_trust_domain_from_hostname(server_hostname)
        try:
            trust_store.verify_peer_der_cert(
                der,
                expected_trust_domain=eff_td,
                expected_spiffe_id=pinned_spiffe_id,
                required_eku=required_eku,
            )
        except MTLSError as exc:
            raise ssl.SSLCertVerificationError(str(exc)) from exc

    class _VerifiedSSLSocket(base_sock_cls):  # type: ignore[valid-type,misc]
        def do_handshake(self, *args: object, **kwargs: object) -> object:
            res = super().do_handshake(*args, **kwargs)
            if is_client or ctx.verify_mode == ssl.CERT_REQUIRED:
                try:
                    _check_der(
                        self.getpeercert(binary_form=True),
                        getattr(self, "server_hostname", None),
                    )
                except Exception:
                    try:
                        self.close()
                    except Exception:
                        pass
                    raise
            return res

    class _VerifiedSSLObject(base_obj_cls):  # type: ignore[valid-type,misc]
        def do_handshake(self, *args: object, **kwargs: object) -> object:
            res = super().do_handshake(*args, **kwargs)
            if is_client or ctx.verify_mode == ssl.CERT_REQUIRED:
                _check_der(
                    self.getpeercert(binary_form=True),
                    getattr(self, "server_hostname", None),
                )
            return res

    ctx.sslsocket_class = _VerifiedSSLSocket
    ctx.sslobject_class = _VerifiedSSLObject

    if is_client:
        orig_wrap_socket = ctx.wrap_socket
        orig_wrap_bio = ctx.wrap_bio

        def _wrap_socket_no_ip_sni(sock: object, *args: object, **kwargs: object) -> object:
            sh = kwargs.get("server_hostname")
            if isinstance(sh, str) and _is_ip_literal(sh) and not ctx.check_hostname:
                kwargs = dict(kwargs)
                kwargs["server_hostname"] = None
            return orig_wrap_socket(sock, *args, **kwargs)  # type: ignore[arg-type]

        def _wrap_bio_no_ip_sni(
            incoming: object,
            outgoing: object,
            server_side: bool = False,
            server_hostname: Optional[str] = None,
            *args: object,
            **kwargs: object,
        ) -> object:
            eff_sh = server_hostname
            if isinstance(eff_sh, str) and _is_ip_literal(eff_sh) and not ctx.check_hostname:
                eff_sh = None
            return orig_wrap_bio(
                incoming,  # type: ignore[arg-type]
                outgoing,  # type: ignore[arg-type]
                server_side=server_side,
                server_hostname=eff_sh,
                *args,
                **kwargs,
            )

        ctx.wrap_socket = _wrap_socket_no_ip_sni  # type: ignore[method-assign]
        ctx.wrap_bio = _wrap_bio_no_ip_sni  # type: ignore[method-assign]


@dataclass
class WorkloadMTLSBundle:
    """In-memory X.509-SVID + Federated Trust Store bundle for Sidecar & Gateway mTLS 1.3.

    Supports zero-restart hot-reload on both:
    1. Peer trust-store Root CA updates (`trust_store.version` bumps); and
    2. Local X.509-SVID automatic renewal (`update_svid(...)` bumps `_bundle_generation`).
    """

    spiffe_id: str
    keypair: KeyPair
    leaf_cert_pem: str
    trust_store: X509FederationTrustStore
    _client_ctx_cache: Dict[Tuple[bool, Optional[str], Optional[str]], ssl.SSLContext] = field(
        default_factory=dict, init=False, repr=False
    )
    _server_ctx_cache: Dict[bool, ssl.SSLContext] = field(
        default_factory=dict, init=False, repr=False
    )
    _bundle_generation: int = field(default=0, init=False, repr=False)
    _cached_store_version: int = field(default=-1, init=False, repr=False)
    _cached_bundle_generation: int = field(default=-1, init=False, repr=False)
    _cache_lock: threading.RLock = field(
        default_factory=threading.RLock, init=False, repr=False
    )

    @property
    def generation(self) -> int:
        with self._cache_lock:
            return self._bundle_generation

    def _sync_cache_epoch_locked(self) -> Tuple[int, int, KeyPair, str]:
        store_ver = self.trust_store.version
        if (
            store_ver != self._cached_store_version
            or self._bundle_generation != self._cached_bundle_generation
        ):
            self._client_ctx_cache.clear()
            self._server_ctx_cache.clear()
            self._cached_store_version = store_ver
            self._cached_bundle_generation = self._bundle_generation
        return store_ver, self._bundle_generation, self.keypair, self.leaf_cert_pem

    def update_svid(self, leaf_cert_pem: str, keypair: Optional[KeyPair] = None) -> int:
        """Atomically swap renewed leaf X.509-SVID PEM (and optional rotated keypair)."""
        with self._cache_lock:
            if keypair is not None:
                self.keypair = keypair
            self.leaf_cert_pem = str(leaf_cert_pem)
            self._bundle_generation += 1
            self._client_ctx_cache.clear()
            self._server_ctx_cache.clear()
            return self._bundle_generation

    def server_ssl_context_provider(
        self, require_client_cert: bool = True
    ) -> Callable[[], ssl.SSLContext]:
        return lambda: self.build_server_ssl_context(require_client_cert=require_client_cert)

    def build_server_ssl_context(self, require_client_cert: bool = True) -> ssl.SSLContext:
        req_flag = bool(require_client_cert)
        with self._cache_lock:
            store_ver, gen, kp, leaf_pem = self._sync_cache_epoch_locked()
            cached = self._server_ctx_cache.get(req_flag)
            if cached is not None:
                return cached

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = (
            ssl.TLSVersion.TLSv1_3 if getattr(ssl, "HAS_TLSv1_3", False) else ssl.TLSVersion.TLSv1_2
        )
        ctx.verify_mode = ssl.CERT_REQUIRED if req_flag else ssl.CERT_NONE
        if req_flag:
            ctx.load_verify_locations(cadata=self.trust_store.combined_ca_pem())
        _load_keypair_into_ssl_context(ctx, leaf_pem, kp)
        if req_flag:
            _attach_peer_verification_hooks(
                ctx,
                self.trust_store,
                required_eku=ExtendedKeyUsageOID.CLIENT_AUTH,
                is_client=False,
            )
        with self._cache_lock:
            if (
                self.trust_store.version == store_ver
                and self._bundle_generation == gen
            ):
                self._server_ctx_cache[req_flag] = ctx
        return ctx

    def build_client_ssl_context(
        self,
        check_hostname: bool = True,
        expected_trust_domain: Optional[str] = None,
        expected_spiffe_id: Optional[str] = None,
    ) -> ssl.SSLContext:
        norm_spiffe: Optional[str] = None
        if expected_spiffe_id:
            parsed_sp = SpiffeId.parse(expected_spiffe_id)
            norm_spiffe = parsed_sp.uri
            if expected_trust_domain is None:
                expected_trust_domain = parsed_sp.trust_domain
        if not check_hostname and not norm_spiffe:
            raise MTLSError(
                "TLS check_hostname=False is strictly forbidden without explicit expected_spiffe_id pinning"
            )
        norm_td = expected_trust_domain.strip().lower() if expected_trust_domain else None

        cache_key = (bool(check_hostname), norm_td, norm_spiffe)
        with self._cache_lock:
            store_ver, gen, kp, leaf_pem = self._sync_cache_epoch_locked()
            cached = self._client_ctx_cache.get(cache_key)
            if cached is not None:
                return cached

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = (
            ssl.TLSVersion.TLSv1_3 if getattr(ssl, "HAS_TLSv1_3", False) else ssl.TLSVersion.TLSv1_2
        )
        ctx.check_hostname = check_hostname
        ctx.verify_mode = ssl.CERT_REQUIRED
        cadata = (
            self.trust_store.domain_ca_pem(norm_td)
            if norm_td is not None
            else self.trust_store.combined_ca_pem()
        )
        ctx.load_verify_locations(cadata=cadata)
        _load_keypair_into_ssl_context(ctx, leaf_pem, kp)
        _attach_peer_verification_hooks(
            ctx,
            self.trust_store,
            required_eku=ExtendedKeyUsageOID.SERVER_AUTH,
            pinned_trust_domain=norm_td,
            pinned_spiffe_id=norm_spiffe,
            is_client=True,
        )
        with self._cache_lock:
            if (
                self.trust_store.version == store_ver
                and self._bundle_generation == gen
            ):
                self._client_ctx_cache[cache_key] = ctx
        return ctx

    def verify_for_target(
        self,
        target_url: Optional[str] = None,
        expected_trust_domain: Optional[str] = None,
        expected_spiffe_id: Optional[str] = None,
        check_hostname: bool = True,
    ) -> ssl.SSLContext:
        """Return a per-domain-pinned client `SSLContext` for `target_url` / `expected_spiffe_id`."""
        eff_td = expected_trust_domain
        if eff_td is None and expected_spiffe_id:
            eff_td = SpiffeId.parse(expected_spiffe_id).trust_domain
        target_host = urlsplit(target_url).hostname if target_url else None
        if eff_td is None and target_host:
            eff_td = self.trust_store.infer_trust_domain_from_hostname(target_host)
        eff_check_hostname = bool(check_hostname)
        if target_host and _is_ip_literal(target_host):
            if expected_spiffe_id:
                # Identity-addressed IP locator: disable DNS hostname check, strip IP SNI, and pin strictly to expected_spiffe_id
                eff_check_hostname = False
            else:
                try:
                    is_lo = ipaddress.ip_address(target_host).is_loopback
                except ValueError:
                    is_lo = False
                if not is_lo:
                    raise MTLSError(
                        f"Cross-machine IP-literal TLS target {target_url!r} requires explicit expected_spiffe_id pinning"
                    )
        return self.build_client_ssl_context(
            check_hostname=eff_check_hostname,
            expected_trust_domain=eff_td,
            expected_spiffe_id=expected_spiffe_id,
        )

    def cleanup(self) -> None:
        """Deterministically release cached SSLContext closure references on shutdown."""
        with self._cache_lock:
            self._client_ctx_cache.clear()
            self._server_ctx_cache.clear()
