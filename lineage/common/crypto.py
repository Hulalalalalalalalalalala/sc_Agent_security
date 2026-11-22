"""Real cryptographic primitives for Lineage Capability Tree (LCT).

Implements:
- Base64url encoding/decoding without padding (RFC 7515 Appendix C)
- Deterministic Canonical JSON serialization (RFC 8785 compatible subset)
- SHA-256 hashing and hex/base64url commitments
- Asymmetric key generation and JWK export/import for ES256 (ECDSA P-256) and RS256 (RSA-2048+)
- RFC 7638 JSON Web Key (JWK) Thumbprint (`jkt`) computation
- RFC 7515 JSON Web Signature (JWS) compact signing and verification (including proper
  ASN.1 DER <-> fixed 64-byte R||S conversion for ES256)
- Sensitive field redaction to prevent private keys or raw tokens from leaking into logs
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

PublicKeyTypes = Union[ec.EllipticCurvePublicKey, rsa.RSAPublicKey]
PrivateKeyTypes = Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]

SUPPORTED_ALGS = frozenset({"ES256", "RS256"})
_P256_COORD_SIZE = 32

SENSITIVE_KEYS = frozenset(
    {
        "d",
        "p",
        "q",
        "dp",
        "dq",
        "qi",
        "private_key",
        "private_pem",
        "secret",
        "client_secret",
        "password",
        "authorization",
        "raw_token",
        "compact_lineage_token",
    }
)


class CryptoError(Exception):
    """Raised on cryptographic verification, key parsing, or formatting failure."""


def b64url_encode(data: bytes) -> str:
    """Encode bytes using URL-safe Base64 without '=' padding (RFC 7515)."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("b64url_encode requires bytes-like input")
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode URL-safe Base64 string without padding, rejecting malformed input."""
    if not isinstance(text, str) or not text:
        raise CryptoError("Invalid empty or non-string base64url input")
    rem = len(text) % 4
    if rem == 1:
        raise CryptoError("Invalid base64url length")
    padded = text + ("=" * ((4 - rem) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise CryptoError(f"Base64url decode failed: {exc}") from exc
    # Enforce canonical base64url encoding (prevents malleable trailing-bit tricks!)
    if b64url_encode(decoded) != text.rstrip("="):
        raise CryptoError("Non-canonical base64url encoding rejected")
    return decoded


def _int_to_b64url_uint(value: int, fixed_length: Optional[int] = None) -> str:
    if value < 0:
        raise CryptoError("Negative integer cannot be encoded as JWK UInt")
    if fixed_length is not None:
        raw = value.to_bytes(fixed_length, byteorder="big")
    else:
        byte_len = max(1, (value.bit_length() + 7) // 8)
        raw = value.to_bytes(byte_len, byteorder="big")
    return b64url_encode(raw)


def _b64url_uint_to_int(text: str, expected_length: Optional[int] = None) -> int:
    raw = b64url_decode(text)
    if expected_length is not None and len(raw) != expected_length:
        raise CryptoError(
            f"Expected {expected_length}-byte coordinate, got {len(raw)} bytes"
        )
    if expected_length is None and len(raw) > 1 and raw[0] == 0:
        raise CryptoError("Non-minimal RSA JWK integer with leading zero byte")
    return int.from_bytes(raw, byteorder="big")


def _reject_nonfinite_json_constant(constant: str) -> Any:
    raise CryptoError(f"Non-finite JSON constant {constant!r} is strictly forbidden")


def strict_json_loads(raw: Union[str, bytes, bytearray]) -> Any:
    """Parse JSON while strictly rejecting IEEE-754 NaN, Infinity, and -Infinity."""
    try:
        text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
        return json.loads(text, parse_constant=_reject_nonfinite_json_constant)
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError(f"Invalid JSON input: {exc}") from exc


def require_finite_timestamp(value: Any, field_name: str = "timestamp") -> float:
    """Validate that a timestamp is a finite real number (rejecting bool, str, NaN, Inf)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CryptoError(
            f"Field {field_name!r} must be a finite int/float, got {type(value).__name__}"
        )
    fval = float(value)
    if not math.isfinite(fval):
        raise CryptoError(f"Field {field_name!r} must be finite, got {value!r}")
    return fval


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize Python data structure into deterministic canonical UTF-8 JSON bytes."""
    try:
        rendered = json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CryptoError(f"Failed canonical JSON serialization: {exc}") from exc
    return rendered.encode("utf-8")


def canonical_json_str(obj: Any) -> str:
    """Serialize Python data structure into deterministic canonical JSON string."""
    return canonical_json_bytes(obj).decode("utf-8")


def sha256_bytes(data: bytes) -> bytes:
    """Compute raw 32-byte SHA-256 digest using cryptography's OpenSSL backend."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def sha256_b64url(data: bytes) -> str:
    """Compute base64url-encoded SHA-256 digest without padding."""
    return b64url_encode(sha256_bytes(data))


def sha256_hex(data: bytes) -> str:
    """Compute hex-encoded SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def sha256_canonical_b64url(obj: Any) -> str:
    """Compute base64url-encoded SHA-256 commitment over canonical JSON representation."""
    return sha256_b64url(canonical_json_bytes(obj))


def public_key_to_jwk(
    pub_key: PublicKeyTypes, kid: Optional[str] = None
) -> Dict[str, Any]:
    """Export an EC P-256 or RSA public key to a public RFC 7517 JWK dictionary."""
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        if not isinstance(pub_key.curve, ec.SECP256R1):
            raise CryptoError(f"Unsupported EC curve: {pub_key.curve.name}")
        nums = pub_key.public_numbers()
        jwk: Dict[str, Any] = {
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "x": _int_to_b64url_uint(nums.x, fixed_length=_P256_COORD_SIZE),
            "y": _int_to_b64url_uint(nums.y, fixed_length=_P256_COORD_SIZE),
        }
    elif isinstance(pub_key, rsa.RSAPublicKey):
        if pub_key.key_size < 2048:
            raise CryptoError("RSA key size must be at least 2048 bits")
        nums = pub_key.public_numbers()
        jwk = {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": _int_to_b64url_uint(nums.n),
            "e": _int_to_b64url_uint(nums.e),
        }
    else:
        raise CryptoError(f"Unsupported public key type: {type(pub_key).__name__}")

    if kid is not None:
        jwk["kid"] = kid
    return jwk


def jwk_to_public_key(jwk: Mapping[str, Any]) -> Tuple[PublicKeyTypes, str]:
    """Parse and validate a public JWK into (PublicKey, algorithm).

    Explicitly rejects any JWK containing private key parameters ('d', 'p', 'q', etc.)
    when used in a public verification context.
    """
    if not isinstance(jwk, Mapping):
        raise CryptoError("JWK must be a mapping")
    for forbidden in ("d", "p", "q", "dp", "dq", "qi"):
        if forbidden in jwk:
            raise CryptoError(
                f"Private JWK parameter '{forbidden}' must never appear in public JWK"
            )

    kty = jwk.get("kty")
    if kty == "EC":
        if jwk.get("crv") != "P-256":
            raise CryptoError(f"Unsupported EC crv: {jwk.get('crv')}")
        alg = jwk.get("alg", "ES256")
        if alg != "ES256":
            raise CryptoError(f"Mismatched EC alg: {alg}")
        if "x" not in jwk or "y" not in jwk:
            raise CryptoError("EC JWK missing x or y coordinate")
        x = _b64url_uint_to_int(str(jwk["x"]), expected_length=_P256_COORD_SIZE)
        y = _b64url_uint_to_int(str(jwk["y"]), expected_length=_P256_COORD_SIZE)
        try:
            pub_nums = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
            return pub_nums.public_key(), "ES256"
        except ValueError as exc:
            raise CryptoError(f"Invalid EC P-256 public point: {exc}") from exc

    if kty == "RSA":
        alg = jwk.get("alg", "RS256")
        if alg != "RS256":
            raise CryptoError(f"Mismatched RSA alg: {alg}")
        if "n" not in jwk or "e" not in jwk:
            raise CryptoError("RSA JWK missing n or e")
        n = _b64url_uint_to_int(str(jwk["n"]))
        e = _b64url_uint_to_int(str(jwk["e"]))
        if e < 3 or e % 2 == 0:
            raise CryptoError("Invalid RSA public exponent")
        try:
            pub_nums = rsa.RSAPublicNumbers(e, n)
            pub_key = pub_nums.public_key()
        except ValueError as exc:
            raise CryptoError(f"Invalid RSA public numbers: {exc}") from exc
        if pub_key.key_size < 2048:
            raise CryptoError("RSA key size below minimum 2048 bits")
        return pub_key, "RS256"

    raise CryptoError(f"Unsupported JWK kty: {kty}")


def compute_jwk_thumbprint(jwk_or_key: Union[Mapping[str, Any], PublicKeyTypes]) -> str:
    """Compute RFC 7638 JWK SHA-256 Thumbprint (`jkt`).

    Uses exact lexicographically ordered required members:
    - EC:  {"crv":..., "kty":"EC", "x":..., "y":...}
    - RSA: {"e":..., "kty":"RSA", "n":...}
    """
    if isinstance(jwk_or_key, (ec.EllipticCurvePublicKey, rsa.RSAPublicKey)):
        jwk = public_key_to_jwk(jwk_or_key)
    else:
        # Validate public key structure & point validity first
        pub_key, _ = jwk_to_public_key(jwk_or_key)
        jwk = public_key_to_jwk(pub_key)

    kty = jwk["kty"]
    if kty == "EC":
        canonical_members = {
            "crv": jwk["crv"],
            "kty": "EC",
            "x": jwk["x"],
            "y": jwk["y"],
        }
    elif kty == "RSA":
        canonical_members = {
            "e": jwk["e"],
            "kty": "RSA",
            "n": jwk["n"],
        }
    else:
        raise CryptoError(f"Unsupported kty for thumbprint: {kty}")

    return sha256_b64url(canonical_json_bytes(canonical_members))


@dataclass(frozen=True)
class KeyPair:
    """In-memory asymmetric keypair wrapper preventing accidental secret serialization."""

    alg: str
    kid: str
    _private_key: PrivateKeyTypes

    def __repr__(self) -> str:
        return f"KeyPair(alg={self.alg!r}, kid={self.kid!r}, jkt={self.jkt!r})"

    __str__ = __repr__

    @classmethod
    def generate(cls, alg: str = "ES256", kid: Optional[str] = None) -> "KeyPair":
        """Generate a fresh cryptographic keypair ('ES256' or 'RS256')."""
        if alg == "ES256":
            priv: PrivateKeyTypes = ec.generate_private_key(ec.SECP256R1())
        elif alg == "RS256":
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            raise CryptoError(f"Unsupported key generation algorithm: {alg}")

        jkt = compute_jwk_thumbprint(priv.public_key())
        resolved_kid = kid if kid else f"{alg.lower()}-{jkt[:16]}"
        return cls(alg=alg, kid=resolved_kid, _private_key=priv)

    @property
    def public_key(self) -> PublicKeyTypes:
        return self._private_key.public_key()

    @property
    def jkt(self) -> str:
        return compute_jwk_thumbprint(self._private_key.public_key())

    def public_jwk(self, include_kid: bool = True) -> Dict[str, Any]:
        return public_key_to_jwk(
            self._private_key.public_key(), kid=self.kid if include_kid else None
        )

    def public_pem(self) -> str:
        return (
            self._private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )

    def sign_bytes(self, signing_input: bytes) -> bytes:
        """Sign raw bytes using RFC 7515 JWS signature encoding."""
        if self.alg == "ES256" and isinstance(
            self._private_key, ec.EllipticCurvePrivateKey
        ):
            der_sig = self._private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(der_sig)
            return r.to_bytes(_P256_COORD_SIZE, "big") + s.to_bytes(
                _P256_COORD_SIZE, "big"
            )
        if self.alg == "RS256" and isinstance(self._private_key, rsa.RSAPrivateKey):
            return self._private_key.sign(
                signing_input, padding.PKCS1v15(), hashes.SHA256()
            )
        raise CryptoError(f"Key/algorithm mismatch in KeyPair: {self.alg}")


def verify_bytes_signature(
    pub_key: PublicKeyTypes, alg: str, signing_input: bytes, signature: bytes
) -> None:
    """Verify raw RFC 7515 JWS signature bytes, raising CryptoError on failure."""
    if alg not in SUPPORTED_ALGS:
        raise CryptoError(f"Unsupported verification algorithm: {alg}")

    try:
        if alg == "ES256":
            if not isinstance(pub_key, ec.EllipticCurvePublicKey):
                raise CryptoError("Algorithm ES256 requires EC public key")
            if len(signature) != 2 * _P256_COORD_SIZE:
                raise CryptoError(
                    f"ES256 signature must be 64 bytes, got {len(signature)}"
                )
            r = int.from_bytes(signature[:_P256_COORD_SIZE], "big")
            s = int.from_bytes(signature[_P256_COORD_SIZE:], "big")
            if r == 0 or s == 0:
                raise CryptoError("Invalid zero ECDSA signature component")
            der_sig = encode_dss_signature(r, s)
            pub_key.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
            return

        if alg == "RS256":
            if not isinstance(pub_key, rsa.RSAPublicKey):
                raise CryptoError("Algorithm RS256 requires RSA public key")
            pub_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            return
    except InvalidSignature as exc:
        raise CryptoError("Cryptographic signature verification failed") from exc


def jws_sign_compact(
    payload: Mapping[str, Any],
    keypair: KeyPair,
    typ: str = "JWT",
    extra_headers: Optional[Mapping[str, Any]] = None,
) -> str:
    """Create a standard 3-part RFC 7515 Compact JWS string (`header.payload.signature`)."""
    header: Dict[str, Any] = {
        "alg": keypair.alg,
        "typ": typ,
        "kid": keypair.kid,
    }
    if extra_headers:
        for k, v in extra_headers.items():
            if k == "alg" and v != keypair.alg:
                raise CryptoError("Cannot override JWS alg header")
            header[k] = v

    header_b64 = b64url_encode(canonical_json_bytes(header))
    payload_b64 = b64url_encode(canonical_json_bytes(payload))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig_b64 = b64url_encode(keypair.sign_bytes(signing_input))
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def jws_parse_unverified(compact_jws: str) -> Tuple[Dict[str, Any], Dict[str, Any], bytes, bytes]:
    """Parse a 3-part Compact JWS into (header, payload, signing_input, raw_signature).

    NOTE: Does NOT verify signature; callers MUST pass to jws_verify_compact or verify_bytes_signature.
    """
    if not isinstance(compact_jws, str):
        raise CryptoError("Compact JWS must be a string")
    parts = compact_jws.split(".")
    if len(parts) != 3 or not all(parts):
        raise CryptoError("Compact JWS must have exactly 3 non-empty dot-separated parts")

    header_b64, payload_b64, sig_b64 = parts
    try:
        header = strict_json_loads(b64url_decode(header_b64))
        payload = strict_json_loads(b64url_decode(payload_b64))
    except Exception as exc:
        raise CryptoError(f"Malformed JWS JSON header or payload: {exc}") from exc

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise CryptoError("JWS header and payload must be JSON objects")

    alg = header.get("alg")
    if alg not in SUPPORTED_ALGS:
        raise CryptoError(f"Unsupported or dangerous JWS alg: {alg!r}")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig_bytes = b64url_decode(sig_b64)
    return header, payload, signing_input, sig_bytes


def jws_verify_compact(
    compact_jws: str,
    public_key_or_jwk: Union[PublicKeyTypes, Mapping[str, Any]],
    expected_typ: Optional[str] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Cryptographically verify a 3-part Compact JWS and return (header, payload)."""
    header, payload, signing_input, sig_bytes = jws_parse_unverified(compact_jws)
    alg = str(header["alg"])

    if expected_typ is not None and header.get("typ") != expected_typ:
        raise CryptoError(
            f"Unexpected JWS typ: expected {expected_typ!r}, got {header.get('typ')!r}"
        )

    if isinstance(public_key_or_jwk, (ec.EllipticCurvePublicKey, rsa.RSAPublicKey)):
        pub_key = public_key_or_jwk
        key_alg = "ES256" if isinstance(pub_key, ec.EllipticCurvePublicKey) else "RS256"
    else:
        pub_key, key_alg = jwk_to_public_key(public_key_or_jwk)

    if alg != key_alg:
        raise CryptoError(
            f"Algorithm confusion blocked: header alg {alg!r} != key alg {key_alg!r}"
        )

    verify_bytes_signature(pub_key, alg, signing_input, sig_bytes)
    return header, payload


def sign_canonical_object(obj: Mapping[str, Any], keypair: KeyPair, domain_tag: str) -> str:
    """Sign a canonical JSON dictionary with an explicit cryptographic domain separation tag."""
    envelope = {
        "_domain": domain_tag,
        "body": obj,
    }
    sig_bytes = keypair.sign_bytes(canonical_json_bytes(envelope))
    return b64url_encode(sig_bytes)


def verify_canonical_object(
    obj: Mapping[str, Any],
    signature_b64: str,
    public_key_or_jwk: Union[PublicKeyTypes, Mapping[str, Any]],
    domain_tag: str,
) -> None:
    """Verify a domain-separated signature over a canonical JSON dictionary."""
    if isinstance(public_key_or_jwk, (ec.EllipticCurvePublicKey, rsa.RSAPublicKey)):
        pub_key = public_key_or_jwk
        alg = "ES256" if isinstance(pub_key, ec.EllipticCurvePublicKey) else "RS256"
    else:
        pub_key, alg = jwk_to_public_key(public_key_or_jwk)

    envelope = {
        "_domain": domain_tag,
        "body": obj,
    }
    sig_bytes = b64url_decode(signature_b64)
    verify_bytes_signature(pub_key, alg, canonical_json_bytes(envelope), sig_bytes)


def redact_sensitive(value: Any) -> Any:
    """Recursively redact sensitive keys or raw compact JWT/JWS tokens before logging."""
    if isinstance(value, Mapping):
        cleaned: Dict[str, Any] = {}
        for k, v in value.items():
            key_lower = str(k).lower()
            if key_lower in SENSITIVE_KEYS or key_lower.endswith("_secret") or key_lower.endswith("_private_key"):
                cleaned[str(k)] = "[REDACTED]"
            else:
                cleaned[str(k)] = redact_sensitive(v)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, str):
        # Redact compact LCT single-chain (`lct1.`) and multi-parent (`lctm1.`/`lctmp1.`) bearer/DPoP tokens
        if value.startswith(("lct1.", "lctm1.", "lctmp1.")):
            return f"[REDACTED_LCT_TOKEN_SHA256:{sha256_hex(value.encode('utf-8'))[:12]}]"
        # Redact raw 3-part JWS/JWT strings if accidentally placed in log metadata
        if value.startswith("eyJ") and value.count(".") == 2 and len(value) > 40:
            return f"[REDACTED_JWS_SHA256:{sha256_hex(value.encode('utf-8'))[:12]}]"
    return value
