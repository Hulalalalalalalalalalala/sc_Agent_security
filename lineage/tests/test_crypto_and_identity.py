"""Unit & Adversarial Tests for Cryptography, Multi-Domain SPIFFE Identity, and Agent Registry."""

from __future__ import annotations

import json
import unittest

from jwcrypto import jwk as jwcrypto_jwk
from jwcrypto import jws as jwcrypto_jws

from lineage.common.crypto import (
    CryptoError,
    KeyPair,
    b64url_decode,
    b64url_encode,
    compute_jwk_thumbprint,
    jwk_to_public_key,
    jws_sign_compact,
    jws_verify_compact,
    redact_sensitive,
)
from lineage.identity import (
    IdentityError,
    SpiffeId,
    TrustBundleResolver,
    TrustDomainCA,
)
from lineage.registry import (
    AgentCard,
    AgentCardError,
    AgentDirectoryClient,
    AgentDirectoryService,
)


class TestCryptoAndIdentity(unittest.TestCase):
    def test_es256_and_rs256_rfc7515_and_rfc7638_interop_with_jwcrypto(self) -> None:
        """Verify our ES256/RS256 JWS and RFC 7638 thumbprints match independent `jwcrypto`."""
        for alg in ("ES256", "RS256"):
            kp = KeyPair.generate(alg=alg)
            pub_dict = kp.public_jwk()

            # Cross-check RFC 7638 JWK thumbprint against independent jwcrypto library
            ext_key = jwcrypto_jwk.JWK(**pub_dict)
            self.assertEqual(kp.jkt, ext_key.thumbprint())

            # Sign with our implementation, verify with jwcrypto
            claims = {"hello": "world", "num": 42}
            compact = jws_sign_compact(claims, kp, typ="JWT")
            verifier = jwcrypto_jws.JWS()
            verifier.deserialize(compact)
            verifier.verify(ext_key, alg=alg)
            self.assertEqual(json.loads(verifier.payload.decode("utf-8")), claims)

            # Verify with our implementation
            hdr, verified_claims = jws_verify_compact(compact, pub_dict, expected_typ="JWT")
            self.assertEqual(hdr["alg"], alg)
            self.assertEqual(verified_claims, claims)

    def test_signature_bitflip_and_noncanonical_base64_rejected(self) -> None:
        kp = KeyPair.generate("ES256")
        tok = jws_sign_compact({"role": "worker"}, kp)
        h, p, s = tok.split(".")

        # Flip middle character of signature
        mid = len(s) // 2
        replacement = "A" if s[mid] != "A" else "B"
        tampered_mid = f"{h}.{p}.{s[:mid]}{replacement}{s[mid + 1:]}"
        with self.assertRaises(CryptoError):
            jws_verify_compact(tampered_mid, kp.public_jwk())

        # Flip last character of signature (including padding-bit malleability check!)
        last_rep = "A" if s[-1] != "A" else "B"
        tampered_last = f"{h}.{p}.{s[:-1]}{last_rep}"
        with self.assertRaises(CryptoError):
            jws_verify_compact(tampered_last, kp.public_jwk())

    def test_algorithm_confusion_and_private_jwk_leak_blocked(self) -> None:
        ec_kp = KeyPair.generate("ES256")
        rsa_kp = KeyPair.generate("RS256")
        ec_tok = jws_sign_compact({"x": 1}, ec_kp)

        # Verify ES256 JWS against RS256 public key -> must fail
        with self.assertRaises(CryptoError):
            jws_verify_compact(ec_tok, rsa_kp.public_jwk())

        # Craft alg="none" JWS -> must fail
        none_hdr = b64url_encode(b'{"alg":"none","typ":"JWT"}')
        none_pay = b64url_encode(b'{"admin":true}')
        with self.assertRaises(CryptoError):
            jws_verify_compact(f"{none_hdr}.{none_pay}.aa", ec_kp.public_jwk())

        # Smuggle private parameter 'd' into public JWK -> must fail
        bad_jwk = ec_kp.public_jwk()
        bad_jwk["d"] = b64url_encode(b"\x01" * 32)
        with self.assertRaises(CryptoError):
            jwk_to_public_key(bad_jwk)

    def test_secret_redaction_never_exposes_keys_or_jws(self) -> None:
        kp = KeyPair.generate("ES256")
        raw_jws = jws_sign_compact({"sub": "alice"}, kp)
        dirty = {
            "user": "alice",
            "private_key": "SUPER_SECRET_PEM",
            "nested": {"d": "secret_scalar", "token": raw_jws},
        }
        cleaned = redact_sensitive(dirty)
        self.assertEqual(cleaned["private_key"], "[REDACTED]")
        self.assertEqual(cleaned["nested"]["d"], "[REDACTED]")
        self.assertTrue(cleaned["nested"]["token"].startswith("[REDACTED_JWS_SHA256:"))
        self.assertNotIn("eyJ", json.dumps(cleaned))
        self.assertNotIn("SUPER_SECRET", repr(kp))

    def test_multi_domain_spiffe_isolation_and_key_rotation(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io", alg="ES256")
        ca_beta = TrustDomainCA("org-beta.io", alg="RS256")
        ca_payment = TrustDomainCA("org-payment.io", alg="ES256")

        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)
        resolver.register_domain_ca(ca_payment)

        wl_alpha = ca_alpha.issue_workload("/ns/coord/sa/planner")
        wl_beta = ca_beta.issue_workload("/ns/analytics/sa/solver", workload_alg="ES256")

        # Valid verification across domains
        c1 = resolver.verify_workload_svid(
            wl_alpha.workload_svid,
            expected_spiffe_id="spiffe://org-alpha.io/ns/coord/sa/planner",
            expected_jkt=wl_alpha.jkt,
        )
        self.assertEqual(c1["trust_domain"], "org-alpha.io")

        c2 = resolver.verify_workload_svid(
            wl_beta.workload_svid,
            expected_spiffe_id="spiffe://org-beta.io/ns/analytics/sa/solver",
            expected_jkt=wl_beta.jkt,
        )
        self.assertEqual(c2["trust_domain"], "org-beta.io")

        # Adversarial: Cross-Domain CA Impersonation!
        # Compromised org-beta CA tries to mint an SVID claiming to be org-payment.io!
        forged_claims = {
            "iss": "spiffe://org-payment.io/authority/ca",
            "sub": "spiffe://org-payment.io/ns/vault/sa/ledger",
            "trust_domain": "org-payment.io",
            "iat": wl_beta.issued_at,
            "exp": wl_beta.expires_at,
            "jti": "forged-1",
            "cnf": {"jkt": wl_beta.jkt, "jwk": wl_beta.public_jwk()},
        }
        forged_svid = jws_sign_compact(
            forged_claims, ca_beta.active_keypair, typ="spiffe-svid+jwt"
        )
        with self.assertRaises(IdentityError):
            resolver.verify_workload_svid(forged_svid)

        # Key rotation preserves existing SVID verification while issuing under v2
        new_bundle = ca_alpha.rotate_key()
        resolver.register_bundle(new_bundle)
        wl_alpha_v2 = ca_alpha.issue_workload("/ns/coord/sa/planner-v2")
        resolver.verify_workload_svid(wl_alpha.workload_svid)
        resolver.verify_workload_svid(wl_alpha_v2.workload_svid)

        # Bundle version rollback rejected
        stale_bundle = dict(new_bundle, version=1)
        with self.assertRaises(IdentityError):
            resolver.register_bundle(stale_bundle)

        # Invalid SPIFFE IDs rejected
        for bad_uri in (
            "http://org-alpha.io/ns/a",
            "spiffe://ORG_UPPER/ns/a",
            "spiffe://org-alpha.io/ns/../admin",
            "spiffe://org-alpha.io:8080/ns/a",
            "spiffe://org-alpha.io/",
        ):
            with self.assertRaises(IdentityError):
                SpiffeId.parse(bad_uri)

    def test_agent_directory_http_service_and_anti_poisoning(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        ca_evil = TrustDomainCA("org-evil.io")

        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)
        # Note: org-evil.io is NOT trusted!

        directory = AgentDirectoryService(resolver)
        dir_url = directory.start()
        try:
            client = AgentDirectoryClient(dir_url, resolver)

            w_primary = ca_alpha.issue_workload("/ns/travel/sa/flight-primary")
            w_backup = ca_beta.issue_workload("/ns/travel/sa/flight-backup")

            card_primary = AgentCard.sign_and_create(
                identity=w_primary,
                name="Flight Primary",
                endpoint="http://127.0.0.1:19101",
                skills=["flight.book", "flight.search"],
                priority=10,
            )
            card_backup = AgentCard.sign_and_create(
                identity=w_backup,
                name="Flight Backup Cross-Org",
                endpoint="http://127.0.0.1:19102",
                skills=["flight.book"],
                priority=20,
            )

            client.register(card_primary)
            client.register(card_backup)

            # Discover flight.book -> ordered by priority (primary first, backup second)
            found = client.discover(skill="flight.book")
            self.assertEqual(
                [c.spiffe_id for c in found],
                [w_primary.spiffe_id, w_backup.spiffe_id],
            )

            # Fallback discovery excluding failed primary -> returns cross-domain backup!
            substitutes = client.discover(
                skill="flight.book", exclude_spiffe_ids=[w_primary.spiffe_id]
            )
            self.assertEqual([c.spiffe_id for c in substitutes], [w_backup.spiffe_id])

            # Attack 1: Agent Card Poisoning (MITM alters endpoint URL after signing)
            poisoned_dict = card_primary.to_dict()
            poisoned_dict["endpoint"] = "http://attacker.evil.io:9999"
            poisoned_dict["version"] = 2
            with self.assertRaises(AgentCardError):
                directory.register_card_direct(poisoned_dict)

            # Attack 2: Untrusted domain workload attempts registration
            w_evil = ca_evil.issue_workload("/ns/evil/sa/spoof")
            evil_card = AgentCard.sign_and_create(
                identity=w_evil,
                name="Evil Spoofer",
                endpoint="http://127.0.0.1:19999",
                skills=["flight.book"],
            )
            with self.assertRaises(AgentCardError):
                client.register(evil_card)

            # Attack 3: Replay / version rollback
            with self.assertRaises(AgentCardError):
                client.register(card_primary)

            # Quarantine primary via authorized domain CA (or verified delegator) -> excluded from discovery
            client.quarantine(ca_alpha, w_primary.spiffe_id, "byzantine_fault")
            after_q = client.discover(skill="flight.book")
            self.assertEqual([c.spiffe_id for c in after_q], [w_backup.spiffe_id])
        finally:
            directory.stop()


if __name__ == "__main__":
    unittest.main()
