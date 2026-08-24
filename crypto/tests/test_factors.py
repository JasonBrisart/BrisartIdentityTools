"""Tests for crypto.factors.

Two factor families are tested:

* The keyed-MAC path (bind_factor / verify_bound_factor) is FAST (~15 ms) and
  is exercised thoroughly here.
* The slow-KDF path (hash_factor / verify_factor) is SLOW (~85 s per
  derivation). Its parse-time validation (the iteration-count ceiling/floor
  added in 0.8.0-beta) is tested WITHOUT running the KDF by handing
  verify_factor a hand-built, structurally-valid hash string with an
  out-of-range iteration count -- _parse_kdf rejects it before any derivation.
  Exactly ONE real KDF round trip is included, in its own class, and is slow by
  design (consistent with the vault/package suites' real-KDF tests).
"""
import secrets
import unittest

from crypto.errors import Bsr2IntegrationError
from crypto import factors

_HEX32 = "ab" * 32  # 64 lowercase hex chars == 32 bytes, a valid salt/digest field


def _kdf_hash_string(iterations):
    return "$".join(("bsr2", "derive_password_key", f"iterations={iterations}", _HEX32, _HEX32))


class BoundFactorTests(unittest.TestCase):
    def setUp(self):
        self.master_key = secrets.token_bytes(32)

    def test_bind_then_verify_matches(self):
        verifier = factors.bind_factor(self.master_key, "device", "fingerprint-value")
        self.assertTrue(factors.verify_bound_factor(self.master_key, "device", "fingerprint-value", verifier))

    def test_wrong_value_does_not_verify(self):
        verifier = factors.bind_factor(self.master_key, "device", "correct")
        self.assertFalse(factors.verify_bound_factor(self.master_key, "device", "wrong", verifier))

    def test_wrong_master_key_does_not_verify(self):
        verifier = factors.bind_factor(self.master_key, "device", "v")
        self.assertFalse(factors.verify_bound_factor(secrets.token_bytes(32), "device", "v", verifier))

    def test_a_verifier_is_bound_to_its_factor_name(self):
        # A verifier built as "voice" must not verify under the "fingerprint" slot.
        verifier = factors.bind_factor(self.master_key, "voice", "v")
        self.assertFalse(factors.verify_bound_factor(self.master_key, "fingerprint", "v", verifier))

    def test_bind_factor_rejects_short_master_key(self):
        with self.assertRaises(Bsr2IntegrationError):
            factors.bind_factor(b"tooshort", "device", "v")

    def test_bind_factor_rejects_dollar_in_factor_name(self):
        with self.assertRaises(Bsr2IntegrationError):
            factors.bind_factor(self.master_key, "bad$name", "v")

    def test_is_bound_factor_predicate(self):
        verifier = factors.bind_factor(self.master_key, "device", "v")
        self.assertTrue(factors.is_bound_factor(verifier))
        self.assertFalse(factors.is_bound_factor("not-a-bound-factor"))


class FactorHashValidationTests(unittest.TestCase):
    """Parse-time validation only -- no KDF is run in this class."""

    def test_verify_factor_rejects_above_maximum_iterations_without_kdf(self):
        # A tampered hash claiming an astronomical iteration count must be
        # rejected at parse time, not run to completion.
        tampered = _kdf_hash_string(99_999_999)
        self.assertFalse(factors.verify_factor("any-secret", tampered))

    def test_verify_factor_rejects_below_minimum_iterations_without_kdf(self):
        tampered = _kdf_hash_string(5_000)
        self.assertFalse(factors.verify_factor("any-secret", tampered))

    def test_verify_factor_rejects_malformed_string(self):
        self.assertFalse(factors.verify_factor("secret", "not$a$valid$hash"))

    def test_verify_factor_rejects_empty_secret(self):
        self.assertFalse(factors.verify_factor("", _kdf_hash_string(10_000)))

    def test_is_factor_hash_predicate(self):
        self.assertTrue(factors.is_factor_hash(_kdf_hash_string(10_000)))
        self.assertFalse(factors.is_factor_hash("nope"))

    def test_is_legacy_digest_predicate(self):
        self.assertTrue(factors.is_legacy_digest("a" * 64))
        self.assertFalse(factors.is_legacy_digest("a" * 63))
        self.assertFalse(factors.is_legacy_digest("z" * 64))  # non-hex

    def test_needs_rehash_true_for_malformed(self):
        self.assertTrue(factors.needs_rehash("garbage"))

    def test_hash_factor_rejects_below_minimum_iterations_fast(self):
        # Rejected before any derivation runs.
        with self.assertRaises(Bsr2IntegrationError):
            factors.hash_factor("secret", iterations=5_000)

    def test_hash_factor_rejects_above_maximum_iterations_fast(self):
        with self.assertRaises(Bsr2IntegrationError):
            factors.hash_factor("secret", iterations=99_999_999)


class FactorHashKdfRoundTripTests(unittest.TestCase):
    """SLOW: exercises the real password KDF (~85 s per derivation)."""

    def test_hash_and_verify_round_trip(self):
        encoded = factors.hash_factor("correct horse battery staple")
        self.assertTrue(factors.is_factor_hash(encoded))
        self.assertTrue(factors.verify_factor("correct horse battery staple", encoded))
        self.assertFalse(factors.verify_factor("wrong passphrase", encoded))


if __name__ == "__main__":
    unittest.main()
