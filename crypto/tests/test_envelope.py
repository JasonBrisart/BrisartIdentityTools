"""Tests for crypto.envelope: length-hiding padding, JSON canonicalisation,
context binding, and uniform authentication failure.

These use a random 32-byte master key plus a real crypto.rng generator, NOT a
passphrase, so they exercise the full BSR2 seal/open path WITHOUT paying the
slow KDF cost (envelope sealing is sponge-based, not KDF-based).
"""
import unittest

from crypto.envelope import (
    MAX_PAYLOAD_BYTES,
    PADDING_BLOCK_BYTES,
    is_envelope,
    open_bytes,
    open_json,
    seal_bytes,
    seal_json,
)
from crypto.errors import Bsr2IntegrationError, EnvelopeAuthenticationError
from crypto.rng import new_generator

import secrets

_ALGORITHM = "BSR2-ARX-SPONGE-ETM"


def _flip_one_hex_char(text):
    replacement = "0" if text[-1] != "0" else "1"
    return text[:-1] + replacement


class EnvelopeRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_bytes(32)

    def _rng(self):
        return new_generator("envelope-test")

    def test_seal_bytes_round_trips_exactly(self):
        data = secrets.token_bytes(1000)
        envelope = seal_bytes(self.key, data, "ctx", self._rng())
        self.assertEqual(open_bytes(self.key, envelope, "ctx"), data)

    def test_empty_bytes_round_trip(self):
        envelope = seal_bytes(self.key, b"", "ctx", self._rng())
        self.assertEqual(open_bytes(self.key, envelope, "ctx"), b"")

    def test_seal_json_round_trips(self):
        payload = {"b": 2, "a": [1, 2, 3], "nested": {"x": True}}
        envelope = seal_json(self.key, payload, "ctx", self._rng())
        self.assertEqual(open_json(self.key, envelope, "ctx"), payload)

    def test_sealed_object_reports_as_an_envelope(self):
        envelope = seal_bytes(self.key, b"hi", "ctx", self._rng())
        self.assertTrue(is_envelope(envelope))
        self.assertEqual(envelope["algorithm"], _ALGORITHM)

    def test_is_envelope_false_for_junk(self):
        self.assertFalse(is_envelope({"not": "an envelope"}))
        self.assertFalse(is_envelope("string"))
        self.assertFalse(is_envelope({"algorithm": _ALGORITHM}))


class EnvelopeAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_bytes(32)
        self.envelope = seal_bytes(self.key, b"secret payload", "ctx",
                                   new_generator("envelope-test"))

    def test_modified_ciphertext_fails_authentication(self):
        tampered = dict(self.envelope)
        tampered["ciphertext"] = _flip_one_hex_char(tampered["ciphertext"])
        with self.assertRaises(EnvelopeAuthenticationError):
            open_bytes(self.key, tampered, "ctx")

    def test_wrong_key_fails_authentication(self):
        with self.assertRaises(EnvelopeAuthenticationError):
            open_bytes(secrets.token_bytes(32), self.envelope, "ctx")

    def test_wrong_context_fails_authentication(self):
        with self.assertRaises(EnvelopeAuthenticationError):
            open_bytes(self.key, self.envelope, "different-context")

    def test_authentication_error_is_a_bsr2_integration_error(self):
        # Callers only need to catch Bsr2IntegrationError, never a vendor type.
        self.assertTrue(issubclass(EnvelopeAuthenticationError, Bsr2IntegrationError))


class EnvelopePaddingTests(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_bytes(32)

    def _ciphertext_len(self, plaintext):
        envelope = seal_bytes(self.key, plaintext, "ctx", new_generator("pad-test"))
        return len(envelope["ciphertext"]) // 2  # hex -> bytes

    def test_short_plaintexts_share_a_ciphertext_length_bucket(self):
        # Length-hiding padding means a 1-byte and a 40-byte payload seal to the
        # same ciphertext size, so ciphertext length does not leak plaintext length.
        self.assertEqual(self._ciphertext_len(b"x"), self._ciphertext_len(b"x" * 40))

    def test_ciphertext_length_is_a_multiple_of_the_padding_block(self):
        self.assertEqual(self._ciphertext_len(b"hello") % PADDING_BLOCK_BYTES, 0)


class EnvelopeLimitTests(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_bytes(32)

    def test_oversized_plaintext_is_refused(self):
        oversized = b"x" * (MAX_PAYLOAD_BYTES + 1)
        with self.assertRaises(Bsr2IntegrationError):
            seal_bytes(self.key, oversized, "ctx", new_generator("limit-test"))

    def test_seal_bytes_rejects_non_bytes(self):
        with self.assertRaises(Bsr2IntegrationError):
            seal_bytes(self.key, "a string, not bytes", "ctx", new_generator("t"))

    def test_seal_json_rejects_non_dict(self):
        with self.assertRaises(Bsr2IntegrationError):
            seal_json(self.key, ["not", "an", "object"], "ctx", new_generator("t"))

    def test_open_json_on_non_json_payload_raises_after_auth(self):
        # Sealed as raw non-UTF-8 bytes, then opened as JSON: the tag verifies,
        # but the decode/parse fails -> Bsr2IntegrationError (genuine corruption
        # path, not a tamper).
        envelope = seal_bytes(self.key, b"\xff\xfe\x00 not json", "ctx",
                              new_generator("t"))
        with self.assertRaises(Bsr2IntegrationError):
            open_json(self.key, envelope, "ctx")


if __name__ == "__main__":
    unittest.main()
