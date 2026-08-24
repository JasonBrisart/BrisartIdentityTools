"""Tests for crypto.keyring.Keyring.

Split into two classes by cost:

* KeyringValidationTests is FAST. Constructing a Keyring only validates the
  stored state -- it does NOT run the KDF -- so malformed-state rejection,
  iteration-bound rejection (0.8.0-beta), and recovery-code formatting are all
  tested here without any derivation, using a hand-built structurally-valid
  state dict.
* KeyringUnlockTests is SLOW. It creates one real keyring in setUpClass (two
  KDF derivations) and performs a small, fixed number of real unlocks. This is
  the same real-KDF cost the existing vault/package suites already pay.
"""
import copy
import secrets
import unittest

from crypto.errors import (
    Bsr2IntegrationError,
    KeyringAuthenticationError,
    KeyringFormatError,
    KeyringLockedError,
)
from crypto.keyring import (
    KEYRING_FORMAT,
    Keyring,
    format_recovery_code,
    generate_recovery_code,
)

_ALGORITHM = "BSR2-ARX-SPONGE-ETM"


def _fake_envelope():
    return {
        "algorithm": _ALGORITHM,
        "version": 2,
        "salt": "00" * 32,
        "nonce": "00" * 32,
        "ciphertext": "00" * 256,
        "tag": "00" * 32,
    }


def _valid_looking_state():
    """A state dict that passes Keyring._validate (no KDF), so individual
    fields can be corrupted to test each rejection path."""
    return {
        "format": KEYRING_FORMAT,
        "kdf": "BSR2/derive_password_key",
        "iterations": 10_000,
        "passphrase": {"salt": "aa" * 32, "wrapped_master_key": _fake_envelope()},
        "recovery": {"salt": "bb" * 32, "wrapped_master_key": _fake_envelope()},
        "master_key_check": "cc" * 32,
    }


class KeyringValidationTests(unittest.TestCase):
    def test_a_valid_looking_state_constructs(self):
        # Sanity check: the fixture itself must validate, or the negative tests
        # below would be meaningless.
        Keyring(_valid_looking_state())

    def test_non_dict_state_is_rejected(self):
        with self.assertRaises(KeyringFormatError):
            Keyring(["not", "a", "dict"])

    def test_wrong_format_is_rejected(self):
        state = _valid_looking_state()
        state["format"] = "something-else"
        with self.assertRaises(KeyringFormatError):
            Keyring(state)

    def test_wrong_kdf_is_rejected(self):
        state = _valid_looking_state()
        state["kdf"] = "not-bsr2"
        with self.assertRaises(KeyringFormatError):
            Keyring(state)

    def test_iterations_below_floor_is_rejected(self):
        state = _valid_looking_state()
        state["iterations"] = 9_999
        with self.assertRaises(KeyringFormatError):
            Keyring(state)

    def test_iterations_above_ceiling_is_rejected(self):
        # 0.8.0-beta: an astronomical iteration count must be rejected at parse
        # time so unlock cannot be turned into a years-long derivation.
        state = _valid_looking_state()
        state["iterations"] = 10_000_000
        with self.assertRaises(KeyringFormatError):
            Keyring(state)

    def test_missing_wrapper_section_is_rejected(self):
        state = _valid_looking_state()
        del state["passphrase"]
        with self.assertRaises(KeyringFormatError):
            Keyring(state)

    def test_bad_salt_length_is_rejected(self):
        state = _valid_looking_state()
        state["passphrase"]["salt"] = "aa" * 8  # too short
        with self.assertRaises(KeyringFormatError):
            Keyring(state)

    def test_non_envelope_wrapper_is_rejected(self):
        state = _valid_looking_state()
        state["recovery"]["wrapped_master_key"] = {"not": "an envelope"}
        with self.assertRaises(KeyringFormatError):
            Keyring(state)

    def test_bad_master_key_check_length_is_rejected(self):
        state = _valid_looking_state()
        state["master_key_check"] = "cc" * 8
        with self.assertRaises(KeyringFormatError):
            Keyring(state)

    def test_locked_keyring_refuses_to_hand_out_the_master_key(self):
        keyring = Keyring(_valid_looking_state())
        self.assertFalse(keyring.is_unlocked)
        with self.assertRaises(KeyringLockedError):
            _ = keyring.master_key

    def test_public_summary_reports_metadata_only(self):
        summary = Keyring(_valid_looking_state()).public_summary()
        self.assertEqual(summary["iterations"], 10_000)
        self.assertFalse(summary["unlocked"])
        self.assertNotIn("master_key_check", summary)

    def test_create_rejects_iterations_below_floor_fast(self):
        # Rejected before any derivation runs.
        with self.assertRaises(Bsr2IntegrationError):
            Keyring.create("passphrase", iterations=5_000)


class RecoveryCodeTests(unittest.TestCase):
    def test_generated_code_normalises_to_forty_characters(self):
        formatted = format_recovery_code(generate_recovery_code())
        self.assertEqual(len(formatted.replace("-", "")), 40)

    def test_formatting_uses_five_char_groups(self):
        formatted = format_recovery_code(generate_recovery_code())
        for group in formatted.split("-"):
            self.assertEqual(len(group), 5)

    def test_confusable_characters_are_folded_on_normalisation(self):
        # A code transcribed with I/O should still round-trip through
        # format_recovery_code (which normalises I->1, O->0, etc.).
        code = generate_recovery_code()
        self.assertEqual(
            format_recovery_code(code),
            format_recovery_code(format_recovery_code(code)),
        )


class KeyringUnlockTests(unittest.TestCase):
    """SLOW: real KDF. Creates one keyring, then a few real unlocks."""

    @classmethod
    def setUpClass(cls):
        cls.passphrase = "correct horse battery staple"
        cls.keyring, cls.recovery_code = Keyring.create(cls.passphrase)
        cls.state = copy.deepcopy(cls.keyring.to_state())

    def test_create_returns_an_unlocked_keyring(self):
        self.assertTrue(self.keyring.is_unlocked)
        self.assertEqual(len(self.keyring.master_key), 32)

    def test_unlock_with_correct_passphrase(self):
        keyring = Keyring(copy.deepcopy(self.state))
        master_key = keyring.unlock_with_passphrase(self.passphrase)
        self.assertEqual(len(master_key), 32)
        self.assertTrue(keyring.is_unlocked)

    def test_unlock_with_recovery_code(self):
        keyring = Keyring(copy.deepcopy(self.state))
        keyring.unlock_with_recovery_code(self.recovery_code)
        self.assertTrue(keyring.is_unlocked)

    def test_wrong_passphrase_is_rejected(self):
        keyring = Keyring(copy.deepcopy(self.state))
        with self.assertRaises(KeyringAuthenticationError):
            keyring.unlock_with_passphrase("the wrong passphrase")


if __name__ == "__main__":
    unittest.main()
