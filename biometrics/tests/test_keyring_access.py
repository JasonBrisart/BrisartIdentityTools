"""Tests for biometrics.identity.keyring_access: the shared,
attempt-throttled entry point both the biometrics CLI (biometrics/app.py)
and the desktop GUI (gui/tabs/tab_biometrics.py) unlock through.

SLOW: setUpClass() creates one real BSR2 keyring (Keyring.create(), a single
~85-90s KDF derivation). Locked-out refusal is tested without any further
KDF cost (the whole point of check_and_get_state() running before
Keyring.unlock_with_passphrase() is called), and exactly one more real KDF
call confirms a genuine wrong-passphrase failure is recorded, plus one more
confirms a correct unlock clears it.
"""
import json
import tempfile
import unittest
from pathlib import Path

from biometrics.identity import keyring_access
from crypto import attempt_store
from crypto.keyring import Keyring
from crypto.throttle import AttemptLimiter


class KeyringAccessThrottleTests(unittest.TestCase):
    """SLOW: real KDF in setUpClass."""

    @classmethod
    def setUpClass(cls):
        cls._tmp_dir = tempfile.TemporaryDirectory()
        cls.path = Path(cls._tmp_dir.name) / "keyring.json"
        cls.passphrase = "a passphrase for keyring access tests"
        keyring, cls.recovery_code = Keyring.create(cls.passphrase)
        with open(cls.path, "w", encoding="utf-8") as handle:
            json.dump(keyring.to_state(), handle, indent=2, sort_keys=True)

    @classmethod
    def tearDownClass(cls):
        cls._tmp_dir.cleanup()

    def _fresh_keyring(self):
        with open(self.path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        return Keyring(state)

    def _force_locked_out(self):
        with open(self.path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        limiter = AttemptLimiter()
        attempt_state = None
        for _ in range(limiter.max_attempts):
            attempt_state = limiter.record_failure(attempt_state)
        state[attempt_store.ATTEMPT_STATE_FIELD] = attempt_state
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)

    def _clear_attempts(self):
        with open(self.path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        state.pop(attempt_store.ATTEMPT_STATE_FIELD, None)
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)

    def test_locked_out_keyring_refuses_before_any_kdf_runs(self):
        self._force_locked_out()
        keyring = self._fresh_keyring()
        with self.assertRaises(keyring_access.KeyringAccessError):
            keyring_access.unlock_with_passphrase(keyring, self.path, self.passphrase)
        self._clear_attempts()

    def test_a_wrong_passphrase_records_one_failure(self):
        keyring = self._fresh_keyring()
        with self.assertRaises(keyring_access.KeyringAccessError):
            keyring_access.unlock_with_passphrase(keyring, self.path, "the wrong passphrase")
        with open(self.path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        self.assertEqual(state[attempt_store.ATTEMPT_STATE_FIELD]["failed_attempts"], 1)

    def test_a_correct_unlock_clears_recorded_failures(self):
        keyring = self._fresh_keyring()
        master_key = keyring_access.unlock_with_passphrase(keyring, self.path, self.passphrase)
        self.assertEqual(len(master_key), 32)
        with open(self.path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        self.assertEqual(state[attempt_store.ATTEMPT_STATE_FIELD]["failed_attempts"], 0)

    def test_keyring_access_error_wraps_attemptlockedout_message(self):
        self._force_locked_out()
        keyring = self._fresh_keyring()
        try:
            keyring_access.unlock_with_passphrase(keyring, self.path, self.passphrase)
            self.fail("expected KeyringAccessError to be raised")
        except keyring_access.KeyringAccessError as exc:
            self.assertIn("too many recent failed attempts", str(exc))
        finally:
            self._clear_attempts()


if __name__ == "__main__":
    unittest.main()
