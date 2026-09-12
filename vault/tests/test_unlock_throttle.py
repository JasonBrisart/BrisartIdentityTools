"""Tests for the crypto.attempt_store wiring inside
vault.store.vault_service.VaultService.unlock()/unlock_with_recovery_code().

SLOW: setUpClass() creates one real vault (VaultService.create(), which pays
BSR2's real ~85-90s KDF derivation twice -- once for the passphrase wrapper,
once for the recovery-code wrapper). Individual test methods that simulate a
LOCKED-OUT container do NOT pay any further KDF cost, because
check_and_get_state() raises before a Keyring is even constructed -- that
fast-refusal property is itself part of what this module verifies. Exactly
two test methods perform a real unlock attempt (one wrong passphrase, one
correct unlock) to confirm genuine failure/success are recorded correctly,
and one more confirms a recovery-code unlock clears a counter a prior
passphrase failure had incremented.
"""
import tempfile
import unittest
from pathlib import Path

from crypto import attempt_store
from crypto.throttle import AttemptLimiter
from vault.store.vault_file import load_state, save_state
from vault.store.vault_service import VaultService, VaultServiceError


class VaultUnlockThrottleTests(unittest.TestCase):
    """SLOW: real KDF in setUpClass."""

    @classmethod
    def setUpClass(cls):
        cls._tmp_dir = tempfile.TemporaryDirectory()
        cls.vault_path = Path(cls._tmp_dir.name) / "vault.json"
        cls.passphrase = "correct horse battery staple"
        cls.service, cls.recovery_code = VaultService.create(cls.vault_path, cls.passphrase)

    @classmethod
    def tearDownClass(cls):
        cls._tmp_dir.cleanup()

    def _force_locked_out(self):
        """Directly write an already-exhausted attempt state into the vault
        file, without running the KDF at all."""
        state = load_state(self.vault_path)
        limiter = AttemptLimiter()
        attempt_state = None
        for _ in range(limiter.max_attempts):
            attempt_state = limiter.record_failure(attempt_state)
        state[attempt_store.ATTEMPT_STATE_FIELD] = attempt_state
        save_state(self.vault_path, state)

    def _clear_attempts(self):
        state = load_state(self.vault_path)
        state.pop(attempt_store.ATTEMPT_STATE_FIELD, None)
        save_state(self.vault_path, state)

    def test_locked_out_vault_refuses_before_any_kdf_runs(self):
        self._force_locked_out()
        service = VaultService(self.vault_path)
        with self.assertRaises(VaultServiceError):
            service.unlock(self.passphrase)  # correct passphrase, but still locked out
        self._clear_attempts()

    def test_a_wrong_passphrase_records_one_failure(self):
        service = VaultService(self.vault_path)
        with self.assertRaises(VaultServiceError):
            service.unlock("definitely the wrong passphrase")
        state = load_state(self.vault_path)
        self.assertEqual(state[attempt_store.ATTEMPT_STATE_FIELD]["failed_attempts"], 1)

    def test_a_correct_unlock_clears_recorded_failures(self):
        service = VaultService(self.vault_path)
        service.unlock(self.passphrase)
        state = load_state(self.vault_path)
        self.assertEqual(state[attempt_store.ATTEMPT_STATE_FIELD]["failed_attempts"], 0)

    def test_recovery_code_unlock_shares_the_same_counter_as_passphrase(self):
        service = VaultService(self.vault_path)
        with self.assertRaises(VaultServiceError):
            service.unlock("wrong again")
        state = load_state(self.vault_path)
        self.assertEqual(state[attempt_store.ATTEMPT_STATE_FIELD]["failed_attempts"], 1)

        # The failure correctly starts a one-second backoff. Expire only that
        # time gate before trying the recovery code; preserve failed_attempts
        # so this test still proves both credential paths share one counter.
        state[attempt_store.ATTEMPT_STATE_FIELD]["locked_until"] = 0.0
        save_state(self.vault_path, state)

        service_2 = VaultService(self.vault_path)
        service_2.unlock_with_recovery_code(self.recovery_code)
        state = load_state(self.vault_path)
        # The recovery-code unlock succeeded and cleared the SAME field the
        # earlier passphrase failure had incremented -- confirming the two
        # credential types share one attempt budget rather than each having
        # its own.
        self.assertEqual(state[attempt_store.ATTEMPT_STATE_FIELD]["failed_attempts"], 0)

    def test_wrong_recovery_code_also_counts_against_the_shared_budget(self):
        service = VaultService(self.vault_path)
        with self.assertRaises(VaultServiceError):
            service.unlock_with_recovery_code("WRONGCODE-WRONGCODE-WRONGCODE-WRONGCODE")
        state = load_state(self.vault_path)
        self.assertEqual(state[attempt_store.ATTEMPT_STATE_FIELD]["failed_attempts"], 1)
        # Clean up so subsequent test runs in this class start fresh.
        self._clear_attempts()


if __name__ == "__main__":
    unittest.main()
