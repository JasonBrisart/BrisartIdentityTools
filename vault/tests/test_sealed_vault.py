"""End-to-end tests proving vault records are actually sealed, and that
unlock/lock and wrong-passphrase behavior work correctly."""
import json
import tempfile
import unittest
from pathlib import Path

from vault.store.vault_service import VaultService, VaultServiceError


class SealedVaultTests(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self._tmp_dir.name) / "vault.json"
        self.service, self.recovery_code = VaultService.create(
            self.vault_path, "correct horse battery staple"
        )

    def tearDown(self):
        self._tmp_dir.cleanup()

    def test_stored_record_is_not_plaintext(self):
        self.service.upsert("Email password", "credential", {"secret": "hunter2"})
        raw_text = self.vault_path.read_text()
        self.assertNotIn("hunter2", raw_text)
        parsed = json.loads(raw_text)
        record_id = next(iter(parsed["records"]))
        envelope = parsed["records"][record_id]["payload"]
        # NOTE: fixed 2026-08-24 -- this previously asserted "BSR2", but the
        # real algorithm constant (crypto.vendor.ALGORITHM /
        # vendor.brisart_security_envelope.ALGORITHM) is "BSR2-ARX-SPONGE-ETM".
        # The old assertion always failed even though sealing itself was
        # correct; see docs/BUGFIX_2026-08-24.md for the bug-fix entry.
        self.assertEqual(envelope["algorithm"], "BSR2-ARX-SPONGE-ETM")
        self.assertIn("ciphertext", envelope)

    def test_get_returns_the_original_payload(self):
        summary = self.service.upsert("Email password", "credential", {"secret": "hunter2"})
        payload = self.service.get(summary["record_id"])
        self.assertEqual(payload, {"secret": "hunter2"})

    def test_unlock_with_wrong_passphrase_fails(self):
        service = VaultService(self.vault_path)
        with self.assertRaises(VaultServiceError):
            service.unlock("definitely the wrong passphrase")

    def test_unlock_with_correct_passphrase_after_reopen(self):
        service = VaultService(self.vault_path)
        service.unlock("correct horse battery staple")
        self.assertTrue(service.is_unlocked)

    def test_unlock_with_recovery_code_works(self):
        service = VaultService(self.vault_path)
        service.unlock_with_recovery_code(self.recovery_code)
        self.assertTrue(service.is_unlocked)

    def test_lock_clears_unlocked_state(self):
        self.assertTrue(self.service.is_unlocked)
        self.service.lock()
        self.assertFalse(self.service.is_unlocked)

    def test_operations_require_unlock(self):
        self.service.lock()
        with self.assertRaises(VaultServiceError):
            self.service.upsert("Label", "note", {"value": 1})

    def test_get_nonexistent_record_raises(self):
        with self.assertRaises(VaultServiceError):
            self.service.get("does-not-exist")

    def test_delete_removes_record(self):
        summary = self.service.upsert("Temp note", "note", {"value": 1})
        self.assertTrue(self.service.delete(summary["record_id"]))
        with self.assertRaises(VaultServiceError):
            self.service.get(summary["record_id"])

    def test_delete_missing_record_returns_false(self):
        self.assertFalse(self.service.delete("nope"))

    def test_create_refuses_to_overwrite_existing_vault(self):
        from vault.store.vault_file import VaultFileError

        with self.assertRaises(VaultFileError):
            VaultService.create(self.vault_path, "another passphrase")


if __name__ == "__main__":
    unittest.main()
