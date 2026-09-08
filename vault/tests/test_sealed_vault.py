"""End-to-end tests proving vault records are actually sealed, and that
unlock/lock and wrong-passphrase behavior work correctly.

Fix 1 (2026-09-08): added VaultFilePermissionTests, an integration-level
regression test confirming vault/store/vault_file.py's create_vault_file and
save_state actually wire up common.atomic_io's SENSITIVE_FILE_MODE, closing
the gap where vault.json (holding the BSR2-wrapped master key) was written
with default OS permissions despite docs/BSR2_INTEGRATION.md claiming
owner-only protection. Skipped on Windows, where POSIX permission bits are
not meaningfully enforceable -- see common/atomic_io.py's own docstring.
"""
import json
import os
import stat
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
        # correct.
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


@unittest.skipIf(os.name == "nt", "POSIX permission bits are not enforced on Windows")
class VaultFilePermissionTests(unittest.TestCase):
    """Fix 1 (2026-09-08): create_vault_file/save_state must chmod vault.json
    to owner-only (0600), since it holds the BSR2-wrapped master key."""

    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self._tmp_dir.name) / "vault.json"

    def tearDown(self):
        self._tmp_dir.cleanup()

    def _mode_of(self, path: Path) -> int:
        return stat.S_IMODE(path.stat().st_mode)

    def test_create_vault_file_writes_owner_only_permissions(self):
        service, _ = VaultService.create(self.vault_path, "a passphrase for testing")
        self.assertEqual(self._mode_of(self.vault_path), 0o600)

    def test_save_state_re_applies_owner_only_permissions_after_widening(self):
        service, _ = VaultService.create(self.vault_path, "a passphrase for testing")
        # Simulate the file having been widened by hand (or by a pre-fix
        # version of this code) after creation.
        self.vault_path.chmod(0o644)
        service.upsert("Note", "note", {"value": 1})
        self.assertEqual(self._mode_of(self.vault_path), 0o600)


if __name__ == "__main__":
    unittest.main()
