import json
import tempfile
import unittest
from pathlib import Path

from IdentityVault_beta.vault.vault_service import IdentityVaultService


class TestPlaintextVault(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temporary_directory.name)
        self.vault_path = self.base_path / "main_vault.json"

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _load_raw_vault_text(self):
        return self.vault_path.read_text(encoding="utf-8")

    def _load_raw_vault_json(self):
        return json.loads(self._load_raw_vault_text())

    def _assert_no_encryption_fields(self, text):
        forbidden_terms = (
            "encrypted",
            "ciphertext",
            "tag",
            "nonce",
            "salt",
            "password",
            "pbkdf2",
            "hmac",
        )

        lowered = text.lower()

        for term in forbidden_terms:
            self.assertNotIn(
                term,
                lowered,
                f"unexpected encryption-related term found: {term}",
            )

    def test_initialize_creates_plaintext_vault(self):
        service = IdentityVaultService(str(self.vault_path))

        created = service.initialize()

        self.assertEqual(created["app"], "IdentityVault")
        self.assertEqual(created["storage_mode"], "plaintext_json_beta")
        self.assertEqual(created["records"], {})
        self.assertTrue(self.vault_path.is_file())

        raw_text = self._load_raw_vault_text()
        raw_data = self._load_raw_vault_json()

        self.assertEqual(raw_data["storage_mode"], "plaintext_json_beta")
        self._assert_no_encryption_fields(raw_text)

    def test_add_and_get_plaintext_record(self):
        service = IdentityVaultService(str(self.vault_path))
        service.initialize()

        public_record = service.add_record(
            kind="identity",
            label="Researcher One",
            value="example plaintext identity record",
            notes="stored without local encryption",
            metadata={
                "source": "unit_test",
                "purpose": "plaintext_storage_check",
            },
        )

        self.assertEqual(public_record["kind"], "identity")
        self.assertEqual(public_record["label"], "Researcher One")
        self.assertEqual(
            public_record["storage_mode"],
            "plaintext_json_beta",
        )

        full_record = service.get_record(public_record["record_id"])

        self.assertEqual(
            full_record["value"],
            "example plaintext identity record",
        )
        self.assertEqual(
            full_record["notes"],
            "stored without local encryption",
        )
        self.assertEqual(
            full_record["metadata"]["source"],
            "unit_test",
        )

        raw_text = self._load_raw_vault_text()
        raw_data = self._load_raw_vault_json()

        self.assertIn("example plaintext identity record", raw_text)
        self.assertIn("Researcher One", raw_text)
        self.assertIn("payload", raw_text)

        stored_record = raw_data["records"][public_record["record_id"]]

        self.assertIn("payload", stored_record)
        self.assertNotIn("encrypted", stored_record)
        self.assertEqual(
            stored_record["storage_mode"],
            "plaintext_json_beta",
        )

        self._assert_no_encryption_fields(raw_text)

    def test_verify_plaintext_vault(self):
        service = IdentityVaultService(str(self.vault_path))
        service.initialize()

        service.add_record(
            kind="general",
            label="Plain Record",
            value="plain value",
        )

        result = service.verify()

        self.assertEqual(result["result"], "OK")
        self.assertEqual(result["checked_records"], 1)
        self.assertEqual(result["failed_records"], [])
        self.assertEqual(
            result["storage_mode"],
            "plaintext_json_beta",
        )

    def test_manifest_reports_plaintext_storage(self):
        service = IdentityVaultService(str(self.vault_path))
        service.initialize()

        service.add_record(
            kind="verification_metadata",
            label="Verification Metadata",
            value="metadata example",
        )

        manifest = service.manifest()

        self.assertEqual(manifest["record_count"], 1)
        self.assertEqual(
            manifest["storage_mode"],
            "plaintext_json_beta",
        )
        self.assertEqual(
            manifest["records"][0]["storage_mode"],
            "plaintext_json_beta",
        )

    def test_delete_record_removes_plaintext_payload(self):
        service = IdentityVaultService(str(self.vault_path))
        service.initialize()

        record = service.add_record(
            kind="general",
            label="Temporary",
            value="delete me",
        )

        service.delete_record(record["record_id"])

        raw_text = self._load_raw_vault_text()

        self.assertNotIn("delete me", raw_text)

        result = service.verify()

        self.assertEqual(result["result"], "OK")
        self.assertEqual(result["checked_records"], 0)


if __name__ == "__main__":
    unittest.main()