"""Vault storage tests for BSR2-sealed records.

This file replaces the former ``test_plaintext_vault.py``, which asserted that
no encryption fields were present. Those assertions described the old beta
behaviour and would now fail by design.

Every test here initializes the vault with an injected ``master_key`` rather
than a passphrase. A BSR2 passphrase derivation takes roughly a minute and
these suites run on five Python versions in CI, so deriving per test would push
the run into hours. Passphrase and recovery-code unlocking are covered
separately in ``test_vault_keyring.py``, which pays that cost once.
"""

import json
import secrets
import tempfile
import unittest
from pathlib import Path

from brisart_bsr2.errors import (
    Bsr2IntegrationError,
    EnvelopeAuthenticationError,
)
from brisart_bsr2.keyring import MASTER_KEY_BYTES
from IdentityVault_beta.config.settings import (
    PLAINTEXT_STORAGE_MODE,
    SEALED_STORAGE_MODE,
)
from IdentityVault_beta.vault.vault_service import (
    IdentityVaultService,
    VaultLockedError,
)


class SealedVaultTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temporary_directory.name)
        self.vault_path = self.base_path / "main_vault.json"
        self.master_key = secrets.token_bytes(MASTER_KEY_BYTES)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _new_service(self):
        service = IdentityVaultService(str(self.vault_path))
        service.initialize(master_key=self.master_key)
        return service

    def _load_raw_vault_text(self):
        return self.vault_path.read_text(encoding="utf-8")

    def _load_raw_vault_json(self):
        return json.loads(self._load_raw_vault_text())


class TestSealedVault(SealedVaultTestCase):
    def test_initialize_creates_sealed_vault(self):
        service = IdentityVaultService(str(self.vault_path))

        created, recovery_code = service.initialize(master_key=self.master_key)

        self.assertEqual(created["app"], "IdentityVault")
        self.assertEqual(created["storage_mode"], SEALED_STORAGE_MODE)
        self.assertEqual(created["records"], {})
        self.assertTrue(self.vault_path.is_file())

        # A master-key vault has no keyring, so there is nothing to recover to.
        self.assertIsNone(recovery_code)
        self.assertNotIn("keyring", created)

        raw_data = self._load_raw_vault_json()
        self.assertEqual(raw_data["storage_mode"], SEALED_STORAGE_MODE)

    def test_initialize_requires_a_passphrase_or_key(self):
        service = IdentityVaultService(str(self.vault_path))

        with self.assertRaises(Bsr2IntegrationError):
            service.initialize()

        self.assertFalse(self.vault_path.exists())

    def test_initialize_rejects_both_passphrase_and_key(self):
        service = IdentityVaultService(str(self.vault_path))

        with self.assertRaises(Bsr2IntegrationError):
            service.initialize(
                passphrase="something",
                master_key=self.master_key,
            )

    def test_record_value_is_not_written_in_cleartext(self):
        service = self._new_service()

        public_record = service.add_record(
            kind="identity",
            label="Researcher One",
            value="example confidential identity record",
            notes="stored under BSR2",
            metadata={
                "source": "unit_test",
                "purpose": "sealed_storage_check",
            },
        )

        raw_text = self._load_raw_vault_text()

        # The point of the whole exercise.
        self.assertNotIn("example confidential identity record", raw_text)
        self.assertNotIn("stored under BSR2", raw_text)
        self.assertNotIn("sealed_storage_check", raw_text)

        # Shell metadata stays readable so records can be listed while locked.
        self.assertIn("Researcher One", raw_text)

        stored_record = self._load_raw_vault_json()["records"][
            public_record["record_id"]
        ]

        self.assertIn("sealed_payload", stored_record)
        self.assertNotIn("payload", stored_record)
        self.assertEqual(
            stored_record["storage_mode"],
            SEALED_STORAGE_MODE,
        )

    def test_add_and_get_round_trip(self):
        service = self._new_service()

        public_record = service.add_record(
            kind="identity",
            label="Researcher One",
            value="example confidential identity record",
            notes="stored under BSR2",
            metadata={"source": "unit_test"},
        )

        self.assertEqual(public_record["kind"], "identity")
        self.assertEqual(public_record["label"], "Researcher One")
        self.assertEqual(
            public_record["storage_mode"],
            SEALED_STORAGE_MODE,
        )

        full_record = service.get_record(public_record["record_id"])

        self.assertEqual(
            full_record["value"],
            "example confidential identity record",
        )
        self.assertEqual(full_record["notes"], "stored under BSR2")
        self.assertEqual(full_record["metadata"]["source"], "unit_test")

    def test_reopening_the_vault_with_the_same_key_reads_records(self):
        service = self._new_service()
        record = service.add_record(
            kind="secret",
            label="Persisted",
            value="survives a reopen",
        )

        reopened = IdentityVaultService(
            str(self.vault_path),
            master_key=self.master_key,
        )

        self.assertEqual(
            reopened.get_record(record["record_id"])["value"],
            "survives a reopen",
        )

    def test_locked_service_cannot_read_a_record(self):
        service = self._new_service()
        record = service.add_record(
            kind="secret",
            label="Locked Read",
            value="should not be readable",
        )

        locked = IdentityVaultService(str(self.vault_path))

        self.assertFalse(locked.is_unlocked)

        with self.assertRaises(VaultLockedError):
            locked.get_record(record["record_id"])

    def test_lock_discards_the_master_key(self):
        service = self._new_service()
        record = service.add_record(
            kind="secret",
            label="Lock Me",
            value="value",
        )

        self.assertTrue(service.is_unlocked)
        service.lock()
        self.assertFalse(service.is_unlocked)

        with self.assertRaises(VaultLockedError):
            service.get_record(record["record_id"])

    def test_wrong_master_key_cannot_read_a_record(self):
        service = self._new_service()
        record = service.add_record(
            kind="secret",
            label="Wrong Key",
            value="should not decrypt",
        )

        attacker = IdentityVaultService(
            str(self.vault_path),
            master_key=secrets.token_bytes(MASTER_KEY_BYTES),
        )

        with self.assertRaises(EnvelopeAuthenticationError):
            attacker.get_record(record["record_id"])

    def test_listing_records_does_not_require_unlocking(self):
        service = self._new_service()
        service.add_record(kind="general", label="One", value="a")
        service.add_record(kind="general", label="Two", value="b")

        locked = IdentityVaultService(str(self.vault_path))
        records = locked.list_records()

        self.assertEqual([record["label"] for record in records], ["One", "Two"])

    def test_tampered_ciphertext_is_rejected(self):
        service = self._new_service()
        record = service.add_record(
            kind="general",
            label="Tampered",
            value="original value",
        )

        raw_data = self._load_raw_vault_json()
        sealed = raw_data["records"][record["record_id"]]["sealed_payload"]
        ciphertext = sealed["ciphertext"]
        flipped = ("ff" if ciphertext[:2] != "ff" else "00") + ciphertext[2:]
        sealed["ciphertext"] = flipped
        self.vault_path.write_text(json.dumps(raw_data), encoding="utf-8")

        with self.assertRaises(EnvelopeAuthenticationError):
            service.get_record(record["record_id"])

    def test_relabelling_the_shell_breaks_the_context_binding(self):
        """A sealed payload is bound to its record id, kind, and label.

        Editing the readable shell to point a record's envelope at a different
        label must fail rather than silently decrypt, otherwise the searchable
        metadata would be freely rewritable by anyone with file access.
        """
        service = self._new_service()
        record = service.add_record(
            kind="general",
            label="Original Label",
            value="value",
        )

        raw_data = self._load_raw_vault_json()
        raw_data["records"][record["record_id"]]["label"] = "Attacker Label"
        self.vault_path.write_text(json.dumps(raw_data), encoding="utf-8")

        with self.assertRaises(EnvelopeAuthenticationError):
            service.get_record(record["record_id"])

    def test_moving_a_sealed_payload_to_another_record_is_rejected(self):
        service = self._new_service()
        first = service.add_record(kind="general", label="First", value="one")
        second = service.add_record(kind="general", label="Second", value="two")

        raw_data = self._load_raw_vault_json()
        raw_data["records"][first["record_id"]]["sealed_payload"] = raw_data[
            "records"
        ][second["record_id"]]["sealed_payload"]
        self.vault_path.write_text(json.dumps(raw_data), encoding="utf-8")

        with self.assertRaises(EnvelopeAuthenticationError):
            service.get_record(first["record_id"])

    def test_verify_sealed_vault(self):
        service = self._new_service()
        service.add_record(
            kind="general",
            label="Sealed Record",
            value="sealed value",
        )

        result = service.verify()

        self.assertEqual(result["result"], "OK")
        self.assertEqual(result["checked_records"], 1)
        self.assertEqual(result["failed_records"], [])
        self.assertEqual(result["unprotected_records"], [])
        self.assertEqual(result["storage_mode"], SEALED_STORAGE_MODE)

    def test_manifest_reports_sealed_storage(self):
        service = self._new_service()
        service.add_record(
            kind="verification_metadata",
            label="Verification Metadata",
            value="metadata example",
        )

        manifest = service.manifest()

        self.assertEqual(manifest["record_count"], 1)
        self.assertEqual(manifest["storage_mode"], SEALED_STORAGE_MODE)
        self.assertEqual(
            manifest["records"][0]["storage_mode"],
            SEALED_STORAGE_MODE,
        )

    def test_delete_record_removes_the_sealed_payload(self):
        service = self._new_service()
        record = service.add_record(
            kind="general",
            label="Temporary",
            value="delete me",
        )

        before = self._load_raw_vault_json()["records"]
        sealed_ciphertext = before[record["record_id"]]["sealed_payload"][
            "ciphertext"
        ]

        service.delete_record(record["record_id"])

        raw_text = self._load_raw_vault_text()
        self.assertNotIn(sealed_ciphertext, raw_text)

        result = service.verify()
        self.assertEqual(result["result"], "OK")
        self.assertEqual(result["checked_records"], 0)


class TestLegacyPlaintextMigration(SealedVaultTestCase):
    """Vaults written before BSR2 must stay readable and get re-sealed on write."""

    def _write_legacy_record(self, service):
        raw_data = self._load_raw_vault_json()
        raw_data["records"]["vault-legacy-1"] = {
            "record_id": "vault-legacy-1",
            "kind": "credential",
            "label": "Legacy Record",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "storage_mode": PLAINTEXT_STORAGE_MODE,
            "payload": {
                "kind": "credential",
                "label": "Legacy Record",
                "value": "legacy cleartext value",
                "notes": "written by an older build",
                "metadata": {},
            },
        }
        self.vault_path.write_text(json.dumps(raw_data), encoding="utf-8")

    def test_legacy_plaintext_record_is_still_readable(self):
        service = self._new_service()
        self._write_legacy_record(service)

        record = service.get_record("vault-legacy-1")

        self.assertEqual(record["value"], "legacy cleartext value")

    def test_verify_flags_legacy_records_as_unprotected(self):
        service = self._new_service()
        self._write_legacy_record(service)

        result = service.verify()

        self.assertEqual(result["result"], "OK")
        self.assertEqual(result["unprotected_records"], ["vault-legacy-1"])

    def test_updating_a_legacy_record_seals_it_and_drops_the_cleartext(self):
        service = self._new_service()
        self._write_legacy_record(service)

        service.upsert_record(
            kind="credential",
            label="Legacy Record",
            value="rotated value",
        )

        stored = self._load_raw_vault_json()["records"]["vault-legacy-1"]

        self.assertIn("sealed_payload", stored)
        self.assertNotIn("payload", stored)
        self.assertEqual(stored["storage_mode"], SEALED_STORAGE_MODE)

        raw_text = self._load_raw_vault_text()
        self.assertNotIn("legacy cleartext value", raw_text)
        self.assertNotIn("rotated value", raw_text)

        self.assertEqual(
            service.get_record("vault-legacy-1")["value"],
            "rotated value",
        )
        self.assertEqual(service.verify()["unprotected_records"], [])


if __name__ == "__main__":
    unittest.main()
