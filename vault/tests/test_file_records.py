"""Tests for VaultService.upsert_file/upsert_file_bytes/get_file/get_file_bytes:
arbitrary raw-file encryption, independent of extension, kind, or any
assumption about the file's content shape.

Follows the same convention as test_sealed_vault.py: setUp() runs a real
VaultService.create() call, which pays BSR2's real ~85-90 second KDF cost
per test method. That is consistent with how this repository's existing
vault test suite is written and how its own CI documents the expected
runtime (see .github/workflows/tests.yml's "vault and package CLIs each
run BSR2's deliberately slow passphrase derivation" comment) -- this is not
a new cost introduced by this feature, only the same accepted cost applied
to a new code path.
"""
import secrets
import tempfile
import unittest
from pathlib import Path

from vault.store.vault_service import VaultService, VaultServiceError


class FileRecordTests(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp_dir.name)
        self.vault_path = self.tmp_path / "vault.json"
        self.service, _ = VaultService.create(self.vault_path, "file record test passphrase")

    def tearDown(self):
        self._tmp_dir.cleanup()

    def test_arbitrary_binary_with_no_extension_round_trips_exactly(self):
        content = bytes(range(256)) * 20 + secrets.token_bytes(500)
        summary = self.service.upsert_file_bytes("no-extension-blob", content, original_filename="blob")
        recovered = self.service.get_file_bytes(summary["record_id"])
        self.assertEqual(recovered, content)

    def test_content_resembling_json_is_never_parsed_as_json(self):
        tricky = b'{"looks": "like json"}' + b"\x00\xff\xfe garbage"
        summary = self.service.upsert_file_bytes("tricky", tricky, original_filename="tricky.dat")
        recovered = self.service.get_file_bytes(summary["record_id"])
        self.assertEqual(recovered, tricky)

    def test_exe_shaped_binary_round_trips_exactly(self):
        fake_exe = b"MZ" + secrets.token_bytes(2000)
        summary = self.service.upsert_file_bytes("program", fake_exe, original_filename="program.exe")
        recovered = self.service.get_file_bytes(summary["record_id"])
        self.assertEqual(recovered, fake_exe)

    def test_empty_file_round_trips_correctly(self):
        summary = self.service.upsert_file_bytes("empty", b"", original_filename="empty")
        recovered = self.service.get_file_bytes(summary["record_id"])
        self.assertEqual(recovered, b"")

    def test_upsert_file_reads_a_real_file_from_disk(self):
        source = self.tmp_path / "source_file_no_ext"
        content = secrets.token_bytes(4000)
        source.write_bytes(content)
        summary = self.service.upsert_file(source)
        self.assertEqual(summary["original_filename"], "source_file_no_ext")
        recovered = self.service.get_file_bytes(summary["record_id"])
        self.assertEqual(recovered, content)

    def test_get_file_writes_decrypted_bytes_to_disk(self):
        source = self.tmp_path / "source.bin"
        content = secrets.token_bytes(4000)
        source.write_bytes(content)
        summary = self.service.upsert_file(source)
        output = self.tmp_path / "decrypted_output.bin"
        self.service.get_file(summary["record_id"], output)
        self.assertEqual(output.read_bytes(), content)

    def test_stored_vault_file_never_contains_the_plaintext(self):
        content = secrets.token_bytes(2000)
        self.service.upsert_file_bytes("secret-file", content, original_filename="secret.bin")
        raw_vault_bytes = self.vault_path.read_bytes()
        self.assertNotIn(content, raw_vault_bytes)

    def test_file_record_reports_size_and_hash_metadata(self):
        content = b"hello world" * 100
        summary = self.service.upsert_file_bytes("meta-test", content, original_filename="meta.txt")
        self.assertEqual(summary["file_size_bytes"], len(content))
        self.assertEqual(len(summary["file_sha256"]), 64)

    def test_upsert_file_missing_source_raises(self):
        with self.assertRaises(VaultServiceError):
            self.service.upsert_file(self.tmp_path / "does_not_exist.bin")

    def test_file_record_requires_unlocked_vault(self):
        self.service.lock()
        with self.assertRaises(VaultServiceError):
            self.service.upsert_file_bytes("x", b"data", original_filename="x")


if __name__ == "__main__":
    unittest.main()
