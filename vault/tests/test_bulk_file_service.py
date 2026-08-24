"""Tests for BulkFileService: chunked encryption of content past BSR2's
single-envelope ~16 MiB limit, and multi-path (files + folders + drive
roots) bundling into one encrypted archive.

Uses an injected master key (like test_file_records.py could, but doesn't
currently) to avoid paying the real ~85-90 second KDF cost per test -- the
chunking/reassembly/zip-bundling logic under test here is independent of
HOW the master key was obtained, so this is a faithful test of the actual
logic without the unrelated KDF cost. A separate, slower real-KDF
end-to-end confirmation was run manually during development (see this
feature's delivery notes) proving the two layers compose correctly.
"""
import secrets
import tempfile
import unittest
from pathlib import Path

from vault.store.vault_file import VAULT_FORMAT, save_state
from vault.store.vault_service import VaultService
from vault.store.bulk_file_service import BulkFileService, BulkFileServiceError


class BulkFileServiceTests(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp_dir.name)
        self.vault_path = self.tmp_path / "vault.json"
        save_state(self.vault_path, {"format": VAULT_FORMAT, "keyring": {"placeholder": True},
                                     "records": {}})
        self.service = VaultService(self.vault_path)
        self.service._master_key = secrets.token_bytes(32)
        self.bulk = BulkFileService(self.service, chunk_bytes=64 * 1024)  # small for fast tests

    def tearDown(self):
        self._tmp_dir.cleanup()

    def test_small_content_uses_a_single_chunk(self):
        data = b"small content"
        summary = self.bulk.upsert_large_bytes("small", data)
        self.assertEqual(summary["chunk_count"], 1)
        self.assertEqual(self.bulk.restore_bytes(summary["record_id"]), data)

    def test_content_larger_than_chunk_size_splits_correctly(self):
        data = secrets.token_bytes(64 * 1024 * 3 + 100)  # forces 4 chunks
        summary = self.bulk.upsert_large_bytes("multi-chunk", data)
        self.assertEqual(summary["chunk_count"], 4)
        recovered = self.bulk.restore_bytes(summary["record_id"])
        self.assertEqual(recovered, data)

    def test_empty_content_round_trips(self):
        summary = self.bulk.upsert_large_bytes("empty", b"")
        self.assertEqual(self.bulk.restore_bytes(summary["record_id"]), b"")

    def test_restore_detects_missing_chunk(self):
        data = secrets.token_bytes(64 * 1024 * 2 + 500)
        summary = self.bulk.upsert_large_bytes("will-corrupt", data)
        self.service.delete(self._first_chunk_id(summary["record_id"]))
        with self.assertRaises(Exception):
            self.bulk.restore_bytes(summary["record_id"])

    def _first_chunk_id(self, manifest_record_id):
        manifest = self.service.get(manifest_record_id)
        return manifest["chunk_record_ids"][0]

    def test_upsert_paths_bundles_mixed_files_and_folders(self):
        f1 = self.tmp_path / "standalone.pdf"
        f1.write_bytes(b"%PDF fake content")
        folder = self.tmp_path / "MyFolder"
        (folder / "sub").mkdir(parents=True)
        (folder / "a.txt").write_bytes(b"file a")
        (folder / "sub" / "b_no_ext").write_bytes(b"file b, no extension")

        summary = self.bulk.upsert_paths([f1, folder], "mixed-bundle")
        self.assertEqual(summary["files_bundled"], 3)

        restore_dir = self.tmp_path / "restored"
        result = self.bulk.restore_paths(summary["record_id"], restore_dir)
        self.assertEqual(result["files_restored"], 3)
        self.assertEqual((restore_dir / "standalone.pdf").read_bytes(), b"%PDF fake content")
        self.assertEqual((restore_dir / "MyFolder" / "a.txt").read_bytes(), b"file a")
        self.assertEqual(
            (restore_dir / "MyFolder" / "sub" / "b_no_ext").read_bytes(),
            b"file b, no extension",
        )

    def test_upsert_paths_requires_at_least_one_path(self):
        with self.assertRaises(BulkFileServiceError):
            self.bulk.upsert_paths([], "empty-bundle")

    def test_upsert_paths_rejects_nonexistent_path(self):
        with self.assertRaises(BulkFileServiceError):
            self.bulk.upsert_paths([self.tmp_path / "does_not_exist"], "bad-bundle")

    def test_requires_unlocked_vault(self):
        self.service.lock()
        with self.assertRaises(BulkFileServiceError):
            self.bulk.upsert_large_bytes("x", b"data")


if __name__ == "__main__":
    unittest.main()
