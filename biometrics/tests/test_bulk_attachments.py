"""Tests for biometrics.engine.bulk_attachments: chunked, multi-path
file/folder/drive attachments on an identity record.

Like biometrics/tests/test_attachments.py, these use an injected 32-byte master
key (secrets.token_bytes) rather than a real Keyring unlock, so they exercise
the full chunk/bundle/manifest logic and real BSR2 sealing of each chunk WITHOUT
paying the slow KDF cost. A small chunk size forces the multi-chunk path.
"""
import secrets
import tempfile
import unittest
from pathlib import Path

from biometrics.identity.identity_record import new_record
from biometrics.engine import bulk_attachments
from biometrics.engine.bulk_attachments import BulkAttachmentError


class BulkAttachmentTests(unittest.TestCase):
    def setUp(self):
        self.master_key = secrets.token_bytes(32)
        self.record = new_record("alice", "Alice Example", "device-binding-placeholder")
        self.small_chunk = 32 * 1024  # force multi-chunk on modest inputs

    def test_small_content_uses_a_single_chunk(self):
        data = b"a short attachment"
        record = bulk_attachments.attach_large_bytes(
            self.record, "note", data, self.master_key, chunk_bytes=self.small_chunk)
        self.assertEqual(
            bulk_attachments.restore_large_bytes(record, "note", self.master_key), data)

    def test_multi_chunk_content_round_trips_exactly(self):
        data = secrets.token_bytes(self.small_chunk * 3 + 123)
        record = bulk_attachments.attach_large_bytes(
            self.record, "big", data, self.master_key, chunk_bytes=self.small_chunk)
        self.assertEqual(
            bulk_attachments.restore_large_bytes(record, "big", self.master_key), data)

    def test_empty_content_round_trips(self):
        record = bulk_attachments.attach_large_bytes(
            self.record, "empty", b"", self.master_key, chunk_bytes=self.small_chunk)
        self.assertEqual(
            bulk_attachments.restore_large_bytes(record, "empty", self.master_key), b"")

    def test_a_manifest_attachment_is_created(self):
        record = bulk_attachments.attach_large_bytes(
            self.record, "bundle", b"data", self.master_key, chunk_bytes=self.small_chunk)
        self.assertIn("bundle.manifest", record.get("attachments", {}))

    def test_restore_detects_a_missing_chunk(self):
        data = secrets.token_bytes(self.small_chunk * 2 + 50)
        record = bulk_attachments.attach_large_bytes(
            self.record, "corrupt", data, self.master_key, chunk_bytes=self.small_chunk)
        # Drop one chunk attachment and confirm reassembly refuses.
        del record["attachments"]["corrupt.chunk0"]
        with self.assertRaises(BulkAttachmentError):
            bulk_attachments.restore_large_bytes(record, "corrupt", self.master_key)

    def test_restore_missing_bundle_raises(self):
        with self.assertRaises(BulkAttachmentError):
            bulk_attachments.restore_large_bytes(self.record, "nope", self.master_key)

    def test_attach_paths_bundles_mixed_files_and_folders(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            standalone = tmp_path / "report.pdf"
            standalone.write_bytes(b"%PDF fake")
            folder = tmp_path / "Photos"
            (folder / "sub").mkdir(parents=True)
            (folder / "a.txt").write_bytes(b"file a")
            (folder / "sub" / "b_no_ext").write_bytes(b"no extension file")

            record, report = bulk_attachments.attach_paths(
                self.record, "my-bundle", [standalone, folder], self.master_key,
                chunk_bytes=self.small_chunk)
            self.assertEqual(report["files_bundled"], 3)

            restore_dir = tmp_path / "restored"
            result = bulk_attachments.restore_paths(
                record, "my-bundle", self.master_key, restore_dir)
            self.assertEqual(result["files_restored"], 3)
            self.assertEqual((restore_dir / "report.pdf").read_bytes(), b"%PDF fake")
            self.assertEqual(
                (restore_dir / "Photos" / "sub" / "b_no_ext").read_bytes(),
                b"no extension file")

    def test_attach_paths_requires_at_least_one_path(self):
        with self.assertRaises(BulkAttachmentError):
            bulk_attachments.attach_paths(self.record, "empty", [], self.master_key)

    def test_attach_paths_rejects_a_nonexistent_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(BulkAttachmentError):
                bulk_attachments.attach_paths(
                    self.record, "bad", [Path(tmp) / "does_not_exist"], self.master_key)

    def test_remove_bulk_attachment_clears_chunks_and_manifest(self):
        data = secrets.token_bytes(self.small_chunk * 2 + 10)
        record = bulk_attachments.attach_large_bytes(
            self.record, "temp", data, self.master_key, chunk_bytes=self.small_chunk)
        record = bulk_attachments.remove_bulk_attachment(record, "temp", self.master_key)
        remaining = [name for name in record.get("attachments", {}) if name.startswith("temp")]
        self.assertEqual(remaining, [])
        with self.assertRaises(BulkAttachmentError):
            bulk_attachments.restore_large_bytes(record, "temp", self.master_key)


if __name__ == "__main__":
    unittest.main()
