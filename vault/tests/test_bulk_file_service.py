"""Tests for BulkFileService: chunked encryption of content past BSR2's
single-envelope ~16 MiB limit, and multi-path (files + folders + drive
roots) bundling into one encrypted archive.

Uses an injected master key (like test_file_records.py could, but doesn't
currently) to avoid paying the real ~85-90 second KDF cost per test -- the
chunking/reassembly/zip-bundling logic under test here is independent of
HOW the master key was obtained, so this is a faithful test of the actual
logic without the unrelated KDF cost.
"""
import secrets
import tempfile
import unittest
from pathlib import Path

from vault.store.vault_file import VAULT_FORMAT, save_state
from vault.store.vault_service import VaultService
from vault.store.bulk_file_service import BulkFileService, BulkFileServiceError, BUNDLE_CHUNK_KIND


class BulkFileServiceTests(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp_dir.name)
        self.vault_path = self.tmp_path / "vault.json"
        save_state(self.vault_path, {"format": VAULT_FORMAT, "keyring": {"placeholder": True},
                                     "records": {}})
        self.service = VaultService(self.vault_path)
        self.service._master_key = secrets.token_bytes(32)
        # NOTE: BSR2's pure-Python stream cipher runs at roughly 1.4 KB/s
        # (see docs/README_FULL_FILE_ENCRYPTION.md), and every sealed
        # payload is padded up to at least a 256-byte block regardless of
        # its real size. A tiny chunk size here still forces the same
        # multi-chunk/restore code paths under test while keeping the
        # total sealed bytes -- and therefore runtime -- small.
        self.bulk = BulkFileService(self.service, chunk_bytes=256)

    def tearDown(self):
        self._tmp_dir.cleanup()

    def test_small_content_uses_a_single_chunk(self):
        data = b"small content"
        summary = self.bulk.upsert_large_bytes("small", data)
        self.assertEqual(summary["chunk_count"], 1)
        self.assertEqual(self.bulk.restore_bytes(summary["record_id"]), data)

    def test_content_larger_than_chunk_size_splits_correctly(self):
        data = secrets.token_bytes(256 * 3 + 20)  # forces 4 chunks
        summary = self.bulk.upsert_large_bytes("multi-chunk", data)
        self.assertEqual(summary["chunk_count"], 4)
        recovered = self.bulk.restore_bytes(summary["record_id"])
        self.assertEqual(recovered, data)

    def test_empty_content_round_trips(self):
        summary = self.bulk.upsert_large_bytes("empty", b"")
        self.assertEqual(self.bulk.restore_bytes(summary["record_id"]), b"")

    def test_restore_detects_missing_chunk(self):
        data = secrets.token_bytes(256 * 2 + 30)
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

    # --- BUG FIX regression tests (2026-08-25) -------------------------
    # Bundle chunk records must be sealed under BUNDLE_CHUNK_KIND, not the
    # standalone FILE_RECORD_KIND ("file"). Before this fix, chunk records
    # were indistinguishable from real standalone single-file records:
    # they cluttered the vault's file listing (each chunk showed up as its
    # own "file") and the GUI's restore button always assumed every
    # "file"-kind record was a JSON bundle manifest, so opening a real
    # standalone file (or a stray chunk) crashed instead of decrypting.

    def test_chunk_records_use_the_bundle_chunk_kind(self):
        data = secrets.token_bytes(256 * 2 + 10)  # forces multiple chunks
        summary = self.bulk.upsert_large_bytes("kind-check", data)
        manifest = self.service.get(summary["record_id"])
        chunk_kinds = {
            self.service.get_summary(chunk_id)["kind"]
            for chunk_id in manifest["chunk_record_ids"]
        }
        self.assertEqual(chunk_kinds, {BUNDLE_CHUNK_KIND})

    def test_manifest_record_is_not_a_bundle_chunk(self):
        summary = self.bulk.upsert_large_bytes("manifest-kind-check", b"some data")
        self.assertEqual(
            self.service.get_summary(summary["record_id"])["kind"], "bundle-manifest"
        )

    def test_standalone_file_record_is_distinguishable_from_a_chunk(self):
        # A real standalone file record (created directly through
        # VaultService, the same path the CLI's `encrypt-file` command
        # uses) must keep the plain "file" kind, separate from any bundle
        # chunk's "bundle-chunk" kind, so a GUI (or any caller) can tell
        # the two apart before deciding how to decrypt a selected record.
        standalone_summary = self.service.upsert_file_bytes("standalone", b"raw file bytes")
        self.assertEqual(standalone_summary["kind"], "file")
        data = secrets.token_bytes(256 * 2 + 10)
        bundle_summary = self.bulk.upsert_large_bytes("bundle", data)
        manifest = self.service.get(bundle_summary["record_id"])
        chunk_kind = self.service.get_summary(manifest["chunk_record_ids"][0])["kind"]
        self.assertNotEqual(chunk_kind, standalone_summary["kind"])


if __name__ == "__main__":
    unittest.main()
