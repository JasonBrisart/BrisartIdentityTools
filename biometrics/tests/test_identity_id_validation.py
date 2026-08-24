"""Tests for identity id validation across identity_record and identity_store."""
import tempfile
import unittest

from biometrics.identity.identity_record import (
    IdentityRecordError,
    has_modality,
    new_record,
    public_summary,
    validate_record,
)
from biometrics.identity.identity_store import IdentityStore, IdentityStoreError


class IdentityRecordValidationTests(unittest.TestCase):
    def test_new_record_rejects_empty_identity_id(self):
        with self.assertRaises(IdentityRecordError):
            new_record("", "Label", "binding")

    def test_new_record_rejects_empty_label(self):
        with self.assertRaises(IdentityRecordError):
            new_record("id-1", "", "binding")

    def test_new_record_rejects_empty_device_binding(self):
        with self.assertRaises(IdentityRecordError):
            new_record("id-1", "Label", "")

    def test_validate_record_rejects_wrong_format(self):
        with self.assertRaises(IdentityRecordError):
            validate_record({"format": "something-else"})

    def test_validate_record_rejects_non_dict(self):
        with self.assertRaises(IdentityRecordError):
            validate_record(["not", "a", "dict"])

    def test_has_modality_false_for_fresh_record(self):
        record = new_record("id-1", "Label", "binding")
        self.assertFalse(has_modality(record, "voice"))

    def test_public_summary_omits_device_binding(self):
        record = new_record("id-1", "Label", "secret-binding-value")
        summary = public_summary(record)
        self.assertNotIn("device_binding", summary)
        self.assertNotIn("secret-binding-value", str(summary))


class IdentityStorePathSafetyTests(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.store = IdentityStore(self._tmp_dir.name)

    def tearDown(self):
        self._tmp_dir.cleanup()

    def test_rejects_path_traversal_in_identity_id(self):
        with self.assertRaises(IdentityStoreError):
            self.store.exists("../escape")

    def test_rejects_forward_slash_in_identity_id(self):
        with self.assertRaises(IdentityStoreError):
            self.store.exists("a/b")

    def test_rejects_backslash_in_identity_id(self):
        with self.assertRaises(IdentityStoreError):
            self.store.exists("a\\b")

    def test_rejects_whitespace_padded_identity_id(self):
        with self.assertRaises(IdentityStoreError):
            self.store.exists("  id-1  ")

    def test_rejects_non_string_identity_id(self):
        with self.assertRaises(IdentityStoreError):
            self.store.exists(12345)

    def test_load_missing_identity_raises(self):
        with self.assertRaises(IdentityStoreError):
            self.store.load("does-not-exist")

    def test_save_and_load_round_trip(self):
        record = new_record("id-1", "Label", "binding")
        self.store.save(record)
        loaded = self.store.load("id-1")
        self.assertEqual(loaded["identity_id"], "id-1")
        self.assertEqual(loaded["label"], "Label")

    def test_delete_missing_identity_returns_false(self):
        self.assertFalse(self.store.delete("nope"))

    def test_delete_existing_identity_returns_true(self):
        record = new_record("id-2", "Label", "binding")
        self.store.save(record)
        self.assertTrue(self.store.delete("id-2"))
        self.assertFalse(self.store.exists("id-2"))

    def test_list_identity_ids_sorted(self):
        for identity_id in ("charlie", "alpha", "bravo"):
            self.store.save(new_record(identity_id, "Label", "binding"))
        self.assertEqual(
            self.store.list_identity_ids(), ["alpha", "bravo", "charlie"]
        )


if __name__ == "__main__":
    unittest.main()
