"""Tests for label normalization in vault.records.record_model, and its
effect on vault-level lookups."""
import tempfile
import unittest
from pathlib import Path

from vault.records.record_model import VaultRecordError, normalize_label
from vault.store.vault_service import VaultService


class LabelNormalizationTests(unittest.TestCase):
    def test_strips_surrounding_whitespace(self):
        self.assertEqual(normalize_label("  My Label  "), "My Label")

    def test_nfkc_normalizes_composed_and_decomposed_forms(self):
        composed = "Caf\u00e9"          # "Café" as a single precomposed codepoint
        decomposed = "Cafe\u0301"       # "Café" as "Cafe" + combining accent
        self.assertEqual(normalize_label(composed), normalize_label(decomposed))

    def test_rejects_empty_label(self):
        with self.assertRaises(VaultRecordError):
            normalize_label("")

    def test_rejects_whitespace_only_label(self):
        with self.assertRaises(VaultRecordError):
            normalize_label("     ")

    def test_rejects_non_string_label(self):
        with self.assertRaises(VaultRecordError):
            normalize_label(12345)

    def test_rejects_overly_long_label(self):
        with self.assertRaises(VaultRecordError):
            normalize_label("x" * 300)


class VaultLookupNormalizationTests(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self._tmp_dir.name) / "vault.json"
        self.service, _ = VaultService.create(self.vault_path, "a passphrase for testing")

    def tearDown(self):
        self._tmp_dir.cleanup()

    def test_find_by_label_matches_after_normalization(self):
        self.service.upsert("  Wi-Fi Password  ", "credential", {"value": "abc123"})
        matches = self.service.find_by_label("Wi-Fi Password")
        self.assertEqual(len(matches), 1)

    def test_find_by_label_matches_unicode_composition_variants(self):
        self.service.upsert("Caf\u00e9 Wifi", "credential", {"value": "xyz"})
        matches = self.service.find_by_label("Cafe\u0301 Wifi")
        self.assertEqual(len(matches), 1)

    def test_stored_label_is_the_normalized_form(self):
        summary = self.service.upsert("  Padded Label  ", "note", {"value": 1})
        self.assertEqual(summary["label"], "Padded Label")

    def test_list_records_sorted_by_normalized_label(self):
        self.service.upsert("Zebra", "note", {"value": 1})
        self.service.upsert("  Apple  ", "note", {"value": 2})
        labels = [summary["label"] for summary in self.service.list_records()]
        self.assertEqual(labels, ["Apple", "Zebra"])


if __name__ == "__main__":
    unittest.main()
