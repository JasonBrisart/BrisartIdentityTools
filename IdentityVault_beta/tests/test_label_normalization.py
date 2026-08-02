"""Regression tests for label normalization in the vault service.

Stored labels pass through ``safe_label()``, which collapses internal runs of
whitespace. Lookups used to compare against ``label.strip()``, which does not.
Any label containing a double space therefore never matched an existing record,
so duplicate detection failed open and ``upsert_record`` appended a new record
on every call instead of updating in place.
"""

import json
import tempfile
import unittest
from pathlib import Path

from IdentityVault_beta.vault.vault_service import IdentityVaultService


class TestLabelNormalization(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.vault_path = (
            Path(self.temporary_directory.name) / "vault.json"
        )
        self.service = IdentityVaultService(str(self.vault_path))
        self.service.initialize()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _record_count(self):
        data = json.loads(
            self.vault_path.read_text(encoding="utf-8")
        )
        return len(data["records"])

    def test_duplicate_add_with_internal_double_space_is_rejected(self):
        self.service.add_record(
            kind="identity",
            label="Researcher  One",
            value="first",
        )

        with self.assertRaises(FileExistsError):
            self.service.add_record(
                kind="identity",
                label="Researcher  One",
                value="second",
            )

        self.assertEqual(self._record_count(), 1)

    def test_upsert_with_internal_double_space_updates_in_place(self):
        first = self.service.upsert_record(
            kind="general",
            label="My  Label",
            value="first",
        )
        second = self.service.upsert_record(
            kind="general",
            label="My  Label",
            value="second",
        )

        self.assertEqual(
            first["record_id"],
            second["record_id"],
        )
        self.assertEqual(self._record_count(), 1)

    def test_lookup_matches_unnormalized_query(self):
        self.service.add_record(
            kind="general",
            label="My  Label",
            value="stored",
        )

        found = self.service.get_record_by_label(
            kind="general",
            label="My  Label",
        )

        self.assertEqual(found["value"], "stored")

    def test_whitespace_variants_resolve_to_one_record(self):
        self.service.add_record(
            kind="general",
            label="Alpha  Beta",
            value="stored",
        )

        for variant in (
            "Alpha  Beta",
            "  Alpha  Beta  ",
            "Alpha   Beta",
            "Alpha\tBeta",
        ):
            with self.subTest(variant=variant):
                found = self.service.get_record_by_label(
                    kind="general",
                    label=variant,
                )
                self.assertEqual(found["value"], "stored")

        self.assertEqual(self._record_count(), 1)

    def test_distinct_labels_still_create_distinct_records(self):
        self.service.add_record(
            kind="general",
            label="Alpha",
            value="a",
        )
        self.service.add_record(
            kind="general",
            label="Beta",
            value="b",
        )

        self.assertEqual(self._record_count(), 2)

    def test_same_label_under_different_kinds_is_allowed(self):
        self.service.add_record(
            kind="general",
            label="Shared  Label",
            value="a",
        )
        self.service.add_record(
            kind="secret",
            label="Shared  Label",
            value="b",
        )

        self.assertEqual(self._record_count(), 2)


if __name__ == "__main__":
    unittest.main()
