"""Regression tests for batch record writes.

``upsert_records`` mutated the in-memory vault as it walked the batch and only
called ``save()`` at the end. An invalid item at position N therefore raised
after items 0..N-1 had already been applied, and because the save never ran the
caller silently lost that work with no indication of how far the batch got.
Validation now happens for every item before anything is mutated.
"""

import json
import tempfile
import unittest
from pathlib import Path

from IdentityVault_beta.vault.vault_service import IdentityVaultService


class TestBatchUpsert(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.vault_path = (
            Path(self.temporary_directory.name) / "vault.json"
        )
        self.service = IdentityVaultService(str(self.vault_path))
        self.service.initialize()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _raw(self):
        return json.loads(
            self.vault_path.read_text(encoding="utf-8")
        )

    def test_valid_batch_writes_every_record(self):
        written = self.service.upsert_records(
            [
                {"kind": "general", "label": "A", "value": "1"},
                {"kind": "secret", "label": "B", "value": "2"},
            ]
        )

        self.assertEqual(len(written), 2)
        self.assertEqual(len(self._raw()["records"]), 2)

    def test_invalid_kind_leaves_vault_untouched(self):
        self.service.upsert_records(
            [{"kind": "general", "label": "Existing", "value": "keep"}]
        )
        before = self._raw()

        with self.assertRaises(ValueError):
            self.service.upsert_records(
                [
                    {"kind": "general", "label": "Good", "value": "ok"},
                    {"kind": "NOT_A_KIND", "label": "Bad", "value": "x"},
                ]
            )

        after = self._raw()
        self.assertEqual(before["records"], after["records"])
        self.assertEqual(
            before["audit_log"],
            after["audit_log"],
        )

    def test_partial_batch_does_not_persist_earlier_items(self):
        with self.assertRaises(ValueError):
            self.service.upsert_records(
                [
                    {"kind": "general", "label": "Good", "value": "ok"},
                    {"kind": "NOT_A_KIND", "label": "Bad", "value": "x"},
                ]
            )

        labels = [
            record["label"]
            for record in self._raw()["records"].values()
        ]
        self.assertNotIn("Good", labels)

    def test_missing_required_field_is_rejected(self):
        for incomplete in (
            {"kind": "general", "label": "X"},
            {"kind": "general", "value": "X"},
            {"label": "X", "value": "X"},
        ):
            with self.subTest(item=incomplete):
                with self.assertRaises(ValueError):
                    self.service.upsert_records([incomplete])

    def test_non_object_item_is_rejected(self):
        with self.assertRaises(ValueError):
            self.service.upsert_records(["not-an-object"])

    def test_empty_batch_is_rejected(self):
        with self.assertRaises(ValueError):
            self.service.upsert_records([])

    def test_batch_updates_existing_record_in_place(self):
        self.service.upsert_records(
            [{"kind": "general", "label": "Shared", "value": "v1"}]
        )
        self.service.upsert_records(
            [{"kind": "general", "label": "Shared", "value": "v2"}]
        )

        self.assertEqual(len(self._raw()["records"]), 1)
        found = self.service.get_record_by_label(
            kind="general",
            label="Shared",
        )
        self.assertEqual(found["value"], "v2")


if __name__ == "__main__":
    unittest.main()
