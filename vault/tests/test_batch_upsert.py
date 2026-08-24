"""Tests for VaultService.batch_upsert: bulk creation, bulk updates, and
that a batch containing an invalid item fails without silently skipping it."""
import tempfile
import unittest
from pathlib import Path

from vault.store.vault_service import VaultService, VaultServiceError


class BatchUpsertTests(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self._tmp_dir.name) / "vault.json"
        self.service, _ = VaultService.create(self.vault_path, "batch test passphrase")

    def tearDown(self):
        self._tmp_dir.cleanup()

    def test_batch_creates_all_records(self):
        items = [
            {"label": "Record A", "kind": "note", "payload": {"value": 1}},
            {"label": "Record B", "kind": "note", "payload": {"value": 2}},
            {"label": "Record C", "kind": "credential", "payload": {"value": 3}},
        ]
        summaries = self.service.batch_upsert(items)
        self.assertEqual(len(summaries), 3)
        self.assertEqual(len(self.service.list_records()), 3)

    def test_batch_payloads_are_individually_retrievable(self):
        items = [
            {"label": "Record A", "kind": "note", "payload": {"value": "alpha"}},
            {"label": "Record B", "kind": "note", "payload": {"value": "bravo"}},
        ]
        summaries = self.service.batch_upsert(items)
        payload_a = self.service.get(summaries[0]["record_id"])
        payload_b = self.service.get(summaries[1]["record_id"])
        self.assertEqual(payload_a, {"value": "alpha"})
        self.assertEqual(payload_b, {"value": "bravo"})

    def test_batch_with_explicit_record_ids_updates_in_place(self):
        first_pass = self.service.batch_upsert(
            [{"label": "Record A", "kind": "note", "payload": {"value": 1}, "record_id": "fixed-id"}]
        )
        record_id = first_pass[0]["record_id"]
        self.assertEqual(record_id, "fixed-id")

        second_pass = self.service.batch_upsert(
            [{"label": "Record A", "kind": "note", "payload": {"value": 2}, "record_id": "fixed-id"}]
        )
        self.assertEqual(second_pass[0]["record_id"], "fixed-id")
        self.assertEqual(len(self.service.list_records()), 1)
        self.assertEqual(self.service.get("fixed-id"), {"value": 2})

    def test_batch_rejects_item_missing_required_fields(self):
        items = [
            {"label": "Record A", "kind": "note", "payload": {"value": 1}},
            {"label": "Record B", "payload": {"value": 2}},  # missing 'kind'
        ]
        with self.assertRaises(VaultServiceError):
            self.service.batch_upsert(items)

    def test_failed_batch_does_not_partially_commit(self):
        items = [
            {"label": "Record A", "kind": "note", "payload": {"value": 1}},
            {"label": "Record B", "payload": {"value": 2}},  # missing 'kind', fails validation
        ]
        with self.assertRaises(VaultServiceError):
            self.service.batch_upsert(items)
        # Neither record should have been written: validation happens before
        # any records are added to the in-memory map that gets saved.
        self.assertEqual(len(self.service.list_records()), 0)

    def test_batch_upsert_requires_unlocked_vault(self):
        self.service.lock()
        with self.assertRaises(VaultServiceError):
            self.service.batch_upsert([{"label": "A", "kind": "note", "payload": {}}])

    def test_large_batch_generates_unique_ids(self):
        items = [
            {"label": f"Record {index}", "kind": "note", "payload": {"index": index}}
            for index in range(50)
        ]
        summaries = self.service.batch_upsert(items)
        record_ids = {summary["record_id"] for summary in summaries}
        self.assertEqual(len(record_ids), 50)


if __name__ == "__main__":
    unittest.main()
