"""Tests for vault.reports.audit_log."""
import json
import tempfile
import unittest
from pathlib import Path
from vault.reports import audit_log
from vault.reports.audit_log import AuditLogError


class VaultAuditLogTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.audit_dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_build_entry_shape(self):
        entry = audit_log.build_entry("created", "rid-1", "Label", "note")
        self.assertEqual(entry["action"], "created")
        self.assertEqual(entry["record_id"], "rid-1")

    def test_unknown_action_is_rejected(self):
        with self.assertRaises(AuditLogError):
            audit_log.build_entry("exploded")

    def test_vault_level_events_omit_a_record_id(self):
        path = audit_log.record_event(self.audit_dir, "unlocked")
        stored = json.loads(path.read_text())
        self.assertEqual(stored["record_id"], "")
        # filename falls back to 'vault' when no record id is present
        self.assertIn("_vault_", path.name)

    def test_record_event_writes_readable_json(self):
        path = audit_log.record_event(self.audit_dir, "deleted", "rid-9", "Old", "note")
        self.assertEqual(json.loads(path.read_text())["action"], "deleted")

    def test_write_entry_rejects_bad_format_marker(self):
        with self.assertRaises(AuditLogError):
            audit_log.write_entry(self.audit_dir, {"action": "created"})

    def test_list_entries_filters_by_record_id(self):
        audit_log.record_event(self.audit_dir, "created", "aaa", "A", "note")
        audit_log.record_event(self.audit_dir, "created", "bbb", "B", "note")
        self.assertEqual(len(audit_log.list_entries(self.audit_dir, "aaa")), 1)

    def test_all_lifecycle_actions_are_valid(self):
        for action in ("created", "updated", "deleted", "unlocked", "locked"):
            audit_log.build_entry(action)


if __name__ == "__main__":
    unittest.main()
