"""Tests for vault.reports.audit_log."""
import json
import re
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

    # --- Fix 1 (2026-09-10) regression coverage -----------------------
    def test_entry_filename_uses_microsecond_precision(self):
        # Mirrors common/tests/test_common_utils.py's
        # test_microsecond_timestamp_has_more_precision: the filename must
        # embed a microsecond-precision stamp, not just a second-precision
        # one, so same-second events remain distinguishable by timestamp
        # alone (before the random suffix is even considered).
        path = audit_log.record_event(self.audit_dir, "created", "rid-1", "A", "note")
        self.assertRegex(path.name, r"^\d{8}_\d{6}_\d{6}Z_created_rid-1_[0-9a-f]{8}\.json$")

    def test_rapid_successive_events_sort_oldest_first_by_filename(self):
        # Before this fix, two entries written in the same wall-clock second
        # sorted only by their random suffix (list_entries()'s own
        # oldest-first ordering guarantee did not actually hold). Writing
        # several entries back-to-back (well within the same second on any
        # reasonable machine) must still produce filenames that sort in the
        # order they were written.
        paths = [
            audit_log.record_event(self.audit_dir, "created", f"rid-{i}", f"Record {i}", "note")
            for i in range(20)
        ]
        listed = audit_log.list_entries(self.audit_dir)
        self.assertEqual([p.name for p in listed], sorted(p.name for p in paths))
        # And the sorted filename order matches the actual write order.
        self.assertEqual(listed, paths)


if __name__ == "__main__":
    unittest.main()
