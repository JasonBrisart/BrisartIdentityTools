"""Tests for packages.audit: the external, append-only package audit trail."""
import json
import tempfile
import unittest
from pathlib import Path
from packages import audit
from packages.audit import PackageAuditError


class PackageAuditTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.audit_dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_build_entry_has_expected_shape(self):
        entry = audit.build_entry("created", "pkg-1", "Alice")
        self.assertEqual(entry["action"], "created")
        self.assertEqual(entry["package_id"], "pkg-1")
        self.assertEqual(entry["actor_label"], "Alice")
        self.assertIn("recorded_at", entry)

    def test_unknown_action_is_rejected(self):
        with self.assertRaises(PackageAuditError):
            audit.build_entry("teleported", "pkg-1")

    def test_empty_package_id_is_rejected(self):
        with self.assertRaises(PackageAuditError):
            audit.build_entry("created", "")

    def test_record_event_writes_a_readable_file(self):
        path = audit.record_event(self.audit_dir, "opened", "pkg-1", "Bob")
        self.assertTrue(path.is_file())
        stored = json.loads(path.read_text())
        self.assertEqual(stored["action"], "opened")

    def test_write_entry_rejects_bad_format_marker(self):
        with self.assertRaises(PackageAuditError):
            audit.write_entry(self.audit_dir, {"action": "created", "package_id": "pkg-1"})

    def test_list_entries_filters_by_package_id(self):
        audit.record_event(self.audit_dir, "created", "alpha", "A")
        audit.record_event(self.audit_dir, "created", "beta", "B")
        only_alpha = audit.list_entries(self.audit_dir, "alpha")
        self.assertEqual(len(only_alpha), 1)

    def test_list_entries_on_missing_directory_returns_empty(self):
        self.assertEqual(audit.list_entries(self.audit_dir / "nope"), [])

    def test_open_denied_and_custody_violation_are_valid_actions(self):
        audit.build_entry("open_denied", "pkg-1")
        audit.build_entry("custody_violation_detected", "pkg-1")


if __name__ == "__main__":
    unittest.main()
