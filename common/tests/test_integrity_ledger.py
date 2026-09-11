"""Tests for common.integrity_ledger: the external, hash-chained checkpoint
ledger used to narrow (not close) the edit-then-revert blind spot shared by
every other tamper-evidence mechanism in this repository.
"""
import tempfile
import unittest
from pathlib import Path

from common import integrity_ledger
from common.integrity_ledger import IntegrityLedgerError


class AppendCheckpointTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)
        self.ledger_path = self.tmp_path / "ledger.json"
        self.target_path = self.tmp_path / "target.json"
        self.target_path.write_text('{"a": 1}')

    def tearDown(self):
        self._tmp.cleanup()

    def test_first_checkpoint_creates_a_fresh_ledger(self):
        entry = integrity_ledger.append_checkpoint(self.ledger_path, self.target_path, "Alice")
        self.assertEqual(entry["previous_hash"], integrity_ledger.GENESIS_PREVIOUS_HASH)
        self.assertEqual(entry["actor_label"], "Alice")
        self.assertTrue(self.ledger_path.is_file())

    def test_second_checkpoint_chains_to_the_first(self):
        first = integrity_ledger.append_checkpoint(self.ledger_path, self.target_path, "Alice")
        second = integrity_ledger.append_checkpoint(self.ledger_path, self.target_path, "Bob")
        self.assertEqual(second["previous_hash"], first["entry_hash"])

    def test_checkpoint_missing_target_raises(self):
        with self.assertRaises(IntegrityLedgerError):
            integrity_ledger.append_checkpoint(self.ledger_path, self.tmp_path / "nope.json")

    def test_unchanged_content_still_appends_a_new_entry(self):
        # An unchanged file is still worth recording -- the timestamp itself
        # is evidence the file was inspected and found unchanged.
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path)
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path)
        self.assertEqual(len(integrity_ledger.all_entries(self.ledger_path)), 2)

    def test_checkpoint_records_correct_sha256_and_size(self):
        entry = integrity_ledger.append_checkpoint(self.ledger_path, self.target_path)
        from common.hashing import sha256_file
        self.assertEqual(entry["sha256"], sha256_file(self.target_path))
        self.assertEqual(entry["size_bytes"], self.target_path.stat().st_size)


class VerifyLedgerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)
        self.ledger_path = self.tmp_path / "ledger.json"
        self.target_path = self.tmp_path / "target.json"
        self.target_path.write_text('{"a": 1}')

    def tearDown(self):
        self._tmp.cleanup()

    def test_empty_ledger_verifies(self):
        self.assertTrue(integrity_ledger.verify_ledger(self.ledger_path))

    def test_intact_multi_entry_ledger_verifies(self):
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path, "Alice")
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path, "Bob")
        self.assertTrue(integrity_ledger.verify_ledger(self.ledger_path))

    def test_tampering_with_an_entry_field_is_detected(self):
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path, "Alice")
        import json
        with open(self.ledger_path) as handle:
            state = json.load(handle)
        state["entries"][0]["actor_label"] = "Mallory (forged after the fact)"
        with open(self.ledger_path, "w") as handle:
            json.dump(state, handle)
        with self.assertRaises(IntegrityLedgerError):
            integrity_ledger.verify_ledger(self.ledger_path)

    def test_deleting_a_middle_entry_breaks_the_chain(self):
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path, "Alice")
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path, "Bob")
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path, "Carol")
        import json
        with open(self.ledger_path) as handle:
            state = json.load(handle)
        del state["entries"][1]
        with open(self.ledger_path, "w") as handle:
            json.dump(state, handle)
        with self.assertRaises(IntegrityLedgerError):
            integrity_ledger.verify_ledger(self.ledger_path)

    def test_wrong_format_marker_is_rejected(self):
        import json
        self.ledger_path.write_text(json.dumps({"format": "not-a-ledger", "entries": []}))
        with self.assertRaises(IntegrityLedgerError):
            integrity_ledger.verify_ledger(self.ledger_path)


class CurrentStatusTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)
        self.ledger_path = self.tmp_path / "ledger.json"
        self.target_path = self.tmp_path / "target.json"
        self.target_path.write_text('{"a": 1}')

    def tearDown(self):
        self._tmp.cleanup()

    def test_unchanged_file_matches_latest_checkpoint(self):
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path)
        status = integrity_ledger.current_status(self.ledger_path, self.target_path)
        self.assertTrue(status["matches_latest_checkpoint"])

    def test_changed_file_does_not_match_latest_checkpoint(self):
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path)
        self.target_path.write_text('{"a": 999, "TAMPERED": true}')
        status = integrity_ledger.current_status(self.ledger_path, self.target_path)
        self.assertFalse(status["matches_latest_checkpoint"])

    def test_never_checkpointed_file_reports_none(self):
        status = integrity_ledger.current_status(self.ledger_path, self.target_path)
        self.assertIsNone(status["matches_latest_checkpoint"])
        self.assertIsNone(status["latest_checkpoint"])

    def test_missing_target_file_reports_none_for_current_hash(self):
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path)
        self.target_path.unlink()
        status = integrity_ledger.current_status(self.ledger_path, self.target_path)
        self.assertIsNone(status["current_sha256"])

    def test_edit_then_revert_straddling_a_checkpoint_is_caught(self):
        # The core scenario this module exists for: if a checkpoint happens
        # to fall INSIDE a tamper window, the mismatch is visible even after
        # the file is reverted to its original bytes.
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path, "Alice")
        self.target_path.write_text('{"a": 999, "TAMPERED": true}')
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path, "Bob (mid-tamper)")
        self.target_path.write_text('{"a": 1}')  # reverted to original bytes
        status = integrity_ledger.current_status(self.ledger_path, self.target_path)
        # Current file again matches the FIRST checkpoint's hash...
        self.assertEqual(status["current_sha256"], integrity_ledger.history_for_path(
            self.ledger_path, self.target_path)[0]["sha256"])
        # ...but does NOT match the most recent (mid-tamper) checkpoint,
        # which is exactly what exposes that something happened in between.
        self.assertFalse(status["matches_latest_checkpoint"])

    def test_edit_then_revert_entirely_between_checkpoints_is_not_caught(self):
        # The documented, honest limitation: if no checkpoint falls inside
        # the tamper window, a perfect revert is indistinguishable from
        # nothing having happened at all.
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path, "Alice")
        original = self.target_path.read_text()
        self.target_path.write_text('{"a": 999, "TAMPERED": true}')
        self.target_path.write_text(original)
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_path, "Alice")
        status = integrity_ledger.current_status(self.ledger_path, self.target_path)
        self.assertTrue(status["matches_latest_checkpoint"])
        entries = integrity_ledger.history_for_path(self.ledger_path, self.target_path)
        self.assertEqual(entries[0]["sha256"], entries[1]["sha256"])


class HistoryAndListTrackedTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)
        self.ledger_path = self.tmp_path / "ledger.json"
        self.target_a = self.tmp_path / "a.json"
        self.target_b = self.tmp_path / "b.json"
        self.target_a.write_text('{"a": 1}')
        self.target_b.write_text('{"b": 1}')

    def tearDown(self):
        self._tmp.cleanup()

    def test_history_for_path_filters_correctly(self):
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_a)
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_b)
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_a)
        history = integrity_ledger.history_for_path(self.ledger_path, self.target_a)
        self.assertEqual(len(history), 2)

    def test_history_for_untracked_path_is_empty(self):
        self.assertEqual(integrity_ledger.history_for_path(self.ledger_path, self.target_a), [])

    def test_list_tracked_paths_is_sorted_and_deduplicated(self):
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_b)
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_a)
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_a)
        tracked = integrity_ledger.list_tracked_paths(self.ledger_path)
        self.assertEqual(tracked, sorted({str(self.target_a), str(self.target_b)}))

    def test_all_entries_returns_every_entry_regardless_of_target(self):
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_a)
        integrity_ledger.append_checkpoint(self.ledger_path, self.target_b)
        self.assertEqual(len(integrity_ledger.all_entries(self.ledger_path)), 2)


if __name__ == "__main__":
    unittest.main()
