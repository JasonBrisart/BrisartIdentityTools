"""Tests for the shared common/ utilities: atomic writes, hashing, and the
UTC timestamp helpers -- including the utc_now_iso alias whose absence broke
every tool's imports (see docs/CHANGELOG.md 1.0.0 'Fixed').
"""
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from common import timestamps
from common.atomic_io import (
    AtomicWriteError,
    SENSITIVE_FILE_MODE,
    atomic_write_json,
    atomic_write_text,
    warn_if_permissive,
)
from common.hashing import sha256_bytes, sha256_file


class TimestampTests(unittest.TestCase):
    def test_utc_now_iso_alias_exists_and_matches_utc_now(self):
        # The whole 1.0.0 import-crash fix hinges on this alias existing.
        self.assertTrue(hasattr(timestamps, "utc_now_iso"))
        self.assertIs(timestamps.utc_now_iso, timestamps.utc_now)

    def test_utc_now_is_timezone_aware_iso(self):
        value = timestamps.utc_now()
        self.assertTrue(value.endswith("+00:00"))

    def test_iso_timestamps_are_lexically_sortable(self):
        earlier = "2026-08-24T14:25:30+00:00"
        later = "2026-08-24T14:25:31+00:00"
        self.assertLess(earlier, later)

    def test_filename_timestamp_is_path_safe(self):
        stamp = timestamps.filename_timestamp()
        for bad in (":", "+", "/", "\\"):
            self.assertNotIn(bad, stamp)

    def test_microsecond_timestamp_has_more_precision(self):
        stamp = timestamps.microsecond_timestamp()
        self.assertRegex(stamp, r"^\d{8}_\d{6}_\d{6}Z$")


class HashingTests(unittest.TestCase):
    def test_sha256_bytes_matches_known_vector(self):
        self.assertEqual(
            sha256_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_sha256_file_matches_sha256_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blob.bin"
            data = b"hello world" * 1000
            path.write_bytes(data)
            self.assertEqual(sha256_file(path), sha256_bytes(data))

    def test_sha256_file_streams_large_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "big.bin"
            data = b"x" * (2 * 1024 * 1024 + 7)  # > one 1 MiB read chunk
            path.write_bytes(data)
            self.assertEqual(sha256_file(path), sha256_bytes(data))


class AtomicIoTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_atomic_write_text_round_trips(self):
        target = self.tmp / "note.txt"
        atomic_write_text(target, "hello", fsync_dir=False)
        self.assertEqual(target.read_text(), "hello")

    def test_atomic_write_json_round_trips(self):
        target = self.tmp / "data.json"
        atomic_write_json(target, {"b": 2, "a": 1}, fsync_dir=False)
        self.assertEqual(json.loads(target.read_text()), {"a": 1, "b": 2})

    def test_atomic_write_json_sorts_keys(self):
        target = self.tmp / "sorted.json"
        atomic_write_json(target, {"z": 1, "a": 2}, fsync_dir=False)
        self.assertLess(target.read_text().index('"a"'), target.read_text().index('"z"'))

    def test_atomic_write_json_rejects_non_dict(self):
        with self.assertRaises(AtomicWriteError):
            atomic_write_json(self.tmp / "bad.json", ["not", "a", "dict"], fsync_dir=False)

    def test_atomic_write_creates_parent_directories(self):
        target = self.tmp / "nested" / "deep" / "file.txt"
        atomic_write_text(target, "x", fsync_dir=False)
        self.assertTrue(target.is_file())

    def test_write_leaves_no_temp_file_behind(self):
        target = self.tmp / "clean.json"
        atomic_write_json(target, {"ok": True}, fsync_dir=False)
        leftovers = [p for p in self.tmp.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [])


@unittest.skipIf(os.name == "nt", "POSIX permission bits are not enforced on Windows")
class AtomicIoPermissionTests(unittest.TestCase):
    """Fix 1 (2026-09-08): file_mode / warn_if_permissive regression coverage."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _mode_of(self, path: Path) -> int:
        return stat.S_IMODE(path.stat().st_mode)

    def test_atomic_write_text_applies_requested_file_mode(self):
        target = self.tmp / "secret.txt"
        atomic_write_text(target, "shh", fsync_dir=False, file_mode=SENSITIVE_FILE_MODE)
        self.assertEqual(self._mode_of(target), SENSITIVE_FILE_MODE)

    def test_atomic_write_json_applies_requested_file_mode(self):
        target = self.tmp / "secret.json"
        atomic_write_json(target, {"master_key": "wrapped"}, fsync_dir=False,
                          file_mode=SENSITIVE_FILE_MODE)
        self.assertEqual(self._mode_of(target), SENSITIVE_FILE_MODE)

    def test_omitting_file_mode_does_not_force_sensitive_mode(self):
        # atomic_write_* always creates a brand-new temp file and os.replace()s
        # it into place (that is what makes the write atomic), so a target's
        # permissions were never "preserved" across writes even before this
        # fix -- each write's temp file gets the process umask's default
        # permissions. What this fix must NOT do is start forcing
        # SENSITIVE_FILE_MODE onto every write; omitting file_mode must
        # produce the same umask-determined permissions as any other file
        # written directly, not the 0600 used by the vault/keyring call sites.
        target = self.tmp / "ordinary.json"
        atomic_write_json(target, {"v": 1}, fsync_dir=False, file_mode=SENSITIVE_FILE_MODE)
        self.assertEqual(self._mode_of(target), SENSITIVE_FILE_MODE)
        atomic_write_json(target, {"v": 2}, fsync_dir=False)
        baseline = self.tmp / "baseline.json"
        baseline.write_text("{}")
        self.assertEqual(self._mode_of(target), self._mode_of(baseline))

    def test_warn_if_permissive_flags_an_overly_open_file(self):
        target = self.tmp / "open.json"
        atomic_write_json(target, {"v": 1}, fsync_dir=False)
        target.chmod(0o644)
        self.assertTrue(warn_if_permissive(target, label="test file"))

    def test_warn_if_permissive_is_silent_for_a_correctly_restricted_file(self):
        target = self.tmp / "restricted.json"
        atomic_write_json(target, {"v": 1}, fsync_dir=False, file_mode=SENSITIVE_FILE_MODE)
        self.assertFalse(warn_if_permissive(target))

    def test_warn_if_permissive_is_silent_for_a_missing_file(self):
        self.assertFalse(warn_if_permissive(self.tmp / "does_not_exist.json"))


if __name__ == "__main__":
    unittest.main()
