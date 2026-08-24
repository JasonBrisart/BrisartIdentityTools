"""Tests for the shared common/ utilities: atomic writes, hashing, and the
UTC timestamp helpers -- including the utc_now_iso alias whose absence broke
every tool's imports (see docs/CHANGELOG.md 1.0.0 'Fixed')."""
import json
import tempfile
import unittest
from pathlib import Path

from common import timestamps
from common.atomic_io import AtomicWriteError, atomic_write_json, atomic_write_text
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


if __name__ == "__main__":
    unittest.main()
