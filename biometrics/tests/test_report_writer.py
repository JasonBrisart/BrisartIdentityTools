"""Tests for biometrics.reports.report_writer."""
import json
import tempfile
import unittest
from pathlib import Path
from biometrics.reports import report_writer
from biometrics.reports.report_writer import ReportWriterError


class ReportWriterTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.report_dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_enrollment_report_sorts_modalities(self):
        report = report_writer.build_enrollment_report("alice", "Alice", ["voice", "fingerprint"])
        self.assertEqual(report["modalities_enrolled"], ["fingerprint", "voice"])

    def test_enrollment_report_requires_at_least_one_modality(self):
        with self.assertRaises(ReportWriterError):
            report_writer.build_enrollment_report("alice", "Alice", [])

    def test_verification_report_keeps_only_non_secret_fields(self):
        result = {
            "identity_id": "alice",
            "matched": True,
            "results": [{"modality": "voice", "score": 0.99, "threshold": 0.85,
                         "matched": True, "vector": [1, 2, 3]}],
        }
        report = report_writer.build_verification_report(result)
        self.assertNotIn("vector", report["modality_results"][0])
        self.assertTrue(report["matched"])

    def test_verification_report_requires_identity_and_results(self):
        with self.assertRaises(ReportWriterError):
            report_writer.build_verification_report({"identity_id": "alice"})

    def test_write_report_rejects_bad_format_marker(self):
        with self.assertRaises(ReportWriterError):
            report_writer.write_report(self.report_dir, {"event_type": "x", "identity_id": "y"})

    def test_write_and_list_reports_round_trip(self):
        report = report_writer.build_enrollment_report("bob", "Bob", ["voice"])
        path = report_writer.write_report(self.report_dir, report)
        self.assertEqual(json.loads(path.read_text())["identity_id"], "bob")
        self.assertEqual(len(report_writer.list_reports(self.report_dir, "bob")), 1)

    def test_list_reports_on_missing_dir_returns_empty(self):
        self.assertEqual(report_writer.list_reports(self.report_dir / "nope"), [])


if __name__ == "__main__":
    unittest.main()
