import json
import sys
import tempfile
import unittest
from pathlib import Path

LABID_ROOT = Path(__file__).resolve().parents[1]

if str(LABID_ROOT) not in sys.path:
    sys.path.insert(0, str(LABID_ROOT))

import config.settings as settings
import identity.identity_store as identity_store
import reports.report_writer as report_writer

from biometrics.enrollment import enroll_identity
from biometrics.verification import verify_identity
from core.pgm import write_pgm


class TestPlaintextLabIDFlow(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temporary_directory.name)

        self.data_dir = self.base_path / "data"
        self.identity_dir = self.data_dir / "identities"
        self.template_dir = self.data_dir / "templates"
        self.report_dir = self.data_dir / "reports"

        self._patch_data_directories()

        self.enroll_image = self.base_path / "sample_enroll.pgm"
        self.close_image = self.base_path / "sample_close.pgm"

        write_pgm(
            str(self.enroll_image),
            16,
            16,
            self._simple_pattern(16, 16, shift=0),
        )

        write_pgm(
            str(self.close_image),
            16,
            16,
            self._simple_pattern(16, 16, shift=1),
        )

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _patch_data_directories(self):
        settings.DATA_DIR = self.data_dir
        settings.IDENTITY_DIR = self.identity_dir
        settings.TEMPLATE_DIR = self.template_dir
        settings.REPORT_DIR = self.report_dir

        identity_store.IDENTITY_DIR = self.identity_dir
        identity_store.TEMPLATE_DIR = self.template_dir

        report_writer.REPORT_DIR = self.report_dir

        settings.ensure_data_dirs()

    def _simple_pattern(self, width, height, shift=0):
        pixels = []

        center_x = width // 2 + shift
        center_y = height // 2

        for y in range(height):
            for x in range(width):
                distance = abs(x - center_x) + abs(y - center_y)
                value = max(0, min(255, 220 - distance * 18))
                pixels.append(value)

        return pixels

    def _read_json(self, path):
        return json.loads(
            Path(path).read_text(encoding="utf-8")
        )

    def _assert_plaintext_json_file(self, path):
        text = Path(path).read_text(encoding="utf-8")

        forbidden_terms = (
            "encrypted",
            "ciphertext",
            "tag",
            "nonce",
            "salt",
            "password",
            "pbkdf2",
            "hmac",
        )

        lowered = text.lower()

        for term in forbidden_terms:
            self.assertNotIn(
                term,
                lowered,
                f"unexpected encryption-related term found: {term}",
            )

        return text

    def test_enrollment_writes_plaintext_identity_and_template(self):
        result = enroll_identity(
            identity_id="researcher_001",
            display_name="Researcher One",
            image_path=str(self.enroll_image),
            threshold=0.0,
        )

        identity = result["identity"]
        template = result["template"]

        identity_path = identity_store.identity_path("researcher_001")
        template_path = identity_store.template_path("researcher_001")

        self.assertTrue(identity_path.is_file())
        self.assertTrue(template_path.is_file())

        identity_text = self._assert_plaintext_json_file(identity_path)
        template_text = self._assert_plaintext_json_file(template_path)

        self.assertIn("Researcher One", identity_text)
        self.assertIn("researcher_001", identity_text)
        self.assertIn("features", template_text)
        self.assertIn("template_sha256", template_text)

        identity_json = self._read_json(identity_path)
        template_json = self._read_json(template_path)

        self.assertEqual(identity_json["identity_id"], "researcher_001")
        self.assertEqual(identity_json["display_name"], "Researcher One")
        self.assertEqual(identity_json["storage_mode"], "local_json_beta")
        self.assertEqual(template_json["identity_id"], "researcher_001")
        self.assertEqual(
            identity_json["template_sha256"],
            template["template_sha256"],
        )

    def test_verification_writes_plaintext_report(self):
        enroll_identity(
            identity_id="researcher_001",
            display_name="Researcher One",
            image_path=str(self.enroll_image),
            threshold=0.0,
        )

        report = verify_identity(
            identity_id="researcher_001",
            image_path=str(self.close_image),
            threshold=0.0,
        )

        self.assertEqual(report["identity_id"], "researcher_001")
        self.assertEqual(report["result"], "MATCH")
        self.assertEqual(report["storage_mode"], "local_json_beta")

        report_file = Path(report["report_file"])

        self.assertTrue(report_file.is_file())

        report_text = self._assert_plaintext_json_file(report_file)
        report_json = self._read_json(report_file)

        self.assertIn("biometric_verification_beta_report", report_text)
        self.assertEqual(report_json["identity_id"], "researcher_001")
        self.assertEqual(report_json["result"], "MATCH")
        self.assertIn("stored_template_sha256", report_json)
        self.assertIn("candidate_template_sha256", report_json)

    def test_template_tamper_is_detected_by_hash_check(self):
        enroll_identity(
            identity_id="researcher_001",
            display_name="Researcher One",
            image_path=str(self.enroll_image),
            threshold=0.0,
        )

        template_path = identity_store.template_path("researcher_001")
        template_data = self._read_json(template_path)

        template_data["features"]["intensity_grid"][0] = 999

        template_path.write_text(
            json.dumps(
                template_data,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        report = verify_identity(
            identity_id="researcher_001",
            image_path=str(self.close_image),
            threshold=0.0,
        )

        self.assertEqual(
            report["result"],
            "TEMPLATE_INTEGRITY_FAILED",
        )
        self.assertEqual(report["storage_mode"], "local_json_beta")


if __name__ == "__main__":
    unittest.main()