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
        """Assert a file carries no sealed payload.

        Applies to identity records and verification reports, which stay
        readable on purpose. Biometric templates are sealed and must not be
        checked with this; see ``_assert_sealed_template_file``.
        """
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

    def _assert_sealed_template_file(self, path):
        """Assert a template file is sealed and leaks no feature data.

        The inverse of the identity-record check: a template on disk must be
        BSR2 ciphertext, and the feature values a match is computed against must
        not appear in it.
        """
        text = Path(path).read_text(encoding="utf-8")
        stored = json.loads(text)

        self.assertEqual(
            stored["format"],
            identity_store.TEMPLATE_FILE_FORMAT,
        )
        self.assertIn("sealed_template", stored)

        envelope = stored["sealed_template"]
        for field in ("algorithm", "ciphertext", "nonce", "salt", "tag"):
            self.assertIn(field, envelope)

        # Feature data is what an attacker wants; none of it should be readable.
        self.assertNotIn("intensity_grid", text)
        self.assertNotIn("features", text)
        self.assertNotIn("template_sha256", text)

        return stored

    def test_enrollment_writes_readable_identity_and_sealed_template(self):
        result = enroll_identity(
            identity_id="researcher_001",
            display_name="Researcher One",
            source_path=str(self.enroll_image),
            threshold=0.0,
        )

        identity = result["identity"]
        template = result["template"]

        identity_path = identity_store.identity_path("researcher_001")
        template_path = identity_store.template_path("researcher_001")

        self.assertTrue(identity_path.is_file())
        self.assertTrue(template_path.is_file())

        identity_text = self._assert_plaintext_json_file(identity_path)
        self._assert_sealed_template_file(template_path)

        self.assertIn("Researcher One", identity_text)
        self.assertIn("researcher_001", identity_text)

        identity_json = self._read_json(identity_path)

        self.assertEqual(identity_json["identity_id"], "researcher_001")
        self.assertEqual(identity_json["display_name"], "Researcher One")
        self.assertEqual(identity_json["storage_mode"], "local_json_beta")
        self.assertEqual(identity_json, identity)
        self.assertEqual(
            identity_json["template_sha256"],
            template["template_sha256"],
        )

    def test_sealed_template_round_trips_through_the_store(self):
        result = enroll_identity(
            identity_id="researcher_001",
            display_name="Researcher One",
            source_path=str(self.enroll_image),
            threshold=0.0,
        )

        loaded = identity_store.load_template("researcher_001")

        self.assertEqual(
            loaded["template_sha256"],
            result["template"]["template_sha256"],
        )
        self.assertIn("features", loaded)

    def test_template_sealed_for_one_identity_cannot_be_moved_to_another(self):
        enroll_identity(
            identity_id="researcher_001",
            display_name="Researcher One",
            source_path=str(self.enroll_image),
            threshold=0.0,
        )
        enroll_identity(
            identity_id="researcher_002",
            display_name="Researcher Two",
            source_path=str(self.close_image),
            threshold=0.0,
        )

        # Copy the first identity's sealed template over the second's, keeping
        # the second's identity id in the wrapper. The envelope is bound to the
        # identity it was sealed for, so it must refuse to open.
        first = self._read_json(identity_store.template_path("researcher_001"))
        second_path = identity_store.template_path("researcher_002")
        second = self._read_json(second_path)
        second["sealed_template"] = first["sealed_template"]

        second_path.write_text(
            json.dumps(second, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        with self.assertRaises(identity_store.IdentityStoreError):
            identity_store.load_template("researcher_002")

    def test_verification_writes_plaintext_report(self):
        enroll_identity(
            identity_id="researcher_001",
            display_name="Researcher One",
            source_path=str(self.enroll_image),
            threshold=0.0,
        )

        report = verify_identity(
            identity_id="researcher_001",
            source_path=str(self.close_image),
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

    def test_template_tamper_is_detected_by_the_envelope(self):
        """A flipped byte in a sealed template must fail authentication.

        Stronger than the old plaintext hash check this replaces: tampering is
        caught by the BSR2 tag before any feature data is parsed, so a forged
        template never reaches the matcher at all.
        """
        enroll_identity(
            identity_id="researcher_001",
            display_name="Researcher One",
            source_path=str(self.enroll_image),
            threshold=0.0,
        )

        template_path = identity_store.template_path("researcher_001")
        stored = self._read_json(template_path)

        ciphertext = stored["sealed_template"]["ciphertext"]
        flipped = ("ff" if ciphertext[:2] != "ff" else "00") + ciphertext[2:]
        stored["sealed_template"]["ciphertext"] = flipped

        template_path.write_text(
            json.dumps(stored, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        with self.assertRaises(identity_store.IdentityStoreError):
            identity_store.load_template("researcher_001")


if __name__ == "__main__":
    unittest.main()
