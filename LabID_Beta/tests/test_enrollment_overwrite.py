"""Regression tests for re-enrollment protection.

``enroll_identity`` wrote the identity record and biometric template with no
existence check, so enrolling an id that already existed silently replaced both
and destroyed the only stored copy of that identity's template. Re-enrollment
now requires an explicit opt-in.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

import config.settings as settings
from biometrics.enrollment import enroll_identity
from samples.sample_generator import generate_samples


class TestEnrollmentOverwrite(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temporary_directory.name)

        # Redirect every storage location at the settings module so the test
        # never touches the repository's own data directory.
        self._saved = {
            name: getattr(settings, name)
            for name in (
                "DATA_DIR",
                "IDENTITY_DIR",
                "TEMPLATE_DIR",
                "REPORT_DIR",
                "SAMPLE_DIR",
            )
        }

        settings.DATA_DIR = self.base_path / "data"
        settings.IDENTITY_DIR = settings.DATA_DIR / "identities"
        settings.TEMPLATE_DIR = settings.DATA_DIR / "templates"
        settings.REPORT_DIR = settings.DATA_DIR / "reports"
        settings.SAMPLE_DIR = settings.DATA_DIR / "samples"
        settings.ensure_data_dirs()

        self.sample_files = generate_samples(
            output_dir=str(self.base_path / "samples")
        )
        self.enroll_image = self.sample_files[0]
        self.other_image = self.sample_files[2]

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(settings, name, value)
        self.temporary_directory.cleanup()

    def _identity_file(self, identity_id):
        return settings.IDENTITY_DIR / f"{identity_id}.json"

    def test_first_enrollment_succeeds(self):
        result = enroll_identity(
            identity_id="jason",
            display_name="Jason B",
            image_path=self.enroll_image,
        )

        self.assertEqual(
            result["identity"]["identity_id"],
            "jason",
        )
        self.assertTrue(self._identity_file("jason").is_file())

    def test_reenrollment_without_overwrite_is_rejected(self):
        enroll_identity(
            identity_id="jason",
            display_name="Jason B",
            image_path=self.enroll_image,
        )

        with self.assertRaises(FileExistsError):
            enroll_identity(
                identity_id="jason",
                display_name="Someone Else",
                image_path=self.other_image,
            )

    def test_rejected_reenrollment_preserves_original_record(self):
        enroll_identity(
            identity_id="jason",
            display_name="Jason B",
            image_path=self.enroll_image,
        )
        original = json.loads(
            self._identity_file("jason").read_text(encoding="utf-8")
        )

        with self.assertRaises(FileExistsError):
            enroll_identity(
                identity_id="jason",
                display_name="Someone Else",
                image_path=self.other_image,
            )

        current = json.loads(
            self._identity_file("jason").read_text(encoding="utf-8")
        )
        self.assertEqual(original, current)
        self.assertEqual(current["display_name"], "Jason B")

    def test_overwrite_flag_allows_reenrollment(self):
        enroll_identity(
            identity_id="jason",
            display_name="Jason B",
            image_path=self.enroll_image,
        )

        result = enroll_identity(
            identity_id="jason",
            display_name="Jason Renewed",
            image_path=self.other_image,
            overwrite=True,
        )

        self.assertEqual(
            result["identity"]["display_name"],
            "Jason Renewed",
        )

    def test_error_message_names_the_existing_identity(self):
        enroll_identity(
            identity_id="jason",
            display_name="Jason B",
            image_path=self.enroll_image,
        )

        with self.assertRaises(FileExistsError) as caught:
            enroll_identity(
                identity_id="jason",
                display_name="Someone Else",
                image_path=self.other_image,
            )

        message = str(caught.exception)
        self.assertIn("jason", message)
        self.assertIn("Jason B", message)

    def test_invalid_identity_id_is_rejected_before_any_write(self):
        with self.assertRaises(ValueError):
            enroll_identity(
                identity_id="ja/son",
                display_name="Jason B",
                image_path=self.enroll_image,
            )

        self.assertEqual(
            list(settings.IDENTITY_DIR.glob("*.json")),
            [],
        )

    def test_samples_are_written_to_the_requested_directory(self):
        target = self.base_path / "explicit_samples"
        written = generate_samples(output_dir=str(target))

        self.assertEqual(len(written), 3)
        for path_text in written:
            with self.subTest(path=path_text):
                self.assertTrue(Path(path_text).is_file())
                self.assertEqual(
                    Path(path_text).parent.resolve(),
                    target.resolve(),
                )

    def test_samples_do_not_land_in_the_working_directory(self):
        working_directory = self.base_path / "cwd"
        working_directory.mkdir()
        previous = os.getcwd()
        os.chdir(working_directory)
        try:
            generate_samples(
                output_dir=str(self.base_path / "samples_again")
            )
        finally:
            os.chdir(previous)

        self.assertEqual(
            list(working_directory.glob("*.pgm")),
            [],
        )


if __name__ == "__main__":
    unittest.main()
