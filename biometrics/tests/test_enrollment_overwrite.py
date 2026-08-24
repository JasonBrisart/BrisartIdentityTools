"""Tests covering re-enrollment / template overwrite behavior.

set_template must replace a modality's template without disturbing any other
modality already on the record, and without mutating the caller's original
record object in place.
"""
import secrets
import tempfile
import unittest
from pathlib import Path

from biometrics.engine import enrollment
from biometrics.identity.identity_record import enrolled_modalities
from biometrics.identity.identity_store import IdentityStore
from biometrics.samples import sample_generator


class EnrollmentOverwriteTests(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp_dir.name)
        self.master_key = secrets.token_bytes(32)
        self.fingerprint_path_a = self.tmp_path / "fp_a.pgm"
        self.fingerprint_path_b = self.tmp_path / "fp_b.pgm"
        sample_generator.write_fingerprint_sample(self.fingerprint_path_a, "seed-a")
        sample_generator.write_fingerprint_sample(self.fingerprint_path_b, "seed-b")

    def tearDown(self):
        self._tmp_dir.cleanup()

    def test_enroll_modality_does_not_mutate_original_record(self):
        record = enrollment.create_identity("id-1", "Label", self.master_key)
        original_templates = record["templates"]
        updated = enrollment.enroll_modality(
            record, "fingerprint", self.fingerprint_path_a, self.master_key
        )
        # The original record's templates dict must be unchanged; only the
        # returned copy has the new template.
        self.assertEqual(original_templates, {})
        self.assertIn("fingerprint", updated["templates"])

    def test_re_enrolling_a_modality_replaces_its_template(self):
        record = enrollment.create_identity("id-2", "Label", self.master_key)
        record = enrollment.enroll_modality(
            record, "fingerprint", self.fingerprint_path_a, self.master_key
        )
        first_envelope = record["templates"]["fingerprint"]
        record = enrollment.enroll_modality(
            record, "fingerprint", self.fingerprint_path_b, self.master_key
        )
        second_envelope = record["templates"]["fingerprint"]
        self.assertNotEqual(
            first_envelope["ciphertext"], second_envelope["ciphertext"]
        )
        self.assertEqual(enrolled_modalities(record), ["fingerprint"])

    def test_enrolling_a_second_modality_preserves_the_first(self):
        record = enrollment.create_identity("id-3", "Label", self.master_key)
        record = enrollment.enroll_modality(
            record, "fingerprint", self.fingerprint_path_a, self.master_key
        )
        first_envelope = record["templates"]["fingerprint"]

        video_path = self.tmp_path / "clip.brvid"
        sample_generator.write_video_sample(video_path, "seed-vid", width=12, height=12, frame_count=4)
        record = enrollment.enroll_modality(record, "video", video_path, self.master_key)

        self.assertEqual(record["templates"]["fingerprint"], first_envelope)
        self.assertEqual(enrolled_modalities(record), ["fingerprint", "video"])

    def test_store_save_overwrites_existing_identity_file(self):
        store = IdentityStore(self.tmp_path / "identities")
        record = enrollment.enroll_identity(
            "id-4", "Label", self.master_key, {"fingerprint": self.fingerprint_path_a}
        )
        store.save(record)
        updated_record = enrollment.enroll_modality(
            record, "fingerprint", self.fingerprint_path_b, self.master_key
        )
        store.save(updated_record)
        reloaded = store.load("id-4")
        self.assertEqual(
            reloaded["templates"]["fingerprint"],
            updated_record["templates"]["fingerprint"],
        )


if __name__ == "__main__":
    unittest.main()
