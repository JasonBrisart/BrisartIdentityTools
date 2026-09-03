"""Tests for biometrics.features.liveness and its integration into
enrollment.py / verification.py.

Uses hand-built frame sequences (not the synthetic sample generator) so the
static-vs-live cases are exact and unambiguous: an all-identical-bytes frame
list is EXACTLY zero motion by construction, and a frame list with a real
pixel-value shift between frames is unambiguously non-zero motion, without
depending on sample_generator's seed-dependent drift (which can itself be
zero for some seeds -- see sample_generator.generate_video_frames).
"""
import secrets
import tempfile
import unittest
from pathlib import Path

from biometrics.codecs import video
from biometrics.engine import enrollment, verification
from biometrics.features.liveness import (
    LivenessError,
    MIN_FRAMES_FOR_LIVENESS,
    assess_liveness,
    compute_motion_energy,
)
from biometrics.samples import sample_generator


WIDTH = HEIGHT = 8


def _static_frames(count=5):
    frame = bytes([100] * (WIDTH * HEIGHT))
    return [frame] * count


def _moving_frames(count=5):
    frames = []
    for index in range(count):
        value = (index * 40) % 256
        frames.append(bytes([value] * (WIDTH * HEIGHT)))
    return frames


class ComputeMotionEnergyTests(unittest.TestCase):
    def test_identical_frames_have_zero_motion(self):
        self.assertEqual(compute_motion_energy(WIDTH, HEIGHT, _static_frames()), 0.0)

    def test_shifting_frames_have_positive_motion(self):
        self.assertGreater(compute_motion_energy(WIDTH, HEIGHT, _moving_frames()), 0.0)

    def test_single_frame_returns_zero_not_an_error(self):
        self.assertEqual(compute_motion_energy(WIDTH, HEIGHT, [_static_frames(1)[0]]), 0.0)

    def test_empty_frame_list_raises(self):
        with self.assertRaises(LivenessError):
            compute_motion_energy(WIDTH, HEIGHT, [])

    def test_mismatched_frame_length_raises(self):
        with self.assertRaises(LivenessError):
            compute_motion_energy(WIDTH, HEIGHT, [bytes([1] * (WIDTH * HEIGHT)), bytes([1] * 4)])


class AssessLivenessTests(unittest.TestCase):
    def test_static_clip_fails_the_gate(self):
        result = assess_liveness(WIDTH, HEIGHT, _static_frames())
        self.assertFalse(result["is_live"])
        self.assertEqual(result["motion_energy"], 0.0)

    def test_moving_clip_passes_the_gate(self):
        result = assess_liveness(WIDTH, HEIGHT, _moving_frames())
        self.assertTrue(result["is_live"])

    def test_custom_threshold_is_respected(self):
        result = assess_liveness(WIDTH, HEIGHT, _moving_frames(), threshold=1000.0)
        self.assertFalse(result["is_live"])

    def test_non_positive_threshold_rejected(self):
        with self.assertRaises(LivenessError):
            assess_liveness(WIDTH, HEIGHT, _moving_frames(), threshold=0.0)

    def test_min_frames_constant_is_two(self):
        # Documents the documented edge case: exactly one frame short of a
        # comparable pair always reports zero motion, never an error.
        self.assertEqual(MIN_FRAMES_FOR_LIVENESS, 2)


class EnrollmentLivenessGateTests(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp_dir.name)
        self.master_key = secrets.token_bytes(32)

    def tearDown(self):
        self._tmp_dir.cleanup()

    def _write_clip(self, frames, name="clip.brvid", frame_rate=5):
        path = self.tmp_path / name
        video.write_video(path, WIDTH, HEIGHT, frame_rate, frames)
        return path

    def test_static_video_enrollment_is_refused_by_default(self):
        clip = self._write_clip(_static_frames())
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.enroll_identity(
                "static-id", "Static", self.master_key, {"video": clip}
            )

    def test_static_video_enrollment_allowed_with_override(self):
        clip = self._write_clip(_static_frames())
        record = enrollment.enroll_identity(
            "static-id-2", "Static", self.master_key, {"video": clip}, allow_static=True
        )
        self.assertIn("video", record["templates"])

    def test_moving_video_enrollment_succeeds_without_override(self):
        clip = self._write_clip(_moving_frames())
        record = enrollment.enroll_identity(
            "moving-id", "Moving", self.master_key, {"video": clip}
        )
        self.assertIn("video", record["templates"])

    def test_liveness_gate_does_not_affect_other_modalities(self):
        fingerprint_path = self.tmp_path / "fp.pgm"
        sample_generator.write_fingerprint_sample(fingerprint_path, "seed-a")
        # No video source at all -- must not raise or require --allow-static.
        record = enrollment.enroll_identity(
            "fp-only", "Fingerprint Only", self.master_key,
            {"fingerprint": fingerprint_path},
        )
        self.assertIn("fingerprint", record["templates"])


class VerificationLivenessGateTests(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp_dir.name)
        self.master_key = secrets.token_bytes(32)
        self.enroll_clip = self.tmp_path / "enroll.brvid"
        video.write_video(self.enroll_clip, WIDTH, HEIGHT, 5, _moving_frames())
        self.record = enrollment.enroll_identity(
            "vid-id", "Video Person", self.master_key, {"video": self.enroll_clip}
        )

    def tearDown(self):
        self._tmp_dir.cleanup()

    def test_static_probe_reports_liveness_failed_not_a_score(self):
        static_clip = self.tmp_path / "probe_static.brvid"
        video.write_video(static_clip, WIDTH, HEIGHT, 5, _static_frames())
        result = verification.verify_modality(
            self.record, "video", static_clip, self.master_key
        )
        self.assertFalse(result["matched"])
        self.assertIn("liveness", result)
        self.assertFalse(result["liveness"]["is_live"])

    def test_static_probe_with_allow_static_gets_a_real_score(self):
        static_clip = self.tmp_path / "probe_static2.brvid"
        video.write_video(static_clip, WIDTH, HEIGHT, 5, _static_frames())
        result = verification.verify_modality(
            self.record, "video", static_clip, self.master_key, allow_static=True
        )
        self.assertNotIn("liveness", result)

    def test_moving_probe_is_scored_normally(self):
        moving_clip = self.tmp_path / "probe_moving.brvid"
        video.write_video(moving_clip, WIDTH, HEIGHT, 5, _moving_frames())
        result = verification.verify_modality(
            self.record, "video", moving_clip, self.master_key
        )
        self.assertIn("liveness", result)
        self.assertTrue(result["liveness"]["is_live"])
        self.assertAlmostEqual(result["score"], 1.0, places=6)

    def test_non_video_modality_never_gets_a_liveness_key(self):
        fingerprint_path = self.tmp_path / "fp.pgm"
        sample_generator.write_fingerprint_sample(fingerprint_path, "seed-b")
        record = enrollment.enroll_identity(
            "fp-verify", "FP", self.master_key, {"fingerprint": fingerprint_path}
        )
        result = verification.verify_modality(
            record, "fingerprint", fingerprint_path, self.master_key
        )
        self.assertNotIn("liveness", result)


if __name__ == "__main__":
    unittest.main()
