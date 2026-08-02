import tempfile
import unittest
from pathlib import Path

import config.settings as settings
import identity.identity_store as identity_store
import reports.report_writer as report_writer
from biometrics.enrollment import enroll_identity
from biometrics.verification import verify_identity
from core.wave_tools import write_wav_mono
from samples.sample_generator import (
    _face_like_pattern,
    _far_pattern,
    _fingerprint_pattern,
    _voice_pattern,
)
from core.png import write_png_grayscale
from core.video import write_avi_grayscale


class TestMultimodalFlow(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temporary_directory.name)
        self.data_dir = self.base_path / "data"
        self.identity_dir = self.data_dir / "identities"
        self.template_dir = self.data_dir / "templates"
        self.report_dir = self.data_dir / "reports"
        self._patch_data_directories()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _patch_data_directories(self):
        settings.DATA_DIR = self.data_dir
        settings.IDENTITY_DIR = self.identity_dir
        settings.TEMPLATE_DIR = self.template_dir
        settings.REPORT_DIR = self.report_dir
        settings.SAMPLE_DIR = self.data_dir / "samples"

        identity_store.IDENTITY_DIR = self.identity_dir
        identity_store.TEMPLATE_DIR = self.template_dir
        report_writer.REPORT_DIR = self.report_dir
        settings.ensure_data_dirs()

    def test_face_png_voice_wav_and_fingerprint_png_end_to_end(self):
        face_enroll = self.base_path / "face_enroll.png"
        face_close = self.base_path / "face_close.png"
        face_far = self.base_path / "face_far.png"
        write_png_grayscale(str(face_enroll), 96, 96, _face_like_pattern(96, 96, shift=0, contrast=0))
        write_png_grayscale(str(face_close), 96, 96, _face_like_pattern(96, 96, shift=2, contrast=3))
        write_png_grayscale(str(face_far), 96, 96, _far_pattern(96, 96))

        face_identity = enroll_identity("face_user", "Face User", str(face_enroll), modality="face")
        self.assertEqual(face_identity["identity"]["biometric_modality"], "face")
        self.assertEqual(face_identity["identity"]["default_threshold"], 0.94)
        self.assertEqual(verify_identity("face_user", str(face_close), modality="face")["result"], "MATCH")
        self.assertEqual(verify_identity("face_user", str(face_far), modality="face")["result"], "NO_MATCH")

        voice_enroll = self.base_path / "voice_enroll.wav"
        voice_close = self.base_path / "voice_close.wav"
        voice_far = self.base_path / "voice_far.wav"
        write_wav_mono(str(voice_enroll), 16000, _voice_pattern(16000, 220.0, 440.0, wobble=1.5))
        write_wav_mono(str(voice_close), 16000, _voice_pattern(16000, 223.0, 446.0, wobble=1.6))
        write_wav_mono(str(voice_far), 16000, _voice_pattern(16000, 330.0, 660.0, wobble=4.5))

        voice_identity = enroll_identity("voice_user", "Voice User", str(voice_enroll), modality="voice")
        self.assertEqual(voice_identity["identity"]["biometric_modality"], "voice")
        self.assertEqual(voice_identity["identity"]["default_threshold"], 0.94)
        self.assertEqual(verify_identity("voice_user", str(voice_close), modality="voice")["result"], "MATCH")
        self.assertEqual(verify_identity("voice_user", str(voice_far), modality="voice")["result"], "NO_MATCH")

        finger_enroll = self.base_path / "finger_enroll.png"
        finger_close = self.base_path / "finger_close.png"
        finger_far = self.base_path / "finger_far.png"
        write_png_grayscale(str(finger_enroll), 120, 120, _fingerprint_pattern(120, 120, shift=0, bend=2.0, mode="arch"))
        write_png_grayscale(str(finger_close), 120, 120, _fingerprint_pattern(120, 120, shift=1, bend=2.2, mode="arch"))
        write_png_grayscale(str(finger_far), 120, 120, _fingerprint_pattern(120, 120, shift=0, bend=0.0, mode="whorl"))

        finger_identity = enroll_identity("finger_user", "Finger User", str(finger_enroll), modality="fingerprint")
        self.assertEqual(finger_identity["identity"]["biometric_modality"], "fingerprint")
        self.assertEqual(finger_identity["identity"]["default_threshold"], 0.975)
        self.assertEqual(verify_identity("finger_user", str(finger_close), modality="fingerprint")["result"], "MATCH")
        far_report = verify_identity("finger_user", str(finger_far), modality="fingerprint")
        self.assertEqual(far_report["result"], "NO_MATCH")
        self.assertEqual(far_report["threshold"], 0.975)

    def _video(self, name, frames):
        path = self.base_path / name
        write_avi_grayscale(str(path), 96, 96, frames)
        return str(path)

    def _live_frames(self, count, shift_base, contrast):
        return [
            _face_like_pattern(96, 96, shift=shift_base + (index % 3), contrast=contrast)
            for index in range(count)
        ]

    def test_video_faceid_end_to_end_with_liveness_gate(self):
        enroll_video = self._video("video_enroll.avi", self._live_frames(10, 0, 0))
        close_video = self._video("video_close.avi", self._live_frames(10, 1, 3))
        far_video = self._video(
            "video_far.avi",
            [_far_pattern(96, 96, shift=index % 3) for index in range(10)],
        )
        # A recording of a still photo: identical frames, so motion is zero.
        single = _face_like_pattern(96, 96, shift=0, contrast=0)
        replay_video = self._video("video_replay.avi", [list(single) for _ in range(10)])

        enrolled = enroll_identity("video_user", "Video User", enroll_video, modality="video")
        self.assertEqual(enrolled["identity"]["biometric_modality"], "video")
        self.assertTrue(enrolled["liveness"]["passed"])

        close_report = verify_identity("video_user", close_video, modality="video")
        self.assertEqual(close_report["result"], "MATCH")
        self.assertTrue(close_report["liveness"]["passed"])

        far_report = verify_identity("video_user", far_video, modality="video")
        self.assertEqual(far_report["result"], "NO_MATCH")
        self.assertTrue(far_report["liveness"]["passed"])

        # The replay scores a near-perfect face match, so only the liveness gate
        # can stop it. This is the assertion that keeps liveness a gate rather
        # than a score component.
        replay_report = verify_identity("video_user", replay_video, modality="video")
        self.assertEqual(replay_report["result"], "LIVENESS_FAILED")
        self.assertFalse(replay_report["liveness"]["passed"])
        self.assertGreaterEqual(replay_report["similarity_score"], replay_report["threshold"])

        # And the override still reports the raw score for the same file.
        bypassed = verify_identity(
            "video_user", replay_video, modality="video", require_live=False
        )
        self.assertEqual(bypassed["result"], "MATCH")

    def test_static_video_enrollment_is_refused_unless_allowed(self):
        single = _face_like_pattern(96, 96, shift=0, contrast=0)
        replay_video = self._video("static_enroll.avi", [list(single) for _ in range(8)])

        with self.assertRaises(ValueError) as context:
            enroll_identity("static_user", "Static User", replay_video, modality="video")
        self.assertIn("video enrollment rejected", str(context.exception))

        allowed = enroll_identity(
            "static_user", "Static User", replay_video,
            modality="video", require_live=False,
        )
        self.assertFalse(allowed["liveness"]["passed"])

    def test_video_modality_inferred_from_avi_extension(self):
        enroll_video = self._video("inferred.avi", self._live_frames(8, 0, 0))

        enrolled = enroll_identity("inferred_user", "Inferred User", enroll_video)

        self.assertEqual(enrolled["identity"]["biometric_modality"], "video")

    def test_modality_mismatch_is_rejected(self):
        face_enroll = self.base_path / "face_enroll.png"
        voice_probe = self.base_path / "voice.wav"
        write_png_grayscale(str(face_enroll), 96, 96, _face_like_pattern(96, 96, shift=0, contrast=0))
        write_wav_mono(str(voice_probe), 16000, _voice_pattern(16000, 220.0, 440.0, wobble=1.5))

        enroll_identity("mixed_user", "Mixed User", str(face_enroll), modality="face")
        with self.assertRaises(Exception) as context:
            verify_identity("mixed_user", str(voice_probe), modality="voice")
        self.assertIn("enrolled for modality face", str(context.exception))


if __name__ == "__main__":
    unittest.main()
