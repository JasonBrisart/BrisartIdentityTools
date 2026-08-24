"""Tests for biometrics.codecs.video and biometrics.features.video_features."""
import tempfile
import unittest
from pathlib import Path

from biometrics.codecs import video
from biometrics.features import video_features
from biometrics.samples import sample_generator


class VideoCodecTests(unittest.TestCase):
    def test_encode_decode_round_trip(self):
        width, height = 4, 4
        frames = [bytes([value] * (width * height)) for value in (10, 20, 30)]
        encoded = video.encode(width, height, frame_rate=5, frames=frames)
        decoded = video.decode(encoded)
        self.assertEqual(decoded["width"], width)
        self.assertEqual(decoded["height"], height)
        self.assertEqual(decoded["frame_rate"], 5)
        self.assertEqual(decoded["frames"], frames)

    def test_rejects_wrong_frame_size(self):
        with self.assertRaises(video.VideoFormatError):
            video.encode(4, 4, 5, [b"\x00" * 10])

    def test_rejects_empty_frame_list(self):
        with self.assertRaises(video.VideoFormatError):
            video.encode(4, 4, 5, [])

    def test_rejects_bad_magic(self):
        with self.assertRaises(video.VideoFormatError):
            video.decode(b"NOTVIDEO" + b"\x00" * 20)

    def test_probe_reports_header_without_reading_frames(self):
        width, height = 4, 4
        frames = [bytes([1] * (width * height))]
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.brvid"
            video.write_video(path, width, height, 5, frames)
            info = video.probe(path)
            self.assertEqual(info["width"], width)
            self.assertEqual(info["height"], height)
            self.assertEqual(info["frame_count"], 1)
            self.assertTrue(info["size_matches_header"])


class VideoFeatureTests(unittest.TestCase):
    def test_extract_from_frames_returns_fixed_length_vector(self):
        width, height = 12, 12
        frames = sample_generator.generate_video_frames("seed-a", width, height, 5)
        vector = video_features.extract_from_frames(width, height, frames)
        self.assertEqual(len(vector), video_features.FEATURE_VECTOR_LENGTH)

    def test_single_frame_has_zero_motion_component(self):
        width, height = 12, 12
        frames = sample_generator.generate_video_frames("seed-b", width, height, 1)
        vector = video_features.extract_from_frames(width, height, frames)
        motion_half = vector[len(vector) // 2:]
        self.assertTrue(all(value == 0.0 for value in motion_half))

    def test_different_seeds_produce_different_vectors(self):
        width, height = 16, 16
        frames_a = sample_generator.generate_video_frames("seed-a", width, height, 6)
        frames_b = sample_generator.generate_video_frames("seed-z", width, height, 6)
        vector_a = video_features.extract_from_frames(width, height, frames_a)
        vector_b = video_features.extract_from_frames(width, height, frames_b)
        self.assertNotEqual(vector_a, vector_b)

    def test_compare_identical_vectors_is_near_one(self):
        width, height = 12, 12
        frames = sample_generator.generate_video_frames("seed-c", width, height, 5)
        vector = video_features.extract_from_frames(width, height, frames)
        self.assertAlmostEqual(video_features.compare(vector, vector), 1.0, places=6)

    def test_compare_rejects_mismatched_lengths(self):
        with self.assertRaises(video_features.VideoFeatureError):
            video_features.compare([1.0, 2.0], [1.0])

    def test_extract_from_video_file_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.brvid"
            sample_generator.write_video_sample(path, "seed-d", width=16, height=16, frame_count=4)
            vector = video_features.extract_from_video(path)
            self.assertEqual(len(vector), video_features.FEATURE_VECTOR_LENGTH)


if __name__ == "__main__":
    unittest.main()
