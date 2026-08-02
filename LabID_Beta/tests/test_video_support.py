"""Video codec, template and liveness-gate tests.

The AVI reader is checked against bytes assembled by hand in the test rather
than only against this package's own writer, so a matching bug in both would
still be caught.
"""

import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.video import (  # noqa: E402
    VideoError,
    probe_avi_grayscale,
    read_avi_grayscale_frames,
    write_avi_grayscale,
)
from core.video_features import (  # noqa: E402
    MIN_LIVENESS_MOTION,
    VideoTemplateError,
    create_video_template,
    liveness_assessment,
)


def _gradient_frame(width, height, offset=0):
    return [(x + y + offset) % 256 for y in range(height) for x in range(width)]


def _handmade_avi(width, height, frames):
    """Build a minimal uncompressed 8-bit AVI without using our writer."""
    stride = (width + 3) & ~3

    palette = b"".join(struct.pack("<BBBB", i, i, i, 0) for i in range(256))
    bitmap_info = struct.pack(
        "<IiiHHIIiiII",
        40, width, height, 1, 8, 0, stride * height, 0, 0, 256, 0,
    )
    strf = b"strf" + struct.pack("<I", len(bitmap_info) + len(palette))
    strf += bitmap_info + palette

    stream_header = struct.pack(
        "<4s4sIHHIIIIIIIIhhhh",
        b"vids", b"DIB ", 0, 0, 0, 0, 1, 10, 0, len(frames),
        stride * height, 0xFFFFFFFF, 0, 0, 0, width, height,
    )
    strh = b"strh" + struct.pack("<I", len(stream_header)) + stream_header

    strl_payload = b"strl" + strh + strf
    strl = b"LIST" + struct.pack("<I", len(strl_payload)) + strl_payload

    main_header = struct.pack(
        "<IIIIIIIIIIIIIII",
        66666, 0, 0, 0, len(frames), 0, 1, 0, width, height, 0, 0, 0, 0, 0,
    )
    avih = b"avih" + struct.pack("<I", len(main_header)) + main_header

    hdrl_payload = b"hdrl" + avih + strl
    hdrl = b"LIST" + struct.pack("<I", len(hdrl_payload)) + hdrl_payload

    movi_payload = b"movi"
    for frame in frames:
        rows = []
        # Bottom-up rows, because raw_height above is positive.
        for y in range(height - 1, -1, -1):
            row = bytes(frame[y * width:(y + 1) * width])
            rows.append(row + b"\x00" * (stride - width))
        payload = b"".join(rows)
        chunk = b"00db" + struct.pack("<I", len(payload)) + payload
        if len(payload) % 2:
            chunk += b"\x00"
        movi_payload += chunk

    movi = b"LIST" + struct.pack("<I", len(movi_payload)) + movi_payload

    body = b"AVI " + hdrl + movi
    return b"RIFF" + struct.pack("<I", len(body)) + body


class AviCodecTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.temp_dir = Path(self._temp.name)

    def tearDown(self):
        self._temp.cleanup()

    def test_reads_handmade_avi_bytes(self):
        width, height = 12, 9
        frames = [_gradient_frame(width, height, offset) for offset in (0, 40)]
        path = self.temp_dir / "handmade.avi"
        path.write_bytes(_handmade_avi(width, height, frames))

        read_width, read_height, read_frames = read_avi_grayscale_frames(str(path))

        self.assertEqual((read_width, read_height), (width, height))
        self.assertEqual(len(read_frames), 2)
        self.assertEqual(read_frames[0], frames[0])
        self.assertEqual(read_frames[1], frames[1])

    def test_write_then_read_round_trips_exactly(self):
        width, height = 17, 5
        frames = [_gradient_frame(width, height, offset) for offset in (0, 7, 90)]
        path = self.temp_dir / "written.avi"

        write_avi_grayscale(str(path), width, height, frames, frames_per_second=20)
        read_width, read_height, read_frames = read_avi_grayscale_frames(str(path))

        self.assertEqual((read_width, read_height), (width, height))
        self.assertEqual(read_frames, frames)

    def test_odd_width_padding_round_trips(self):
        # A width of 13 needs 3 padding bytes per row; getting the stride wrong
        # shears the image instead of failing loudly.
        width, height = 13, 4
        frames = [_gradient_frame(width, height), _gradient_frame(width, height, 3)]
        path = self.temp_dir / "odd.avi"

        write_avi_grayscale(str(path), width, height, frames)
        _, _, read_frames = read_avi_grayscale_frames(str(path))

        self.assertEqual(read_frames, frames)

    def test_max_frames_limits_decoding(self):
        width, height = 8, 8
        frames = [_gradient_frame(width, height, offset) for offset in range(6)]
        path = self.temp_dir / "many.avi"
        write_avi_grayscale(str(path), width, height, frames)

        _, _, read_frames = read_avi_grayscale_frames(str(path), max_frames=2)

        self.assertEqual(len(read_frames), 2)

    def test_probe_reports_frame_count(self):
        width, height = 10, 6
        frames = [_gradient_frame(width, height, offset) for offset in range(4)]
        path = self.temp_dir / "probe.avi"
        write_avi_grayscale(str(path), width, height, frames)

        self.assertEqual(probe_avi_grayscale(str(path)), (width, height, 4))

    def test_rejects_non_avi_file(self):
        path = self.temp_dir / "not_video.bin"
        path.write_bytes(zlib.compress(b"definitely not an AVI"))

        with self.assertRaises(VideoError):
            read_avi_grayscale_frames(str(path))

    def test_rejects_truncated_file(self):
        path = self.temp_dir / "tiny.avi"
        path.write_bytes(b"RIFF")

        with self.assertRaises(VideoError):
            read_avi_grayscale_frames(str(path))

    def test_rejects_missing_file(self):
        with self.assertRaises(VideoError):
            read_avi_grayscale_frames(str(self.temp_dir / "absent.avi"))

    def test_writer_rejects_inconsistent_frame_sizes(self):
        path = self.temp_dir / "bad.avi"
        with self.assertRaises(VideoError):
            write_avi_grayscale(str(path), 8, 8, [[0] * 64, [0] * 9])


class VideoTemplateTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.temp_dir = Path(self._temp.name)
        self.width = 40
        self.height = 40

    def tearDown(self):
        self._temp.cleanup()

    def _moving_frames(self, count=8, step=6):
        return [
            _gradient_frame(self.width, self.height, index * step)
            for index in range(count)
        ]

    def _static_frames(self, count=8):
        single = _gradient_frame(self.width, self.height)
        return [list(single) for _ in range(count)]

    def _write(self, name, frames):
        path = self.temp_dir / name
        write_avi_grayscale(str(path), self.width, self.height, frames)
        return str(path)

    def test_template_is_deterministic(self):
        path = self._write("stable.avi", self._moving_frames())

        first = create_video_template(path)
        second = create_video_template(path)

        self.assertEqual(first["template_sha256"], second["template_sha256"])

    def test_template_records_frame_and_motion_metadata(self):
        path = self._write("meta.avi", self._moving_frames(count=10))
        template = create_video_template(path)
        features = template["features"]

        self.assertEqual(features["frame_count"], 10)
        self.assertEqual(features["frame_width"], self.width)
        self.assertEqual(features["frame_height"], self.height)
        self.assertGreater(features["motion_mean"], 0.0)
        self.assertEqual(template["source_format"], "AVI uncompressed DIB")

    def test_single_frame_video_is_rejected(self):
        path = self.temp_dir / "one.avi"
        write_avi_grayscale(
            str(path), self.width, self.height,
            [_gradient_frame(self.width, self.height)],
        )

        with self.assertRaises(VideoTemplateError):
            create_video_template(str(path))

    def test_static_recording_fails_liveness(self):
        path = self._write("static.avi", self._static_frames())
        assessment = liveness_assessment(create_video_template(path))

        self.assertFalse(assessment["passed"])
        self.assertEqual(assessment["motion_mean"], 0.0)
        self.assertIn("static", assessment["reason"])

    def test_moving_recording_passes_liveness(self):
        path = self._write("moving.avi", self._moving_frames(step=12))
        assessment = liveness_assessment(create_video_template(path))

        self.assertTrue(assessment["passed"])
        self.assertGreaterEqual(assessment["motion_mean"], MIN_LIVENESS_MOTION)

    def test_key_frame_selection_caps_at_configured_count(self):
        path = self._write("long.avi", self._moving_frames(count=40, step=5))
        template = create_video_template(path)

        self.assertEqual(template["features"]["frame_count"], 40)
        self.assertLessEqual(len(template["key_frame_indexes"]), 8)
        self.assertEqual(
            len(template["key_frame_indexes"]),
            template["features"]["key_frame_count"],
        )


if __name__ == "__main__":
    unittest.main()
