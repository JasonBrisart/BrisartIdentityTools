import math
import struct
import tempfile
import unittest
import wave
import zlib
from pathlib import Path

from core.dsp import (
    apply_window,
    autocorrelation_pitch,
    frame_signal,
    hann_window,
    mfcc,
    next_power_of_two,
    power_spectrum,
    pre_emphasis,
    rms_energy,
    zero_crossing_rate,
)
from core.png import PNGError, read_png_grayscale, write_png_grayscale
from core.wave_tools import WaveError, read_wav_mono, write_wav_mono


class TestCodecAndDSPSupport(unittest.TestCase):
    def _png_chunk(self, tag, payload):
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    def _build_png(self, width, height, depth, colour_type, rows, palette=None):
        raw = bytearray()
        for row in rows:
            raw.append(0)
            raw.extend(row)
        out = b"\x89PNG\r\n\x1a\n"
        out += self._png_chunk(
            b"IHDR",
            struct.pack(">IIBBBBB", width, height, depth, colour_type, 0, 0, 0),
        )
        if palette:
            out += self._png_chunk(b"PLTE", palette)
        out += self._png_chunk(b"IDAT", zlib.compress(bytes(raw)))
        out += self._png_chunk(b"IEND", b"")
        return out

    def _build_wav(self, path, rate, width, channels, frames):
        with wave.open(str(path), "wb") as handle:
            handle.setnchannels(channels)
            handle.setsampwidth(width)
            handle.setframerate(rate)
            handle.writeframes(frames)

    def test_png_reader_supports_rgb_palette_and_rejects_crc_corruption(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            rgb_path = temp / "rgb.png"
            rgb_path.write_bytes(
                self._build_png(
                    3,
                    1,
                    8,
                    2,
                    [[255, 0, 0, 0, 255, 0, 0, 0, 255]],
                )
            )
            self.assertEqual(read_png_grayscale(str(rgb_path))[2], [54, 182, 18])

            palette_path = temp / "palette.png"
            palette_path.write_bytes(
                self._build_png(
                    3,
                    1,
                    8,
                    3,
                    [[0, 1, 2]],
                    palette=bytes([255, 255, 255, 0, 0, 0, 255, 0, 0]),
                )
            )
            self.assertEqual(read_png_grayscale(str(palette_path))[2], [255, 0, 54])

            roundtrip_path = temp / "roundtrip.png"
            write_png_grayscale(str(roundtrip_path), 4, 2, [0, 10, 20, 30, 40, 50, 60, 70])
            self.assertEqual(
                read_png_grayscale(str(roundtrip_path)),
                (4, 2, [0, 10, 20, 30, 40, 50, 60, 70]),
            )

            damaged = bytearray(rgb_path.read_bytes())
            idat_start = damaged.index(b"IDAT") + 4
            damaged[idat_start + 2] ^= 0xFF
            bad_path = temp / "bad.png"
            bad_path.write_bytes(bytes(damaged))
            with self.assertRaises(PNGError):
                read_png_grayscale(str(bad_path))

    def test_wave_reader_and_dsp_pipeline_work_without_third_party_deps(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            wav_path = temp / "voice.wav"
            samples = [math.sin(2 * math.pi * 220 * t / 16000) for t in range(16000)]
            write_wav_mono(str(wav_path), 16000, samples)
            sample_rate, decoded = read_wav_mono(str(wav_path))
            self.assertEqual(sample_rate, 16000)
            self.assertEqual(len(decoded), len(samples))
            self.assertLess(max(abs(a - b) for a, b in zip(samples, decoded)), 0.0001)

            stereo_path = temp / "stereo.wav"
            self._build_wav(
                stereo_path,
                16000,
                2,
                2,
                struct.pack("<hh", 32767, -32768) + struct.pack("<hh", 10000, 10000),
            )
            _, stereo = read_wav_mono(str(stereo_path))
            self.assertAlmostEqual(stereo[0], 0.0, places=3)
            self.assertAlmostEqual(stereo[1], 10000 / 32768.0, places=3)

            frame = apply_window(pre_emphasis(decoded[:400]), hann_window(400))
            coeffs = mfcc(frame, sample_rate, filters=20, coefficients=13)
            self.assertEqual(len(coeffs), 13)
            self.assertTrue(all(math.isfinite(value) for value in coeffs))
            self.assertEqual(frame_signal([1, 2, 3, 4, 5], 4, 2), [[1.0, 2.0, 3.0, 4.0], [3.0, 4.0, 5.0, 0.0]])
            self.assertEqual([round(value, 4) for value in power_spectrum([1.0] * 8)], [8.0, 0.0, 0.0, 0.0, 0.0])
            self.assertAlmostEqual(zero_crossing_rate([1, -1, 1, -1, 1]), 1.0)
            self.assertAlmostEqual(rms_energy([1, -1, 1, -1]), 1.0)
            self.assertTrue(215.0 <= autocorrelation_pitch(decoded, sample_rate) <= 225.0)
            self.assertEqual(next_power_of_two(400), 512)

            empty_path = temp / "empty.wav"
            self._build_wav(empty_path, 16000, 2, 1, b"")
            with self.assertRaises(WaveError):
                read_wav_mono(str(empty_path))


if __name__ == "__main__":
    unittest.main()
