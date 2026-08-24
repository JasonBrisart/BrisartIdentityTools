"""Round-trip and correctness tests for biometrics.codecs.*"""
import unittest

from biometrics.codecs import dsp, image_tools, pgm, png


class PgmRoundTripTests(unittest.TestCase):
    def test_encode_decode_round_trip(self):
        width, height = 4, 3
        pixels = bytes(range(width * height))
        encoded = pgm.encode(width, height, pixels)
        decoded = pgm.decode(encoded)
        self.assertEqual(decoded["width"], width)
        self.assertEqual(decoded["height"], height)
        self.assertEqual(decoded["pixels"], pixels)

    def test_rejects_wrong_pixel_length(self):
        with self.assertRaises(pgm.PgmFormatError):
            pgm.encode(4, 4, b"\x00" * 10)

    def test_rejects_bad_magic(self):
        with self.assertRaises(pgm.PgmFormatError):
            pgm.decode(b"P6\n1 1\n255\n\x00")

    def test_handles_comments_in_header(self):
        raw = b"P5\n# a comment\n2 2\n255\n\x00\x01\x02\x03"
        decoded = pgm.decode(raw)
        self.assertEqual(decoded["pixels"], b"\x00\x01\x02\x03")


class PngRoundTripTests(unittest.TestCase):
    def test_encode_decode_round_trip(self):
        width, height = 5, 5
        pixels = bytes((i * 7) % 256 for i in range(width * height))
        encoded = png.encode(width, height, pixels)
        decoded = png.decode(encoded)
        self.assertEqual(decoded["width"], width)
        self.assertEqual(decoded["height"], height)
        self.assertEqual(decoded["pixels"], pixels)

    def test_rejects_bad_signature(self):
        with self.assertRaises(png.PngFormatError):
            png.decode(b"not a png")

    def test_rejects_corrupted_crc(self):
        encoded = bytearray(png.encode(2, 2, bytes([0, 1, 2, 3])))
        # Flip a byte inside the first IDAT payload to corrupt its CRC.
        encoded[40] ^= 0xFF
        with self.assertRaises(png.PngFormatError):
            png.decode(bytes(encoded))


class ImageToolsTests(unittest.TestCase):
    def test_crop_center_smaller_than_source(self):
        width, height = 4, 4
        pixels = bytes(range(16))
        new_width, new_height, cropped = image_tools.crop_center(
            width, height, pixels, 2, 2
        )
        self.assertEqual((new_width, new_height), (2, 2))
        self.assertEqual(len(cropped), 4)

    def test_crop_center_pads_when_source_smaller(self):
        width, height = 2, 2
        pixels = bytes([10, 20, 30, 40])
        new_width, new_height, cropped = image_tools.crop_center(
            width, height, pixels, 4, 4
        )
        self.assertEqual((new_width, new_height), (4, 4))
        self.assertEqual(len(cropped), 16)

    def test_resize_nearest_preserves_dimensions(self):
        pixels = bytes(range(16))
        resized = image_tools.resize_nearest(4, 4, pixels, 8, 8)
        self.assertEqual(len(resized), 64)

    def test_normalize_flat_input_unchanged(self):
        flat = bytes([100] * 10)
        self.assertEqual(image_tools.normalize(flat), flat)

    def test_normalize_stretches_range(self):
        pixels = bytes([10, 20, 30])
        normalized = image_tools.normalize(pixels)
        self.assertEqual(min(normalized), 0)
        self.assertEqual(max(normalized), 255)

    def test_block_grid_means_shape(self):
        width, height = 8, 8
        pixels = bytes([50] * (width * height))
        means = image_tools.block_grid_means(width, height, pixels, 4)
        self.assertEqual(len(means), 16)
        for value in means:
            self.assertAlmostEqual(value, 50.0)

    def test_sobel_gradient_flat_image_is_zero(self):
        width, height = 5, 5
        pixels = bytes([128] * (width * height))
        magnitudes = image_tools.sobel_gradient_magnitude(width, height, pixels)
        self.assertTrue(all(value == 0.0 for value in magnitudes))


class DspTests(unittest.TestCase):
    def test_frame_signal_pads_final_frame(self):
        samples = list(range(10))
        frames = dsp.frame_signal(samples, frame_size=4, hop_size=4)
        self.assertEqual(len(frames[-1]), 4)

    def test_zero_crossing_rate_all_positive_is_zero(self):
        frame = [1, 2, 3, 4, 5]
        self.assertEqual(dsp.zero_crossing_rate(frame), 0.0)

    def test_zero_crossing_rate_alternating_is_high(self):
        frame = [1, -1, 1, -1, 1]
        self.assertGreater(dsp.zero_crossing_rate(frame), 0.5)

    def test_short_time_energy_of_silence_is_zero(self):
        self.assertEqual(dsp.short_time_energy([0, 0, 0]), 0.0)

    def test_band_energies_count_matches_request(self):
        energies = dsp.band_energies(list(range(20)), 5)
        self.assertEqual(len(energies), 5)

    def test_normalize_vector_scales_to_unit_peak(self):
        normalized = dsp.normalize_vector([2, -4, 1])
        self.assertEqual(max(abs(value) for value in normalized), 1.0)

    def test_normalize_vector_handles_silence(self):
        self.assertEqual(dsp.normalize_vector([0, 0, 0]), [0, 0, 0])


if __name__ == "__main__":
    unittest.main()
