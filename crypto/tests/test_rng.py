"""Tests for crypto.rng.ManagedGenerator / new_generator.

Fast: seeds from secrets.token_bytes and expands via BSR2's sponge DRBG; no
KDF involved.
"""
import unittest

from crypto.errors import Bsr2IntegrationError
from crypto.rng import ManagedGenerator, new_generator


class NewGeneratorTests(unittest.TestCase):
    def test_new_generator_returns_a_usable_generator(self):
        rng = new_generator("test-purpose")
        self.assertTrue(hasattr(rng, "generate"))

    def test_new_generator_rejects_empty_purpose(self):
        with self.assertRaises(Bsr2IntegrationError):
            new_generator("")

    def test_new_generator_rejects_non_string_purpose(self):
        with self.assertRaises(Bsr2IntegrationError):
            new_generator(123)


class GenerateTests(unittest.TestCase):
    def setUp(self):
        self.rng = new_generator("generate-test")

    def test_generate_returns_the_requested_length(self):
        output = self.rng.generate(64, b"additional-input")
        self.assertEqual(len(output), 64)

    def test_generate_rejects_non_positive_length(self):
        with self.assertRaises(Bsr2IntegrationError):
            self.rng.generate(0, b"additional")

    def test_generate_rejects_empty_additional_input(self):
        with self.assertRaises(Bsr2IntegrationError):
            self.rng.generate(32, b"")

    def test_different_additional_input_yields_different_output(self):
        a = self.rng.generate(32, b"context-a")
        b = self.rng.generate(32, b"context-b")
        self.assertNotEqual(a, b)

    def test_two_generators_produce_independent_streams(self):
        # Each generator seeds from fresh OS entropy, so two generators built
        # for the same purpose should not produce the same first block.
        first = new_generator("same-purpose").generate(32, b"x")
        second = new_generator("same-purpose").generate(32, b"x")
        self.assertNotEqual(first, second)


class PersonalizationTests(unittest.TestCase):
    def test_direct_construction_rejects_short_personalization(self):
        with self.assertRaises(Bsr2IntegrationError):
            ManagedGenerator(b"short")

    def test_direct_construction_rejects_non_bytes_personalization(self):
        with self.assertRaises(Bsr2IntegrationError):
            ManagedGenerator("not-bytes-and-long-enough-string")


if __name__ == "__main__":
    unittest.main()
