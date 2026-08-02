"""Regression tests for identity id validation.

``safe_identity_id`` used to strip disallowed characters instead of rejecting
them, so "ja/son", "ja son" and "ja*son" all collapsed to "jason". The id is
also used to build the record and template filenames, which meant two distinct
identities silently shared one file and one biometric template.
"""

import unittest

from identity.identity_record import safe_identity_id


class TestSafeIdentityId(unittest.TestCase):
    def test_valid_ids_pass_through_unchanged(self):
        for candidate in (
            "jason",
            "JASON",
            "jason_b",
            "jason-b",
            "lab01",
            "a",
        ):
            with self.subTest(candidate=candidate):
                self.assertEqual(
                    safe_identity_id(candidate),
                    candidate,
                )

    def test_surrounding_whitespace_is_trimmed(self):
        self.assertEqual(safe_identity_id("  jason  "), "jason")

    def test_disallowed_characters_are_rejected_not_stripped(self):
        for candidate in (
            "ja/son",
            "ja son",
            "ja*son",
            "ja.son",
            "ja:son",
            "jason!",
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    safe_identity_id(candidate)

    def test_path_traversal_is_rejected(self):
        for candidate in (
            "../../etc/passwd",
            "..",
            "../jason",
            "/absolute",
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    safe_identity_id(candidate)

    def test_ids_that_used_to_collide_no_longer_can(self):
        # All three of these previously normalized to "jason".
        self.assertEqual(safe_identity_id("jason"), "jason")
        for colliding in ("ja/son", "ja son", "ja*son"):
            with self.subTest(candidate=colliding):
                with self.assertRaises(ValueError):
                    safe_identity_id(colliding)

    def test_empty_and_whitespace_only_are_rejected(self):
        for candidate in ("", "   ", "\t", "\n"):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    safe_identity_id(candidate)

    def test_non_string_is_rejected(self):
        for candidate in (None, 42, ["jason"], {"id": "jason"}):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    safe_identity_id(candidate)

    def test_overlong_id_is_rejected(self):
        with self.assertRaises(ValueError):
            safe_identity_id("a" * 129)

        self.assertEqual(
            safe_identity_id("a" * 128),
            "a" * 128,
        )

    def test_error_message_names_the_invalid_characters(self):
        with self.assertRaises(ValueError) as caught:
            safe_identity_id("ja/son")

        self.assertIn("/", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
