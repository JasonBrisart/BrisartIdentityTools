"""Regression tests for identity-bound package integrity and validation.

Covers three classes of defect:

1. Digest comparisons used ``==``, which short-circuits at the first differing
   character and leaks match length through timing. They now go through
   ``crypto.digests_equal``, which uses ``hmac.compare_digest``.
2. ``verify_signature`` and the payload integrity check raised ``TypeError`` on
   a package whose ``signature`` or ``payload_hash`` was missing, instead of
   reporting the package as invalid. ``verify_chain`` raised ``KeyError`` on a
   truncated custody event.
3. ``create_package`` accepted an empty recipient list, an unknown mode, and an
   out-of-range threshold, producing packages that no identity could open.
"""

import json
import tempfile
import unittest
from pathlib import Path

import crypto
import identity as identity_module
import package as package_module
from crypto import digests_equal, hash_text
from custody import verify_chain
from identity import IdentityProfile
from package import (
    create_package,
    identity_authorized,
    load_package,
    open_package,
    save_package,
    verify_signature,
)

PASSPHRASE = "open-sesame"
VOICE_PHRASE = "my voice is my key"


def build_identity(identity_id="analyst", name="Analyst"):
    return IdentityProfile(
        {
            "identity_id": identity_id,
            "name": name,
            "passphrase_hash": hash_text(PASSPHRASE),
            "voice_hash": hash_text(VOICE_PHRASE),
            "face_hash": None,
            "fingerprint_hash": None,
        }
    )


class RedirectedStorage(unittest.TestCase):
    """Base class that points every write at a temporary directory."""

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temporary_directory.name)

        self._saved_package_dir = package_module.PACKAGE_DIR
        self._saved_identity_dir = identity_module.IDENTITY_DIR

        package_module.PACKAGE_DIR = self.base_path / "packages"
        identity_module.IDENTITY_DIR = self.base_path / "identities"

    def tearDown(self):
        package_module.PACKAGE_DIR = self._saved_package_dir
        identity_module.IDENTITY_DIR = self._saved_identity_dir
        self.temporary_directory.cleanup()

    def make_package(self, message="classified findings", **kwargs):
        options = {
            "recipients": ["analyst"],
            "message": message,
            "actor": "analyst",
            "location": "lab",
        }
        options.update(kwargs)
        return create_package(**options)


class TestDigestsEqual(unittest.TestCase):
    def test_identical_digests_match(self):
        digest = hash_text("correct horse battery staple")
        self.assertTrue(digests_equal(digest, digest))

    def test_different_digests_do_not_match(self):
        self.assertFalse(
            digests_equal(hash_text("a"), hash_text("b"))
        )

    def test_none_operand_returns_false_instead_of_raising(self):
        digest = hash_text("a")
        self.assertFalse(digests_equal(digest, None))
        self.assertFalse(digests_equal(None, digest))
        self.assertFalse(digests_equal(None, None))

    def test_non_string_operand_returns_false(self):
        digest = hash_text("a")
        for other in (42, b"bytes", ["list"], {"k": "v"}):
            with self.subTest(other=other):
                self.assertFalse(digests_equal(digest, other))

    def test_hash_text_is_stable_for_non_ascii(self):
        self.assertEqual(
            crypto.hash_text("café"),
            crypto.hash_text("café"),
        )

    def test_hash_text_differs_for_different_input(self):
        self.assertNotEqual(
            crypto.hash_text("cafe"),
            crypto.hash_text("café"),
        )


class TestPackageLifecycle(RedirectedStorage):
    def test_created_package_verifies_end_to_end(self):
        path = self.make_package()
        package = load_package(path)

        self.assertTrue(verify_signature(package))
        self.assertTrue(verify_chain(package))

    def test_correct_factors_open_the_package(self):
        path = self.make_package()

        plaintext = open_package(
            path,
            build_identity(),
            passphrase=PASSPHRASE,
            voice_phrase=VOICE_PHRASE,
            actor="analyst",
            location="lab",
        )

        self.assertEqual(plaintext, "classified findings")

    def test_wrong_passphrase_is_denied(self):
        path = self.make_package()

        with self.assertRaises(PermissionError):
            open_package(
                path,
                build_identity(),
                passphrase="wrong",
                voice_phrase=VOICE_PHRASE,
                actor="analyst",
                location="lab",
            )

    def test_wrong_voice_phrase_is_denied(self):
        path = self.make_package()

        with self.assertRaises(PermissionError):
            open_package(
                path,
                build_identity(),
                passphrase=PASSPHRASE,
                voice_phrase="wrong",
                actor="analyst",
                location="lab",
            )

    def test_unauthorized_identity_is_denied(self):
        path = self.make_package()

        with self.assertRaises(PermissionError):
            open_package(
                path,
                build_identity(identity_id="stranger", name="Stranger"),
                passphrase=PASSPHRASE,
                voice_phrase=VOICE_PHRASE,
                actor="stranger",
                location="lab",
            )

    def test_tampered_payload_is_rejected(self):
        path = self.make_package()
        package = load_package(path)
        package["payload"] = "swapped findings"
        save_package(package, path)

        with self.assertRaises(ValueError):
            open_package(
                path,
                build_identity(),
                passphrase=PASSPHRASE,
                voice_phrase=VOICE_PHRASE,
                actor="analyst",
                location="lab",
            )

    def test_missing_signature_is_invalid_not_a_crash(self):
        package = load_package(self.make_package())
        package.pop("signature", None)

        self.assertFalse(verify_signature(package))

    def test_tampered_signature_is_invalid(self):
        package = load_package(self.make_package())
        package["signature"] = "0" * 64

        self.assertFalse(verify_signature(package))

    def test_round_trip_through_disk_preserves_verification(self):
        original_path = self.make_package()
        package = load_package(original_path)

        copy_path = self.base_path / "roundtrip.ibp"
        save_package(package, copy_path)
        reloaded = load_package(copy_path)

        self.assertTrue(verify_signature(reloaded))
        self.assertTrue(verify_chain(reloaded))
        self.assertEqual(reloaded["payload"], package["payload"])

    def test_non_ascii_payload_survives_the_round_trip(self):
        path = self.make_package(message="findings: café ✓")

        plaintext = open_package(
            path,
            build_identity(),
            passphrase=PASSPHRASE,
            voice_phrase=VOICE_PHRASE,
            actor="analyst",
            location="lab",
        )

        self.assertEqual(plaintext, "findings: café ✓")

    def test_package_is_json_serializable(self):
        package = load_package(self.make_package())
        json.dumps(package)


class TestCreatePackageValidation(RedirectedStorage):
    def test_empty_recipient_list_is_rejected(self):
        with self.assertRaises(ValueError):
            self.make_package(recipients=[])

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            self.make_package(mode="SOMETIMES")

    def test_non_string_message_is_rejected(self):
        with self.assertRaises(ValueError):
            self.make_package(message=None)

    def test_threshold_above_recipient_count_is_rejected(self):
        with self.assertRaises(ValueError):
            self.make_package(
                recipients=["a", "b"],
                mode="THRESHOLD",
                required=3,
            )

    def test_threshold_below_one_is_rejected(self):
        with self.assertRaises(ValueError):
            self.make_package(
                recipients=["a", "b"],
                mode="THRESHOLD",
                required=0,
            )

    def test_valid_threshold_is_accepted(self):
        package = load_package(
            self.make_package(
                recipients=["a", "b", "c"],
                mode="THRESHOLD",
                required=2,
            )
        )

        self.assertEqual(
            package["recipient_policy"]["required"],
            2,
        )

    def test_single_recipient_string_is_normalized_to_a_list(self):
        package = load_package(self.make_package(recipients="analyst"))

        self.assertEqual(
            package["recipient_policy"]["recipients"],
            ["analyst"],
        )


class TestIdentityAuthorized(unittest.TestCase):
    def test_missing_recipient_policy_denies_instead_of_raising(self):
        self.assertFalse(
            identity_authorized({}, build_identity())
        )

    def test_null_recipient_list_denies_instead_of_raising(self):
        self.assertFalse(
            identity_authorized(
                {"recipient_policy": {"recipients": None}},
                build_identity(),
            )
        )

    def test_listed_recipient_is_authorized(self):
        self.assertTrue(
            identity_authorized(
                {"recipient_policy": {"recipients": ["analyst"]}},
                build_identity(),
            )
        )


class TestCustodyChainValidation(unittest.TestCase):
    def test_truncated_event_is_invalid_not_a_crash(self):
        malformed = {
            "custody_chain": [{"action": "PACKAGE_CREATED"}]
        }

        self.assertFalse(verify_chain(malformed))

    def test_broken_link_is_detected(self):
        package = {
            "custody_chain": [
                {
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "action": "PACKAGE_CREATED",
                    "actor": "analyst",
                    "location": "lab",
                    "previous_hash": None,
                    "event_hash": "0" * 64,
                }
            ]
        }

        self.assertFalse(verify_chain(package))

    def test_empty_chain_is_trivially_valid(self):
        self.assertTrue(verify_chain({"custody_chain": []}))


class TestNoImportSideEffects(unittest.TestCase):
    def test_storage_directories_are_not_created_at_import_time(self):
        # Importing these modules used to call mkdir at module scope, so merely
        # importing the package left untracked identities/, packages/ and logs/
        # directories in the working tree.
        for module in (identity_module, package_module):
            source = Path(module.__file__).read_text(encoding="utf-8")
            module_level_mkdir = [
                line
                for line in source.splitlines()
                if ".mkdir(" in line and not line.startswith((" ", "\t"))
            ]
            with self.subTest(module=module.__name__):
                self.assertEqual(module_level_mkdir, [])


if __name__ == "__main__":
    unittest.main()
