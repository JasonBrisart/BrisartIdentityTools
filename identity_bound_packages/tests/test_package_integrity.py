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

Identities here are built with an injected random master key rather than a
passphrase. A BSR2 passphrase derivation takes roughly a minute, and this suite
runs on five Python versions in CI, so deriving per test would push the run into
hours. Passphrase and recovery-code unlocking are covered in
``test_identity_keyring.py``, which pays that cost once.
"""

import json
import secrets
import tempfile
import unittest
from pathlib import Path

import crypto
import identity as identity_module
import package as package_module
import verification as verification_module
from brisart_bsr2.errors import Bsr2IntegrationError
from crypto import digests_equal, hash_text
from custody import verify_chain
from identity import IdentityProfile, build_identity_state
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


def build_identity(
    identity_id="analyst",
    name="Analyst",
    master_key=None,
    voice_phrase=VOICE_PHRASE,
):
    """Return an unlocked identity bound to a fresh random master key.

    No keyring is attached: these tests never unlock by passphrase, they adopt
    the master key directly.
    """
    master_key = master_key or secrets.token_bytes(32)

    state = build_identity_state(
        name=name,
        master_key=master_key,
        keyring_state=None,
        voice_phrase=voice_phrase,
        identity_id=identity_id,
    )

    profile = IdentityProfile(state)
    profile.adopt_master_key(master_key)
    return profile


class RedirectedStorage(unittest.TestCase):
    """Base class that points every write at a temporary directory."""

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temporary_directory.name)

        self._saved_package_dir = package_module.PACKAGE_DIR
        self._saved_identity_dir = identity_module.IDENTITY_DIR

        package_module.PACKAGE_DIR = self.base_path / "packages"
        identity_module.IDENTITY_DIR = self.base_path / "identities"

        # One identity reused across a test, so the master key that sealed a
        # package is the same one that opens it.
        self.identity = build_identity()

        # Passphrase verification would cost a full BSR2 derivation per call.
        # The factor logic itself is covered in test_identity_keyring.py.
        self._saved_verify_passphrase = verification_module.verify_passphrase
        verification_module.verify_passphrase = (
            lambda identity, candidate: candidate == PASSPHRASE
        )

    def tearDown(self):
        verification_module.verify_passphrase = self._saved_verify_passphrase
        package_module.PACKAGE_DIR = self._saved_package_dir
        identity_module.IDENTITY_DIR = self._saved_identity_dir
        self.temporary_directory.cleanup()

    def make_package(self, message="classified findings", **kwargs):
        options = {
            "recipients": [self.identity.identity_id],
            "message": message,
            "actor": "analyst",
            "location": "lab",
            "unlocked_identities": [self.identity],
        }
        options.update(kwargs)
        return create_package(**options)

    def open_as(self, path, identity=None, **kwargs):
        options = {
            "passphrase": PASSPHRASE,
            "voice_phrase": VOICE_PHRASE,
            "actor": "analyst",
            "location": "lab",
        }
        options.update(kwargs)
        return open_package(path, identity or self.identity, **options)


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

    def test_payload_is_not_stored_in_cleartext(self):
        path = self.make_package(message="classified findings")
        raw = Path(path).read_text(encoding="utf-8")

        self.assertNotIn("classified findings", raw)
        self.assertIn("sealed_payload", raw)

    def test_correct_factors_open_the_package(self):
        path = self.make_package()

        plaintext = self.open_as(path)

        self.assertEqual(plaintext, "classified findings")

    def test_wrong_passphrase_is_denied(self):
        path = self.make_package()

        with self.assertRaises(PermissionError):
            self.open_as(path, passphrase="wrong")

    def test_wrong_voice_phrase_is_denied(self):
        path = self.make_package()

        with self.assertRaises(PermissionError):
            self.open_as(path, voice_phrase="wrong")

    def test_locked_identity_cannot_open_a_package(self):
        path = self.make_package()
        self.identity.lock()

        # This suite stubs verify_passphrase with a plain string comparison, so
        # unlike production it does not unlock the identity as a side effect.
        # The locked identity therefore survives the passphrase check and fails
        # at the first factor that needs the master key, which is the condition
        # under test: no factor is verifiable while locked.
        with self.assertRaises(Bsr2IntegrationError):
            self.open_as(path)

    def test_unauthorized_identity_is_denied(self):
        path = self.make_package()
        stranger = build_identity(identity_id="stranger", name="Stranger")

        with self.assertRaises(PermissionError):
            self.open_as(path, identity=stranger, actor="stranger")

    def test_tampered_payload_is_rejected(self):
        path = self.make_package()
        package = load_package(path)
        ciphertext = package["sealed_payload"]["ciphertext"]
        package["sealed_payload"]["ciphertext"] = (
            "ff" if ciphertext[:2] != "ff" else "00"
        ) + ciphertext[2:]
        save_package(package, path)

        with self.assertRaises(ValueError):
            self.open_as(path)

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
        self.assertEqual(
            reloaded["sealed_payload"],
            package["sealed_payload"],
        )

    def test_non_ascii_payload_survives_the_round_trip(self):
        path = self.make_package(message="findings: café ✓")

        plaintext = self.open_as(path)

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

    def test_missing_unlocked_identities_is_rejected(self):
        with self.assertRaises(ValueError):
            create_package(
                recipients=[self.identity.identity_id],
                message="text",
                actor="analyst",
                location="lab",
            )

    def test_recipient_without_a_supplied_key_is_rejected(self):
        with self.assertRaises(ValueError):
            self.make_package(
                recipients=[self.identity.identity_id, "absent-recipient"],
            )

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
        second = build_identity(identity_id="b", name="B")
        third = build_identity(identity_id="c", name="C")

        package = load_package(
            self.make_package(
                recipients=[
                    self.identity.identity_id,
                    second.identity_id,
                    third.identity_id,
                ],
                mode="THRESHOLD",
                required=2,
                unlocked_identities=[self.identity, second, third],
            )
        )

        self.assertEqual(
            package["recipient_policy"]["required"],
            2,
        )

    def test_single_recipient_string_is_normalized_to_a_list(self):
        package = load_package(
            self.make_package(recipients=self.identity.identity_id)
        )

        self.assertEqual(
            package["recipient_policy"]["recipients"],
            [self.identity.identity_id],
        )


class TestIdentityAuthorized(RedirectedStorage):
    def test_missing_recipient_policy_denies_instead_of_raising(self):
        self.assertFalse(
            identity_authorized({}, self.identity)
        )

    def test_null_recipient_list_denies_instead_of_raising(self):
        self.assertFalse(
            identity_authorized(
                {"recipient_policy": {"recipients": None}},
                self.identity,
            )
        )

    def test_listed_recipient_is_authorized(self):
        self.assertTrue(
            identity_authorized(
                {
                    "recipient_policy": {
                        "recipients": [self.identity.identity_id]
                    }
                },
                self.identity,
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
