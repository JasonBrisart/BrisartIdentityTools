"""Integrity tests for Identity-Bound Packages: sealed storage, recipient
authorization, custody chain tamper-evidence, and open/add/remove flows."""
import secrets
import unittest

from packages import package
from packages.custody import CustodyError
from packages.package import PackageAuthorizationError, PackageError


class PackageCreationTests(unittest.TestCase):
    def setUp(self):
        self.alice_key = secrets.token_bytes(32)
        self.bob_key = secrets.token_bytes(32)

    def test_create_requires_at_least_one_recipient(self):
        with self.assertRaises(PackageError):
            package.create_package("pkg-1", "Alice", {"value": 1}, {})

    def test_create_produces_a_valid_package(self):
        state = package.create_package(
            "pkg-1", "Alice", {"value": 1}, {"alice": ("Alice", self.alice_key)}
        )
        package.validate_package(state)

    def test_payload_is_not_stored_in_plaintext(self):
        import json

        state = package.create_package(
            "pkg-1", "Alice", {"secret": "do-not-leak-me"}, {"alice": ("Alice", self.alice_key)}
        )
        raw_text = json.dumps(state)
        self.assertNotIn("do-not-leak-me", raw_text)

    def test_custody_chain_starts_with_created_entry(self):
        state = package.create_package(
            "pkg-1", "Alice", {"value": 1}, {"alice": ("Alice", self.alice_key)}
        )
        self.assertEqual(state["custody_chain"][0]["action"], "created")
        self.assertEqual(len(state["custody_chain"]), 1)


class PackageOpenTests(unittest.TestCase):
    def setUp(self):
        self.alice_key = secrets.token_bytes(32)
        self.bob_key = secrets.token_bytes(32)
        self.state = package.create_package(
            "pkg-2", "Alice", {"message": "hello"}, {"alice": ("Alice", self.alice_key)}
        )

    def test_correct_recipient_can_open(self):
        payload, updated = package.open_package(self.state, "alice", self.alice_key)
        self.assertEqual(payload, {"message": "hello"})
        self.assertEqual(updated["custody_chain"][-1]["action"], "opened")

    def test_non_recipient_cannot_open(self):
        with self.assertRaises(PackageAuthorizationError):
            package.open_package(self.state, "bob", self.bob_key)

    def test_wrong_master_key_for_real_recipient_cannot_open(self):
        wrong_key = secrets.token_bytes(32)
        with self.assertRaises(PackageAuthorizationError):
            package.open_package(self.state, "alice", wrong_key)

    def test_opening_appends_to_custody_chain_without_mutating_original(self):
        original_length = len(self.state["custody_chain"])
        _, updated = package.open_package(self.state, "alice", self.alice_key)
        self.assertEqual(len(self.state["custody_chain"]), original_length)
        self.assertEqual(len(updated["custody_chain"]), original_length + 1)


class RecipientManagementTests(unittest.TestCase):
    def setUp(self):
        self.alice_key = secrets.token_bytes(32)
        self.bob_key = secrets.token_bytes(32)
        self.carol_key = secrets.token_bytes(32)
        self.state = package.create_package(
            "pkg-3", "Alice", {"value": 42}, {"alice": ("Alice", self.alice_key)}
        )

    def test_add_recipient_requires_authorized_existing_recipient(self):
        with self.assertRaises(PackageAuthorizationError):
            package.add_recipient(
                self.state, "bob", "Bob", self.bob_key, "alice", secrets.token_bytes(32)
            )

    def test_added_recipient_can_open_and_read_same_payload(self):
        updated = package.add_recipient(
            self.state, "bob", "Bob", self.bob_key, "alice", self.alice_key
        )
        payload, _ = package.open_package(updated, "bob", self.bob_key)
        self.assertEqual(payload, {"value": 42})

    def test_cannot_add_duplicate_recipient(self):
        updated = package.add_recipient(
            self.state, "bob", "Bob", self.bob_key, "alice", self.alice_key
        )
        with self.assertRaises(PackageError):
            package.add_recipient(updated, "bob", "Bob Again", self.carol_key, "alice", self.alice_key)

    def test_remove_recipient_revokes_access(self):
        with_bob = package.add_recipient(
            self.state, "bob", "Bob", self.bob_key, "alice", self.alice_key
        )
        without_bob = package.remove_recipient(with_bob, "bob", "alice", self.alice_key)
        with self.assertRaises(PackageAuthorizationError):
            package.open_package(without_bob, "bob", self.bob_key)

    def test_remaining_recipient_still_has_access_after_removal(self):
        with_bob = package.add_recipient(
            self.state, "bob", "Bob", self.bob_key, "alice", self.alice_key
        )
        without_bob = package.remove_recipient(with_bob, "bob", "alice", self.alice_key)
        payload, _ = package.open_package(without_bob, "alice", self.alice_key)
        self.assertEqual(payload, {"value": 42})

    def test_cannot_remove_the_last_recipient(self):
        with self.assertRaises(PackageError):
            package.remove_recipient(self.state, "alice", "alice", self.alice_key)

    def test_removing_recipient_does_not_require_removing_own_access(self):
        with_bob = package.add_recipient(
            self.state, "bob", "Bob", self.bob_key, "alice", self.alice_key
        )
        updated = package.remove_recipient(with_bob, "bob", "bob", self.bob_key)
        payload, _ = package.open_package(updated, "alice", self.alice_key)
        self.assertEqual(payload, {"value": 42})


class CustodyChainIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.alice_key = secrets.token_bytes(32)
        self.state = package.create_package(
            "pkg-4", "Alice", {"value": 1}, {"alice": ("Alice", self.alice_key)}
        )

    def test_validate_package_passes_for_untampered_state(self):
        package.validate_package(self.state)

    def test_tampering_with_custody_entry_action_is_detected(self):
        tampered = dict(self.state)
        tampered["custody_chain"] = [dict(self.state["custody_chain"][0])]
        tampered["custody_chain"][0]["action"] = "opened"
        with self.assertRaises((PackageError, CustodyError)):
            package.validate_package(tampered)

    def test_tampering_with_actor_label_is_detected(self):
        _, updated = package.open_package(self.state, "alice", self.alice_key)
        tampered = dict(updated)
        tampered["custody_chain"] = list(updated["custody_chain"])
        tampered["custody_chain"][-1] = dict(updated["custody_chain"][-1])
        tampered["custody_chain"][-1]["actor_label"] = "Not Alice"
        with self.assertRaises((PackageError, CustodyError)):
            package.validate_package(tampered)

    def test_deleting_a_middle_entry_breaks_the_chain(self):
        with_bob = package.add_recipient(
            self.state, "bob", "Bob", secrets.token_bytes(32), "alice", self.alice_key
        )
        payload_and_state = package.open_package(with_bob, "alice", self.alice_key)
        _, three_entries = payload_and_state
        self.assertEqual(len(three_entries["custody_chain"]), 3)
        tampered = dict(three_entries)
        tampered["custody_chain"] = [
            three_entries["custody_chain"][0],
            three_entries["custody_chain"][2],
        ]
        with self.assertRaises((PackageError, CustodyError)):
            package.validate_package(tampered)

    def test_mismatched_recipients_and_key_slots_is_rejected(self):
        tampered = dict(self.state)
        tampered["key_slots"] = dict(self.state["key_slots"])
        del tampered["key_slots"]["alice"]
        with self.assertRaises(PackageError):
            package.validate_package(tampered)

    def test_verify_chain_rejects_non_list_chain(self):
        # Edge case added 2026-08-24: a hand-edited package with a non-list
        # custody_chain (e.g. an integer) must raise CustodyError, not a raw
        # TypeError. See packages/custody.py's verify_chain docstring/comment.
        from packages.custody import verify_chain
        with self.assertRaises(CustodyError):
            verify_chain(12345)

    def test_verify_chain_rejects_chain_with_non_dict_entry(self):
        from packages.custody import verify_chain
        with self.assertRaises(CustodyError):
            verify_chain([self.state["custody_chain"][0], "not-a-dict-entry"])


if __name__ == "__main__":
    unittest.main()
