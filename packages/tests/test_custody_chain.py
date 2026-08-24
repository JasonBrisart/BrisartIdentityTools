"""Tests for packages.custody: the in-package tamper-evident hash chain,
including the non-list / non-dict hardening from 0.8.2-beta."""
import unittest
from packages import custody
from packages.custody import CustodyError


class CustodyChainTests(unittest.TestCase):
    def test_new_chain_starts_with_a_genesis_created_entry(self):
        chain = custody.new_chain("Alice", "pkg-1")
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0]["action"], "created")
        self.assertEqual(chain[0]["previous_hash"], custody.GENESIS_PREVIOUS_HASH)

    def test_append_returns_a_new_list_without_mutating_the_original(self):
        chain = custody.new_chain("Alice", "pkg-1")
        extended = custody.append(chain, "opened", "Alice")
        self.assertEqual(len(chain), 1)
        self.assertEqual(len(extended), 2)

    def test_a_clean_chain_verifies(self):
        chain = custody.new_chain("Alice", "pkg-1")
        chain = custody.append(chain, "recipient_added", "Alice", {"identity_id": "bob"})
        chain = custody.append(chain, "opened", "Bob")
        self.assertTrue(custody.verify_chain(chain, "pkg-1"))

    def test_each_entry_links_to_the_previous_entry_hash(self):
        chain = custody.new_chain("Alice", "pkg-1")
        chain = custody.append(chain, "opened", "Alice")
        self.assertEqual(chain[1]["previous_hash"], chain[0]["entry_hash"])

    def test_tampering_with_an_action_is_detected(self):
        chain = custody.new_chain("Alice", "pkg-1")
        chain[0] = dict(chain[0])
        chain[0]["action"] = "opened"
        with self.assertRaises(CustodyError):
            custody.verify_chain(chain, "pkg-1")

    def test_tampering_with_actor_label_is_detected(self):
        chain = custody.new_chain("Alice", "pkg-1")
        chain = custody.append(chain, "opened", "Alice")
        chain[1] = dict(chain[1])
        chain[1]["actor_label"] = "Mallory"
        with self.assertRaises(CustodyError):
            custody.verify_chain(chain, "pkg-1")

    def test_deleting_a_middle_entry_breaks_the_chain(self):
        chain = custody.new_chain("Alice", "pkg-1")
        chain = custody.append(chain, "recipient_added", "Alice", {"identity_id": "bob"})
        chain = custody.append(chain, "opened", "Bob")
        broken = [chain[0], chain[2]]
        with self.assertRaises(CustodyError):
            custody.verify_chain(broken, "pkg-1")

    def test_genesis_package_id_mismatch_is_detected(self):
        chain = custody.new_chain("Alice", "pkg-1")
        with self.assertRaises(CustodyError):
            custody.verify_chain(chain, "different-package")

    def test_non_list_chain_raises_custody_error_not_type_error(self):
        # 0.8.2-beta regression: "custody_chain": 123 previously raised a raw
        # TypeError; it must raise CustodyError instead.
        with self.assertRaises(CustodyError):
            custody.verify_chain(123)

    def test_chain_with_a_non_dict_entry_raises_custody_error(self):
        chain = custody.new_chain("Alice", "pkg-1")
        with self.assertRaises(CustodyError):
            custody.verify_chain([chain[0], "not-a-dict"])

    def test_empty_chain_is_rejected(self):
        with self.assertRaises(CustodyError):
            custody.verify_chain([])

    def test_append_to_empty_chain_is_rejected(self):
        with self.assertRaises(CustodyError):
            custody.append([], "opened", "Alice")

    def test_unknown_action_is_rejected(self):
        chain = custody.new_chain("Alice", "pkg-1")
        with self.assertRaises(CustodyError):
            custody.append(chain, "not_a_real_action", "Alice")

    def test_empty_actor_label_is_rejected(self):
        chain = custody.new_chain("Alice", "pkg-1")
        with self.assertRaises(CustodyError):
            custody.append(chain, "opened", "")

    def test_summarize_omits_hashes(self):
        chain = custody.new_chain("Alice", "pkg-1")
        summary = custody.summarize(chain)[0]
        self.assertNotIn("entry_hash", summary)
        self.assertIn("action", summary)


if __name__ == "__main__":
    unittest.main()
