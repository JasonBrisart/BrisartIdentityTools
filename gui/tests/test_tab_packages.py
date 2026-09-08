"""Tests for gui.tabs.tab_packages.PackagesTab -- the Packages-tab slice of
KI-002's remaining gap ("gui/tabs/*.py ... still has no direct coverage").

Scope is limited to the tab's own pure logic: the passphrase-text-to-master-
key stretch (_derive_master_key), the state-presence guard used before every
package operation (_require_state -- only its True branch is exercised here,
since the False branch pops a blocking messagebox.showerror with no user
present to dismiss it), and the recipient list refresh (_refresh_recipients).
Methods that pop a real modal dialog, run a background operation, or write a
package file to disk (_create_package, _add_recipient, _remove_recipient,
_open_package, _verify_custody, _run_demo) are intentionally NOT exercised
here, for the same reason the Vault- and Biometrics-tab test files exclude
their equivalents.

Package fixtures use packages.package.create_package with injected 32-byte
master keys -- fast, keyed-MAC-based sealing (no slow KDF), the same
convention already used throughout packages/tests/.

Requires a real Tk root and skips cleanly on a headless runner with no
display, matching the convention used throughout gui/tests/.
"""
import hashlib
import secrets
import unittest


def _tk_display_available():
    try:
        import tkinter as tk
    except ImportError:
        return False
    try:
        root = tk.Tk()
    except Exception:
        return False
    root.destroy()
    return True


_HAS_DISPLAY = _tk_display_available()


@unittest.skipUnless(_HAS_DISPLAY, "requires a Tk-capable display")
class PackagesTabTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        from gui.tabs.tab_packages import PackagesTab

        self.root = tk.Tk()
        self.root.withdraw()
        self.tab = PackagesTab(self.root)

    def tearDown(self):
        self.root.destroy()

    # -- _derive_master_key ------------------------------------------------
    def test_derive_master_key_is_deterministic(self):
        first = self.tab._derive_master_key("correct horse battery staple")
        second = self.tab._derive_master_key("correct horse battery staple")
        self.assertEqual(first, second)

    def test_derive_master_key_matches_plain_sha256(self):
        text = "some passphrase text"
        expected = hashlib.sha256(text.encode("utf-8")).digest()
        self.assertEqual(self.tab._derive_master_key(text), expected)

    def test_derive_master_key_differs_for_different_input(self):
        first = self.tab._derive_master_key("alice's passphrase")
        second = self.tab._derive_master_key("bob's passphrase")
        self.assertNotEqual(first, second)

    def test_derive_master_key_is_32_bytes(self):
        self.assertEqual(len(self.tab._derive_master_key("x")), 32)

    # -- _require_state ------------------------------------------------------
    def test_require_state_true_when_state_present(self):
        self.tab.state = {"format": "brisart-identity-tools/ibp-package/v1"}
        self.assertTrue(self.tab._require_state())

    # -- _refresh_recipients ---------------------------------------------------
    def test_refresh_recipients_empty_when_state_none(self):
        self.tab.state = None
        self.tab._refresh_recipients()
        self.assertEqual(len(self.tab.tree.get_children()), 0)

    def test_refresh_recipients_populates_rows_from_package_state(self):
        from packages import package as ibp_package

        alice_key = secrets.token_bytes(32)
        bob_key = secrets.token_bytes(32)
        state = ibp_package.create_package(
            "pkg-1", "Alice", {"message": "hello"}, {"alice": ("Alice", alice_key)}
        )
        state = ibp_package.add_recipient(state, "bob", "Bob", bob_key, "alice", alice_key)

        self.tab.state = state
        self.tab._refresh_recipients()
        rows = {self.tab.tree.item(i, "values") for i in self.tab.tree.get_children()}
        self.assertEqual(rows, {("alice", "Alice"), ("bob", "Bob")})

    def test_refresh_recipients_clears_previous_rows_on_refresh(self):
        from packages import package as ibp_package

        alice_key = secrets.token_bytes(32)
        state_a = ibp_package.create_package(
            "pkg-a", "Alice", {"v": 1}, {"alice": ("Alice", alice_key)}
        )
        self.tab.state = state_a
        self.tab._refresh_recipients()
        self.assertEqual(len(self.tab.tree.get_children()), 1)

        # Switching to an empty state must clear the previously listed rows,
        # not append to or leave them behind.
        self.tab.state = None
        self.tab._refresh_recipients()
        self.assertEqual(len(self.tab.tree.get_children()), 0)


if __name__ == "__main__":
    unittest.main()
