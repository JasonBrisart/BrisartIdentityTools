"""Tests for gui.tabs.tab_vault.VaultTab -- the piece of KI-002's remaining
gap ("gui/tabs/*.py ... still has no direct coverage") that this file closes
for the Vault tab specifically.

Scope is deliberately limited to state-inspection and list-refresh logic:
tree selection helpers (_selected_record_id / _selected_file_record_id),
the Records-vs-Files kind filtering in _refresh_list / _refresh_file_list,
_clear_list, and _refresh_path_label. Methods that pop a real modal dialog
(messagebox.showinfo/showerror, TextPromptDialog, RecordDialog -- all of
which call Tkinter's blocking wait_window()) are intentionally NOT
exercised here, since there is no user present in an automated test run to
dismiss them; that would hang the suite rather than test it. Those
click-through workflows (_init_vault, _unlock, _new_record, _view_selected,
_encrypt_selected_paths, _decrypt_selected_bundle, ...) remain an open gap,
consistent with how KI-002's "Next step" already scoped this pass to
regression coverage for existing logic, not full workflow simulation.

Uses the same injected-master-key convention as
vault/tests/test_bulk_file_service.py: a real VaultService bound to a real
(placeholder-keyring) vault file on disk, with the master key set directly
rather than derived through a real passphrase unlock, so these tests run
fast and do not pay BSR2's real ~85-90 second KDF cost. Listing records
does not decrypt anything (VaultService.list_records() only validates
structure and reports public_summary()), so the master key here exists
only to let setup fixtures call service.upsert() to create test records.

Requires a real Tk root (ttk.Treeview cannot be constructed without one)
and skips cleanly on a headless runner with no display, matching the
convention used throughout gui/tests/.
"""
import secrets
import tempfile
import unittest
from pathlib import Path


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
class VaultTabTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        from gui.tabs.tab_vault import VaultTab
        from vault.store.vault_file import VAULT_FORMAT, save_state
        from vault.store.vault_service import VaultService

        self._tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp_dir.name)
        self.vault_path = self.tmp_path / "vault.json"
        save_state(
            self.vault_path,
            {"format": VAULT_FORMAT, "keyring": {"placeholder": True}, "records": {}},
        )
        self.service = VaultService(self.vault_path)
        self.service._master_key = secrets.token_bytes(32)

        self.root = tk.Tk()
        self.root.withdraw()
        self.tab = VaultTab(self.root)
        # Constructor already ran once against the default (non-existent)
        # vault_settings.VAULT_FILE path; override with our real fixture
        # before any test-specific refresh is triggered.
        self.tab.vault_path = self.vault_path
        self.tab.service = self.service

    def tearDown(self):
        self.root.destroy()
        self._tmp_dir.cleanup()

    # -- selection helpers --------------------------------------------------
    def test_selected_record_id_returns_none_when_nothing_selected(self):
        self.assertIsNone(self.tab._selected_record_id())

    def test_selected_record_id_returns_correct_id_when_selected(self):
        self.service.upsert("Wifi Password", "credential", {"v": 1})
        self.tab._refresh_list()
        children = self.tab.tree.get_children()
        self.assertEqual(len(children), 1)
        self.tab.tree.selection_set(children[0])
        record_id = self.tab._selected_record_id()
        summaries = self.service.list_records()
        self.assertEqual(record_id, summaries[0]["record_id"])

    def test_selected_file_record_id_returns_correct_id_when_selected(self):
        self.service.upsert_file_bytes("a-file", b"raw bytes", original_filename="a.bin")
        self.tab._refresh_file_list()
        children = self.tab.file_tree.get_children()
        self.assertEqual(len(children), 1)
        self.tab.file_tree.selection_set(children[0])
        self.assertIsNotNone(self.tab._selected_file_record_id())

    # -- Records tab: kind filtering -----------------------------------------
    def test_clear_list_empties_tree(self):
        self.service.upsert("Note A", "note", {"v": 1})
        self.tab._refresh_list()
        self.assertGreater(len(self.tab.tree.get_children()), 0)
        self.tab._clear_list()
        self.assertEqual(len(self.tab.tree.get_children()), 0)

    def test_refresh_list_shows_note_and_credential_kinds(self):
        self.service.upsert("A Note", "note", {"v": 1})
        self.service.upsert("A Credential", "credential", {"v": 2})
        self.tab._refresh_list()
        labels = {self.tab.tree.item(i, "values")[1] for i in self.tab.tree.get_children()}
        self.assertEqual(labels, {"A Note", "A Credential"})

    def test_refresh_list_excludes_file_bundle_manifest_and_bundle_chunk_kinds(self):
        self.service.upsert_file_bytes("standalone-file", b"data", original_filename="f.bin")
        # kind is a free-text field on vault records; fabricating these two
        # kinds directly (rather than going through BulkFileService) is
        # sufficient to test the tab's own filtering logic in isolation.
        self.service.upsert("A Manifest", "bundle-manifest", {"chunk_record_ids": []})
        self.service.upsert("A Chunk", "bundle-chunk", {"v": 1})
        self.service.upsert("A Real Note", "note", {"v": 1})
        self.tab._refresh_list()
        labels = {self.tab.tree.item(i, "values")[1] for i in self.tab.tree.get_children()}
        self.assertEqual(labels, {"A Real Note"})

    # -- Files sub-tab: kind filtering ---------------------------------------
    def test_refresh_file_list_shows_only_file_and_bundle_manifest_kinds(self):
        self.service.upsert_file_bytes("standalone-file", b"data", original_filename="f.bin")
        self.service.upsert("A Manifest", "bundle-manifest", {"chunk_record_ids": []})
        self.service.upsert("A Note", "note", {"v": 1})
        self.tab._refresh_file_list()
        labels = {self.tab.file_tree.item(i, "values")[1] for i in self.tab.file_tree.get_children()}
        self.assertEqual(labels, {"standalone-file", "A Manifest"})

    def test_refresh_file_list_excludes_bundle_chunk_kind(self):
        self.service.upsert("Some Chunk", "bundle-chunk", {"v": 1})
        self.tab._refresh_file_list()
        self.assertEqual(len(self.tab.file_tree.get_children()), 0)

    # -- path label -----------------------------------------------------------
    def test_refresh_path_label_reports_exists_for_existing_vault(self):
        self.tab._refresh_path_label()
        self.assertIn("exists", self.tab._path_label.cget("text"))

    def test_refresh_path_label_reports_not_created_yet_for_missing_vault(self):
        self.tab.vault_path = self.tmp_path / "does_not_exist.json"
        self.tab._refresh_path_label()
        self.assertIn("not created yet", self.tab._path_label.cget("text"))


if __name__ == "__main__":
    unittest.main()
