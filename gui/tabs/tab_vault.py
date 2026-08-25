"""The Vault tab: init/unlock/lock a vault, manage JSON records, and
encrypt/decrypt arbitrary files, folders, or drives (any size, chunked
transparently past BSR2's single-envelope limit)."""
import json
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from gui.core.constants import APP_TITLE
from gui.core.busy import run_in_background
from gui.widgets.dialogs import RecordDialog, TextPromptDialog, TextViewDialog
from gui.widgets.path_panel import PathSelectionPanel
from vault.config import settings as vault_settings
from vault.store.vault_file import VaultFileError, vault_exists
from vault.store.vault_service import VaultService, VaultServiceError
from vault.store.bulk_file_service import BulkFileService


class VaultTab(ttk.Frame):
    """Init/unlock/lock a vault, create/view/delete JSON records, and (new)
    encrypt/decrypt arbitrary files, folders, or drives -- any combination,
    any size, chunked transparently past BSR2's single-envelope limit."""

    def __init__(self, master):
        super().__init__(master, padding=12)
        self.service = None
        self.vault_path = vault_settings.VAULT_FILE
        self._build_widgets()
        self._refresh_path_label()
        self._refresh_list()

    def _build_widgets(self):
        top = ttk.Frame(self)
        top.pack(fill="x", pady=(0, 8))
        ttk.Button(top, text="Choose Vault File...", command=self._choose_path).pack(side="left")
        self._path_label = ttk.Label(top, text="")
        self._path_label.pack(side="left", padx=8)

        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(0, 8))
        ttk.Button(actions, text="Init Vault", command=self._init_vault).pack(side="left")
        ttk.Button(actions, text="Unlock", command=self._unlock).pack(side="left", padx=4)
        ttk.Button(actions, text="Lock", command=self._lock).pack(side="left", padx=4)
        ttk.Button(actions, text="Refresh", command=self._refresh_list).pack(side="left", padx=4)
        self._status_label = ttk.Label(actions, text="locked")
        self._status_label.pack(side="right")

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)
        self._build_records_subtab(notebook)
        self._build_files_subtab(notebook)

    # -- records sub-tab (unchanged JSON-record behavior) -- #
    def _build_records_subtab(self, notebook):
        tab = ttk.Frame(notebook, padding=8)
        notebook.add(tab, text="Records")

        columns = ("record_id", "label", "kind", "updated_at")
        self.tree = ttk.Treeview(tab, columns=columns, show="headings", selectmode="browse")
        for col, width in zip(columns, (140, 220, 100, 180)):
            self.tree.heading(col, text=col.replace("_", " ").title())
            self.tree.column(col, width=width)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda _e: self._view_selected())

        record_actions = ttk.Frame(tab)
        record_actions.pack(fill="x", pady=(8, 0))
        ttk.Button(record_actions, text="New Record...", command=self._new_record).pack(side="left")
        ttk.Button(record_actions, text="View / Decrypt", command=self._view_selected).pack(side="left", padx=4)
        ttk.Button(record_actions, text="Delete", command=self._delete_selected).pack(side="left", padx=4)

    # -- files sub-tab (any file/folder/drive, multi-select) -- #
    def _build_files_subtab(self, notebook):
        tab = ttk.Frame(notebook, padding=8)
        notebook.add(tab, text="Files / Folders / Drives")

        ttk.Label(
            tab,
            text="Encrypt ANY combination of files, folders, or whole drives together as "
                 "one bundle -- any extension, no extension, any size. Larger content is "
                 "automatically split across multiple sealed chunks and reassembled on decrypt.",
            foreground="#555", wraplength=620, justify="left",
        ).pack(anchor="w", pady=(0, 6))

        self.file_selection_panel = PathSelectionPanel(tab)
        self.file_selection_panel.pack(fill="both", expand=True, pady=(0, 8))

        encrypt_row = ttk.Frame(tab)
        encrypt_row.pack(fill="x", pady=(0, 8))
        ttk.Label(encrypt_row, text="Bundle label:").pack(side="left")
        self._bundle_label_var = ttk.Entry(encrypt_row, width=30)
        self._bundle_label_var.pack(side="left", padx=(6, 8))
        ttk.Button(encrypt_row, text="Encrypt Selected", command=self._encrypt_selected_paths).pack(side="left")

        ttk.Separator(tab, orient="horizontal").pack(fill="x", pady=8)
        ttk.Label(tab, text="Encrypted bundles/files in this vault:").pack(anchor="w")

        columns = ("record_id", "label", "size")
        self.file_tree = ttk.Treeview(tab, columns=columns, show="headings", height=6, selectmode="browse")
        for col, width in zip(columns, (140, 260, 100)):
            self.file_tree.heading(col, text=col.replace("_", " ").title())
            self.file_tree.column(col, width=width)
        self.file_tree.pack(fill="both", expand=True, pady=(4, 8))

        restore_row = ttk.Frame(tab)
        restore_row.pack(fill="x")
        ttk.Button(restore_row, text="Refresh List", command=self._refresh_file_list).pack(side="left")
        ttk.Button(restore_row, text="Decrypt / Restore Selected...",
                   command=self._decrypt_selected_bundle).pack(side="left", padx=4)

    def _refresh_path_label(self):
        exists = vault_exists(self.vault_path)
        self._path_label.configure(
            text=f"{self.vault_path}  ({'exists' if exists else 'not created yet'})"
        )

    def _choose_path(self):
        chosen = filedialog.asksaveasfilename(
            title="Vault file", defaultextension=".json", initialfile="vault.json",
            filetypes=[("Vault files", "*.json"), ("All files", "*.*")],
        )
        if chosen:
            self.vault_path = Path(chosen)
            self.service = None
            self._status_label.configure(text="locked")
            self._refresh_path_label()
            self._refresh_list()
            self._refresh_file_list()

    def _clear_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def _init_vault(self):
        if vault_exists(self.vault_path):
            messagebox.showerror(APP_TITLE, "A vault already exists at this path.", parent=self)
            return
        prompt = TextPromptDialog(
            self, "Create Vault",
            [("passphrase", "New passphrase", True), ("confirm", "Confirm passphrase", True)],
        )
        if prompt.result is None:
            return
        passphrase, confirm = prompt.result["passphrase"], prompt.result["confirm"]
        if not passphrase:
            messagebox.showerror(APP_TITLE, "Passphrase cannot be empty.", parent=self)
            return
        if passphrase != confirm:
            messagebox.showerror(APP_TITLE, "Passphrases did not match.", parent=self)
            return

        vault_settings.ensure_data_dirs()
        path = self.vault_path

        def work():
            return VaultService.create(path, passphrase, audit_dir=vault_settings.AUDIT_DIR)

        def on_success(result):
            service, recovery_code = result
            self.service = service
            self._status_label.configure(text="unlocked")
            self._refresh_path_label()
            self._refresh_list()
            self._refresh_file_list()
            TextViewDialog(
                self, "Recovery Code -- Save This Now",
                "This code is shown once and cannot be recovered later.\n"
                "Without it or the passphrase, the vault cannot be opened by "
                "anyone, including you.\n\n"
                f"    {recovery_code}\n",
            )

        def on_error(exc):
            messagebox.showerror(APP_TITLE, f"Could not create vault: {exc}", parent=self)

        run_in_background(
            self, work, on_success, on_error,
            "Creating vault (this runs a slow key derivation twice)...",
        )

    def _unlock(self):
        if not vault_exists(self.vault_path):
            messagebox.showerror(APP_TITLE, "No vault file exists at this path yet.", parent=self)
            return
        prompt = TextPromptDialog(self, "Unlock Vault", [("passphrase", "Passphrase", True)])
        if prompt.result is None:
            return
        passphrase = prompt.result["passphrase"]

        vault_settings.ensure_data_dirs()
        path = self.vault_path

        def work():
            service = VaultService(path, audit_dir=vault_settings.AUDIT_DIR)
            service.unlock(passphrase)
            return service

        def on_success(service):
            self.service = service
            self._status_label.configure(text="unlocked")
            self._refresh_list()
            self._refresh_file_list()

        def on_error(exc):
            messagebox.showerror(APP_TITLE, f"Unlock failed: {exc}", parent=self)

        run_in_background(
            self, work, on_success, on_error,
            "Unlocking vault (this runs a slow key derivation)...",
        )

    def _lock(self):
        if self.service is not None:
            self.service.lock()
        self._status_label.configure(text="locked")

    def _require_service(self):
        if self.service is None:
            messagebox.showerror(APP_TITLE, "Unlock the vault first.", parent=self)
            return None
        return self.service

    def _refresh_list(self):
        service = self.service
        if service is None:
            if not vault_exists(self.vault_path):
                self._clear_list()
                return
            service = VaultService(self.vault_path, audit_dir=vault_settings.AUDIT_DIR)
        try:
            summaries = service.list_records()
        except (VaultServiceError, VaultFileError) as exc:
            messagebox.showerror(APP_TITLE, str(exc), parent=self)
            return
        self._clear_list()
        for summary in summaries:
            if summary["kind"] in ("file", "bundle-manifest", "bundle-chunk"):
                continue  # shown on the Files sub-tab instead
            self.tree.insert(
                "", "end",
                values=(summary["record_id"], summary["label"], summary["kind"], summary["updated_at"]),
            )

    def _refresh_file_list(self):
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        service = self.service
        if service is None:
            return
        try:
            summaries = service.list_records()
        except (VaultServiceError, VaultFileError):
            return
        for summary in summaries:
            # BUG FIX (2026-08-25): "bundle-chunk" records (see
            # vault.store.bulk_file_service's BUNDLE_CHUNK_KIND) are
            # internal pieces of a chunked bundle, never meant to be
            # listed or decrypted on their own. Before this kind existed,
            # chunks were sealed with the same "file" kind as a genuinely
            # standalone file, so every chunk of a large bundle cluttered
            # this list as if it were its own independent encrypted file.
            if summary["kind"] not in ("file", "bundle-manifest"):
                continue
            size = summary.get("file_size_bytes") or summary.get("total_size_bytes") or ""
            self.file_tree.insert("", "end", values=(summary["record_id"], summary["label"], size))

    def _new_record(self):
        service = self._require_service()
        if service is None:
            return
        dialog = RecordDialog(self, "New Record")
        if dialog.result is None:
            return

        def work():
            return service.upsert(dialog.result["label"], dialog.result["kind"], dialog.result["payload"])

        def on_success(_summary):
            self._refresh_list()

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(self, work, on_success, on_error, "Sealing record...")

    def _selected_record_id(self):
        selection = self.tree.selection()
        if not selection:
            return None
        return self.tree.item(selection[0], "values")[0]

    def _view_selected(self):
        service = self._require_service()
        if service is None:
            return
        record_id = self._selected_record_id()
        if record_id is None:
            messagebox.showinfo(APP_TITLE, "Select a record first.", parent=self)
            return

        def work():
            return service.get(record_id)

        def on_success(payload):
            TextViewDialog(self, f"Record {record_id}", json.dumps(payload, indent=2, sort_keys=True))

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(self, work, on_success, on_error, "Decrypting record...")

    def _delete_selected(self):
        service = self._require_service()
        if service is None:
            return
        record_id = self._selected_record_id()
        if record_id is None:
            messagebox.showinfo(APP_TITLE, "Select a record first.", parent=self)
            return
        if not messagebox.askyesno(APP_TITLE, f"Delete record {record_id}?", parent=self):
            return
        service.delete(record_id)
        self._refresh_list()

    # -- bulk file/folder/drive encrypt/decrypt -- #
    def _encrypt_selected_paths(self):
        service = self._require_service()
        if service is None:
            return
        paths = self.file_selection_panel.paths
        if not paths:
            messagebox.showinfo(
                APP_TITLE, "Add at least one file, folder, or drive first "
                "(use the buttons above).", parent=self,
            )
            return
        label = self._bundle_label_var.get().strip() or Path(paths[0]).name
        if not messagebox.askyesno(
            APP_TITLE,
            f"Encrypt {len(paths)} selected item(s) as one bundle labelled {label!r}?\n\n"
            "Any content over roughly 16 MB will be automatically split into "
            "multiple sealed chunks.",
            parent=self,
        ):
            return

        bulk = BulkFileService(service)

        def work():
            return bulk.upsert_paths(paths, label)

        def on_success(summary):
            self.file_selection_panel._clear_all()
            self._bundle_label_var.delete(0, "end")
            self._refresh_file_list()
            messagebox.showinfo(
                APP_TITLE,
                f"Encrypted {summary['files_bundled']} file(s) across "
                f"{summary['chunk_count']} sealed chunk(s), "
                f"{summary['total_size_bytes']:,} bytes total."
                + (f"\n\n{len(summary['files_skipped'])} file(s) could not be read "
                   "and were skipped." if summary.get("files_skipped") else ""),
                parent=self,
            )

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(
            self, work, on_success, on_error,
            f"Zipping and encrypting {len(paths)} item(s) (this can take a while for "
            f"large folders/drives)...",
        )

    def _selected_file_record_id(self):
        selection = self.file_tree.selection()
        if not selection:
            return None
        return self.file_tree.item(selection[0], "values")[0]

    def _decrypt_selected_bundle(self):
        service = self._require_service()
        if service is None:
            return
        record_id = self._selected_file_record_id()
        if record_id is None:
            messagebox.showinfo(APP_TITLE, "Select an encrypted file/bundle first.", parent=self)
            return

        # BUG FIX (2026-08-25): this button previously called
        # BulkFileService.restore_paths() unconditionally for whatever was
        # selected, which assumes the record's payload is a JSON bundle
        # manifest wrapping a zip archive. A record created as a genuinely
        # standalone single file (kind "file", e.g. one created via the
        # CLI's `vault.app encrypt-file` command, or any small file sealed
        # directly through VaultService.upsert_file/upsert_file_bytes
        # rather than through BulkFileService.upsert_paths) has its raw
        # file bytes sealed directly -- never JSON, never a zip -- so
        # treating it as a manifest raised a confusing
        # "decrypted payload is not valid JSON" error instead of just
        # decrypting the file. The record's own "kind" is checked first so
        # each kind is decrypted through the path that actually matches how
        # it was sealed.
        try:
            summary = service.get_summary(record_id)
        except VaultServiceError as exc:
            messagebox.showerror(APP_TITLE, str(exc), parent=self)
            return

        if summary["kind"] == "file":
            output_path = filedialog.asksaveasfilename(
                title="Save decrypted file as", initialfile=summary["label"],
            )
            if not output_path:
                return

            def work():
                return service.get_file(record_id, output_path)

            def on_success(result_path):
                messagebox.showinfo(APP_TITLE, f"Decrypted to:\n{result_path}", parent=self)

            def on_error(exc):
                messagebox.showerror(APP_TITLE, str(exc), parent=self)

            run_in_background(self, work, on_success, on_error, "Decrypting file...")
            return

        output_dir = filedialog.askdirectory(title="Choose a folder to restore into")
        if not output_dir:
            return

        bulk = BulkFileService(service)

        def work():
            return bulk.restore_paths(record_id, output_dir)

        def on_success(result):
            messagebox.showinfo(
                APP_TITLE,
                f"Restored {result['files_restored']} file(s) to:\n{result['output_dir']}",
                parent=self,
            )

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(self, work, on_success, on_error, "Decrypting and restoring...")
