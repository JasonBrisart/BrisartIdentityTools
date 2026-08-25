"""The Biometrics tab: create/unlock the keyring, enroll/verify/inspect/delete
identities, and attach/extract arbitrary files, folders, or drives to/from an
identity (chunked transparently past BSR2's single-envelope size limit)."""

import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from gui.core.constants import APP_TITLE
from gui.core.busy import run_in_background
from gui.widgets.dialogs import ModalityPathDialog, TextPromptDialog, TextViewDialog
from gui.widgets.path_panel import PathSelectionPanel

from biometrics.config import settings as biometrics_settings
from biometrics.engine import enrollment as bio_enrollment
from biometrics.engine import verification as bio_verification
from biometrics.engine import attachments as bio_attachment_engine
from biometrics.engine import bulk_attachments as bio_bulk_attachments
from biometrics.identity.identity_record import public_summary as bio_public_summary
from biometrics.identity.identity_store import IdentityStore, IdentityStoreError
from biometrics.samples import sample_generator
from crypto.keyring import Keyring


class BiometricsTab(ttk.Frame):
    """Create/unlock the biometrics keyring, enroll/verify/inspect/delete
    identities, and (new) attach/extract arbitrary files, folders, or
    drives to/from an identity -- independent of the voice/fingerprint/
    video modality system, chunked transparently past BSR2's single-
    envelope size limit."""

    KEYRING_FILE_NAME = "keyring.json"

    def __init__(self, master):
        super().__init__(master, padding=12)
        self._keyring = None
        self._store = None
        self._build_widgets()
        self._refresh_list()

    def _keyring_path(self) -> Path:
        biometrics_settings.ensure_data_dirs()
        return biometrics_settings.DATA_DIR / self.KEYRING_FILE_NAME

    def _store_ref(self) -> IdentityStore:
        if self._store is None:
            biometrics_settings.ensure_data_dirs()
            self._store = IdentityStore(biometrics_settings.IDENTITY_DIR)
        return self._store

    def _build_widgets(self):
        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(0, 8))
        ttk.Button(actions, text="Unlock / Create Keyring", command=self._ensure_keyring).pack(side="left")
        ttk.Button(actions, text="Lock", command=self._lock).pack(side="left", padx=4)
        ttk.Button(actions, text="Refresh", command=self._refresh_list).pack(side="left", padx=4)
        ttk.Button(actions, text="Make Samples...", command=self._make_samples).pack(side="left", padx=4)
        self._status_label = ttk.Label(actions, text="locked")
        self._status_label.pack(side="right")
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)
        self._build_identities_subtab(notebook)
        self._build_attachments_subtab(notebook)

    def _build_identities_subtab(self, notebook):
        tab = ttk.Frame(notebook, padding=8)
        notebook.add(tab, text="Identities")
        columns = ("identity_id", "label", "modalities")
        self.tree = ttk.Treeview(tab, columns=columns, show="headings", selectmode="browse")
        for col, width in zip(columns, (160, 220, 220)):
            self.tree.heading(col, text=col.replace("_", " ").title())
            self.tree.column(col, width=width)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda _e: self._inspect_selected())
        record_actions = ttk.Frame(tab)
        record_actions.pack(fill="x", pady=(8, 0))
        ttk.Button(record_actions, text="Enroll...", command=self._enroll).pack(side="left")
        ttk.Button(record_actions, text="Verify...", command=self._verify).pack(side="left", padx=4)
        ttk.Button(record_actions, text="Inspect", command=self._inspect_selected).pack(side="left", padx=4)
        ttk.Button(record_actions, text="Delete", command=self._delete_selected).pack(side="left", padx=4)

    def _build_attachments_subtab(self, notebook):
        tab = ttk.Frame(notebook, padding=8)
        notebook.add(tab, text="File Attachments")
        ttk.Label(
            tab,
            text="Attach ANY combination of files, folders, or whole drives to the "
                 "identity selected on the Identities tab -- any extension, no extension, "
                 "any size (large content is chunked automatically).",
            foreground="#555", wraplength=620, justify="left",
        ).pack(anchor="w", pady=(0, 6))
        target_row = ttk.Frame(tab)
        target_row.pack(fill="x", pady=(0, 6))
        ttk.Label(target_row, text="Target identity:").pack(side="left")
        self._attach_identity_var = tk.StringVar()
        ttk.Entry(target_row, textvariable=self._attach_identity_var, width=24).pack(
            side="left", padx=(6, 0))
        ttk.Label(target_row, text="(defaults to the identity selected above)",
                  foreground="#777").pack(side="left", padx=(6, 0))
        self.attach_selection_panel = PathSelectionPanel(tab)
        self.attach_selection_panel.pack(fill="both", expand=True, pady=(0, 8))
        attach_row = ttk.Frame(tab)
        attach_row.pack(fill="x", pady=(0, 8))
        ttk.Label(attach_row, text="Bundle name:").pack(side="left")
        self._attach_bundle_name_var = tk.StringVar()
        ttk.Entry(attach_row, textvariable=self._attach_bundle_name_var, width=30).pack(
            side="left", padx=(6, 8))
        ttk.Button(attach_row, text="Attach Selected", command=self._attach_selected_paths).pack(side="left")
        ttk.Separator(tab, orient="horizontal").pack(fill="x", pady=8)
        ttk.Label(tab, text="Attachments on the selected identity:").pack(anchor="w")
        columns = ("filename", "size_bytes")
        self.attachment_tree = ttk.Treeview(tab, columns=columns, show="headings",
                                            height=6, selectmode="browse")
        for col, width in zip(columns, (300, 120)):
            self.attachment_tree.heading(col, text=col.replace("_", " ").title())
            self.attachment_tree.column(col, width=width)
        self.attachment_tree.pack(fill="both", expand=True, pady=(4, 8))
        restore_row = ttk.Frame(tab)
        restore_row.pack(fill="x")
        ttk.Button(restore_row, text="Refresh", command=self._refresh_attachment_list).pack(side="left")
        ttk.Button(restore_row, text="Extract Selected...",
                   command=self._extract_selected_attachment).pack(side="left", padx=4)
        ttk.Button(restore_row, text="Remove Selected",
                   command=self._remove_selected_attachment).pack(side="left", padx=4)

    def _ensure_keyring(self):
        if self._keyring is not None and self._keyring.is_unlocked:
            messagebox.showinfo(APP_TITLE, "Keyring is already unlocked.", parent=self)
            return
        path = self._keyring_path()
        if path.is_file():
            with open(path, "r", encoding="utf-8") as handle:
                state = json.load(handle)
            keyring = Keyring(state)
            prompt = TextPromptDialog(self, "Unlock Biometrics", [("passphrase", "Passphrase", True)])
            if prompt.result is None:
                return
            passphrase = prompt.result["passphrase"]

            def work():
                keyring.unlock_with_passphrase(passphrase)
                return keyring

            def on_success(unlocked_keyring):
                self._keyring = unlocked_keyring
                self._status_label.configure(text="unlocked")
                self._refresh_attachment_list()

            def on_error(exc):
                messagebox.showerror(APP_TITLE, f"Unlock failed: {exc}", parent=self)

            run_in_background(self, work, on_success, on_error, "Unlocking (slow key derivation)...")
        else:
            prompt = TextPromptDialog(
                self, "Create Biometrics Keyring",
                [("passphrase", "New passphrase", True), ("confirm", "Confirm passphrase", True)],
            )
            if prompt.result is None:
                return
            passphrase, confirm = prompt.result["passphrase"], prompt.result["confirm"]
            if not passphrase or passphrase != confirm:
                messagebox.showerror(APP_TITLE, "Passphrases must match and cannot be empty.", parent=self)
                return

            def work():
                keyring, recovery_code = Keyring.create(passphrase)
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(keyring.to_state(), handle, indent=2, sort_keys=True)
                return keyring, recovery_code

            def on_success(result):
                keyring, recovery_code = result
                self._keyring = keyring
                self._status_label.configure(text="unlocked")
                TextViewDialog(
                    self, "Recovery Code -- Save This Now",
                    "This code is shown only once and cannot be recovered later.\n\n"
                    f"    {recovery_code}\n",
                )

            def on_error(exc):
                messagebox.showerror(APP_TITLE, f"Could not create keyring: {exc}", parent=self)

            run_in_background(self, work, on_success, on_error, "Creating keyring (slow key derivation)...")

    def _lock(self):
        if self._keyring is not None:
            self._keyring.lock()
        self._status_label.configure(text="locked")

    def _refresh_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        biometrics_settings.ensure_data_dirs()
        store = self._store_ref()
        for identity_id in store.list_identity_ids():
            try:
                record = store.load(identity_id)
            except IdentityStoreError:
                continue
            summary = bio_public_summary(record)
            self.tree.insert(
                "", "end",
                values=(summary["identity_id"], summary["label"], ", ".join(summary["modalities"])),
            )

    def _selected_identity_id(self):
        selection = self.tree.selection()
        if not selection:
            return None
        return self.tree.item(selection[0], "values")[0]

    def _target_identity_id(self):
        typed = self._attach_identity_var.get().strip()
        return typed or self._selected_identity_id()

    def _inspect_selected(self):
        identity_id = self._selected_identity_id()
        if identity_id is None:
            messagebox.showinfo(APP_TITLE, "Select an identity first.", parent=self)
            return
        try:
            record = self._store_ref().load(identity_id)
        except IdentityStoreError as exc:
            messagebox.showerror(APP_TITLE, str(exc), parent=self)
            return
        TextViewDialog(
            self, f"Identity {identity_id}",
            json.dumps(bio_public_summary(record), indent=2, sort_keys=True),
        )
        self._attach_identity_var.set(identity_id)
        self._refresh_attachment_list()

    def _delete_selected(self):
        identity_id = self._selected_identity_id()
        if identity_id is None:
            messagebox.showinfo(APP_TITLE, "Select an identity first.", parent=self)
            return
        if not messagebox.askyesno(APP_TITLE, f"Delete identity {identity_id!r}?", parent=self):
            return
        self._store_ref().delete(identity_id)
        self._refresh_list()

    def _enroll(self):
        dialog = ModalityPathDialog(
            self, "Enroll Identity",
            [("identity_id", "Identity id"), ("label", "Label")],
        )
        if dialog.result is None:
            return
        fields, sources = dialog.result["fields"], dialog.result["sources"]
        identity_id, label = fields["identity_id"].strip(), fields["label"].strip()
        if not identity_id or not label:
            messagebox.showerror(APP_TITLE, "Identity id and label are required.", parent=self)
            return
        if not sources:
            messagebox.showerror(
                APP_TITLE, "At least one of voice, fingerprint, or video is required.", parent=self
            )
            return
        if self._store_ref().exists(identity_id):
            messagebox.showerror(
                APP_TITLE,
                f"Identity {identity_id!r} already exists; delete it first to re-enroll.",
                parent=self,
            )
            return
        if self._keyring is None or not self._keyring.is_unlocked:
            messagebox.showerror(APP_TITLE, "Unlock (or create) the biometrics keyring first.", parent=self)
            return
        master_key = self._keyring.master_key
        store = self._store_ref()

        def work():
            record = bio_enrollment.enroll_identity(identity_id, label, master_key, sources)
            store.save(record)
            return record

        def on_success(_record):
            self._refresh_list()
            messagebox.showinfo(APP_TITLE, f"Enrolled {identity_id!r}.", parent=self)

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(self, work, on_success, on_error, "Enrolling (sealing templates)...")

    def _verify(self):
        default_id = self._selected_identity_id() or ""
        dialog = ModalityPathDialog(
            self, "Verify Identity",
            [("identity_id", "Identity id")],
            defaults={"identity_id": default_id},
            include_any_match=True,
        )
        if dialog.result is None:
            return
        fields, sources = dialog.result["fields"], dialog.result["sources"]
        identity_id = fields["identity_id"].strip()
        any_match = fields.get("_any_match", False)
        if not identity_id:
            messagebox.showerror(APP_TITLE, "Identity id is required.", parent=self)
            return
        if not sources:
            messagebox.showerror(
                APP_TITLE, "At least one of voice, fingerprint, or video is required.", parent=self
            )
            return
        if self._keyring is None or not self._keyring.is_unlocked:
            messagebox.showerror(APP_TITLE, "Unlock the biometrics keyring first.", parent=self)
            return
        master_key = self._keyring.master_key
        try:
            record = self._store_ref().load(identity_id)
        except IdentityStoreError as exc:
            messagebox.showerror(APP_TITLE, str(exc), parent=self)
            return

        def work():
            return bio_verification.verify_identity(record, sources, master_key, require_all=not any_match)

        def on_success(result):
            lines = [f"Identity: {result['identity_id']}", ""]
            for modality_result in result["results"]:
                outcome = "MATCH" if modality_result["matched"] else "NO MATCH"
                lines.append(
                    f"{modality_result['modality']}: score={modality_result['score']:.4f} "
                    f"threshold={modality_result['threshold']:.4f} -> {outcome}"
                )
            lines.append("")
            lines.append(f"Overall: {'MATCH' if result['matched'] else 'NO MATCH'}")
            TextViewDialog(self, "Verification Result", "\n".join(lines))

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(self, work, on_success, on_error, "Verifying...")

    def _make_samples(self):
        prompt = TextPromptDialog(self, "Make Samples", [("seed", "Seed", False)])
        if prompt.result is None:
            return
        seed = prompt.result["seed"].strip()
        if not seed:
            messagebox.showerror(APP_TITLE, "Seed cannot be empty.", parent=self)
            return
        biometrics_settings.ensure_data_dirs()
        output_dir = biometrics_settings.SAMPLE_DIR

        def work():
            sample_generator.write_fingerprint_sample(output_dir / f"{seed}_fingerprint.pgm", seed)
            sample_generator.write_voice_sample(output_dir / f"{seed}_voice.wav", seed)
            sample_generator.write_video_sample(output_dir / f"{seed}_video.brvid", seed)
            return output_dir

        def on_success(directory):
            messagebox.showinfo(APP_TITLE, f"Samples written to {directory}", parent=self)

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(self, work, on_success, on_error, "Generating samples...")

    # -- generic file/folder/drive attachments -- #
    def _refresh_attachment_list(self):
        for item in self.attachment_tree.get_children():
            self.attachment_tree.delete(item)
        identity_id = self._target_identity_id()
        if not identity_id:
            return
        try:
            record = self._store_ref().load(identity_id)
        except IdentityStoreError:
            return
        summary = bio_public_summary(record)
        for attachment in summary.get("attachments", []):
            # A chunked bundle surfaces as "{name}.manifest" plus several
            # "{name}.chunkN" entries in the raw record; only the manifest
            # (or a plain, non-chunked attachment) is shown here as one row,
            # so a large bundle doesn't clutter the list with its internal
            # chunk entries.
            filename = attachment["filename"]
            if ".chunk" in filename:
                continue
            display_name = filename[: -len(".manifest")] if filename.endswith(".manifest") else filename
            self.attachment_tree.insert("", "end", values=(display_name, attachment["size_bytes"]))

    def _selected_attachment_name(self):
        selection = self.attachment_tree.selection()
        if not selection:
            return None
        return self.attachment_tree.item(selection[0], "values")[0]

    def _attach_selected_paths(self):
        identity_id = self._target_identity_id()
        if not identity_id:
            messagebox.showinfo(APP_TITLE, "Type or select a target identity first.", parent=self)
            return
        if self._keyring is None or not self._keyring.is_unlocked:
            messagebox.showerror(APP_TITLE, "Unlock the biometrics keyring first.", parent=self)
            return
        paths = self.attach_selection_panel.paths
        if not paths:
            messagebox.showinfo(
                APP_TITLE, "Add at least one file, folder, or drive first "
                "(use the buttons above).", parent=self,
            )
            return
        try:
            record = self._store_ref().load(identity_id)
        except IdentityStoreError as exc:
            messagebox.showerror(APP_TITLE, str(exc), parent=self)
            return
        bundle_name = self._attach_bundle_name_var.get().strip() or Path(paths[0]).name
        master_key = self._keyring.master_key
        store = self._store_ref()

        def work():
            updated, report = bio_bulk_attachments.attach_paths(record, bundle_name, paths, master_key)
            store.save(updated)
            return report

        def on_success(report):
            self.attach_selection_panel._clear_all()
            self._attach_bundle_name_var.set("")
            self._refresh_attachment_list()
            messagebox.showinfo(
                APP_TITLE,
                f"Attached {report['files_bundled']} file(s), "
                f"{report['total_size_bytes']:,} bytes total, to {identity_id!r}."
                + (f"\n\n{len(report['files_skipped'])} file(s) could not be read "
                   "and were skipped." if report.get("files_skipped") else ""),
                parent=self,
            )

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(
            self, work, on_success, on_error,
            f"Zipping and attaching {len(paths)} item(s)...",
        )

    def _extract_selected_attachment(self):
        identity_id = self._target_identity_id()
        if not identity_id:
            messagebox.showinfo(APP_TITLE, "Type or select a target identity first.", parent=self)
            return
        if self._keyring is None or not self._keyring.is_unlocked:
            messagebox.showerror(APP_TITLE, "Unlock the biometrics keyring first.", parent=self)
            return
        name = self._selected_attachment_name()
        if name is None:
            messagebox.showinfo(APP_TITLE, "Select an attachment first.", parent=self)
            return
        try:
            record = self._store_ref().load(identity_id)
        except IdentityStoreError as exc:
            messagebox.showerror(APP_TITLE, str(exc), parent=self)
            return
        master_key = self._keyring.master_key
        is_bundle = f"{name}.manifest" in record.get("attachments", {})
        if is_bundle:
            output_dir = filedialog.askdirectory(title="Choose a folder to restore into")
            if not output_dir:
                return

            def work():
                return bio_bulk_attachments.restore_paths(record, name, master_key, output_dir)

            def on_success(result):
                messagebox.showinfo(
                    APP_TITLE, f"Restored {result['files_restored']} file(s) to:\n{result['output_dir']}",
                    parent=self,
                )
        else:
            output_path = filedialog.asksaveasfilename(title="Save extracted file as", initialfile=name)
            if not output_path:
                return

            def work():
                return bio_attachment_engine.extract_attachment_to_file(record, name, master_key, output_path)

            def on_success(result_path):
                messagebox.showinfo(APP_TITLE, f"Extracted to:\n{result_path}", parent=self)

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(self, work, on_success, on_error, "Decrypting attachment...")

    def _remove_selected_attachment(self):
        identity_id = self._target_identity_id()
        if not identity_id:
            messagebox.showinfo(APP_TITLE, "Type or select a target identity first.", parent=self)
            return
        name = self._selected_attachment_name()
        if name is None:
            messagebox.showinfo(APP_TITLE, "Select an attachment first.", parent=self)
            return
        if not messagebox.askyesno(APP_TITLE, f"Remove attachment {name!r}?", parent=self):
            return
        try:
            record = self._store_ref().load(identity_id)
        except IdentityStoreError as exc:
            messagebox.showerror(APP_TITLE, str(exc), parent=self)
            return
        is_bundle = f"{name}.manifest" in record.get("attachments", {})
        if is_bundle:
            if self._keyring is None or not self._keyring.is_unlocked:
                messagebox.showerror(
                    APP_TITLE, "Unlock the keyring first (needed to identify this bundle's "
                    "chunk parts before removing them).", parent=self,
                )
                return
            updated = bio_bulk_attachments.remove_bulk_attachment(record, name, self._keyring.master_key)
        else:
            updated = bio_attachment_engine.remove_identity_attachment(record, name)
        self._store_ref().save(updated)
        self._refresh_attachment_list()
