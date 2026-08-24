"""Tkinter desktop GUI for BrisartIdentityTools: Vault, Biometrics, and
Packages in one window.

Standard-library only (``tkinter`` ships with Python), consistent with the
rest of this ecosystem's zero-third-party-dependency rule. This module is a
thin presentation layer over the same service classes and functions the
three CLIs use -- ``vault.store.vault_service.VaultService`` (and now
``vault.store.bulk_file_service.BulkFileService`` for any-size/multi-path
encryption), ``biometrics.engine.enrollment``/``verification`` (and now
``biometrics.engine.attachments``/``bulk_attachments`` for generic file
attachments), and ``packages.package``. No cryptography, validation, or
persistence logic is duplicated here; every button is wired directly to the
existing, already-tested application layer.

BSR2's password-based key derivation is deliberately slow (tens of seconds to
low minutes per call -- see ``docs/BSR2_INTEGRATION.md``). Every operation
that touches the KDF (vault init/unlock, biometrics keyring create/unlock,
and any package operation) therefore runs on a background thread behind a
modal "Working..." dialog, so the window never appears frozen. Tkinter itself
is not thread-safe: background threads never touch a widget directly, they
only push a result onto a queue that the main thread polls via ``after()``.

FILE / FOLDER / DRIVE SELECTION: done entirely through tkinter.filedialog's
real, standard, cross-platform picker dialogs via the "Add Files...",
"Add Folder...", and "Add Drive..." buttons. (An earlier experimental
native-Windows drag-and-drop hook was removed for the 1.0.0 release; it is
not needed -- the Browse buttons provide the identical capability.)

Run with::

    python -m gui.app

or via the unified dispatcher::

    python cli.py gui

or open this file directly in an editor/IDE (e.g. VS Code's "Run Python
File") -- see the ``sys.path`` bootstrap immediately below for why that
also works.
"""
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import hashlib
import json
import queue
import secrets
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from biometrics.config import settings as biometrics_settings
from biometrics.engine import enrollment as bio_enrollment
from biometrics.engine import modalities as bio_modalities
from biometrics.engine import verification as bio_verification
from biometrics.engine import attachments as bio_attachment_engine
from biometrics.engine import bulk_attachments as bio_bulk_attachments
from biometrics.identity.identity_record import public_summary as bio_public_summary
from biometrics.identity.identity_store import IdentityStore, IdentityStoreError
from biometrics.samples import sample_generator
from crypto.keyring import Keyring
from packages import package as ibp_package
from packages.custody import CustodyError
from packages.package import PackageError
from vault.config import settings as vault_settings
from vault.store.vault_file import VaultFileError, vault_exists
from vault.store.vault_service import VaultService, VaultServiceError
from vault.store.bulk_file_service import BulkFileService

APP_TITLE = "BrisartIdentityTools"
_MODALITY_FILETYPES = {
    "voice": [("WAV audio", "*.wav")],
    "fingerprint": [("Fingerprint images", "*.pgm *.png")],
    "video": [("BRVID clips", "*.brvid")],
}


class _Cancelled(Exception):
    """Raised internally when a nested sub-dialog (e.g. a payload editor
    opened from within another dialog) is cancelled by the user."""


# --------------------------------------------------------------------- busy
class BusyDialog(tk.Toplevel):
    """A small, non-closable modal dialog with an indeterminate progress bar.

    Shown while a background thread runs a slow BSR2 KDF operation, so the
    main window never looks frozen or unresponsive.
    """

    def __init__(self, parent, message):
        super().__init__(parent)
        self.title(APP_TITLE)
        self.resizable(False, False)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", lambda: None)  # not user-closable
        ttk.Label(self, text=message, padding=(16, 12, 16, 4)).pack()
        bar = ttk.Progressbar(self, mode="indeterminate", length=280)
        bar.pack(padx=16, pady=(0, 16))
        bar.start(12)
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.grab_set()


def run_in_background(parent, work, on_success, on_error=None, message="Working..."):
    """Run ``work()`` on a background thread behind a modal busy dialog.

    ``work`` takes no arguments and returns a value or raises. ``on_success``
    receives the return value on the *main* thread once the thread finishes;
    ``on_error`` (if given) receives the exception on the main thread,
    otherwise a message box is shown automatically. This is the only path by
    which any BSR2 KDF call (or any large/slow bulk encrypt/decrypt call)
    should ever be invoked from this GUI -- calling one directly from a
    button handler would freeze the window for the duration of the work.
    """
    result_queue = queue.Queue()
    busy = BusyDialog(parent, message)

    def runner():
        try:
            value = work()
            result_queue.put(("ok", value))
        except Exception as exc:  # noqa: BLE001 - surfaced to the user below
            result_queue.put(("error", exc))

    threading.Thread(target=runner, daemon=True).start()

    def poll():
        try:
            status, payload = result_queue.get_nowait()
        except queue.Empty:
            parent.after(100, poll)
            return
        busy.destroy()
        if status == "ok":
            on_success(payload)
        elif on_error is not None:
            on_error(payload)
        else:
            messagebox.showerror(APP_TITLE, str(payload), parent=parent)

    parent.after(100, poll)


# ------------------------------------------------------------------ dialogs
class TextPromptDialog(tk.Toplevel):
    """A modal dialog collecting one or more labelled single-line fields.

    ``fields`` is a list of ``(key, label, is_secret)`` tuples. The result is
    stored in ``self.result`` as ``{key: value, ...}``, or ``None`` if the
    user cancelled.
    """

    def __init__(self, parent, title, fields):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.result = None
        self._entries = {}
        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)
        for row, (key, label, is_secret) in enumerate(fields):
            ttk.Label(body, text=label).grid(row=row, column=0, sticky="w", pady=4)
            entry = ttk.Entry(body, width=42, show="*" if is_secret else "")
            entry.grid(row=row, column=1, pady=4, padx=(8, 0))
            self._entries[key] = entry
        if fields:
            self._entries[fields[0][0]].focus_set()
        button_row = ttk.Frame(self, padding=(16, 0, 16, 16))
        button_row.pack(fill="x")
        ttk.Button(button_row, text="Cancel", command=self._on_cancel).pack(side="right")
        ttk.Button(button_row, text="OK", command=self._on_ok).pack(side="right", padx=(0, 8))
        self.bind("<Return>", lambda _event: self._on_ok())
        self.bind("<Escape>", lambda _event: self._on_cancel())
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.grab_set()
        self.wait_window(self)

    def _on_ok(self):
        self.result = {key: entry.get() for key, entry in self._entries.items()}
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


class RecordDialog(tk.Toplevel):
    """Modal dialog for creating a vault record: label, kind, and a JSON
    payload body."""

    def __init__(self, parent, title, label="", kind="note", payload_text="{}"):
        super().__init__(parent)
        self.title(title)
        self.resizable(True, True)
        self.transient(parent)
        self.result = None
        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Label").grid(row=0, column=0, sticky="w")
        self._label_entry = ttk.Entry(body, width=48)
        self._label_entry.insert(0, label)
        self._label_entry.grid(row=0, column=1, pady=4, sticky="ew")
        ttk.Label(body, text="Kind").grid(row=1, column=0, sticky="w")
        self._kind_entry = ttk.Entry(body, width=48)
        self._kind_entry.insert(0, kind)
        self._kind_entry.grid(row=1, column=1, pady=4, sticky="ew")
        ttk.Label(body, text="Payload (JSON object)").grid(row=2, column=0, sticky="nw", pady=(8, 0))
        self._payload_text = scrolledtext.ScrolledText(body, width=48, height=10, wrap="word")
        self._payload_text.insert("1.0", payload_text)
        self._payload_text.grid(row=2, column=1, pady=(8, 0), sticky="nsew")
        body.columnconfigure(1, weight=1)
        body.rowconfigure(2, weight=1)
        button_row = ttk.Frame(self, padding=(16, 8, 16, 16))
        button_row.pack(fill="x")
        ttk.Button(button_row, text="Cancel", command=self._on_cancel).pack(side="right")
        ttk.Button(button_row, text="Save", command=self._on_save).pack(side="right", padx=(0, 8))
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.geometry("480x420")
        self.grab_set()
        self.wait_window(self)

    def _on_save(self):
        label = self._label_entry.get().strip()
        kind = self._kind_entry.get().strip()
        raw_payload = self._payload_text.get("1.0", "end").strip()
        if not label:
            messagebox.showerror(APP_TITLE, "Label cannot be empty.", parent=self)
            return
        if not kind:
            messagebox.showerror(APP_TITLE, "Kind cannot be empty.", parent=self)
            return
        try:
            payload = json.loads(raw_payload or "{}")
        except json.JSONDecodeError as exc:
            messagebox.showerror(APP_TITLE, f"Payload is not valid JSON: {exc}", parent=self)
            return
        if not isinstance(payload, dict):
            messagebox.showerror(APP_TITLE, "Payload must be a JSON object.", parent=self)
            return
        self.result = {"label": label, "kind": kind, "payload": payload}
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


class TextViewDialog(tk.Toplevel):
    """A modal, read-only, scrollable text viewer.

    Used to show a decrypted payload, a verification result, a custody-chain
    summary, or a one-time recovery code -- anything that is safe to display
    but should not be silently logged anywhere else.
    """

    def __init__(self, parent, title, text):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        body = scrolledtext.ScrolledText(self, width=76, height=24, wrap="word")
        body.insert("1.0", text)
        body.configure(state="disabled")
        body.pack(fill="both", expand=True, padx=12, pady=(12, 4))
        ttk.Button(self, text="Close", command=self.destroy).pack(pady=(0, 12))
        self.geometry("620x460")
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.grab_set()


class ModalityPathDialog(tk.Toplevel):
    """Modal dialog for biometrics enroll/verify: arbitrary extra text
    fields (identity id, label, ...) plus a file path with a Browse button
    for every registered modality (``biometrics.engine.modalities``), so a
    new modality added there appears here automatically without editing the
    GUI.
    """

    def __init__(self, parent, title, extra_fields, defaults=None, include_any_match=False):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.result = None
        defaults = defaults or {}
        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)
        self._field_entries = {}
        row = 0
        for key, label in extra_fields:
            ttk.Label(body, text=label).grid(row=row, column=0, sticky="w", pady=4)
            entry = ttk.Entry(body, width=42)
            entry.insert(0, defaults.get(key, ""))
            entry.grid(row=row, column=1, columnspan=2, sticky="ew", pady=4)
            self._field_entries[key] = entry
            row += 1
        self._path_entries = {}
        for modality in bio_modalities.supported_modalities():
            filetypes = _MODALITY_FILETYPES.get(modality, [])
            ttk.Label(body, text=modality.title()).grid(row=row, column=0, sticky="w", pady=4)
            entry = ttk.Entry(body, width=32)
            entry.grid(row=row, column=1, sticky="ew", pady=4)
            ttk.Button(
                body, text="Browse...",
                command=lambda e=entry, ft=filetypes: self._browse(e, ft),
            ).grid(row=row, column=2, padx=(4, 0))
            self._path_entries[modality] = entry
            row += 1
        self._any_match_var = tk.BooleanVar(value=False)
        if include_any_match:
            ttk.Checkbutton(
                body,
                text="Accept if ANY selected modality matches (default: all must match)",
                variable=self._any_match_var,
            ).grid(row=row, column=0, columnspan=3, sticky="w", pady=(6, 0))
            row += 1
        body.columnconfigure(1, weight=1)
        button_row = ttk.Frame(self, padding=(16, 8, 16, 16))
        button_row.pack(fill="x")
        ttk.Button(button_row, text="Cancel", command=self._on_cancel).pack(side="right")
        ttk.Button(button_row, text="OK", command=self._on_ok).pack(side="right", padx=(0, 8))
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.grab_set()
        self.wait_window(self)

    def _browse(self, entry, filetypes):
        chosen = filedialog.askopenfilename(
            title="Select file", filetypes=filetypes + [("All files", "*.*")]
        )
        if chosen:
            entry.delete(0, "end")
            entry.insert(0, chosen)

    def _on_ok(self):
        fields = {key: entry.get() for key, entry in self._field_entries.items()}
        fields["_any_match"] = self._any_match_var.get()
        sources = {}
        for modality, entry in self._path_entries.items():
            value = entry.get().strip()
            if value:
                sources[modality] = value
        self.result = {"fields": fields, "sources": sources}
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


# ------------------------------------------------------ path-selection panel
class PathSelectionPanel(ttk.Frame):
    """A reusable panel for building up a list of files/folders/drives to
    bulk-encrypt or bulk-attach in one operation -- this is the shared "any
    combination of files, folders, drives" multi-select UI used by both the
    Vault and Biometrics tabs, so the same behavior (add files via a real
    multi-select dialog, add a folder, add a drive root, remove a selected
    entry) only needs to be built and reasoned about once.

    Selection is done entirely through tkinter.filedialog's real,
    guaranteed cross-platform picker dialogs via the buttons below.
    """

    def __init__(self, master, on_change=None):
        super().__init__(master)
        self.paths = []
        self._on_change = on_change
        self._build_widgets()

    def _build_widgets(self):
        ttk.Label(
            self,
            text="Add files, folders, or a drive using the buttons below.",
            foreground="#666", font=("TkDefaultFont", 8),
        ).pack(anchor="w")

        self.listbox = tk.Listbox(self, height=6, selectmode="extended")
        self.listbox.pack(fill="both", expand=True, pady=(4, 4))

        btn_row = ttk.Frame(self)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="Add Files...", command=self._add_files).pack(side="left")
        ttk.Button(btn_row, text="Add Folder...", command=self._add_folder).pack(side="left", padx=4)
        ttk.Button(btn_row, text="Add Drive...", command=self._add_drive).pack(side="left", padx=4)
        ttk.Button(btn_row, text="Remove Selected", command=self._remove_selected).pack(side="left", padx=4)
        ttk.Button(btn_row, text="Clear All", command=self._clear_all).pack(side="left", padx=4)

    def _refresh_listbox(self):
        self.listbox.delete(0, "end")
        for path in self.paths:
            self.listbox.insert("end", path)
        if self._on_change:
            self._on_change(self.paths)

    def _add_paths(self, new_paths):
        for path in new_paths:
            if path not in self.paths:
                self.paths.append(path)
        self._refresh_listbox()

    def _add_files(self):
        chosen = filedialog.askopenfilenames(title="Select one or more files (any type)")
        if chosen:
            self._add_paths(list(chosen))

    def _add_folder(self):
        chosen = filedialog.askdirectory(title="Select a folder")
        if chosen:
            self._add_paths([chosen])

    def _add_drive(self):
        # tkinter has no "pick a drive" dialog; askdirectory already lets a
        # user navigate to and select a drive root (e.g. "D:\") directly,
        # so this button is a clearly-labeled shortcut to the same dialog
        # rather than a separate mechanism -- avoids inventing a second,
        # redundant drive-enumeration UI when the folder picker already
        # covers it.
        chosen = filedialog.askdirectory(title="Select a drive root (e.g. D:\\) or any folder")
        if chosen:
            self._add_paths([chosen])

    def _remove_selected(self):
        selected_indices = list(self.listbox.curselection())
        for index in reversed(selected_indices):
            del self.paths[index]
        self._refresh_listbox()

    def _clear_all(self):
        self.paths = []
        self._refresh_listbox()


# --------------------------------------------------------------- vault tab
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
        self._bundle_label_var = tk.StringVar()
        ttk.Entry(encrypt_row, textvariable=self._bundle_label_var, width=30).pack(
            side="left", padx=(6, 8))
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
            self._bundle_label_var.set("")
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


# ---------------------------------------------------------- biometrics tab
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


# ------------------------------------------------------------- packages tab
class PackagesTab(ttk.Frame):
    """Create, add/remove recipients on, open, and inspect the custody chain
    of Identity-Bound Packages."""

    def __init__(self, master):
        super().__init__(master, padding=12)
        self.package_path = None
        self.state = None
        self._build_widgets()

    def _build_widgets(self):
        top = ttk.Frame(self)
        top.pack(fill="x", pady=(0, 8))
        ttk.Button(top, text="Choose Package File...", command=self._choose_path).pack(side="left")
        self._path_label = ttk.Label(top, text="(none selected)")
        self._path_label.pack(side="left", padx=8)

        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(0, 8))
        ttk.Button(actions, text="Create Package...", command=self._create_package).pack(side="left")
        ttk.Button(actions, text="Add Recipient...", command=self._add_recipient).pack(side="left", padx=4)
        ttk.Button(actions, text="Remove Recipient...", command=self._remove_recipient).pack(side="left", padx=4)
        ttk.Button(actions, text="Open Package...", command=self._open_package).pack(side="left", padx=4)
        ttk.Button(actions, text="Verify Custody", command=self._verify_custody).pack(side="left", padx=4)
        ttk.Button(actions, text="Run Demo", command=self._run_demo).pack(side="right")

        ttk.Label(self, text="Recipients:").pack(anchor="w")
        columns = ("identity_id", "label")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=8, selectmode="browse")
        for col, width in zip(columns, (200, 280)):
            self.tree.heading(col, text=col.replace("_", " ").title())
            self.tree.column(col, width=width)
        self.tree.pack(fill="both", expand=True)

    def _choose_path(self):
        chosen = filedialog.asksaveasfilename(
            title="Package file", defaultextension=".json", initialfile="package.json",
            filetypes=[("Package files", "*.json"), ("All files", "*.*")],
        )
        if chosen:
            self.package_path = Path(chosen)
            self._path_label.configure(text=str(self.package_path))
            self._load_state(quiet=True)

    def _load_state(self, quiet=False):
        if self.package_path is None or not self.package_path.is_file():
            self.state = None
            self._refresh_recipients()
            return
        try:
            with open(self.package_path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
            self.state = ibp_package.validate_package(raw)
        except (OSError, json.JSONDecodeError, PackageError, CustodyError) as exc:
            self.state = None
            if not quiet:
                messagebox.showerror(APP_TITLE, f"Could not load package: {exc}", parent=self)
        self._refresh_recipients()

    def _save_state(self):
        if self.package_path is None or self.state is None:
            return
        with open(self.package_path, "w", encoding="utf-8") as handle:
            json.dump(self.state, handle, indent=2, sort_keys=True)

    def _refresh_recipients(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        if self.state is None:
            return
        for recipient in ibp_package.list_recipients(self.state):
            self.tree.insert("", "end", values=(recipient["identity_id"], recipient["label"]))

    @staticmethod
    def _derive_master_key(text):
        return hashlib.sha256(text.encode("utf-8")).digest()

    def _prompt_payload(self, initial='{\n  "message": "hello"\n}'):
        dialog = tk.Toplevel(self)
        dialog.title("Payload (JSON object)")
        dialog.transient(self)
        text = scrolledtext.ScrolledText(dialog, width=56, height=12, wrap="word")
        text.insert("1.0", initial)
        text.pack(fill="both", expand=True, padx=12, pady=12)
        result = {}

        def on_ok():
            result["value"] = text.get("1.0", "end").strip()
            dialog.destroy()

        def on_cancel():
            dialog.destroy()

        row = ttk.Frame(dialog, padding=(12, 0, 12, 12))
        row.pack(fill="x")
        ttk.Button(row, text="Cancel", command=on_cancel).pack(side="right")
        ttk.Button(row, text="OK", command=on_ok).pack(side="right", padx=(0, 8))
        dialog.protocol("WM_DELETE_WINDOW", on_cancel)
        dialog.grab_set()
        dialog.wait_window(dialog)
        if "value" not in result:
            raise _Cancelled()
        return result["value"]

    def _create_package(self):
        if self.package_path is None:
            messagebox.showerror(APP_TITLE, "Choose a package file path first.", parent=self)
            return
        if self.package_path.is_file():
            messagebox.showerror(APP_TITLE, "A package file already exists at this path.", parent=self)
            return
        dialog = TextPromptDialog(
            self, "Create Package",
            [
                ("package_id", "Package id", False),
                ("identity_id", "Your identity id", False),
                ("label", "Your label", False),
                ("master_key", "Master key text (any text)", True),
            ],
        )
        if dialog.result is None:
            return
        values = dialog.result
        try:
            payload_text = self._prompt_payload()
        except _Cancelled:
            return
        package_id = values["package_id"].strip()
        identity_id = values["identity_id"].strip()
        label = values["label"].strip()
        if not package_id or not identity_id or not label:
            messagebox.showerror(APP_TITLE, "Package id, identity id, and label are required.", parent=self)
            return
        try:
            payload = json.loads(payload_text or "{}")
        except json.JSONDecodeError as exc:
            messagebox.showerror(APP_TITLE, f"Payload is not valid JSON: {exc}", parent=self)
            return
        master_key = self._derive_master_key(values["master_key"])
        audit_dir = Path("data") / "packages" / "audit"
        path = self.package_path

        def work():
            return ibp_package.create_package(
                package_id, label, payload, {identity_id: (label, master_key)}, audit_dir=audit_dir
            )

        def on_success(state):
            self.state = state
            self._save_state()
            self._refresh_recipients()
            messagebox.showinfo(APP_TITLE, f"Created package {package_id!r}.", parent=self)

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(self, work, on_success, on_error, "Creating package (sealing content key)...")

    def _add_recipient(self):
        if not self._require_state():
            return
        dialog = TextPromptDialog(
            self, "Add Recipient",
            [
                ("opener_id", "Your identity id (existing recipient)", False),
                ("opener_key", "Your master key text", True),
                ("new_id", "New recipient identity id", False),
                ("new_label", "New recipient label", False),
                ("new_key", "New recipient master key text", True),
            ],
        )
        if dialog.result is None:
            return
        values = dialog.result
        opener_key = self._derive_master_key(values["opener_key"])
        new_key = self._derive_master_key(values["new_key"])
        state = self.state
        audit_dir = Path("data") / "packages" / "audit"

        def work():
            return ibp_package.add_recipient(
                state, values["new_id"].strip(), values["new_label"].strip(), new_key,
                values["opener_id"].strip(), opener_key, audit_dir=audit_dir,
            )

        def on_success(updated):
            self.state = updated
            self._save_state()
            self._refresh_recipients()

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(self, work, on_success, on_error, "Adding recipient...")

    def _remove_recipient(self):
        if not self._require_state():
            return
        selection = self.tree.selection()
        default_id = self.tree.item(selection[0], "values")[0] if selection else ""
        dialog = TextPromptDialog(
            self, "Remove Recipient",
            [
                ("identity_id", f"Identity id to remove (default: {default_id})", False),
                ("opener_id", "Your identity id (authorizing this)", False),
                ("opener_key", "Your master key text", True),
            ],
        )
        if dialog.result is None:
            return
        values = dialog.result
        identity_id = values["identity_id"].strip() or default_id
        opener_key = self._derive_master_key(values["opener_key"])
        state = self.state
        audit_dir = Path("data") / "packages" / "audit"

        def work():
            return ibp_package.remove_recipient(
                state, identity_id, values["opener_id"].strip(), opener_key, audit_dir=audit_dir
            )

        def on_success(updated):
            self.state = updated
            self._save_state()
            self._refresh_recipients()

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(self, work, on_success, on_error, "Removing recipient...")

    def _open_package(self):
        if not self._require_state():
            return
        dialog = TextPromptDialog(
            self, "Open Package",
            [("identity_id", "Your identity id", False), ("master_key", "Master key text", True)],
        )
        if dialog.result is None:
            return
        values = dialog.result
        master_key = self._derive_master_key(values["master_key"])
        state = self.state
        audit_dir = Path("data") / "packages" / "audit"

        def work():
            return ibp_package.open_package(state, values["identity_id"].strip(), master_key, audit_dir=audit_dir)

        def on_success(result):
            payload, updated_state = result
            self.state = updated_state
            self._save_state()
            TextViewDialog(self, "Package Payload", json.dumps(payload, indent=2, sort_keys=True))

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(self, work, on_success, on_error, "Opening package...")

    def _verify_custody(self):
        if not self._require_state():
            return
        try:
            ibp_package.validate_package(self.state)
        except (PackageError, CustodyError) as exc:
            messagebox.showerror(APP_TITLE, f"Custody chain is invalid: {exc}", parent=self)
            return
        lines = [
            f"{entry['recorded_at']}  {entry['action']:<20} {entry['actor_label']}"
            for entry in ibp_package.custody_summary(self.state)
        ]
        TextViewDialog(self, "Custody Chain", "\n".join(lines) or "(empty)")

    def _require_state(self):
        if self.state is None:
            messagebox.showerror(APP_TITLE, "Choose and load a package file first.", parent=self)
            return False
        return True

    def _run_demo(self):
        def work():
            package_id = f"demo-{secrets.token_hex(4)}"
            alice_key = secrets.token_bytes(32)
            bob_key = secrets.token_bytes(32)
            log = [f"creating package {package_id!r} with recipient 'alice'..."]
            state = ibp_package.create_package(
                package_id, "Alice", {"message": "hello from the GUI demo package"},
                {"alice": ("Alice", alice_key)},
            )
            log.append("adding recipient 'bob' (authorized by alice)...")
            state = ibp_package.add_recipient(state, "bob", "Bob", bob_key, "alice", alice_key)
            log.append("opening the package as 'bob'...")
            payload, state = ibp_package.open_package(state, "bob", bob_key)
            log.append(f"bob opened the package and read: {payload!r}")
            log.append("verifying the custody chain...")
            ibp_package.validate_package(state)
            for entry in ibp_package.custody_summary(state):
                log.append(f"  {entry['recorded_at']}  {entry['action']:<20} {entry['actor_label']}")
            log.append("demo complete: custody chain is intact.")
            return "\n".join(log)

        def on_success(transcript):
            TextViewDialog(self, "Package Demo", transcript)

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(self, work, on_success, on_error, "Running demo (real BSR2 derivations)...")


# ---------------------------------------------------------------- app shell
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("900x640")
        self.minsize(760, 520)

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)
        notebook.add(VaultTab(notebook), text="Vault")
        notebook.add(BiometricsTab(notebook), text="Biometrics")
        notebook.add(PackagesTab(notebook), text="Packages")

        menu_bar = tk.Menu(self)
        file_menu = tk.Menu(menu_bar, tearoff=False)
        file_menu.add_command(label="Exit", command=self.destroy)
        menu_bar.add_cascade(label="File", menu=file_menu)
        help_menu = tk.Menu(menu_bar, tearoff=False)
        help_menu.add_command(label="About", command=self._show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        self.configure(menu=menu_bar)

    def _show_about(self):
        from version import __version__
        messagebox.showinfo(
            APP_TITLE,
            f"BrisartIdentityTools {__version__}\n\n"
            "Local identity tooling: a BSR2-encrypted vault (any file, folder, "
            "or drive, any size), local biometric verification with sealed "
            "templates and file attachments, and identity-bound packages.\n\n"
            "Standard library only. No cloud services, no third-party "
            "dependencies.",
        )


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
