"""The Packages tab: create, add/remove recipients on, open, and inspect the
custody chain of Identity-Bound Packages.

Two demo entry points are provided, both backed by the single shared
packages.demo.run_demo() implementation so the CLI's `demo` command and this
tab can never drift apart from each other:

    "Run Demo"              -- the original, in-memory-only sanity check.
                               Nothing is written to disk; the result is
                               shown once in a read-only transcript dialog
                               and then gone.
    "Run Demo (Save Files)" -- runs the identical cycle, but additionally
                               writes the real package file, both
                               recipients' passphrase text, and a formatted
                               custody-chain summary to a clearly-named
                               folder on disk, and offers to open that
                               folder in the OS file manager so a new user
                               can inspect (and try tampering with) real
                               artifacts firsthand.
"""
import hashlib
import json
import os
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from gui.core.constants import APP_TITLE, _Cancelled
from gui.core.busy import run_in_background
from gui.widgets.dialogs import TextPromptDialog, TextViewDialog
from packages import package as ibp_package
from packages.custody import CustodyError
from packages.demo import run_demo
from packages.package import PackageError


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
        ttk.Button(actions, text="Run Demo (Save Files)", command=self._run_demo_to_folder).pack(side="right")
        ttk.Button(actions, text="Run Demo", command=self._run_demo).pack(side="right", padx=(0, 4))

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
        """Run the original, in-memory-only demo. Nothing is written to
        disk; the transcript is shown once and then discarded."""

        def work():
            result = run_demo(save_to_disk=False)
            return "\n".join(result["transcript"])

        def on_success(transcript):
            TextViewDialog(self, "Package Demo", transcript)

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(self, work, on_success, on_error, "Running demo (real BSR2 derivations)...")

    def _run_demo_to_folder(self):
        """Run the same demo cycle as _run_demo, but additionally write the
        real package file, both recipients' passphrase text, and a
        formatted custody-chain summary to a clearly-named folder on disk,
        then offer to open that folder in the OS file manager."""

        def work():
            return run_demo(save_to_disk=True)

        def on_success(result):
            transcript = "\n".join(result["transcript"])
            TextViewDialog(self, "Package Demo (Saved to Disk)", transcript)
            folder = result.get("folder")
            if folder is not None and messagebox.askyesno(
                APP_TITLE,
                f"Demo artifacts saved to:\n{folder}\n\nOpen this folder now?",
                parent=self,
            ):
                self._open_folder(folder)

        def on_error(exc):
            messagebox.showerror(APP_TITLE, str(exc), parent=self)

        run_in_background(self, work, on_success, on_error, "Running demo and saving artifacts...")

    @staticmethod
    def _open_folder(folder: Path) -> None:
        """Open a folder in the OS's file manager, best-effort only.

        Uses os.startfile on Windows (this project's primary development
        platform per version.py's git history), and falls back to `open`
        (macOS) / `xdg-open` (Linux) elsewhere. Never raises: if none of
        these succeed, the folder path was already shown in the dialog the
        caller just displayed, so a failure here only means the user
        navigates there manually instead of automatically.
        """
        try:
            if os.name == "nt":
                os.startfile(str(folder))  # noqa: S606 - user-initiated, local path only
            elif sys.platform == "darwin":
                subprocess.run(["open", str(folder)], check=False)
            else:
                subprocess.run(["xdg-open", str(folder)], check=False)
        except OSError:
            pass
