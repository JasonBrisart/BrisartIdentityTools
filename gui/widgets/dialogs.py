"""Modal dialog helpers shared across the three tabs.

None of these dialogs touch the application/service layer or the BSR2 KDF --
they only collect input or display text. The slow work a dialog's result feeds
into is always run through gui.core.busy.run_in_background by the caller, never
here.
"""

import json
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from gui.core.constants import _MODALITY_FILETYPES
from biometrics.engine import modalities as bio_modalities


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
            messagebox.showerror("BrisartIdentityTools", "Label cannot be empty.", parent=self)
            return
        if not kind:
            messagebox.showerror("BrisartIdentityTools", "Kind cannot be empty.", parent=self)
            return
        try:
            payload = json.loads(raw_payload or "{}")
        except json.JSONDecodeError as exc:
            messagebox.showerror("BrisartIdentityTools", f"Payload is not valid JSON: {exc}", parent=self)
            return
        if not isinstance(payload, dict):
            messagebox.showerror("BrisartIdentityTools", "Payload must be a JSON object.", parent=self)
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
    for every registered modality (biometrics.engine.modalities), so a
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
