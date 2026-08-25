"""The shared multi-select file/folder/drive picker panel.

Used by both the Vault "Files / Folders / Drives" sub-tab and the Biometrics
"File Attachments" sub-tab, so the same behavior (add files via a real
multi-select dialog, add a folder, add a drive root, remove a selected entry)
only needs to be built and reasoned about once.

Selection is done entirely through tkinter.filedialog's real, guaranteed
cross-platform picker dialogs via the buttons below.
"""

import tkinter as tk
from tkinter import filedialog, ttk


class PathSelectionPanel(ttk.Frame):
    """A reusable panel for building up a list of files/folders/drives to
    bulk-encrypt or bulk-attach in one operation."""

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
        # user navigate to and select a drive root (e.g. "D:\\") directly,
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
