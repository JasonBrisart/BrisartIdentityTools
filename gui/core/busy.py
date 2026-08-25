"""The threading core shared by all three tabs.

BSR2's password KDF is deliberately slow (tens of seconds to a couple of
minutes per call -- see docs/BSR2_INTEGRATION.md). Every operation that touches
the KDF (vault init/unlock, biometrics keyring create/unlock, any package
operation) therefore runs on a background thread behind a modal "Working..."
dialog, so the window never appears frozen. Tkinter is not thread-safe:
background threads never touch a widget directly, they only push a result onto
a queue that the main thread polls via ``after()``.

This lives in gui/core because it is the one piece every tab depends on;
centralizing it here keeps it from being duplicated into each tab file.
"""

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from gui.core.constants import APP_TITLE


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
