"""Drag-and-drop support shim -- intentionally disabled.

HISTORY / WHY THIS IS A STUB:
An earlier version of this module attempted native Windows file drag-and-drop
by subclassing the Tk window's message procedure (WNDPROC) via ctypes and
intercepting WM_DROPFILES. That approach had a fatal ctypes bug: the original
WNDPROC returned by GetWindowLongPtrW is a 64-bit pointer, but without an
explicit restype ctypes truncated it to a 32-bit int. Forwarding messages
through that truncated pointer read invalid memory, raising

    OSError: exception: access violation reading 0x...

on essentially every window message -- an unrecoverable, screen-filling crash
loop that froze the whole GUI.

Rather than ship an unverifiable, crash-prone native hook in a 1.0.0 release,
drag-and-drop is DISABLED here. This module keeps the exact same public API
(is_supported / enable_file_drop / disable_file_drop) so gui/app.py needs no
changes: enable_file_drop simply returns False, the PathSelectionPanel shows
its "use the buttons below" note, and the guaranteed-working "Add Files...",
"Add Folder...", and "Add Drive..." buttons (tkinter.filedialog) are used
instead. Nothing in the application depends on drag-and-drop functioning.

If real drag-and-drop is wanted in a future version, the correct fix is to
declare argtypes/restype = ctypes.c_void_p on GetWindowLongPtrW /
SetWindowLongPtrW / CallWindowProcW (or use the tkinterdnd2 package), and to
verify it on an actual Windows machine before shipping. It is deliberately
NOT re-enabled here.
"""


def is_supported() -> bool:
    """Report whether native drag-and-drop is available. Always False: this
    build ships with drag-and-drop disabled (see module docstring)."""
    return False


def enable_file_drop(tk_widget, on_files_dropped) -> bool:
    """No-op. Returns False so callers fall back to their Browse buttons.

    Takes the same arguments as the original implementation so callers do
    not need to change, but does nothing at all -- no WNDPROC is replaced,
    so the access-violation crash loop cannot occur.
    """
    return False


def disable_file_drop(tk_widget) -> None:
    """No-op. Safe to call unconditionally; there is nothing to undo."""
    return None
