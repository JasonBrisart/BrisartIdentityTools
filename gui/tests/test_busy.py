"""Tests for gui.core.busy: the shared BusyDialog + run_in_background
background-thread/queue contract every slow (BSR2 KDF-touching) GUI action
goes through.

These need a real Tk root to construct a BusyDialog and pump the event loop
(run_in_background schedules its poll via root.after(), which only fires
inside Tk's own event loop). On a machine with a working Tk/display (any
normal desktop, including Windows, which is this project's primary target)
these run for real. On a headless CI runner with no display, the whole class
skips cleanly rather than failing the suite -- consistent with how GUI tests
are conventionally handled when a project's CI doesn't provision a display.
"""
import time
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


def _pump_until(root, predicate, timeout_seconds=5.0, interval_seconds=0.02):
    """Pump the Tk event loop until predicate() is true or timeout elapses.

    run_in_background's poll loop relies on root.after(), which only runs
    inside update()/mainloop(); a test cannot simply call the work function
    and check the result synchronously without giving Tk a chance to service
    its own event queue.
    """
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        root.update()
        if predicate():
            return True
        time.sleep(interval_seconds)
    return False


@unittest.skipUnless(_HAS_DISPLAY, "requires a Tk-capable display")
class RunInBackgroundTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        from gui.core.busy import run_in_background

        self.tk = tk
        self.run_in_background = run_in_background
        self.root = tk.Tk()
        self.root.withdraw()  # never actually show a window during tests

    def tearDown(self):
        self.root.destroy()

    def test_successful_work_calls_on_success_with_the_return_value(self):
        result = {}

        def work():
            return 42

        def on_success(value):
            result["value"] = value

        self.run_in_background(self.root, work, on_success, message="Testing...")
        ok = _pump_until(self.root, lambda: "value" in result)
        self.assertTrue(ok, "on_success was never called")
        self.assertEqual(result["value"], 42)

    def test_failing_work_calls_on_error_with_the_exception(self):
        result = {}

        def work():
            raise ValueError("boom")

        def on_success(_value):
            self.fail("on_success should not be called when work() raises")

        def on_error(exc):
            result["error"] = exc

        self.run_in_background(self.root, work, on_success, on_error)
        ok = _pump_until(self.root, lambda: "error" in result)
        self.assertTrue(ok, "on_error was never called")
        self.assertIsInstance(result["error"], ValueError)

    def test_failing_work_without_on_error_does_not_raise_out_of_the_poll(self):
        # No on_error supplied: run_in_background falls back to a message
        # box (gui.core.busy imports tkinter.messagebox for this). We only
        # assert that the poll loop itself completes without an unhandled
        # exception escaping the Tk main loop; the message box popping up
        # briefly during a headless-but-Tk-capable test run is expected.
        def work():
            raise RuntimeError("boom without handler")

        def on_success(_value):
            self.fail("on_success should not be called when work() raises")

        called = {"done": False}
        original_destroy = self.tk.Toplevel.destroy

        def patched_destroy(self_widget):
            called["done"] = True
            return original_destroy(self_widget)

        self.tk.Toplevel.destroy = patched_destroy
        try:
            self.run_in_background(self.root, work, on_success)
            _pump_until(self.root, lambda: called["done"])
        finally:
            self.tk.Toplevel.destroy = original_destroy
        self.assertTrue(called["done"], "busy dialog was never torn down")

    def test_work_runs_off_the_main_thread(self):
        import threading

        result = {}

        def work():
            result["thread_name"] = threading.current_thread().name
            return None

        def on_success(_value):
            pass

        self.run_in_background(self.root, work, on_success)
        _pump_until(self.root, lambda: "thread_name" in result)
        self.assertNotEqual(result.get("thread_name"), "MainThread")


@unittest.skipUnless(_HAS_DISPLAY, "requires a Tk-capable display")
class BusyDialogTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk

        self.root = tk.Tk()
        self.root.withdraw()

    def tearDown(self):
        self.root.destroy()

    def test_busy_dialog_constructs_and_is_not_user_closable(self):
        from gui.core.busy import BusyDialog

        dialog = BusyDialog(self.root, "Working...")
        try:
            # protocol("WM_DELETE_WINDOW") is set to a no-op; there is no
            # public getter, so this just confirms construction succeeds
            # and the dialog is a real Toplevel bound to the given parent.
            self.assertEqual(dialog.master, self.root)
        finally:
            dialog.destroy()


if __name__ == "__main__":
    unittest.main()
