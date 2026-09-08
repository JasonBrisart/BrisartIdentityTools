"""Tests for gui.core.constants: the repo-root bootstrap walk and the
shared constants every other gui/ module depends on.

Fast and fully headless: _find_repo_root() is pure path arithmetic over
temporary directories built with tempfile, so this exercises the real
walk-up logic without needing tkinter, a display, or the actual repository
checkout on disk.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

# gui.core.constants runs its repo-root sys.path bootstrap at import time
# (see that module's docstring), which is exactly the behavior under test
# here. Importing it directly would only prove it works against THIS
# checkout, so _find_repo_root is instead loaded as a standalone function
# via importlib, decoupled from the module-level bootstrap side effect,
# and re-exercised against synthetic directory trees below.
_CONSTANTS_PATH = Path(__file__).resolve().parent.parent / "core" / "constants.py"


def _load_find_repo_root():
    spec = importlib.util.spec_from_file_location(
        "gui_core_constants_under_test", _CONSTANTS_PATH
    )
    module = importlib.util.module_from_spec(spec)
    # The module's own top-level bootstrap runs on exec_module(); that's
    # fine here since it only mutates sys.path (idempotent, harmless) and
    # does not require tkinter to import successfully.
    spec.loader.exec_module(module)
    return module


class FindRepoRootTests(unittest.TestCase):
    def setUp(self):
        self.module = _load_find_repo_root()

    def test_finds_root_when_version_py_is_two_levels_up(self):
        # Mirrors the real layout: gui/core/constants.py -> repo root is
        # two directories up (gui/core/../.. == root).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "version.py").write_text("__version__ = '0.0.0'\n")
            nested = root / "gui" / "core"
            nested.mkdir(parents=True)
            fake_file = nested / "constants.py"
            fake_file.write_text("# placeholder\n")

            found = self.module._find_repo_root(fake_file)
            self.assertEqual(found.resolve(), root.resolve())

    def test_finds_root_when_starting_file_is_directly_in_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "version.py").write_text("__version__ = '0.0.0'\n")
            fake_file = root / "some_module.py"
            fake_file.write_text("# placeholder\n")

            found = self.module._find_repo_root(fake_file)
            self.assertEqual(found.resolve(), root.resolve())

    def test_falls_back_to_top_of_walk_when_version_py_is_missing(self):
        # No version.py anywhere in the chain: the walk must not raise, and
        # must return SOME ancestor rather than crash the whole gui/ import.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "a" / "b" / "c"
            nested.mkdir(parents=True)
            fake_file = nested / "constants.py"
            fake_file.write_text("# placeholder\n")

            found = self.module._find_repo_root(fake_file)
            # Falls back to the top of the walk (filesystem root or the
            # highest parent reachable), never raises.
            self.assertTrue(found.exists())

    def test_prefers_the_nearest_ancestor_containing_version_py(self):
        # If version.py exists at multiple levels, the nearest one wins,
        # matching "first ancestor" semantics rather than "topmost".
        with tempfile.TemporaryDirectory() as tmp:
            outer = Path(tmp)
            (outer / "version.py").write_text("__version__ = '0.0.0'\n")
            inner = outer / "nested_repo"
            inner.mkdir()
            (inner / "version.py").write_text("__version__ = '0.0.0'\n")
            deeper = inner / "gui" / "core"
            deeper.mkdir(parents=True)
            fake_file = deeper / "constants.py"
            fake_file.write_text("# placeholder\n")

            found = self.module._find_repo_root(fake_file)
            self.assertEqual(found.resolve(), inner.resolve())


class ModuleConstantsTests(unittest.TestCase):
    def setUp(self):
        self.module = _load_find_repo_root()

    def test_app_title_is_a_non_empty_string(self):
        self.assertIsInstance(self.module.APP_TITLE, str)
        self.assertTrue(self.module.APP_TITLE)

    def test_modality_filetypes_keys_are_known_modalities(self):
        # Every key must be a plausible modality name; this doesn't require
        # biometrics.engine.modalities to agree exactly (that coupling is
        # exercised in gui/widgets/dialogs.py's ModalityPathDialog instead),
        # only that the table is well-formed: string keys, list-of-tuple
        # values shaped like tkinter filetypes.
        for modality, filetypes in self.module._MODALITY_FILETYPES.items():
            self.assertIsInstance(modality, str)
            self.assertIsInstance(filetypes, list)
            for entry in filetypes:
                self.assertEqual(len(entry), 2)
                label, pattern = entry
                self.assertIsInstance(label, str)
                self.assertIsInstance(pattern, str)

    def test_cancelled_is_an_exception_type(self):
        self.assertTrue(issubclass(self.module._Cancelled, Exception))


if __name__ == "__main__":
    unittest.main()
