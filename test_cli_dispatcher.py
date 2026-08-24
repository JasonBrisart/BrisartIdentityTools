"""Tests for cli.py's dispatcher (the fast paths that do not import a tool)."""
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

import cli
from version import __version__


class CliDispatcherTests(unittest.TestCase):
    def test_version_prints_the_ecosystem_version(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.main(["version"])
        self.assertEqual(code, 0)
        self.assertIn(__version__, buffer.getvalue())

    def test_help_returns_zero(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["help"]), 0)

    def test_help_flags_are_aliases(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["--help"]), 0)
            self.assertEqual(cli.main(["-h"]), 0)

    def test_no_arguments_returns_two(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main([]), 2)

    def test_unknown_tool_returns_two(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["not-a-real-tool"]), 2)

    def test_every_documented_tool_is_dispatchable(self):
        for tool in ("biometrics", "vault", "package", "gui", "version", "help"):
            self.assertIn(tool, cli._DISPATCH)


if __name__ == "__main__":
    unittest.main()
