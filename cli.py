"""Unified entry point: python cli.py <tool> ...

    python cli.py biometrics enroll ...
    python cli.py vault --vault v.json init
    python cli.py package demo
    python cli.py gui
    python cli.py version

Everything now lives flat at the repo root (no wrapper package), so each
tool's main() is called in-process with a plain top-level import. Tool
modules are imported lazily so `version`/`help` never pay an import cost for
a tool they are not running.
"""
import sys

from version import __version__

USAGE = """\
brisart - unified entry point for BrisartIdentityTools

Usage:
  python cli.py <tool> [args...]

Tools:
  biometrics [args...]   Local biometric enroll/verify
  vault      [args...]   Encrypted record store
  package    [args...]   Identity-bound packages
  gui                    Launch the desktop GUI (Tkinter)
  version                Print the ecosystem version
  help                   Show this message
"""


def _run_biometrics(rest):
    from biometrics import app
    sys.argv = ["brisart-biometrics", *rest]
    app.main()
    return 0


def _run_vault(rest):
    from vault import app
    sys.argv = ["brisart-vault", *rest]
    app.main()
    return 0


def _run_package(rest):
    from packages import main as package_main
    sys.argv = ["brisart-package", *rest]
    package_main.main()
    return 0


def _run_gui(_rest):
    from gui import app
    app.main()
    return 0


def _run_version(_rest):
    print(f"BrisartIdentityTools {__version__}")
    return 0


def _run_help(_rest):
    print(USAGE)
    return 0


_DISPATCH = {
    "biometrics": _run_biometrics,
    "vault": _run_vault,
    "package": _run_package,
    "gui": _run_gui,
    "version": _run_version,
    "help": _run_help,
    "--help": _run_help,
    "-h": _run_help,
}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(USAGE, file=sys.stderr)
        return 2
    tool, rest = argv[0], argv[1:]
    handler = _DISPATCH.get(tool)
    if handler is None:
        print(f"brisart: unknown tool '{tool}'.\n", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2
    try:
        return handler(rest)
    except SystemExit as exit_exc:
        return int(exit_exc.code or 0)


if __name__ == "__main__":
    raise SystemExit(main())
