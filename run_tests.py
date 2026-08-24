#!/usr/bin/env python3
"""Run the full test suite from one entry point.

Now that the repository is a single flat tree with fully-qualified imports
throughout, one `unittest discover` from the repository root finds every
tests/ directory in the tree (biometrics/tests/, vault/tests/,
packages/tests/) in a single pass -- the old per-tool discovery split is
no longer needed.

Usage:
    python3 run_tests.py            # run everything
    python3 run_tests.py -v         # verbose
"""
import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent


def run_suite(verbose: bool) -> bool:
    command = [
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "-s",
        ".",
        "-t",
        ".",
    ]
    if verbose:
        command.append("-v")
    completed = subprocess.run(
        command,
        cwd=str(REPOSITORY_ROOT),
        check=False,
    )
    return completed.returncode == 0


def main():
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    passed = run_suite(verbose)
    print("\n=== summary ===")
    print(f"{'PASS' if passed else 'FAIL'}  full suite")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())