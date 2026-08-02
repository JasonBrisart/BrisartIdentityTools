#!/usr/bin/env python3
"""Run every test suite in this repository from one entry point.

The three application trees use different import roots, so no single
``unittest discover`` invocation could collect them all:

* ``IdentityVault_beta`` uses absolute ``IdentityVault_beta.*`` imports and
  needs the repository root on ``sys.path``.
* ``LabID_Beta`` uses root-relative imports (``config.settings``, ``core.pgm``)
  and needs its own directory on ``sys.path``.
* ``identity_bound_packages`` uses flat imports and likewise needs its own
  directory on ``sys.path``.

Usage:
    python3 run_tests.py            # run everything
    python3 run_tests.py -v         # verbose
"""

import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent

# (label, working directory, discovery start directory, top-level directory)
SUITES = (
    (
        "IdentityVault_beta",
        REPOSITORY_ROOT,
        "IdentityVault_beta/tests",
        ".",
    ),
    (
        "LabID_Beta",
        REPOSITORY_ROOT / "LabID_Beta",
        "tests",
        ".",
    ),
    (
        "identity_bound_packages",
        REPOSITORY_ROOT / "identity_bound_packages",
        "tests",
        ".",
    ),
)


def run_suite(label, working_directory, start_directory, top_level, verbose):
    command = [
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "-s",
        start_directory,
        "-t",
        top_level,
    ]

    if verbose:
        command.append("-v")

    print(f"\n=== {label} ===", flush=True)

    completed = subprocess.run(
        command,
        cwd=str(working_directory),
        check=False,
    )

    return completed.returncode == 0


def main():
    verbose = "-v" in sys.argv or "--verbose" in sys.argv

    results = {}

    for label, working_directory, start_directory, top_level in SUITES:
        results[label] = run_suite(
            label,
            working_directory,
            start_directory,
            top_level,
            verbose,
        )

    print("\n=== summary ===")
    for label, passed in results.items():
        print(f"{'PASS' if passed else 'FAIL'}  {label}")

    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
