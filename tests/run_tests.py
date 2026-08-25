#!/usr/bin/env python3
"""Run the BrisartIdentityTools test suite.

The repository is one flat PEP 420 namespace-package tree with no __init__.py
files. unittest's discover(start_dir=...) cannot import a namespace sub-package
as a start directory, so this runner instead finds every test_*.py file on disk,
converts each path to its dotted module name, and loads it by name. Loading by
dotted name works for namespace packages as long as the repository root is on
sys.path (added below).

This file may live at the repository root OR under tests/; the repository root
is located by walking up to the directory that holds both version.py and
vendor/, so relocating the runner never breaks discovery or sys.path.

A handful of tests exercise BSR2's real, deliberately-slow password KDF
(~1 minute per derivation), grouped by class in SLOW_TEST_CLASSES so they can be
run separately:

    python tests/run_tests.py            run every test
    python tests/run_tests.py --fast     everything EXCEPT the slow real-KDF tests
    python tests/run_tests.py --slow     ONLY the slow real-KDF tests
    python tests/run_tests.py --fast -v  verbose
"""

import argparse
import sys
import unittest
from pathlib import Path


def _find_repo_root(start: Path) -> Path:
    """Return the repository root: the first ancestor of ``start`` (including
    ``start``'s own directory) that contains both ``version.py`` and
    ``vendor/``."""
    current = start.resolve().parent
    for candidate in (current, *current.parents):
        if (candidate / "version.py").is_file() and (candidate / "vendor").is_dir():
            return candidate
    return current


REPOSITORY_ROOT = _find_repo_root(Path(__file__))
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

# TestCase classes that run BSR2's real password KDF and are slow by design.
# Filtered at the class level so a module holding BOTH fast and slow classes
# (test_keyring, test_factors, test_label_normalization) still runs its fast
# classes under --fast.
SLOW_TEST_CLASSES = {
    "vault.tests.test_sealed_vault.SealedVaultTests",
    "vault.tests.test_file_records.FileRecordTests",
    "vault.tests.test_batch_upsert.BatchUpsertTests",
    "vault.tests.test_label_normalization.VaultLookupNormalizationTests",
    "crypto.tests.test_keyring.KeyringUnlockTests",
    "crypto.tests.test_factors.FactorHashKdfRoundTripTests",
}

_EXCLUDED_PARTS = {
    "__pycache__", "vendor", ".git", "build", "dist",
    ".venv", "venv", "node_modules", ".idea", ".vscode",
    "PROJECT_CONTEXT_EXPORTS", "data",
}


def _discover_module_names():
    names = []
    for path in sorted(REPOSITORY_ROOT.rglob("test_*.py")):
        relative = path.relative_to(REPOSITORY_ROOT)
        if any(part in _EXCLUDED_PARTS for part in relative.parts):
            continue
        names.append(".".join(relative.with_suffix("").parts))
    return names


def _iter_tests(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _iter_tests(item)
        else:
            yield item


def _class_id(test):
    # test.id() -> "module.Class.method"; drop the trailing ".method".
    return test.id().rsplit(".", 1)[0]


def build_suite(mode):
    loader = unittest.TestLoader()
    collected = unittest.TestSuite()
    for module_name in _discover_module_names():
        collected.addTests(loader.loadTestsFromName(module_name))
    if loader.errors:
        for message in loader.errors:
            print(message, file=sys.stderr)
        raise SystemExit("test collection failed; see the import errors above.")
    if mode == "all":
        return collected
    filtered = unittest.TestSuite()
    for test in _iter_tests(collected):
        is_slow = _class_id(test) in SLOW_TEST_CLASSES
        if (mode == "fast" and not is_slow) or (mode == "slow" and is_slow):
            filtered.addTest(test)
    return filtered


def main():
    parser = argparse.ArgumentParser(description="Run the BrisartIdentityTools test suite.")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--fast", action="store_true", help="skip the slow real-KDF tests.")
    selection.add_argument("--slow", action="store_true", help="run ONLY the slow real-KDF tests.")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    mode = "fast" if args.fast else "slow" if args.slow else "all"
    suite = build_suite(mode)
    result = unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite)
    print(f"\n=== summary ({mode}) ===")
    print(f"{'PASS' if result.wasSuccessful() else 'FAIL'}  ran {result.testsRun} test(s)")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
