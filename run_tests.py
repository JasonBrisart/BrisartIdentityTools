#!/usr/bin/env python3
"""Run the BrisartIdentityTools test suite.

The repository is one flat PEP 420 namespace-package tree with no __init__.py
files, and conftest.py is a pytest-only hook that `unittest` never loads. A
blanket `unittest discover -s . -t .` is therefore fragile: it can silently
collect nothing or error on import. This runner instead discovers each tests/
directory explicitly (with the repository root as top_level_dir, so imports
like `crypto.tests.test_envelope` resolve as namespace packages on every
supported Python), adds the two root-level test modules by name, and fails
loudly if collection hits an import error rather than passing with zero tests.

A handful of tests exercise BSR2's real, deliberately-slow password KDF
(~1 minute per derivation on CI hardware). They are grouped by class in
SLOW_TEST_CLASSES so they can be run separately from everything else:

    python run_tests.py            run every test
    python run_tests.py --fast     everything EXCEPT the slow real-KDF tests
    python run_tests.py --slow     ONLY the slow real-KDF tests
    python run_tests.py --fast -v  verbose (combine with --fast/--slow)
"""
import argparse
import sys
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

# Every directory that holds tests, discovered as a namespace subpackage.
TEST_DIRECTORIES = [
    "crypto/tests",
    "common/tests",
    "vault/tests",
    "biometrics/tests",
    "packages/tests",
]

# Test modules that live at the repository root (top-level modules).
ROOT_TEST_MODULES = [
    "test_bsr2_vendor_integrity",
    "test_cli_dispatcher",
]

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
    for directory in TEST_DIRECTORIES:
        start = REPOSITORY_ROOT / directory
        if not start.is_dir():
            continue
        collected.addTests(
            loader.discover(
                start_dir=str(start),
                pattern="test_*.py",
                top_level_dir=str(REPOSITORY_ROOT),
            )
        )
    for module_name in ROOT_TEST_MODULES:
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
    parser = argparse.ArgumentParser(
        description="Run the BrisartIdentityTools test suite."
    )
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--fast", action="store_true",
                           help="skip the slow real-KDF tests.")
    selection.add_argument("--slow", action="store_true",
                           help="run ONLY the slow real-KDF tests.")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    mode = "fast" if args.fast else "slow" if args.slow else "all"
    suite = build_suite(mode)
    result = unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite)

    print(f"\n=== summary ({mode}) ===")
    print(f"{'PASS' if result.wasSuccessful() else 'FAIL'}  "
          f"ran {result.testsRun} test(s)")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())