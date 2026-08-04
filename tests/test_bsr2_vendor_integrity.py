"""Guard the vendored BSR2 files against local modification.

The four files in ``bsr2_vendor/`` are copied byte-identical from
BrisartSecurityResearch. Editing one locally would silently fork the construction:
data sealed by the forked build would still decrypt under the forked build, so
nothing would look wrong until an upstream update or a second installation failed
to open it.

Pinning digests turns that silent fork into a failing test. When taking a genuine
upstream update, re-copy all four files and update both these digests and the
commit SHA in ``bsr2_vendor/README.md``.
"""

import hashlib
import unittest
from pathlib import Path

VENDOR_DIR = Path(__file__).resolve().parent.parent / "bsr2_vendor"

UPSTREAM_COMMIT = "656d962c447b7ac69d76b717820c34ae8e56b38a"

EXPECTED_DIGESTS = {
    "brisart_security_drbg.py": (
        "11db87c761e1f1b3c4c927aa6abac0ef72bb8987943e81e155df0f8ca92c3ce7"
    ),
    "brisart_security_entropy.py": (
        "efa8db935dc51a73f4729c4d68d91dac663f359bae01ed6c18adf1d566252252"
    ),
    "brisart_security_envelope.py": (
        "e0233e4c0ed8c2ec6754aede0f683f3530f1714a60592515736e9688364c55fe"
    ),
    "brisart_security_primitives.py": (
        "c131ba20d8cad116bf82422904e3a9f3f140edee22a8af14f5a00732c5e5524d"
    ),
}


class VendorIntegrityTests(unittest.TestCase):
    def test_vendor_directory_exists(self):
        self.assertTrue(
            VENDOR_DIR.is_dir(),
            f"vendored BSR2 directory is missing: {VENDOR_DIR}",
        )

    def test_every_vendored_file_matches_upstream(self):
        for name, expected in sorted(EXPECTED_DIGESTS.items()):
            with self.subTest(vendored_file=name):
                path = VENDOR_DIR / name
                self.assertTrue(path.is_file(), f"missing vendored file: {name}")
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                self.assertEqual(
                    expected,
                    digest,
                    f"{name} does not match the pinned upstream digest. "
                    "Do not edit vendored BSR2 files; see bsr2_vendor/README.md.",
                )

    def test_no_unexpected_vendored_modules(self):
        found = {
            path.name
            for path in VENDOR_DIR.glob("brisart_security_*.py")
        }
        self.assertEqual(
            set(EXPECTED_DIGESTS),
            found,
            "vendored module set changed; update EXPECTED_DIGESTS deliberately.",
        )

    def test_readme_records_the_pinned_commit(self):
        readme = (VENDOR_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            UPSTREAM_COMMIT,
            readme,
            "bsr2_vendor/README.md must record the pinned upstream commit.",
        )


if __name__ == "__main__":
    unittest.main()
