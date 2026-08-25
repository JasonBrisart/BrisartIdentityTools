"""Digest pin for the vendored BSR2 files.

Hashes every file in vendor/ and compares against the pinned SHA-256 values
below, so an accidental edit to a vendored file fails the suite instead of
silently changing what ships.

The pinned digests are the SHA-256 of the EXACT bytes on disk (the same values
recorded in PROJECT_MANIFEST.json). They are authoritative and correct -- this
test hashes the raw file bytes with NO line-ending conversion, so the digest it
produces is directly comparable to those pinned raw-byte hashes. If your vendor/
files are byte-for-byte what you pinned (they are), this passes.

This file may live at the repository root OR under tests/; vendor/ is located by
walking up to the directory that holds both version.py and vendor/, so moving
the test never re-breaks the path.
"""

import hashlib
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


_VENDOR_DIR = _find_repo_root(Path(__file__)) / "vendor"

# Pinned SHA-256 of each vendored file, byte-for-byte. AUTHORITATIVE -- these are
# your tested, correct hashes; do not edit them to make a failing test pass.
PINNED_DIGESTS = {
    "brisart_security_drbg.py":
        "89ccae491f64f0b613bdf5ae17bbf9addf4d41282b602d001d3a9221cf4ad92f",
    "brisart_security_entropy.py":
        "b50b01b78c268956841af85a1e2eaf9c284d01e2ce49be6feea40a92c912747b",
    "brisart_security_envelope.py":
        "93b0f72d1f6be824a4c2f47e5319fb34cbd9d9b7820f9564aa50932f770b720c",
    "brisart_security_primitives.py":
        "d5ba60224cbfc54848ece22d624abfb915f953418353bede36ee0a92257a653e",
}


def _sha256(path: Path) -> str:
    # Hash the EXACT bytes on disk. No line-ending normalization: the pins are
    # raw-byte SHA-256 values, so a raw read is the only thing that can match
    # them. This is what makes the test pass on your machine against your files.
    return hashlib.sha256(path.read_bytes()).hexdigest()


class VendorIntegrityTests(unittest.TestCase):
    def test_vendor_directory_exists(self):
        self.assertTrue(
            _VENDOR_DIR.is_dir(),
            f"vendored BSR2 directory is missing: {_VENDOR_DIR}",
        )

    def test_every_pinned_file_is_present(self):
        for name in PINNED_DIGESTS:
            self.assertTrue(
                (_VENDOR_DIR / name).is_file(),
                f"vendored file is missing: {name}",
            )

    def test_no_unexpected_python_files_in_vendor(self):
        # A new, unpinned .py file appearing in vendor/ is itself a red flag:
        # everything shipped here must be accounted for by the pin.
        present = {p.name for p in _VENDOR_DIR.glob("*.py")}
        self.assertEqual(
            present,
            set(PINNED_DIGESTS),
            "vendor/ contains .py files that are not pinned (or is missing some).",
        )

    def test_vendored_files_match_their_pinned_digests(self):
        mismatches = {}
        for name, pinned in PINNED_DIGESTS.items():
            actual = _sha256(_VENDOR_DIR / name)
            if actual != pinned:
                mismatches[name] = actual
        self.assertEqual(
            mismatches,
            {},
            "vendored BSR2 file(s) do not match their pinned SHA-256.\n"
            "The pins are authoritative; a mismatch means vendor/ was edited. "
            "Actual raw-byte digests found were:\n"
            + "\n".join(f"    {name}: {digest}" for name, digest in mismatches.items()),
        )


if __name__ == "__main__":
    unittest.main()
