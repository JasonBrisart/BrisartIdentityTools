"""Digest pin for the vendored BSR2 files.

Recreates the integrity test that was dropped during the 1.0.0 restructure
(flagged as an open item in README.md, docs/BSR2_INTEGRATION.md, and
vendor/README.md). It hashes every file in vendor/ and compares against the
pinned SHA-256 values below, so an accidental edit to a vendored file -- or a
lint autofix, or an upstream drift -- fails the suite instead of silently
changing what ships.

The pinned hashes below were taken from PROJECT_MANIFEST.json for the working
tree that shipped 1.0.0. To take a legitimate upstream update: re-copy the four
files, run this test to see the new digests it prints on failure, and paste
them in (see vendor/README.md's "Re-syncing" section).
"""
import hashlib
import unittest
from pathlib import Path

# This file lives at the repository root, next to vendor/, so vendor/ is ONE
# level up from it -- Path(__file__).parent is the repo root itself.
_VENDOR_DIR = Path(__file__).resolve().parent / "vendor"

# Pinned SHA-256 of each vendored file, byte-for-byte, as shipped in 1.0.0.
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


def _sha256(path):
    # Normalize line endings before hashing so a Windows (CRLF) checkout and a
    # Linux/CI (LF) checkout of the SAME file produce the SAME digest. This is
    # a byte-exact vendoring pin on CONTENT, not on incidental line endings.
    data = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(data).hexdigest()


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
            "If this is an intentional upstream re-sync, update PINNED_DIGESTS "
            "with these actual values:\n"
            + "\n".join(f"    {name}: {digest}" for name, digest in mismatches.items()),
        )


if __name__ == "__main__":
    unittest.main()
