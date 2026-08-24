"""SHA-256 helpers, the single canonical copy.

Replaces the byte-identical sha256_bytes/sha256_file that were pasted into five
LabID feature modules. The 1 MiB streaming read is preserved so a large
biometric sample is never loaded whole into memory. These are integrity
fingerprints over non-secret content; secret material goes through the BSR2
factor and envelope layers instead.
"""
import hashlib
from pathlib import Path
from typing import Union

_CHUNK_BYTES = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of a bytes object."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Union[str, Path]) -> str:
    """Return the SHA-256 hex digest of a file, read in 1 MiB chunks."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()
