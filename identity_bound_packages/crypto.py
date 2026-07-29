"""
crypto.py
---------
Hashing + payload obfuscation helpers for the Identity-Bound Package
BETA prototype.

*** RESEARCH / DEMO ONLY ***
The XOR routine below is NOT encryption. It is reversible obfuscation
used purely to demonstrate the package workflow. Do NOT use this to
protect real secrets. A production version must use a reviewed
cryptography library (e.g. AES-GCM + real key management).
"""

import hashlib


def hash_text(text: str) -> str:
    """Return the SHA-256 hex digest of a string."""
    return hashlib.sha256(text.encode()).hexdigest()


def hash_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def derive_key(seed: str) -> bytes:
    """Derive a 32-byte key from a seed string (demo only)."""
    return hashlib.sha256(seed.encode()).digest()


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """
    Reversible XOR transform (obfuscation, NOT encryption).
    Running it twice with the same key returns the original data.
    """
    out = bytearray()
    for i, value in enumerate(data):
        out.append(value ^ key[i % len(key)])
    return bytes(out)
