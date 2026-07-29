"""
crypto.py
---------
Hash helpers for the Identity-Bound Package (IBP) BETA prototype.

*** NO ENCRYPTION HERE - BY DESIGN ***
This module intentionally provides ONLY hashing utilities. It does not
provide any confidentiality/encryption mechanism. Encryption is expected
to be handled by a dedicated security framework (e.g. BSR2 from
BrisartSecurityResearch) when confidentiality is required.

IBP's job is identity binding, authorization, audit trails, and custody
tracking - not protecting the secrecy of the payload.
"""

import hashlib


def hash_text(text: str) -> str:
    """Return the SHA-256 hex digest of a string."""
    return hashlib.sha256(text.encode()).hexdigest()


def hash_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()
