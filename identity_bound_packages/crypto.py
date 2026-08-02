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
import hmac


def hash_text(text: str) -> str:
    """Return the SHA-256 hex digest of a string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def digests_equal(left, right) -> bool:
    """Compare two hex digests in constant time.

    Plain ``==`` on digests short-circuits at the first differing character,
    which leaks how much of a guess was correct through timing. ``compare_digest``
    does not. It also raises on a non-string operand, so ``None`` (a missing
    signature or an unset factor hash) is normalised to a mismatch here rather
    than crashing the caller.
    """
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left, right)
