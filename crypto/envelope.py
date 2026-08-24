"""BSR2 envelope operations with length-hiding padding.

All encryption and authentication is BSR2's. This module adds two things around
it.

**Padding.** A BSR2 envelope's ciphertext is exactly as long as its plaintext,
because the construction XORs a keystream over the plaintext with no block
structure. For identity data that leaks more than it looks like: an encrypted
vault record whose ciphertext is 41 bytes narrows the stored value considerably,
and across many records the size pattern alone distinguishes a short credential
from a long recovery note. Plaintext is therefore length-prefixed and padded to a
256-byte multiple before being handed to BSR2, so ciphertext size reveals only
which bucket the plaintext fell into.

**Canonical JSON.** Objects are serialised with sorted keys and no incidental
whitespace, so resealing identical content produces identical plaintext and
diffs stay meaningful.

The padding is applied *inside* the BSR2 plaintext, so it is fully covered by
BSR2's authentication tag. Length recovery happens only after the tag verifies,
which means a forged envelope can never steer the unpadding logic.
"""
import json

from crypto.errors import (
    Bsr2IntegrationError,
    EnvelopeAuthenticationError,
)
from crypto.vendor import (
    ALGORITHM,
    MAX_PLAINTEXT_BYTES,
    VERSION,
    BrisartEnvelopeError,
    decrypt,
    encrypt,
)

PADDING_BLOCK_BYTES = 256
_LENGTH_PREFIX_BYTES = 8
_ENVELOPE_FIELDS = frozenset(
    {"algorithm", "version", "salt", "nonce", "ciphertext", "tag"}
)

# Leave room for the prefix and one full padding block under BSR2's own limit.
MAX_PAYLOAD_BYTES = MAX_PLAINTEXT_BYTES - _LENGTH_PREFIX_BYTES - PADDING_BLOCK_BYTES


def _pad(plaintext: bytes) -> bytes:
    prefixed = len(plaintext).to_bytes(_LENGTH_PREFIX_BYTES, "big") + plaintext
    remainder = len(prefixed) % PADDING_BLOCK_BYTES
    if remainder:
        prefixed += b"\x00" * (PADDING_BLOCK_BYTES - remainder)
    return prefixed


def _unpad(padded: bytes) -> bytes:
    if len(padded) < _LENGTH_PREFIX_BYTES:
        raise Bsr2IntegrationError("decrypted payload is truncated.")
    declared = int.from_bytes(padded[:_LENGTH_PREFIX_BYTES], "big")
    available = len(padded) - _LENGTH_PREFIX_BYTES
    if declared > available:
        raise Bsr2IntegrationError(
            "decrypted payload declares a length beyond its own data."
        )
    return padded[_LENGTH_PREFIX_BYTES:_LENGTH_PREFIX_BYTES + declared]


def is_envelope(value) -> bool:
    """Report whether ``value`` looks like a BSR2 envelope.

    Used by migration code to tell a sealed payload from a legacy plaintext one
    without attempting to decrypt.
    """
    return (
        isinstance(value, dict)
        and set(value) == _ENVELOPE_FIELDS
        and value.get("algorithm") == ALGORITHM
        and value.get("version") == VERSION
    )


def seal_bytes(master_key: bytes, plaintext: bytes, context: str, rng) -> dict:
    """Pad and seal ``plaintext`` into a BSR2 envelope."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise Bsr2IntegrationError("plaintext must be bytes.")
    if len(plaintext) > MAX_PAYLOAD_BYTES:
        raise Bsr2IntegrationError("plaintext exceeds the supported size limit.")
    return encrypt(master_key, _pad(bytes(plaintext)), context, rng)


def open_bytes(master_key: bytes, envelope: dict, context: str) -> bytes:
    """Verify, decrypt, and unpad a BSR2 envelope.

    An authentication failure from the vendored layer is re-raised as
    :class:`EnvelopeAuthenticationError` so callers only ever need to catch
    ``Bsr2IntegrationError`` and its subclasses, never a vendor exception type.
    The original is preserved as ``__cause__``.
    """
    try:
        padded = decrypt(master_key, envelope, context)
    except BrisartEnvelopeError as exc:
        raise EnvelopeAuthenticationError(
            "sealed payload failed authentication: wrong key, wrong context, "
            "or modified ciphertext."
        ) from exc
    return _unpad(padded)


def seal_json(master_key: bytes, payload: dict, context: str, rng) -> dict:
    """Seal a JSON-serialisable object."""
    if not isinstance(payload, dict):
        raise Bsr2IntegrationError("payload must be an object.")
    try:
        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise Bsr2IntegrationError(
            "payload is not JSON-serialisable."
        ) from exc
    return seal_bytes(master_key, serialized, context, rng)


def open_json(master_key: bytes, envelope: dict, context: str) -> dict:
    """Open an envelope sealed by :func:`seal_json`."""
    plaintext = open_bytes(master_key, envelope, context)
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        # Reached only after the tag verified, so this means genuine corruption
        # rather than tampering.
        raise Bsr2IntegrationError(
            "decrypted payload is not valid JSON."
        ) from exc
    if not isinstance(payload, dict):
        raise Bsr2IntegrationError("decrypted payload must be an object.")
    return payload


__all__ = [
    "BrisartEnvelopeError",
    "MAX_PAYLOAD_BYTES",
    "PADDING_BLOCK_BYTES",
    "is_envelope",
    "open_bytes",
    "open_json",
    "seal_bytes",
    "seal_json",
]
