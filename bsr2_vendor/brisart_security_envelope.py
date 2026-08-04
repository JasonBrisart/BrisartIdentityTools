"""Versioned authenticated-envelope operations for experimental BSR2.

Each encryption combines the caller-supplied deterministic generator with
fresh operating-system entropy. This prevents recreation of the caller's DRBG
state, by itself, from recreating the same salt, nonce, and keystream.

This is defensive hardening, not a proof of cryptographic security. A complete
machine snapshot that also reproduces the operating-system randomness state is
outside what process-local Python code can guarantee against.
"""

from brisart_security_entropy import BrisartEntropyError, system_entropy
from brisart_security_primitives import (
    constant_time_equal,
    derive_subkey,
    frame,
    hex_decode,
    hex_encode,
    keyed_mac,
    stream_bytes,
    xor_bytes,
)

ALGORITHM = "BSR2-ARX-SPONGE-ETM"
VERSION = 2
SALT_BYTES = 32
NONCE_BYTES = 32
TAG_BYTES = 32
MAX_CONTEXT_BYTES = 4096
MAX_PLAINTEXT_BYTES = 16 * 1024 * 1024

_EXPECTED_FIELDS = {
    "algorithm",
    "version",
    "salt",
    "nonce",
    "ciphertext",
    "tag",
}


class BrisartEnvelopeError(Exception):
    """Raised when an envelope operation fails validation or authentication."""


def _context_bytes(context: str) -> bytes:
    if not isinstance(context, str) or not context:
        raise BrisartEnvelopeError("context must be a non-empty string")
    try:
        encoded = context.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise BrisartEnvelopeError("context is not valid UTF-8 text") from exc
    if len(encoded) > MAX_CONTEXT_BYTES:
        raise BrisartEnvelopeError("context exceeds the size limit")
    return encoded


def _tag_input(
    context: bytes,
    salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    return b"".join(
        (
            frame(ALGORITHM.encode("ascii")),
            VERSION.to_bytes(4, "big"),
            frame(context),
            frame(salt),
            frame(nonce),
            frame(ciphertext),
        )
    )


def _require_generator_output(
    value,
    expected_length: int,
    name: str,
) -> bytes:
    if not isinstance(value, bytes):
        raise BrisartEnvelopeError(f"generator {name} must be bytes")
    if len(value) != expected_length:
        raise BrisartEnvelopeError(
            f"generator {name} must contain exactly {expected_length} bytes"
        )
    return value


def _generate_value(
    rng,
    length: int,
    additional_input: bytes,
    name: str,
) -> bytes:
    try:
        value = rng.generate(length, additional_input)
    except Exception as exc:
        raise BrisartEnvelopeError(
            f"generator failed while producing {name}"
        ) from exc
    return _require_generator_output(value, length, name)


def _fresh_entropy(length: int, name: str) -> bytes:
    try:
        return system_entropy(length)
    except BrisartEntropyError as exc:
        raise BrisartEnvelopeError(
            f"fresh entropy failed while producing {name}"
        ) from exc


def _diversify(generator_value: bytes, name: str) -> bytes:
    """XOR deterministic generator output with independent fresh entropy.

    If either same-length input is uniformly unpredictable and independent,
    the XOR result remains uniformly unpredictable. The implementation does
    not claim to validate either source.
    """

    fresh = _fresh_entropy(len(generator_value), name)
    return xor_bytes(generator_value, fresh)


def _require_hex_field(
    envelope: dict,
    name: str,
    maximum_bytes: int,
    *,
    exact_bytes: int | None = None,
) -> str:
    value = envelope[name]
    if not isinstance(value, str):
        raise BrisartEnvelopeError(f"envelope {name} must be hexadecimal text")

    if exact_bytes is not None:
        if len(value) != exact_bytes * 2:
            raise BrisartEnvelopeError("envelope field length is invalid")
    elif len(value) > maximum_bytes * 2:
        raise BrisartEnvelopeError(f"envelope {name} exceeds the size limit")

    return value


def _decode_envelope_fields(envelope: dict) -> tuple[bytes, bytes, bytes, bytes]:
    salt_text = _require_hex_field(
        envelope,
        "salt",
        SALT_BYTES,
        exact_bytes=SALT_BYTES,
    )
    nonce_text = _require_hex_field(
        envelope,
        "nonce",
        NONCE_BYTES,
        exact_bytes=NONCE_BYTES,
    )
    ciphertext_text = _require_hex_field(
        envelope,
        "ciphertext",
        MAX_PLAINTEXT_BYTES,
    )
    tag_text = _require_hex_field(
        envelope,
        "tag",
        TAG_BYTES,
        exact_bytes=TAG_BYTES,
    )

    try:
        return (
            hex_decode(salt_text),
            hex_decode(nonce_text),
            hex_decode(ciphertext_text),
            hex_decode(tag_text),
        )
    except Exception as exc:
        raise BrisartEnvelopeError("envelope encoding is invalid") from exc


def encrypt(master_key: bytes, plaintext: bytes, context: str, rng) -> dict:
    if not isinstance(master_key, bytes) or len(master_key) < 32:
        raise BrisartEnvelopeError("master key must contain at least 32 bytes")
    if not isinstance(plaintext, bytes):
        raise BrisartEnvelopeError("plaintext must be bytes")
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise BrisartEnvelopeError("plaintext exceeds the size limit")
    if not callable(getattr(rng, "generate", None)):
        raise BrisartEnvelopeError(
            "a caller-supplied research generator is required"
        )

    context_bytes = _context_bytes(context)

    generator_salt = _generate_value(
        rng,
        SALT_BYTES,
        b"BSR2/envelope-v2/salt/" + context_bytes,
        "salt",
    )
    generator_nonce = _generate_value(
        rng,
        NONCE_BYTES,
        b"BSR2/envelope-v2/nonce/" + context_bytes,
        "nonce",
    )

    if generator_salt == generator_nonce:
        raise BrisartEnvelopeError(
            "generator produced equal salt and nonce values"
        )

    message_salt = _diversify(generator_salt, "salt")
    nonce = _diversify(generator_nonce, "nonce")

    if message_salt == nonce:
        raise BrisartEnvelopeError(
            "diversified salt and nonce values are equal"
        )

    encryption_key = derive_subkey(
        master_key,
        message_salt,
        b"BSR2/encryption",
    )
    authentication_key = derive_subkey(
        master_key,
        message_salt,
        b"BSR2/authentication",
    )
    ciphertext = xor_bytes(
        plaintext,
        stream_bytes(encryption_key, nonce, len(plaintext)),
    )
    tag = keyed_mac(
        authentication_key,
        _tag_input(context_bytes, message_salt, nonce, ciphertext),
        TAG_BYTES,
    )

    return {
        "algorithm": ALGORITHM,
        "version": VERSION,
        "salt": hex_encode(message_salt),
        "nonce": hex_encode(nonce),
        "ciphertext": hex_encode(ciphertext),
        "tag": hex_encode(tag),
    }


def decrypt(master_key: bytes, envelope: dict, context: str) -> bytes:
    if not isinstance(master_key, bytes) or len(master_key) < 32:
        raise BrisartEnvelopeError("master key must contain at least 32 bytes")
    if not isinstance(envelope, dict):
        raise BrisartEnvelopeError("envelope must be an object")
    if set(envelope) != _EXPECTED_FIELDS:
        raise BrisartEnvelopeError("envelope fields are invalid")

    if not isinstance(envelope["algorithm"], str):
        raise BrisartEnvelopeError("envelope algorithm must be text")
    if type(envelope["version"]) is not int:
        raise BrisartEnvelopeError("envelope version must be an integer")
    if envelope["algorithm"] != ALGORITHM or envelope["version"] != VERSION:
        raise BrisartEnvelopeError("unsupported envelope format")

    context_bytes = _context_bytes(context)
    message_salt, nonce, ciphertext, provided_tag = _decode_envelope_fields(
        envelope
    )

    encryption_key = derive_subkey(
        master_key,
        message_salt,
        b"BSR2/encryption",
    )
    authentication_key = derive_subkey(
        master_key,
        message_salt,
        b"BSR2/authentication",
    )
    expected_tag = keyed_mac(
        authentication_key,
        _tag_input(context_bytes, message_salt, nonce, ciphertext),
        TAG_BYTES,
    )

    if not constant_time_equal(expected_tag, provided_tag):
        raise BrisartEnvelopeError("authentication failed")

    return xor_bytes(
        ciphertext,
        stream_bytes(encryption_key, nonce, len(ciphertext)),
    )
