"""Recipient identity shape for Identity-Bound Packages.

A recipient here is deliberately lightweight compared to
``biometrics.identity.identity_record``: a package does not care whether a
recipient enrolled a fingerprint or a voice template, only that they hold a
master key and can be referred to by a stable id and a human-readable label.
This module owns that shape and its validation only; whether a supplied
master key actually matches a recipient is ``verification.py``'s job, and
sealing/opening key slots is ``ciphers.py``'s job.

Kept free of any crypto import, matching the layering already used in
``biometrics.identity.identity_record`` and ``vault.records.record_model``:
the data shape is unit-testable with plain dicts.
"""
MAX_IDENTITY_ID_LENGTH = 128
MAX_LABEL_LENGTH = 256


class RecipientIdentityError(ValueError):
    """Raised when recipient identity data is malformed or invalid."""


def validate_identity_id(identity_id) -> str:
    """Validate a recipient identity id.

    Rejects the same problem characters :mod:`crypto.context` would reject
    anyway (``|`` and NUL), surfaced here with a recipient-specific message
    instead of a deeper context-building error.
    """
    if not isinstance(identity_id, str) or not identity_id:
        raise RecipientIdentityError("identity_id must be a non-empty string.")
    if identity_id.strip() != identity_id:
        raise RecipientIdentityError(
            "identity_id cannot have leading or trailing whitespace."
        )
    if len(identity_id) > MAX_IDENTITY_ID_LENGTH:
        raise RecipientIdentityError(
            f"identity_id cannot be longer than {MAX_IDENTITY_ID_LENGTH} characters."
        )
    if "|" in identity_id:
        raise RecipientIdentityError("identity_id cannot contain '|'.")
    if "\x00" in identity_id:
        raise RecipientIdentityError("identity_id cannot contain a NUL byte.")
    return identity_id


def validate_label(label) -> str:
    """Validate a recipient's human-readable label."""
    if not isinstance(label, str) or not label.strip():
        raise RecipientIdentityError("label must be a non-empty string.")
    if len(label) > MAX_LABEL_LENGTH:
        raise RecipientIdentityError(
            f"label cannot be longer than {MAX_LABEL_LENGTH} characters."
        )
    return label


def new_recipient(identity_id: str, label: str) -> dict:
    """Build a fresh recipient descriptor.

    Contains no key material; the master key never appears in a recipient
    descriptor, only in the caller's memory and inside the sealed key slot
    ``ciphers.wrap_content_key`` produces from it.
    """
    return {
        "identity_id": validate_identity_id(identity_id),
        "label": validate_label(label),
    }


def validate_recipient(recipient: dict) -> dict:
    """Validate a recipient descriptor's shape, returning it unchanged."""
    if not isinstance(recipient, dict):
        raise RecipientIdentityError("recipient must be an object.")
    validate_identity_id(recipient.get("identity_id"))
    validate_label(recipient.get("label"))
    return recipient
