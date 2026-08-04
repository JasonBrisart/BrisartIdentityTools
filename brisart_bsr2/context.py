"""Canonical context strings for BSR2 envelopes.

A BSR2 envelope binds itself to a context string: decryption with a different
context fails authentication even when the key is right. That property is only
worth anything if the context actually identifies the object, and if the format
cannot be confused between object types.

Every context here starts with a distinct type prefix, so a sealed vault record
cannot be opened as a template. Fields are joined with a separator that is
rejected inside the field values themselves, so ``("a|b", "c")`` and
``("a", "b|c")`` cannot produce the same string.
"""

from brisart_bsr2.errors import Bsr2IntegrationError

SEPARATOR = "|"
_PREFIX = "BrisartIdentityTools/v1"


def _clean(name: str, value) -> str:
    if not isinstance(value, str):
        raise Bsr2IntegrationError(f"context {name} must be a string.")
    if not value:
        raise Bsr2IntegrationError(f"context {name} cannot be empty.")
    if SEPARATOR in value:
        # Rejected rather than escaped: escaping needs an unescape path to stay
        # correct, and no legitimate id, kind, or label here contains a pipe.
        raise Bsr2IntegrationError(
            f"context {name} cannot contain {SEPARATOR!r}."
        )
    if "\x00" in value:
        raise Bsr2IntegrationError(f"context {name} cannot contain a NUL byte.")
    return value


def _join(kind: str, *parts) -> str:
    return SEPARATOR.join((_PREFIX, kind, *parts))


def record_context(record_id: str, kind: str, label: str) -> str:
    """Context for a sealed IdentityVault record payload.

    Binding all three fields means an attacker who swaps a sealed payload onto a
    different record, or edits the record's visible kind or label, produces an
    envelope that no longer authenticates.
    """
    return _join(
        "vault-record",
        _clean("record_id", record_id),
        _clean("kind", kind),
        _clean("label", label),
    )


def template_context(identity_id: str, modality: str) -> str:
    """Context for a sealed LabID biometric template.

    Includes the modality so a voice template cannot be substituted for a face
    template belonging to the same identity.
    """
    return _join(
        "labid-template",
        _clean("identity_id", identity_id),
        _clean("modality", modality),
    )


def identity_context(identity_id: str) -> str:
    """Context for a sealed LabID identity record."""
    return _join("labid-identity", _clean("identity_id", identity_id))


def package_context(package_id: str) -> str:
    """Context for a sealed Identity-Bound Package payload.

    Bound to the package id, so a sealed payload cannot be moved into a different
    package while keeping its content key.
    """
    return _join("ibp-package", _clean("package_id", package_id))


def key_slot_context(package_id: str, identity_id: str) -> str:
    """Context for a per-recipient wrapped content key.

    Binds both the package and the recipient, so a key slot cannot be copied to
    another recipient's slot in the same package, nor reused across packages.
    """
    return _join(
        "ibp-key-slot",
        _clean("package_id", package_id),
        _clean("identity_id", identity_id),
    )


def keyring_context(wrapper: str) -> str:
    """Context for a master-key wrapper inside a keyring.

    ``wrapper`` is ``passphrase`` or ``recovery``. Distinct contexts stop a
    recovery wrapper from being replayed into the passphrase slot, which would
    otherwise let an attacker who knows the recovery code unlock via the
    passphrase path and defeat separate attempt limiting.
    """
    return _join("keyring-wrapper", _clean("wrapper", wrapper))
