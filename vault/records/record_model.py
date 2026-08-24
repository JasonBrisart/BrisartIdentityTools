"""The vault record data model.

A vault record is a labeled, kinded, sealed payload: an id, a normalized
label used for lookup and display, a free-text kind (``"credential"``,
``"note"``, ``"recovery-code"``, or any caller-defined string), and a BSR2
envelope holding the actual secret content. This module defines the record's
shape and validation only -- sealing and opening the payload, and where
records are persisted, are ``vault.store``'s job.

Kept free of file I/O so it can be unit tested with plain dicts, the same
separation ``biometrics.identity.identity_record`` uses.
"""
import unicodedata

from crypto.envelope import is_envelope

RECORD_FORMAT = "brisart-identity-tools/vault-record/v1"
MAX_LABEL_LENGTH = 256
MAX_KIND_LENGTH = 64


class VaultRecordError(ValueError):
    """Raised when vault record data is malformed or invalid."""


def normalize_label(label: str) -> str:
    """Normalize a label for consistent storage and lookup.

    NFKC-normalizes and collapses surrounding whitespace so that two labels
    differing only in Unicode composition or incidental padding
    (``"Café "`` vs ``"Cafe\u0301"``) are treated as the same label rather
    than silently creating near-duplicate records.
    """
    if not isinstance(label, str):
        raise VaultRecordError("label must be a string.")
    normalized = unicodedata.normalize("NFKC", label).strip()
    if not normalized:
        raise VaultRecordError("label cannot be empty.")
    if len(normalized) > MAX_LABEL_LENGTH:
        raise VaultRecordError(f"label cannot be longer than {MAX_LABEL_LENGTH} characters.")
    return normalized


def _validate_kind(kind: str) -> str:
    if not isinstance(kind, str) or not kind:
        raise VaultRecordError("kind must be a non-empty string.")
    if len(kind) > MAX_KIND_LENGTH:
        raise VaultRecordError(f"kind cannot be longer than {MAX_KIND_LENGTH} characters.")
    return kind


def new_record(record_id: str, label: str, kind: str, payload_envelope: dict, timestamps: dict) -> dict:
    """Build a fresh vault record from an already-sealed payload envelope.

    ``timestamps`` is expected to come from
    ``vault.core.time_tools.stamp_new_record()`` (or ``stamp_updated`` when
    replacing an existing record), so record construction and timestamp
    policy stay decoupled.
    """
    if not isinstance(record_id, str) or not record_id:
        raise VaultRecordError("record_id must be a non-empty string.")
    if not is_envelope(payload_envelope):
        raise VaultRecordError("payload must be a BSR2 envelope.")
    if "created_at" not in timestamps or "updated_at" not in timestamps:
        raise VaultRecordError("timestamps must contain created_at and updated_at.")
    return {
        "format": RECORD_FORMAT,
        "record_id": record_id,
        "label": normalize_label(label),
        "kind": _validate_kind(kind),
        "payload": payload_envelope,
        "created_at": timestamps["created_at"],
        "updated_at": timestamps["updated_at"],
    }


def validate_record(record: dict) -> dict:
    """Validate a record's shape, raising :class:`VaultRecordError` on failure.

    Returns the record unchanged so it can be used inline.
    """
    if not isinstance(record, dict):
        raise VaultRecordError("vault record must be an object.")
    if record.get("format") != RECORD_FORMAT:
        raise VaultRecordError("unsupported vault record format.")
    if not isinstance(record.get("record_id"), str) or not record["record_id"]:
        raise VaultRecordError("record_id must be a non-empty string.")
    normalize_label(record.get("label", ""))
    _validate_kind(record.get("kind", ""))
    if not is_envelope(record.get("payload")):
        raise VaultRecordError("payload must be a BSR2 envelope.")
    if not isinstance(record.get("created_at"), str) or not record["created_at"]:
        raise VaultRecordError("created_at must be a non-empty string.")
    if not isinstance(record.get("updated_at"), str) or not record["updated_at"]:
        raise VaultRecordError("updated_at must be a non-empty string.")
    return record


def replace_payload(record: dict, new_payload_envelope: dict, timestamps: dict) -> dict:
    """Return a copy of ``record`` with its payload and timestamps replaced.

    A copy is returned rather than mutating in place, matching
    ``biometrics.identity.identity_record.set_template``'s contract: a
    caller holding a reference to the pre-update record (for an audit log
    entry, for instance) is not surprised by it changing underfoot.
    """
    if not is_envelope(new_payload_envelope):
        raise VaultRecordError("payload must be a BSR2 envelope.")
    updated = dict(record)
    updated["payload"] = new_payload_envelope
    updated["updated_at"] = timestamps["updated_at"]
    return updated


def public_summary(record: dict) -> dict:
    """A non-secret summary of a record, safe for listing or logging.

    Omits the sealed payload entirely; only metadata about the record is
    reported.
    """
    return {
        "record_id": record["record_id"],
        "label": record["label"],
        "kind": record["kind"],
        "created_at": record["created_at"],
        "updated_at": record["updated_at"],
    }
