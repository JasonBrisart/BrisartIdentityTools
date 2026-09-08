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
    pass


def normalize_label(label: str) -> str:
    if not isinstance(label, str):
        raise VaultRecordError("label must be a string.")
    normalized = unicodedata.normalize("NFKC", label).strip()
    if not normalized:
        raise VaultRecordError("label cannot be empty.")
    if len(normalized) > MAX_LABEL_LENGTH:
        raise VaultRecordError("label too long.")
    return normalized


def _validate_kind(kind: str) -> str:
    if not isinstance(kind, str) or not kind:
        raise VaultRecordError("kind must be a non-empty string.")
    if len(kind) > MAX_KIND_LENGTH:
        raise VaultRecordError("kind too long.")
    return kind


def new_record(record_id, label, kind, payload_envelope, timestamps) -> dict:
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
    if not is_envelope(new_payload_envelope):
        raise VaultRecordError("payload must be a BSR2 envelope.")
    updated = dict(record)
    updated["payload"] = new_payload_envelope
    updated["updated_at"] = timestamps["updated_at"]
    return updated


# A file/bundle record carries three optional plaintext metadata fields
# (original_filename, file_size_bytes, file_sha256) set directly on the record
# by vault.store.vault_service.upsert_file_bytes. They are returned here
# whenever present so list_records()/get_summary() (which call public_summary
# directly) surface a file's size/name/hash, not just the five fields every
# record kind shares. Additive and backward compatible: an ordinary
# note/credential record, or a bundle-manifest record (whose size is sealed
# inside its payload and genuinely isn't available here), gains none of these
# keys and is summarized exactly as before.
_OPTIONAL_PLAINTEXT_FIELDS = ("original_filename", "file_size_bytes", "file_sha256")


def public_summary(record: dict) -> dict:
    summary = {
        "record_id": record["record_id"],
        "label": record["label"],
        "kind": record["kind"],
        "created_at": record["created_at"],
        "updated_at": record["updated_at"],
    }
    for field in _OPTIONAL_PLAINTEXT_FIELDS:
        if field in record:
            summary[field] = record[field]
    return summary
