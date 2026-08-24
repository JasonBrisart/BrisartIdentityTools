"""The identity record data model.

An identity record is the persisted unit for one enrolled person: an id, a
human-readable label, a device binding, zero or more sealed biometric
templates keyed by modality (``"voice"``, ``"fingerprint"``, ``"video"``),
and (new) zero or more sealed FILE ATTACHMENTS keyed by filename -- an
arbitrary raw file of any kind, any extension, or no extension at all,
completely independent of the voice/fingerprint/video modality system.
Template payloads AND attachment payloads are both opaque BSR2 envelopes
here -- this module only defines the record's shape and its validation, not
how a payload is sealed or opened (see biometrics.engine.enrollment /
biometrics.engine.verification for templates, and
biometrics.engine.attachments for attachments).

Kept intentionally separate from identity_store.py: this module has no file
I/O and no knowledge of where records live on disk, so it can be unit
tested with plain dicts.
"""
from crypto.envelope import is_envelope

SUPPORTED_MODALITIES = ("voice", "fingerprint", "video")
RECORD_FORMAT = "brisart-identity-tools/biometrics-identity/v1"

# Attachment filenames are stored and used as literal dict keys, and also
# get embedded directly into a BSR2 context string (see
# crypto.context.attachment_context, which itself rejects "|" and NUL) --
# both '/' and '\\' are additionally rejected here since a filename is
# purely a label in this system, never a real filesystem path component,
# and allowing path separators would invite confusion with an actual path.
MAX_ATTACHMENT_FILENAME_LENGTH = 256


class IdentityRecordError(ValueError):
    """Raised when identity record data is malformed or invalid."""


def _require_non_empty_string(value, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise IdentityRecordError(f"{name} must be a non-empty string.")
    return value


def _validate_attachment_filename(filename) -> str:
    if not isinstance(filename, str) or not filename:
        raise IdentityRecordError("attachment filename must be a non-empty string.")
    if len(filename) > MAX_ATTACHMENT_FILENAME_LENGTH:
        raise IdentityRecordError(
            f"attachment filename cannot be longer than {MAX_ATTACHMENT_FILENAME_LENGTH} characters."
        )
    if "/" in filename or "\\" in filename:
        raise IdentityRecordError("attachment filename cannot contain a path separator.")
    if "\x00" in filename:
        raise IdentityRecordError("attachment filename cannot contain a NUL byte.")
    return filename


def new_record(identity_id: str, label: str, device_binding: str) -> dict:
    """Build a fresh identity record with no enrolled templates or
    attachments yet."""
    _require_non_empty_string(identity_id, "identity_id")
    _require_non_empty_string(label, "label")
    _require_non_empty_string(device_binding, "device_binding")
    return {
        "format": RECORD_FORMAT,
        "identity_id": identity_id,
        "label": label,
        "device_binding": device_binding,
        "templates": {},
        "attachments": {},
    }


def validate_record(record: dict) -> dict:
    """Validate a record's shape, raising :class:`IdentityRecordError` on
    failure. Returns the record unchanged so it can be used inline.

    ``attachments`` defaults to ``{}`` when absent, so records created
    before this feature existed (with only ``templates``, no
    ``attachments`` key) remain valid and simply report zero attachments --
    the same backward-compatibility approach templates itself would need
    if a fourth modality were added later.
    """
    if not isinstance(record, dict):
        raise IdentityRecordError("identity record must be an object.")
    if record.get("format") != RECORD_FORMAT:
        raise IdentityRecordError("unsupported identity record format.")
    _require_non_empty_string(record.get("identity_id"), "identity_id")
    _require_non_empty_string(record.get("label"), "label")
    _require_non_empty_string(record.get("device_binding"), "device_binding")
    templates = record.get("templates")
    if not isinstance(templates, dict):
        raise IdentityRecordError("templates must be an object.")
    for modality, envelope in templates.items():
        if modality not in SUPPORTED_MODALITIES:
            raise IdentityRecordError(f"unsupported modality: {modality!r}")
        if not is_envelope(envelope):
            raise IdentityRecordError(
                f"template for modality {modality!r} is not a BSR2 envelope."
            )
    attachments = record.get("attachments", {})
    if not isinstance(attachments, dict):
        raise IdentityRecordError("attachments must be an object.")
    for filename, entry in attachments.items():
        _validate_attachment_filename(filename)
        if not isinstance(entry, dict) or not is_envelope(entry.get("payload")):
            raise IdentityRecordError(
                f"attachment {filename!r} is not a valid sealed attachment entry."
            )
    return record


def set_template(record: dict, modality: str, envelope: dict) -> dict:
    """Return a copy of ``record`` with ``modality``'s template replaced."""
    if modality not in SUPPORTED_MODALITIES:
        raise IdentityRecordError(f"unsupported modality: {modality!r}")
    if not is_envelope(envelope):
        raise IdentityRecordError("template must be a BSR2 envelope.")
    updated = dict(record)
    updated["templates"] = dict(record.get("templates", {}))
    updated["templates"][modality] = envelope
    return updated


def remove_template(record: dict, modality: str) -> dict:
    """Return a copy of ``record`` with ``modality``'s template removed, if present."""
    updated = dict(record)
    templates = dict(record.get("templates", {}))
    templates.pop(modality, None)
    updated["templates"] = templates
    return updated


def set_attachment(record: dict, filename: str, envelope: dict, original_size_bytes: int,
                   sha256: str) -> dict:
    """Return a copy of ``record`` with a sealed file attachment added or
    replaced under ``filename``.

    ``original_size_bytes`` and ``sha256`` are stored in the clear
    alongside the sealed payload -- exactly the same non-secret,
    integrity-fingerprint role they play on vault file records (see
    vault.store.vault_service.upsert_file_bytes), never used to protect a
    secret, only to let a caller sanity-check a decrypted attachment
    without needing to re-derive anything.
    """
    _validate_attachment_filename(filename)
    if not is_envelope(envelope):
        raise IdentityRecordError("attachment payload must be a BSR2 envelope.")
    updated = dict(record)
    updated["attachments"] = dict(record.get("attachments", {}))
    updated["attachments"][filename] = {
        "payload": envelope,
        "original_size_bytes": original_size_bytes,
        "sha256": sha256,
    }
    return updated


def remove_attachment(record: dict, filename: str) -> dict:
    """Return a copy of ``record`` with the named attachment removed, if present."""
    updated = dict(record)
    attachments = dict(record.get("attachments", {}))
    attachments.pop(filename, None)
    updated["attachments"] = attachments
    return updated


def enrolled_modalities(record: dict) -> list:
    """List the modalities this record currently has templates for."""
    return sorted(record.get("templates", {}).keys())


def has_modality(record: dict, modality: str) -> bool:
    """Report whether ``record`` has a template for ``modality``."""
    return modality in record.get("templates", {})


def attached_filenames(record: dict) -> list:
    """List the filenames this record currently has attachments for."""
    return sorted(record.get("attachments", {}).keys())


def has_attachment(record: dict, filename: str) -> bool:
    """Report whether ``record`` has an attachment named ``filename``."""
    return filename in record.get("attachments", {})


def public_summary(record: dict) -> dict:
    """A non-secret summary of a record, safe for listing or logging.

    Deliberately omits the sealed template/attachment payloads and the
    device binding value; only their presence, names, and (for
    attachments) plaintext size/hash metadata are reported.
    """
    attachments = record.get("attachments", {})
    return {
        "identity_id": record["identity_id"],
        "label": record["label"],
        "modalities": enrolled_modalities(record),
        "attachments": [
            {"filename": filename, "size_bytes": entry["original_size_bytes"],
            "sha256": entry["sha256"]}
            for filename, entry in sorted(attachments.items())
        ],
    }
