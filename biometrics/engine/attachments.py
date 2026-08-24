"""Generic file attachments on a biometrics identity record.

This is deliberately independent of the voice/fingerprint/video modality
system in engine/modalities.py: a modality template is always the OUTPUT
of a feature extractor run over a specific file format (WAV, PGM/PNG,
BRVID). An attachment is the RAW ORIGINAL FILE ITSELF, completely
unprocessed and un-interpreted -- any extension, no extension, any binary
content whatsoever -- sealed and later returned byte-for-byte identical to
what was attached. Nothing here ever inspects a file's name or contents to
decide how to handle it; every attachment is handled exactly the same way
regardless of what it actually is.

Sealed under the SAME master key templates already use (this project's
existing device-key/keyring path -- see biometrics/README.md's "Storage
Model" section), bound to a context naming both the identity id and the
attachment's filename (crypto.context.attachment_context), so a sealed
attachment can never be moved to a different identity, or relabeled under
a different filename, without failing authentication -- exactly the same
protection template_context already gives modality templates.
"""
from pathlib import Path

from common.hashing import sha256_bytes
from crypto.context import attachment_context
from crypto.envelope import open_bytes, seal_bytes
from crypto.errors import Bsr2IntegrationError
from crypto.rng import new_generator
from biometrics.identity.identity_record import (
    IdentityRecordError, has_attachment, remove_attachment, set_attachment,
)


class AttachmentError(ValueError):
    """Raised when an attachment cannot be sealed, opened, or is missing."""


def attach_bytes(record: dict, filename: str, file_bytes: bytes, master_key: bytes) -> dict:
    """Seal ``file_bytes`` (any content whatsoever) as an attachment named
    ``filename`` on ``record``, replacing any existing attachment under
    that same name. Returns a NEW record (the input is not mutated), the
    same contract every other record-mutating function in this project
    follows (set_template, remove_template, ...).
    """
    if not isinstance(file_bytes, (bytes, bytearray)):
        raise AttachmentError("file_bytes must be bytes.")
    context = attachment_context(record["identity_id"], filename)
    rng = new_generator("biometrics-attachment")
    try:
        envelope = seal_bytes(master_key, bytes(file_bytes), context, rng)
    except Exception as exc:
        raise AttachmentError(f"failed to seal attachment {filename!r}: {exc}") from exc
    try:
        return set_attachment(
            record, filename, envelope, len(file_bytes), sha256_bytes(bytes(file_bytes)),
        )
    except IdentityRecordError as exc:
        raise AttachmentError(str(exc)) from exc


def attach_file(record: dict, filename: str, source_path, master_key: bytes) -> dict:
    """Read a REAL file from disk (any name, any extension, or none at
    all -- the source path's own name/extension is never inspected to
    decide anything) and attach its exact raw bytes. ``filename`` is the
    name the attachment will be stored and later retrieved under; it does
    not need to match ``source_path``'s own filename.
    """
    resolved = Path(source_path)
    if not resolved.is_file():
        raise AttachmentError(f"no file found at {resolved}.")
    file_bytes = resolved.read_bytes()
    return attach_bytes(record, filename, file_bytes, master_key)


def extract_attachment_bytes(record: dict, filename: str, master_key: bytes) -> bytes:
    """Open a sealed attachment, returning the exact original bytes -- the
    precise inverse of attach_bytes()/attach_file(). Uses open_bytes
    (never open_json or any text/format-specific decoder), so whatever
    bytes were sealed are exactly the bytes returned.
    """
    if not has_attachment(record, filename):
        raise AttachmentError(
            f"identity {record['identity_id']!r} has no attachment named {filename!r}."
        )
    entry = record["attachments"][filename]
    context = attachment_context(record["identity_id"], filename)
    try:
        return open_bytes(master_key, entry["payload"], context)
    except Bsr2IntegrationError as exc:
        raise AttachmentError(
            f"attachment {filename!r} for identity {record['identity_id']!r} "
            f"failed to authenticate: {exc}"
        ) from exc


def extract_attachment_to_file(record: dict, filename: str, master_key: bytes, output_path) -> Path:
    """Decrypt a sealed attachment straight to disk at ``output_path``.
    Returns the resolved output path. No assumption is made about what
    extension ``output_path`` should have -- the exact original bytes are
    written regardless.
    """
    file_bytes = extract_attachment_bytes(record, filename, master_key)
    resolved_output = Path(output_path)
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    resolved_output.write_bytes(file_bytes)
    return resolved_output


def remove_identity_attachment(record: dict, filename: str) -> dict:
    """Return a copy of ``record`` with the named attachment removed."""
    return remove_attachment(record, filename)
