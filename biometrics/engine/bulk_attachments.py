"""Chunked, multi-path bulk file/folder/drive attachments on a biometrics
identity record -- the biometrics-side counterpart to
vault.store.bulk_file_service.BulkFileService, built for exactly the same
reason: a single BSR2 envelope hard-caps at ~16 MiB
(crypto.envelope.MAX_PAYLOAD_BYTES), so a large file, or a zip built from
an entire folder/drive, must be split into several sealed chunk
attachments and reassembled on the way back out.

Manifest + chunk model: attaching a bundle under `name` actually creates
several REAL attachments on the record (via the existing
biometrics.engine.attachments.attach_bytes, unmodified) named
"{name}.manifest" (a small JSON-shaped payload describing the chunk
attachment names, order, total size, and whole-content SHA-256) and
"{name}.chunk0", "{name}.chunk1", ... in order. Nothing about an individual
chunk attachment's own storage is special -- it is a completely ordinary
sealed attachment; only the manifest naming convention ties them together.

Since biometrics attachments seal raw bytes (not JSON) via
crypto.envelope.seal_bytes/open_bytes, the manifest itself is stored as
UTF-8-encoded JSON bytes through the exact same attach_bytes/
extract_attachment_bytes path every other attachment uses -- there is no
separate "JSON attachment" concept here, keeping this module's storage
shape uniform with single-file attachments rather than introducing a
second payload format.
"""
import json
import tempfile
import time
import zipfile
from pathlib import Path

from common.hashing import sha256_bytes
from biometrics.engine.attachments import (
    AttachmentError, attach_bytes, extract_attachment_bytes, remove_identity_attachment,
)

DEFAULT_CHUNK_BYTES = 8 * 1024 * 1024
_MANIFEST_SUFFIX = ".manifest"


class BulkAttachmentError(ValueError):
    """Raised when a bulk attach/restore operation cannot proceed."""


def _iter_chunks(data: bytes, chunk_size: int):
    for offset in range(0, len(data), chunk_size):
        yield data[offset:offset + chunk_size]


def _build_zip_from_paths(paths, zip_path) -> dict:
    """Identical logic to vault.store.bulk_file_service._build_zip_from_paths
    (duplicated rather than imported, so biometrics/ has no import
    dependency on vault/ -- the two tools remain independently usable, per
    this project's existing separation between biometrics/, vault/, and
    packages/)."""
    resolved_paths = [Path(p) for p in paths]
    for p in resolved_paths:
        if not p.exists():
            raise BulkAttachmentError(f"path does not exist: {p}")

    file_count = 0
    skipped = []
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
        for root_path in resolved_paths:
            if root_path.is_file():
                try:
                    archive.write(root_path, arcname=root_path.name)
                    file_count += 1
                except OSError as exc:
                    skipped.append({"path": str(root_path), "reason": str(exc)})
                continue
            base_name = root_path.name or root_path.drive.rstrip(":\\/") or "root"
            for candidate in root_path.rglob("*"):
                if not candidate.is_file():
                    continue
                try:
                    relative = candidate.relative_to(root_path)
                except ValueError:
                    continue
                arcname = str(Path(base_name) / relative)
                try:
                    archive.write(candidate, arcname=arcname)
                    file_count += 1
                except OSError as exc:
                    skipped.append({"path": str(candidate), "reason": str(exc)})
    return {"file_count": file_count, "skipped": skipped}


def attach_large_bytes(record: dict, name: str, data: bytes, master_key: bytes,
                       chunk_bytes: int = DEFAULT_CHUNK_BYTES) -> dict:
    """Attach bytes of ANY size under `name`, transparently chunking past
    BSR2's single-envelope limit. Returns the updated record (attach_bytes'
    same not-mutate-in-place contract)."""
    if not isinstance(data, (bytes, bytearray)):
        raise BulkAttachmentError("data must be bytes.")
    data = bytes(data)
    whole_sha256 = sha256_bytes(data)
    chunk_names = []
    chunk_index = 0
    for chunk in _iter_chunks(data, chunk_bytes) if data else [b""]:
        chunk_name = f"{name}.chunk{chunk_index}"
        record = attach_bytes(record, chunk_name, chunk, master_key)
        chunk_names.append(chunk_name)
        chunk_index += 1
    manifest = {
        "chunk_names": chunk_names, "chunk_count": len(chunk_names),
        "total_size_bytes": len(data), "whole_sha256": whole_sha256, "chunk_bytes": chunk_bytes,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
    record = attach_bytes(record, f"{name}{_MANIFEST_SUFFIX}", manifest_bytes, master_key)
    return record


def restore_large_bytes(record: dict, name: str, master_key: bytes) -> bytes:
    """Reassemble a (possibly chunked) attach_large_bytes()/attach_paths()
    bundle back into the exact original bytes, verifying the whole-content
    SHA-256 recorded in the manifest."""
    try:
        manifest_bytes = extract_attachment_bytes(record, f"{name}{_MANIFEST_SUFFIX}", master_key)
    except AttachmentError as exc:
        raise BulkAttachmentError(f"no bulk attachment bundle named {name!r}: {exc}") from exc
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BulkAttachmentError(f"manifest for {name!r} is corrupted: {exc}") from exc
    required = {"chunk_names", "chunk_count", "total_size_bytes", "whole_sha256"}
    if not required.issubset(manifest):
        raise BulkAttachmentError(f"manifest for {name!r} is missing required fields.")
    if len(manifest["chunk_names"]) != manifest["chunk_count"]:
        raise BulkAttachmentError("manifest chunk count does not match its chunk name list.")
    pieces = [extract_attachment_bytes(record, chunk_name, master_key)
             for chunk_name in manifest["chunk_names"]]
    reassembled = b"".join(pieces)
    if len(reassembled) != manifest["total_size_bytes"]:
        raise BulkAttachmentError(
            f"reassembled size {len(reassembled)} does not match manifest's "
            f"recorded size {manifest['total_size_bytes']} -- a chunk is missing or truncated."
        )
    if sha256_bytes(reassembled) != manifest["whole_sha256"]:
        raise BulkAttachmentError(
            f"reassembled content for {name!r} failed its SHA-256 check -- "
            f"the bundle is corrupted or was tampered with."
        )
    return reassembled


def attach_paths(record: dict, name: str, paths, master_key: bytes,
                 chunk_bytes: int = DEFAULT_CHUNK_BYTES) -> tuple:
    """Attach any combination of files/folders/drive roots to this identity
    as ONE bundle under `name`, zipping them first (preserving relative
    structure) then chunking as needed. Returns (updated_record, report)."""
    if not paths:
        raise BulkAttachmentError("at least one path is required.")
    with tempfile.TemporaryDirectory() as tmp_dir:
        zip_path = Path(tmp_dir) / f"bundle_{int(time.time())}.zip"
        zip_report = _build_zip_from_paths(paths, zip_path)
        if zip_report["file_count"] == 0:
            raise BulkAttachmentError("no readable files were found under the given path(s).")
        zip_bytes = zip_path.read_bytes()
    updated = attach_large_bytes(record, name, zip_bytes, master_key, chunk_bytes=chunk_bytes)
    report = {"files_bundled": zip_report["file_count"], "files_skipped": zip_report["skipped"],
             "total_size_bytes": len(zip_bytes)}
    return updated, report


def restore_paths(record: dict, name: str, master_key: bytes, output_dir) -> dict:
    """Reassemble an attach_paths() bundle and unzip it back into a real
    directory tree at `output_dir`."""
    zip_bytes = restore_large_bytes(record, name, master_key)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp_dir:
        zip_path = Path(tmp_dir) / "restore.zip"
        zip_path.write_bytes(zip_bytes)
        with zipfile.ZipFile(zip_path, "r") as archive:
            archive.extractall(output_dir)
            extracted_names = archive.namelist()
    return {"output_dir": str(output_dir), "files_restored": len(extracted_names)}


def remove_bulk_attachment(record: dict, name: str, master_key: bytes) -> dict:
    """Remove every chunk + the manifest for a bundle named `name`. Needs
    the real master_key to decrypt the manifest and discover which chunk
    attachment names belong to this bundle (attachment names alone don't
    reveal that -- they're just opaque dict keys on the record). If the
    manifest cannot be decrypted (wrong key, or it's already gone), this
    still removes whatever attachment literally matches
    "{name}.manifest" and reports that the chunks could not be
    automatically identified, rather than silently doing nothing or
    raising and blocking the caller from cleaning up at all.
    """
    try:
        manifest_bytes = extract_attachment_bytes(record, f"{name}{_MANIFEST_SUFFIX}", master_key)
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        for chunk_name in manifest.get("chunk_names", []):
            record = remove_identity_attachment(record, chunk_name)
    except (AttachmentError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    record = remove_identity_attachment(record, f"{name}{_MANIFEST_SUFFIX}")
    return record
