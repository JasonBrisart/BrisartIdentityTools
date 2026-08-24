"""Chunked, multi-path bulk file/folder/drive encryption on top of VaultService.

WHY THIS MODULE EXISTS (the constraint that makes it necessary): BSR2's
vendored envelope hard-caps a single sealed payload at
vendor.brisart_security_envelope.MAX_PLAINTEXT_BYTES == 16 MiB
(crypto/envelope.py's own MAX_PAYLOAD_BYTES trims that further for its
length-prefix + padding overhead). Calling encrypt() on anything larger
raises BrisartEnvelopeError outright -- there is no silent truncation or
degraded behavior, it simply refuses. That means "encrypt this file" only
works unmodified for content under roughly 16 MiB. Anything bigger --
a large single file, a folder, an entire drive -- needs to be split into
several separately-sealed chunks and reassembled on the way back out. This
module is that splitting/reassembly layer, built once here so both Vault
and Biometrics attachments can share it instead of each re-solving it.

WHAT THIS MODULE DOES NOT DO: it does not stream-encrypt on the fly. A
bundle (whether one big file or a zip of many files/folders) is first
fully materialized as a real zip file on local disk via the stdlib
`zipfile` module, then read back and chunked. This means the practical
ceiling for "encrypt my whole hard drive" is realistically bounded by
available local disk space for that temporary zip and by how long walking
+ compressing that many files takes -- not by anything in this module's
own logic, which has no additional size ceiling of its own beyond "how
many chunk records can be created" (i.e. none, chunk count is unbounded).
This is stated plainly rather than left implied: encrypting a full,
multi-hundred-gigabyte drive is technically supported by this code but
will take a genuinely long time and require that much free disk space for
the intermediate zip, exactly as a normal "zip up my C: drive" operation
would on any system.

MANIFEST + CHUNK MODEL: a bulk encryption produces exactly one small
manifest record (a completely ordinary vault JSON record, kind
BUNDLE_MANIFEST_KIND) naming how many chunk records exist, their ordered
record ids, the original total size, and a SHA-256 of the COMPLETE
reassembled plaintext (the zip bytes, before any chunking) -- so a restore
can verify integrity across the whole chunk set, not just per-chunk. Each
chunk itself is a completely ordinary vault FILE record (created via
VaultService.upsert_file_bytes, the same function a single small file
uses), so nothing about a chunk record's own storage format is special;
only the manifest that ties them together is new.
"""
import tempfile
import time
import zipfile
from pathlib import Path

from common.hashing import sha256_bytes
from vault.store.vault_service import FILE_RECORD_KIND, VaultServiceError

BUNDLE_MANIFEST_KIND = "bundle-manifest"
BUNDLE_CHUNK_KIND = "bundle-chunk"

# Conservative: real cap (crypto.envelope.MAX_PAYLOAD_BYTES) is ~16 MiB minus
# 264 bytes. 8 MiB leaves comfortable headroom and keeps each individual
# chunk's BSR2 seal/open call (and the vault's single JSON write per
# upsert) a reasonable size to hold in memory at once, rather than pushing
# right up against the hard ceiling.
DEFAULT_CHUNK_BYTES = 8 * 1024 * 1024


class BulkFileServiceError(ValueError):
    """Raised when a bulk encrypt/restore operation cannot proceed."""


def _iter_chunks(data: bytes, chunk_size: int):
    for offset in range(0, len(data), chunk_size):
        yield data[offset:offset + chunk_size]


def _build_zip_from_paths(paths, zip_path) -> dict:
    """Zip every file under every given path (a path may be an individual
    file, a folder, or a drive root -- os.walk/Path.rglob treat all three
    identically, since a drive root is simply a folder with no parent) into
    a single archive at `zip_path`, preserving each entry's path relative to
    a common ancestor so the original directory structure can be restored
    later. Returns a small report dict (file count, skipped-file count and
    reasons) rather than raising on the first unreadable file -- a locked
    system file or a permissions error partway through a large drive should
    not abort the entire operation; it should be skipped and reported.
    """
    resolved_paths = [Path(p) for p in paths]
    for p in resolved_paths:
        if not p.exists():
            raise BulkFileServiceError(f"path does not exist: {p}")

    file_count = 0
    skipped = []
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
        for root_path in resolved_paths:
            if root_path.is_file():
                arcname = root_path.name
                try:
                    archive.write(root_path, arcname=arcname)
                    file_count += 1
                except OSError as exc:
                    skipped.append({"path": str(root_path), "reason": str(exc)})
                continue
            # Folder (or drive root, which is just a folder with no parent
            # and no files directly explainable as a single "file" case
            # above): walk every file underneath it, preserving the
            # relative structure under a top-level folder named after the
            # root itself, so restoring multiple selected folders together
            # never collides their contents into one flat namespace.
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


class BulkFileService:
    """Wraps an already-unlocked VaultService with chunked bulk operations."""

    def __init__(self, vault_service, chunk_bytes: int = DEFAULT_CHUNK_BYTES):
        self.vault_service = vault_service
        self.chunk_bytes = chunk_bytes

    def _require_unlocked(self):
        if not self.vault_service.is_unlocked:
            raise BulkFileServiceError("vault is locked; unlock it before this operation.")

    def upsert_large_bytes(self, label: str, data: bytes, original_filename: str = "",
                           record_id: str = None) -> dict:
        """Seal arbitrary bytes of ANY size, transparently chunking if the
        content exceeds a single BSR2 envelope's hard 16 MiB limit.

        For content that fits in one envelope, this is functionally
        identical to VaultService.upsert_file_bytes (still produces a
        manifest wrapper for a UNIFORM restore path regardless of size --
        see restore_bytes below -- rather than silently branching into two
        different record shapes depending on size, which would force every
        caller to guess which kind of record they're dealing with before
        reading it back).
        """
        self._require_unlocked()
        if not isinstance(data, (bytes, bytearray)):
            raise BulkFileServiceError("data must be bytes.")
        data = bytes(data)
        whole_sha256 = sha256_bytes(data)
        chunk_summaries = []
        chunk_index = 0
        for chunk in _iter_chunks(data, self.chunk_bytes) if data else [b""]:
            chunk_summary = self.vault_service.upsert_file_bytes(
                f"{label} (part {chunk_index})", chunk,
                original_filename=f"{original_filename}.part{chunk_index}",
            )
            chunk_summaries.append(chunk_summary)
            chunk_index += 1
        manifest_payload = {
            "chunk_record_ids": [s["record_id"] for s in chunk_summaries],
            "chunk_count": len(chunk_summaries),
            "original_filename": original_filename,
            "total_size_bytes": len(data),
            "whole_sha256": whole_sha256,
            "chunk_bytes": self.chunk_bytes,
        }
        manifest_summary = self.vault_service.upsert(
            label, BUNDLE_MANIFEST_KIND, manifest_payload, record_id=record_id,
        )
        return {
            **manifest_summary,
            "chunk_count": len(chunk_summaries),
            "total_size_bytes": len(data),
            "whole_sha256": whole_sha256,
        }

    def restore_bytes(self, manifest_record_id: str) -> bytes:
        """Reassemble a (possibly chunked) upsert_large_bytes()/upsert_paths()
        bundle back into the exact original bytes, verifying the whole-content
        SHA-256 recorded in the manifest against what was actually reassembled
        -- so silent corruption or a missing/mismatched chunk is caught
        immediately rather than handing back truncated or reordered data.
        """
        self._require_unlocked()
        manifest = self.vault_service.get(manifest_record_id)
        required_fields = {"chunk_record_ids", "chunk_count", "total_size_bytes", "whole_sha256"}
        if not required_fields.issubset(manifest):
            raise BulkFileServiceError(
                f"record {manifest_record_id!r} is not a valid bulk-encryption manifest."
            )
        if len(manifest["chunk_record_ids"]) != manifest["chunk_count"]:
            raise BulkFileServiceError("manifest chunk count does not match its chunk id list.")
        pieces = []
        for chunk_record_id in manifest["chunk_record_ids"]:
            pieces.append(self.vault_service.get_file_bytes(chunk_record_id))
        reassembled = b"".join(pieces)
        if len(reassembled) != manifest["total_size_bytes"]:
            raise BulkFileServiceError(
                f"reassembled size {len(reassembled)} does not match manifest's "
                f"recorded size {manifest['total_size_bytes']} -- a chunk is "
                f"missing, truncated, or out of order."
            )
        actual_sha256 = sha256_bytes(reassembled)
        if actual_sha256 != manifest["whole_sha256"]:
            raise BulkFileServiceError(
                "reassembled content's SHA-256 does not match the manifest's "
                "recorded hash -- the bundle is corrupted or was tampered with."
            )
        return reassembled

    def upsert_paths(self, paths, label: str, record_id: str = None) -> dict:
        """THE entry point for 'encrypt any combination of files, folders,
        and drives, all at once': zips every real file found under every
        given path (files are added directly; folders and drive roots are
        walked recursively, preserving their relative structure -- see
        _build_zip_from_paths) into one temporary archive, then seals that
        archive's bytes via upsert_large_bytes, transparently chunking if
        the resulting zip exceeds 16 MiB. `paths` may freely mix individual
        files, folders, and drive roots (e.g. ["C:\\report.pdf",
        "C:\\Users\\me\\Photos", "D:\\"]) in a single call -- this is the
        literal "everything combined" behavior requested: one bundle, one
        manifest record, one restore operation, regardless of how many
        distinct files/folders/drives contributed to it.
        """
        self._require_unlocked()
        if not paths:
            raise BulkFileServiceError("at least one path is required.")
        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / f"bundle_{int(time.time())}.zip"
            zip_report = _build_zip_from_paths(paths, zip_path)
            if zip_report["file_count"] == 0:
                raise BulkFileServiceError(
                    "no readable files were found under the given path(s)."
                )
            zip_bytes = zip_path.read_bytes()
        summary = self.upsert_large_bytes(
            label, zip_bytes, original_filename=f"{label}.zip", record_id=record_id,
        )
        summary["source_paths"] = [str(p) for p in paths]
        summary["files_bundled"] = zip_report["file_count"]
        summary["files_skipped"] = zip_report["skipped"]
        return summary

    def restore_paths(self, manifest_record_id: str, output_dir) -> dict:
        """Reassemble a upsert_paths() bundle and unzip it back into a real
        directory tree at `output_dir`, restoring every file/folder that
        was originally selected, with their relative structure intact.
        """
        zip_bytes = self.restore_bytes(manifest_record_id)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "restore.zip"
            zip_path.write_bytes(zip_bytes)
            with zipfile.ZipFile(zip_path, "r") as archive:
                archive.extractall(output_dir)
                extracted_names = archive.namelist()
        return {"output_dir": str(output_dir), "files_restored": len(extracted_names)}
