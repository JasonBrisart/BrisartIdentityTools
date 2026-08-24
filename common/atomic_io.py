"""Atomic JSON/text file writes, the single canonical copy.

Replaces the write-to-temp-then-rename dance that existed in three places
(vault_file.save_vault_file, identity_store.save_json, report_writer). Two of
them fsync the containing directory for durability; the report writer did not.
That difference is preserved as the fsync_dir flag rather than silently
unified, because a report is regenerable and a vault is not.

A reader sees either the old file or the fully-written new one, never a
half-written file: bytes land in a uniquely-named temp file that is os.replace-d
into position only after being flushed and fsync-ed.
"""
import json
import os
import secrets
from pathlib import Path
from typing import Union


class AtomicWriteError(Exception):
    """Raised when a file could not be written atomically."""


def _flush_directory(directory: Path) -> None:
    """fsync a directory so a rename into it is durable. No-op on Windows."""
    if os.name == "nt":
        return
    descriptor = None
    try:
        descriptor = os.open(str(directory), os.O_RDONLY)
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)


def atomic_write_text(
    path: Union[str, Path],
    text: str,
    *,
    fsync_dir: bool = True,
    make_parents: bool = True,
) -> None:
    """Write text to path atomically via a temp file and os.replace."""
    target = Path(path)
    if make_parents:
        target.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = target.parent / f".{target.name}.{secrets.token_hex(8)}.tmp"
    try:
        with temporary_path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, target)
        if fsync_dir:
            _flush_directory(target.parent)
    except OSError as exc:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise AtomicWriteError(f"unable to write file: {target}") from exc


def atomic_write_json(
    path: Union[str, Path],
    data: dict,
    *,
    fsync_dir: bool = True,
    make_parents: bool = True,
) -> None:
    """Serialise data (indent=2, sort_keys=True, ensure_ascii=False) and write it
    atomically, matching every existing call site's serialisation."""
    if not isinstance(data, dict):
        raise AtomicWriteError("data to write must be a JSON object.")
    serialized = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
    atomic_write_text(path, serialized, fsync_dir=fsync_dir, make_parents=make_parents)
