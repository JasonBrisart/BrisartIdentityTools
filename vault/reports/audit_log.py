"""
File: vault/reports/audit_log.py

Purpose:
    Append-only audit trail for vault mutation and lifecycle events. Every
    time a vault record is created, updated, deleted, or the vault itself is
    unlocked/locked, this module writes one small, independent JSON file
    describing that event. The vault's primary store only ever holds the
    *current* state of each record (an update overwrites the previous
    version), so this module exists to answer "what happened, and when" --
    a question the vault store itself cannot answer on its own.

    Entries never contain sealed payload bytes, key material, or decrypted
    field values -- only record id, label, kind, the action taken, and a
    timestamp. This is deliberate: a lab reviewing the audit trail to see
    what changed and when should never need to unlock the vault or handle
    any secret material to do so.

Communication relationships:
    Called by:
        - vault/core/*.py record-mutation paths (create/update/delete),
          which call record_event() once a mutation has been durably
          written to the vault store, so the audit entry reflects a
          committed change rather than an in-progress one.
        - vault/gui or vault/cli lock/unlock handlers, which call
          record_event() with action="locked"/"unlocked" for vault-level
          (not record-level) events.
        - Any reporting/export tool that needs to display or verify the
          audit history calls list_entries() to enumerate entries in
          chronological order, then reads the JSON files directly.
    Calls out to:
        - common.atomic_io.atomic_write_json -- every entry is written via
          the shared atomic-write helper (write to a temp file, then
          os.replace()), so a crash or power loss mid-write cannot leave a
          half-written or corrupt audit entry behind.
        - common.timestamps.microsecond_timestamp / utc_now_iso -- the
          former is used for the on-disk filename (sortable, filename-safe,
          microsecond precision); the latter is used for the
          human-readable "recorded_at" field stored inside the entry body.
    Does not depend on:
        - Any crypto/vault-sealing module. Audit entries are plaintext JSON
          by design, since they never contain sealed material.

Parameters / settings:
    AUDIT_FORMAT (str):
        A version-tagged format marker ("brisart-identity-tools/vault-audit/v1")
        stored in every entry and required by write_entry(). Lets a future
        reader (or a future version of this module) distinguish this entry
        shape from any later revision without guessing from field presence
        alone.
    _SUFFIX_BYTES (int, currently 4):
        Number of random bytes (8 hex characters) appended to each entry
        filename. Exists purely to avoid filename collisions between two
        entries that resolve to the same timestamp; it does not provide
        ordering on its own (see Edge-case behavior below).
    _VALID_ACTIONS (tuple[str, ...]):
        The closed set of actions build_entry()/record_event() will accept:
        "created", "updated", "deleted", "unlocked", "locked". Anything
        else raises AuditLogError rather than silently writing an entry
        with an unrecognized action string.

Edge-case behavior:
    - Vault-level events (action="unlocked"/"locked") have no associated
      record, so record_id/label/kind are left as empty strings rather than
      omitted from the entry -- every entry has the same field shape
      regardless of action, which keeps downstream parsing simple. The
      filename falls back to the literal "vault" in place of a record id.
    - Filename ordering: entries are named
      "<microsecond-timestamp>_<action>_<record_id>_<random-suffix>.json".
      Sorting filenames lexically therefore sorts entries chronologically
      to microsecond precision; the random suffix only exists to break ties
      on the exceedingly rare occasion two events share the same
      microsecond, and is never relied on for ordering by itself.
    - write_entry() independently re-checks the "format" field on the
      entry it's given (not just entries built by build_entry() in this
      same process), so a hand-constructed or malformed entry dict passed
      in from elsewhere cannot silently be written to disk.
    - list_entries() returns an empty list (not an error) if audit_dir does
      not exist yet -- a vault that has never recorded an event has no
      audit directory at all, and callers should treat that the same as
      "no entries" rather than a failure.
"""
import secrets
from pathlib import Path

from common.atomic_io import atomic_write_json
from common.timestamps import microsecond_timestamp, utc_now_iso

AUDIT_FORMAT = "brisart-identity-tools/vault-audit/v1"
_SUFFIX_BYTES = 4
_VALID_ACTIONS = ("created", "updated", "deleted", "unlocked", "locked")


class AuditLogError(ValueError):
    """Raised when an audit entry cannot be built or written."""


def _entry_filename(action: str, record_id: str) -> str:
    timestamp = microsecond_timestamp()
    suffix = secrets.token_hex(_SUFFIX_BYTES)
    safe_record_id = record_id or "vault"
    return f"{timestamp}_{action}_{safe_record_id}_{suffix}.json"


def build_entry(action: str, record_id: str = "", label: str = "", kind: str = "") -> dict:
    """Build an audit entry describing a single vault mutation or lifecycle event.

    ``record_id``/``label``/``kind`` are left as empty strings for
    vault-level events like ``"unlocked"`` or ``"locked"`` that are not
    about one specific record.
    """
    if action not in _VALID_ACTIONS:
        raise AuditLogError(
            f"unsupported audit action {action!r}; expected one of {_VALID_ACTIONS}."
        )
    return {
        "format": AUDIT_FORMAT,
        "action": action,
        "record_id": record_id,
        "label": label,
        "kind": kind,
        "recorded_at": utc_now_iso(),
    }


def write_entry(audit_dir, entry: dict) -> Path:
    """Persist an audit entry to ``audit_dir``, returning the path written to."""
    if entry.get("format") != AUDIT_FORMAT:
        raise AuditLogError("entry does not have the expected format marker.")
    directory = Path(audit_dir)
    directory.mkdir(parents=True, exist_ok=True)
    filename = _entry_filename(entry["action"], entry.get("record_id", ""))
    path = directory / filename
    atomic_write_json(path, entry)
    return path


def record_event(audit_dir, action: str, record_id: str = "", label: str = "", kind: str = "") -> Path:
    """Build and immediately persist an audit entry. Convenience wrapper
    around :func:`build_entry` + :func:`write_entry`."""
    entry = build_entry(action, record_id, label, kind)
    return write_entry(audit_dir, entry)


def list_entries(audit_dir, record_id: str = None) -> list:
    """List audit entry file paths in ``audit_dir``, sorted oldest first.

    If ``record_id`` is given, only entries whose filename contains that
    record id are returned.
    """
    directory = Path(audit_dir)
    if not directory.is_dir():
        return []
    paths = sorted(directory.glob("*.json"))
    if record_id is None:
        return paths
    return [path for path in paths if f"_{record_id}_" in path.name]
