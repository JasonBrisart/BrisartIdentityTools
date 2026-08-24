"""Append-only audit trail for vault mutation events.

Mirrors the reasoning in ``biometrics.reports.report_writer``: a record of
"what changed, when, and to what" needs to survive independently of the
vault's current state, since the vault file only ever holds the *latest*
version of each record. One JSON file per event, named with a timestamp and a
random suffix so concurrent events never collide, written atomically so a
crash mid-write cannot corrupt the trail.

Entries never contain sealed payload bytes -- only record id, label, kind,
and the action taken -- so an audit review does not require decrypting
vault secrets to see that something changed.
"""
import secrets
from pathlib import Path

from common.atomic_io import atomic_write_json
from common.timestamps import utc_now_iso

AUDIT_FORMAT = "brisart-identity-tools/vault-audit/v1"
_SUFFIX_BYTES = 4

_VALID_ACTIONS = ("created", "updated", "deleted", "unlocked", "locked")


class AuditLogError(ValueError):
    """Raised when an audit entry cannot be built or written."""


def _entry_filename(action: str, record_id: str) -> str:
    timestamp = utc_now_iso().replace(":", "").replace("+", "Z")
    suffix = secrets.token_hex(_SUFFIX_BYTES)
    safe_record_id = record_id or "vault"
    return f"{timestamp}_{action}_{safe_record_id}_{suffix}.json"


def build_entry(action: str, record_id: str = "", label: str = "", kind: str = "") -> dict:
    """Build an audit entry describing a single vault mutation or lifecycle event.

    ``record_id``/``label``/``kind`` are omitted (left blank) for
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
