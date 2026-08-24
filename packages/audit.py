"""External, append-only audit trail for Identity-Bound Package events.

Deliberately parallel to ``biometrics.reports.report_writer`` and
``vault.reports.audit_log``: one JSON file per event, named with a timestamp
and a random suffix so concurrent events never collide, written atomically
so a crash mid-write cannot corrupt the trail. This is external to the
package (written to a separate audit directory), which is what distinguishes
it from ``custody.py``'s chain that travels inside the package itself --
losing or never having access to the package file still leaves this trail
intact.

Never contains content keys, master keys, or sealed payload bytes -- only
package id, action, and actor label.
"""
import secrets
from pathlib import Path

from common.atomic_io import atomic_write_json
from common.timestamps import utc_now_iso

AUDIT_FORMAT = "brisart-identity-tools/package-audit/v1"
_SUFFIX_BYTES = 4

_VALID_ACTIONS = (
    "created",
    "recipient_added",
    "recipient_removed",
    "opened",
    "open_denied",
    "custody_violation_detected",
)


class PackageAuditError(ValueError):
    """Raised when a package audit entry cannot be built or written."""


def _entry_filename(action: str, package_id: str) -> str:
    timestamp = utc_now_iso().replace(":", "").replace("+", "Z")
    suffix = secrets.token_hex(_SUFFIX_BYTES)
    return f"{timestamp}_{action}_{package_id}_{suffix}.json"


def build_entry(action: str, package_id: str, actor_label: str = "") -> dict:
    """Build an audit entry describing a single package lifecycle event."""
    if action not in _VALID_ACTIONS:
        raise PackageAuditError(
            f"unsupported audit action {action!r}; expected one of {_VALID_ACTIONS}."
        )
    if not isinstance(package_id, str) or not package_id:
        raise PackageAuditError("package_id must be a non-empty string.")
    return {
        "format": AUDIT_FORMAT,
        "action": action,
        "package_id": package_id,
        "actor_label": actor_label,
        "recorded_at": utc_now_iso(),
    }


def write_entry(audit_dir, entry: dict) -> Path:
    """Persist an audit entry to ``audit_dir``, returning the path written to."""
    if entry.get("format") != AUDIT_FORMAT:
        raise PackageAuditError("entry does not have the expected format marker.")
    directory = Path(audit_dir)
    directory.mkdir(parents=True, exist_ok=True)
    filename = _entry_filename(entry["action"], entry["package_id"])
    path = directory / filename
    atomic_write_json(path, entry)
    return path


def record_event(audit_dir, action: str, package_id: str, actor_label: str = "") -> Path:
    """Build and immediately persist an audit entry."""
    entry = build_entry(action, package_id, actor_label)
    return write_entry(audit_dir, entry)


def list_entries(audit_dir, package_id: str = None) -> list:
    """List audit entry file paths in ``audit_dir``, sorted oldest first."""
    directory = Path(audit_dir)
    if not directory.is_dir():
        return []
    paths = sorted(directory.glob("*.json"))
    if package_id is None:
        return paths
    return [path for path in paths if f"_{package_id}_" in path.name]
