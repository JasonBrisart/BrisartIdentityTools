"""
File: packages/audit.py

Purpose:
    External, append-only audit trail for Identity-Bound Package events.
    Every package lifecycle event (created, a recipient added or removed,
    opened, an open denied, a custody violation detected) writes one small,
    independent JSON file describing that event, into a directory separate
    from the package file itself. This is what distinguishes it from
    packages.custody's hash chain, which travels *inside* the package's own
    state: losing the package file, or never having had access to it,
    still leaves this external trail intact. The two are complementary,
    not redundant -- custody proves the package's own history was not
    edited after the fact; this module proves an event happened at all,
    independent of the package surviving.

    Entries never contain content keys, master keys, or sealed payload
    bytes -- only package id, action, and actor label. An audit review of
    "who touched this package, and when" never requires unwrapping a
    content key or opening the package to do so.

Communication relationships:
    Called by:
        - packages.package.create_package / add_recipient / remove_recipient
          / open_package, each of which calls record_event() once the
          corresponding package-state mutation has already succeeded, so an
          audit entry reflects a committed change rather than an
          in-progress one.
        - packages.main's CLI commands and gui.tabs.tab_packages's GUI
          handlers pass an audit_dir through to those package.py functions,
          which is what actually triggers an entry being written; audit.py
          itself has no opinion about where that directory lives.
        - Any reporting/review tool that needs to display or verify a
          package's audit history calls list_entries() to enumerate entries
          in chronological order, then reads the JSON files directly.
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
        - packages.ciphers, packages.custody, or any other crypto-touching
          module in this package. Audit entries are plaintext JSON by
          design, since they never contain sealed material.

Parameters / settings:
    AUDIT_FORMAT (str):
        A version-tagged format marker ("brisart-identity-tools/package-audit/v1")
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
        "created", "recipient_added", "recipient_removed", "opened",
        "open_denied", "custody_violation_detected". Anything else raises
        PackageAuditError rather than silently writing an entry with an
        unrecognized action string.

Edge-case behavior:
    - Filename ordering: entries are named
      "<microsecond-timestamp>_<action>_<package_id>_<random-suffix>.json".
      Sorting filenames lexically therefore sorts entries chronologically
      to microsecond precision; the random suffix only exists to break ties
      on the exceedingly rare occasion two events share the same
      microsecond, and is never relied on for ordering by itself. This
      matters more here than it may first appear: a single call to
      packages.main's "demo" command, or any real create -> add-recipient
      -> open workflow, can easily produce three audit events within the
      same wall-clock second.
    - write_entry() independently re-checks the "format" field on the
      entry it's given (not just entries built by build_entry() in this
      same process), so a hand-constructed or malformed entry dict passed
      in from elsewhere cannot silently be written to disk.
    - list_entries() returns an empty list (not an error) if audit_dir does
      not exist yet -- a package that has never had an audit-recorded event
      has no audit directory at all, and callers should treat that the same
      as "no entries" rather than a failure.
"""
import secrets
from pathlib import Path

from common.atomic_io import atomic_write_json
from common.timestamps import microsecond_timestamp, utc_now_iso

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
    timestamp = microsecond_timestamp()
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
