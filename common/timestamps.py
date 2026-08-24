"""UTC timestamp helpers, the single canonical copy.

Three formats were previously redefined across three files; all three are kept
here because they serve different needs:

* utc_now              ISO-8601 to the second. Was in vault time_tools and LabID
                       identity_record.
* filename_timestamp   filename-safe stamp to the second. Was vault utc_stamp.
* microsecond_timestamp filename-safe stamp with microseconds. Was LabID
                       report_timestamp; the extra precision stops two reports
                       written in the same second from colliding on filename.

All timezone-aware UTC. The old naive-local helper is intentionally dropped.
"""
import datetime as _dt


def utc_now() -> str:
    """Current UTC time as ISO-8601 to the second (e.g. 2026-08-23T14:25:30+00:00)."""
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


# BUG FIX (see docs/CHANGELOG.md): every consumer in this repository --
# vault/core/time_tools.py, vault/reports/audit_log.py,
# biometrics/identity/identity_store.py, biometrics/reports/report_writer.py,
# packages/custody.py, and packages/audit.py -- imports `utc_now_iso`, not
# `utc_now`. Without this alias, importing any of those modules raised
# `ImportError: cannot import name 'utc_now_iso' from 'common.timestamps'`,
# which broke the vault, biometrics, and packages tools entirely (nothing
# that touched a timestamp could even be imported). Both names are kept:
# `utc_now` in case anything external already depends on it, `utc_now_iso`
# because it is what every actual call site in this repository uses.
utc_now_iso = utc_now


def filename_timestamp() -> str:
    """Filename-safe UTC stamp to the second, e.g. 20260823_142530Z."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d_%H%M%SZ")


def microsecond_timestamp() -> str:
    """Filename-safe UTC stamp with microseconds, e.g. 20260823_142530_004821Z."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d_%H%M%S_%fZ")
