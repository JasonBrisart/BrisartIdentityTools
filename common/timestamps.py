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

``utc_now_iso`` is an alias of ``utc_now``: every consumer in this repository
(vault, biometrics, and packages timestamp call sites) imports ``utc_now_iso``,
so both names are kept -- ``utc_now`` for any external dependant, ``utc_now_iso``
because it is what every actual call site here uses.
"""
import datetime as _dt


def utc_now() -> str:
    """Current UTC time as ISO-8601 to the second (e.g. 2026-08-23T14:25:30+00:00)."""
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


utc_now_iso = utc_now


def filename_timestamp() -> str:
    """Filename-safe UTC stamp to the second, e.g. 20260823_142530Z."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d_%H%M%SZ")


def microsecond_timestamp() -> str:
    """Filename-safe UTC stamp with microseconds, e.g. 20260823_142530_004821Z."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d_%H%M%S_%fZ")
