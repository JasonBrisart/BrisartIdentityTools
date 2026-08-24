"""Timestamp helpers specific to vault record bookkeeping.

Wraps :mod:`common.timestamps` rather than duplicating its logic, but adds
two things ``common`` deliberately does not know about: comparing two
already-formatted ISO strings without re-parsing the whole vault on every
sort, and stamping a record with ``created_at``/``updated_at`` from a single
captured instant so the two fields can never straddle a second boundary.
"""
from common.timestamps import utc_now_iso


def stamp_new_record() -> dict:
    """Return ``{"created_at", "updated_at"}`` both set to the same instant.

    Two separate ``utc_now_iso()`` calls can straddle a second boundary and
    make a brand-new record's ``updated_at`` appear to be a moment after its
    own ``created_at`` -- capturing one timestamp and reusing it avoids that.
    """
    now = utc_now_iso()
    return {"created_at": now, "updated_at": now}


def stamp_updated(existing_created_at: str) -> dict:
    """Return ``{"created_at", "updated_at"}`` preserving the original creation time."""
    return {"created_at": existing_created_at, "updated_at": utc_now_iso()}


def is_chronologically_ordered(earlier: str, later: str) -> bool:
    """Report whether ``earlier`` sorts at or before ``later``.

    ISO 8601 timestamps in the format ``common.timestamps.utc_now_iso``
    produces are lexically sortable, so this is a plain string comparison --
    no parsing required, which matters when comparing many record timestamps
    during a listing sort.
    """
    return earlier <= later
