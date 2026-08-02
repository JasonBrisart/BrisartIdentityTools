import datetime as dt


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def utc_stamp() -> str:
    """Return a filename-safe UTC timestamp.

    This replaces a previous ``local_stamp()`` helper that used a naive
    ``datetime.now()``. It had no callers, and a naive local timestamp is
    ambiguous across DST changes and machines in different time zones.
    """
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%SZ")
