import datetime as dt


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def local_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")
