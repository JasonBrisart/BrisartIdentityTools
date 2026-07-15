import json

from config.settings import SUPPORTED_RECORD_KINDS
from core.ids import new_record_id, safe_label
from core.time_tools import utc_now


def validate_kind(kind: str) -> str:
    cleaned = kind.strip().lower()
    if cleaned not in SUPPORTED_RECORD_KINDS:
        raise ValueError(f"unsupported record kind: {kind}. Supported: {sorted(SUPPORTED_RECORD_KINDS)}")
    return cleaned


def build_plain_payload(kind: str, label: str, value: str, notes: str = "", metadata=None) -> dict:
    return {
        "kind": validate_kind(kind),
        "label": safe_label(label),
        "value": value,
        "notes": notes or "",
        "metadata": metadata or {},
    }


def payload_to_bytes(payload: dict) -> bytes:
    return json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")


def payload_from_bytes(data: bytes) -> dict:
    return json.loads(data.decode("utf-8"))


def build_record_shell(kind: str, label: str) -> dict:
    record_id = new_record_id("vault")
    now = utc_now()
    return {
        "record_id": record_id,
        "kind": validate_kind(kind),
        "label": safe_label(label),
        "created_at": now,
        "updated_at": now,
        "encrypted": {},
    }
