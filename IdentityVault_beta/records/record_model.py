import json

from IdentityVault_beta.config.settings import SUPPORTED_RECORD_KINDS
from IdentityVault_beta.core.ids import new_record_id, safe_label
from IdentityVault_beta.core.time_tools import utc_now


def validate_kind(kind: str) -> str:
    if not isinstance(kind, str):
        raise ValueError("record kind must be a string.")

    cleaned = kind.strip().lower()

    if cleaned not in SUPPORTED_RECORD_KINDS:
        raise ValueError(
            f"unsupported record kind: {kind}. "
            f"Supported: {sorted(SUPPORTED_RECORD_KINDS)}"
        )

    return cleaned


def validate_value(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("record value must be a string.")

    return value


def validate_metadata(metadata) -> dict:
    if metadata is None:
        return {}

    if not isinstance(metadata, dict):
        raise ValueError("record metadata must be an object.")

    return dict(metadata)


def build_plain_payload(
    kind: str,
    label: str,
    value: str,
    notes: str = "",
    metadata=None,
) -> dict:
    return {
        "kind": validate_kind(kind),
        "label": safe_label(label),
        "value": validate_value(value),
        "notes": notes if isinstance(notes, str) else str(notes),
        "metadata": validate_metadata(metadata),
    }


def payload_to_bytes(payload: dict) -> bytes:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object.")

    return json.dumps(
        payload,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")


def payload_from_bytes(data: bytes) -> dict:
    if not isinstance(data, bytes):
        raise ValueError("payload data must be bytes.")

    payload = json.loads(data.decode("utf-8"))

    if not isinstance(payload, dict):
        raise ValueError("decrypted payload must contain an object.")

    return payload


def build_record_shell(
    kind: str,
    label: str,
) -> dict:
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