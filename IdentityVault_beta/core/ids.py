import secrets


def new_record_id(prefix: str = "rec") -> str:
    return f"{prefix}_{secrets.token_hex(10)}"


def safe_label(value: str) -> str:
    cleaned = " ".join(value.strip().split())
    if not cleaned:
        raise ValueError("label cannot be empty.")
    return cleaned
