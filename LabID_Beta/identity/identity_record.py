import datetime as dt
import secrets

from config.settings import APP_NAME, APP_VERSION


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def safe_identity_id(identity_id: str) -> str:
    cleaned = "".join(character for character in identity_id.strip() if character.isalnum() or character in ("_", "-"))
    if not cleaned:
        raise ValueError("identity_id must contain letters, numbers, underscores, or dashes.")
    return cleaned


def build_identity_record(identity_id: str, display_name: str, template_file: str, template_sha256: str, threshold: float) -> dict:
    safe_id = safe_identity_id(identity_id)
    return {
        "app": APP_NAME,
        "app_version": APP_VERSION,
        "identity_id": safe_id,
        "display_name": display_name,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "status": "beta_enrolled",
        "identity_type": "local_identity_beta",
        "biometric_mode": "local_biometric_verification_beta",
        "template_file": template_file,
        "template_sha256": template_sha256,
        "default_threshold": threshold,
        "local_record_id": secrets.token_hex(16),
    }
