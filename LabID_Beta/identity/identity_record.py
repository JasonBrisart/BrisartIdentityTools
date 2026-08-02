import datetime as dt
import secrets

from config.settings import APP_NAME, APP_VERSION


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


ALLOWED_IDENTITY_CHARACTERS = ("_", "-")
MAX_IDENTITY_ID_LENGTH = 128


def safe_identity_id(identity_id: str) -> str:
    """Validate an identity id without silently rewriting it.

    Stripping disallowed characters instead of rejecting them makes distinct
    ids collapse onto the same record file: "ja/son", "ja son" and "ja*son"
    all became "jason". Because the id is also used to build the record and
    template filenames, a rewritten id silently overwrites another identity.
    """
    if not isinstance(identity_id, str):
        raise ValueError("identity_id must be a string.")

    candidate = identity_id.strip()

    if not candidate:
        raise ValueError("identity_id cannot be empty.")

    if len(candidate) > MAX_IDENTITY_ID_LENGTH:
        raise ValueError(
            "identity_id cannot be longer than "
            f"{MAX_IDENTITY_ID_LENGTH} characters."
        )

    invalid = sorted(
        {
            character
            for character in candidate
            if not (
                character.isalnum()
                or character in ALLOWED_IDENTITY_CHARACTERS
            )
        }
    )

    if invalid:
        raise ValueError(
            "identity_id may only contain letters, numbers, "
            "underscores, or dashes. Invalid characters: "
            f"{invalid}"
        )

    return candidate


def build_identity_record(identity_id: str, display_name: str, template_file: str, template_sha256: str, threshold: float) -> dict:
    safe_id = safe_identity_id(identity_id)
    # One timestamp for both fields: two utc_now() calls can straddle a second
    # boundary and make a brand-new record look like it was already updated.
    created = utc_now()
    return {
        "app": APP_NAME,
        "app_version": APP_VERSION,
        "identity_id": safe_id,
        "display_name": display_name,
        "created_at": created,
        "updated_at": created,
        "status": "beta_enrolled",
        "identity_type": "local_identity_beta",
        "biometric_mode": "local_biometric_verification_beta",
        "template_file": template_file,
        "template_sha256": template_sha256,
        "default_threshold": threshold,
        "local_record_id": secrets.token_hex(16),
    }
