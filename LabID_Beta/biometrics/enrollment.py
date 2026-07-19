from config.settings import DEFAULT_THRESHOLD
from core.template_engine import create_template
from identity.identity_record import (
    build_identity_record,
    safe_identity_id,
)
from identity.identity_store import (
    save_identity,
    save_template,
    template_path,
)
from vault_bridge import (
    new_enrollment_id,
    store_enrollment,
    vault_template_uri,
)


def enroll_identity(
    identity_id: str,
    display_name: str,
    image_path: str,
    threshold: float = DEFAULT_THRESHOLD,
    vault_path: str = None,
    vault_password: str = None,
) -> dict:
    safe_id = safe_identity_id(identity_id)

    if not isinstance(display_name, str):
        raise ValueError(
            "display name must be a string."
        )

    cleaned_display_name = " ".join(
        display_name.strip().split()
    )

    if not cleaned_display_name:
        raise ValueError(
            "display name cannot be empty."
        )

    selected_threshold = float(threshold)

    if not 0.0 <= selected_threshold <= 1.0:
        raise ValueError(
            "threshold must be between 0.0 and 1.0."
        )

    if bool(vault_path) != bool(vault_password):
        raise ValueError(
            "vault path and vault password "
            "must be provided together."
        )

    vault_backed = bool(vault_path)

    template = create_template(image_path)
    enrollment_id = new_enrollment_id()

    if vault_backed:
        stored_template_path = vault_template_uri(
            safe_id
        )
    else:
        stored_template_path = str(
            template_path(safe_id)
        )

    record = build_identity_record(
        identity_id=safe_id,
        display_name=cleaned_display_name,
        template_file=stored_template_path,
        template_sha256=template[
            "template_sha256"
        ],
        threshold=selected_threshold,
    )

    record["enrollment_id"] = enrollment_id

    record["storage_mode"] = (
        "encrypted_identity_vault"
        if vault_backed
        else "local_json_beta"
    )

    template["enrollment_id"] = enrollment_id
    template["identity_id"] = safe_id

    if vault_backed:
        # Use positional arguments because the current
        # vault bridge uses a different internal name
        # for its password parameter.
        vault_result = store_enrollment(
            vault_path,
            vault_password,
            record,
            template,
        )
    else:
        # The local identity store creates the required
        # directories only when plaintext storage is used.
        save_identity(
            safe_id,
            record,
        )

        save_template(
            safe_id,
            template,
        )

        vault_result = None

    return {
        "identity": record,
        "template": template,
        "vault": vault_result,
    }