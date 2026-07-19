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


def enroll_identity(
    identity_id: str,
    display_name: str,
    image_path: str,
    threshold: float = DEFAULT_THRESHOLD,
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

    template = create_template(image_path)

    record = build_identity_record(
        identity_id=safe_id,
        display_name=cleaned_display_name,
        template_file=str(template_path(safe_id)),
        template_sha256=template["template_sha256"],
        threshold=selected_threshold,
    )

    record["storage_mode"] = "local_json_beta"
    template["identity_id"] = safe_id

    save_identity(
        safe_id,
        record,
    )

    save_template(
        safe_id,
        template,
    )

    return {
        "identity": record,
        "template": template,
    }