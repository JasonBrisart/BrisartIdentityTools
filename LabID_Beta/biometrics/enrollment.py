from config.settings import DEFAULT_THRESHOLD, ensure_data_dirs
from core.template_engine import create_template
from identity.identity_record import build_identity_record, safe_identity_id
from identity.identity_store import save_identity, save_template, template_path


def enroll_identity(identity_id: str, display_name: str, image_path: str, threshold: float = DEFAULT_THRESHOLD) -> dict:
    ensure_data_dirs()
    safe_id = safe_identity_id(identity_id)

    template = create_template(image_path)
    record = build_identity_record(
        identity_id=safe_id,
        display_name=display_name,
        template_file=str(template_path(safe_id)),
        template_sha256=template["template_sha256"],
        threshold=threshold,
    )

    save_identity(safe_id, record)
    save_template(safe_id, template)

    return {
        "identity": record,
        "template": template,
    }
