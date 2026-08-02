from typing import Optional
from biometrics.modalities import (
    assess_liveness,
    create_template,
    default_threshold_for_modality,
    normalize_modality,
    requires_liveness,
)
from identity.identity_record import (
    build_identity_record,
    safe_identity_id,
)
from identity.identity_store import (
    identity_exists,
    load_identity,
    save_identity,
    save_template,
    template_path,
)


def enroll_identity(
    identity_id: str,
    display_name: str,
    source_path: str,
    threshold: Optional[float] = None,
    overwrite: bool = False,
    modality: Optional[str] = None,
    require_live: bool = True,
) -> dict:
    safe_id = safe_identity_id(identity_id)

    # Enrolling an existing id used to overwrite that identity's record and
    # biometric template with no warning, which silently destroys the only copy
    # of the enrolled template. Require an explicit opt-in instead.
    if identity_exists(safe_id) and not overwrite:
        existing = load_identity(safe_id)
        raise FileExistsError(
            f"identity already enrolled: {safe_id} "
            f"(display name: {existing.get('display_name')}). "
            "Pass overwrite=True / --overwrite to re-enroll."
        )

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

    selected_modality = normalize_modality(modality, source_path)
    selected_threshold = (
        default_threshold_for_modality(selected_modality)
        if threshold is None
        else float(threshold)
    )

    if not 0.0 <= selected_threshold <= 1.0:
        raise ValueError(
            "threshold must be between 0.0 and 1.0."
        )

    template = create_template(selected_modality, source_path)

    # Enrolling from a static recording would bake a photograph into the
    # template and make the liveness gate at verification time meaningless.
    liveness = None
    if requires_liveness(selected_modality):
        liveness = assess_liveness(template)
        if require_live and not liveness["passed"]:
            raise ValueError(
                f"video enrollment rejected: {liveness['reason']} "
                "Record a live clip, or pass require_live=False / "
                "--allow-static to enroll from a static recording anyway."
            )

    record = build_identity_record(
        identity_id=safe_id,
        display_name=cleaned_display_name,
        template_file=str(template_path(safe_id)),
        template_sha256=template["template_sha256"],
        threshold=selected_threshold,
        modality=selected_modality,
        template_mode=template.get("mode", "local_biometric_verification_beta"),
    )

    record["storage_mode"] = "local_json_beta"
    template["identity_id"] = safe_id
    template["modality"] = selected_modality

    save_identity(
        safe_id,
        record,
    )

    save_template(
        safe_id,
        template,
    )

    result = {
        "identity": record,
        "template": template,
    }
    if liveness is not None:
        result["liveness"] = liveness
    return result
