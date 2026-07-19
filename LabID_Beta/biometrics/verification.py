from config.settings import DEFAULT_THRESHOLD
from core.scoring import template_similarity
from core.template_engine import create_template
from identity.identity_record import safe_identity_id
from identity.identity_store import (
    load_identity,
    load_template,
)
from reports.report_writer import (
    write_verification_report,
)
from vault_bridge import (
    load_enrollment,
    verify_template_integrity,
)


def _selected_threshold(
    identity: dict,
    threshold,
) -> float:
    if threshold is None:
        value = identity.get(
            "default_threshold",
            DEFAULT_THRESHOLD,
        )
    else:
        value = threshold

    selected = float(value)

    if not 0.0 <= selected <= 1.0:
        raise ValueError(
            "threshold must be between 0.0 and 1.0."
        )

    return selected


def _failure_report(
    identity: dict,
    result: str,
    threshold: float,
    stored_template: dict,
    persist: bool,
) -> dict:
    return write_verification_report(
        identity=identity,
        result=result,
        score=0.0,
        threshold=threshold,
        stored_template=stored_template,
        candidate_template={
            "template_sha256": None,
            "source_image_sha256": None,
        },
        persist=persist,
    )


def verify_identity(
    identity_id: str,
    image_path: str,
    threshold=None,
    vault_path: str = None,
    vault_password: str = None,
) -> dict:
    safe_id = safe_identity_id(identity_id)

    if bool(vault_path) != bool(vault_password):
        raise ValueError(
            "vault path and vault password "
            "must be provided together."
        )

    vault_backed = bool(vault_path)

    if vault_backed:
        # Use positional arguments here because vault_bridge.py
        # currently uses a different internal password parameter name.
        enrollment = load_enrollment(
            vault_path,
            vault_password,
            safe_id,
        )

        identity = enrollment["identity"]
        stored_template = enrollment["template"]

    else:
        identity = load_identity(safe_id)
        stored_template = load_template(safe_id)

    selected_threshold = _selected_threshold(
        identity,
        threshold,
    )

    # Vault-backed verification must not write an unencrypted
    # verification report into the normal plaintext reports folder.
    persist_report = not vault_backed

    if not verify_template_integrity(stored_template):
        report = _failure_report(
            identity=identity,
            result="TEMPLATE_INTEGRITY_FAILED",
            threshold=selected_threshold,
            stored_template=stored_template,
            persist=persist_report,
        )

        report["storage_mode"] = (
            "encrypted_identity_vault"
            if vault_backed
            else "local_json_beta"
        )

        return report

    expected_template_hash = identity.get(
        "template_sha256"
    )

    actual_template_hash = stored_template.get(
        "template_sha256"
    )

    if expected_template_hash != actual_template_hash:
        report = _failure_report(
            identity=identity,
            result="TEMPLATE_REFERENCE_MISMATCH",
            threshold=selected_threshold,
            stored_template=stored_template,
            persist=persist_report,
        )

        report["storage_mode"] = (
            "encrypted_identity_vault"
            if vault_backed
            else "local_json_beta"
        )

        return report

    candidate_template = create_template(image_path)

    score = template_similarity(
        stored_template,
        candidate_template,
    )

    result = (
        "MATCH"
        if score >= selected_threshold
        else "NO_MATCH"
    )

    report = write_verification_report(
        identity=identity,
        result=result,
        score=score,
        threshold=selected_threshold,
        stored_template=stored_template,
        candidate_template=candidate_template,
        persist=persist_report,
    )

    report["storage_mode"] = (
        "encrypted_identity_vault"
        if vault_backed
        else "local_json_beta"
    )

    return report