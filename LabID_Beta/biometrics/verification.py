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


def _template_feature_hash(template: dict) -> str:
    import hashlib
    import json

    features = template["features"]

    serialized = json.dumps(
        features,
        sort_keys=True,
    ).encode("utf-8")

    return hashlib.sha256(serialized).hexdigest()


def verify_template_integrity(template: dict) -> bool:
    expected = template.get("template_sha256")

    if not isinstance(expected, str) or not expected:
        return False

    try:
        calculated = _template_feature_hash(template)
    except Exception:
        return False

    return calculated == expected


def _failure_report(
    identity: dict,
    result: str,
    threshold: float,
    stored_template: dict,
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
        persist=True,
    )


def verify_identity(
    identity_id: str,
    image_path: str,
    threshold=None,
) -> dict:
    safe_id = safe_identity_id(identity_id)

    identity = load_identity(safe_id)
    stored_template = load_template(safe_id)

    selected_threshold = _selected_threshold(
        identity,
        threshold,
    )

    if not verify_template_integrity(stored_template):
        report = _failure_report(
            identity=identity,
            result="TEMPLATE_INTEGRITY_FAILED",
            threshold=selected_threshold,
            stored_template=stored_template,
        )
        report["storage_mode"] = "local_json_beta"
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
        )
        report["storage_mode"] = "local_json_beta"
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
        persist=True,
    )

    report["storage_mode"] = "local_json_beta"

    return report