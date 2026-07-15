from config.settings import DEFAULT_THRESHOLD
from core.scoring import template_similarity
from core.template_engine import create_template
from identity.identity_record import safe_identity_id
from identity.identity_store import load_identity, load_template
from reports.report_writer import write_verification_report


def verify_identity(identity_id: str, image_path: str, threshold=None) -> dict:
    safe_id = safe_identity_id(identity_id)
    identity = load_identity(safe_id)
    stored_template = load_template(safe_id)
    candidate_template = create_template(image_path)

    selected_threshold = threshold
    if selected_threshold is None:
        selected_threshold = float(identity.get("default_threshold", DEFAULT_THRESHOLD))

    score = template_similarity(stored_template, candidate_template)
    result = "MATCH" if score >= selected_threshold else "NO_MATCH"

    report = write_verification_report(
        identity=identity,
        result=result,
        score=score,
        threshold=selected_threshold,
        stored_template=stored_template,
        candidate_template=candidate_template,
    )

    return report
