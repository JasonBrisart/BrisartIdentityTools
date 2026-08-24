"""Audit-trail reports for enrollment and verification events.

Every enroll or verify action that touches an identity is worth a durable
record independent of the identity file itself: a security review of "who was
verified, when, and did it match" should not require reconstructing history
from a mutable record that only holds current state. Reports are therefore
append-style -- one JSON file per event, named with a timestamp and a short
random suffix so concurrent events never collide -- rather than one growing
log file that a partial write could corrupt.

Reports never contain sealed template bytes or feature vectors, only
identity ids, modality names, scores, and outcomes: enough to audit a
decision without re-exposing the biometric data the decision was made about.
"""
import secrets
from pathlib import Path

from common.atomic_io import atomic_write_json
from common.timestamps import utc_now_iso

REPORT_FORMAT = "brisart-identity-tools/biometrics-report/v1"
_SUFFIX_BYTES = 4


class ReportWriterError(ValueError):
    """Raised when a report cannot be built or written."""


def _report_filename(event_type: str, identity_id: str) -> str:
    timestamp = utc_now_iso().replace(":", "").replace("+", "Z")
    suffix = secrets.token_hex(_SUFFIX_BYTES)
    return f"{timestamp}_{event_type}_{identity_id}_{suffix}.json"


def _base_report(event_type: str, identity_id: str) -> dict:
    return {
        "format": REPORT_FORMAT,
        "event_type": event_type,
        "identity_id": identity_id,
        "recorded_at": utc_now_iso(),
    }


def build_enrollment_report(identity_id: str, label: str, modalities_enrolled: list) -> dict:
    """Build a report describing an enrollment event.

    ``modalities_enrolled`` is the list of modality names that were
    successfully attached during this enrollment call.
    """
    if not isinstance(modalities_enrolled, list) or not modalities_enrolled:
        raise ReportWriterError("modalities_enrolled must be a non-empty list.")
    report = _base_report("enrollment", identity_id)
    report["label"] = label
    report["modalities_enrolled"] = sorted(modalities_enrolled)
    return report


def build_verification_report(verification_result: dict) -> dict:
    """Build a report from a ``biometrics.engine.verification.verify_identity``
    result.

    Only the modality name, score, threshold, and matched flag are kept from
    each per-modality result -- never the feature vectors that were compared.
    """
    if "identity_id" not in verification_result or "results" not in verification_result:
        raise ReportWriterError(
            "verification_result must contain 'identity_id' and 'results'."
        )
    report = _base_report("verification", verification_result["identity_id"])
    report["matched"] = bool(verification_result["matched"])
    report["modality_results"] = [
        {
            "modality": result["modality"],
            "score": result["score"],
            "threshold": result["threshold"],
            "matched": result["matched"],
        }
        for result in verification_result["results"]
    ]
    return report


def write_report(report_dir, report: dict) -> Path:
    """Persist a report to ``report_dir``, returning the path written to."""
    if report.get("format") != REPORT_FORMAT:
        raise ReportWriterError("report does not have the expected format marker.")
    directory = Path(report_dir)
    directory.mkdir(parents=True, exist_ok=True)
    filename = _report_filename(report["event_type"], report["identity_id"])
    path = directory / filename
    atomic_write_json(path, report)
    return path


def list_reports(report_dir, identity_id: str = None) -> list:
    """List report file paths in ``report_dir``, sorted oldest first.

    If ``identity_id`` is given, only reports whose filename contains that
    identity id are returned. Filtering by filename (rather than opening and
    parsing every file) keeps a large report directory cheap to browse.
    """
    directory = Path(report_dir)
    if not directory.is_dir():
        return []
    paths = sorted(directory.glob("*.json"))
    if identity_id is None:
        return paths
    return [path for path in paths if f"_{identity_id}_" in path.name]