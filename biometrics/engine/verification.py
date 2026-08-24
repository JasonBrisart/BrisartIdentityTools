"""Verification: comparing fresh biometric input against a stored template.

The flow is the reverse of enrollment: open the sealed template for the
requested modality (using the same context construction enrollment used, so
a mismatched identity id or modality fails authentication before any
comparison happens), extract a feature vector from the fresh probe input, and
score the two vectors against each other using the modality's comparison
function. The caller decides accept/reject by comparing the score to a
threshold (``biometrics.engine.modalities.default_threshold`` unless
overridden).
"""
from biometrics.engine import modalities
from biometrics.identity.identity_record import has_modality
from crypto.context import template_context
from crypto.envelope import open_json
from crypto.errors import Bsr2IntegrationError


class VerificationError(ValueError):
    """Raised when verification cannot proceed (missing template, bad input)."""


def verify_modality(
    record: dict,
    modality: str,
    probe_path,
    master_key: bytes,
    threshold: float = None,
) -> dict:
    """Verify a probe file against a record's stored template for ``modality``.

    Returns ``{"modality", "score", "threshold", "matched"}``. Raises
    :class:`VerificationError` if the record has no template for this
    modality, or if the stored template fails to open (wrong master key, or
    the template was sealed under a different identity id / modality than
    claimed).
    """
    if not has_modality(record, modality):
        raise VerificationError(
            f"identity {record['identity_id']!r} has no enrolled {modality} template."
        )
    if threshold is None:
        threshold = modalities.default_threshold(modality)

    context = template_context(record["identity_id"], modality)
    envelope = record["templates"][modality]
    try:
        payload = open_json(master_key, envelope, context)
    except Bsr2IntegrationError as exc:
        raise VerificationError(
            f"stored {modality} template for {record['identity_id']!r} failed "
            f"to authenticate: {exc}"
        ) from exc
    if payload.get("modality") != modality:
        raise VerificationError(
            f"stored template payload does not match the requested modality "
            f"{modality!r}."
        )
    stored_vector = payload.get("vector")
    if not isinstance(stored_vector, list):
        raise VerificationError("stored template payload has no feature vector.")

    try:
        probe_vector = modalities.extract_from_path(modality, probe_path)
    except (OSError, ValueError) as exc:
        raise VerificationError(
            f"failed to extract {modality} features from {probe_path!r}: {exc}"
        ) from exc

    score = modalities.compare(modality, stored_vector, probe_vector)
    return {
        "modality": modality,
        "score": score,
        "threshold": threshold,
        "matched": score >= threshold,
    }


def verify_identity(
    record: dict,
    probe_sources: dict,
    master_key: bytes,
    thresholds: dict = None,
    require_all: bool = True,
) -> dict:
    """Verify several modalities at once, e.g. voice and fingerprint together.

    ``probe_sources`` maps modality name to a probe file path. ``thresholds``
    optionally overrides the per-modality default. ``require_all`` controls
    whether *every* requested modality must match (``True``, the default and
    the more conservative choice for a multimodal check) or whether *any one*
    matching is sufficient (``False``).

    Returns ``{"identity_id", "results", "matched"}`` where ``results`` is a
    list of the same per-modality dicts :func:`verify_modality` returns.
    """
    if not probe_sources:
        raise VerificationError("at least one probe source is required.")
    thresholds = thresholds or {}
    results = []
    for modality, probe_path in probe_sources.items():
        results.append(
            verify_modality(
                record,
                modality,
                probe_path,
                master_key,
                thresholds.get(modality),
            )
        )
    if require_all:
        matched = all(result["matched"] for result in results)
    else:
        matched = any(result["matched"] for result in results)
    return {
        "identity_id": record["identity_id"],
        "results": results,
        "matched": matched,
    }
