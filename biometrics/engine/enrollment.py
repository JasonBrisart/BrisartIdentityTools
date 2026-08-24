"""Enrollment: turning raw biometric input into a sealed, stored template.

The flow for enrolling one modality is: extract a feature vector from the
input file (via ``biometrics.engine.modalities``), serialise it as JSON,
seal it as a BSR2 envelope bound to a context that names the identity and
modality (via ``crypto.context.template_context``), and attach the sealed
envelope to the identity record. Persisting the record is the caller's
responsibility (typically ``biometrics.app``), so this module can be
exercised in tests without touching the filesystem.
"""
from biometrics.engine import modalities
from biometrics.identity import device_key
from biometrics.identity.identity_record import new_record, set_template
from crypto.context import template_context
from crypto.envelope import seal_json
from crypto.rng import new_generator


class EnrollmentError(ValueError):
    """Raised when enrollment cannot proceed."""


def create_identity(identity_id: str, label: str, master_key: bytes) -> dict:
    """Create a fresh identity record bound to the current device.

    No templates are attached yet; call :func:`enroll_modality` for each
    modality to enroll.
    """
    binding = device_key.bind_device(master_key)
    return new_record(identity_id, label, binding)


def enroll_modality(record: dict, modality: str, source_path, master_key: bytes) -> dict:
    """Extract, seal, and attach a template for one modality.

    Returns a new record with the template attached; the input ``record`` is
    not mutated (see ``identity_record.set_template``).
    """
    try:
        vector = modalities.extract_from_path(modality, source_path)
    except modalities.UnsupportedModalityError:
        raise
    except (OSError, ValueError) as exc:
        raise EnrollmentError(
            f"failed to extract {modality} features from {source_path!r}: {exc}"
        ) from exc

    payload = {"modality": modality, "vector": vector}
    context = template_context(record["identity_id"], modality)
    rng = new_generator(f"enrollment-{modality}")
    envelope = seal_json(master_key, payload, context, rng)
    return set_template(record, modality, envelope)


def enroll_identity(
    identity_id: str,
    label: str,
    master_key: bytes,
    modality_sources: dict,
) -> dict:
    """Convenience wrapper: create an identity and enroll several modalities
    at once.

    ``modality_sources`` maps modality name to a source file path, e.g.
    ``{"voice": "sample.wav", "fingerprint": "sample.png"}``. At least one
    modality is required, since an identity record with zero templates
    cannot ever be verified against.
    """
    if not modality_sources:
        raise EnrollmentError("at least one modality source is required.")
    record = create_identity(identity_id, label, master_key)
    for modality, source_path in modality_sources.items():
        record = enroll_modality(record, modality, source_path, master_key)
    return record
