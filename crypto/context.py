from crypto.errors import Bsr2IntegrationError
SEPARATOR = "|"
_PREFIX = "BrisartIdentityTools/v1"
def _clean(name, value):
    if not isinstance(value, str):
        raise Bsr2IntegrationError(f"context {name} must be a string.")
    if not value:
        raise Bsr2IntegrationError(f"context {name} cannot be empty.")
    if SEPARATOR in value:
        raise Bsr2IntegrationError(f"context {name} cannot contain {SEPARATOR!r}.")
    if "\x00" in value:
        raise Bsr2IntegrationError(f"context {name} cannot contain a NUL byte.")
    return value
def _join(kind, *parts):
    return SEPARATOR.join((_PREFIX, kind, *parts))
def record_context(record_id, kind, label):
    return _join("vault-record", _clean("record_id", record_id), _clean("kind", kind), _clean("label", label))
def template_context(identity_id, modality):
    return _join("biometrics-template", _clean("identity_id", identity_id), _clean("modality", modality))
def attachment_context(identity_id, filename):
    # Distinct "kind" prefix from template_context ("biometrics-attachment"
    # vs "biometrics-template"), and the filename is bound alongside the
    # identity_id, so a sealed attachment can never be swapped onto a
    # different identity OR relabeled as a different attachment name
    # without failing authentication -- the same cross-substitution
    # protection template_context already gives modality templates.
    return _join("biometrics-attachment", _clean("identity_id", identity_id), _clean("filename", filename))
def identity_context(identity_id):
    return _join("biometrics-identity", _clean("identity_id", identity_id))
def package_context(package_id):
    return _join("ibp-package", _clean("package_id", package_id))
def key_slot_context(package_id, identity_id):
    return _join("ibp-key-slot", _clean("package_id", package_id), _clean("identity_id", identity_id))
def keyring_context(wrapper):
    return _join("keyring-wrapper", _clean("wrapper", wrapper))
