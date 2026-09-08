"""Canonical context strings that bind every sealed object to what it is.

This module is the single source of the context strings passed to BSR2's
authenticated envelope (crypto.envelope) and factor layer (crypto.factors).
A context is authenticated alongside the ciphertext, so an envelope sealed
under one context cannot be opened under another: this is the mechanism that
makes cross-substitution detectable across the whole ecosystem. A biometric
template sealed for one identity/modality cannot be dropped into another's
slot, a vault record's payload cannot be swapped with a different record's,
and a package key slot cannot be moved between recipients or packages -- in
every case the moved envelope fails authentication instead of decrypting into
the wrong place (see docs/BSR2_INTEGRATION.md's "Context binding" section).

COMMUNICATION RELATIONSHIPS
- crypto.envelope.seal_bytes/seal_json/open_bytes/open_json take a context
  string produced here and hand it to the vendored BSR2 envelope, which binds
  it into the authentication tag.
- vault.store.vault_service uses record_context; biometrics.engine.enrollment
  /verification use template_context; biometrics.engine.attachments uses
  attachment_context; packages.ciphers uses package_context and
  key_slot_context; crypto.keyring uses keyring_context. Each tool depends on
  this module rather than assembling its own context strings, so the exact
  binding rules live in exactly one auditable place.

FORMAT
Every context is SEPARATOR-joined ("|") and begins with the versioned prefix
"BrisartIdentityTools/v1", followed by a "kind" tag naming the object type,
followed by the identifying fields for that object. The kind tag is what keeps
two different object types (e.g. a biometrics-template vs a
biometrics-attachment for the same identity) from ever producing the same
context string.

WHY "|" AND NUL ARE REJECTED IN FIELD VALUES
Because fields are joined with "|", a field value that itself contained "|"
could shift the boundary between fields and forge a *different* context that
still authenticates -- e.g. record_context("a", "b|c", ...) colliding with
record_context("a|b", "c", ...). _clean() therefore rejects "|" and NUL in
every field value, so no combination of field contents can impersonate a
different context. This validation is duplicated as friendlier, field-named
errors in each tool's own id/label validators (e.g. vault.core.ids,
packages.identity), but this module is the last line that actually enforces
it before sealing.
"""
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
