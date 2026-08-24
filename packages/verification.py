"""Recipient authorization checks for Identity-Bound Packages.

Before ``package.py`` attempts to unwrap a key slot, it is useful to be able
to answer "does this master key actually belong to this recipient?" as a
fast, clearly-named check, rather than letting a mismatched key fail deep
inside ``ciphers.unwrap_content_key`` with a generic authentication error.

This reuses :mod:`crypto.factors`' keyed-binding construction (the same one
``biometrics.identity.device_key`` uses for device binding): a recipient's
master key is bound to a fixed marker string at registration time, and
verified against that binding before any key slot is touched. This is a
belt-and-suspenders check, not the package's actual security boundary --
that boundary is the key slot's own BSR2 authentication tag, which
``ciphers.unwrap_content_key`` enforces regardless.
"""
from crypto.errors import Bsr2IntegrationError
from crypto.factors import bind_factor, verify_bound_factor

RECIPIENT_FACTOR_NAME = "package-recipient"
_VERIFIER_MARKER = "recipient-master-key-bound"


class VerificationError(ValueError):
    """Raised when recipient verification cannot proceed or fails."""


def build_recipient_verifier(master_key: bytes, identity_id: str) -> str:
    """Build a stored verifier binding a recipient's master key to their id.

    The verifier does not reveal the master key and cannot be used to
    recover it; it can only confirm, later, that a supplied master key
    matches the one used here.
    """
    factor_name = f"{RECIPIENT_FACTOR_NAME}:{identity_id}"
    try:
        return bind_factor(master_key, factor_name, _VERIFIER_MARKER)
    except Bsr2IntegrationError as exc:
        raise VerificationError(f"failed to build recipient verifier: {exc}") from exc


def verify_recipient_master_key(master_key: bytes, identity_id: str, verifier: str) -> bool:
    """Check whether ``master_key`` matches a previously built verifier.

    Returns ``False`` rather than raising on a mismatch, so a caller can
    distinguish "wrong key" (a normal, expected outcome to handle
    gracefully) from a malformed verifier string (an actual data problem).
    """
    factor_name = f"{RECIPIENT_FACTOR_NAME}:{identity_id}"
    return verify_bound_factor(master_key, factor_name, _VERIFIER_MARKER, verifier)
