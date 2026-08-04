"""
verification.py
---------------
Identity factor verification for the Identity-Bound Package prototype.

Factors: passphrase (via the keyring), voice phrase, and optional face and
fingerprint templates.

How verification works now
--------------------------
The passphrase is verified by *unlocking the keyring*, not by comparing a digest.
A wrong passphrase fails to unwrap the master key, so it fails authentication
cryptographically rather than by digest comparison. That also means the master key
is a by-product of a successful passphrase check, which is what every other
factor needs.

All other factors are keyed BSR2 MACs under that master key, so they can only be
verified once the identity is unlocked. Stealing an identity file therefore gives
an attacker nothing to test candidate templates against offline.

Attempt limiting
----------------
BSR2's slow KDF raises the cost of offline guessing, but does nothing about an
attacker calling ``verify_identity`` in a loop against a running process. The
caller-persisted ``AttemptLimiter`` in ``brisart_bsr2.throttle`` covers that. It
is not applied implicitly here, because this module has nowhere durable to store
counters; ``verify_identity_throttled`` takes the state and returns the updated
copy for the caller to persist.

Biometric matching remains exact-match on a template digest. Real biometric
verification needs tolerance-based matching and liveness checks, which live in
LabID rather than here.
"""

import sys
from pathlib import Path
from typing import Optional

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from brisart_bsr2.errors import (  # noqa: E402
    Bsr2IntegrationError,
    KeyringAuthenticationError,
)
from brisart_bsr2.throttle import AttemptLimiter, AttemptLockedOut  # noqa: E402
from crypto import verify_bound_factor  # noqa: E402
from identity import (  # noqa: E402
    FACTOR_FACE,
    FACTOR_FINGERPRINT,
    FACTOR_VOICE,
)


def verify_passphrase(identity, candidate: str) -> bool:
    """Verify the passphrase by unlocking the keyring.

    Slow by design. On success the identity is left unlocked, so the caller can
    verify the remaining factors without a second derivation.
    """
    if not isinstance(candidate, str) or not candidate:
        return False
    try:
        identity.unlock(candidate)
    except (KeyringAuthenticationError, Bsr2IntegrationError):
        return False
    return True


def _verify_bound(identity, factor_name: str, candidate, required: bool) -> bool:
    stored = identity.factors.get(factor_name)

    if stored is None:
        # An absent optional factor is not a failure. An absent required one is.
        return not required

    if not isinstance(candidate, str) or not candidate:
        return False

    return verify_bound_factor(
        identity.master_key, factor_name, candidate, stored
    )


def verify_voice(identity, candidate: str) -> bool:
    """Verify the voice phrase. Requires an unlocked identity."""
    return _verify_bound(identity, FACTOR_VOICE, candidate, required=True)


def verify_face(identity, candidate_template: str) -> bool:
    """Verify a face template digest, if one is enrolled."""
    return _verify_bound(identity, FACTOR_FACE, candidate_template, required=False)


def verify_fingerprint(identity, candidate_template: str) -> bool:
    """Verify a fingerprint template digest, if one is enrolled."""
    return _verify_bound(
        identity, FACTOR_FINGERPRINT, candidate_template, required=False
    )


def verify_identity(
    identity,
    passphrase: str,
    voice_phrase: str,
    face_template: Optional[str] = None,
    fingerprint_template: Optional[str] = None,
) -> bool:
    """Require every enrolled factor to pass.

    Evaluated in order, and short-circuits, so a failed passphrase avoids the
    remaining work. Enrolled optional factors are checked only when a candidate is
    supplied; passing ``None`` for an enrolled face template skips that factor
    rather than failing it, which lets a caller run a passphrase-plus-voice gate
    against an identity that also has biometrics enrolled.
    """
    if not verify_passphrase(identity, passphrase):
        return False

    if not verify_voice(identity, voice_phrase):
        return False

    if face_template is not None and not verify_face(identity, face_template):
        return False

    if fingerprint_template is not None and not verify_fingerprint(
        identity, fingerprint_template
    ):
        return False

    return True


def verify_identity_throttled(
    identity,
    passphrase: str,
    voice_phrase: str,
    limiter_state: dict,
    limiter: AttemptLimiter = None,
    **factor_candidates,
):
    """Verify with attempt limiting.

    Returns ``(verified, updated_limiter_state)``. The caller must persist the
    returned state; an in-memory-only counter resets whenever the process
    restarts, which an attacker controls for free.

    Raises :class:`AttemptLockedOut` when an attempt is refused outright.
    """
    limiter = limiter or AttemptLimiter()
    current = limiter.check(limiter_state)

    verified = verify_identity(
        identity, passphrase, voice_phrase, **factor_candidates
    )

    if verified:
        return True, limiter.record_success(current)

    return False, limiter.record_failure(current)


__all__ = [
    "AttemptLimiter",
    "AttemptLockedOut",
    "verify_face",
    "verify_fingerprint",
    "verify_identity",
    "verify_identity_throttled",
    "verify_passphrase",
    "verify_voice",
]
