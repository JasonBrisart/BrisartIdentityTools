"""
crypto.py
---------
Hashing and encryption helpers for the Identity-Bound Package (IBP) prototype.

Integrity hashing versus confidentiality
---------------------------------------
Two different jobs live in this module, and conflating them causes real bugs.

``hash_text`` and ``hash_bytes`` are **integrity digests** over non-secret
content: the manifest, the custody chain, the payload. They are meant to be
recomputable by anyone holding the same data, which is exactly what makes an
audit trail verifiable. They are deliberately unkeyed and fast, and they are the
right tool for that job.

Factor secrets and payload contents are a different matter, and are no longer
handled by a bare digest:

* Low-entropy factors (passphrase, voice phrase) go through
  ``brisart_bsr2.factors.hash_factor``, which is a salted, deliberately slow
  BSR2 derivation.
* High-entropy factors (biometric templates) go through
  ``brisart_bsr2.factors.bind_factor``, a keyed BSR2 MAC.
* Payload confidentiality uses the BSR2 envelope via
  ``brisart_bsr2.envelope``.

The previous version of this module hashed factor secrets with a single unsalted
SHA-256. See ``brisart_bsr2/factors.py`` for why that failed and what replaced
it.

IBP's own job is still identity binding, authorization, audit trails, and custody
tracking. Confidentiality now comes from BSR2 rather than being out of scope.
"""

import hashlib
import hmac
import sys
from pathlib import Path

# IBP modules are imported flat (``from crypto import ...``), so the repository
# root has to be importable for the shared BSR2 layer to resolve.
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from brisart_bsr2 import envelope as _envelope  # noqa: E402
from brisart_bsr2 import factors as _factors  # noqa: E402
from brisart_bsr2.context import identity_context  # noqa: E402
from brisart_bsr2.errors import Bsr2IntegrationError  # noqa: E402
from brisart_bsr2.rng import new_generator  # noqa: E402

# Re-exported so IBP modules keep importing from ``crypto`` rather than reaching
# into the BSR2 layer directly.
bind_factor = _factors.bind_factor
hash_factor = _factors.hash_factor
is_bound_factor = _factors.is_bound_factor
is_factor_hash = _factors.is_factor_hash
is_legacy_digest = _factors.is_legacy_digest
needs_rehash = _factors.needs_rehash
verify_bound_factor = _factors.verify_bound_factor
verify_factor = _factors.verify_factor

is_envelope = _envelope.is_envelope


def hash_text(text: str) -> str:
    """Return the SHA-256 hex digest of a string.

    For integrity of non-secret content only. Never use this for a secret; use
    ``hash_factor`` or ``bind_factor`` instead.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of raw bytes.

    For integrity of non-secret content only. See :func:`hash_text`.
    """
    return hashlib.sha256(data).hexdigest()


def digests_equal(left, right) -> bool:
    """Compare two hex digests in constant time.

    Plain ``==`` on digests short-circuits at the first differing character,
    which leaks how much of a guess was correct through timing. ``compare_digest``
    does not. It also raises on a non-string operand, so ``None`` (a missing
    signature or an unset factor hash) is normalised to a mismatch here rather
    than crashing the caller.
    """
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left, right)


def seal_payload(master_key: bytes, identity_id: str, payload: bytes) -> dict:
    """Encrypt a package payload under the master key.

    Bound to ``identity_id``, so a sealed payload lifted from one package cannot
    be attached to a package belonging to a different identity.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise Bsr2IntegrationError("payload must be bytes.")

    return _envelope.seal_bytes(
        master_key,
        bytes(payload),
        identity_context(identity_id),
        new_generator("ibp-payload"),
    )


def open_payload(master_key: bytes, identity_id: str, sealed: dict) -> bytes:
    """Decrypt a package payload sealed by :func:`seal_payload`."""
    return _envelope.open_bytes(
        master_key, sealed, identity_context(identity_id)
    )
