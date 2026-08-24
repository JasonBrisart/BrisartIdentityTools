"""Low-level cryptographic operations for Identity-Bound Packages.

An IBP separates the secret that protects the *payload* from the secrets
that protect *access to that secret*, the same envelope-around-a-key pattern
:mod:`crypto.keyring` uses for a single master key. Here it is generalised to
many recipients:

* A random 32-byte **content key** seals the actual payload once.
* The content key itself is sealed once per recipient, each under that
  recipient's own master key, in that recipient's own **key slot**.

Consequences that follow from this and are deliberate: adding or removing a
recipient only touches that recipient's key slot -- the payload is never
re-encrypted, and no other recipient's slot is touched. Losing every
recipient's master key makes the package permanently unopenable, by design;
there is no back door.

Named ``ciphers.py`` rather than ``crypto.py`` specifically to avoid
colliding with the top-level ``crypto/`` package this module imports from.
"""
import secrets

from crypto.context import key_slot_context, package_context
from crypto.envelope import open_bytes, open_json, seal_bytes, seal_json
from crypto.errors import Bsr2IntegrationError
from crypto.rng import new_generator

CONTENT_KEY_BYTES = 32


class CiphersError(ValueError):
    """Raised on invalid cipher inputs (not on authentication failure --
    see :class:`crypto.errors.Bsr2IntegrationError` and its subclasses for
    that)."""


def new_content_key() -> bytes:
    """Generate a fresh random content key for one package."""
    return secrets.token_bytes(CONTENT_KEY_BYTES)


def wrap_content_key(recipient_master_key: bytes, package_id: str, identity_id: str, content_key: bytes) -> dict:
    """Seal ``content_key`` into one recipient's key slot.

    The envelope's context binds both ``package_id`` and ``identity_id``, so
    a key slot sealed for one recipient cannot be moved into another
    recipient's slot in the same package, nor reused in a different package,
    even by an attacker who can edit the stored package file.
    """
    if not isinstance(content_key, (bytes, bytearray)) or len(content_key) != CONTENT_KEY_BYTES:
        raise CiphersError(f"content_key must be exactly {CONTENT_KEY_BYTES} bytes.")
    context = key_slot_context(package_id, identity_id)
    rng = new_generator("package-key-slot")
    return seal_bytes(recipient_master_key, content_key, context, rng)


def unwrap_content_key(recipient_master_key: bytes, package_id: str, identity_id: str, wrapped: dict) -> bytes:
    """Recover the content key from one recipient's key slot.

    Raises :class:`crypto.errors.EnvelopeAuthenticationError` (a
    ``Bsr2IntegrationError``) if the supplied master key does not match the
    slot, or if the slot was sealed under a different package or identity
    context than claimed.
    """
    context = key_slot_context(package_id, identity_id)
    content_key = open_bytes(recipient_master_key, wrapped, context)
    if len(content_key) != CONTENT_KEY_BYTES:
        raise CiphersError("unwrapped content key has an invalid length.")
    return content_key


def seal_payload(content_key: bytes, package_id: str, payload: dict) -> dict:
    """Seal a package's payload under its content key."""
    context = package_context(package_id)
    rng = new_generator("package-payload")
    return seal_json(content_key, payload, context, rng)


def open_payload(content_key: bytes, package_id: str, sealed_payload: dict) -> dict:
    """Open a package's payload using an already-recovered content key."""
    context = package_context(package_id)
    return open_json(content_key, sealed_payload, context)


__all__ = [
    "CONTENT_KEY_BYTES",
    "CiphersError",
    "new_content_key",
    "open_payload",
    "seal_payload",
    "unwrap_content_key",
    "wrap_content_key",
]
