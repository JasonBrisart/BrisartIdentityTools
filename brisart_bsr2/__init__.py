"""BSR2 integration layer for BrisartIdentityTools.

The cryptography here is entirely BSR2, vendored unmodified in ``bsr2_vendor/``.
This package does not implement any cryptographic primitive. It supplies the
surrounding machinery BSR2 deliberately leaves to its caller:

* a DRBG instance with correct seeding, reseed handling, and lifecycle limits
* length-hiding padding, because a BSR2 envelope's ciphertext is exactly as long
  as its plaintext
* a keyring: one expensive passphrase derivation, then a random master key
  wrapped under both the passphrase and an offline recovery code
* attempt limiting, so an online guessing loop is bounded independently of the
  KDF cost
* canonical context strings, so every sealed object is bound to its own identity

Everything is standard library only, matching the repository's zero-dependency
rule. BSR2 itself is standard library only as well.
"""

from brisart_bsr2.context import (
    identity_context,
    keyring_context,
    record_context,
    template_context,
)
from brisart_bsr2.envelope import (
    PADDING_BLOCK_BYTES,
    is_envelope,
    open_bytes,
    open_json,
    seal_bytes,
    seal_json,
)
from brisart_bsr2.errors import (
    Bsr2IntegrationError,
    EnvelopeAuthenticationError,
    KeyringAuthenticationError,
    KeyringFormatError,
    KeyringLockedError,
)
from brisart_bsr2.factors import (
    hash_factor,
    needs_rehash,
    verify_factor,
)
from brisart_bsr2.keyring import (
    MASTER_KEY_BYTES,
    Keyring,
    format_recovery_code,
    generate_recovery_code,
)
from brisart_bsr2.rng import new_generator
from brisart_bsr2.throttle import AttemptLimiter

__all__ = [
    "AttemptLimiter",
    "Bsr2IntegrationError",
    "EnvelopeAuthenticationError",
    "Keyring",
    "KeyringAuthenticationError",
    "KeyringFormatError",
    "KeyringLockedError",
    "MASTER_KEY_BYTES",
    "PADDING_BLOCK_BYTES",
    "format_recovery_code",
    "generate_recovery_code",
    "hash_factor",
    "identity_context",
    "is_envelope",
    "keyring_context",
    "needs_rehash",
    "new_generator",
    "open_bytes",
    "open_json",
    "record_context",
    "seal_bytes",
    "seal_json",
    "template_context",
    "verify_factor",
]
