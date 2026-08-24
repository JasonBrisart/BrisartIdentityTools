"""Error types for the BSR2 integration layer.

Authentication failure is kept distinct from malformed input. Callers need to
treat "this is not shaped like a keyring" as a data bug and "the tag did not
verify" as a security event, and one shared exception type forces them to
string-match messages to tell those apart.
"""


class Bsr2IntegrationError(Exception):
    """Base class for BSR2 integration failures."""


class KeyringFormatError(Bsr2IntegrationError):
    """Raised when stored keyring material is not well formed."""


class KeyringAuthenticationError(Bsr2IntegrationError):
    """Raised when a passphrase or recovery code does not unwrap the master key.

    The message deliberately does not say whether the wrapper was structurally
    valid, because that distinction tells an attacker whether a guess was
    partially correct.
    """


class KeyringLockedError(Bsr2IntegrationError):
    """Raised when an operation needs a master key that is not unlocked."""


class EnvelopeAuthenticationError(Bsr2IntegrationError):
    """Raised when a sealed payload fails authentication.

    Wraps the vendored layer's ``BrisartEnvelopeError`` so callers catch a
    single exception family instead of importing vendor exception types. It
    covers a modified ciphertext, the wrong key, and the wrong context alike:
    all three are indistinguishable to the verifier, and treating them as one
    outcome avoids leaking which one occurred.

    The original exception is kept as ``__cause__`` for debugging.
    """
