"""BSR2 keyring: master key wrapping under a passphrase and a recovery code.

The design problem this solves: BSR2's ``derive_password_key`` is genuinely
expensive in pure Python (measured at roughly 70 seconds at its own enforced
minimum of 10,000 iterations, and around 14 minutes at its 120,000 default).
Deriving a key from the passphrase for every operation would be unusable, and
lowering the iteration count below BSR2's floor is not permitted by BSR2 itself.

The answer is standard key wrapping, which is what full-disk encryption has
always done for the same reason:

* The data is encrypted under a random 32-byte **master key**, never directly
  under a passphrase-derived key.
* The master key is sealed twice, once under a key derived from the passphrase
  and once under a key derived from an offline **recovery code**.
* Unlocking derives one KDF result, unwraps the master key, and holds it for the
  session. Every subsequent seal and open is fast.

Consequences that follow from this, and are deliberate:

* Changing the passphrase re-wraps the master key. It does not re-encrypt any
  data, because the master key does not change.
* The recovery code is a second full-strength path to the master key. Anyone
  holding it has the same access the passphrase gives. That is the price of
  recoverability, and it is why the code is shown exactly once and never stored.
* Losing both the passphrase and the recovery code is unrecoverable. There is no
  third path by design.
"""
import secrets
import unicodedata
from typing import Optional

from crypto.context import keyring_context
from crypto.envelope import is_envelope, open_bytes, seal_bytes
from crypto.errors import (
    Bsr2IntegrationError,
    KeyringAuthenticationError,
    KeyringFormatError,
    KeyringLockedError,
)
from crypto.rng import new_generator
from crypto.vendor import (
    BrisartEnvelopeError,
    BrisartPrimitiveError,
    constant_time_equal,
    derive_password_key,
    hex_decode,
    hex_encode,
    keyed_mac,
)

MASTER_KEY_BYTES = 32
KDF_SALT_BYTES = 32

# BSR2 enforces a 10,000 floor and defaults to 120,000. At roughly 7 ms per
# iteration in pure Python, the floor already costs about 70 seconds per
# derivation. That is the value used here: it is the strongest setting BSR2
# permits that still allows an unlock to complete in under a couple of minutes,
# and because unlocking happens once per session rather than per operation, the
# cost is paid once. Recorded per keyring so it can be raised later without
# invalidating existing keyrings.
KDF_ITERATIONS = 10_000

# Upper bound mirroring crypto.factors.MAXIMUM_ITERATIONS. Legitimate
# keyrings sit at 10,000..120,000; a tampered header carrying an astronomical
# count would otherwise make an unlock derive for years before it can fail.
MAXIMUM_KDF_ITERATIONS = 1_000_000

RECOVERY_CODE_GROUPS = 8
RECOVERY_CODE_GROUP_SIZE = 5

# Crockford base32 without I, L, O, U: no ambiguity when transcribed by hand.
_RECOVERY_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
# The characters excluded from the alphabet, mapped to their visual equivalents,
# so a code transcribed by hand still resolves.
_CONFUSABLE_CHARACTERS = {"I": "1", "L": "1", "O": "0", "U": "V"}

KEYRING_FORMAT = "brisart-identity-tools/bsr2-keyring/v1"

_WRAPPER_PASSPHRASE = "passphrase"
_WRAPPER_RECOVERY = "recovery"


def generate_recovery_code() -> str:
    """Generate a fresh recovery code.

    Forty characters from a 32-symbol alphabet is 200 bits, drawn from
    ``secrets.choice``. Well beyond any brute-force reach, which matters because
    this code is a direct path to the master key and gets no attempt limiting
    once an attacker has the keyring file.
    """
    characters = [
        secrets.choice(_RECOVERY_ALPHABET)
        for _ in range(RECOVERY_CODE_GROUPS * RECOVERY_CODE_GROUP_SIZE)
    ]
    return "".join(characters)


def format_recovery_code(code: str) -> str:
    """Format a recovery code in readable groups for display or printing."""
    normalized = _normalize_recovery_code(code)
    return "-".join(
        normalized[index:index + RECOVERY_CODE_GROUP_SIZE]
        for index in range(0, len(normalized), RECOVERY_CODE_GROUP_SIZE)
    )


def _normalize_recovery_code(code: str) -> str:
    """Normalise a typed recovery code.

    Hyphens and spaces are stripped, case is folded, and the characters excluded
    from the alphabet are mapped to their visual equivalents, so a code
    transcribed by hand still works.
    """
    if not isinstance(code, str):
        raise Bsr2IntegrationError("recovery code must be a string.")
    cleaned = []
    for character in code.strip().upper():
        if character in "- \t\r\n":
            continue
        folded = _CONFUSABLE_CHARACTERS.get(character, character)
        if folded not in _RECOVERY_ALPHABET:
            raise Bsr2IntegrationError(
                "recovery code contains characters outside its alphabet."
            )
        cleaned.append(folded)
    normalized = "".join(cleaned)
    expected = RECOVERY_CODE_GROUPS * RECOVERY_CODE_GROUP_SIZE
    if len(normalized) != expected:
        raise Bsr2IntegrationError(
            f"recovery code must contain {expected} characters, "
            f"got {len(normalized)}."
        )
    return normalized


def _normalize_passphrase(passphrase: str) -> str:
    if not isinstance(passphrase, str):
        raise Bsr2IntegrationError("passphrase must be a string.")
    if not passphrase:
        raise Bsr2IntegrationError("passphrase cannot be empty.")
    # NFKC so a passphrase typed on a different platform or keyboard layout does
    # not derive a different key purely through Unicode composition.
    return unicodedata.normalize("NFKC", passphrase)


def _derive_wrapping_key(secret_text: str, salt: bytes, iterations: int) -> bytes:
    """Derive a wrapping key from a passphrase or recovery code using BSR2."""
    return derive_password_key(
        secret_text,
        salt,
        iterations=iterations,
        output_bytes=MASTER_KEY_BYTES,
    )


def _require_int(value, name: str) -> int:
    if type(value) is not int:
        raise KeyringFormatError(f"keyring {name} must be an integer.")
    return value


class Keyring:
    """A master key wrapped under a passphrase and a recovery code.

    ``state`` is a plain JSON-serialisable dict, so it can live inside a vault
    header or a standalone file. It contains no plaintext key material: only
    salts, iteration counts, and two BSR2 envelopes.
    """

    def __init__(self, state: dict):
        self._state = self._validate(state)
        self._master_key = None

    # ---------------------------------------------------------------- creation
    @classmethod
    def create(
        cls,
        passphrase: str,
        iterations: int = KDF_ITERATIONS,
        recovery_code: Optional[str] = None,
    ):
        """Build a new keyring around a fresh random master key.

        Returns ``(keyring, recovery_code)``. The recovery code is returned only
        here and never stored in recoverable form, so a caller that discards it
        cannot get it back.
        """
        passphrase_text = _normalize_passphrase(passphrase)
        iterations = _require_int(iterations, "iterations")
        if iterations < 10_000:
            # Mirrors BSR2's own floor. Stated explicitly so the failure names
            # the real constraint rather than surfacing a primitive error.
            raise Bsr2IntegrationError(
                "iteration count is below the BSR2 research minimum of 10,000."
            )
        if iterations > MAXIMUM_KDF_ITERATIONS:
            raise Bsr2IntegrationError(
                f"iteration count is above the {MAXIMUM_KDF_ITERATIONS} maximum."
            )
        if recovery_code is None:
            recovery_text = generate_recovery_code()
        else:
            recovery_text = _normalize_recovery_code(recovery_code)
        master_key = secrets.token_bytes(MASTER_KEY_BYTES)
        rng = new_generator("keyring-create")
        passphrase_salt = secrets.token_bytes(KDF_SALT_BYTES)
        recovery_salt = secrets.token_bytes(KDF_SALT_BYTES)
        passphrase_key = _derive_wrapping_key(
            passphrase_text, passphrase_salt, iterations
        )
        recovery_key = _derive_wrapping_key(
            recovery_text, recovery_salt, iterations
        )
        state = {
            "format": KEYRING_FORMAT,
            "kdf": "BSR2/derive_password_key",
            "iterations": iterations,
            "passphrase": {
                "salt": hex_encode(passphrase_salt),
                "wrapped_master_key": seal_bytes(
                    passphrase_key,
                    master_key,
                    keyring_context(_WRAPPER_PASSPHRASE),
                    rng,
                ),
            },
            "recovery": {
                "salt": hex_encode(recovery_salt),
                "wrapped_master_key": seal_bytes(
                    recovery_key,
                    master_key,
                    keyring_context(_WRAPPER_RECOVERY),
                    rng,
                ),
            },
            "master_key_check": hex_encode(cls._check_value(master_key)),
        }
        keyring = cls(state)
        keyring._master_key = master_key
        return keyring, format_recovery_code(recovery_text)

    # -------------------------------------------------------------- validation
    @staticmethod
    def _validate(state: dict) -> dict:
        if not isinstance(state, dict):
            raise KeyringFormatError("keyring state must be an object.")
        if state.get("format") != KEYRING_FORMAT:
            raise KeyringFormatError("unsupported keyring format.")
        if state.get("kdf") != "BSR2/derive_password_key":
            raise KeyringFormatError("unsupported keyring KDF.")
        iterations = _require_int(state.get("iterations"), "iterations")
        if iterations < 10_000:
            # A tampered keyring header could otherwise request a cheap
            # derivation and make the KDF trivially brute-forceable.
            raise KeyringFormatError(
                "keyring iteration count is below the BSR2 minimum."
            )
        if iterations > MAXIMUM_KDF_ITERATIONS:
            # The opposite tamper: an astronomical count that turns unlock into
            # a years-long hang before authentication can fail.
            raise KeyringFormatError(
                "keyring iteration count is above the supported maximum."
            )
        for wrapper in (_WRAPPER_PASSPHRASE, _WRAPPER_RECOVERY):
            section = state.get(wrapper)
            if not isinstance(section, dict):
                raise KeyringFormatError(
                    f"keyring {wrapper} section must be an object."
                )
            salt_text = section.get("salt")
            if not isinstance(salt_text, str):
                raise KeyringFormatError(
                    f"keyring {wrapper} salt must be hexadecimal text."
                )
            try:
                salt = hex_decode(salt_text)
            except BrisartPrimitiveError as exc:
                raise KeyringFormatError(
                    f"keyring {wrapper} salt is not valid hexadecimal."
                ) from exc
            if len(salt) != KDF_SALT_BYTES:
                raise KeyringFormatError(
                    f"keyring {wrapper} salt has an invalid length."
                )
            if not is_envelope(section.get("wrapped_master_key")):
                raise KeyringFormatError(
                    f"keyring {wrapper} wrapper is not a BSR2 envelope."
                )
        check = state.get("master_key_check")
        if not isinstance(check, str):
            raise KeyringFormatError("keyring master key check must be text.")
        try:
            if len(hex_decode(check)) != 32:
                raise KeyringFormatError(
                    "keyring master key check has an invalid length."
                )
        except BrisartPrimitiveError as exc:
            raise KeyringFormatError(
                "keyring master key check is not valid hexadecimal."
            ) from exc
        return state

    @staticmethod
    def _check_value(master_key: bytes) -> bytes:
        """A MAC over a fixed string, used to confirm an unwrap produced the
        expected master key.

        The BSR2 tag already authenticates each wrapper, so this is a redundancy
        check: it catches a keyring whose two wrappers hold *different* master
        keys, which would otherwise show up much later as unopenable data.
        """
        return keyed_mac(
            master_key,
            b"BrisartIdentityTools/keyring/master-key-check/v1",
            32,
        )

    # ------------------------------------------------------------------ unlock
    def _unwrap(self, wrapper: str, secret_text: str) -> bytes:
        section = self._state[wrapper]
        salt = hex_decode(section["salt"])
        wrapping_key = _derive_wrapping_key(
            secret_text, salt, self._state["iterations"]
        )
        try:
            master_key = open_bytes(
                wrapping_key,
                section["wrapped_master_key"],
                keyring_context(wrapper),
            )
        except (BrisartEnvelopeError, Bsr2IntegrationError) as exc:
            # Deliberately uniform: the caller learns the unlock failed, not
            # whether the envelope was structurally valid.
            raise KeyringAuthenticationError(
                "unlock failed: incorrect secret or modified keyring."
            ) from exc
        if len(master_key) != MASTER_KEY_BYTES:
            raise KeyringFormatError("unwrapped master key has an invalid length.")
        if not constant_time_equal(
            self._check_value(master_key), hex_decode(self._state["master_key_check"])
        ):
            raise KeyringFormatError(
                "unwrapped master key does not match the keyring check value."
            )
        return master_key

    def unlock_with_passphrase(self, passphrase: str) -> bytes:
        """Unwrap and cache the master key using the passphrase."""
        master_key = self._unwrap(
            _WRAPPER_PASSPHRASE, _normalize_passphrase(passphrase)
        )
        self._master_key = master_key
        return master_key

    def unlock_with_recovery_code(self, recovery_code: str) -> bytes:
        """Unwrap and cache the master key using the recovery code."""
        master_key = self._unwrap(
            _WRAPPER_RECOVERY, _normalize_recovery_code(recovery_code)
        )
        self._master_key = master_key
        return master_key

    @property
    def is_unlocked(self) -> bool:
        return self._master_key is not None

    @property
    def master_key(self) -> bytes:
        if self._master_key is None:
            raise KeyringLockedError(
                "keyring is locked; unlock it before using the master key."
            )
        return self._master_key

    def lock(self) -> None:
        """Drop the cached master key.

        Python cannot guarantee the bytes leave process memory, so this reduces
        exposure rather than eliminating it. Claiming otherwise would be false.
        """
        self._master_key = None

    # ----------------------------------------------------------- modification
    def change_passphrase(self, new_passphrase: str) -> None:
        """Re-wrap the master key under a new passphrase.

        Requires the keyring to be unlocked. No stored data is re-encrypted,
        because the master key itself does not change.
        """
        if self._master_key is None:
            raise KeyringLockedError(
                "unlock the keyring before changing its passphrase."
            )
        passphrase_text = _normalize_passphrase(new_passphrase)
        salt = secrets.token_bytes(KDF_SALT_BYTES)
        wrapping_key = _derive_wrapping_key(
            passphrase_text, salt, self._state["iterations"]
        )
        rng = new_generator("keyring-rewrap")
        self._state["passphrase"] = {
            "salt": hex_encode(salt),
            "wrapped_master_key": seal_bytes(
                wrapping_key,
                self._master_key,
                keyring_context(_WRAPPER_PASSPHRASE),
                rng,
            ),
        }

    def rotate_recovery_code(self) -> str:
        """Issue a new recovery code, invalidating the previous one.

        Returns the new code formatted for display. Requires an unlocked keyring.
        """
        if self._master_key is None:
            raise KeyringLockedError(
                "unlock the keyring before rotating its recovery code."
            )
        recovery_text = generate_recovery_code()
        salt = secrets.token_bytes(KDF_SALT_BYTES)
        wrapping_key = _derive_wrapping_key(
            recovery_text, salt, self._state["iterations"]
        )
        rng = new_generator("keyring-rotate")
        self._state["recovery"] = {
            "salt": hex_encode(salt),
            "wrapped_master_key": seal_bytes(
                wrapping_key,
                self._master_key,
                keyring_context(_WRAPPER_RECOVERY),
                rng,
            ),
        }
        return format_recovery_code(recovery_text)

    # ------------------------------------------------------------------ export
    def to_state(self) -> dict:
        """Return the storable keyring state.

        Contains no plaintext key material, so it is safe to write to disk
        alongside the data it protects.
        """
        return self._state

    def public_summary(self) -> dict:
        """Non-secret keyring metadata, for status output."""
        return {
            "format": self._state["format"],
            "kdf": self._state["kdf"],
            "iterations": self._state["iterations"],
            "recovery_code_available": True,
            "unlocked": self.is_unlocked,
        }
