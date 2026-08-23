"""
identity.py
-----------
Identity model + creation/loading for the Identity-Bound Package prototype.

An identity never stores a raw factor value. It stores:

* a **BSR2 keyring**, holding a random master key wrapped under the passphrase
  and under an offline recovery code
* **bound factor records** for every other factor (voice phrase, and optionally
  face and fingerprint templates), each a keyed BSR2 MAC under that master key

Why the passphrase is treated differently from the rest
-------------------------------------------------------
The passphrase is the only low-entropy factor here, so it is the only one worth
attacking by guessing. It goes through BSR2's deliberately slow
``derive_password_key``, which is why :func:`create_identity` takes minutes
rather than milliseconds. Every other factor is high-entropy and gets a fast
keyed MAC under the master key; stretching those would cost time and add nothing.
See ``brisart_bsr2/factors.py`` for the full reasoning.

A consequence worth stating plainly: because the other factors are keyed under
the master key, they cannot be verified at all without first unlocking the
keyring. That is intentional. Stealing an identity file no longer lets an
attacker test candidate voice phrases or templates offline, which the previous
unsalted-SHA-256 version allowed.
"""
import json
import secrets
import sys
import uuid
from pathlib import Path
from typing import Optional

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from brisart_bsr2.errors import Bsr2IntegrationError  # noqa: E402
from brisart_bsr2.keyring import MASTER_KEY_BYTES, Keyring  # noqa: E402
from crypto import bind_factor  # noqa: E402

IDENTITY_DIR = Path(__file__).parent / "identities"
IDENTITY_FORMAT = "brisart-identity-tools/ibp-identity/v2"

FACTOR_VOICE = "voice"
FACTOR_FACE = "face"
FACTOR_FINGERPRINT = "fingerprint"


class IdentityProfile:
    """A loaded identity.

    Holds an optional in-memory master key. It is present immediately after
    :func:`create_identity` and after :meth:`unlock`, and absent otherwise, so
    code paths that need it fail loudly rather than silently skipping a check.
    """

    def __init__(self, data: dict):
        if not isinstance(data, dict):
            raise Bsr2IntegrationError("identity data must be an object.")
        fmt = data.get("format")
        if fmt != IDENTITY_FORMAT:
            # Legacy v1 identities stored bare SHA-256 factor hashes. They cannot
            # be upgraded in place, because the original factor values are not
            # recoverable from those digests.
            raise Bsr2IntegrationError(
                "unsupported identity format: "
                f"{fmt!r}. Identities created before BSR2 must be re-enrolled; "
                "their factor values cannot be recovered from the old hashes."
            )
        # A malformed file missing these fields used to raise a bare KeyError out
        # of the constructor. Report it as an integration error like every other
        # structural problem here, so callers only ever catch Bsr2IntegrationError.
        if "identity_id" not in data or "name" not in data:
            raise Bsr2IntegrationError(
                "identity file is missing identity_id or name."
            )
        self.identity_id = data["identity_id"]
        self.name = data["name"]
        # The keyring is parsed lazily. An identity whose master key is supplied
        # directly via adopt_master_key() never needs one, which is how the test
        # suite and any caller that already unlocked elsewhere avoid paying for a
        # passphrase derivation. Validating it here would reject those outright.
        self._keyring_state = data.get("keyring")
        self._keyring = None
        factors = data.get("factors")
        if not isinstance(factors, dict):
            raise Bsr2IntegrationError("identity factors must be an object.")
        self.factors = factors
        self._master_key = None

    def _require_keyring(self) -> Keyring:
        if self._keyring is None:
            if not isinstance(self._keyring_state, dict):
                raise Bsr2IntegrationError(
                    "identity has no keyring; it cannot be unlocked by "
                    "passphrase or recovery code."
                )
            self._keyring = Keyring(self._keyring_state)
        return self._keyring

    # ----------------------------------------------------------------- loading
    @classmethod
    def load(cls, filepath: str) -> "IdentityProfile":
        with open(filepath, "r", encoding="utf-8") as handle:
            return cls(json.load(handle))

    # ------------------------------------------------------------------ unlock
    def unlock(self, passphrase: str) -> bytes:
        """Unlock with the passphrase. Slow by design; see the module docstring."""
        self._master_key = self._require_keyring().unlock_with_passphrase(
            passphrase
        )
        return self._master_key

    def unlock_with_recovery_code(self, recovery_code: str) -> bytes:
        """Unlock with the offline recovery code."""
        self._master_key = self._require_keyring().unlock_with_recovery_code(
            recovery_code
        )
        return self._master_key

    def adopt_master_key(self, master_key: bytes) -> None:
        """Attach an already-unwrapped master key.

        For callers that unlocked the same keyring elsewhere and are avoiding a
        second expensive derivation. The key is not verified against the keyring
        here, so a wrong key surfaces later as a factor mismatch.
        """
        if (
            not isinstance(master_key, (bytes, bytearray))
            or len(master_key) != MASTER_KEY_BYTES
        ):
            raise Bsr2IntegrationError(
                f"master key must be {MASTER_KEY_BYTES} bytes."
            )
        self._master_key = bytes(master_key)

    def lock(self) -> None:
        self._master_key = None
        if self._keyring is not None:
            self._keyring.lock()

    @property
    def is_unlocked(self) -> bool:
        return self._master_key is not None

    @property
    def master_key(self) -> bytes:
        if self._master_key is None:
            raise Bsr2IntegrationError(
                "identity is locked; unlock it before verifying factors."
            )
        return self._master_key

    # ------------------------------------------------------------------ export
    def to_state(self) -> dict:
        state = {
            "format": IDENTITY_FORMAT,
            "identity_id": self.identity_id,
            "name": self.name,
            "factors": self.factors,
        }
        if self._keyring is not None:
            state["keyring"] = self._keyring.to_state()
        elif self._keyring_state is not None:
            state["keyring"] = self._keyring_state
        return state

    def save(self, filepath: str) -> None:
        with open(filepath, "w", encoding="utf-8") as handle:
            json.dump(self.to_state(), handle, indent=4, sort_keys=True)


def build_identity_state(
    name: str,
    master_key: bytes,
    keyring_state: dict,
    voice_phrase: str,
    face_template: Optional[str] = None,
    fingerprint_template: Optional[str] = None,
    identity_id: Optional[str] = None,
) -> dict:
    """Assemble identity state from an already-created keyring and master key.

    Separated from :func:`create_identity` so callers that already hold a master
    key do not pay for a second passphrase derivation. ``keyring_state`` may be
    ``None`` for an identity that will only ever adopt its master key directly;
    such an identity cannot be unlocked by passphrase.
    """
    identity_id = identity_id or str(uuid.uuid4())
    factors = {
        FACTOR_VOICE: bind_factor(master_key, FACTOR_VOICE, voice_phrase),
    }
    if face_template is not None:
        factors[FACTOR_FACE] = bind_factor(
            master_key, FACTOR_FACE, face_template
        )
    if fingerprint_template is not None:
        factors[FACTOR_FINGERPRINT] = bind_factor(
            master_key, FACTOR_FINGERPRINT, fingerprint_template
        )
    state = {
        "format": IDENTITY_FORMAT,
        "identity_id": identity_id,
        "name": name,
        "factors": factors,
    }
    if keyring_state is not None:
        state["keyring"] = keyring_state
    return state


def create_identity(
    name: str,
    passphrase: str,
    voice_phrase: str,
    face_template: Optional[str] = None,
    fingerprint_template: Optional[str] = None,
    output_dir=None,
):
    """Create an identity file.

    Returns ``(path, recovery_code)``. The recovery code is shown once and is not
    stored in recoverable form; losing both it and the passphrase makes the
    identity permanently unopenable.

    Slow: performs two BSR2 passphrase derivations (passphrase and recovery
    wrappers), on the order of minutes.
    """
    if not isinstance(name, str) or not name:
        raise Bsr2IntegrationError("identity name must be a non-empty string.")
    if not isinstance(voice_phrase, str) or not voice_phrase:
        raise Bsr2IntegrationError("voice phrase must be a non-empty string.")
    keyring, recovery_code = Keyring.create(passphrase)
    state = build_identity_state(
        name=name,
        master_key=keyring.master_key,
        keyring_state=keyring.to_state(),
        voice_phrase=voice_phrase,
        face_template=face_template,
        fingerprint_template=fingerprint_template,
    )
    directory = Path(output_dir) if output_dir else IDENTITY_DIR
    directory.mkdir(parents=True, exist_ok=True)
    out = directory / f"{state['identity_id']}.identity"
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=4, sort_keys=True)
    return str(out), recovery_code


def _random_master_key() -> bytes:
    return secrets.token_bytes(MASTER_KEY_BYTES)


if __name__ == "__main__":
    entered_name = input("Name: ")
    entered_passphrase = input("Passphrase: ")
    entered_voice = input("Voice phrase: ")
    print("\nDeriving keys with BSR2. This takes several minutes.\n")
    path, code = create_identity(
        entered_name, entered_passphrase, entered_voice
    )
    print(f"Created identity '{entered_name}'")
    print(f"  File: {path}")
    print("\n  RECOVERY CODE (write this down, it is shown only once):")
    print(f"    {code}")
    print(
        "\n  Without the passphrase or this recovery code, the identity "
        "cannot be opened by anyone, including you."
    )