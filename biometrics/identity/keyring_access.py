"""
File: biometrics/identity/keyring_access.py
Purpose:
    Single shared entry point for unlocking the biometrics BSR2 keyring
    (data/keyring.json) with online-attempt throttling enforced identically
    for every caller. Before this module existed, biometrics/app.py's CLI
    (_unlock_keyring()) and gui/tabs/tab_biometrics.py's GUI
    (_ensure_keyring()) each called crypto.keyring.Keyring.
    unlock_with_passphrase() directly, and neither consulted
    crypto.throttle.AttemptLimiter at all -- an attacker driving either
    entry point in a loop against a running process paid no cost beyond
    BSR2's own slow KDF, with no backoff and no lockout, and the two
    interfaces did not even agree with each other on what (if anything) was
    enforced. Both entry points now call unlock_with_passphrase() below
    instead, so the identical throttling policy applies no matter which
    interface is used to reach it.

Communication relationships:
    Called by:
        - biometrics.app._unlock_keyring(), the CLI's sole unlock path,
          reached from every command that touches an identity's stored
          templates or attachments (enroll, verify, attach, attach-paths,
          extract-attachment, restore-paths, remove-attachment).
        - gui.tabs.tab_biometrics.BiometricsTab._ensure_keyring()'s unlock
          branch, the GUI's sole unlock path.
    Calls out to:
        - crypto.keyring.Keyring.unlock_with_passphrase() to perform the
          actual BSR2 KDF derivation and master-key unwrap. This module
          does not touch cryptography itself; it only gates when that call
          is allowed to run and records whether it succeeded.
        - crypto.attempt_store (check_and_get_state / record_failure /
          record_success), which is the same adapter
          vault.store.vault_service uses for the vault's own unlock paths,
          so both tools in the ecosystem persist throttle state the same
          way even though this module and vault_service.py otherwise share
          no code (consistent with this repository's existing deliberate
          separation between the vault and biometrics tools -- see e.g.
          biometrics.engine.bulk_attachments's own docstring on why it
          duplicates vault.store.bulk_file_service rather than importing
          it).
        - common.atomic_io.atomic_write_json (with
          common.atomic_io.SENSITIVE_FILE_MODE) to persist the updated
          attempt state back into keyring.json, matching how
          biometrics.app._load_or_create_keyring() already writes that
          file.

Parameters / settings:
    KeyringAccessError:
        The single exception type every caller catches. Wraps both a
        throttled/locked-out refusal (crypto.throttle.AttemptLockedOut,
        raised BEFORE any KDF is attempted) and a genuine wrong-passphrase
        failure (crypto.errors.Bsr2IntegrationError, raised by
        Keyring.unlock_with_passphrase() itself), so callers do not need to
        import or distinguish between crypto.throttle and crypto.errors
        exception types -- the same simplification
        crypto.envelope.EnvelopeAuthenticationError already gives envelope
        callers.

Edge-case behavior:
    - A keyring.json with no prior "unlock_attempts" field (every keyring
      created before this module existed, or a brand-new one) is treated as
      fresh, unthrottled state on first call -- see crypto.attempt_store's
      own docstring for why no migration step is needed.
    - The attempt state is re-read from disk at the START of every call
      (rather than trusted from a value cached in memory), so a check
      always reflects the most recently persisted failure/success, even if
      the in-memory Keyring object passed in was constructed from a
      slightly earlier read of the same file.
    - If Keyring.unlock_with_passphrase() itself raises for a reason other
      than a wrong passphrase (e.g. a structurally corrupted keyring
      section), that failure is still recorded as one failed attempt and
      still raises KeyringAccessError -- this module does not attempt to
      distinguish "wrong secret" from "corrupted keyring" the same way
      crypto.keyring.Keyring itself deliberately keeps that distinction
      uniform (see crypto/keyring.py's own docstring on why an unlock
      failure message does not disclose which one occurred).
"""
import json
from pathlib import Path

from common.atomic_io import SENSITIVE_FILE_MODE, atomic_write_json
from crypto import attempt_store
from crypto.errors import Bsr2IntegrationError
from crypto.keyring import Keyring
from crypto.throttle import AttemptLockedOut


class KeyringAccessError(ValueError):
    """Raised for a refused or failed biometrics keyring unlock attempt,
    whether refused by the attempt-throttle gate or rejected by the
    underlying BSR2 unwrap itself."""


def _read_raw_state(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_raw_state(path: Path, raw_state: dict) -> None:
    atomic_write_json(path, raw_state, file_mode=SENSITIVE_FILE_MODE)


def unlock_with_passphrase(keyring: Keyring, path: Path, passphrase: str) -> bytes:
    """Unlock `keyring` (already constructed from the state stored at
    `path`) using `passphrase`, enforcing crypto.attempt_store throttling
    state persisted in the same file.

    Raises KeyringAccessError if the attempt budget is currently exhausted
    (before the passphrase is even attempted), or if the passphrase itself
    fails to unlock the keyring. Returns the unlocked master key on success.
    """
    raw_state = _read_raw_state(path)
    try:
        attempt_store.check_and_get_state(raw_state)
    except AttemptLockedOut as exc:
        raise KeyringAccessError(
            "unlock refused: too many recent failed attempts; retry in "
            f"{exc.retry_after_seconds:.0f} second(s)."
        ) from exc
    try:
        master_key = keyring.unlock_with_passphrase(passphrase)
    except Bsr2IntegrationError as exc:
        raw_state[attempt_store.ATTEMPT_STATE_FIELD] = attempt_store.record_failure(raw_state)
        _write_raw_state(path, raw_state)
        raise KeyringAccessError(f"unlock failed: {exc}") from exc
    raw_state[attempt_store.ATTEMPT_STATE_FIELD] = attempt_store.record_success(raw_state)
    _write_raw_state(path, raw_state)
    return master_key


__all__ = ["KeyringAccessError", "unlock_with_passphrase"]
