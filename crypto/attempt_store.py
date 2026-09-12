"""
File: crypto/attempt_store.py
Purpose:
    Shared persistence adapter between crypto.throttle.AttemptLimiter (pure
    in-memory backoff/lockout math) and the on-disk JSON containers that
    actually hold unlock state for this ecosystem: vault.json (vault/store/
    vault_file.py) and the biometrics keyring.json (biometrics/identity/
    keyring_access.py). AttemptLimiter itself has no opinion about where its
    state lives -- its own docstring says state is "caller-persisted, not
    held in memory" -- and until this module existed, no caller in this
    repository actually persisted it anywhere. This module is that missing
    wiring: a thin adapter that reads/writes a single well-known field
    (ATTEMPT_STATE_FIELD) on whatever JSON-shaped dict a caller already has
    open, so every unlock path in the ecosystem stores its throttle state
    the same way instead of each inventing its own container shape.

Communication relationships:
    Called by:
        - vault.store.vault_service.VaultService.unlock() and
          .unlock_with_recovery_code(), which pass the whole in-memory
          vault-file state dict (the same dict vault.store.vault_file.
          load_state()/save_state() already read and write) as `container`.
          Both unlock methods share the SAME attempt counter regardless of
          which credential (passphrase or recovery code) was attempted, so
          an attacker cannot reset their attempt budget by switching
          between the two credential types.
        - biometrics.identity.keyring_access.unlock_with_passphrase(), which
          passes the raw keyring.json dict as `container`.
    Calls out to:
        - crypto.throttle.AttemptLimiter for all backoff/lockout math and
          state normalization. This module performs no arithmetic of its
          own; it only reads/writes ATTEMPT_STATE_FIELD on the caller's
          dict and delegates everything else.
    Does not persist anything itself:
        - This module never opens a file. The caller is responsible for
          reading `container` from disk before calling into this module and
          writing it back out afterward (typically via
          common.atomic_io.atomic_write_json), exactly as vault_service.py
          and keyring_access.py already do for every other field in the
          same containers.

Parameters / settings:
    ATTEMPT_STATE_FIELD (str, "unlock_attempts"):
        The dict key this module reads and writes on `container`. Chosen to
        sit as a plain sibling field alongside a vault file's existing
        "format"/"keyring"/"records" keys, or a keyring.json's existing
        "format"/"kdf"/"passphrase"/"recovery"/"master_key_check" keys.
        Neither vault.store.vault_file.load_state() nor
        crypto.keyring.Keyring's own state validation rejects unrecognized
        extra keys, so this field survives every existing load/save round
        trip unmodified when a caller does not touch it, and gets carried
        forward correctly when a caller does.
    limiter (crypto.throttle.AttemptLimiter, optional, per-call):
        Every function below accepts an optional `limiter` override,
        defaulting to a single module-level AttemptLimiter() built with
        crypto.throttle's own defaults (5 attempts, 1s base backoff
        doubling up to a 300s cap, 900s/15-minute lockout after the 5th
        failure). Production call sites (vault_service.py,
        keyring_access.py) never pass this override and simply get the
        shared default instance, which holds no per-call state itself
        (crypto.throttle.AttemptLimiter is stateless between calls; all
        state lives in `container`, not in the limiter object) -- so
        sharing one module-level instance across every call in the process
        is safe and avoids reconstructing an AttemptLimiter on every unlock
        attempt. Tests inject a distinct AttemptLimiter (e.g. a lower
        max_attempts, or a fake time_source) to exercise lockout behavior
        without waiting on real wall-clock delays.

Edge-case behavior:
    - A `container` with no ATTEMPT_STATE_FIELD at all (a vault or keyring
      file created before this module existed, or a fresh one) is treated
      as fresh, unthrottled state -- container.get(ATTEMPT_STATE_FIELD)
      returns None, and AttemptLimiter.check()/record_failure()/
      record_success() all already treat a None state as
      AttemptLimiter.new_state() per crypto/throttle.py's own contract. No
      migration step is required for existing vault/keyring files.
    - This module never raises on its own account. check_and_get_state()
      re-raises crypto.throttle.AttemptLockedOut exactly as
      AttemptLimiter.check() raises it (a Bsr2IntegrationError subclass);
      both current call sites catch AttemptLockedOut specifically so they
      can surface exc.retry_after_seconds to the user.
    - record_failure()/record_success() never raise; they only compute and
      return the next state dict. Writing that returned dict back into
      `container[ATTEMPT_STATE_FIELD]` and persisting `container` to disk
      is always the caller's next step, immediately after calling either
      function -- this module does not do it automatically, since the
      caller's container may need other fields updated in the same write
      (e.g. vault_service.py also records an audit-log entry around the
      same save_state() call).
"""
from crypto.throttle import AttemptLimiter

ATTEMPT_STATE_FIELD = "unlock_attempts"

_DEFAULT_LIMITER = AttemptLimiter()


def check_and_get_state(container: dict, limiter: AttemptLimiter = None) -> dict:
    """Raise AttemptLockedOut if an unlock attempt is not allowed yet.

    Returns the normalized attempt state on success (mirroring
    AttemptLimiter.check()'s own return value); callers are not required to
    use the return value, since record_failure()/record_success() each
    re-normalize the state themselves.
    """
    active_limiter = limiter or _DEFAULT_LIMITER
    return active_limiter.check(container.get(ATTEMPT_STATE_FIELD))


def record_failure(container: dict, limiter: AttemptLimiter = None) -> dict:
    """Return updated attempt state after a failed unlock attempt.

    Does not mutate or persist `container`; the caller assigns the return
    value to container[ATTEMPT_STATE_FIELD] and saves `container` itself.
    """
    active_limiter = limiter or _DEFAULT_LIMITER
    return active_limiter.record_failure(container.get(ATTEMPT_STATE_FIELD))


def record_success(container: dict, limiter: AttemptLimiter = None) -> dict:
    """Return cleared attempt state after a successful unlock attempt."""
    active_limiter = limiter or _DEFAULT_LIMITER
    return active_limiter.record_success(container.get(ATTEMPT_STATE_FIELD))


def status(container: dict, limiter: AttemptLimiter = None) -> dict:
    """Report attempt state without raising, for display purposes."""
    active_limiter = limiter or _DEFAULT_LIMITER
    return active_limiter.status(container.get(ATTEMPT_STATE_FIELD))


__all__ = [
    "ATTEMPT_STATE_FIELD",
    "check_and_get_state",
    "record_failure",
    "record_success",
    "status",
]
