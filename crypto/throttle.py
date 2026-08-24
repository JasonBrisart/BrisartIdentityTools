"""Attempt limiting for unlock and verification paths.

BSR2's KDF makes each *offline* guess expensive. It does nothing about online
guessing against a running process: an attacker who can call unlock in a loop
still gets unlimited attempts, and the only cost is time they were going to spend
anyway. This adds exponential backoff and a lockout on top.

State is persisted by the caller rather than held in memory. An in-memory counter
resets when the process restarts, which an attacker controls for free by killing
the process between guesses.
"""
import math
import time

from crypto.errors import Bsr2IntegrationError

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BASE_DELAY_SECONDS = 1.0
DEFAULT_MAX_DELAY_SECONDS = 300.0
DEFAULT_LOCKOUT_SECONDS = 900.0


class AttemptLockedOut(Bsr2IntegrationError):
    """Raised when an attempt is refused and the caller must wait.

    Carries ``retry_after_seconds`` so a CLI can report a concrete wait rather
    than a bare refusal.
    """

    def __init__(self, message: str, retry_after_seconds: float):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class AttemptLimiter:
    """Exponential-backoff attempt limiter over caller-persisted state.

    State is JSON-serialisable so it can live inside a vault header or identity
    record. ``time_source`` is injectable for testing; production callers leave it
    at ``time.time``.
    """

    def __init__(
        self,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        base_delay_seconds: float = DEFAULT_BASE_DELAY_SECONDS,
        max_delay_seconds: float = DEFAULT_MAX_DELAY_SECONDS,
        lockout_seconds: float = DEFAULT_LOCKOUT_SECONDS,
        time_source=time.time,
    ):
        if max_attempts < 1:
            raise Bsr2IntegrationError("max_attempts must be at least 1.")
        if base_delay_seconds < 0 or max_delay_seconds < 0:
            raise Bsr2IntegrationError("delays cannot be negative.")
        if lockout_seconds < 0:
            raise Bsr2IntegrationError("lockout_seconds cannot be negative.")
        self.max_attempts = max_attempts
        self.base_delay_seconds = float(base_delay_seconds)
        self.max_delay_seconds = float(max_delay_seconds)
        self.lockout_seconds = float(lockout_seconds)
        self._time = time_source

    @staticmethod
    def new_state() -> dict:
        """Return fresh, JSON-serialisable limiter state."""
        return {
            "failed_attempts": 0,
            "last_failure_at": 0.0,
            "locked_until": 0.0,
        }

    def _normalize(self, state) -> dict:
        if state is None:
            return self.new_state()
        if not isinstance(state, dict):
            raise Bsr2IntegrationError("limiter state must be an object.")
        normalized = self.new_state()
        for field, default in normalized.items():
            value = state.get(field, default)
            # A corrupted or hostile field reads as "no credit earned" rather
            # than as permission to skip the limiter.
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                continue
            # NaN and +/-Infinity are floats and slip past a plain "< 0" guard.
            # A NaN locked_until makes "locked_until > now" false (silent bypass)
            # and int(NaN) later raises ValueError out of a function whose
            # contract is to raise AttemptLockedOut or return state. Treat a
            # non-finite field as corrupt, i.e. as no credit earned.
            if not math.isfinite(value):
                continue
            if value < 0:
                continue
            normalized[field] = value
        return normalized

    # Cap the exponent well past where the delay saturates at max_delay_seconds.
    # A persisted failed_attempts is attacker-influenced, and 2 ** (n - 1) is an
    # unbounded bignum computed before the min() clamp, so a huge stored count
    # would otherwise burn seconds building a number that is immediately thrown
    # away. 2 ** 64 seconds already dwarfs any real max_delay_seconds.
    _MAX_BACKOFF_EXPONENT = 64

    def _required_delay(self, failed_attempts: int) -> float:
        if failed_attempts < 1:
            return 0.0
        exponent = min(failed_attempts - 1, self._MAX_BACKOFF_EXPONENT)
        delay = self.base_delay_seconds * (2 ** exponent)
        return min(delay, self.max_delay_seconds)

    def check(self, state) -> dict:
        """Raise :class:`AttemptLockedOut` if an attempt is not allowed yet."""
        current = self._normalize(state)
        now = self._time()
        if current["locked_until"] > now:
            raise AttemptLockedOut(
                "too many failed attempts; locked out.",
                round(current["locked_until"] - now, 3),
            )
        required = self._required_delay(int(current["failed_attempts"]))
        if required > 0.0:
            elapsed = now - current["last_failure_at"]
            if elapsed < required:
                raise AttemptLockedOut(
                    "attempt rejected; backoff period has not elapsed.",
                    round(required - elapsed, 3),
                )
        return current

    def record_failure(self, state) -> dict:
        """Return updated state after a failed attempt."""
        current = self._normalize(state)
        now = self._time()
        current["failed_attempts"] = int(current["failed_attempts"]) + 1
        current["last_failure_at"] = now
        if current["failed_attempts"] >= self.max_attempts:
            current["locked_until"] = now + self.lockout_seconds
        return current

    def record_success(self, state) -> dict:
        """Return cleared state after a successful attempt."""
        self._normalize(state)
        return self.new_state()

    def status(self, state) -> dict:
        """Report limiter state without raising, for display purposes."""
        current = self._normalize(state)
        now = self._time()
        locked_for = max(0.0, current["locked_until"] - now)
        required = self._required_delay(int(current["failed_attempts"]))
        waiting_for = (
            max(0.0, required - (now - current["last_failure_at"]))
            if required
            else 0.0
        )
        return {
            "failed_attempts": int(current["failed_attempts"]),
            "max_attempts": self.max_attempts,
            "locked": locked_for > 0.0,
            "locked_for_seconds": round(locked_for, 3),
            "backoff_remaining_seconds": round(waiting_for, 3),
        }
