"""Tests for crypto.throttle.AttemptLimiter, including the corrupt-state
hardening from 0.8.0-beta (non-finite fields, and the backoff exponent cap
that stops a huge persisted failed_attempts from building a giant integer)."""
import math
import unittest
from crypto.errors import Bsr2IntegrationError
from crypto.throttle import AttemptLimiter, AttemptLockedOut


class _Clock:
    def __init__(self, now=1000.0):
        self.now = now
    def __call__(self):
        return self.now


class AttemptLimiterBasicTests(unittest.TestCase):
    def setUp(self):
        self.clock = _Clock()
        self.limiter = AttemptLimiter(max_attempts=3, base_delay_seconds=1.0,
                                      max_delay_seconds=100.0, lockout_seconds=60.0,
                                      time_source=self.clock)

    def test_fresh_state_allows_an_attempt(self):
        self.assertEqual(self.limiter.check(None)["failed_attempts"], 0)

    def test_first_failure_records_one_attempt(self):
        state = self.limiter.record_failure(self.limiter.new_state())
        self.assertEqual(state["failed_attempts"], 1)

    def test_reaching_max_attempts_triggers_lockout(self):
        state = self.limiter.new_state()
        for _ in range(3):
            state = self.limiter.record_failure(state)
        with self.assertRaises(AttemptLockedOut):
            self.limiter.check(state)

    def test_success_clears_state(self):
        state = self.limiter.record_failure(self.limiter.new_state())
        cleared = self.limiter.record_success(state)
        self.assertEqual(cleared["failed_attempts"], 0)

    def test_backoff_rejects_a_too_soon_retry(self):
        state = self.limiter.record_failure(self.limiter.new_state())
        state = self.limiter.record_failure(state)  # 2 failures -> 2s backoff
        with self.assertRaises(AttemptLockedOut):
            self.limiter.check(state)

    def test_backoff_allows_retry_after_enough_time(self):
        state = self.limiter.record_failure(self.limiter.new_state())
        state = self.limiter.record_failure(state)
        self.clock.now += 1000.0
        self.assertIsNotNone(self.limiter.check(state))


class AttemptLimiterCorruptStateTests(unittest.TestCase):
    def setUp(self):
        self.clock = _Clock()
        self.limiter = AttemptLimiter(time_source=self.clock)

    def test_nan_locked_until_does_not_silently_unlock(self):
        # A NaN locked_until previously made "locked_until > now" False (silent
        # bypass). It must be discarded and read as fresh state instead.
        state = {"failed_attempts": 0, "last_failure_at": 0.0, "locked_until": float("nan")}
        normalized = self.limiter.check(state)
        self.assertEqual(normalized["locked_until"], 0.0)

    def test_nan_failed_attempts_does_not_crash(self):
        state = {"failed_attempts": float("nan"), "last_failure_at": 0.0, "locked_until": 0.0}
        # Must not raise ValueError out of int(nan); reads as fresh instead.
        self.assertEqual(self.limiter.check(state)["failed_attempts"], 0)

    def test_infinity_fields_are_discarded(self):
        state = {"failed_attempts": float("inf"), "last_failure_at": float("inf"),
                 "locked_until": float("inf")}
        normalized = self.limiter.check(state)
        self.assertTrue(math.isfinite(normalized["locked_until"]))

    def test_negative_fields_are_discarded(self):
        state = {"failed_attempts": -5, "last_failure_at": -1.0, "locked_until": -1.0}
        self.assertEqual(self.limiter.check(state)["failed_attempts"], 0)

    def test_boolean_fields_are_ignored(self):
        state = {"failed_attempts": True, "last_failure_at": 0.0, "locked_until": 0.0}
        self.assertEqual(self.limiter.check(state)["failed_attempts"], 0)

    def test_non_dict_state_is_rejected(self):
        with self.assertRaises(Bsr2IntegrationError):
            self.limiter.check(["not", "a", "dict"])

    def test_astronomical_failed_attempts_does_not_hang(self):
        # Before the exponent cap, 2 ** (10**9 - 1) built a multi-gigabit int.
        # With the cap the call must return promptly and stay bounded.
        limiter = AttemptLimiter(base_delay_seconds=1.0, max_delay_seconds=300.0,
                                 lockout_seconds=0.0, time_source=self.clock, max_attempts=1)
        delay = limiter._required_delay(10 ** 9)
        self.assertLessEqual(delay, 300.0)


class AttemptLimiterConstructionTests(unittest.TestCase):
    def test_rejects_zero_max_attempts(self):
        with self.assertRaises(Bsr2IntegrationError):
            AttemptLimiter(max_attempts=0)

    def test_rejects_negative_delay(self):
        with self.assertRaises(Bsr2IntegrationError):
            AttemptLimiter(base_delay_seconds=-1.0)


if __name__ == "__main__":
    unittest.main()
