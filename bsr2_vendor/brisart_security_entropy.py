"""Fresh operating-system entropy for BSR2 envelope diversification.

The custom BSR2 DRBG is deterministic. This module adds an independent,
non-deterministic input at each encryption so a recreated DRBG state does not,
by itself, recreate the envelope salt and nonce.

This module uses only the Python standard library, but the entropy is supplied
by the operating system through secrets.token_bytes. It is intentionally not a
custom entropy source.
"""

from __future__ import annotations

import secrets
import threading


class BrisartEntropyError(RuntimeError):
    """Raised when fresh operating-system entropy cannot be obtained safely."""


_LOCK = threading.Lock()
_PREVIOUS_SAMPLE: bytes | None = None


def system_entropy(length: int) -> bytes:
    """Return fresh operating-system entropy and perform basic health checks.

    The duplicate-sample check is only a catastrophic-failure detector. It is
    not an entropy estimate and does not validate the operating-system source.
    """

    if type(length) is not int or length <= 0:
        raise BrisartEntropyError("entropy length must be a positive integer")

    try:
        sample = secrets.token_bytes(length)
    except Exception as exc:
        raise BrisartEntropyError(
            "operating-system entropy request failed"
        ) from exc

    if not isinstance(sample, bytes) or len(sample) != length:
        raise BrisartEntropyError(
            "operating-system entropy returned an invalid result"
        )
    if not any(sample):
        raise BrisartEntropyError(
            "operating-system entropy returned an all-zero sample"
        )

    global _PREVIOUS_SAMPLE
    with _LOCK:
        if _PREVIOUS_SAMPLE == sample:
            _PREVIOUS_SAMPLE = None
            raise BrisartEntropyError(
                "operating-system entropy repeated the previous sample"
            )
        _PREVIOUS_SAMPLE = sample

    return sample
