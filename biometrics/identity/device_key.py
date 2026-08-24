"""Device binding: tying an enrolled identity to the machine that enrolled it.

The problem this solves: a stolen identity store (the JSON file on disk) should
not be usable on a different machine without also compromising something that
is not stored in the file itself. A device key is a value derived from
machine-specific material that is never written to disk in recoverable form --
only a keyed binding of it is stored, via :mod:`crypto.factors`. Verifying a
device later means recomputing the same derivation from the live machine and
checking it against the stored binding, not reading a device key back out of
the record.

Machine-specific material is deliberately weak on its own (a hostname is public,
a MAC address is often guessable). This module does not claim device binding is
a strong security boundary equivalent to the passphrase or recovery code -- it
is one more thing an attacker must also reproduce, not a replacement for the
keyring's own authentication.
"""
import platform
import socket
import uuid

from crypto.factors import bind_factor, verify_bound_factor

DEVICE_FACTOR_NAME = "device_binding"


class DeviceKeyError(ValueError):
    """Raised when device fingerprint material cannot be gathered or is invalid."""


def _safe(getter, default: str = "") -> str:
    try:
        value = getter()
    except Exception:
        return default
    if value is None:
        return default
    return str(value)


def current_device_fingerprint() -> str:
    """Collect a best-effort, machine-specific fingerprint string.

    Combines several weak, individually public signals (hostname, platform
    string, MAC address) so that reproducing all of them together is harder
    than reproducing any single one. Every field is gathered defensively:
    a platform that cannot report one of these (a stripped-down or unusual
    environment) still produces a fingerprint, just a less specific one,
    rather than raising and blocking enrollment entirely.
    """
    hostname = _safe(socket.gethostname)
    platform_string = _safe(platform.platform)
    machine = _safe(platform.machine)
    # uuid.getnode() returns a MAC address when available, or a random value
    # (marked by its multicast bit) when it is not. A random fallback still
    # contributes to the fingerprint's specificity for this run; it simply
    # cannot be reproduced across runs on the same machine, which is a known,
    # accepted limitation on such platforms.
    node = _safe(uuid.getnode)
    fingerprint = "|".join((hostname, platform_string, machine, node))
    if not fingerprint.strip("|"):
        raise DeviceKeyError(
            "unable to gather any device fingerprint material on this platform."
        )
    return fingerprint


def bind_device(master_key: bytes, fingerprint: str = None) -> str:
    """Produce a stored binding of a device fingerprint under the master key.

    ``fingerprint`` defaults to the current machine's fingerprint; a caller can
    pass an explicit value when re-binding to a previously recorded fingerprint
    (for example, during a migration that must not change the binding).
    """
    fingerprint = fingerprint if fingerprint is not None else current_device_fingerprint()
    return bind_factor(master_key, DEVICE_FACTOR_NAME, fingerprint)


def verify_device(master_key: bytes, bound_value: str, fingerprint: str = None) -> bool:
    """Check whether the current (or supplied) device matches a stored binding."""
    fingerprint = fingerprint if fingerprint is not None else current_device_fingerprint()
    return verify_bound_factor(master_key, DEVICE_FACTOR_NAME, fingerprint, bound_value)
