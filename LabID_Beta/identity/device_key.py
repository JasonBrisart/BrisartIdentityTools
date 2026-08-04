"""Device-key management for LabID biometric templates at rest.

Why LabID uses a device key instead of a passphrase
---------------------------------------------------
IdentityVault and identity-bound packages protect secrets that a *person*
chooses to release, so a passphrase is the right gate: the human is present at
unlock time and can pay BSR2's deliberately slow key derivation once per
session.

LabID is not that. It is an unattended local verification service: enroll a
biometric sample, later verify another sample against it. Nobody is standing
there to type a passphrase, and BSR2's ``derive_password_key`` costs roughly a
minute and a half per call, so a passphrase gate would make each CLI invocation
unusable.

So templates are sealed under a random 32-byte device key held in a local
key file. Be clear about what that does and does not buy:

**Protects against**

* casual disclosure of template contents: a template file copied off the
  machine, pulled out of a backup, recovered from a stale disk image, or
  attached to a bug report is BSR2 ciphertext, not biometric feature data
* silent tampering: an attacker who edits a sealed template to weaken a match
  gets an authentication failure, not a forged pass
* cross-identity substitution: every template is bound to its identity id and
  modality, so template files cannot be swapped between identities or between
  a face and a fingerprint slot

**Does not protect against**

* an attacker who can read the key file. The key sits next to the data it
  protects, so anyone with filesystem access to the LabID data directory can
  decrypt every template. That is inherent to unattended operation and is not
  a defect to be fixed by moving the file somewhere cleverer.

If you need templates protected from someone with local filesystem access, put
the data directory on an encrypted volume, or use OS file permissions to
restrict it to the service account. This module deliberately does not pretend
to solve that problem in software.

The key file is created with mode 0600 and the loader warns if the mode has
been widened.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from brisart_bsr2 import rng  # noqa: E402
from brisart_bsr2.errors import Bsr2IntegrationError  # noqa: E402
from brisart_bsr2.keyring import MASTER_KEY_BYTES  # noqa: E402
from brisart_bsr2.vendor import (  # noqa: E402
    BrisartPrimitiveError,
    hex_decode,
    hex_encode,
)
from config import settings  # noqa: E402

KEY_FILE_FORMAT = "brisart-identity-tools/labid-device-key/v1"

KEY_FILE_NAME = "device_key.json"

_OWNER_ONLY = 0o600

# Additional input for the DRBG call. Not secret, just a domain separator.
_GENERATE_LABEL = b"BrisartIdentityTools/labid-device-key/v1"


class DeviceKeyError(Bsr2IntegrationError):
    """Raised when the LabID device key cannot be created, read, or trusted."""


def key_path() -> Path:
    """Return the device key path.

    Read from ``settings`` on every call so a test can redirect the data
    directory after import.
    """
    return settings.DATA_DIR / KEY_FILE_NAME


def _write_key_file(path: Path, key: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    state = {
        "format": KEY_FILE_FORMAT,
        "device_key": hex_encode(key),
        "note": (
            "This key decrypts every biometric template in this directory. "
            "It is stored beside the data it protects because LabID runs "
            "unattended. Treat the whole data directory as sensitive."
        ),
    }

    serialized = json.dumps(state, indent=2, sort_keys=True)

    # Create with owner-only permissions from the start, rather than creating
    # then chmod-ing, so the key is never briefly world-readable on disk.
    descriptor = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        _OWNER_ONLY,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise DeviceKeyError(f"unable to write device key: {path}") from exc


def create_device_key() -> bytes:
    """Generate and persist a new device key. Refuses to overwrite an existing one.

    Overwriting would silently orphan every template sealed under the old key,
    so that has to be an explicit delete by the operator.
    """
    path = key_path()
    if path.exists():
        raise DeviceKeyError(
            f"device key already exists: {path}. Delete it deliberately if you "
            "intend to discard access to every existing template."
        )

    generator = rng.new_generator("labid-device-key")
    try:
        key = generator.generate(MASTER_KEY_BYTES, _GENERATE_LABEL)
    finally:
        # Zero the DRBG state; the key is now the only thing that matters.
        generator.destroy()

    _write_key_file(path, key)
    return key


def _check_permissions(path: Path) -> None:
    if os.name == "nt":
        return

    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return

    if mode & 0o077:
        print(
            f"WARNING: {path} is readable beyond its owner (mode {mode:04o}). "
            "Anyone who can read it can decrypt every template. "
            f"Run: chmod 600 {path}",
            file=sys.stderr,
        )


def load_device_key(create_if_missing: bool = True) -> bytes:
    """Return the device key, creating one on first use when allowed."""
    path = key_path()

    if not path.exists():
        if not create_if_missing:
            raise DeviceKeyError(f"device key not found: {path}")
        return create_device_key()

    _check_permissions(path)

    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeviceKeyError(f"unable to read device key: {path}") from exc

    if not isinstance(state, dict):
        raise DeviceKeyError(f"device key file must contain an object: {path}")

    if state.get("format") != KEY_FILE_FORMAT:
        raise DeviceKeyError(
            f"unsupported device key format: {state.get('format')!r}"
        )

    try:
        encoded = state["device_key"]
    except KeyError as exc:
        raise DeviceKeyError("device key file has no device_key field.") from exc

    if not isinstance(encoded, str):
        raise DeviceKeyError("device_key must be hexadecimal text.")

    try:
        key = hex_decode(encoded)
    except BrisartPrimitiveError as exc:
        raise DeviceKeyError("device key is not valid hexadecimal.") from exc

    if len(key) != MASTER_KEY_BYTES:
        raise DeviceKeyError(
            f"device key must be {MASTER_KEY_BYTES} bytes, got {len(key)}."
        )

    return key
