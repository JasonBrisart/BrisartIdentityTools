"""Local storage for LabID identity records and biometric templates.

Biometric templates are sealed with BSR2 before they touch disk. A template is
derived feature data, not a raw sample, but it is still biometric material about
a person and it is what a match is computed against, so it does not belong in
cleartext on disk.

Identity records (id, display name, modality, timestamps) stay readable so
``list`` and ``inspect`` work without touching the device key. See
``identity/device_key.py`` for what the device key does and does not protect.
"""

import functools
import json
import os
import secrets
import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from brisart_bsr2 import rng  # noqa: E402
from brisart_bsr2.context import template_context  # noqa: E402
from brisart_bsr2.envelope import is_envelope, open_json, seal_json  # noqa: E402
from brisart_bsr2.errors import Bsr2IntegrationError  # noqa: E402
from config import settings  # noqa: E402
from config.settings import ensure_data_dirs  # noqa: E402
from identity.device_key import load_device_key  # noqa: E402
from identity.identity_record import safe_identity_id  # noqa: E402

TEMPLATE_FILE_FORMAT = "brisart-identity-tools/labid-template/v2"


@functools.lru_cache(maxsize=1)
def _generator():
    """Return a DRBG shared across seals in this process.

    Cached rather than rebuilt per seal: constructing a generator draws fresh
    operating-system entropy, and ``ManagedGenerator`` already reseeds itself
    before its own lifecycle limits, so one instance per process is both
    cheaper and correct.
    """
    return rng.new_generator("labid-template")


class IdentityStoreError(Exception):
    """Raised when local identity data cannot be stored or loaded."""


# Directories are read from the settings module on every call rather than
# imported once into this namespace. Binding them at import time froze the
# storage location at first import, so it could not be reconfigured (or pointed
# at a temporary directory by a test) after that.
def identity_path(identity_id: str) -> Path:
    return settings.IDENTITY_DIR / f"{safe_identity_id(identity_id)}.json"


def template_path(identity_id: str) -> Path:
    return (
        settings.TEMPLATE_DIR
        / f"{safe_identity_id(identity_id)}_template.json"
    )


def _flush_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    descriptor = None
    try:
        descriptor = os.open(str(directory), os.O_RDONLY)
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)


def save_json(path: Path, data: dict) -> None:
    if not isinstance(data, dict):
        raise IdentityStoreError("Stored JSON data must be an object.")

    ensure_data_dirs()
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(
        data,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )
    temporary_path = path.parent / (
        f".{path.name}.{secrets.token_hex(8)}.tmp"
    )

    try:
        with temporary_path.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        _flush_directory(path.parent)
    except OSError as exc:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise IdentityStoreError(f"Unable to save JSON file: {path}") from exc


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdentityStoreError(f"Unable to load JSON file: {path}") from exc
    if not isinstance(data, dict):
        raise IdentityStoreError(f"JSON file must contain an object: {path}")
    return data


def save_identity(identity_id: str, record: dict) -> None:
    save_json(identity_path(identity_id), record)


def save_template(identity_id: str, template: dict) -> None:
    """Seal a biometric template and write it to disk.

    The envelope is bound to the identity id and modality, so a sealed template
    cannot be moved to another identity or presented in a different modality's
    slot: both produce an authentication failure rather than a match.
    """
    if not isinstance(template, dict):
        raise IdentityStoreError("Template must be an object.")

    modality = template.get("modality")
    if not isinstance(modality, str) or not modality:
        raise IdentityStoreError(
            "Template must carry a modality; it binds the encryption context."
        )

    try:
        envelope = seal_json(
            load_device_key(),
            template,
            template_context(identity_id, modality),
            _generator(),
        )
    except Bsr2IntegrationError as exc:
        raise IdentityStoreError(
            f"Unable to seal template for {identity_id}: {exc}"
        ) from exc

    save_json(
        template_path(identity_id),
        {
            "format": TEMPLATE_FILE_FORMAT,
            "identity_id": identity_id,
            "modality": modality,
            "sealed_template": envelope,
        },
    )


def identity_exists(identity_id: str) -> bool:
    return identity_path(identity_id).is_file()


def load_identity(identity_id: str) -> dict:
    path = identity_path(identity_id)
    if not path.is_file():
        raise FileNotFoundError(f"Identity record not found: {path}")
    return load_json(path)


def load_template(identity_id: str) -> dict:
    """Load and unseal a biometric template.

    Pre-BSR2 plaintext templates still load, so an existing data directory keeps
    working. They are re-sealed on the next write.
    """
    path = template_path(identity_id)
    if not path.is_file():
        raise FileNotFoundError(f"Template record not found: {path}")

    stored = load_json(path)

    if stored.get("format") != TEMPLATE_FILE_FORMAT:
        # Legacy plaintext template. Readable, but flagged so callers can tell
        # the difference between a protected template and an exposed one.
        stored["storage_protection"] = "unprotected_legacy_plaintext"
        return stored

    envelope = stored.get("sealed_template")
    if not is_envelope(envelope):
        raise IdentityStoreError(
            f"Template file is missing its sealed payload: {path}"
        )

    modality = stored.get("modality")
    if not isinstance(modality, str) or not modality:
        raise IdentityStoreError(f"Template file has no modality: {path}")

    try:
        template = open_json(
            load_device_key(create_if_missing=False),
            envelope,
            template_context(identity_id, modality),
        )
    except Bsr2IntegrationError as exc:
        raise IdentityStoreError(
            f"Unable to open template for {identity_id}: {exc}. "
            "The template may have been tampered with, moved from another "
            "identity, or sealed under a different device key."
        ) from exc

    return template


def list_identities() -> list:
    ensure_data_dirs()
    records = []
    for path in sorted(settings.IDENTITY_DIR.glob("*.json")):
        records.append(load_json(path))
    return records
