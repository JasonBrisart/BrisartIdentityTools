import json
import os
import secrets
from pathlib import Path

from config.settings import IDENTITY_DIR, TEMPLATE_DIR, ensure_data_dirs
from identity.identity_record import safe_identity_id


class IdentityStoreError(Exception):
    """Raised when local identity data cannot be stored or loaded."""


def identity_path(identity_id: str) -> Path:
    return IDENTITY_DIR / f"{safe_identity_id(identity_id)}.json"


def template_path(identity_id: str) -> Path:
    return TEMPLATE_DIR / f"{safe_identity_id(identity_id)}_template.json"


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
    save_json(template_path(identity_id), template)


def load_identity(identity_id: str) -> dict:
    path = identity_path(identity_id)
    if not path.is_file():
        raise FileNotFoundError(f"Identity record not found: {path}")
    return load_json(path)


def load_template(identity_id: str) -> dict:
    path = template_path(identity_id)
    if not path.is_file():
        raise FileNotFoundError(f"Template record not found: {path}")
    return load_json(path)


def list_identities() -> list[dict]:
    ensure_data_dirs()
    records: list[dict] = []
    for path in sorted(IDENTITY_DIR.glob("*.json")):
        records.append(load_json(path))
    return records
