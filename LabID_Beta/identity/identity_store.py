import json
from pathlib import Path

from config.settings import IDENTITY_DIR, TEMPLATE_DIR, ensure_data_dirs
from identity.identity_record import safe_identity_id


def identity_path(identity_id: str) -> Path:
    return IDENTITY_DIR / f"{safe_identity_id(identity_id)}.json"


def template_path(identity_id: str) -> Path:
    return TEMPLATE_DIR / f"{safe_identity_id(identity_id)}_template.json"


def save_json(path: Path, data: dict) -> None:
    ensure_data_dirs()
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save_identity(identity_id: str, record: dict) -> None:
    save_json(identity_path(identity_id), record)


def save_template(identity_id: str, template: dict) -> None:
    save_json(template_path(identity_id), template)


def load_identity(identity_id: str) -> dict:
    path = identity_path(identity_id)
    if not path.exists():
        raise FileNotFoundError(f"Identity record not found: {path}")
    return load_json(path)


def load_template(identity_id: str) -> dict:
    path = template_path(identity_id)
    if not path.exists():
        raise FileNotFoundError(f"Template record not found: {path}")
    return load_json(path)


def list_identities():
    ensure_data_dirs()
    records = []
    for path in sorted(IDENTITY_DIR.glob("*.json")):
        try:
            records.append(load_json(path))
        except Exception:
            continue
    return records
