import json
from pathlib import Path


def load_vault_file(path: str) -> dict:
    vault_path = Path(path)
    if not vault_path.exists():
        raise FileNotFoundError(f"vault file not found: {vault_path}")
    return json.loads(vault_path.read_text(encoding="utf-8"))


def save_vault_file(path: str, data: dict) -> None:
    vault_path = Path(path)
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    vault_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
