import json
import os
import secrets
from pathlib import Path


class VaultFileError(Exception):
    """Raised when a vault file cannot be loaded or saved."""


def load_vault_file(path: str) -> dict:
    vault_path = Path(path)

    if not vault_path.exists():
        raise FileNotFoundError(
            f"vault file not found: {vault_path}"
        )

    if not vault_path.is_file():
        raise VaultFileError(
            f"vault path is not a file: {vault_path}"
        )

    try:
        text = vault_path.read_text(encoding="utf-8")
        data = json.loads(text)
    except UnicodeDecodeError as exc:
        raise VaultFileError(
            f"vault file is not valid UTF-8: {vault_path}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise VaultFileError(
            f"vault file contains invalid JSON: {vault_path}"
        ) from exc
    except OSError as exc:
        raise VaultFileError(
            f"unable to read vault file: {vault_path}"
        ) from exc

    if not isinstance(data, dict):
        raise VaultFileError(
            "vault file must contain a JSON object."
        )

    return data


def _flush_directory(directory: Path) -> None:
    if os.name == "nt":
        return

    directory_descriptor = None

    try:
        directory_descriptor = os.open(
            str(directory),
            os.O_RDONLY,
        )
        os.fsync(directory_descriptor)
    except OSError:
        pass
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def save_vault_file(
    path: str,
    data: dict,
) -> None:
    if not isinstance(data, dict):
        raise VaultFileError(
            "vault data must be a JSON object."
        )

    vault_path = Path(path)
    vault_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    serialized = json.dumps(
        data,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )

    temporary_name = (
        f".{vault_path.name}."
        f"{secrets.token_hex(8)}.tmp"
    )
    temporary_path = vault_path.parent / temporary_name

    try:
        with temporary_path.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(
            temporary_path,
            vault_path,
        )

        _flush_directory(vault_path.parent)

    except OSError as exc:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass

        raise VaultFileError(
            f"unable to save vault file: {vault_path}"
        ) from exc