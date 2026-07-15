import json
from pathlib import Path

from config.settings import APP_NAME, APP_VERSION, PBKDF2_ITERATIONS
from core.crypto import (
    decrypt_payload,
    derive_master_key,
    encrypt_payload,
    password_check_value,
    random_salt,
    verify_password_check,
)
from core.encoding import b64d, b64e
from core.time_tools import utc_now
from records.record_model import (
    build_plain_payload,
    build_record_shell,
    payload_from_bytes,
    payload_to_bytes,
    validate_kind,
)
from reports.audit_log import append_audit
from vault.vault_file import load_vault_file, save_vault_file


class IdentityVaultService:
    def __init__(self, vault_path: str):
        self.vault_path = str(vault_path)

    def init_vault(self, password: str, overwrite: bool = False) -> dict:
        path = Path(self.vault_path)
        if path.exists() and not overwrite:
            raise FileExistsError(f"vault already exists: {path}")
        salt = random_salt()
        master_key = derive_master_key(password, salt)
        data = {
            "app": APP_NAME,
            "app_version": APP_VERSION,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "kdf": {
                "name": "pbkdf2_hmac",
                "hash": "sha256",
                "iterations": PBKDF2_ITERATIONS,
                "salt": b64e(salt),
            },
            "password_check": password_check_value(master_key),
            "records": {},
            "audit_log": [],
        }
        append_audit(data, "init_vault", {"vault_path": self.vault_path})
        save_vault_file(self.vault_path, data)
        return data

    def load(self) -> dict:
        return load_vault_file(self.vault_path)

    def save(self, data: dict) -> None:
        data["updated_at"] = utc_now()
        save_vault_file(self.vault_path, data)

    def master_key(self, data: dict, password: str) -> bytes:
        kdf = data["kdf"]
        salt = b64d(kdf["salt"])
        iterations = int(kdf["iterations"])
        master_key = derive_master_key(password, salt, iterations)
        if not verify_password_check(master_key, data["password_check"]):
            raise PermissionError("wrong password or invalid vault.")
        return master_key

    def add_record(self, password: str, kind: str, label: str, value: str, notes: str = "", metadata=None) -> dict:
        data = self.load()
        master_key = self.master_key(data, password)
        kind = validate_kind(kind)
        record = build_record_shell(kind, label)
        payload = build_plain_payload(kind, label, value, notes, metadata)
        encrypted = encrypt_payload(
            master_key=master_key,
            record_id=record["record_id"],
            kind=record["kind"],
            label=record["label"],
            plaintext=payload_to_bytes(payload),
        )
        record["encrypted"] = encrypted
        data["records"][record["record_id"]] = record
        append_audit(data, "add_record", {"record_id": record["record_id"], "kind": kind, "label": label})
        self.save(data)
        return record

    def get_record(self, password: str, record_id: str) -> dict:
        data = self.load()
        master_key = self.master_key(data, password)
        record = data["records"].get(record_id)
        if not record:
            raise KeyError(f"record not found: {record_id}")
        plaintext = decrypt_payload(master_key, record["record_id"], record["kind"], record["label"], record["encrypted"])
        return payload_from_bytes(plaintext)

    def list_records(self) -> list:
        data = self.load()
        records = []
        for record in data.get("records", {}).values():
            records.append({
                "record_id": record["record_id"],
                "kind": record["kind"],
                "label": record["label"],
                "created_at": record["created_at"],
                "updated_at": record["updated_at"],
            })
        return sorted(records, key=lambda item: (item["kind"], item["label"]))

    def delete_record(self, password: str, record_id: str) -> dict:
        data = self.load()
        self.master_key(data, password)
        record = data["records"].pop(record_id, None)
        if not record:
            raise KeyError(f"record not found: {record_id}")
        append_audit(data, "delete_record", {"record_id": record_id, "kind": record["kind"], "label": record["label"]})
        self.save(data)
        return record

    def verify_integrity(self, password: str) -> dict:
        data = self.load()
        master_key = self.master_key(data, password)
        checked = 0
        failures = []
        for record in data.get("records", {}).values():
            try:
                decrypt_payload(master_key, record["record_id"], record["kind"], record["label"], record["encrypted"])
                checked += 1
            except Exception as exc:
                failures.append({"record_id": record.get("record_id"), "error": str(exc)})
        return {
            "vault_path": self.vault_path,
            "checked_records": checked,
            "failed_records": failures,
            "result": "OK" if not failures else "FAILED",
        }

    def manifest(self) -> dict:
        data = self.load()
        return {
            "app": data.get("app"),
            "app_version": data.get("app_version"),
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at"),
            "record_count": len(data.get("records", {})),
            "records": self.list_records(),
        }

    def change_password(self, old_password: str, new_password: str) -> dict:
        data = self.load()
        old_master = self.master_key(data, old_password)
        plaintext_payloads = {}
        for record_id, record in data.get("records", {}).items():
            plaintext_payloads[record_id] = decrypt_payload(old_master, record["record_id"], record["kind"], record["label"], record["encrypted"])

        new_salt = random_salt()
        new_master = derive_master_key(new_password, new_salt)
        data["kdf"]["salt"] = b64e(new_salt)
        data["password_check"] = password_check_value(new_master)

        for record_id, plaintext in plaintext_payloads.items():
            record = data["records"][record_id]
            record["encrypted"] = encrypt_payload(new_master, record["record_id"], record["kind"], record["label"], plaintext)
            record["updated_at"] = utc_now()

        append_audit(data, "change_password", {"record_count": len(plaintext_payloads)})
        self.save(data)
        return {"result": "OK", "record_count": len(plaintext_payloads)}
