from pathlib import Path

from IdentityVault_beta.config.settings import (
    APP_NAME,
    APP_VERSION,
    PBKDF2_ALGORITHM,
    PBKDF2_ITERATIONS,
)
from IdentityVault_beta.core.crypto import (
    VaultCryptoError,
    decrypt_payload,
    derive_master_key,
    encrypt_payload,
    password_check_value,
    random_salt,
    verify_password_check,
)
from IdentityVault_beta.core.encoding import b64d, b64e
from IdentityVault_beta.core.time_tools import utc_now
from IdentityVault_beta.records.record_model import (
    build_plain_payload,
    build_record_shell,
    payload_from_bytes,
    payload_to_bytes,
    validate_kind,
)
from IdentityVault_beta.reports.audit_log import append_audit
from IdentityVault_beta.vault.vault_file import (
    load_vault_file,
    save_vault_file,
)


class IdentityVaultService:
    def __init__(self, vault_path: str):
        self.vault_path = str(vault_path)

    def initialize(
        self,
        password: str,
        overwrite: bool = False,
    ) -> dict:
        path = Path(self.vault_path)

        if path.exists() and not overwrite:
            raise FileExistsError(
                f"vault already exists: {path}"
            )

        salt = random_salt()
        master_key = derive_master_key(
            password=password,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )

        now = utc_now()

        data = {
            "app": APP_NAME,
            "app_version": APP_VERSION,
            "format_version": 1,
            "created_at": now,
            "updated_at": now,
            "kdf": {
                "name": "pbkdf2_hmac",
                "hash": PBKDF2_ALGORITHM,
                "iterations": PBKDF2_ITERATIONS,
                "salt": b64e(salt),
            },
            "password_check": password_check_value(master_key),
            "records": {},
            "audit_log": [],
        }

        append_audit(
            data,
            "init_vault",
            {
                "vault_path": self.vault_path,
            },
        )

        save_vault_file(
            self.vault_path,
            data,
        )

        return data

    def load(self) -> dict:
        data = load_vault_file(self.vault_path)
        self._validate_structure(data)
        return data

    def save(self, data: dict) -> None:
        self._validate_structure(data)
        data["updated_at"] = utc_now()
        data["app_version"] = APP_VERSION

        save_vault_file(
            self.vault_path,
            data,
        )

    def _validate_structure(self, data: dict) -> None:
        required_fields = {
            "app",
            "created_at",
            "updated_at",
            "kdf",
            "password_check",
            "records",
            "audit_log",
        }

        missing_fields = required_fields.difference(data)

        if missing_fields:
            raise ValueError(
                f"vault is missing required fields: "
                f"{sorted(missing_fields)}"
            )

        if data.get("app") != APP_NAME:
            raise ValueError(
                "file is not an IdentityVault vault."
            )

        if not isinstance(data.get("kdf"), dict):
            raise ValueError("vault kdf must be an object.")

        if not isinstance(data.get("records"), dict):
            raise ValueError("vault records must be an object.")

        if not isinstance(data.get("audit_log"), list):
            raise ValueError("vault audit log must be a list.")

    def master_key(
        self,
        data: dict,
        password: str,
    ) -> bytes:
        self._validate_structure(data)

        kdf = data["kdf"]

        if kdf.get("name") != "pbkdf2_hmac":
            raise VaultCryptoError(
                f"unsupported KDF: {kdf.get('name')}"
            )

        if kdf.get("hash") != PBKDF2_ALGORITHM:
            raise VaultCryptoError(
                f"unsupported KDF hash: {kdf.get('hash')}"
            )

        try:
            salt = b64d(kdf["salt"])
            iterations = int(kdf["iterations"])
        except (KeyError, TypeError, ValueError) as exc:
            raise VaultCryptoError(
                "vault contains invalid KDF settings."
            ) from exc

        master_key = derive_master_key(
            password=password,
            salt=salt,
            iterations=iterations,
        )

        if not verify_password_check(
            master_key,
            data["password_check"],
        ):
            raise PermissionError(
                "wrong password or invalid vault."
            )

        return master_key

    def _find_record_in_data(
        self,
        data: dict,
        kind: str,
        label: str,
    ):
        selected_kind = validate_kind(kind)
        selected_label = label.strip()

        for record in data["records"].values():
            if (
                record.get("kind") == selected_kind
                and record.get("label") == selected_label
            ):
                return record

        return None

    def find_record(
        self,
        kind: str,
        label: str,
    ):
        data = self.load()
        record = self._find_record_in_data(
            data=data,
            kind=kind,
            label=label,
        )

        if record is None:
            return None

        return {
            "record_id": record["record_id"],
            "kind": record["kind"],
            "label": record["label"],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
        }

    def add_record(
        self,
        password: str,
        kind: str,
        label: str,
        value: str,
        notes: str = "",
        metadata=None,
    ) -> dict:
        data = self.load()
        master_key = self.master_key(
            data=data,
            password=password,
        )

        selected_kind = validate_kind(kind)

        existing = self._find_record_in_data(
            data=data,
            kind=selected_kind,
            label=label,
        )

        if existing is not None:
            raise FileExistsError(
                f"record already exists for kind={selected_kind} "
                f"and label={label}"
            )

        record = build_record_shell(
            kind=selected_kind,
            label=label,
        )

        payload = build_plain_payload(
            kind=selected_kind,
            label=record["label"],
            value=value,
            notes=notes,
            metadata=metadata,
        )

        record["encrypted"] = encrypt_payload(
            master_key=master_key,
            record_id=record["record_id"],
            kind=record["kind"],
            label=record["label"],
            plaintext=payload_to_bytes(payload),
        )

        data["records"][record["record_id"]] = record

        append_audit(
            data,
            "add_record",
            {
                "record_id": record["record_id"],
                "kind": record["kind"],
                "label": record["label"],
            },
        )

        self.save(data)

        return self._public_record(record)

    def upsert_record(
        self,
        password: str,
        kind: str,
        label: str,
        value: str,
        notes: str = "",
        metadata=None,
    ) -> dict:
        results = self.upsert_records(
            password=password,
            items=[
                {
                    "kind": kind,
                    "label": label,
                    "value": value,
                    "notes": notes,
                    "metadata": metadata or {},
                }
            ],
        )

        return results[0]

    def upsert_records(
        self,
        password: str,
        items: list,
    ) -> list:
        if not isinstance(items, list) or not items:
            raise ValueError(
                "items must be a non-empty list."
            )

        data = self.load()
        master_key = self.master_key(
            data=data,
            password=password,
        )

        updated_records = []

        for item in items:
            if not isinstance(item, dict):
                raise ValueError(
                    "each record item must be an object."
                )

            selected_kind = validate_kind(item["kind"])
            selected_label = item["label"].strip()

            existing = self._find_record_in_data(
                data=data,
                kind=selected_kind,
                label=selected_label,
            )

            now = utc_now()

            if existing is None:
                record = build_record_shell(
                    kind=selected_kind,
                    label=selected_label,
                )
                action = "add_record"
            else:
                record = existing
                record["updated_at"] = now
                action = "update_record"

            payload = build_plain_payload(
                kind=selected_kind,
                label=record["label"],
                value=item["value"],
                notes=item.get("notes", ""),
                metadata=item.get("metadata"),
            )

            record["encrypted"] = encrypt_payload(
                master_key=master_key,
                record_id=record["record_id"],
                kind=record["kind"],
                label=record["label"],
                plaintext=payload_to_bytes(payload),
            )

            data["records"][record["record_id"]] = record

            append_audit(
                data,
                action,
                {
                    "record_id": record["record_id"],
                    "kind": record["kind"],
                    "label": record["label"],
                },
            )

            updated_records.append(
                self._public_record(record)
            )

        self.save(data)

        return updated_records

    def get_record(
        self,
        password: str,
        record_id: str,
    ) -> dict:
        data = self.load()
        master_key = self.master_key(
            data=data,
            password=password,
        )

        record = data["records"].get(record_id)

        if record is None:
            raise KeyError(
                f"record not found: {record_id}"
            )

        plaintext = decrypt_payload(
            master_key=master_key,
            record_id=record["record_id"],
            kind=record["kind"],
            label=record["label"],
            encrypted=record["encrypted"],
        )

        payload = payload_from_bytes(plaintext)

        if payload.get("kind") != record["kind"]:
            raise VaultCryptoError(
                "decrypted record kind does not match "
                "the record envelope."
            )

        if payload.get("label") != record["label"]:
            raise VaultCryptoError(
                "decrypted record label does not match "
                "the record envelope."
            )

        return {
            "record_id": record["record_id"],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
            **payload,
        }

    def get_record_by_label(
        self,
        password: str,
        kind: str,
        label: str,
    ) -> dict:
        record = self.find_record(
            kind=kind,
            label=label,
        )

        if record is None:
            raise KeyError(
                f"record not found for kind={kind} "
                f"and label={label}"
            )

        return self.get_record(
            password=password,
            record_id=record["record_id"],
        )

    def list_records(self) -> list:
        data = self.load()

        records = [
            self._public_record(record)
            for record in data["records"].values()
        ]

        return sorted(
            records,
            key=lambda item: (
                item["kind"],
                item["label"],
                item["record_id"],
            ),
        )

    def delete_record(
        self,
        password: str,
        record_id: str,
    ) -> dict:
        data = self.load()

        self.master_key(
            data=data,
            password=password,
        )

        record = data["records"].pop(
            record_id,
            None,
        )

        if record is None:
            raise KeyError(
                f"record not found: {record_id}"
            )

        append_audit(
            data,
            "delete_record",
            {
                "record_id": record_id,
                "kind": record["kind"],
                "label": record["label"],
            },
        )

        self.save(data)

        return self._public_record(record)

    def verify(
        self,
        password: str,
    ) -> dict:
        data = self.load()
        master_key = self.master_key(
            data=data,
            password=password,
        )

        checked = 0
        failures = []

        for record in data["records"].values():
            try:
                plaintext = decrypt_payload(
                    master_key=master_key,
                    record_id=record["record_id"],
                    kind=record["kind"],
                    label=record["label"],
                    encrypted=record["encrypted"],
                )

                payload = payload_from_bytes(plaintext)

                if payload.get("kind") != record["kind"]:
                    raise VaultCryptoError(
                        "payload kind mismatch."
                    )

                if payload.get("label") != record["label"]:
                    raise VaultCryptoError(
                        "payload label mismatch."
                    )

                checked += 1

            except Exception as exc:
                failures.append(
                    {
                        "record_id": record.get("record_id"),
                        "error": str(exc),
                    }
                )

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
            "format_version": data.get("format_version"),
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at"),
            "record_count": len(data["records"]),
            "records": self.list_records(),
        }

    def change_password(
        self,
        old_password: str,
        new_password: str,
    ) -> dict:
        if not new_password:
            raise ValueError(
                "new password cannot be empty."
            )

        data = self.load()
        old_master_key = self.master_key(
            data=data,
            password=old_password,
        )

        plaintext_payloads = {}

        for record_id, record in data["records"].items():
            plaintext_payloads[record_id] = decrypt_payload(
                master_key=old_master_key,
                record_id=record["record_id"],
                kind=record["kind"],
                label=record["label"],
                encrypted=record["encrypted"],
            )

        new_salt = random_salt()
        new_master_key = derive_master_key(
            password=new_password,
            salt=new_salt,
            iterations=PBKDF2_ITERATIONS,
        )

        data["kdf"] = {
            "name": "pbkdf2_hmac",
            "hash": PBKDF2_ALGORITHM,
            "iterations": PBKDF2_ITERATIONS,
            "salt": b64e(new_salt),
        }
        data["password_check"] = password_check_value(
            new_master_key
        )

        for record_id, plaintext in plaintext_payloads.items():
            record = data["records"][record_id]

            record["encrypted"] = encrypt_payload(
                master_key=new_master_key,
                record_id=record["record_id"],
                kind=record["kind"],
                label=record["label"],
                plaintext=plaintext,
            )
            record["updated_at"] = utc_now()

        append_audit(
            data,
            "change_password",
            {
                "record_count": len(plaintext_payloads),
            },
        )

        self.save(data)

        return {
            "result": "OK",
            "record_count": len(plaintext_payloads),
        }

    @staticmethod
    def _public_record(record: dict) -> dict:
        return {
            "record_id": record["record_id"],
            "kind": record["kind"],
            "label": record["label"],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
        }
