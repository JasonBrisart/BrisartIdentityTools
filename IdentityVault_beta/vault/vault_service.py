from pathlib import Path

from IdentityVault_beta.config.settings import (
    APP_NAME,
    APP_VERSION,
)
from IdentityVault_beta.core.time_tools import utc_now
from IdentityVault_beta.records.record_model import (
    build_plain_payload,
    build_record_shell,
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
        overwrite: bool = False,
    ) -> dict:
        path = Path(self.vault_path)

        if path.exists() and not overwrite:
            raise FileExistsError(
                f"vault already exists: {path}"
            )

        now = utc_now()

        data = {
            "app": APP_NAME,
            "app_version": APP_VERSION,
            "format_version": 1,
            "created_at": now,
            "updated_at": now,
            "storage_mode": "plaintext_json_beta",
            "records": {},
            "audit_log": [],
        }

        append_audit(
            data,
            "init_vault",
            {
                "vault_path": self.vault_path,
                "storage_mode": "plaintext_json_beta",
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
            "records",
            "audit_log",
        }

        missing_fields = required_fields.difference(data)

        if missing_fields:
            raise ValueError(
                "vault is missing required fields: "
                f"{sorted(missing_fields)}"
            )

        if data.get("app") != APP_NAME:
            raise ValueError(
                "file is not an IdentityVault vault."
            )

        if not isinstance(data.get("records"), dict):
            raise ValueError(
                "vault records must be an object."
            )

        if not isinstance(data.get("audit_log"), list):
            raise ValueError(
                "vault audit log must be a list."
            )

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

        return self._public_record(record)

    def add_record(
        self,
        kind: str,
        label: str,
        value: str,
        notes: str = "",
        metadata=None,
    ) -> dict:
        data = self.load()

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

        record["payload"] = payload
        record["storage_mode"] = "plaintext_json_beta"

        data["records"][record["record_id"]] = record

        append_audit(
            data,
            "add_record",
            {
                "record_id": record["record_id"],
                "kind": record["kind"],
                "label": record["label"],
                "storage_mode": "plaintext_json_beta",
            },
        )

        self.save(data)

        return self._public_record(record)

    def upsert_record(
        self,
        kind: str,
        label: str,
        value: str,
        notes: str = "",
        metadata=None,
    ) -> dict:
        results = self.upsert_records(
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
        items: list,
    ) -> list:
        if not isinstance(items, list) or not items:
            raise ValueError(
                "items must be a non-empty list."
            )

        data = self.load()
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

            record["payload"] = payload
            record["storage_mode"] = "plaintext_json_beta"

            data["records"][record["record_id"]] = record

            append_audit(
                data,
                action,
                {
                    "record_id": record["record_id"],
                    "kind": record["kind"],
                    "label": record["label"],
                    "storage_mode": "plaintext_json_beta",
                },
            )

            updated_records.append(
                self._public_record(record)
            )

        self.save(data)

        return updated_records

    def get_record(
        self,
        record_id: str,
    ) -> dict:
        data = self.load()

        record = data["records"].get(record_id)

        if record is None:
            raise KeyError(
                f"record not found: {record_id}"
            )

        payload = record.get("payload")

        if not isinstance(payload, dict):
            raise ValueError(
                "record payload is missing or invalid."
            )

        if payload.get("kind") != record["kind"]:
            raise ValueError(
                "record payload kind does not match "
                "the record shell."
            )

        if payload.get("label") != record["label"]:
            raise ValueError(
                "record payload label does not match "
                "the record shell."
            )

        return {
            "record_id": record["record_id"],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
            **payload,
        }

    def get_record_by_label(
        self,
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
        record_id: str,
    ) -> dict:
        data = self.load()

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

    def verify(self) -> dict:
        data = self.load()
        checked = 0
        failures = []

        for record in data["records"].values():
            try:
                payload = record.get("payload")

                if not isinstance(payload, dict):
                    raise ValueError(
                        "record payload is missing or invalid."
                    )

                if payload.get("kind") != record["kind"]:
                    raise ValueError(
                        "payload kind mismatch."
                    )

                if payload.get("label") != record["label"]:
                    raise ValueError(
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
            "storage_mode": "plaintext_json_beta",
        }

    def manifest(self) -> dict:
        data = self.load()

        return {
            "app": data.get("app"),
            "app_version": data.get("app_version"),
            "format_version": data.get("format_version"),
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at"),
            "storage_mode": data.get(
                "storage_mode",
                "plaintext_json_beta",
            ),
            "record_count": len(data["records"]),
            "records": self.list_records(),
        }

    @staticmethod
    def _public_record(record: dict) -> dict:
        return {
            "record_id": record["record_id"],
            "kind": record["kind"],
            "label": record["label"],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
            "storage_mode": record.get(
                "storage_mode",
                "plaintext_json_beta",
            ),
        }