from pathlib import Path
from typing import Optional

from brisart_bsr2 import envelope as _envelope
from brisart_bsr2.context import record_context
from brisart_bsr2.errors import Bsr2IntegrationError
from brisart_bsr2.keyring import MASTER_KEY_BYTES, Keyring
from brisart_bsr2.rng import new_generator

from IdentityVault_beta.config.settings import (
    APP_NAME,
    APP_VERSION,
    FORMAT_VERSION,
    PLAINTEXT_STORAGE_MODE,
    SEALED_STORAGE_MODE,
)
from IdentityVault_beta.core.time_tools import utc_now
from IdentityVault_beta.core.ids import safe_label
from IdentityVault_beta.records.record_model import (
    build_plain_payload,
    build_record_shell,
    validate_kind,
    validate_value,
    payload_from_bytes,
    payload_to_bytes,
)
from IdentityVault_beta.reports.audit_log import append_audit
from IdentityVault_beta.vault.vault_file import (
    load_vault_file,
    save_vault_file,
)


class VaultLockedError(Exception):
    """Raised when an operation needs a master key the service does not hold."""


class IdentityVaultService:
    """Vault operations over a BSR2-sealed vault file.

    Record *payloads* are encrypted. Record shells stay readable: ``record_id``,
    ``kind``, ``label``, and timestamps are stored in the clear so records can be
    listed, searched, and deduplicated without unlocking the vault. That is a
    deliberate trade -- the vault leaks that a credential labelled
    ``bank-login`` exists while protecting its value. Hiding labels too would
    require decrypting every record for any lookup, and would make the vault
    unusable at the CLI.

    The master key is held in memory only after :meth:`unlock`, and only for the
    lifetime of the service object.
    """

    def __init__(self, vault_path: str, master_key: Optional[bytes] = None):
        self.vault_path = str(vault_path)
        self._master_key = None
        if master_key is not None:
            self.adopt_master_key(master_key)

    # ------------------------------------------------------------------ locking
    def adopt_master_key(self, master_key: bytes) -> None:
        """Attach an already-unwrapped master key, skipping the slow derivation."""
        if (
            not isinstance(master_key, (bytes, bytearray))
            or len(master_key) != MASTER_KEY_BYTES
        ):
            raise Bsr2IntegrationError(
                f"master key must be {MASTER_KEY_BYTES} bytes."
            )
        self._master_key = bytes(master_key)

    def unlock(self, passphrase: str) -> None:
        """Unlock with the vault passphrase.

        Slow by design: BSR2's passphrase derivation takes on the order of a
        minute. Unlock once and reuse the service instance.
        """
        data = load_vault_file(self.vault_path)
        keyring_state = data.get("keyring")
        if not isinstance(keyring_state, dict):
            raise Bsr2IntegrationError(
                "vault has no keyring; it predates BSR2 and must be migrated."
            )
        self._master_key = Keyring(keyring_state).unlock_with_passphrase(
            passphrase
        )

    def unlock_with_recovery_code(self, recovery_code: str) -> None:
        """Unlock with the offline recovery code issued at initialize()."""
        data = load_vault_file(self.vault_path)
        keyring_state = data.get("keyring")
        if not isinstance(keyring_state, dict):
            raise Bsr2IntegrationError(
                "vault has no keyring; it predates BSR2 and must be migrated."
            )
        self._master_key = Keyring(keyring_state).unlock_with_recovery_code(
            recovery_code
        )

    def lock(self) -> None:
        self._master_key = None

    @property
    def is_unlocked(self) -> bool:
        return self._master_key is not None

    @property
    def master_key(self) -> bytes:
        if self._master_key is None:
            raise VaultLockedError(
                "vault is locked; call unlock() before reading or writing "
                "record values."
            )
        return self._master_key

    # --------------------------------------------------------------- initialize
    def initialize(
        self,
        passphrase: Optional[str] = None,
        overwrite: bool = False,
        master_key: Optional[bytes] = None,
    ):
        """Create a new sealed vault.

        Returns ``(data, recovery_code)``. The recovery code is displayed once
        and is not recoverable from the vault file; losing both it and the
        passphrase makes every record permanently unreadable. That is the
        intended property of an offline encrypted store, but it is worth saying
        out loud before a user commits data to it.

        ``master_key`` creates a vault with **no keyring**, sealed directly under
        a caller-supplied key. It exists so tests and known-answer vectors do not
        pay for a passphrase derivation that takes minutes. Such a vault cannot be
        unlocked by passphrase, only by re-supplying the same key, and
        ``recovery_code`` is ``None``. Do not use it for a vault holding real
        data: the key has to live somewhere, and if that somewhere is a script
        next to the vault file the encryption achieves nothing.
        """
        path = Path(self.vault_path)
        if path.exists() and not overwrite:
            raise FileExistsError(
                f"vault already exists: {path}"
            )
        if master_key is not None:
            if passphrase is not None:
                raise Bsr2IntegrationError(
                    "pass either a passphrase or a master_key, not both."
                )
            self.adopt_master_key(master_key)
            keyring_state = None
            recovery_code = None
        else:
            if not isinstance(passphrase, str) or not passphrase:
                raise Bsr2IntegrationError(
                    "a passphrase is required to initialize a sealed vault."
                )
            keyring, recovery_code = Keyring.create(passphrase)
            self._master_key = keyring.master_key
            keyring_state = keyring.to_state()
        now = utc_now()
        data = {
            "app": APP_NAME,
            "app_version": APP_VERSION,
            "format_version": FORMAT_VERSION,
            "created_at": now,
            "updated_at": now,
            "storage_mode": SEALED_STORAGE_MODE,
            "records": {},
            "audit_log": [],
        }
        if keyring_state is not None:
            data["keyring"] = keyring_state
        append_audit(
            data,
            "init_vault",
            {
                "vault_path": self.vault_path,
                "storage_mode": SEALED_STORAGE_MODE,
            },
        )
        save_vault_file(
            self.vault_path,
            data,
        )
        return data, recovery_code

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

    # ------------------------------------------------------------ seal / unseal
    def _seal_payload(self, record: dict, payload: dict) -> dict:
        context = record_context(
            record["record_id"], record["kind"], record["label"]
        )
        return _envelope.seal_bytes(
            self.master_key,
            payload_to_bytes(payload),
            context,
            new_generator("vault-record"),
        )

    def _open_payload(self, record: dict) -> dict:
        """Return a record's payload, sealed or legacy plaintext."""
        sealed = record.get("sealed_payload")
        if sealed is not None:
            context = record_context(
                record["record_id"], record["kind"], record["label"]
            )
            plaintext = _envelope.open_bytes(
                self.master_key, sealed, context
            )
            return payload_from_bytes(plaintext)
        legacy = record.get("payload")
        if isinstance(legacy, dict):
            # Pre-BSR2 record. Readable so an upgrade does not strand data.
            return legacy
        raise ValueError("record payload is missing or invalid.")

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
        # Stored labels were normalized by safe_label(), which also collapses
        # internal whitespace. Normalizing the query the same way is what makes
        # duplicate detection and label lookups actually match.
        selected_label = safe_label(label)
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
        record["sealed_payload"] = self._seal_payload(record, payload)
        record["storage_mode"] = SEALED_STORAGE_MODE
        data["records"][record["record_id"]] = record
        append_audit(
            data,
            "add_record",
            {
                "record_id": record["record_id"],
                "kind": record["kind"],
                "label": record["label"],
                "storage_mode": SEALED_STORAGE_MODE,
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
        # Validate every item up front. Without this pass, an invalid item at
        # position N raises after items 0..N-1 have already been mutated into
        # `data`, and because save() never runs the caller loses that work with
        # no indication of how far the batch got. The value type is validated
        # here too, so a non-string value is rejected before any mutation rather
        # than raising from inside build_plain_payload in the second loop.
        prepared_items = []
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(
                    "each record item must be an object."
                )
            for required_field in ("kind", "label", "value"):
                if required_field not in item:
                    raise ValueError(
                        "each record item requires "
                        f"'{required_field}'."
                    )
            prepared_items.append(
                {
                    "kind": validate_kind(item["kind"]),
                    "label": safe_label(item["label"]),
                    "value": validate_value(item["value"]),
                    "notes": item.get("notes", ""),
                    "metadata": item.get("metadata"),
                }
            )
        for item in prepared_items:
            selected_kind = item["kind"]
            selected_label = item["label"]
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
                notes=item["notes"],
                metadata=item["metadata"],
            )
            record["sealed_payload"] = self._seal_payload(record, payload)
            record["storage_mode"] = SEALED_STORAGE_MODE
            # An updated pre-BSR2 record is re-sealed, so the old cleartext
            # payload must not be left behind next to the new envelope.
            record.pop("payload", None)
            data["records"][record["record_id"]] = record
            append_audit(
                data,
                action,
                {
                    "record_id": record["record_id"],
                    "kind": record["kind"],
                    "label": record["label"],
                    "storage_mode": SEALED_STORAGE_MODE,
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
        payload = self._open_payload(record)
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
        unprotected = []
        for record in data["records"].values():
            try:
                if record.get("sealed_payload") is None:
                    unprotected.append(record.get("record_id"))
                payload = self._open_payload(record)
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
            "unprotected_records": unprotected,
            "result": "OK" if not failures else "FAILED",
            "storage_mode": data.get(
                "storage_mode",
                PLAINTEXT_STORAGE_MODE,
            ),
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
                PLAINTEXT_STORAGE_MODE,
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
                PLAINTEXT_STORAGE_MODE,
           