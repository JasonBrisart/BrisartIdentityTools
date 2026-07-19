import hashlib
import json
import secrets
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
REPOSITORY_ROOT_STRING = str(REPOSITORY_ROOT)

if REPOSITORY_ROOT_STRING not in sys.path:
    sys.path.insert(0, REPOSITORY_ROOT_STRING)


from IdentityVault_beta.vault.vault_service import (
    IdentityVaultService,
)


IDENTITY_LABEL_PREFIX = "labid:identity:"
TEMPLATE_LABEL_PREFIX = "labid:template:"


class VaultBridgeError(Exception):
    """Raised when LabID cannot communicate with IdentityVault."""


def identity_label(identity_id: str) -> str:
    return f"{IDENTITY_LABEL_PREFIX}{identity_id}"


def template_label(identity_id: str) -> str:
    return f"{TEMPLATE_LABEL_PREFIX}{identity_id}"


def vault_identity_uri(identity_id: str) -> str:
    return f"vault://identity/{identity_id}"


def vault_template_uri(identity_id: str) -> str:
    return f"vault://biometric-template/{identity_id}"


def new_enrollment_id() -> str:
    return f"enroll_{secrets.token_hex(16)}"


def encode_json(data: dict) -> str:
    if not isinstance(data, dict):
        raise VaultBridgeError(
            "vault bridge data must be an object."
        )

    return json.dumps(
        data,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )


def decode_json(value: str) -> dict:
    try:
        data = json.loads(value)
    except json.JSONDecodeError as exc:
        raise VaultBridgeError(
            "encrypted LabID record contains invalid JSON."
        ) from exc

    if not isinstance(data, dict):
        raise VaultBridgeError(
            "encrypted LabID record must contain an object."
        )

    return data


def template_feature_hash(template: dict) -> str:
    try:
        features = template["features"]
    except KeyError as exc:
        raise VaultBridgeError(
            "template does not contain features."
        ) from exc

    serialized = json.dumps(
        features,
        sort_keys=True,
    ).encode("utf-8")

    return hashlib.sha256(serialized).hexdigest()


def verify_template_integrity(template: dict) -> bool:
    expected = template.get("template_sha256")

    if not isinstance(expected, str) or not expected:
        return False

    try:
        calculated = template_feature_hash(template)
    except VaultBridgeError:
        return False

    return secrets.compare_digest(
        calculated,
        expected,
    )


def store_enrollment(
    vault_path: str,
    password: str,
    identity: dict,
    template: dict,
) -> dict:
    identity_id = identity.get("identity_id")

    if not isinstance(identity_id, str) or not identity_id:
        raise VaultBridgeError(
            "identity record is missing identity_id."
        )

    if not verify_template_integrity(template):
        raise VaultBridgeError(
            "template integrity validation failed "
            "before vault storage."
        )

    enrollment_id = identity.get("enrollment_id")

    if not enrollment_id:
        enrollment_id = new_enrollment_id()
        identity["enrollment_id"] = enrollment_id
        template["enrollment_id"] = enrollment_id

    service = IdentityVaultService(vault_path)

    records = service.upsert_records(
        password=password,
        items=[
            {
                "kind": "identity",
                "label": identity_label(identity_id),
                "value": encode_json(identity),
                "notes": (
                    "Encrypted LabID identity enrollment record."
                ),
                "metadata": {
                    "source": "LabID_Beta",
                    "identity_id": identity_id,
                    "enrollment_id": enrollment_id,
                    "record_role": "identity",
                },
            },
            {
                "kind": "biometric_template",
                "label": template_label(identity_id),
                "value": encode_json(template),
                "notes": (
                    "Encrypted LabID biometric template record."
                ),
                "metadata": {
                    "source": "LabID_Beta",
                    "identity_id": identity_id,
                    "enrollment_id": enrollment_id,
                    "record_role": "biometric_template",
                },
            },
        ],
    )

    return {
        "identity_record": records[0],
        "template_record": records[1],
        "enrollment_id": enrollment_id,
    }


def load_enrollment(
    vault_path: str,
    password: str,
    identity_id: str,
) -> dict:
    service = IdentityVaultService(vault_path)

    encrypted_identity = service.get_record_by_label(
        password=password,
        kind="identity",
        label=identity_label(identity_id),
    )

    encrypted_template = service.get_record_by_label(
        password=password,
        kind="biometric_template",
        label=template_label(identity_id),
    )

    identity = decode_json(
        encrypted_identity["value"]
    )
    template = decode_json(
        encrypted_template["value"]
    )

    if identity.get("identity_id") != identity_id:
        raise VaultBridgeError(
            "vault identity ID does not match "
            "the requested identity."
        )

    identity_enrollment_id = identity.get(
        "enrollment_id"
    )
    template_enrollment_id = template.get(
        "enrollment_id"
    )

    if (
        not identity_enrollment_id
        or identity_enrollment_id
        != template_enrollment_id
    ):
        raise VaultBridgeError(
            "identity and template enrollment IDs "
            "do not match."
        )

    return {
        "identity": identity,
        "template": template,
    }
