import argparse
import getpass
import json
import os
import sys
from pathlib import Path

if __package__ in (None, ""):
    repository_root = Path(__file__).resolve().parent.parent
    repository_root_string = str(repository_root)

    if repository_root_string not in sys.path:
        sys.path.insert(0, repository_root_string)

from IdentityVault_beta.config.settings import (
    DEFAULT_VAULT_PATH,
    SEALED_STORAGE_MODE,
    SUPPORTED_RECORD_KINDS,
)
from IdentityVault_beta.vault.vault_service import (
    IdentityVaultService,
)


def print_json(data) -> None:
    print(
        json.dumps(
            data,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
    )


def _read_passphrase(confirm: bool = False) -> str:
    """Read a passphrase without echoing it.

    ``IDENTITY_VAULT_PASSPHRASE`` is honoured for non-interactive use. That is
    convenient for scripting and worse for secrecy: environment variables are
    visible to other processes of the same user and often land in shell history
    and CI logs. Prefer the prompt when a terminal is available.
    """
    from_environment = os.environ.get("IDENTITY_VAULT_PASSPHRASE")

    if from_environment:
        return from_environment

    passphrase = getpass.getpass("Vault passphrase: ")

    if not passphrase:
        raise ValueError("passphrase cannot be empty.")

    if confirm and getpass.getpass("Confirm passphrase: ") != passphrase:
        raise ValueError("passphrases did not match.")

    return passphrase


def _unlocked_service(args) -> IdentityVaultService:
    service = IdentityVaultService(args.vault)

    print(
        "Unlocking with BSR2. This takes about a minute.",
        file=sys.stderr,
    )

    if getattr(args, "recovery_code", None):
        service.unlock_with_recovery_code(args.recovery_code)
    else:
        service.unlock(_read_passphrase())

    return service


def command_init(args) -> None:
    service = IdentityVaultService(args.vault)

    passphrase = _read_passphrase(confirm=True)

    print(
        "Deriving keys with BSR2. This takes a few minutes.",
        file=sys.stderr,
    )

    _, recovery_code = service.initialize(
        passphrase=passphrase,
        overwrite=args.overwrite,
    )

    print(f"Encrypted vault initialized: {args.vault}")
    print(f"Storage mode: {SEALED_STORAGE_MODE}")
    print("\nRECOVERY CODE (write this down, it is shown only once):")
    print(f"  {recovery_code}")
    print(
        "\nWithout the passphrase or this recovery code, the vault cannot be "
        "opened by anyone, including you. There is no reset."
    )


def command_add(args) -> None:
    service = _unlocked_service(args)

    value = args.value

    if value is None:
        raise ValueError(
            "--value is required."
        )

    record = service.add_record(
        kind=args.kind,
        label=args.label,
        value=value,
        notes=args.notes or "",
        metadata={
            "source": "identity_vault_cli",
            "storage_mode": SEALED_STORAGE_MODE,
        },
    )

    print("Record added.")
    print(f"Record ID: {record['record_id']}")
    print(f"Kind: {record['kind']}")
    print(f"Label: {record['label']}")


def command_get(args) -> None:
    service = _unlocked_service(args)

    payload = service.get_record(
        record_id=args.record_id,
    )

    print_json(payload)


def command_list(args) -> None:
    # Record shells are not encrypted, so listing does not require a passphrase.
    service = IdentityVaultService(args.vault)

    records = service.list_records()

    if not records:
        print("No records found.")
        return

    for record in records:
        print(
            f"{record['record_id']} | "
            f"{record['kind']} | "
            f"{record['label']} | "
            f"{record['updated_at']} | "
            f"{record.get('storage_mode')}"
        )


def command_delete(args) -> None:
    service = IdentityVaultService(args.vault)

    record = service.delete_record(
        record_id=args.record_id,
    )

    print("Record deleted.")
    print(f"Record ID: {record['record_id']}")


def command_verify(args) -> None:
    service = _unlocked_service(args)
    result = service.verify()
    print_json(result)


def command_manifest(args) -> None:
    # Manifest reports shell metadata only.
    service = IdentityVaultService(args.vault)
    print_json(service.manifest())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="app.py",
        description=(
            "IdentityVault: dependency-free local identity record store, "
            "encrypted at rest with BSR2"
        ),
    )

    parser.add_argument(
        "--vault",
        default=str(DEFAULT_VAULT_PATH),
        help="Path to vault JSON file.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    init_parser = subparsers.add_parser(
        "init",
        help="Initialize a new encrypted vault.",
    )
    init_parser.add_argument(
        "--overwrite",
        action="store_true",
    )
    init_parser.set_defaults(func=command_init)

    add_parser = subparsers.add_parser(
        "add",
        help="Add an encrypted record.",
    )
    add_parser.add_argument(
        "--kind",
        choices=sorted(SUPPORTED_RECORD_KINDS),
        default="general",
    )
    add_parser.add_argument(
        "--label",
        required=True,
    )
    add_parser.add_argument(
        "--value",
        required=True,
    )
    add_parser.add_argument(
        "--notes",
        default="",
    )
    add_parser.add_argument(
        "--recovery-code",
        dest="recovery_code",
        help="Unlock with the recovery code instead of the passphrase.",
    )
    add_parser.set_defaults(func=command_add)

    get_parser = subparsers.add_parser(
        "get",
        help="Decrypt and print a record.",
    )
    get_parser.add_argument("record_id")
    get_parser.add_argument(
        "--recovery-code",
        dest="recovery_code",
        help="Unlock with the recovery code instead of the passphrase.",
    )
    get_parser.set_defaults(func=command_get)

    list_parser = subparsers.add_parser(
        "list",
        help="List record metadata (no passphrase required).",
    )
    list_parser.set_defaults(func=command_list)

    delete_parser = subparsers.add_parser(
        "delete",
        help="Delete a record.",
    )
    delete_parser.add_argument("record_id")
    delete_parser.set_defaults(func=command_delete)

    verify_parser = subparsers.add_parser(
        "verify",
        help="Decrypt every record and verify vault integrity.",
    )
    verify_parser.add_argument(
        "--recovery-code",
        dest="recovery_code",
        help="Unlock with the recovery code instead of the passphrase.",
    )
    verify_parser.set_defaults(func=command_verify)

    manifest_parser = subparsers.add_parser(
        "manifest",
        help="Export a vault manifest (no passphrase required).",
    )
    manifest_parser.set_defaults(func=command_manifest)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        args.func(args)
    except KeyboardInterrupt:
        print(
            "\nOperation cancelled.",
            file=sys.stderr,
        )
        raise SystemExit(130)
    except Exception as exc:
        print(
            f"Error: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
