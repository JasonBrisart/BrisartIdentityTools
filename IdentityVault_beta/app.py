import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    repository_root = Path(__file__).resolve().parent.parent
    repository_root_string = str(repository_root)

    if repository_root_string not in sys.path:
        sys.path.insert(0, repository_root_string)

from IdentityVault_beta.config.settings import (
    DEFAULT_VAULT_PATH,
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


def command_init(args) -> None:
    service = IdentityVaultService(args.vault)

    service.initialize(
        overwrite=args.overwrite,
    )

    print(f"Plaintext vault initialized: {args.vault}")


def command_add(args) -> None:
    service = IdentityVaultService(args.vault)

    value = args.value

    if value is None:
        raise ValueError(
            "plaintext mode requires --value."
        )

    record = service.add_record(
        kind=args.kind,
        label=args.label,
        value=value,
        notes=args.notes or "",
        metadata={
            "source": "identity_vault_cli",
            "storage_mode": "plaintext_json_beta",
        },
    )

    print("Record added.")
    print(f"Record ID: {record['record_id']}")
    print(f"Kind: {record['kind']}")
    print(f"Label: {record['label']}")


def command_get(args) -> None:
    service = IdentityVaultService(args.vault)

    payload = service.get_record(
        record_id=args.record_id,
    )

    print_json(payload)


def command_list(args) -> None:
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
    service = IdentityVaultService(args.vault)
    result = service.verify()
    print_json(result)


def command_manifest(args) -> None:
    service = IdentityVaultService(args.vault)
    print_json(service.manifest())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="app.py",
        description=(
            "IdentityVault beta dependency-free "
            "plaintext local identity record store"
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
        help="Initialize a new plaintext vault.",
    )
    init_parser.add_argument(
        "--overwrite",
        action="store_true",
    )
    init_parser.set_defaults(func=command_init)

    add_parser = subparsers.add_parser(
        "add",
        help="Add a plaintext record.",
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
    add_parser.set_defaults(func=command_add)

    get_parser = subparsers.add_parser(
        "get",
        help="Print a plaintext record.",
    )
    get_parser.add_argument("record_id")
    get_parser.set_defaults(func=command_get)

    list_parser = subparsers.add_parser(
        "list",
        help="List record metadata.",
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
        help="Verify plaintext vault structure.",
    )
    verify_parser.set_defaults(func=command_verify)

    manifest_parser = subparsers.add_parser(
        "manifest",
        help="Export a vault manifest.",
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