import argparse
import getpass
import json

from config.settings import DEFAULT_VAULT_PATH, SUPPORTED_RECORD_KINDS
from vault.vault_service import IdentityVaultService


def read_password(args, prompt: str = "Vault password: ") -> str:
    if getattr(args, "password", None):
        return args.password
    return getpass.getpass(prompt)


def print_json(data) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def command_init(args) -> None:
    password = read_password(args)
    service = IdentityVaultService(args.vault)
    service.init_vault(password=password, overwrite=args.overwrite)
    print(f"Vault initialized: {args.vault}")


def command_add(args) -> None:
    password = read_password(args)
    service = IdentityVaultService(args.vault)
    value = args.value
    if value is None:
        value = getpass.getpass("Record value: ")
    record = service.add_record(
        password=password,
        kind=args.kind,
        label=args.label,
        value=value,
        notes=args.notes or "",
        metadata={"source": "cli"},
    )
    print("Record added.")
    print(f"Record ID: {record['record_id']}")
    print(f"Kind: {record['kind']}")
    print(f"Label: {record['label']}")


def command_get(args) -> None:
    password = read_password(args)
    service = IdentityVaultService(args.vault)
    payload = service.get_record(password=password, record_id=args.record_id)
    print_json(payload)


def command_list(args) -> None:
    service = IdentityVaultService(args.vault)
    records = service.list_records()
    if not records:
        print("No records found.")
        return
    for record in records:
        print(f"{record['record_id']} | {record['kind']} | {record['label']} | {record['updated_at']}")


def command_delete(args) -> None:
    password = read_password(args)
    service = IdentityVaultService(args.vault)
    record = service.delete_record(password=password, record_id=args.record_id)
    print("Record deleted.")
    print(f"Record ID: {record['record_id']}")


def command_verify(args) -> None:
    password = read_password(args)
    service = IdentityVaultService(args.vault)
    print_json(service.verify_integrity(password=password))


def command_manifest(args) -> None:
    service = IdentityVaultService(args.vault)
    print_json(service.manifest())


def command_change_password(args) -> None:
    old_password = read_password(args, "Old vault password: ")
    if args.new_password:
        new_password = args.new_password
    else:
        new_password = getpass.getpass("New vault password: ")
        confirm = getpass.getpass("Repeat new vault password: ")
        if new_password != confirm:
            raise ValueError("new passwords do not match.")
    service = IdentityVaultService(args.vault)
    print_json(service.change_password(old_password=old_password, new_password=new_password))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="app.py",
        description="IdentityVault beta - dependency-free encrypted local identity vault",
    )
    parser.add_argument("--vault", default=str(DEFAULT_VAULT_PATH), help="Path to vault JSON file.")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Initialize a new vault.")
    init.add_argument("--password", default=None)
    init.add_argument("--overwrite", action="store_true")
    init.set_defaults(func=command_init)

    add = sub.add_parser("add", help="Add an encrypted record.")
    add.add_argument("--password", default=None)
    add.add_argument("--kind", choices=sorted(SUPPORTED_RECORD_KINDS), default="general")
    add.add_argument("--label", required=True)
    add.add_argument("--value", default=None)
    add.add_argument("--notes", default="")
    add.set_defaults(func=command_add)

    get = sub.add_parser("get", help="Decrypt and print a record.")
    get.add_argument("record_id")
    get.add_argument("--password", default=None)
    get.set_defaults(func=command_get)

    list_cmd = sub.add_parser("list", help="List non-secret record metadata.")
    list_cmd.set_defaults(func=command_list)

    delete = sub.add_parser("delete", help="Delete a record.")
    delete.add_argument("record_id")
    delete.add_argument("--password", default=None)
    delete.set_defaults(func=command_delete)

    verify = sub.add_parser("verify", help="Verify vault password and record authentication tags.")
    verify.add_argument("--password", default=None)
    verify.set_defaults(func=command_verify)

    manifest = sub.add_parser("manifest", help="Export non-secret vault manifest.")
    manifest.set_defaults(func=command_manifest)

    change = sub.add_parser("change-password", help="Re-encrypt the vault with a new password.")
    change.add_argument("--password", default=None, help="Old password.")
    change.add_argument("--new-password", default=None)
    change.set_defaults(func=command_change_password)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
