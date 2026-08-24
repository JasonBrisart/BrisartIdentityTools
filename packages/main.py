"""Identity-Bound Packages command-line interface.

Since a package requires an existing recipient's master key to authorize
adding or removing another recipient (see ``package.add_recipient`` /
``package.remove_recipient``), this CLI works against a local JSON file per
package and prompts for whichever master keys an operation needs. A "demo"
command is included that runs a full create -> add-recipient -> open cycle
in one shot with generated keys, useful for a quick end-to-end sanity check
with no setup.
"""
import argparse
import getpass
import json
import secrets
import sys
from pathlib import Path

from packages import package
from packages.custody import CustodyError
from packages.identity import RecipientIdentityError
from packages.package import PackageAuthorizationError, PackageError

DEFAULT_AUDIT_DIR = Path("data") / "packages" / "audit"


class AppError(ValueError):
    """Raised for user-facing CLI failures."""


def _load_state(path: Path) -> dict:
    if not path.is_file():
        raise AppError(f"no package file found at {path}.")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise AppError(f"package file could not be read: {exc}") from exc
    try:
        return package.validate_package(state)
    except (PackageError, CustodyError) as exc:
        raise AppError(f"package file is invalid: {exc}") from exc


def _save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)


def _prompt_master_key(identity_id: str) -> bytes:
    passphrase = getpass.getpass(f"master key material for {identity_id!r} (any text): ")
    # A CLI-friendly stand-in for a real master key source: any text the
    # operator supplies is stretched to a fixed-length key. Production
    # integrations should supply a real 32-byte master key (for example, one
    # unlocked from crypto.keyring.Keyring) instead of typed text.
    import hashlib
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def command_create(args) -> int:
    path = Path(args.package_file)
    if path.is_file():
        raise AppError(f"a package file already exists at {path}.")
    try:
        payload = json.loads(args.payload)
    except json.JSONDecodeError as exc:
        raise AppError(f"--payload must be valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AppError("--payload must be a JSON object.")

    master_key = _prompt_master_key(args.identity_id)
    recipients = {args.identity_id: (args.label, master_key)}
    try:
        state = package.create_package(
            args.package_id, args.label, payload, recipients, audit_dir=DEFAULT_AUDIT_DIR
        )
    except (PackageError, RecipientIdentityError) as exc:
        raise AppError(str(exc)) from exc
    _save_state(path, state)
    print(f"created package {args.package_id!r} at {path} with recipient {args.identity_id!r}.")
    return 0


def command_add_recipient(args) -> int:
    path = Path(args.package_file)
    state = _load_state(path)
    opener_master_key = _prompt_master_key(args.opener_identity_id)
    new_master_key = _prompt_master_key(args.identity_id)
    try:
        updated = package.add_recipient(
            state,
            args.identity_id,
            args.label,
            new_master_key,
            args.opener_identity_id,
            opener_master_key,
            audit_dir=DEFAULT_AUDIT_DIR,
        )
    except (PackageError, PackageAuthorizationError, RecipientIdentityError) as exc:
        raise AppError(str(exc)) from exc
    _save_state(path, updated)
    print(f"added recipient {args.identity_id!r} to package {state['package_id']!r}.")
    return 0


def command_remove_recipient(args) -> int:
    path = Path(args.package_file)
    state = _load_state(path)
    opener_master_key = _prompt_master_key(args.opener_identity_id)
    try:
        updated = package.remove_recipient(
            state, args.identity_id, args.opener_identity_id, opener_master_key,
            audit_dir=DEFAULT_AUDIT_DIR,
        )
    except (PackageError, PackageAuthorizationError) as exc:
        raise AppError(str(exc)) from exc
    _save_state(path, updated)
    print(f"removed recipient {args.identity_id!r} from package {state['package_id']!r}.")
    return 0


def command_open(args) -> int:
    path = Path(args.package_file)
    state = _load_state(path)
    master_key = _prompt_master_key(args.identity_id)
    try:
        payload, updated = package.open_package(
            state, args.identity_id, master_key, audit_dir=DEFAULT_AUDIT_DIR
        )
    except PackageAuthorizationError as exc:
        raise AppError(str(exc)) from exc
    _save_state(path, updated)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def command_list_recipients(args) -> int:
    state = _load_state(Path(args.package_file))
    for recipient in package.list_recipients(state):
        print(f"{recipient['identity_id']}: {recipient['label']}")
    return 0


def command_verify_custody(args) -> int:
    state = _load_state(Path(args.package_file))
    print(f"custody chain verified: {len(state['custody_chain'])} entries.")
    for entry in package.custody_summary(state):
        print(f"  {entry['recorded_at']}  {entry['action']:<20} {entry['actor_label']}")
    return 0


def command_demo(_args) -> int:
    """Run a full create -> add-recipient -> open cycle with generated keys."""
    package_id = f"demo-{secrets.token_hex(4)}"
    alice_key = secrets.token_bytes(32)
    bob_key = secrets.token_bytes(32)

    print(f"creating package {package_id!r} with recipient 'alice'...")
    state = package.create_package(
        package_id, "Alice", {"message": "hello from the demo package"},
        {"alice": ("Alice", alice_key)},
    )

    print("adding recipient 'bob' (authorized by alice)...")
    state = package.add_recipient(state, "bob", "Bob", bob_key, "alice", alice_key)

    print("opening the package as 'bob'...")
    payload, state = package.open_package(state, "bob", bob_key)
    print(f"bob opened the package and read: {payload!r}")

    print("verifying the custody chain...")
    package.validate_package(state)
    for entry in package.custody_summary(state):
        print(f"  {entry['recorded_at']}  {entry['action']:<20} {entry['actor_label']}")
    print("demo complete: custody chain is intact.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="package",
        description="Identity-Bound Packages: content sealed to specific recipient identities.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create a new package.")
    create.add_argument("package_file")
    create.add_argument("--package-id", required=True)
    create.add_argument("--identity-id", required=True)
    create.add_argument("--label", required=True)
    create.add_argument("--payload", required=True, help="JSON object string.")
    create.set_defaults(handler=command_create)

    add_recipient = subparsers.add_parser("add-recipient", help="add a recipient to an existing package.")
    add_recipient.add_argument("package_file")
    add_recipient.add_argument("--identity-id", required=True)
    add_recipient.add_argument("--label", required=True)
    add_recipient.add_argument("--opener-identity-id", required=True)
    add_recipient.set_defaults(handler=command_add_recipient)

    remove_recipient = subparsers.add_parser("remove-recipient", help="remove a recipient from a package.")
    remove_recipient.add_argument("package_file")
    remove_recipient.add_argument("--identity-id", required=True)
    remove_recipient.add_argument("--opener-identity-id", required=True)
    remove_recipient.set_defaults(handler=command_remove_recipient)

    open_command = subparsers.add_parser("open", help="open a package's payload as a recipient.")
    open_command.add_argument("package_file")
    open_command.add_argument("--identity-id", required=True)
    open_command.set_defaults(handler=command_open)

    list_recipients = subparsers.add_parser("list-recipients", help="list a package's recipients.")
    list_recipients.add_argument("package_file")
    list_recipients.set_defaults(handler=command_list_recipients)

    verify_custody = subparsers.add_parser("verify-custody", help="verify and print a package's custody chain.")
    verify_custody.add_argument("package_file")
    verify_custody.set_defaults(handler=command_verify_custody)

    demo = subparsers.add_parser("demo", help="run a full create/add/open cycle with generated keys.")
    demo.set_defaults(handler=command_demo)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    try:
        return args.handler(args)
    except AppError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
