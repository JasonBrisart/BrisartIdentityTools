"""Vault command-line interface: init, unlock, upsert, get, list,
delete, batch-upsert, and (new) encrypt-file/decrypt-file for arbitrary
binary files of any kind, extension, or lack thereof.
"""
import argparse
import getpass
import json
import sys
from pathlib import Path
from vault.config import settings
from vault.store.vault_file import VaultFileError, vault_exists
from vault.store.vault_service import VaultService, VaultServiceError
from vault.store.bulk_file_service import BulkFileService, BulkFileServiceError


class AppError(ValueError):
    pass


def _vault_path(args) -> Path:
    return Path(args.vault) if args.vault else settings.VAULT_FILE


def _open_service(args) -> VaultService:
    settings.ensure_data_dirs()
    return VaultService(_vault_path(args), audit_dir=settings.AUDIT_DIR)


def _unlock(service: VaultService) -> None:
    passphrase = getpass.getpass("Vault passphrase: ")
    try:
        service.unlock(passphrase)
    except VaultServiceError as exc:
        raise AppError(str(exc)) from exc


def command_init(args) -> int:
    settings.ensure_data_dirs()
    path = _vault_path(args)
    if vault_exists(path):
        raise AppError(f"a vault already exists at {path}.")
    passphrase = getpass.getpass("Set a new vault passphrase: ")
    confirm = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirm:
        raise AppError("passphrases did not match.")
    _service, recovery_code = VaultService.create(path, passphrase, audit_dir=settings.AUDIT_DIR)
    print(f"vault created at {path}")
    print(
        "\nSAVE THIS RECOVERY CODE NOW. It is shown only once and cannot be "
        f"recovered later:\n\n    {recovery_code}\n",
        file=sys.stderr,
    )
    return 0


def command_upsert(args) -> int:
    service = _open_service(args)
    _unlock(service)
    try:
        payload = json.loads(args.payload)
    except json.JSONDecodeError as exc:
        raise AppError(f"--payload must be valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AppError("--payload must be a JSON object.")
    try:
        summary = service.upsert(args.label, args.kind, payload, record_id=args.record_id)
    except (VaultServiceError, VaultFileError) as exc:
        raise AppError(str(exc)) from exc
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def command_batch_upsert(args) -> int:
    service = _open_service(args)
    _unlock(service)
    try:
        with open(args.items_file, "r", encoding="utf-8") as handle:
            items = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise AppError(f"could not read --items-file: {exc}") from exc
    if not isinstance(items, list):
        raise AppError("--items-file must contain a JSON array of items.")
    try:
        summaries = service.batch_upsert(items)
    except (VaultServiceError, VaultFileError) as exc:
        raise AppError(str(exc)) from exc
    print(json.dumps(summaries, indent=2, sort_keys=True))
    print(f"upserted {len(summaries)} record(s).", file=sys.stderr)
    return 0


def command_encrypt_file(args) -> int:
    """Encrypt an arbitrary local file -- any extension, or no extension at
    all -- into the vault, sealing its exact raw bytes. The file's contents
    are never inspected, parsed, or assumed to be any particular format."""
    service = _open_service(args)
    _unlock(service)
    try:
        summary = service.upsert_file(args.file_path, label=args.label, record_id=args.record_id)
    except (VaultServiceError, VaultFileError) as exc:
        raise AppError(str(exc)) from exc
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def command_decrypt_file(args) -> int:
    """Decrypt a previously encrypted file record straight back to disk,
    byte-for-byte identical to what was originally encrypted."""
    service = _open_service(args)
    _unlock(service)
    try:
        output_path = service.get_file(args.record_id, args.output_path)
    except VaultServiceError as exc:
        raise AppError(str(exc)) from exc
    print(f"decrypted to {output_path}")
    return 0


def command_encrypt_paths(args) -> int:
    """Encrypt any combination of files, folders, and/or drive roots -- all
    given as separate positional arguments -- as ONE bundle. Any single
    file over BSR2's ~16 MiB envelope cap, and the zip built from
    folders/drives (which will almost always be over that cap), are both
    transparently chunked and reassembled correctly; the caller never
    needs to think about the size limit at all."""
    service = _open_service(args)
    _unlock(service)
    bulk = BulkFileService(service, chunk_bytes=args.chunk_mb * 1024 * 1024)
    label = args.label or Path(args.paths[0]).name
    try:
        summary = bulk.upsert_paths(args.paths, label, record_id=args.record_id)
    except (BulkFileServiceError, VaultServiceError, VaultFileError) as exc:
        raise AppError(str(exc)) from exc
    print(json.dumps(summary, indent=2, sort_keys=True))
    if summary.get("files_skipped"):
        print(f"warning: {len(summary['files_skipped'])} file(s) could not be read "
             f"and were skipped (see 'files_skipped' above).", file=sys.stderr)
    return 0


def command_restore_paths(args) -> int:
    """Decrypt and unzip a bundle created by encrypt-paths back into a real
    directory tree at the given output directory."""
    service = _open_service(args)
    _unlock(service)
    bulk = BulkFileService(service)
    try:
        result = bulk.restore_paths(args.record_id, args.output_dir)
    except (BulkFileServiceError, VaultServiceError) as exc:
        raise AppError(str(exc)) from exc
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def command_get(args) -> int:
    service = _open_service(args)
    _unlock(service)
    try:
        payload = service.get(args.record_id)
    except VaultServiceError as exc:
        raise AppError(str(exc)) from exc
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def command_list(args) -> int:
    service = _open_service(args)
    summaries = service.list_records()
    if not summaries:
        print("no records in vault.")
        return 0
    for summary in summaries:
        extra = ""
        if summary["kind"] == "file":
            extra = f" (encrypted file record)"
        print(f"{summary['record_id']}: {summary['label']} [{summary['kind']}]{extra} "
              f"(updated {summary['updated_at']})")
    return 0


def command_delete(args) -> int:
    service = _open_service(args)
    if service.delete(args.record_id):
        print(f"deleted {args.record_id!r}.")
        return 0
    print(f"no record found for {args.record_id!r}.")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault",
        description="Vault: an encrypted, local, single-file record store.",
    )
    parser.add_argument("--vault", default=None, help="path to the vault file.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="create a new vault.")
    init.set_defaults(handler=command_init)

    upsert = subparsers.add_parser("upsert", help="create or update one JSON-payload record.")
    upsert.add_argument("label")
    upsert.add_argument("--kind", required=True)
    upsert.add_argument("--payload", required=True, help="JSON object string.")
    upsert.add_argument("--record-id", default=None)
    upsert.set_defaults(handler=command_upsert)

    batch_upsert = subparsers.add_parser(
        "batch-upsert", help="create or update many JSON-payload records from a JSON file."
    )
    batch_upsert.add_argument("items_file", help="path to a JSON array of items.")
    batch_upsert.set_defaults(handler=command_batch_upsert)

    encrypt_file = subparsers.add_parser(
        "encrypt-file",
        help="encrypt any local file into the vault, any extension or none at all.",
    )
    encrypt_file.add_argument("file_path", help="path to the file to encrypt.")
    encrypt_file.add_argument("--label", default=None, help="defaults to the file's own name.")
    encrypt_file.add_argument("--record-id", default=None)
    encrypt_file.set_defaults(handler=command_encrypt_file)

    decrypt_file = subparsers.add_parser(
        "decrypt-file", help="decrypt a file record back to disk, byte-for-byte."
    )
    decrypt_file.add_argument("record_id")
    decrypt_file.add_argument("output_path")
    decrypt_file.set_defaults(handler=command_decrypt_file)

    encrypt_paths = subparsers.add_parser(
        "encrypt-paths",
        help="encrypt any combination of files/folders/drive roots as one bundle "
             "(transparently chunked past BSR2's ~16 MiB single-envelope limit).",
    )
    encrypt_paths.add_argument("paths", nargs="+",
                               help="one or more file, folder, or drive root paths.")
    encrypt_paths.add_argument("--label", default=None,
                               help="defaults to the first path's own name.")
    encrypt_paths.add_argument("--record-id", default=None)
    encrypt_paths.add_argument("--chunk-mb", type=int, default=8,
                               help="chunk size in MiB (default 8; must stay under ~16).")
    encrypt_paths.set_defaults(handler=command_encrypt_paths)

    restore_paths = subparsers.add_parser(
        "restore-paths", help="decrypt and unzip a bundle back into a real directory tree."
    )
    restore_paths.add_argument("record_id")
    restore_paths.add_argument("output_dir")
    restore_paths.set_defaults(handler=command_restore_paths)

    get = subparsers.add_parser("get", help="retrieve and decrypt one JSON record's payload.")
    get.add_argument("record_id")
    get.set_defaults(handler=command_get)

    list_command = subparsers.add_parser("list", help="list all records (no unlock required).")
    list_command.set_defaults(handler=command_list)

    delete = subparsers.add_parser("delete", help="delete one record.")
    delete.add_argument("record_id")
    delete.set_defaults(handler=command_delete)

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
