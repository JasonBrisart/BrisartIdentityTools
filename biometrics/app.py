"""Biometrics command-line interface: enroll, verify, inspect, and manage
identities, plus (new) attach/extract arbitrary files -- including whole
folders and drives, chunked past BSR2's single-envelope size limit -- on
an identity, independent of the voice/fingerprint/video modality system.

This module is the single entry point that wires together every other
piece of ``biometrics/``: it loads/unlocks a keyring for the master key,
generates or locates sample/probe files, calls into ``engine.enrollment``
and ``engine.verification``, persists identity records via
``identity.identity_store.IdentityStore``, and writes audit reports via
``reports.report_writer``. Individual modules stay unit-testable on their
own; this file is where a human actually drives them from a terminal.

Invoked either directly (``python biometrics/app.py ...``) or through the
unified dispatcher (``python cli.py biometrics ...``, which sets ``sys.argv``
and calls :func:`main`).
"""
import argparse
import getpass
import json
import sys
from pathlib import Path

from biometrics.config import settings
from biometrics.engine import enrollment, modalities, verification
from biometrics.engine import attachments as attachment_engine
from biometrics.engine import bulk_attachments
from biometrics.identity.identity_record import public_summary
from biometrics.identity.identity_store import IdentityStore, IdentityStoreError
from biometrics.reports import report_writer
from biometrics.samples import sample_generator
from crypto.errors import Bsr2IntegrationError
from crypto.keyring import Keyring

KEYRING_FILE_NAME = "keyring.json"


class AppError(ValueError):
    """Raised for user-facing CLI failures (bad arguments, missing files)."""


# ------------------------------------------------------------------- keyring
def _keyring_path() -> Path:
    settings.ensure_data_dirs()
    return settings.DATA_DIR / KEYRING_FILE_NAME


def _load_or_create_keyring() -> Keyring:
    """Load the on-disk keyring, or create a new one on first run.

    A newly created keyring's recovery code is printed once to stderr, since
    it is never stored in recoverable form and this is the only chance the
    operator has to see it.
    """
    path = _keyring_path()
    if path.is_file():
        with open(path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        return Keyring(state)
    print(
        "No keyring found; creating a new one for this biometrics data directory.",
        file=sys.stderr,
    )
    passphrase = getpass.getpass("Set a new biometrics passphrase: ")
    confirm = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirm:
        raise AppError("passphrases did not match.")
    keyring, recovery_code = Keyring.create(passphrase)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(keyring.to_state(), handle, indent=2, sort_keys=True)
    print(
        "\nSAVE THIS RECOVERY CODE NOW. It is shown only once and cannot be "
        f"recovered later:\n\n    {recovery_code}\n",
        file=sys.stderr,
    )
    return keyring


def _unlock_keyring(keyring: Keyring) -> bytes:
    if keyring.is_unlocked:
        return keyring.master_key
    passphrase = getpass.getpass("Biometrics passphrase: ")
    try:
        return keyring.unlock_with_passphrase(passphrase)
    except Bsr2IntegrationError as exc:
        raise AppError(f"unlock failed: {exc}") from exc


def _store() -> IdentityStore:
    settings.ensure_data_dirs()
    return IdentityStore(settings.IDENTITY_DIR)


# --------------------------------------------------------------- commands
def command_make_samples(args) -> int:
    settings.ensure_data_dirs()
    output_dir = Path(args.output_dir) if args.output_dir else settings.SAMPLE_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []
    if "fingerprint" in args.modalities:
        path = output_dir / f"{args.seed}_fingerprint.pgm"
        sample_generator.write_fingerprint_sample(path, args.seed)
        written.append(path)
    if "voice" in args.modalities:
        path = output_dir / f"{args.seed}_voice.wav"
        sample_generator.write_voice_sample(path, args.seed)
        written.append(path)
    if "video" in args.modalities:
        path = output_dir / f"{args.seed}_video.brvid"
        sample_generator.write_video_sample(path, args.seed)
        written.append(path)
    for path in written:
        print(f"wrote {path}")
    return 0


def command_enroll(args) -> int:
    keyring = _load_or_create_keyring()
    master_key = _unlock_keyring(keyring)
    store = _store()
    if store.exists(args.identity_id):
        raise AppError(
            f"identity {args.identity_id!r} already exists; use 'verify' "
            "or delete it first before re-enrolling."
        )
    modality_sources = {}
    if args.voice:
        modality_sources["voice"] = args.voice
    if args.fingerprint:
        modality_sources["fingerprint"] = args.fingerprint
    if args.video:
        modality_sources["video"] = args.video
    if not modality_sources:
        raise AppError(
            "at least one of --voice, --fingerprint, or --video is required."
        )
    record = enrollment.enroll_identity(
        args.identity_id, args.label, master_key, modality_sources
    )
    store.save(record)
    report = report_writer.build_enrollment_report(
        args.identity_id, args.label, list(modality_sources.keys())
    )
    report_writer.write_report(settings.REPORT_DIR, report)
    print(f"enrolled {args.identity_id!r} with modalities: "
          f"{', '.join(sorted(modality_sources))}")
    return 0


def command_verify(args) -> int:
    keyring = _load_or_create_keyring()
    master_key = _unlock_keyring(keyring)
    store = _store()
    try:
        record = store.load(args.identity_id)
    except IdentityStoreError as exc:
        raise AppError(str(exc)) from exc
    probe_sources = {}
    if args.voice:
        probe_sources["voice"] = args.voice
    if args.fingerprint:
        probe_sources["fingerprint"] = args.fingerprint
    if args.video:
        probe_sources["video"] = args.video
    if not probe_sources:
        raise AppError(
            "at least one of --voice, --fingerprint, or --video is required."
        )
    try:
        result = verification.verify_identity(
            record, probe_sources, master_key, require_all=not args.any_match
        )
    except verification.VerificationError as exc:
        raise AppError(str(exc)) from exc
    report = report_writer.build_verification_report(result)
    report_writer.write_report(settings.REPORT_DIR, report)
    for modality_result in result["results"]:
        outcome = "MATCH" if modality_result["matched"] else "NO MATCH"
        print(
            f"{modality_result['modality']}: score={modality_result['score']:.4f} "
            f"threshold={modality_result['threshold']:.4f} -> {outcome}"
        )
    print(f"overall: {'MATCH' if result['matched'] else 'NO MATCH'}")
    return 0 if result["matched"] else 1


def command_inspect(args) -> int:
    store = _store()
    try:
        record = store.load(args.identity_id)
    except IdentityStoreError as exc:
        raise AppError(str(exc)) from exc
    print(json.dumps(public_summary(record), indent=2, sort_keys=True))
    return 0


def command_list(_args) -> int:
    store = _store()
    identity_ids = store.list_identity_ids()
    if not identity_ids:
        print("no enrolled identities.")
        return 0
    for identity_id in identity_ids:
        try:
            record = store.load(identity_id)
            summary = public_summary(record)
            attachment_note = (f", {len(summary['attachments'])} attachment(s)"
                               if summary.get("attachments") else "")
            print(f"{summary['identity_id']}: {summary['label']} "
                  f"[{', '.join(summary['modalities']) or 'no templates'}]{attachment_note}")
        except IdentityStoreError as exc:
            print(f"{identity_id}: ERROR ({exc})")
    return 0


def command_delete(args) -> int:
    store = _store()
    if store.delete(args.identity_id):
        print(f"deleted {args.identity_id!r}.")
        return 0
    print(f"no identity found for {args.identity_id!r}.")
    return 1


def command_probe_video(args) -> int:
    from biometrics.codecs import video
    info = video.probe(args.path)
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


def command_record_video(args) -> int:
    sample_generator.write_video_sample(
        args.output, args.seed, frame_count=args.frames, frame_rate=args.frame_rate
    )
    print(f"wrote synthetic video capture to {args.output}")
    return 0


# ------------------------------------------------------- attachment commands
def command_attach(args) -> int:
    """Attach an arbitrary file (any extension, or none at all) to an
    already-enrolled identity. The file's contents are never inspected,
    parsed, or assumed to be any particular format -- exactly the raw
    bytes on disk are sealed. Files larger than BSR2's ~16 MiB single-
    envelope limit are transparently chunked."""
    keyring = _load_or_create_keyring()
    master_key = _unlock_keyring(keyring)
    store = _store()
    try:
        record = store.load(args.identity_id)
    except IdentityStoreError as exc:
        raise AppError(str(exc)) from exc
    attachment_name = args.name or Path(args.file_path).name
    file_path = Path(args.file_path)
    if not file_path.is_file():
        raise AppError(f"no file found at {file_path}.")
    file_size = file_path.stat().st_size
    try:
        if file_size > bulk_attachments.DEFAULT_CHUNK_BYTES:
            updated = bulk_attachments.attach_large_bytes(
                record, attachment_name, file_path.read_bytes(), master_key,
            )
        else:
            updated = attachment_engine.attach_file(record, attachment_name, file_path, master_key)
    except (attachment_engine.AttachmentError, bulk_attachments.BulkAttachmentError) as exc:
        raise AppError(str(exc)) from exc
    store.save(updated)
    print(f"attached {attachment_name!r} ({file_size} bytes) to identity {args.identity_id!r}.")
    return 0


def command_attach_paths(args) -> int:
    """Attach any combination of files, folders, and/or drive roots to an
    identity as ONE bundle, zipping them first (preserving relative
    structure) and chunking as needed past the single-envelope size limit."""
    keyring = _load_or_create_keyring()
    master_key = _unlock_keyring(keyring)
    store = _store()
    try:
        record = store.load(args.identity_id)
    except IdentityStoreError as exc:
        raise AppError(str(exc)) from exc
    try:
        updated, report = bulk_attachments.attach_paths(
            record, args.name, args.paths, master_key, chunk_bytes=args.chunk_mb * 1024 * 1024,
        )
    except bulk_attachments.BulkAttachmentError as exc:
        raise AppError(str(exc)) from exc
    store.save(updated)
    print(json.dumps(report, indent=2, sort_keys=True))
    if report.get("files_skipped"):
        print(f"warning: {len(report['files_skipped'])} file(s) could not be read "
             f"and were skipped.", file=sys.stderr)
    return 0


def command_extract_attachment(args) -> int:
    """Decrypt a previously attached file straight back to disk,
    byte-for-byte identical to what was originally attached. Automatically
    detects and reassembles a chunked bundle if one exists under this name."""
    keyring = _load_or_create_keyring()
    master_key = _unlock_keyring(keyring)
    store = _store()
    try:
        record = store.load(args.identity_id)
    except IdentityStoreError as exc:
        raise AppError(str(exc)) from exc
    has_bundle_manifest = f"{args.name}.manifest" in record.get("attachments", {})
    try:
        if has_bundle_manifest:
            data = bulk_attachments.restore_large_bytes(record, args.name, master_key)
            Path(args.output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output_path).write_bytes(data)
        else:
            attachment_engine.extract_attachment_to_file(
                record, args.name, master_key, args.output_path
            )
    except (attachment_engine.AttachmentError, bulk_attachments.BulkAttachmentError) as exc:
        raise AppError(str(exc)) from exc
    print(f"extracted to {args.output_path}")
    return 0


def command_restore_paths(args) -> int:
    """Decrypt and unzip an attach-paths bundle back into a real directory tree."""
    keyring = _load_or_create_keyring()
    master_key = _unlock_keyring(keyring)
    store = _store()
    try:
        record = store.load(args.identity_id)
    except IdentityStoreError as exc:
        raise AppError(str(exc)) from exc
    try:
        result = bulk_attachments.restore_paths(record, args.name, master_key, args.output_dir)
    except bulk_attachments.BulkAttachmentError as exc:
        raise AppError(str(exc)) from exc
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def command_remove_attachment(args) -> int:
    """Remove a named attachment (or bulk bundle) from an identity."""
    keyring = _load_or_create_keyring()
    master_key = _unlock_keyring(keyring) if not args.no_unlock else None
    store = _store()
    try:
        record = store.load(args.identity_id)
    except IdentityStoreError as exc:
        raise AppError(str(exc)) from exc
    is_bundle = f"{args.name}.manifest" in record.get("attachments", {})
    if is_bundle:
        if master_key is None:
            master_key = _unlock_keyring(keyring)
        updated = bulk_attachments.remove_bulk_attachment(record, args.name, master_key)
    else:
        from biometrics.engine.attachments import remove_identity_attachment
        updated = remove_identity_attachment(record, args.name)
    store.save(updated)
    print(f"removed attachment {args.name!r} from identity {args.identity_id!r}.")
    return 0


# --------------------------------------------------------------- argparse
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="biometrics",
        description="Biometrics: local multimodal biometric enrollment and verification.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    make_samples = subparsers.add_parser(
        "make-samples", help="generate synthetic test samples."
    )
    make_samples.add_argument("seed", help="deterministic seed for generation.")
    make_samples.add_argument(
        "--modalities",
        nargs="+",
        choices=modalities.supported_modalities(),
        default=list(modalities.supported_modalities()),
    )
    make_samples.add_argument("--output-dir", default=None)
    make_samples.set_defaults(handler=command_make_samples)

    record_video = subparsers.add_parser(
        "record-video", help="generate a synthetic video capture file."
    )
    record_video.add_argument("output", help="output .brvid path.")
    record_video.add_argument("--seed", default="video-capture")
    record_video.add_argument("--frames", type=int, default=sample_generator.DEFAULT_VIDEO_FRAME_COUNT)
    record_video.add_argument("--frame-rate", type=int, default=sample_generator.DEFAULT_VIDEO_FRAME_RATE)
    record_video.set_defaults(handler=command_record_video)

    probe_video = subparsers.add_parser(
        "probe-video", help="print BRVID file header metadata."
    )
    probe_video.add_argument("path")
    probe_video.set_defaults(handler=command_probe_video)

    enroll = subparsers.add_parser("enroll", help="enroll a new identity.")
    enroll.add_argument("identity_id")
    enroll.add_argument("--label", required=True)
    enroll.add_argument("--voice", default=None, help="path to a WAV file.")
    enroll.add_argument("--fingerprint", default=None, help="path to a PGM/PNG image.")
    enroll.add_argument("--video", default=None, help="path to a BRVID file.")
    enroll.set_defaults(handler=command_enroll)

    verify = subparsers.add_parser("verify", help="verify a probe against an enrolled identity.")
    verify.add_argument("identity_id")
    verify.add_argument("--voice", default=None, help="path to a WAV file.")
    verify.add_argument("--fingerprint", default=None, help="path to a PGM/PNG image.")
    verify.add_argument("--video", default=None, help="path to a BRVID file.")
    verify.add_argument(
        "--any-match",
        action="store_true",
        help="accept if any one requested modality matches, instead of requiring all.",
    )
    verify.set_defaults(handler=command_verify)

    inspect = subparsers.add_parser("inspect", help="show a non-secret summary of one identity.")
    inspect.add_argument("identity_id")
    inspect.set_defaults(handler=command_inspect)

    list_command = subparsers.add_parser("list", help="list all enrolled identities.")
    list_command.set_defaults(handler=command_list)

    delete = subparsers.add_parser("delete", help="delete an enrolled identity.")
    delete.add_argument("identity_id")
    delete.set_defaults(handler=command_delete)

    attach = subparsers.add_parser(
        "attach", help="attach an arbitrary file (any extension, or none) to an identity."
    )
    attach.add_argument("identity_id")
    attach.add_argument("file_path")
    attach.add_argument("--name", default=None,
                        help="attachment name to store it under; defaults to the file's own name.")
    attach.set_defaults(handler=command_attach)

    attach_paths = subparsers.add_parser(
        "attach-paths",
        help="attach any combination of files/folders/drive roots as one bundle.",
    )
    attach_paths.add_argument("identity_id")
    attach_paths.add_argument("name", help="bundle name to store it under.")
    attach_paths.add_argument("paths", nargs="+",
                              help="one or more file, folder, or drive root paths.")
    attach_paths.add_argument("--chunk-mb", type=int, default=8)
    attach_paths.set_defaults(handler=command_attach_paths)

    extract_attachment = subparsers.add_parser(
        "extract-attachment", help="decrypt an attached file (or bundle) back to disk."
    )
    extract_attachment.add_argument("identity_id")
    extract_attachment.add_argument("name")
    extract_attachment.add_argument("output_path")
    extract_attachment.set_defaults(handler=command_extract_attachment)

    restore_paths = subparsers.add_parser(
        "restore-paths", help="decrypt and unzip an attach-paths bundle into a real directory tree."
    )
    restore_paths.add_argument("identity_id")
    restore_paths.add_argument("name")
    restore_paths.add_argument("output_dir")
    restore_paths.set_defaults(handler=command_restore_paths)

    remove_attachment = subparsers.add_parser(
        "remove-attachment", help="remove a named attachment (or bundle) from an identity."
    )
    remove_attachment.add_argument("identity_id")
    remove_attachment.add_argument("name")
    remove_attachment.add_argument("--no-unlock", action="store_true",
                                   help="skip unlocking if this is definitely not a chunked bundle.")
    remove_attachment.set_defaults(handler=command_remove_attachment)

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
