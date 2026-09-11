"""
File: tools/integrity_checkpoint.py
Purpose:
    Standalone CLI for common.integrity_ledger. Meant to be invoked either
    by hand (before/after a sensitive operation on a vault.json, a
    biometrics keyring.json, or a package's .json file) or by an OS-level
    scheduler (a cron job, a Windows Scheduled Task) so checkpoints are
    recorded at a regular cadence with no persistent background process
    and no third-party scheduling dependency -- consistent with
    tools/envinfo.py's existing standalone-script pattern in this
    repository.

    Read common/integrity_ledger.py's module docstring before relying on
    this for anything real: checkpointing narrows, but cannot close, the
    "edit then revert before the next check" blind spot every tamper-
    evidence mechanism in this project shares. The smaller the gap between
    scheduled checkpoints, the smaller that blind spot -- but it is never
    zero unless checkpoints are continuous, which this tool does not
    attempt to be.

Communication relationships:
    Called by: an operator's shell, or an OS scheduler (cron / Task
    Scheduler) invoking this script directly. Not imported by any other
    module in this repository -- it is a thin argument-parsing shell
    around common.integrity_ledger's public functions, the same
    relationship packages/main.py has to packages/package.py.
    Calls out to: common.integrity_ledger (checkpoint/verify/status/
    history/list-tracked operations).

Parameters / settings:
    DEFAULT_LEDGER_PATH (Path, "data/integrity/ledger.json"):
        Used when --ledger is not supplied, consistent with this
        project's existing data/<tool>/ convention (vault/data,
        biometrics/data, packages/data).

Edge-case behavior:
    - Every subcommand's failures are reported as a plain "error: ..."
      message on stderr with a non-zero exit code, matching the existing
      AppError handling convention in vault/app.py, biometrics/app.py, and
      packages/main.py, rather than letting a raw traceback escape.
    - "status" reports "UNKNOWN (no prior checkpoint)" rather than a
      True/False match when a target has never been checkpointed, so an
      operator cannot misread "no checkpoint yet" as "verified clean."
    - "checkpoint" always appends a new checkpoint, even if the file's
      hash is identical to the previous checkpoint -- an unchanged file is
      still worth recording, since the recorded_at timestamp itself is
      evidence that the file was inspected and found unchanged at that
      moment.
"""
import argparse
import sys
from pathlib import Path

from common import integrity_ledger

DEFAULT_LEDGER_PATH = Path("data") / "integrity" / "ledger.json"


class AppError(ValueError):
    """Raised for user-facing CLI failures."""


def _ledger_path(args) -> Path:
    return Path(args.ledger) if args.ledger else DEFAULT_LEDGER_PATH


def command_checkpoint(args) -> int:
    ledger_path = _ledger_path(args)
    try:
        entry = integrity_ledger.append_checkpoint(ledger_path, args.target_file, actor_label=args.label)
    except integrity_ledger.IntegrityLedgerError as exc:
        raise AppError(str(exc)) from exc
    print(f"checkpoint recorded for {entry['target_path']}")
    print(f"  sha256:      {entry['sha256']}")
    print(f"  size_bytes:  {entry['size_bytes']}")
    print(f"  recorded_at: {entry['recorded_at']}")
    print(f"  ledger:      {ledger_path}")
    return 0


def command_status(args) -> int:
    ledger_path = _ledger_path(args)
    status = integrity_ledger.current_status(ledger_path, args.target_file)
    print(f"target:           {status['target_path']}")
    if status["current_sha256"] is None:
        print("current state:    file does not exist")
    else:
        print(f"current sha256:   {status['current_sha256']}")
    if status["latest_checkpoint"] is None:
        print("latest checkpoint: none recorded yet")
        print("result:           UNKNOWN (no prior checkpoint to compare against)")
        return 0
    checkpoint = status["latest_checkpoint"]
    print(f"latest checkpoint: {checkpoint['recorded_at']} (sha256 {checkpoint['sha256']})")
    if status["matches_latest_checkpoint"]:
        print("result:           MATCHES latest checkpoint")
        return 0
    print("result:           DOES NOT MATCH latest checkpoint")
    return 1


def command_history(args) -> int:
    ledger_path = _ledger_path(args)
    entries = integrity_ledger.history_for_path(ledger_path, args.target_file)
    if not entries:
        print(f"no checkpoints recorded for {args.target_file}.")
        return 0
    for entry in entries:
        label = f" ({entry['actor_label']})" if entry.get("actor_label") else ""
        print(f"{entry['recorded_at']}  sha256={entry['sha256']}  size={entry['size_bytes']}{label}")
    return 0


def command_verify(args) -> int:
    ledger_path = _ledger_path(args)
    try:
        integrity_ledger.verify_ledger(ledger_path)
    except integrity_ledger.IntegrityLedgerError as exc:
        raise AppError(str(exc)) from exc
    entry_count = len(integrity_ledger.all_entries(ledger_path))
    print(f"ledger verified: {entry_count} entries, chain intact.")
    return 0


def command_list_tracked(args) -> int:
    ledger_path = _ledger_path(args)
    paths = integrity_ledger.list_tracked_paths(ledger_path)
    if not paths:
        print("no files are currently tracked in this ledger.")
        return 0
    for path in paths:
        print(path)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="integrity-checkpoint",
        description=(
            "Record and inspect periodic file checkpoints, external to the "
            "files themselves, to narrow (not close) the edit-then-revert "
            "blind spot every tamper-evidence mechanism in this project shares."
        ),
    )
    parser.add_argument(
        "--ledger", default=None,
        help=f"path to the ledger file (default: {DEFAULT_LEDGER_PATH}).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    checkpoint = subparsers.add_parser("checkpoint", help="record a new checkpoint of a file.")
    checkpoint.add_argument("target_file")
    checkpoint.add_argument("--label", default="", help="optional actor label to record with this checkpoint.")
    checkpoint.set_defaults(handler=command_checkpoint)

    status = subparsers.add_parser("status", help="compare a file's current hash against its latest checkpoint.")
    status.add_argument("target_file")
    status.set_defaults(handler=command_status)

    history = subparsers.add_parser("history", help="list every checkpoint recorded for a file.")
    history.add_argument("target_file")
    history.set_defaults(handler=command_history)

    verify = subparsers.add_parser("verify", help="verify the ledger's own hash chain is intact.")
    verify.set_defaults(handler=command_verify)

    list_tracked = subparsers.add_parser("list-tracked", help="list every file path tracked in the ledger.")
    list_tracked.set_defaults(handler=command_list_tracked)

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
