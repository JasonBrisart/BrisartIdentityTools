import argparse
import json
import sys

from biometrics.enrollment import enroll_identity
from biometrics.verification import verify_identity
from config.settings import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_THRESHOLD,
    ensure_data_dirs,
)
from identity.identity_store import (
    list_identities,
    load_identity,
)
from samples.sample_generator import generate_samples


def print_json(data: dict) -> None:
    print(
        json.dumps(
            data,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
    )


def command_make_samples(args) -> None:
    written = generate_samples()

    print("Sample files created:")

    for path in written:
        print(f"- {path}")


def command_enroll(args) -> None:
    result = enroll_identity(
        identity_id=args.identity_id,
        display_name=args.display_name,
        image_path=args.image_path,
        threshold=args.threshold,
    )

    identity = result["identity"]
    template = result["template"]

    print("Enrollment complete.")
    print(f"Identity ID: {identity['identity_id']}")
    print(f"Display Name: {identity['display_name']}")
    print(f"Template Location: {identity['template_file']}")
    print(f"Template SHA256: {template['template_sha256']}")
    print(f"Default Threshold: {identity['default_threshold']}")
    print(f"Storage Mode: {identity['storage_mode']}")


def command_verify(args) -> None:
    report = verify_identity(
        identity_id=args.identity_id,
        image_path=args.image_path,
        threshold=args.threshold,
    )

    print("Verification complete.")
    print(f"Identity ID: {report['identity_id']}")
    print(f"Result: {report['result']}")
    print(f"Similarity Score: {report['similarity_score']}")
    print(f"Threshold: {report['threshold']}")
    print(f"Report File: {report['report_file']}")


def command_inspect(args) -> None:
    print_json(
        load_identity(args.identity_id)
    )


def command_list(args) -> None:
    records = list_identities()

    if not records:
        print("No local identities found.")
        return

    for record in records:
        print(
            f"{record.get('identity_id')} | "
            f"{record.get('display_name')} | "
            f"{record.get('status')}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="app.py",
        description=(
            f"{APP_NAME} {APP_VERSION} "
            "local identity verification tools"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    make_samples_parser = subparsers.add_parser(
        "make-samples",
        help="Generate local sample PGM files.",
    )
    make_samples_parser.set_defaults(
        func=command_make_samples
    )

    enroll_parser = subparsers.add_parser(
        "enroll",
        help=(
            "Enroll a local identity from "
            "a PGM image."
        ),
    )
    enroll_parser.add_argument("identity_id")
    enroll_parser.add_argument("display_name")
    enroll_parser.add_argument("image_path")
    enroll_parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
    )
    enroll_parser.set_defaults(
        func=command_enroll
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help=(
            "Verify a candidate PGM image "
            "against an enrolled identity."
        ),
    )
    verify_parser.add_argument("identity_id")
    verify_parser.add_argument("image_path")
    verify_parser.add_argument(
        "--threshold",
        type=float,
        default=None,
    )
    verify_parser.set_defaults(
        func=command_verify
    )

    inspect_parser = subparsers.add_parser(
        "inspect",
        help=(
            "Print a local identity "
            "record as JSON."
        ),
    )
    inspect_parser.add_argument("identity_id")
    inspect_parser.set_defaults(
        func=command_inspect
    )

    list_parser = subparsers.add_parser(
        "list",
        help="List local identities.",
    )
    list_parser.set_defaults(
        func=command_list
    )

    return parser


def main() -> None:
    ensure_data_dirs()

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