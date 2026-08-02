import argparse
import json
import sys

from biometrics.enrollment import enroll_identity
from biometrics.verification import verify_identity
from core.image_loader import read_grayscale_image
from core.video import probe_avi_grayscale, write_avi_grayscale
from config.settings import (
    APP_NAME,
    APP_VERSION,
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


def command_record_video(args) -> None:
    """Assemble captured still frames into an AVI recording for video FaceID.

    Capturing straight from a camera needs a platform-specific driver, which
    would mean a third-party dependency. Instead this takes frames already on
    disk (any PGM/PNG the rest of the tool reads) and writes the uncompressed
    AVI the video modality consumes, keeping the recording path inside the
    standard library.
    """
    if len(args.frames) < 2:
        raise ValueError(
            f"a video recording needs at least 2 frames, got {len(args.frames)}."
        )

    width, height, first_pixels = read_grayscale_image(args.frames[0])
    frames = [first_pixels]

    for frame_path in args.frames[1:]:
        frame_width, frame_height, pixels = read_grayscale_image(frame_path)
        if (frame_width, frame_height) != (width, height):
            raise ValueError(
                f"frame size mismatch: {frame_path} is "
                f"{frame_width}x{frame_height}, expected {width}x{height}. "
                "All frames in a recording must share one resolution."
            )
        frames.append(pixels)

    write_avi_grayscale(
        args.output_path,
        width,
        height,
        frames,
        frames_per_second=args.fps,
    )

    probe_width, probe_height, frame_count = probe_avi_grayscale(args.output_path)

    print("Recording written.")
    print(f"Output File: {args.output_path}")
    print(f"Resolution: {probe_width}x{probe_height}")
    print(f"Frames: {frame_count}")
    print(f"Frames Per Second: {args.fps}")
    print("Container: AVI uncompressed DIB (8-bit grayscale palette)")


def command_probe_video(args) -> None:
    width, height, frame_count = probe_avi_grayscale(args.video_path)
    print(f"Video File: {args.video_path}")
    print(f"Resolution: {width}x{height}")
    print(f"Frames: {frame_count}")


def command_enroll(args) -> None:
    result = enroll_identity(
        identity_id=args.identity_id,
        display_name=args.display_name,
        source_path=args.source_path,
        threshold=args.threshold,
        overwrite=args.overwrite,
        modality=args.modality,
        require_live=not args.allow_static,
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

    liveness = result.get("liveness")
    if liveness is not None:
        state = "PASS" if liveness["passed"] else "FAIL"
        print(f"Liveness Check: {state}")
        print(f"Motion (mean frame delta): {liveness['motion_mean']}")


def command_verify(args) -> None:
    report = verify_identity(
        identity_id=args.identity_id,
        source_path=args.source_path,
        threshold=args.threshold,
        modality=args.modality,
        require_live=not args.allow_static,
    )

    print("Verification complete.")
    print(f"Identity ID: {report['identity_id']}")
    print(f"Result: {report['result']}")
    print(f"Similarity Score: {report['similarity_score']}")
    print(f"Threshold: {report['threshold']}")

    liveness = report.get("liveness")
    if liveness is not None:
        state = "PASS" if liveness["passed"] else "FAIL"
        print(f"Liveness Check: {state}")
        print(f"Motion (mean frame delta): {liveness['motion_mean']}")
        if not liveness["passed"]:
            print(f"Liveness Detail: {liveness['reason']}")

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
        help="Generate local sample biometric files.",
    )
    make_samples_parser.set_defaults(
        func=command_make_samples
    )

    record_parser = subparsers.add_parser(
        "record-video",
        help=(
            "Assemble PGM/PNG frames into an uncompressed AVI recording "
            "for video FaceID enrollment or verification."
        ),
    )
    record_parser.add_argument("output_path")
    record_parser.add_argument(
        "frames",
        nargs="+",
        help="Two or more same-size PGM/PNG frames, in recording order.",
    )
    record_parser.add_argument(
        "--fps",
        type=int,
        default=15,
        help="Frames per second recorded in the AVI header (default: 15).",
    )
    record_parser.set_defaults(
        func=command_record_video
    )

    probe_parser = subparsers.add_parser(
        "probe-video",
        help="Report the resolution and frame count of an AVI recording.",
    )
    probe_parser.add_argument("video_path")
    probe_parser.set_defaults(
        func=command_probe_video
    )

    enroll_parser = subparsers.add_parser(
        "enroll",
        help=(
            "Enroll a local identity from a PGM/PNG image, "
            "a WAV recording, or an AVI video recording."
        ),
    )
    enroll_parser.add_argument("identity_id")
    enroll_parser.add_argument("display_name")
    enroll_parser.add_argument("source_path")
    enroll_parser.add_argument(
        "--modality",
        choices=["face", "video", "voice", "fingerprint"],
        default=None,
        help="Optional explicit modality. Auto-detected from file extension when omitted.",
    )
    enroll_parser.add_argument(
        "--threshold",
        type=float,
        default=None,
    )
    enroll_parser.add_argument(
        "--allow-static",
        action="store_true",
        help=(
            "Allow video enrollment from a recording with no motion. "
            "Static recordings are refused by default because they are what a "
            "photograph held up to the lens produces."
        ),
    )
    enroll_parser.add_argument(
        "--overwrite",
        action="store_true",
        help=(
            "Re-enroll an identity that already exists, "
            "replacing its stored template."
        ),
    )
    enroll_parser.set_defaults(
        func=command_enroll
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help=(
            "Verify a candidate PGM/PNG image, WAV recording, or AVI "
            "video recording against an enrolled identity."
        ),
    )
    verify_parser.add_argument("identity_id")
    verify_parser.add_argument("source_path")
    verify_parser.add_argument(
        "--modality",
        choices=["face", "video", "voice", "fingerprint"],
        default=None,
        help="Optional explicit modality. Auto-detected from file extension when omitted.",
    )
    verify_parser.add_argument(
        "--threshold",
        type=float,
        default=None,
    )
    verify_parser.add_argument(
        "--allow-static",
        action="store_true",
        help=(
            "Skip the video liveness gate and report the raw face score even "
            "when the recording shows no motion."
        ),
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
