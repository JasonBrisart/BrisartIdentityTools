import datetime as dt
import json
import os
import secrets
from pathlib import Path

from config.settings import APP_NAME, APP_VERSION, REPORT_DIR, ensure_data_dirs


class ReportWriteError(Exception):
    """Raised when a verification report cannot be created."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def report_timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S_%fZ")


def _atomic_write_json(path: Path, data: dict) -> None:
    temporary_path = path.parent / (
        f".{path.name}.{secrets.token_hex(8)}.tmp"
    )
    serialized = json.dumps(
        data,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )
    try:
        with temporary_path.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except OSError as exc:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise ReportWriteError(f"Unable to write report: {path}") from exc


def write_verification_report(
    identity: dict,
    result: str,
    score: float,
    threshold: float,
    stored_template: dict,
    candidate_template: dict,
    persist: bool = True,
) -> dict:
    identity_id = identity["identity_id"]
    report = {
        "app": APP_NAME,
        "app_version": APP_VERSION,
        "report_type": "biometric_verification_beta_report",
        "created_at": utc_now(),
        "identity_id": identity_id,
        "display_name": identity.get("display_name"),
        "result": result,
        "similarity_score": float(score),
        "threshold": float(threshold),
        "stored_template_sha256": stored_template.get("template_sha256"),
        "candidate_template_sha256": candidate_template.get(
            "template_sha256"
        ),
        "candidate_image_sha256": candidate_template.get(
            "source_image_sha256"
        ),
        "mode": "local_biometric_verification_beta",
        "report_file": None,
    }

    if not persist:
        return report

    ensure_data_dirs()
    report_path = REPORT_DIR / (
        f"{identity_id}_{report_timestamp()}_report.json"
    )
    report["report_file"] = str(report_path)
    _atomic_write_json(report_path, report)
    return report
