import datetime as dt
import json

from config.settings import APP_NAME, APP_VERSION, REPORT_DIR, ensure_data_dirs


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def report_timestamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def write_verification_report(identity: dict, result: str, score: float, threshold: float, stored_template: dict, candidate_template: dict) -> dict:
    ensure_data_dirs()

    identity_id = identity["identity_id"]
    report = {
        "app": APP_NAME,
        "app_version": APP_VERSION,
        "report_type": "biometric_verification_beta_report",
        "created_at": utc_now(),
        "identity_id": identity_id,
        "display_name": identity.get("display_name"),
        "result": result,
        "similarity_score": score,
        "threshold": threshold,
        "stored_template_sha256": stored_template.get("template_sha256"),
        "candidate_template_sha256": candidate_template.get("template_sha256"),
        "candidate_image_sha256": candidate_template.get("source_image_sha256"),
        "mode": "local_biometric_verification_beta",
    }

    report_path = REPORT_DIR / f"{identity_id}_{report_timestamp()}_report.json"
    report["report_file"] = str(report_path)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    return report
