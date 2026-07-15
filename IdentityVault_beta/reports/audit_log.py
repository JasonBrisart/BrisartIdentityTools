from core.time_tools import utc_now


def audit_event(action: str, details: dict) -> dict:
    return {
        "timestamp": utc_now(),
        "action": action,
        "details": details,
    }


def append_audit(vault_data: dict, action: str, details: dict) -> None:
    vault_data.setdefault("audit_log", [])
    vault_data["audit_log"].append(audit_event(action, details))
