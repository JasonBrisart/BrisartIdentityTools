from IdentityVault_beta.core.time_tools import utc_now


def audit_event(
    action: str,
    details: dict,
) -> dict:
    if not isinstance(action, str) or not action.strip():
        raise ValueError("audit action cannot be empty.")

    if not isinstance(details, dict):
        raise ValueError("audit details must be an object.")

    return {
        "timestamp": utc_now(),
        "action": action.strip(),
        "details": dict(details),
    }


def append_audit(
    vault_data: dict,
    action: str,
    details: dict,
) -> None:
    if not isinstance(vault_data, dict):
        raise ValueError("vault data must be an object.")

    vault_data.setdefault("audit_log", [])

    if not isinstance(vault_data["audit_log"], list):
        raise ValueError("vault audit log must be a list.")

    vault_data["audit_log"].append(
        audit_event(
            action=action,
            details=details,
        )
    )