"""
audit.py
--------
Append-only audit logging for the Identity-Bound Package BETA prototype.
Every meaningful event (create / open / transfer / failure) is written
to logs/audit.log with a UTC timestamp.
"""

from pathlib import Path
from datetime import datetime, timezone

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "audit.log"


def audit_event(message: str) -> None:
    """Write a single timestamped line to the audit log."""
    timestamp = datetime.now(timezone.utc).isoformat()
    line = f"[{timestamp}] {message}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)
