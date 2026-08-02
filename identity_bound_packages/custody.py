"""
custody.py
----------
Chain-of-custody ledger for the Identity-Bound Package BETA prototype.
Each event is hash-linked to the previous one (a tiny hash chain), so
accidental edits or reordering can be detected by verify_chain().

*** RESEARCH / DEMO ONLY ***
This detects casual/accidental tampering. It is NOT a cryptographically
signed ledger and provides no protection against a determined attacker
who can recompute the whole chain.
"""

import json
from datetime import datetime, timezone

from crypto import digests_equal, hash_text


def _event_hash(event: dict) -> str:
    """Deterministic hash of an event's core fields."""
    core = {
        "timestamp": event["timestamp"],
        "action": event["action"],
        "actor": event["actor"],
        "location": event["location"],
        "previous_hash": event["previous_hash"],
    }
    return hash_text(json.dumps(core, sort_keys=True))


def append_event(package: dict, action: str, actor: str, location: str) -> None:
    """Append a new hash-linked custody event to the package."""
    chain = package.setdefault("custody_chain", [])
    previous_hash = chain[-1]["event_hash"] if chain else None

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "actor": actor,
        "location": location,
        "previous_hash": previous_hash,
    }
    event["event_hash"] = _event_hash(event)
    chain.append(event)


def verify_chain(package: dict) -> bool:
    """Return True if the custody chain is internally consistent."""
    previous = None
    for event in package.get("custody_chain", []):
        required = ("timestamp", "action", "actor", "location",
                    "previous_hash", "event_hash")
        if any(field not in event for field in required):
            # A truncated event used to raise KeyError out of a function whose
            # contract is "return True/False"; a malformed chain is not valid.
            return False
        if not digests_equal(_event_hash(event), event["event_hash"]):
            return False
        if event["previous_hash"] != previous:
            return False
        previous = event["event_hash"]
    return True
