"""
package.py
----------
Create, load, save, verify and open Identity-Bound Packages (.ibp)
for the BETA prototype.

A package is bound to an *identity*, not a location. It can be copied
anywhere (USB, disc, archive server) and only opens when the holder
proves the required identity factors.

*** RESEARCH / DEMO ONLY ***
- This module does NOT encrypt the payload. Confidentiality is expected
  to be provided by a dedicated security framework (e.g. BSR2 from
  BrisartSecurityResearch) when required. IBP focuses purely on
  identity-based authorization, integrity checking, custody tracking,
  and audit logging.
- The "signature" is a shared-secret hash, NOT a real digital signature.
  Do not use this to protect real confidential data.
"""

import json
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from crypto import digests_equal, hash_text, hash_bytes
from custody import append_event, verify_chain
from verification import verify_identity
from audit import audit_event

PACKAGE_DIR = Path(__file__).parent / "packages"

PACKAGE_FORMAT = "IBP-BETA-0.3"

# Demo shared secret used for the prototype "signature".
# In a real system this would be a private signing key, never a constant.
SIGNER_SECRET = "ARCHIVE-LAB-DEMO"


# ---------------------------------------------------------------------------
# Signature (prototype integrity check, NOT a real digital signature)
# ---------------------------------------------------------------------------

def _sign(package: dict) -> str:
    core = {
        "format": package["format"],
        "package_id": package["package_id"],
        "recipient_policy": package["recipient_policy"],
        "payload_hash": package["payload_hash"],
    }
    blob = json.dumps(core, sort_keys=True) + SIGNER_SECRET
    return hash_text(blob)


def verify_signature(package: dict) -> bool:
    return digests_equal(_sign(package), package.get("signature"))


# ---------------------------------------------------------------------------
# Recipient policy (multi-recipient support)
# ---------------------------------------------------------------------------

def identity_authorized(package: dict, identity) -> bool:
    """
    Supports policy modes:
      ANY       -> identity must be one of the listed recipients
      ALL       -> (single-holder open) treated same as ANY at open time
      THRESHOLD -> (single-holder open) treated same as ANY at open time

    NOTE: ALL / THRESHOLD really need multi-party approval to be meaningful.
    In this single-user beta they behave like ANY. The field is stored so a
    future multi-approver flow can enforce it properly.
    """
    policy = package.get("recipient_policy") or {}
    recipients = policy.get("recipients") or []
    return identity.identity_id in recipients


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def create_package(recipients, message: str, actor: str = "system",
                    location: str = "origin", mode: str = "ANY",
                    required: int = 1) -> str:
    """
    Create a package bound to one or more recipient identity IDs.

    recipients : list[str] of identity_id values (or a single string)
    mode       : "ANY" | "ALL" | "THRESHOLD"
    required   : threshold count when mode == "THRESHOLD"

    NOTE: The payload is stored as plaintext. This prototype does not
    provide confidentiality - only identity-based authorization,
    integrity checking, custody tracking, and audit logging. Use a
    dedicated security framework (e.g. BSR2) if confidentiality is
    required.
    """
    if isinstance(recipients, str):
        recipients = [recipients]

    if not isinstance(message, str):
        raise ValueError("message must be a string.")

    if not recipients:
        # An empty recipient list produced a package that no identity could
        # ever open, with no error at creation time.
        raise ValueError("at least one recipient identity_id is required.")

    if mode not in ("ANY", "ALL", "THRESHOLD"):
        raise ValueError(
            "mode must be one of ANY, ALL, or THRESHOLD."
        )

    if mode == "THRESHOLD" and not 1 <= required <= len(recipients):
        raise ValueError(
            "required must be between 1 and the recipient count."
        )

    package_id = str(uuid.uuid4())
    payload_bytes = message.encode("utf-8")

    package = {
        "format": PACKAGE_FORMAT,
        "package_id": package_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "recipient_policy": {
            "mode": mode,
            "required": required,
            "recipients": recipients,
        },
        "payload_hash": hash_bytes(payload_bytes),
        "payload": message,
        "signature": "",
        "custody_chain": [],
    }
    package["signature"] = _sign(package)

    append_event(package, "PACKAGE_CREATED", actor, location)

    PACKAGE_DIR.mkdir(parents=True, exist_ok=True)
    out = PACKAGE_DIR / f"{package_id}.ibp"
    save_package(package, out)
    audit_event(f"CREATED package={package_id} recipients={recipients} mode={mode}")
    print(f"Package created: {out}")
    return str(out)


# ---------------------------------------------------------------------------
# Load / Save
# ---------------------------------------------------------------------------

def load_package(filepath: str) -> dict:
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def save_package(package: dict, filepath) -> None:
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(package, f, indent=4)


# ---------------------------------------------------------------------------
# Transfer (records a custody handoff)
# ---------------------------------------------------------------------------

def transfer_package(filepath: str, actor: str, location: str) -> None:
    package = load_package(filepath)
    append_event(package, "TRANSFERRED", actor, location)
    save_package(package, filepath)
    audit_event(f"TRANSFERRED package={package['package_id']} to={actor} @ {location}")
    print(f"Recorded transfer to {actor} @ {location}")


# ---------------------------------------------------------------------------
# Open
# ---------------------------------------------------------------------------

def open_package(filepath: str, identity, passphrase: str, voice_phrase: str,
                  actor: Optional[str] = None,
                  location: str = "open-station") -> str:
    """
    Full open pipeline. Raises on any failure. Returns plaintext on success.
    """
    package = load_package(filepath)
    pid = package["package_id"]
    actor = actor or identity.name

    if not verify_signature(package):
        audit_event(f"DENIED package={pid} reason=signature actor={actor}")
        raise ValueError("Signature verification failed (package altered).")

    if not verify_chain(package):
        audit_event(f"DENIED package={pid} reason=custody actor={actor}")
        raise ValueError("Custody chain is broken or tampered with.")

    if not identity_authorized(package, identity):
        audit_event(f"DENIED package={pid} reason=unauthorized actor={actor}")
        raise PermissionError("This identity is not an authorized recipient.")

    if not verify_identity(identity, passphrase, voice_phrase):
        audit_event(f"DENIED package={pid} reason=factors actor={actor}")
        raise PermissionError("Identity factor verification failed.")

    plaintext = package["payload"]
    if not digests_equal(
        hash_bytes(plaintext.encode("utf-8")),
        package.get("payload_hash"),
    ):
        audit_event(f"DENIED package={pid} reason=integrity actor={actor}")
        raise ValueError("Payload integrity check failed.")

    append_event(package, "PACKAGE_OPENED", actor, location)
    save_package(package, filepath)
    audit_event(f"OPENED package={pid} actor={actor} @ {location}")

    return plaintext
