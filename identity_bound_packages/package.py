"""
package.py
----------
Create, load, save, verify and open Identity-Bound Packages (.ibp).

A package is bound to an *identity*, not a location. It can be copied anywhere
(USB, disc, archive server) and only opens when the holder proves the required
identity factors.

Payload confidentiality
-----------------------
The payload is encrypted with BSR2. Because BSR2 is symmetric and this project
takes no third-party dependencies, there is no public-key mechanism available to
seal a payload *to* a recipient the creator cannot currently unlock. The
consequence is stated plainly rather than hidden: **creating an encrypted package
requires every recipient's identity to be unlocked at creation time.**

To support more than one recipient without encrypting the payload repeatedly, a
package uses a two-level scheme:

* a random per-package *content key* encrypts the payload once
* that content key is then wrapped once per recipient, under each recipient's
  master key

Opening reverses it: unlock your identity, unwrap the content key from your own
slot, decrypt the payload. Adding a recipient later requires an unlocked identity
for that recipient, which is a real limitation of symmetric-only crypto and not
an oversight.

The ``signature`` field remains a shared-secret hash, not a real digital
signature, and still should not be relied on to prove origin.
"""

import json
import secrets
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from audit import audit_event  # noqa: E402
from brisart_bsr2 import envelope as _envelope  # noqa: E402
from brisart_bsr2.context import key_slot_context, package_context  # noqa: E402
from brisart_bsr2.errors import Bsr2IntegrationError  # noqa: E402
from brisart_bsr2.rng import new_generator  # noqa: E402
from crypto import digests_equal, hash_bytes, hash_text  # noqa: E402
from custody import append_event, verify_chain  # noqa: E402
from verification import verify_identity  # noqa: E402

PACKAGE_DIR = Path(__file__).parent / "packages"

PACKAGE_FORMAT = "IBP-0.4-BSR2"
LEGACY_PLAINTEXT_FORMAT = "IBP-BETA-0.3"

CONTENT_KEY_BYTES = 32

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
    # Covering the wrapped content keys means a recipient slot cannot be added,
    # removed, or swapped without invalidating the signature.
    if "key_slots" in package:
        core["key_slots"] = package["key_slots"]
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
# Content key wrapping
# ---------------------------------------------------------------------------

def _wrap_content_key(
    master_key: bytes, package_id: str, identity_id: str, content_key: bytes
) -> dict:
    """Seal the content key for one recipient, bound to package and recipient."""
    return _envelope.seal_bytes(
        master_key,
        content_key,
        key_slot_context(package_id, identity_id),
        new_generator("ibp-key-slot"),
    )


def _unwrap_content_key(
    master_key: bytes, package_id: str, identity_id: str, slot: dict
) -> bytes:
    content_key = _envelope.open_bytes(
        master_key, slot, key_slot_context(package_id, identity_id)
    )
    if len(content_key) != CONTENT_KEY_BYTES:
        raise Bsr2IntegrationError("unwrapped content key has an invalid length.")
    return content_key


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def create_package(recipients, message: str, actor: str = "system",
                    location: str = "origin", mode: str = "ANY",
                    required: int = 1, unlocked_identities=None) -> str:
    """
    Create an encrypted package bound to one or more recipient identities.

    recipients          : list[str] of identity_id values (or a single string)
    mode                : "ANY" | "ALL" | "THRESHOLD"
    required            : threshold count when mode == "THRESHOLD"
    unlocked_identities : unlocked IdentityProfile objects, one per recipient

    Every recipient needs an unlocked identity here, because a symmetric scheme
    cannot wrap a key to an identity the creator cannot open. See the module
    docstring.
    """
    if isinstance(recipients, str):
        recipients = [recipients]

    if not isinstance(message, str):
        raise ValueError("message must be a string.")

    if not recipients:
        # An empty recipient list produced a package that no identity could
        # ever open, with no error at creation time.
        raise ValueError("at least one recipient identity_id is required.")

    if len(set(recipients)) != len(recipients):
        raise ValueError("recipient identity_id values must be unique.")

    if mode not in ("ANY", "ALL", "THRESHOLD"):
        raise ValueError(
            "mode must be one of ANY, ALL, or THRESHOLD."
        )

    if mode == "THRESHOLD" and not 1 <= required <= len(recipients):
        raise ValueError(
            "required must be between 1 and the recipient count."
        )

    if not unlocked_identities:
        raise ValueError(
            "unlocked_identities is required: an encrypted package needs each "
            "recipient's master key to wrap the content key."
        )

    by_id = {}
    for candidate in unlocked_identities:
        if not candidate.is_unlocked:
            raise ValueError(
                f"identity {candidate.identity_id} is locked; unlock it before "
                "creating a package."
            )
        by_id[candidate.identity_id] = candidate

    missing = [rid for rid in recipients if rid not in by_id]
    if missing:
        raise ValueError(
            "no unlocked identity supplied for recipients: "
            f"{', '.join(missing)}"
        )

    package_id = str(uuid.uuid4())
    payload_bytes = message.encode("utf-8")

    content_key = secrets.token_bytes(CONTENT_KEY_BYTES)

    sealed_payload = _envelope.seal_bytes(
        content_key,
        payload_bytes,
        package_context(package_id),
        new_generator("ibp-payload"),
    )

    key_slots = {
        rid: _wrap_content_key(
            by_id[rid].master_key, package_id, rid, content_key
        )
        for rid in recipients
    }

    package = {
        "format": PACKAGE_FORMAT,
        "package_id": package_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "recipient_policy": {
            "mode": mode,
            "required": required,
            "recipients": recipients,
        },
        # Integrity digest over the *plaintext*, checked after decryption. The
        # envelope already authenticates the ciphertext; this catches a mismatch
        # between what was sealed and what was intended.
        "payload_hash": hash_bytes(payload_bytes),
        "sealed_payload": sealed_payload,
        "key_slots": key_slots,
        "signature": "",
        "custody_chain": [],
    }
    package["signature"] = _sign(package)

    append_event(package, "PACKAGE_CREATED", actor, location)

    PACKAGE_DIR.mkdir(parents=True, exist_ok=True)
    out = PACKAGE_DIR / f"{package_id}.ibp"
    save_package(package, out)
    audit_event(
        f"CREATED package={package_id} recipients={recipients} mode={mode}"
    )
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


def is_encrypted_package(package: dict) -> bool:
    """Report whether a loaded package uses the BSR2 sealed format."""
    return isinstance(package, dict) and "sealed_payload" in package


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
                  location: str = "open-station",
                  face_template: Optional[str] = None,
                  fingerprint_template: Optional[str] = None) -> str:
    """
    Full open pipeline. Raises on any failure. Returns plaintext on success.

    Order matters: cheap structural checks run before the expensive factor
    verification, so a tampered package is rejected without paying for a BSR2
    passphrase derivation.
    """
    package = load_package(filepath)
    pid = package["package_id"]
    actor = actor or identity.name

    if package.get("format") == LEGACY_PLAINTEXT_FORMAT:
        audit_event(f"DENIED package={pid} reason=legacy_plaintext actor={actor}")
        raise ValueError(
            "This package uses the pre-BSR2 plaintext format. Re-create it with "
            "the current version; its payload was never encrypted."
        )

    if not is_encrypted_package(package):
        audit_event(f"DENIED package={pid} reason=missing_payload actor={actor}")
        raise ValueError("Package has no sealed payload.")

    if not verify_signature(package):
        audit_event(f"DENIED package={pid} reason=signature actor={actor}")
        raise ValueError("Signature verification failed (package altered).")

    if not verify_chain(package):
        audit_event(f"DENIED package={pid} reason=custody actor={actor}")
        raise ValueError("Custody chain is broken or tampered with.")

    if not identity_authorized(package, identity):
        audit_event(f"DENIED package={pid} reason=unauthorized actor={actor}")
        raise PermissionError("This identity is not an authorized recipient.")

    slot = (package.get("key_slots") or {}).get(identity.identity_id)
    if slot is None:
        audit_event(f"DENIED package={pid} reason=no_key_slot actor={actor}")
        raise PermissionError("No key slot for this identity in this package.")

    if not verify_identity(
        identity,
        passphrase,
        voice_phrase,
        face_template=face_template,
        fingerprint_template=fingerprint_template,
    ):
        audit_event(f"DENIED package={pid} reason=factors actor={actor}")
        raise PermissionError("Identity factor verification failed.")

    try:
        content_key = _unwrap_content_key(
            identity.master_key, pid, identity.identity_id, slot
        )
        plaintext_bytes = _envelope.open_bytes(
            content_key, package["sealed_payload"], package_context(pid)
        )
    except Exception as exc:
        audit_event(f"DENIED package={pid} reason=decrypt actor={actor}")
        raise ValueError("Payload decryption failed (package altered).") from exc

    plaintext = plaintext_bytes.decode("utf-8")

    if not digests_equal(
        hash_bytes(plaintext_bytes),
        package.get("payload_hash"),
    ):
        audit_event(f"DENIED package={pid} reason=integrity actor={actor}")
        raise ValueError("Payload integrity check failed.")

    append_event(package, "PACKAGE_OPENED", actor, location)
    save_package(package, filepath)
    audit_event(f"OPENED package={pid} actor={actor} @ {location}")

    return plaintext
