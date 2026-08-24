"""Identity-Bound Package orchestration: create, add/remove recipients, open.

Ties together every other module in ``packages/``:

* :mod:`packages.ciphers` for content-key generation and per-recipient key
  slot sealing/unwrapping,
* :mod:`packages.identity` for recipient descriptor shape,
* :mod:`packages.verification` for the fast "does this key belong to this
  recipient" check before touching a key slot,
* :mod:`packages.custody` for the package's own tamper-evident history,
* :mod:`packages.audit` for an external, durable trail of package events.

A package's on-disk/in-memory state is a single JSON-serialisable dict with
four parts: identifying metadata, the sealed payload, a map of recipient key
slots, and the custody chain. Nothing here performs file I/O directly --
persistence is left to the caller (typically ``main.py``), matching the
separation ``vault.store.vault_service`` keeps from ``vault.store.vault_file``.
"""
from crypto.errors import Bsr2IntegrationError
from packages import audit, ciphers, custody
# BUG FIX (2026-08-24): this previously also imported RecipientIdentityError
# and validate_identity_id from packages.identity, neither of which is
# referenced anywhere in this file (only new_recipient is actually called).
# Ruff's pyflakes rule (F401, enabled in pyproject.toml's `select`) flags
# unused imports and fails the lint job.
from packages.identity import new_recipient
from packages.verification import build_recipient_verifier, verify_recipient_master_key

PACKAGE_FORMAT = "brisart-identity-tools/ibp-package/v1"


class PackageError(ValueError):
    """Raised for malformed package state or invalid arguments."""


class PackageAuthorizationError(ValueError):
    """Raised when a supplied master key does not match the recipient it
    claims to belong to.

    Deliberately distinct from a key-slot authentication failure
    (:class:`crypto.errors.EnvelopeAuthenticationError`): this is caught
    earlier, before any key slot is touched, using the recipient verifier
    from ``verification.py``.
    """


def create_package(package_id: str, creator_label: str, payload: dict, recipients: dict, audit_dir=None) -> dict:
    """Create a new package sealed for an initial set of recipients.

    ``recipients`` maps ``identity_id -> (label, master_key)`` tuples. At
    least one recipient is required, since a package with zero recipients
    can never be opened by anyone.
    """
    if not isinstance(package_id, str) or not package_id:
        raise PackageError("package_id must be a non-empty string.")
    if not recipients:
        raise PackageError("at least one recipient is required.")

    content_key = ciphers.new_content_key()
    sealed_payload = ciphers.seal_payload(content_key, package_id, payload)

    key_slots = {}
    recipient_descriptors = {}
    for identity_id, (label, master_key) in recipients.items():
        descriptor = new_recipient(identity_id, label)
        verifier = build_recipient_verifier(master_key, identity_id)
        wrapped = ciphers.wrap_content_key(master_key, package_id, identity_id, content_key)
        recipient_descriptors[identity_id] = {**descriptor, "verifier": verifier}
        key_slots[identity_id] = wrapped

    chain = custody.new_chain(creator_label, package_id)

    state = {
        "format": PACKAGE_FORMAT,
        "package_id": package_id,
        "recipients": recipient_descriptors,
        "key_slots": key_slots,
        "payload": sealed_payload,
        "custody_chain": chain,
    }

    if audit_dir is not None:
        audit.record_event(audit_dir, "created", package_id, creator_label)

    return state


def validate_package(state: dict) -> dict:
    """Validate a package's shape, raising :class:`PackageError` on failure."""
    if not isinstance(state, dict):
        raise PackageError("package state must be an object.")
    if state.get("format") != PACKAGE_FORMAT:
        raise PackageError("unsupported package format.")
    if not isinstance(state.get("package_id"), str) or not state["package_id"]:
        raise PackageError("package_id must be a non-empty string.")
    if not isinstance(state.get("recipients"), dict):
        raise PackageError("recipients must be an object.")
    if not isinstance(state.get("key_slots"), dict):
        raise PackageError("key_slots must be an object.")
    if set(state["recipients"]) != set(state["key_slots"]):
        raise PackageError("recipients and key_slots must have matching identity ids.")
    if not isinstance(state.get("payload"), dict):
        raise PackageError("payload must be an object.")
    if not isinstance(state.get("custody_chain"), list) or not state["custody_chain"]:
        raise PackageError("custody_chain must be a non-empty list.")

    custody.verify_chain(state["custody_chain"], state["package_id"])
    return state


def add_recipient(state: dict, identity_id: str, label: str, master_key: bytes, opener_identity_id: str, opener_master_key: bytes, audit_dir=None) -> dict:
    """Add a new recipient to an existing package.

    The caller must supply an existing, authorized recipient's identity and
    master key (``opener_identity_id``/``opener_master_key``) to recover the
    content key -- a package's content key is never derivable from the
    package state alone, so adding a recipient always requires an existing
    one to authorize it.
    """
    state = validate_package(state)
    if identity_id in state["recipients"]:
        raise PackageError(f"recipient {identity_id!r} is already in this package.")

    content_key = _authorized_content_key(state, opener_identity_id, opener_master_key)

    descriptor = new_recipient(identity_id, label)
    verifier = build_recipient_verifier(master_key, identity_id)
    wrapped = ciphers.wrap_content_key(master_key, state["package_id"], identity_id, content_key)

    updated = dict(state)
    updated["recipients"] = dict(state["recipients"])
    updated["recipients"][identity_id] = {**descriptor, "verifier": verifier}
    updated["key_slots"] = dict(state["key_slots"])
    updated["key_slots"][identity_id] = wrapped
    updated["custody_chain"] = custody.append(
        state["custody_chain"], "recipient_added", label, {"identity_id": identity_id}
    )

    if audit_dir is not None:
        audit.record_event(audit_dir, "recipient_added", state["package_id"], label)

    return updated


def remove_recipient(state: dict, identity_id: str, opener_identity_id: str, opener_master_key: bytes, audit_dir=None) -> dict:
    """Remove a recipient from an existing package.

    The removed recipient's key slot is deleted; their master key (which the
    package never stored anyway) no longer opens this package. The payload
    is not re-encrypted and no other recipient's slot is touched.
    """
    state = validate_package(state)
    if identity_id not in state["recipients"]:
        raise PackageError(f"recipient {identity_id!r} is not in this package.")
    if len(state["recipients"]) == 1:
        raise PackageError(
            "cannot remove the last recipient; a package must always have "
            "at least one."
        )

    # Authorization check: the opener must themselves be an existing,
    # verified recipient, even if they are not the one being removed.
    _authorized_content_key(state, opener_identity_id, opener_master_key)

    removed_label = state["recipients"][identity_id]["label"]

    updated = dict(state)
    updated["recipients"] = dict(state["recipients"])
    del updated["recipients"][identity_id]
    updated["key_slots"] = dict(state["key_slots"])
    del updated["key_slots"][identity_id]
    updated["custody_chain"] = custody.append(
        state["custody_chain"], "recipient_removed", removed_label, {"identity_id": identity_id}
    )

    if audit_dir is not None:
        audit.record_event(audit_dir, "recipient_removed", state["package_id"], removed_label)

    return updated


def _authorized_content_key(state: dict, identity_id: str, master_key: bytes) -> bytes:
    """Verify a recipient and recover the content key, or raise."""
    recipient = state["recipients"].get(identity_id)
    if recipient is None:
        raise PackageAuthorizationError(
            f"{identity_id!r} is not a recipient of this package."
        )
    if not verify_recipient_master_key(master_key, identity_id, recipient["verifier"]):
        raise PackageAuthorizationError(
            f"the supplied master key does not match recipient {identity_id!r}."
        )
    wrapped = state["key_slots"][identity_id]
    try:
        return ciphers.unwrap_content_key(master_key, state["package_id"], identity_id, wrapped)
    except Bsr2IntegrationError as exc:
        raise PackageAuthorizationError(
            f"key slot for {identity_id!r} failed to authenticate: {exc}"
        ) from exc


def open_package(state: dict, identity_id: str, master_key: bytes, audit_dir=None) -> dict:
    """Open a package's payload as an authorized recipient.

    Returns ``(payload, updated_state)`` where ``updated_state`` has an
    ``"opened"`` entry appended to its custody chain. The caller is
    responsible for persisting ``updated_state`` if the custody record
    should be kept.
    """
    state = validate_package(state)
    try:
        content_key = _authorized_content_key(state, identity_id, master_key)
    except PackageAuthorizationError:
        if audit_dir is not None:
            audit.record_event(audit_dir, "open_denied", state["package_id"], identity_id)
        raise

    payload = ciphers.open_payload(content_key, state["package_id"], state["payload"])

    label = state["recipients"][identity_id]["label"]
    updated_state = dict(state)
    updated_state["custody_chain"] = custody.append(
        state["custody_chain"], "opened", label, {"identity_id": identity_id}
    )

    if audit_dir is not None:
        audit.record_event(audit_dir, "opened", state["package_id"], label)

    return payload, updated_state


def list_recipients(state: dict) -> list:
    """List every recipient's non-secret descriptor (id and label only)."""
    state = validate_package(state)
    return sorted(
        (
            {"identity_id": identity_id, "label": recipient["label"]}
            for identity_id, recipient in state["recipients"].items()
        ),
        key=lambda item: item["identity_id"],
    )


def custody_summary(state: dict) -> list:
    """A compact, display-friendly summary of the package's custody history."""
    return custody.summarize(state["custody_chain"])
