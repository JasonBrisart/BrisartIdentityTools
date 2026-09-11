"""
File: common/integrity_ledger.py
Purpose:
    An external, hash-chained ledger of periodic file checkpoints, used to
    narrow (not close) the "edit a sealed file, then revert it to its
    original bytes before anyone checks" blind spot that every tamper-
    evidence mechanism already in this repository (BSR2's authentication
    tag, packages.custody's in-package hash chain, vault/biometrics/
    packages' external audit logs) shares by mathematical necessity: all
    of them only ever inspect a file's *current* state, so a file that is
    tampered with and then restored to its original bytes before the next
    inspection leaves no trace in any of them.

    This module does not, and cannot, close that gap completely -- see
    "What this does not do" below. What it adds is a way to record a
    file's SHA-256 at a point in time, external to the file itself, so
    that if a checkpoint happens to fall *inside* a tamper-then-revert
    window, that checkpoint's recorded hash will disagree with its
    neighbors and expose the gap. The narrower the time between
    checkpoints, the smaller the window a tamper-then-revert can hide in
    -- this is a mitigation whose effectiveness is a direct function of
    checkpoint frequency, not a guarantee.

    This is intentionally a general-purpose, target-path-agnostic ledger
    (not folded into vault/, biometrics/, or packages/ specifically) since
    every one of those tools stores its master-key-wrapped state in a
    single file (vault.json, biometrics/data/keyring.json, a package's
    .json file) that is exactly the kind of file this concern applies to,
    and duplicating this logic three times would only invite the three
    copies to drift.

What this DOES do:
    - Records a SHA-256 + size of a target file, chained to the previous
      entry's hash (the same hash-chain construction packages.custody
      already uses), so the LEDGER ITSELF is tamper-evident: deleting,
      reordering, or editing a past checkpoint entry is detectable via
      verify_ledger(), exactly the way packages.custody.verify_chain
      detects tampering with a custody chain.
    - Lets a lab compare a file's *current* hash against its most recent
      recorded checkpoint (current_status()), and inspect the full
      checkpoint history for a given path (history_for_path()).
    - Is meant to be run on a schedule external to this application (a
      cron job, a Windows Scheduled Task, or simply a habit of running it
      before/after sensitive operations) -- see tools/integrity_checkpoint.py.
      This module intentionally contains no scheduling, daemon, or
      background-thread logic of its own; adding one would mean either a
      persistent background process (which this project's tools do not
      run) or a third-party scheduling dependency (which this project does
      not take on).

What this does NOT do (stated plainly, the same way liveness.py and
KNOWN_ISSUES.md's KI-003 state their own scope limits rather than
implying more than they deliver):
    - It cannot detect a file that was tampered with and reverted to its
      exact original bytes ENTIRELY BETWEEN two checkpoints. If checkpoint
      N records hash H, an attacker edits the file and restores it to
      exactly H, and checkpoint N+1 also records H, nothing here or
      anywhere else in this repository can tell that anything happened in
      between. This is a mathematical property of comparing snapshots in
      time, not a defect in this implementation -- see this project's
      docs/BSR2_INTEGRATION.md Residual Risks list, to which this
      limitation is an explicit addition.
    - It does not protect the ledger file's own directory from an attacker
      who can also edit files there. Recording checkpoints in the same
      directory as the data they protect defeats the purpose. Per-entry
      hash chaining means an attacker who edits or deletes a past entry is
      caught by verify_ledger() -- but an attacker able to overwrite the
      ENTIRE ledger file with a new, internally-consistent, wholly
      fabricated chain (with no prior entries at all) cannot be
      distinguished from a legitimately short ledger. As with every other
      file in this project, the ledger's own protection is "keep it
      somewhere the people you don't trust cannot write to," not a
      cryptographic property of this module.
    - It does not seal, encrypt, or otherwise protect the CONTENTS of the
      files it checkpoints. It only records their SHA-256 and size,
      exactly the same non-secret integrity-fingerprint role
      common.hashing.sha256_bytes/sha256_file already plays everywhere
      else in this codebase (vault file records, biometrics attachments).

Communication relationships:
    Called by:
        - tools/integrity_checkpoint.py (new CLI script), which exposes
          checkpoint/status/history/verify as command-line subcommands
          meant to be invoked by an operator or an OS-level scheduler
          (cron, Windows Task Scheduler) against any file this project
          produces: a vault.json, a biometrics keyring.json, a package's
          .json file, or any other file a lab wants tracked.
    Calls out to:
        - common.hashing.sha256_file -- the same streamed, 1 MiB-chunk
          SHA-256 helper already used for biometrics attachment hashing
          and vault file-record hashing, so a large tracked file is never
          loaded whole into memory.
        - common.atomic_io.atomic_write_json -- every ledger write goes
          through the same atomic write-then-rename primitive the rest of
          this project uses, so a crash mid-write cannot leave a
          half-written or corrupt ledger behind.
        - common.timestamps.utc_now_iso -- for each entry's "recorded_at"
          field.
    Does not depend on:
        - crypto/ or vendor/ (no BSR2 involved). This ledger's own
          integrity comes from a plain SHA-256 hash chain, the same
          mechanism packages.custody already uses for the exact same
          "detect if a past entry was edited, deleted, or reordered"
          property -- BSR2's authenticated encryption solves a different
          problem (confidentiality + current-state authentication) that
          this module does not need and intentionally does not duplicate.

Parameters / settings:
    LEDGER_FORMAT (str):
        A version-tagged format marker ("brisart-identity-tools/
        integrity-ledger/v1") stored at the top of every ledger file and
        required by _validate_state(). Lets a future reader, or a future
        version of this module, distinguish this file's shape from any
        later revision without guessing from field presence alone --
        the same convention every other stored format in this repository
        (vault file, package file, keyring) already follows.
    GENESIS_PREVIOUS_HASH (str):
        "0" * 64, the same sentinel value packages.custody.
        GENESIS_PREVIOUS_HASH uses for a chain's very first entry, kept
        identical here so the same "what does entry zero point back to"
        convention holds across both hash-chained structures in this
        codebase.

Edge-case behavior:
    - append_checkpoint() requires the target file to exist and be
      readable; a missing or unreadable target raises
      IntegrityLedgerError rather than silently recording a checkpoint
      for a file that was not actually inspected.
    - A ledger file that does not yet exist is treated as a brand-new,
      empty ledger by append_checkpoint() (mirroring how
      vault.store.vault_file / packages.package treat a first write), not
      as an error -- the very first checkpoint against a fresh ledger path
      creates it.
    - verify_ledger() on an empty ledger (a ledger file that exists but
      whose "entries" list is empty) returns True with no work to do,
      matching the "nothing to verify yet" case rather than treating an
      empty ledger as malformed.
    - history_for_path() and current_status() both normalize target_path
      through str(Path(target_path)) before comparing, so the same file
      referenced with a different (but equivalent) path spelling --
      e.g. "./data/vault/vault.json" vs "data/vault/vault.json" -- is
      still recognized as the same tracked target. This does NOT resolve
      symlinks or relative-vs-absolute differences across working
      directories; a lab that moves between invoking this from different
      directories should pass a consistent, ideally absolute, path.
    - A checkpoint's "sha256" and "size_bytes" fields describe the
      target file's content at checkpoint time; they are never used to
      derive or protect a secret, exactly as with every other plaintext
      integrity fingerprint already present in this repository (vault
      file-record metadata, biometrics attachment metadata).
"""
import json
from pathlib import Path

from common.atomic_io import atomic_write_json
from common.hashing import sha256_bytes, sha256_file
from common.timestamps import utc_now_iso

LEDGER_FORMAT = "brisart-identity-tools/integrity-ledger/v1"
GENESIS_PREVIOUS_HASH = "0" * 64


class IntegrityLedgerError(ValueError):
    """Raised when a ledger cannot be read, written, or fails verification,
    or when a checkpoint cannot be recorded."""


def _entry_hash(previous_hash, target_path, sha256, size_bytes, actor_label, recorded_at):
    canonical = json.dumps(
        {
            "previous_hash": previous_hash,
            "target_path": target_path,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "actor_label": actor_label,
            "recorded_at": recorded_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256_bytes(canonical)


def _empty_state():
    return {"format": LEDGER_FORMAT, "entries": []}


def _validate_state(state):
    if not isinstance(state, dict):
        raise IntegrityLedgerError("ledger state must be an object.")
    if state.get("format") != LEDGER_FORMAT:
        raise IntegrityLedgerError("unsupported integrity ledger format.")
    if not isinstance(state.get("entries"), list):
        raise IntegrityLedgerError("ledger entries must be a list.")
    return state


def _load_state(ledger_path):
    path = Path(ledger_path)
    if not path.is_file():
        return _empty_state()
    try:
        with path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrityLedgerError(f"ledger file could not be read: {exc}") from exc
    return _validate_state(state)


def _save_state(ledger_path, state):
    atomic_write_json(Path(ledger_path), state)


def append_checkpoint(ledger_path, target_path, actor_label=""):
    """Record a new checkpoint of target_path's current SHA-256 into the
    ledger at ledger_path, chained to the ledger's previous entry.

    Returns the newly appended entry (a dict). Raises
    IntegrityLedgerError if target_path does not exist or cannot be read,
    or if the existing ledger file fails validation.
    """
    resolved_target = Path(target_path)
    if not resolved_target.is_file():
        raise IntegrityLedgerError(f"no file found to checkpoint at {resolved_target}.")
    try:
        digest = sha256_file(resolved_target)
        size_bytes = resolved_target.stat().st_size
    except OSError as exc:
        raise IntegrityLedgerError(f"could not read {resolved_target}: {exc}") from exc

    state = _load_state(ledger_path)
    previous_hash = state["entries"][-1]["entry_hash"] if state["entries"] else GENESIS_PREVIOUS_HASH
    recorded_at = utc_now_iso()
    target_path_text = str(resolved_target)
    entry_hash = _entry_hash(previous_hash, target_path_text, digest, size_bytes, actor_label, recorded_at)
    entry = {
        "previous_hash": previous_hash,
        "entry_hash": entry_hash,
        "target_path": target_path_text,
        "sha256": digest,
        "size_bytes": size_bytes,
        "actor_label": actor_label,
        "recorded_at": recorded_at,
    }
    state["entries"].append(entry)
    _save_state(ledger_path, state)
    return entry


def verify_ledger(ledger_path):
    """Verify that every entry in the ledger at ledger_path correctly
    chains to the one before it, and that no entry's recorded fields have
    been altered since it was appended.

    Returns True if the chain is intact (including the trivial case of an
    empty ledger). Raises IntegrityLedgerError naming the first broken or
    tampered entry otherwise.

    This verifies the LEDGER's own integrity -- that its recorded history
    has not been edited, deleted, or reordered -- not whether any tracked
    target file currently matches its most recent checkpoint. Use
    current_status() for that comparison.
    """
    state = _load_state(ledger_path)
    expected_previous = GENESIS_PREVIOUS_HASH
    for index, entry in enumerate(state["entries"]):
        if not isinstance(entry, dict):
            raise IntegrityLedgerError(f"ledger entry {index} is not an object.")
        if entry.get("previous_hash") != expected_previous:
            raise IntegrityLedgerError(
                f"ledger is broken at entry {index}: previous_hash does not "
                "match the prior entry's recorded hash."
            )
        recomputed = _entry_hash(
            entry.get("previous_hash"),
            entry.get("target_path"),
            entry.get("sha256"),
            entry.get("size_bytes"),
            entry.get("actor_label"),
            entry.get("recorded_at"),
        )
        if recomputed != entry.get("entry_hash"):
            raise IntegrityLedgerError(
                f"ledger entry {index} has been tampered with: stored hash "
                "does not match its recomputed content."
            )
        expected_previous = entry["entry_hash"]
    return True


def history_for_path(ledger_path, target_path):
    """Return every checkpoint entry recorded for target_path, oldest
    first, without verifying the ledger's chain integrity first (call
    verify_ledger() separately if that assurance is needed).
    """
    state = _load_state(ledger_path)
    target_text = str(Path(target_path))
    return [entry for entry in state["entries"] if entry.get("target_path") == target_text]


def current_status(ledger_path, target_path):
    """Compare target_path's CURRENT SHA-256 against its most recent
    recorded checkpoint in the ledger at ledger_path.

    Returns a dict:
        {
            "target_path": str,
            "current_sha256": str or None (None if the target file does
                not currently exist),
            "latest_checkpoint": the most recent matching entry, or None
                if target_path has never been checkpointed,
            "matches_latest_checkpoint": bool or None (None if there is no
                prior checkpoint to compare against),
        }

    A True matches_latest_checkpoint means the file's current bytes are
    identical to what was recorded at the last checkpoint -- it does NOT
    mean the file was never touched in between; see this module's
    docstring for why that distinction matters.
    """
    resolved_target = Path(target_path)
    current_sha256 = sha256_file(resolved_target) if resolved_target.is_file() else None
    entries = history_for_path(ledger_path, target_path)
    latest = entries[-1] if entries else None
    matches = None
    if latest is not None and current_sha256 is not None:
        matches = (current_sha256 == latest["sha256"])
    return {
        "target_path": str(resolved_target),
        "current_sha256": current_sha256,
        "latest_checkpoint": latest,
        "matches_latest_checkpoint": matches,
    }


def all_entries(ledger_path):
    """Return every entry in the ledger at ledger_path, oldest first, with
    no filtering and no chain verification. Use verify_ledger() first if
    chain integrity needs to be confirmed before trusting these entries."""
    return list(_load_state(ledger_path)["entries"])


def list_tracked_paths(ledger_path):
    """Return every distinct target_path that has at least one checkpoint
    recorded in the ledger at ledger_path, sorted."""
    state = _load_state(ledger_path)
    return sorted({entry.get("target_path") for entry in state["entries"] if entry.get("target_path")})
