# Integrity Ledger

An external, hash-chained ledger of periodic file checkpoints. Read this
before relying on it for anything real — the honest scope of what it does
and does not do is the entire point of this document.

---

## What problem this addresses

Every tamper-evidence mechanism already in this repository — BSR2's
authentication tag, `packages.custody`'s in-package hash chain, the external
audit logs in `vault/`, `biometrics/`, and `packages/` — only ever inspects a
file's **current state**. That is a structural property of comparing a
snapshot against itself, not a defect in any of them. It means a file that is
edited and then restored to its exact original bytes before the next
inspection leaves **no trace whatsoever** in any of those mechanisms.

The Integrity Ledger does not close that gap. It narrows it, and only by as
much as your checkpoint frequency allows.

## How it works

`tools/integrity_checkpoint.py checkpoint <file>` records that file's SHA-256
and size into an external, hash-chained ledger (`common/integrity_ledger.py`),
with a timestamp. Run it again later — by hand, or on a schedule (cron, a
Windows Scheduled Task) — and you get a second checkpoint.

If someone tampers with the file and reverts it **entirely between two of
your checkpoints**, this is indistinguishable from nothing having happened.
If a checkpoint happens to land **inside** the tamper window — before the
revert — that checkpoint's recorded hash will disagree with its neighbors,
and the history will show it, even after the file has been put back exactly
the way it was.

```text
checkpoint (hash A) --- TAMPER --- checkpoint (hash B, mid-tamper) --- REVERT --- checkpoint (hash A again)
                                          ^^^^^^^^^^^^^^^^^^^^^^^^
                                This is what exposes the tamper window.
```

**The smaller the gap between checkpoints, the smaller the window a
tamper-then-revert can hide in. It is never zero unless checkpoints are
continuous**, which this tool intentionally does not attempt to be — that
would mean either a persistent background process (this project runs none)
or a third-party scheduling dependency (this project takes none).

## What it does NOT do

- It cannot detect a tamper-then-revert that happens entirely between two
  checkpoints. See `common/integrity_ledger.py`'s module docstring for the
  full statement of this limitation.
- It does not protect its own ledger file's directory. Storing the ledger
  beside the data it watches, writable by the same untrusted party, defeats
  the purpose — put it somewhere only you (or your backup/audit process) can
  write to.
- It does not encrypt or seal anything. It records a plaintext SHA-256 and
  size only, the same non-secret integrity-fingerprint role
  `common.hashing` already plays everywhere else in this repository.

## CLI usage

```bash
# Record a checkpoint of any file this project produces
python tools/integrity_checkpoint.py checkpoint data/vault/vault.json --label "nightly cron"

# Compare a file's current hash against its most recent checkpoint
python tools/integrity_checkpoint.py status data/vault/vault.json

# See every checkpoint ever recorded for a file
python tools/integrity_checkpoint.py history data/vault/vault.json

# Verify the ledger's OWN hash chain hasn't been edited, deleted, or reordered
python tools/integrity_checkpoint.py verify

# List every file path currently tracked in a ledger
python tools/integrity_checkpoint.py list-tracked
```

All commands accept `--ledger <path>` to point at a specific ledger file
(default: `data/integrity/ledger.json`).

## Suggested use

Run `checkpoint` against your `vault.json`, your biometrics `keyring.json`,
and any package `.json` files you consider sensitive, on whatever cadence
your threat model calls for — nightly via cron/Task Scheduler is a reasonable
default for most labs. Keep the ledger file itself somewhere the same
untrusted parties who could tamper with your data cannot also write to.
