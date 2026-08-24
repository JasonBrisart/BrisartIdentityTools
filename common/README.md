# Common

Small, shared, dependency-free utilities used by all three tools
(`biometrics/`, `vault/`, `packages/`). Nothing here is specific to identity,
cryptography, or any one tool — it exists so the same handful of low-level
concerns (writing a file safely, hashing bytes, stamping a timestamp) aren't
reimplemented three times with three chances to get subtly different bugs in
each copy.

---

## Module map

### `atomic_io.py`
`atomic_write_text` / `atomic_write_json`: write-to-temp-file-then-`os.replace`
so a crash or power loss mid-write can never leave a half-written file
behind — a reader sees either the old file or the fully-written new one.
Flushes and fsyncs the temp file before the rename, and optionally fsyncs the
containing directory afterward (a no-op on Windows) for durability. Used by
every module in the repo that persists JSON state: identity records, vault
files, package files, audit/report logs.

### `hashing.py`
`sha256_bytes` / `sha256_file`: plain SHA-256 integrity digests, streamed in
1 MiB chunks for `sha256_file` so a large capture is never loaded whole into
memory. These are **integrity fingerprints only** — nowhere in this repo are
they used to protect a secret. Secret material (passphrases, template
vectors, package payloads) goes through the BSR2 factor and envelope layers
in `crypto/` instead.

### `timestamps.py`
Three UTC timestamp formats, each serving a different need:
- `utc_now()` — ISO-8601 to the second, for record `created_at`/`updated_at`.
- `filename_timestamp()` — filename-safe stamp to the second, for report/audit
  filenames.
- `microsecond_timestamp()` — filename-safe stamp with microsecond precision,
  for cases where two events in the same second must not collide on
  filename.

All timezone-aware UTC; there is no naive-local-time helper anywhere in this
module by design.

---

## Design note

None of these functions know anything about identities, vaults, or packages.
That's intentional — it's what makes them safe to share across all three
tools without creating a hidden coupling between them. If a change here ever
needs to special-case one tool's behavior, that's a sign the function belongs
in that tool's own module instead.
