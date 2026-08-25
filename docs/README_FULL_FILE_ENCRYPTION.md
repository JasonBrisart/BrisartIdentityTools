# Full file / folder / drive encryption

BrisartIdentityTools can encrypt **any file** (any extension, no extension, any
binary content), and **any combination of files, folders, and whole drives** in
one operation, with automatic chunking so a single BSR2 envelope's size limit
is no longer a hard ceiling. This is available from both the CLI and the GUI.

**Read the "Real-world throughput" section below before encrypting anything
large — it changes what "drives" realistically means here.**

## The size limit this had to solve

BSR2's vendored envelope hard-caps a single sealed payload at **~16 MiB**
(`vendor/brisart_security_envelope.py`'s `MAX_PLAINTEXT_BYTES`;
`crypto/envelope.py`'s `MAX_PAYLOAD_BYTES` trims that slightly further for its
length-prefix and padding overhead). Calling `encrypt()` on anything larger
raises outright — no truncation, no silent failure, just a refusal.

**`vault/store/bulk_file_service.py`** and
**`biometrics/engine/bulk_attachments.py`** remove that ceiling with real
chunking: content is split into sealed chunks (default 8 MiB) plus one small
JSON manifest recording chunk order, total size, and a whole-content SHA-256.
Restoring reassembles the chunks in order and verifies that hash, so a missing
or corrupted chunk is caught immediately rather than silently returning
truncated data.

## What each file adds

| File | Role |
|---|---|
| `vault/store/bulk_file_service.py` | `BulkFileService`: chunked encrypt/decrypt of any size, plus `upsert_paths()`/`restore_paths()` — zips any mix of files/folders/drive roots into one bundle (preserving relative structure) before chunking. |
| `biometrics/engine/bulk_attachments.py` | Same chunking/bundling logic, biometrics-side, storing chunks as ordinary attachments named `{name}.chunk0`, `{name}.chunk1`, ... plus a `{name}.manifest`. |
| `vault/store/vault_service.py` | `upsert_file`/`upsert_file_bytes`/`get_file`/`get_file_bytes` for single files (sealed as raw bytes, never parsed as JSON). |
| `biometrics/engine/attachments.py` | Attach an arbitrary raw file to an identity, sealed under the same master key, byte-for-byte recoverable. |
| `vault/app.py` | CLI: `encrypt-file`, `decrypt-file`, `encrypt-paths` (multi-path, any size), `restore-paths`. |
| `biometrics/app.py` | CLI: `attach`, `attach-paths`, `extract-attachment`, `restore-paths`, `remove-attachment`. |
| `app.py`, `gui/tabs/`, `gui/widgets/path_panel.py` | The root application shell loads the Vault and Biometrics tabs. Their bulk-data workflows share the modular `PathSelectionPanel` for file, folder, and drive-root selection. |

File, folder, and drive-root selection in the GUI is provided by the shared
`gui/widgets/path_panel.py` component using Tkinter's standard picker dialogs.
The deleted `gui/windows_dnd.py` module is not part of the 1.2.0 GUI layout.

## Real-world throughput — read this before encrypting anything large

BSR2's pure-Python throughput is low by nature. Measured directly:

```text
Sealed   10 KB in 7.44s  → ~1,376 bytes/sec
Restored 10 KB in 6.93s  → ~1,479 bytes/sec