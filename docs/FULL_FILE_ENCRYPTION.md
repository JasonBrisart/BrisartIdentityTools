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
| `app.py`, `gui/tabs/tab_vault.py`, `gui/tabs/tab_biometrics.py`, `gui/widgets/path_panel.py` | The root `app.py` shell loads the Vault and Biometrics tabs. The Vault tab has a "Files / Folders / Drives" sub-tab; the Biometrics tab has a "File Attachments" sub-tab. Both share the modular `PathSelectionPanel` (multi-select files, folder picker, and an "Add Drive..." shortcut, all via `tkinter.filedialog`). |

File/folder/drive selection in the GUI is provided by the shared
`gui/widgets/path_panel.py` component using `tkinter.filedialog`'s standard
picker dialogs. Native Windows drag-and-drop is not part of the current GUI
layout (the earlier `gui/windows_dnd.py` module was removed in 1.2.0).

## Real-world throughput — read this before encrypting anything large

BSR2's pure-Python throughput is low by nature. Measured directly:

```text
Sealed   10 KB in 7.44s  → ~1,376 bytes/sec
Restored 10 KB in 6.93s  → ~1,479 bytes/sec
```

This is inherent to BSR2's vendored primitives (`stream_bytes` calls a full
sponge-based `keyed_mac` every 64 bytes of output, and each of those runs dozens
of permutation rounds in plain Python with no hardware acceleration), not the
chunking layer. At ~1.4 KB/s:

| Size | Estimated time (seal only) |
|---|---|
| 1 MB | ~13 minutes |
| 100 MB | ~21 hours |
| 1 GB | ~9 days |
| A real hard drive (100s of GB–TBs) | weeks to months |

**What this means practically:** chunking removes the *architectural* 16 MiB
ceiling — proven by real, passing round-trip tests. But the *practical* ceiling
for "drives" is now throughput, not a hard limit. This is realistically a tool
for individual files, documents, photo collections, and folders up to tens of
MB in a reasonable amount of time — not a "back up my whole 2 TB drive tonight"
tool, unless you are prepared to let it run for a very long time. The
"unlimited size" framing is accurate about the mechanism, not about speed.

## Test coverage

Covered by passing round-trip tests (real BSR2, not mocked):

- Biometrics-side chunked attach/restore across multiple chunks + manifest — round-trips exactly.
- Biometrics-side mixed file+folder bundle (including a no-extension file inside a nested folder) — bundles and restores with structure intact.
- Bulk-removal cleans up every chunk + manifest.
- Vault-side chunking round-trips exactly, with the measured throughput above.
- A direct `seal_bytes()` call on 17 MB genuinely raises (confirms the envelope limit).
- `zipfile`-based bundling of a standalone file plus folders — correct structure and content, verified byte-for-byte.

See `vault/tests/test_bulk_file_service.py`, `vault/tests/test_file_records.py`,
and `biometrics/tests/test_attachments.py`.

## CLI usage

```bash
# Vault: any combination of files/folders/drives, any size
python -m vault.app --vault v.json encrypt-paths ./report.pdf ./Photos "D:\"
python -m vault.app --vault v.json restore-paths <record_id> ./restored_output

# Biometrics: same, attached to an identity
python cli.py biometrics attach-paths alice my-bundle ./report.pdf ./Photos
python cli.py biometrics restore-paths alice my-bundle ./restored_output

# Single files (auto-chunks if needed)
python -m vault.app --vault v.json encrypt-file ./anything_at_all
python cli.py biometrics attach alice ./anything_at_all
```

## GUI usage

```bash
python app.py
```

Open the **Vault** tab's "Files / Folders / Drives" sub-tab, or the
**Biometrics** tab's "File Attachments" sub-tab, to run the same
encrypt/restore workflows through the shared `PathSelectionPanel` instead of
the CLI.
