# Full file/folder/drive encryption + GUI + drag-and-drop

Everything requested is here and drop-in ready: any file (any extension, no
extension, any content), multi-select, drag-and-drop (Windows), zips,
folders, and drive roots -- all combinable in one operation, with automatic
chunking so size is no longer a hard limit. **Read the "Real-world
throughput" section below before encrypting anything large — it changes
what "drives" realistically means here.**

## The wall this had to solve

BSR2's vendored envelope hard-caps a single sealed payload at **~16 MiB**
(`vendor/brisart_security_envelope.py`'s `MAX_PLAINTEXT_BYTES`). Calling
`encrypt()` on anything bigger raises outright — no truncation, no silent
failure, just a refusal. I verified this directly: a raw `seal_bytes()`
call on 17 MB throws every time.

That means "encrypt my whole drive" was previously impossible past 16 MB.
**New `vault/store/bulk_file_service.py` and
`biometrics/engine/bulk_attachments.py`** solve this with real chunking:
content is split into sealed chunks (default 8 MiB) plus one small JSON
manifest recording chunk order, total size, and a whole-content SHA-256.
Restoring reassembles the chunks in order and verifies that hash — so a
missing or corrupted chunk is caught immediately instead of silently
returning truncated data (I tested this exact failure mode directly).

## What's new, file by file

| File | What it adds |
|---|---|
| `vault/store/bulk_file_service.py` | **New.** `BulkFileService`: chunked encrypt/decrypt of any size, plus `upsert_paths()`/`restore_paths()` — zips any mix of files/folders/drive roots into one bundle (preserving relative structure) before chunking. |
| `biometrics/engine/bulk_attachments.py` | **New.** Same chunking/bundling logic, biometrics-side, storing chunks as ordinary attachments named `{name}.chunk0`, `{name}.chunk1`, ... plus a `{name}.manifest`. |
| `vault/store/vault_service.py` | Modified (from last delivery) — unchanged from before, still has `upsert_file`/`get_file` for single files under 16 MB. |
| `vault/app.py` | Full CLI: added `encrypt-paths` (multi-path, any size) and `restore-paths`. |
| `biometrics/app.py` | **Full real rewrite** (not a patch this time) — your actual enroll/verify/inspect logic preserved verbatim, plus new `attach`, `attach-paths`, `extract-attachment`, `restore-paths`, `remove-attachment` commands. |
| `biometrics/identity/identity_record.py` | Adds the `attachments` dict (unchanged from last delivery). |
| `gui/app.py` | **Full real rewrite** of your actual 1250-line GUI. Vault tab gets a new "Files / Folders / Drives" sub-tab; Biometrics tab gets a new "File Attachments" sub-tab. Both use a shared `PathSelectionPanel` (multi-select via `askopenfilenames`, folder via `askdirectory`, "Add Drive..." shortcut, drag-and-drop). Vault/Biometrics/Packages tab logic is otherwise untouched. |
| `gui/windows_dnd.py` | **New.** Best-effort native Windows drag-and-drop using only `ctypes` (stdlib, zero dependencies) — see its own docstring for the full honest caveat. |
| `crypto/context.py` | Adds `attachment_context()` (unchanged from last delivery). |
| `vault/tests/test_bulk_file_service.py`, `biometrics/tests/test_attachments.py` | New/updated test files, all passing. |

## Real-world throughput — read this before encrypting anything large

I measured BSR2's actual pure-Python throughput directly in testing:

```
Sealed 10KB in 7.44s   → ~1,376 bytes/sec
Restored 10KB in 6.93s → ~1,479 bytes/sec
```

That's not a bug in anything I built — it's inherent to BSR2's vendored
primitives (`stream_bytes` calls a full sponge-based `keyed_mac` every 64
bytes of output; each of *those* calls runs dozens of 16-word permutation
rounds, all in plain Python with no hardware acceleration). At ~1.4 KB/s:

| Size | Estimated time (seal only) |
|---|---|
| 1 MB | ~13 minutes |
| 100 MB | ~21 hours |
| 1 GB | ~9 days |
| A real hard drive (100s of GB–TBs) | weeks to months |

**What this means practically:** the chunking mechanism I built is
correct and removes the *architectural* 16 MB ceiling — I proved this with
real, passing round-trip tests (see below). But the *practical* ceiling
for "drives" is now throughput, not a hard limit. This is realistically a
tool for individual files, documents, photo collections, and folders up to
maybe tens of MB in a reasonable amount of time — not a "back up my whole
2 TB drive tonight" tool, unless you're prepared to let it run for a very
long time. I'm flagging this prominently rather than letting the
"unlimited size" framing imply speed it doesn't have.

## What I actually tested (and what I didn't)

**Fully tested, passing, real crypto (not mocked):**
- Biometrics-side chunked attach/restore (300 KB across 2 chunks + manifest) — round-trips exactly
- Biometrics-side mixed file+folder bundle (3 files, nested folder) — bundles, restores with structure intact
- Bulk-removal cleans up every chunk + manifest correctly
- Vault-side chunking at small scale (10 KB, 50 KB) — round-trips exactly, with real measured throughput above
- A direct `seal_bytes()` call on 17 MB genuinely raises (confirms the wall is real)
- `zipfile`-based bundling of a standalone file + two folders (including a no-extension file inside a folder) — correct structure, correct content, verified byte-for-byte

**Not fully tested — and why:**
- **A complete 18 MB vault-side round trip** — I started this, watched it run for 20+ minutes of genuine CPU-bound work, and killed it once the throughput math became clear rather than let it run indefinitely. The *mechanism* is identical to what the biometrics-side test already proved at smaller scale (same `seal_bytes`/`open_bytes` calls, same manifest/reassembly logic) — I'm confident in correctness, just didn't run this exact size to completion.
- **The GUI itself, at all** — this sandbox has no `_tkinter` C extension whatsoever (not a missing display, the module genuinely isn't installed), so no Tk widget can be instantiated here. Every GUI file is syntax-checked clean, but I cannot show you a screenshot or confirm click-by-click behavior. Please treat the GUI as "written correctly against the real API, needs your own smoke-test."
- **Drag-and-drop, live** — same root cause. `gui/windows_dnd.py` implements a real, documented technique (subclassing the window procedure to intercept `WM_DROPFILES`) using only `ctypes`, with everything wrapped in defensive `try/except` so a failure never crashes the window — it just silently falls back to the "Add Files..."/"Add Folder..." buttons, which **are** guaranteed to work (they're just `tkinter.filedialog`). Please test the actual drag-and-drop on your machine and tell me if anything's off.

## New CLI usage

```bash
# Vault: any combination of files/folders/drives, any size
python -m vault.app --vault v.json encrypt-paths ./report.pdf ./Photos "D:\"
python -m vault.app --vault v.json restore-paths <record_id> ./restored_output

# Biometrics: same, attached to an identity
python cli.py biometrics attach-paths alice my-bundle ./report.pdf ./Photos
python cli.py biometrics restore-paths alice my-bundle ./restored_output

# Single files (existing, still works, auto-chunks if needed)
python -m vault.app --vault v.json encrypt-file ./anything_at_all
python cli.py biometrics attach alice ./anything_at_all
```

## How to apply

Copy every file in this package over your real repo at the same relative
paths. `gui/app.py` and `biometrics/app.py` are **full replacements** this
time (not patches) — your existing enroll/verify/inspect/keyring logic and
Vault/Packages tab logic are preserved exactly, with the new
files/folders/drives functionality added alongside.
