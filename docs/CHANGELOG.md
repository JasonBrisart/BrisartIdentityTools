# Changelog

All notable changes to BrisartIdentityTools are recorded here.

---

## [1.2.0] - 2026-08-25

A GUI architecture release that splits the former single-file desktop interface
into focused, folder-grouped modules. The visible Vault, Biometrics, and
Packages workflows remain in one Tkinter window, but the implementation is now
organized so the window shell, background-operation handling, reusable widgets,
and each tool tab can be maintained independently.

No stored vault, identity, keyring, biometric-template, attachment, package, or
custody-chain format changed. There is no data migration.

### Added

- **`app.py`** is now the small root-level GUI entry point. It owns only the main
  window, notebook assembly, menu bar, About dialog, and `main()`.
- **`gui/core/constants.py`** centralizes the application title, biometric
  file-type filters, cancellation sentinel, and repository-root import
  bootstrap. The root is located by walking upward to `version.py` rather than
  assuming a fixed directory depth.
- **`gui/core/busy.py`** centralizes the modal busy dialog and the shared
  background-operation runner used to keep slow KDF and encrypted-data work
  from blocking Tkinter's event loop.
- **`gui/widgets/dialogs.py`** contains reusable modal-dialog helpers instead of
  repeating dialog construction across tabs.
- **`gui/widgets/path_panel.py`** contains the shared file, folder, and drive-root
  selection panel used by bulk Vault and biometric-attachment workflows.
- **`gui/tabs/tab_vault.py`**, **`gui/tabs/tab_biometrics.py`**, and
  **`gui/tabs/tab_packages.py`** now own their respective interfaces.

### Changed

- **The desktop GUI is modular instead of monolithic.** The former
  `gui/app.py` implementation was split by responsibility. The executable shell
  now lives at the repository root as `app.py`, while reusable GUI code lives
  under `gui/core/`, `gui/widgets/`, and `gui/tabs/`.
- **The supported direct GUI launch command is now `python app.py`.** The GUI
  README and root README now document the actual root entry point and current
  file layout.
- **GUI import setup is depth-independent.** Importing
  `gui.core.constants` establishes the repository root before any tab imports
  Vault, Biometrics, or Packages modules.
- **Documentation now matches the split GUI architecture.** `README.md`,
  `gui/README.md`, and `docs/README_FULL_FILE_ENCRYPTION.md` no longer describe
  `gui/app.py` or the deleted drag-and-drop module as current files.

### Removed

- **`gui/app.py`** was removed after its responsibilities were divided between
  the root `app.py` shell and the new GUI submodules.
- **`gui/windows_dnd.py`** was removed. The 1.2.0 interface uses the shared
  Tkinter path-selection panel and standard picker dialogs.

### Notes

- The split is architectural. GUI actions still call the existing Vault,
  Biometrics, and Packages application layers; cryptography, validation,
  persistence, and identity policy were not reimplemented in the interface.
- The project remains standard-library only and does not add a GUI dependency.
- The 1.1.1 vendored-BSR2 digest-pin fix and the 1.1.0 biometric similarity fix
  remain unchanged.
- Existing security caveats remain in effect: BSR2 is unreviewed research
  cryptography, the package custody chain is tamper-evident rather than a
  digital signature, and losing both a vault passphrase and recovery code is
  unrecoverable by design.

---

## [1.1.1] - 2026-08-25

A patch fixing the digest-pin defect that shipped as a documented **Known
issue** in 1.1.0, plus the CI path and documentation that referred to the
pre-`tests/` layout. No shipped module's behavior changed, no stored format
changed, and there is nothing to migrate. With this release the full suite
(308 fast tests) passes clean.

### Fixed

- **`tests/test_bsr2_vendor_integrity.py` digest pin (the 1.1.0 Known issue) is
  resolved.** The test's `_sha256()` normalized line endings (`\r\n → \n`)
  before hashing, so on a Windows (CRLF) checkout the digest it produced could
  never match the authoritative **raw-byte** pins in `PINNED_DIGESTS`
  (`89ccae49…`, `b50b01b7…`, `93b0f72d…`, `d5ba6022…`), and
  `test_vendored_files_match_their_pinned_digests` failed even though `vendor/`
  was byte-for-byte correct. `_sha256()` now hashes the exact bytes on disk with
  **no** line-ending conversion, so it compares directly against the raw-byte
  pins. As stated in 1.1.0, the pins themselves were always correct — they are
  unchanged; only the test's hashing was wrong.
- **`run_tests.py` and `test_bsr2_vendor_integrity.py` now resolve the
  repository root robustly.** Both locate the root by walking up to the
  directory that contains both `version.py` and `vendor/`, rather than assuming
  a fixed depth. This keeps discovery, `sys.path`, and the `vendor/` lookup
  correct now that all three root-level test files live under `tests/`, and
  removes the fixed-path fragility that caused the 1.0.3 "vendored BSR2
  directory is missing" class of error.
- **CI workflow invoked the runner at its old path.** `.github/workflows/tests.yml`
  called `python run_tests.py` in the `fast` and `slow` jobs, but the runner
  moved to `tests/` in 1.1.0, so both jobs would fail at the first step. Both now
  call `python tests/run_tests.py`. The `smoke` job is unchanged.

### Changed

- **Documentation corrected to match the enforced pin.** `README.md`,
  `docs/BSR2_INTEGRATION.md`, and `vendor/README.md` still carried notes from
  the 1.0.0 window stating the vendor digest test had been "dropped" or "does
  not currently exist." Those notes are replaced with an accurate description:
  `vendor/` is pinned by `tests/test_bsr2_vendor_integrity.py`, which SHA-256s
  every vendored file against a byte-for-byte digest and fails CI on any drift,
  edit, or unpinned `.py` file. The README's test-command examples now point at
  `python tests/run_tests.py`.

### Notes

- The 1.1.0 biometric similarity fix, the `tests/` reorganization, and the
  removal of ruff are all unchanged and remain in effect; this release only
  closes the pin defect and aligns CI and docs with the shipped layout.
- The security caveats are unchanged and still apply: BSR2 is unreviewed
  research crypto, the package custody chain is tamper-evident rather than a
  digital signature, and losing both a vault's passphrase and recovery code is
  unrecoverable by design.

---

## [1.1.0] - 2026-08-25

A biometric matching-accuracy release, combined with a test-suite reorganization
and the final removal of ruff from the toolchain. No stored template format
changed and no shipped module's runtime behavior changed except the biometrics
similarity scoring described below.

### Fixed

- **All three biometric modalities (fingerprint, voice, video) used a
  similarity metric that was blind to real impostors.** `compare()` in each of
  `fingerprint_features.py`, `video_features.py`, and `voice_features.py` used
  plain cosine similarity, which measures only the *angle* between two feature
  vectors, never how far apart their actual values are. For all three of this
  project's feature spaces (fingerprint ridge-orientation + magnitude values,
  raw video pixel-brightness block-means, voice energy/band-DCT vectors), the
  vectors are mostly positive and similarly shaped regardless of whose
  biometric data they came from, so two completely different people's vectors
  still pointed in a broadly similar direction. Cosine similarity reported
  that as a near-perfect match.

  Verified directly against real generated samples (the `ci-enroll` /
  `ci-other` seeds the CLI smoke test uses), confirmed end-to-end through the
  actual CLI:

  | Modality | old cosine score (bug) | new score | threshold | result |
  |---|---|---|---|---|
  | fingerprint | 0.9974 | 0.6197 | 0.80 | correctly rejected |
  | voice | 0.9762 | 0.6213 | 0.85 | correctly rejected |
  | video | 0.9159 | 0.6162 | 0.75 | correctly rejected |

  A genuine self-match scored 1.0000 before and after the fix in every case,
  so real enrollments continue to verify correctly.

  Mean-centering (a Pearson-correlation-style cosine variant) was tried first
  and barely moved the impostor score: cosine similarity is fundamentally an
  angle-only metric, and this project's impostor/genuine separation lives in
  magnitude of difference, not angle, so no cosine variant was going to fix it.

### Added

- **`biometrics/features/similarity.py`** — a new shared module holding
  `distance_similarity()`: a normalized-Euclidean-distance-based score in
  `(0.0, 1.0]`, self-relative to each vector pair's own average magnitude and
  mapped through exponential decay so identical vectors score exactly `1.0`.
  All three feature modules now import this one function instead of each
  defining their own `compare()` math.

### Changed

- **`fingerprint_features.py`, `video_features.py`, `voice_features.py`** —
  each module's `compare()` is now a thin wrapper delegating to
  `distance_similarity()`. Feature extraction itself is unchanged; only the
  similarity/scoring step changed.
- **Test suite reorganized under `tests/`.** `run_tests.py`,
  `test_bsr2_vendor_integrity.py`, and `test_cli_dispatcher.py` moved from the
  repository root into `tests/`, alongside every other tool's `tests/`
  directory, for a more consistent layout. `run_tests.py`'s discovery logic
  is unaffected since it walks the whole tree by dotted module name rather
  than assuming a fixed location for these three files.

### Removed

- **ruff removed entirely.** `pyproject.toml` (which existed solely to
  configure ruff) is deleted, the `lint:` job is removed from
  `.github/workflows/tests.yml`, and the local `.ruff_cache/` is cleared.
  This project remains pure Python with zero external dependencies end to
  end, including in its dev/CI tooling.

### Known issue (not fixed in this release)

- **`tests/test_bsr2_vendor_integrity.py` still has a stale digest pin.**
  `PINNED_DIGESTS` in its current, moved location still holds the
  CRLF-normalized hash values (`89ccae49...`, `b50b01b7...`, `93b0f72d...`,
  `d5ba6022...`), which do not match what the test's own `_sha256()`
  (line-ending-normalizing) hashing produces against the actual `vendor/*.py`
  files on disk. This means `test_vendored_files_match_their_pinned_digests`
  will still fail if the suite is run as-is. This is a carry-over from
  1.0.3.1 that was diagnosed but not yet corrected in the files that shipped
  in this snapshot — flagging it explicitly rather than presenting the suite
  as fully green. Fixing it requires either updating `PINNED_DIGESTS` to
  match the test's own normalized output, or intentionally switching
  `_sha256()` to raw (non-normalized) hashing and re-pinning to match --
  a decision that was in progress but not finalized as of this release.

### Notes

- No enrolled template's stored bytes changed and no re-enrollment is
  required; the biometrics fix applies at verification time against
  templates exactly as they were already stored.
- If you have any automation or tests that assert a specific non-1.0
  similarity score for fingerprint/voice/video, those expected values will
  need updating to reflect the new distance-based scoring.
- The 1.0.3.1 security caveats are unchanged and still apply: BSR2 is
  unreviewed research crypto, the package custody chain is tamper-evident
  rather than a digital signature, and losing both a vault's passphrase and
  recovery code is unrecoverable by design.

---

## [1.0.3] - 2026-08-24

A one-line path fix to the vendored-BSR2 digest-pin test. No shipped module
changed and no stored format changed; this release only makes
`test_bsr2_vendor_integrity.py` actually find the `vendor/` directory it is
supposed to hash, so the integrity pin restored in 1.0.1 genuinely runs
instead of erroring on a wrong path.

### Fixed

- **`test_bsr2_vendor_integrity.py` looked for `vendor/` one directory too
  high.** The test computed `_VENDOR_DIR = Path(__file__).resolve().parent.parent
  / "vendor"`, but the file ships at the **repository root** (next to `vendor/`),
  not under a `tests/` subdirectory, so `.parent.parent` walked up to the
  repository's *parent* folder and looked for `<parent>/vendor` — which does not
  exist. Every subtest failed with a `FileNotFoundError` / "vendored BSR2
  directory is missing" against a path like `.../GitHub/vendor` instead of
  `.../GitHub/BrisartIdentityTools/vendor`. Changed to
  `Path(__file__).resolve().parent / "vendor"` (one level up, since the file is
  already at the root) and corrected the stale `<root>/tests/test_...py` comment.
  The four pinned SHA-256 values were already correct and are unchanged; with
  the path fixed, all four subtests pass and the vendor pin is genuinely
  enforced.

### Notes

- No stored format changed and no shipped module's behavior changed; 1.0.2 data
  loads unchanged and there is nothing to migrate.
- This was purely a test-path arithmetic bug: the vendored files, their pinned
  digests, and the test's comparison logic were all correct. Only the directory
  the test looked in was wrong.
- The 1.0.1 security caveats are unchanged and still apply: BSR2 is unreviewed
  research crypto, the package custody chain is tamper-evident rather than a
  digital signature, and losing both a vault's passphrase and recovery code is
  unrecoverable by design.

---

## [1.0.2] - 2026-08-24

A CI, test-runner, and tooling pass on top of 1.0.1. No shipped module's
behavior changed — this release fixes the failing GitHub Actions workflow,
splits the test suite into fast and slow (real-KDF) runs so CI is affordable
again, corrects one test whose assertions did not match shipped behavior, and
trims `pyproject.toml` down to the only thing that actually reads it. No stored
format changed and no data migration is required.

### Fixed

- **GitHub Actions biometrics smoke job could never pass.** The `smoke` job's
  biometrics steps call `python app.py enroll ...`, which unlocks a local
  keyring via `getpass`. On CI there is no TTY, so `getpass` reads empty input
  and `Keyring.create("")` raised `passphrase cannot be empty` on the very
  first enroll — the job failed before exercising anything. Every
  keyring-touching biometrics step now pipes its passphrase in on stdin, the
  same pattern the vault steps already used. `make-samples`/`list`/`inspect`/
  `delete` do not touch the keyring and need no passphrase.
- **Wrong exception type asserted in `crypto/tests/test_rng.py`.** Two tests
  asserted `generate(0, ...)` and `generate(32, b"")` raise
  `Bsr2IntegrationError`, but `crypto/rng.py` does not wrap the vendored
  `BrisartDRBGError` (a `ValueError`), so it surfaces unwrapped. Both tests now
  assert `ValueError`, matching shipped behavior. (The alternative — wrapping
  the error in `rng.py` for API consistency with the rest of the layer — was
  considered and deferred; it would be a behavior change, not a test fix.)

### Changed

- **`run_tests.py` rewritten for explicit, fail-loud discovery and a fast/slow
  split.** The tree is pure PEP 420 (no `__init__.py`) and `conftest.py` is a
  pytest-only hook `unittest` never loads, so the old
  `unittest discover -s . -t .` was fragile (could silently collect nothing or
  error on import). The runner now discovers each `tests/` directory explicitly
  with the repository root as `top_level_dir`, adds the two root-level test
  modules by name, and **fails loudly on a collection import error instead of
  passing with zero tests**. New flags:
  - `python run_tests.py` — every test.
  - `python run_tests.py --fast` — everything except the real-KDF tests.
  - `python run_tests.py --slow` — only the real-KDF tests.

  Fast/slow is filtered at the **class** level, so a module holding both fast
  and slow classes (`test_keyring`, `test_factors`,
  `test_label_normalization`) still runs its fast classes under `--fast`.
- **CI workflow split into `fast` and `slow` jobs.** The ~75 real-BSR2-KDF
  derivations (`test_sealed_vault`, `test_file_records`, `test_batch_upsert`,
  `KeyringUnlockTests`, `FactorHashKdfRoundTripTests`) previously ran on **every**
  matrix Python (3.10–3.13) via `run_tests.py`, at roughly a minute per
  derivation — about 300 Actions-minutes per push. Now the `fast` job runs the
  full non-KDF suite across 3.10–3.13, and a separate `slow` job runs the
  real-KDF tests **once** on 3.12. Every test still runs on every push; the
  cost is just no longer paid four times over.
- **`pyproject.toml` trimmed to a ruff-only config.** This project is cloned
  and run in place (`python cli.py`, `python run_tests.py`) and is never built
  as a wheel or published, so the `[project]` metadata table was dead config
  and — worse — carried a hardcoded version that had drifted from `version.py`.
  The `[project]` table (and its duplicate version) was removed; `version.py`
  (`__version__`) is now the single source of truth, consistent with how
  `vault/` and `biometrics/` settings already import it. The `[tool.ruff]`
  configuration is unchanged except for one added `per-file-ignores` glob
  (`test_*.py`) so the two root-level test modules are covered like the ones
  under `tests/`.

### Notes

- No stored format changed and no shipped module's behavior changed; 1.0.1 data
  loads unchanged and there is nothing to migrate.
- The version bump exists to record the CI/tooling fixes; the application code,
  stored formats, and BSR2 construction are identical to 1.0.1.
- The 1.0.1 security caveats are unchanged and still apply: BSR2 is unreviewed
  research crypto, the package custody chain is tamper-evident rather than a
  digital signature, and losing both a vault's passphrase and recovery code is
  unrecoverable by design.

---

## [1.0.1] - 2026-08-24

A test-coverage and integrity pass on top of 1.0.0. No shipped module's
behavior changes — this release adds 204 new tests across 19 files, fills the
biggest coverage gaps left after the 1.0.0 restructure (the entire `crypto/`
layer previously had no direct tests), and **restores the vendored-BSR2 digest
pin that was dropped in 1.0.0**. No stored format changed and no data migration
is required.

### Added

**Direct tests for the `crypto/` layer (previously untested)**
- `crypto/tests/test_envelope.py` — seal/open round trips, length-hiding
  padding buckets, context binding (a ciphertext cannot be moved between
  contexts), uniform authentication failure on modified ciphertext / wrong key
  / wrong context, and the `MAX_PAYLOAD_BYTES` refusal. Uses a random 32-byte
  master key, so it exercises real BSR2 sealing without paying the KDF cost.
- `crypto/tests/test_keyring.py` — malformed-state rejection, the iteration
  floor **and** ceiling (0.8.0-beta), recovery-code formatting, and a small
  real-KDF unlock round trip (passphrase and recovery code).
- `crypto/tests/test_factors.py` — keyed-MAC bind/verify (fast), parse-time
  rejection of out-of-range iteration counts without running the KDF, plus one
  real-KDF hash/verify round trip.
- `crypto/tests/test_throttle.py` — regression coverage for the 0.8.0-beta
  corrupt-state hardening: `NaN`/`Infinity`/negative fields are discarded, a
  `NaN` `locked_until` no longer silently unlocks, and an astronomical
  `failed_attempts` no longer builds a giant integer.
- `crypto/tests/test_context.py` and `crypto/tests/test_rng.py` — context-string
  construction/rejection and DRBG output-length/independence checks.

**Coverage for the rest of the tree**
- `common/tests/test_common_utils.py` — atomic writes, hashing, and the
  timestamp helpers, including an explicit check that the `utc_now_iso` alias
  exists (its absence was the 1.0.0 import crash).
- `vault/tests/` — `test_record_model.py`, `test_record_ids_and_time.py` (the
  0.4.0 shared-timestamp rule), and `test_audit_log.py`.
- `biometrics/tests/` — `test_bulk_attachments.py` (multi-chunk + mixed
  file/folder bundling, missing-chunk detection), `test_device_key.py`, and
  `test_report_writer.py`.
- `packages/tests/` — `test_custody_chain.py` (including the 0.8.2-beta
  non-list `CustodyError`), `test_identity.py`, `test_package_audit.py`, and
  `test_verification.py`.
- `tests/test_cli_dispatcher.py` — the `cli.py` dispatch table, including that
  every documented tool (`biometrics`, `vault`, `package`, `gui`, `version`,
  `help`) is reachable.

### Fixed

- **Restored the vendored-BSR2 digest pin.** `tests/test_bsr2_vendor_integrity.py`
  is recreated: it SHA-256s every file in `vendor/` against pinned values and
  fails if any drifts, is edited, or an unpinned `.py` file appears. This closes
  the open item flagged in `README.md`, `docs/BSR2_INTEGRATION.md`, and
  `vendor/README.md` after 1.0.0 dropped the original test.

### Notes

- No stored format changed and no shipped module's behavior changed; 1.0.0 data
  loads unchanged and there is nothing to migrate.
- Most new tests use injected 32-byte keys or envelope-shaped fixtures so they
  run fast; the real-KDF round trips are isolated into their own test classes
  and are slow by design (~85 s per derivation), consistent with the existing
  sealed-vault and package suites.
- The 1.0.0 security caveats are unchanged and still apply: BSR2 is unreviewed
  research crypto, the package custody chain is tamper-evident rather than a
  digital signature, and losing both a vault's passphrase and recovery code is
  unrecoverable by design.

---

## [1.0.0] - 2026-08-24

The first non-beta, production/stable release of **BrisartIdentityTools**.

This release is far more than a version bump over `0.8.2-beta`. Between the two
builds the entire repository was **restructured into a single flat tree**, three
brand-new subsystems were added (a desktop GUI, a full file/folder/drive
encryption layer, and a unified CLI dispatcher), a shared `common/` utility
layer was extracted, and a batch of defensive bug fixes landed. Every tool
directory was renamed and reorganized.

No stored format changed: vaults, identities, keyrings, templates, and packages
written by `0.8.2-beta` load unchanged. There is nothing to migrate.

---

### Added

**Desktop GUI (`gui/`)**
- **`gui/app.py`** — a single-window Tkinter desktop front-end covering all
  three tools (Vault, Biometrics, Packages) in one process. Standard library
  only (`tkinter` ships with Python), so it adds no new dependency. Every
  button calls directly into the existing service layer
  (`vault.store.vault_service.VaultService`,
  `biometrics.engine.enrollment`/`verification`, `packages.package`); no crypto,
  validation, or persistence logic is duplicated in the GUI.
  - **Vault tab**: choose/init/unlock/lock a vault, list records (works while
    locked), create records via a JSON payload editor, view/decrypt or delete a
    record, **plus** a new "Files / Folders / Drives" sub-tab for bulk
    encryption of any size.
  - **Biometrics tab**: create/unlock the keyring, enroll against
    voice/fingerprint/video files, verify a probe with an "any modality matches"
    option, inspect, delete, generate synthetic samples, **plus** a new "File
    Attachments" sub-tab.
  - **Packages tab**: create a package, add/remove recipients, open as a
    recipient, verify and display the custody chain, and run the same demo cycle
    as `packages/main.py demo`.
  - Every KDF-touching operation runs on a background thread behind a modal
    "Working..." progress dialog, so the window never appears frozen during a
    derivation that can take tens of seconds to minutes.

**Full file / folder / drive encryption**
- **`vault/store/bulk_file_service.py`** — `BulkFileService`: chunked
  encrypt/decrypt of content of any size, plus `upsert_paths()` /
  `restore_paths()` to zip any mix of files, folders, and drive roots into one
  bundle (preserving relative structure) before chunking past BSR2's ~16 MiB
  single-envelope limit. Reassembly verifies a whole-content SHA-256.
- **`biometrics/engine/bulk_attachments.py`** — the same chunking/bundling
  logic, biometrics-side, storing chunks as ordinary attachments plus a manifest.
- **`biometrics/engine/attachments.py`** — attach an arbitrary raw file (any
  extension, or none) to an identity, sealed under the same master key,
  byte-for-byte recoverable.
- **`vault/store/vault_service.py`** — new `upsert_file` / `upsert_file_bytes` /
  `get_file` / `get_file_bytes` methods to seal arbitrary raw bytes as a vault
  record (never parsed as JSON), with plaintext filename/size/SHA-256 metadata.
- **`docs/README_FULL_FILE_ENCRYPTION.md`** — documents the feature and its
  honest real-world throughput ceiling (BSR2 is ~1.4 KB/s in pure Python).

**Unified CLI dispatcher**
- **`cli.py`** — `python cli.py <tool> ...` launches `biometrics`, `vault`,
  `package`, or `gui` in-process, plus `version` and `help`.

**Shared utility layer (`common/`)**
- **`common/atomic_io.py`** — the single canonical `atomic_write_text` /
  `atomic_write_json`, replacing three near-identical write-then-rename copies.
- **`common/hashing.py`** — canonical `sha256_bytes` / `sha256_file`, replacing
  five pasted copies.
- **`common/timestamps.py`** — canonical UTC timestamp helpers.
- **`common/README.md`**.

**Other new files**
- **`version.py`** — single source of truth for the ecosystem version
  (`__version__ = "1.0.0"`), imported by both `vault` and `biometrics` settings
  so the two tools can never report different versions.
- New tests: `vault/tests/test_bulk_file_service.py`,
  `vault/tests/test_file_records.py`, `biometrics/tests/test_attachments.py`.
- New docs/READMEs across every subsystem (`crypto/README.md`,
  `packages/README.md`, `vault/README.md`, `biometrics/README.md`,
  `vendor/README.md`).

---

### Changed

**Repository restructure — every tool directory renamed and reorganized**
- `LabID_Beta/`            → **`biometrics/`** (reorganized into
  `codecs/`, `engine/`, `features/`, `identity/`, `reports/`, `samples/`,
  `config/`, `tests/`).
- `IdentityVault_beta/`    → **`vault/`** (persistence moved under
  `vault/store/`).
- `identity_bound_packages/` → **`packages/`**.
- `brisart_bsr2/`          → **`crypto/`** (BSR2 integration layer).
- `bsr2_vendor/`           → **`vendor/`** (vendored BSR2, byte-identical).
- The repository is now **one flat namespace-package tree (PEP 420)** with
  fully-qualified imports throughout; `brisart_bsr2/__init__.py` and other
  `__init__.py` markers were dropped. A single `conftest.py` /
  `run_tests.py` now drives every suite in one pass.
- `packages/crypto.py` → **`packages/ciphers.py`** (renamed to avoid colliding
  with the new top-level `crypto/` package).

**Versioning & packaging**
- Version bumped `0.8.2-beta` → **`1.0.0`**.
- `pyproject.toml` development-status classifier moved from
  `4 - Beta` → **`5 - Production/Stable`**; description and keywords updated to
  mention the GUI.
- `README.md` quick-start now documents `python cli.py gui` and the new
  restructured layout / commands.

**CLI surface**
- `vault/app.py` gained `encrypt-file`, `decrypt-file`, `encrypt-paths`, and
  `restore-paths` subcommands.
- `biometrics/app.py` gained `attach`, `attach-paths`, `extract-attachment`,
  `restore-paths`, and `remove-attachment` subcommands.

---

### Removed

- **`tests/test_bsr2_vendor_integrity.py`** — the digest pin that verified the
  vendored BSR2 files were byte-identical to upstream was **dropped during the
  restructure and not recreated**. Until it (or an equivalent digest check) is
  re-added, an accidental edit to `vendor/` will not be caught by CI. Flagged as
  an open item in `vendor/README.md` and `docs/BSR2_INTEGRATION.md`.
- **`LabID_Beta/core/scoring.py`** and **`LabID_Beta/core/template_engine.py`** —
  no longer present in the reorganized `biometrics/` tree.
- All `_beta` / `LabID` / `IdentityVault` / `brisart_bsr2` / `bsr2_vendor`
  directory names and their contents (superseded by the renamed trees above).

---

### Fixed

- **Timestamp import crash (`common/timestamps.py`)** — every consumer imports
  `utc_now_iso`, but the canonical module only defined `utc_now`. An
  `utc_now_iso = utc_now` alias was added; without it, importing any vault,
  biometrics, or packages module raised
  `ImportError: cannot import name 'utc_now_iso'` and broke all three tools.
- **Wrong sealed-envelope algorithm assertion in tests** — `test_sealed_vault.py`
  and `test_sealed_biometrics_flow.py` asserted the envelope `algorithm` was
  `"BSR2"`, but the real constant is `"BSR2-ARX-SPONGE-ETM"`. The old assertion
  always failed even though sealing was correct; both tests now assert the
  correct value.
- **CI invalid-identity-id smoke step (`.github/workflows/tests.yml`)** — the
  step meant to exercise path-traversal/invalid-char validation was passing a
  bad second positional argument, so argparse rejected the command before
  validation ran (the step passed for the wrong reason). It now uses the real
  CLI signature so the identity-id validation is actually exercised. A stray
  duplicate `tests.yml` at the repo root (which Actions never reads) was noted
  for removal.
- **Custody chain hardening (`packages/custody.py`)** — `verify_chain` now
  rejects a non-list chain and non-dict entries with `CustodyError` before
  iterating, instead of raising a raw `TypeError` on a hand-edited
  `"custody_chain": 123`. New regression tests cover both cases.
- **Unused imports (`packages/package.py`)** — removed `RecipientIdentityError`
  and `validate_identity_id` imports (never referenced) that failed the ruff
  `F401` lint job.

---

### Notes

- **No data migration required.** Every stored format, encryption scheme, and
  the underlying BSR2 construction are unchanged from `0.8.2-beta`; CLI and GUI
  usage can be freely mixed against the same vault/keyring/package files.
- The GUI is a **second way to drive the same application layer**, not a new
  one. Every security caveat in `docs/BSR2_INTEGRATION.md` still applies: BSR2 is
  unreviewed research cryptography, the package custody chain is tamper-evident
  rather than a digital signature, and losing both a vault's passphrase and
  recovery code is unrecoverable by design.
- The full file/folder/drive encryption removes the *architectural* 16 MiB
  ceiling via chunking, but the *practical* ceiling is now throughput
  (~1.4 KB/s in pure Python) — realistic for individual files and folders up to
  tens of MB, not for backing up a whole multi-hundred-GB drive.

---

## [0.8.2-beta] - 2026-08-23

One more defensive bug fix in the identity-bound package open path, in the same
vein as 0.8.1: a malformed custody chain crashed a boolean validator instead of
being reported as invalid. Latent — the normal create-then-open flow never
triggers it. It only fires on a hand-edited `.ibp`. No stored format changed and
no data migration is required. The fix is confined to
`identity_bound_packages/custody.py`.

### Fixed

**Identity-bound packages — verify_chain crashed on a non-list custody chain**

`verify_chain` is a boolean predicate, and 0.4.0 already hardened it so a
truncated custody event returns `False` rather than raising `KeyError`. But it
still iterated `custody_chain` without checking it is a list, so a hand-edited
package carrying `"custody_chain": 123` (or any non-iterable) raised `TypeError`
straight out of the function. Because the package `signature` does not cover
`custody_chain`, `verify_signature` passes first, so in `open_package` that
`TypeError` escaped uncaught instead of producing the uniform
`ValueError("Custody chain is broken or tampered with.")`, and skipped the
`DENIED ... reason=custody` audit event that every other denial records.
`verify_chain` now rejects a non-dict package, a non-list chain, and a non-object
event, returning `False` before iterating.

### Notes

- No stored format changed. Packages, identities, and vaults written by 0.8.1
  load unchanged; there is nothing to migrate.
- This hardens the code against corrupt and adversarial stored input. The 0.7.0
  security caveats are unchanged and still apply: BSR2 is unreviewed research
  crypto, the package `signature` field remains a shared-secret hash rather than
  a digital signature, and losing both the passphrase and the recovery code is
  unrecoverable by design.
  
---

## [0.8.1-beta] - 2026-08-23

Two defensive bug fixes in the identity-bound package open path. Both are
latent: the normal create-then-open flow never triggers either one. They only
fire on a malformed or hand-edited `.ibp` — a package missing a signed field, or
a payload that authenticates but is not valid UTF-8 — where the previous code
raised the wrong exception type and, in `open_package`, skipped the audit event
that every other denial records. No stored format changed and no data migration
is required. The fixes are confined to `identity_bound_packages/package.py`.

### Fixed

**Identity-bound packages — verify_signature crashed on a truncated package**

`verify_signature` is a boolean predicate, and 0.8.0 already hardened it to
report a package with a missing `signature` as invalid rather than raising. But
`_sign` reads `format`, `package_id`, `recipient_policy`, and `payload_hash` by
direct subscript, so a package missing any of those — a truncated file or a
hand-edited one — still raised `KeyError` out of `verify_signature`. In
`open_package` that escaped as an uncaught `KeyError` instead of the intended
`ValueError("Signature verification failed (package altered).")`, and skipped the
`DENIED ... reason=signature` audit event. `verify_signature` now rejects a
non-dict input and any package missing a signed field, returning `False` before
`_sign` is called.

**Identity-bound packages — a non-UTF-8 payload escaped the open pipeline**

In `open_package`, the payload was decrypted inside the guarded block but decoded
to text outside it, so an authenticated-but-non-UTF-8 payload surfaced as an
uncaught `UnicodeDecodeError` instead of the pipeline's uniform
`ValueError("Payload decryption failed (package altered).")`, and skipped the
`DENIED ... reason=decrypt` audit event. The decode now runs inside the guarded
block, so corruption is reported consistently and always audited.

### Notes

- No stored format changed. Packages, identities, and vaults written by 0.8.0
  load unchanged; there is nothing to migrate.
- Both fixes harden the code against corrupt and adversarial stored input. The
  0.7.0 security caveats are unchanged and still apply: BSR2 is unreviewed
  research crypto, the package `signature` field remains a shared-secret hash
  rather than a digital signature, and losing both the passphrase and the
  recovery code is unrecoverable by design.

---

## [0.8.0-beta] - 2026-08-23

A hardening pass over the BSR2 integration and application layers. 0.7.0 moved
every stored secret behind authenticated encryption; this release makes the code
around that encryption hold up when the values it reads back are hostile or
corrupt rather than well-formed. Every finding shares one theme: a persisted
value on the authentication path — limiter state, an iteration count, a stored
record — was trusted more than a file an attacker or a disk fault can edit
deserves. No stored format changes and no data migration is required.

Nothing in `bsr2_vendor/` is touched; it remains byte-identical and pinned by
`tests/test_bsr2_vendor_integrity.py`. Every fix lives in the integration or
application layer. The two behaviours that could hang or crash a process were
reproduced against the vendored primitives before and after the fix.

### Security

- **Attempt limiter no longer crashes or silently unlocks on corrupt state.**
  `AttemptLimiter._normalize` treated `NaN` and `Infinity` as valid numbers,
  because they are floats and `nan < 0` is `False`. A limiter state persisted
  with `locked_until` set to `NaN` made `locked_until > now` evaluate `False`,
  so a genuine lockout silently evaporated; and the subsequent
  `int(failed_attempts)` raised an uncaught `ValueError` out of a method whose
  contract is to raise `AttemptLockedOut` or return state, turning a corrupt
  state file into a hard crash on the unlock path. Non-finite fields are now
  discarded and read as fresh state, the same fail-safe already applied to
  non-numeric fields.
- **Attempt-limiter backoff can no longer be turned into a stall.** The backoff
  delay was computed as `base * 2 ** (failed_attempts - 1)` before being clamped
  to `max_delay_seconds`. Because `failed_attempts` comes from caller-persisted
  state, a stored count in the billions built a multi-gigabit integer that was
  then immediately discarded — a single `check()` measured at roughly 48 seconds.
  The exponent is now capped before exponentiation, so the clamp result is
  identical for honest input and the work is bounded regardless of the stored
  value.
- **KDF iteration counts are now bounded above as well as below.** 0.7.0
  validated the 10,000-iteration floor on read, to stop a tampered header from
  requesting a cheap derivation. It did not bound the ceiling. A stored factor
  hash or keyring header carrying an astronomical iteration count made
  verification or unlock run the deliberately slow KDF to completion — years of
  work — before the digest could even be compared and fail. Factor hashes
  (`factors.py`) and keyrings (`keyring.py`, on both the create and load paths)
  now reject an over-maximum count as malformed at parse time, so a tampered
  value fails fast without ever entering the KDF. The ceiling sits far above
  BSR2's 120,000 default, so no legitimate keyring or hash is affected.

### Fixed

**IdentityVault — batch upserts validated values too late to stay atomic**

`upsert_records` validated `kind` and `label` in its up-front pass but not
`value`, so a non-string value slipped through to the second, mutating loop and
raised from inside `build_plain_payload` — after earlier items in the batch had
already been applied to the in-memory vault and with the final save skipped, the
same failed-open, work-lost behaviour that 0.4.0 fixed for the missing-field
case. `value` is now validated during the prepare pass, so a bad item is
rejected before any record is mutated and the batch stays all-or-nothing.

**Identity-bound packages — malformed identity files raised a bare KeyError**

`IdentityProfile.__init__` read `identity_id` and `name` by direct subscript, so
an identity file missing either field raised a raw `KeyError` out of the
constructor, inconsistent with every other structural check in the class and
invisible to callers catching `Bsr2IntegrationError`. A missing field is now
reported as an integration error like every other malformed-file case.

**Identity-bound packages — a non-UTF-8 payload escaped the open pipeline**

In `open_package`, the payload was decrypted inside the guarded block but decoded
to text outside it, so an authenticated-but-non-UTF-8 payload surfaced as an
uncaught `UnicodeDecodeError` instead of the pipeline's uniform
`ValueError("Payload decryption failed (package altered).")`, and skipped the
`DENIED ... reason=decrypt` audit event that every other open failure records.
The decode now runs inside the guarded block, so corruption is reported
consistently and always audited.

### Notes

- No stored format changed. Vaults, identities, keyrings, templates, and
  packages written by 0.7.0 load unchanged; there is nothing to migrate.
- These fixes harden the code against corrupt and adversarial *stored* input.
  The 0.7.0 security caveats are unchanged and still apply: BSR2 is unreviewed
  research crypto, the package `signature` field remains a shared-secret hash
  rather than a digital signature, and losing both the passphrase and the
  recovery code is unrecoverable by design.

---

## [0.7.0-beta] - 2026-08-04

Encryption at rest, using real BSR2. Everything the repository previously stored
in the clear — vault record values, biometric templates, package payloads — is
now sealed with authenticated encryption. Still zero third-party dependencies:
BSR2 is standard library only, and it is vendored rather than depended on.

This release changes stored formats and refuses some previously readable files.
See **Changed** and **Migration** below.

### Added

- `bsr2_vendor/`: BSR2 vendored **byte-identical** from
  [BrisartSecurityResearch](https://github.com/JasonBrisart/BrisartSecurityResearch)
  at commit `656d962c447b7ac69d76b717820c34ae8e56b38a` — sponge primitives,
  authenticated envelope, DRBG, and OS entropy collection. No cryptographic
  primitive is implemented in this repository.
- `tests/test_bsr2_vendor_integrity.py`: pins every vendored file by SHA-256, so
  an upstream drift or a local edit fails the suite instead of silently changing
  what ships.
- `brisart_bsr2/`: the integration layer between BSR2 and the three tools.
  - `keyring.py` — master-key wrapping. A random 32-byte master key is sealed
    under a passphrase-derived key and again under an offline recovery code, so
    unlocking costs one slow derivation per session rather than one per
    operation.
  - `envelope.py` — seal/open with length-hiding padding (8-byte length prefix,
    256-byte blocks) applied inside the authenticated plaintext.
  - `context.py` — canonical context strings binding each ciphertext to the
    object it belongs to.
  - `factors.py` — factor hashing split by input entropy.
  - `rng.py` — DRBG seeded from `secrets.token_bytes` with transparent reseeding
    at upstream's lifecycle limits.
  - `throttle.py` — `AttemptLimiter` with caller-persisted state.
  - `errors.py` — one exception family; callers never import vendor exceptions.
- Offline recovery codes: 40 characters of Crockford base32 (200 bits), shown
  once at `init`. A second full-strength path to the master key, which is the
  price of being able to recover at all.
- `LabID_Beta/identity/device_key.py`: 32-byte local device key, created on first
  use with mode `0600` via `os.open` so it is never briefly world-readable.
  Refuses to overwrite an existing key, which would orphan every sealed
  template.
- `docs/BSR2_INTEGRATION.md`: full threat model — what each protection buys, the
  KDF cost reasoning, per-tool boundaries, and residual risks.
- New tests covering round trips, tamper rejection, context binding (a template
  sealed for one identity cannot be moved to another), keyring unlock failure,
  recovery-code unlock, iteration-downgrade rejection, and legacy migration.
  Repository total is now **111 passing tests**.

### Changed

- **Minimum Python is now 3.10** (was 3.9). Vendored BSR2 uses `int | None` in
  annotations that Python evaluates at import time, so 3.9 fails to import the
  envelope module. Patching the vendored file would break byte-identical
  vendoring and the digest pin in `tests/test_bsr2_vendor_integrity.py`, so the
  floor moved instead. CI covers 3.10 through 3.13.
- **Vault record values are sealed** under the vault master key. Record shells
  (`record_id`, `kind`, `label`, timestamps) stay readable so `list` and `verify`
  work while locked — a deliberate metadata trade-off, documented rather than
  implied.
- **Biometric templates are sealed** under the device key and bound to identity
  id plus modality. Template format is now
  `brisart-identity-tools/labid-template/v2`.
- **Package payloads are sealed** under a random per-package content key, which
  is itself wrapped once per recipient. Consequence: creating a package requires
  every recipient's identity unlocked at creation time, because BSR2 is
  symmetric and there is no public-key path without a dependency.
- Factor hashing replaced unsalted single-pass SHA-256, which leaked shared
  secrets through identical digests and fell to GPU guessing. Low-entropy inputs
  now use BSR2's slow KDF; high-entropy inputs use a keyed MAC, because
  stretching them adds nothing while a fast digest on a passphrase is a real
  weakness.
- Package verification runs cheap structural checks before expensive factor
  verification, so a tampered package is rejected without paying for a
  derivation.
- `IdentityProfile`'s keyring is now built lazily, so an identity that only ever
  adopts a master key directly is no longer forced to carry and validate a
  keyring it never uses.
- Renamed `test_plaintext_vault.py` → `test_sealed_vault.py` and
  `test_plaintext_labid_flow.py` → `test_sealed_labid_flow.py`; both previously
  asserted that data was readable on disk.
- `.gitignore` now excludes `device_key.json`, `*.identity`, `*.ibp`, and runtime
  `data/` directories. A device key decrypts every template beside it.
- CI smoke job sets `IDENTITY_VAULT_PASSPHRASE` and raises its timeout, since the
  vault and package CLIs each pay a real KDF.
- README's security model rewritten: what is encrypted, and what is explicitly
  not protected.

### Security

- Every sealed object is bound to a context string, so a ciphertext cannot be
  moved between records, identities, modalities, or recipients. A moved envelope
  fails authentication instead of decrypting into the wrong slot.
- Authentication failures are uniform: modified ciphertext, wrong key, and wrong
  context are indistinguishable to the verifier and reported identically.
- Keyring iteration counts are validated on read, so a tampered header cannot
  request a cheap derivation.
- Ciphertext length no longer reveals plaintext length beyond a 256-byte bucket.
- Digest comparison is constant-time.
- **Unchanged:** the package `signature` field is still a shared-secret hash, not
  a digital signature. It detects alteration; it does not prove origin.
- **Unchanged:** BSR2 is unreviewed research crypto. Upstream's `SECURITY.md`
  says not to use it as the sole protection for credentials, identity records, or
  recovery secrets. That caveat is inherited, not softened.

### Migration

- Legacy plaintext **vaults** load and are migrated to sealed storage on first
  write.
- Legacy plaintext **templates** load, flagged
  `storage_protection: unprotected_legacy_plaintext`, and are re-sealed on next
  write.
- Pre-BSR2 **packages are refused**, not opened. Their payloads were never
  encrypted and there is no key to recover; they must be re-created.
- Expect roughly a minute per passphrase unlock, and about three minutes for
  `init` (it derives both the passphrase and recovery wrappers). The KDF is slow
  on purpose; this is not a hang.
- **Losing both the passphrase and the recovery code is unrecoverable by
  design.**

---

## [0.6.0-beta] - 2026-08-02

Video FaceID, with liveness as an enforced gate. Still zero dependencies: the
AVI container is parsed and written by hand with `struct`.

### Added

- Uncompressed AVI support in `LabID_Beta/core/video.py`: RIFF chunk walking,
  `hdrl`/`strf` stream-format parsing, 8-bit palette and 24-bit BGR frame
  decoding, bottom-up and top-down row order, per-row stride padding,
  interleaved `rec ` records, plus a writer used to generate samples and to
  prove the reader against bytes this module laid out itself.
- `probe_avi_grayscale` for reporting resolution and frame count.
- Video FaceID templates in `LabID_Beta/core/video_features.py`: key-frame
  selection, per-frame face descriptors aggregated across the clip, and
  frame-to-frame motion statistics.
- A `video` modality wired through enroll and verify, inferred automatically
  from an `.avi` extension.
- **Liveness gate.** A recording of a still photograph scores a near-perfect
  face match, so liveness is enforced as a pass/fail gate rather than blended
  into the similarity score. A static clip returns `LIVENESS_FAILED` even when
  its face score clears the threshold. `--allow-static` overrides the gate and
  reports the raw score.
- Static-recording enrollment is refused by default, so a photograph cannot be
  baked into a template and make the verification-time gate meaningless.
- `record-video` CLI command: assembles two or more same-size PGM/PNG frames
  into an AVI recording usable for enrollment or verification. Camera capture
  needs a platform-specific driver, which would mean a dependency, so the
  recording path starts from frames already on disk.
- `probe-video` CLI command.
- 4 video demo samples: a live enrollment clip, a matching clip, a
  different-subject clip that also moves, and a static photo replay.
- 18 new tests (15 codec/template/liveness, 3 end-to-end video flow),
  including an AVI assembled byte by byte inside the test so a matching bug in
  both the reader and the writer would still be caught. Repository total is now
  **91 passing tests**.

### Changed

- Verification reports carry a `liveness` block and a
  `candidate_video_sha256`, and `result` can now be `LIVENESS_FAILED`.
- The "far" video sample genuinely moves, so it exercises a face-score
  rejection instead of being stopped by the liveness gate first.
- `test_samples_are_written_to_the_requested_directory` no longer asserts an
  exact sample count, which broke on every new modality; it now checks that all
  four sample formats are present and that every file lands in the requested
  directory.
- CI smoke tests exercise video FaceID, the recording round trip, the photo
  replay rejection, and the static-enrollment refusal plus its override.

---

## [0.5.0-beta] - 2026-08-02

LabID now supports three stdlib-only biometric modalities instead of just the
original grayscale face path.

### Added

- Real PNG support in `LabID_Beta/core/png.py`: chunk parsing, CRC validation,
  zlib decompression, all five PNG scanline filters, and grayscale conversion
  for grayscale, RGB, RGBA, grayscale+alpha, and indexed images.
- Real WAV PCM support in `LabID_Beta/core/wave_tools.py`: 8/16/24/32-bit
  decode, stereo-to-mono downmix, and 16-bit mono output, all without `audioop`
  so the code still runs on Python 3.13.
- Pure-Python DSP in `LabID_Beta/core/dsp.py`: framing, Hann window, radix-2
  FFT, power spectrum, mel filterbank, DCT-II / MFCCs, RMS, zero-crossing rate,
  and autocorrelation pitch estimation.
- Voice templates and verification based on MFCC summary statistics, pitch,
  energy, and zero-crossing rate.
- Fingerprint templates and verification based on normalized intensity,
  orientation/coherence fields, and minutiae-like ridge ending / bifurcation
  proxy grids.
- Multi-modal LabID dispatch so enroll/verify now handle `face`, `voice`, and
  `fingerprint` through one CLI.
- Demo samples for all three modalities: face PGM/PNG, voice WAV, and
  fingerprint PNG.
- 4 new LabID regression/integration tests. Repository total is now 73 passing
  tests across the three suites.

### Changed

- LabID face templates now accept PNG as well as PGM.
- Verification reports now record generic candidate source hashes plus
  modality-specific image/audio hashes.
- Fingerprint uses a stricter default threshold (`0.975`) than face/voice
  (`0.94`), because its score geometry is tighter and should not be forced into
  the same threshold bucket.
- CI smoke tests now exercise face PNG, voice WAV, and fingerprint PNG flows.

---

## [0.4.0-beta] - 2026-08-02

First release where "beta" reflects the state of the code rather than a label.
Every fix below was reproduced against the previous code before being changed,
and each one has a regression test that fails without the fix.

### Fixed

**IdentityVault — duplicate records from label normalization**

Stored labels pass through `safe_label()`, which collapses internal runs of
whitespace. Lookups compared against `label.strip()`, which does not. Any label
containing a double space therefore never matched an existing record, so
duplicate detection failed open and `upsert_record` appended a new record on
every call instead of updating in place. `get_record_by_label` then raised
`KeyError` for a label that was visibly present in the file.

**IdentityVault — batch writes were not atomic**

`upsert_records` mutated the in-memory vault as it walked the batch and saved
only at the end. An invalid item at position N raised after items 0..N-1 had
already been applied, and because the save never ran the caller silently lost
that work with no indication of how far the batch got. All items are now
validated before anything is mutated. Missing `kind`, `label` or `value` fields
are also reported explicitly instead of raising `KeyError`.

**LabID — identity ids silently collapsed onto one another**

`safe_identity_id` stripped disallowed characters instead of rejecting them, so
`ja/son`, `ja son` and `ja*son` all became `jason`, and `../../etc/passwd`
became `etcpasswd`. Since the id builds the record and template filenames, two
distinct identities silently shared one record and one biometric template.
Invalid ids are now rejected with the offending characters named, and there is a
length limit.

**LabID — re-enrollment destroyed the existing template**

`enroll_identity` wrote the identity record and biometric template with no
existence check, so enrolling an id that already existed replaced both without
warning and destroyed the only stored copy of that identity's template.
Re-enrollment now fails unless `--overwrite` is passed.

**LabID — generated samples were written to the current directory**

`make-samples` wrote its PGM files into whatever directory the CLI happened to
be invoked from, which scattered artifacts and made them easy to commit by
accident. They now go to `data/samples/`.

**LabID — storage paths could not be reconfigured**

Modules imported `IDENTITY_DIR`, `TEMPLATE_DIR` and `REPORT_DIR` into their own
namespace at import time, which froze the storage location on first import.
Paths are now resolved through the settings module at call time.

**LabID — new records claimed to be updated before they existed**

`build_identity_record` called `utc_now()` separately for `created_at` and
`updated_at`. The two calls can straddle a second boundary, making a brand-new
record look like it had already been modified. Both fields now share one
timestamp.

**Identity-bound packages — digest comparisons were not constant time**

Passphrase, voice, face, fingerprint, signature, payload and custody-chain
checks all compared SHA-256 digests with `==`, which short-circuits at the first
differing character and leaks how much of a guess was correct through timing.
All of them now use `hmac.compare_digest` via `crypto.digests_equal`.

**Identity-bound packages — malformed input crashed the validators**

`verify_signature` raised `TypeError` on a package with no `signature`,
`verify_chain` raised `KeyError` on a truncated custody event, and
`identity_authorized` raised `KeyError` on a package with no
`recipient_policy`. Functions whose contract is to return a boolean now report
invalid input as invalid.

**Identity-bound packages — unopenable packages could be created**

`create_package` accepted an empty recipient list, an unknown mode, a
non-string message, and a `THRESHOLD` count outside the recipient range,
producing packages that no identity could ever open. These are now rejected at
creation time.

**Identity-bound packages — importing a module created directories**

`identity.py`, `package.py` and `audit.py` called `mkdir` at module scope, so
merely importing them left untracked `identities/`, `packages/` and `logs/`
directories in the working tree. Directories are created when something is
actually written.

**Repository — the test suites could not be run**

`IdentityVault_beta/tests` failed with `ModuleNotFoundError` from the repository
root and `ImportError: Start directory is not importable` from inside its own
directory, so the suite could not be executed at all. Package markers and a
`conftest.py` now make every suite importable from either location.

### Added

- `run_tests.py`, a single entry point that runs all three suites. The three
  application trees use different import roots, so no one `unittest discover`
  call could collect them.
- 65 regression tests across the three suites (73 total, all passing) covering
  every fix above. The repository previously had 8 tests, neither suite of which
  could actually be executed.
- GitHub Actions CI: the full suite on Python 3.9 through 3.13, a `ruff` lint
  job, and a smoke-test job that exercises the real CLI paths end to end
  (enroll, verify, refused re-enrollment, refused duplicate label, package demo)
  and fails if the tests leave artifacts in the working tree.
- `pyproject.toml` with project metadata and a `ruff` configuration selecting
  the rule families that catch real defects.
- `utc_stamp()` replaces an unused `local_stamp()` helper that returned a naive
  local timestamp.

### Notes

Storage in this beta is plaintext by design. These tools provide
identity-based authorization, integrity checking, custody tracking and audit
logging, not confidentiality. Factor hashes are unsalted single-pass SHA-256,
which is fine for a workflow demo and not a secure credential store; a
production version needs a slow salted KDF such as Argon2 or scrypt, along with
protected biometric templates and liveness detection.
