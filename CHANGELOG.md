# Changelog

All notable changes to BrisartIdentityTools are recorded here.

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
