# Changelog

All notable changes to BrisartIdentityTools are recorded here.

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
