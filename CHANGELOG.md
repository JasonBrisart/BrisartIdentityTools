# Changelog

All notable changes to BrisartIdentityTools are recorded here.

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
- 61 regression tests across the three suites (69 total, all passing) covering
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
