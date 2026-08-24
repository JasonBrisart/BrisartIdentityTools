# BrisartIdentityTools

Local-first identity, authentication, and verification tools for offline and air-gapped environments.

No cloud services.
No hosted infrastructure.
No vendor lock-in.
Just Python.

---

## Why This Exists

Modern identity systems are often built around external providers:

- Cloud authentication
- Third-party identity services
- Hosted login systems
- Subscription-based security platforms
- Continuous internet connectivity

BrisartIdentityTools explores a different approach.

The goal is simple:

> If identity matters, you should be able to manage and verify it yourself.

This repository focuses on local-first, transparent, and auditable identity workflows designed for environments that prioritize ownership, control, and long-term accessibility.

---

## Design Principles

### Local First
Identity should function without requiring external services.

### Offline Capable
Systems should remain usable in disconnected and air-gapped environments.

### Human Readable
Identity records and configuration should be understandable by humans.

### Source Available
Users should be able to inspect how verification occurs.

### Audit Friendly
Verification logic should be transparent and reviewable.

### Long-Term Maintainability
Identity systems should remain understandable years from now.

---

## What Is An Identity?

For this project, an identity can represent:

- A researcher
- A developer
- A laboratory member
- An archivist
- A workstation
- A server
- A device
- A removable media token

Identity is intentionally broader than just people.

---

## The Three Tools

| Tool | What it does |
| --- | --- |
| **Vault** (`vault/`) | An encrypted, local, single-file record store. Record values are sealed; record shells stay readable so the vault lists without unlocking. Also seals arbitrary files, folders, and drives. |
| **Biometrics** (`biometrics/`) | Local multimodal biometric enrollment and verification (voice / fingerprint / video), with sealed templates and arbitrary file attachments. |
| **Packages** (`packages/`) | Identity-Bound Packages: content sealed so only a specific set of recipient identities can open it, with a tamper-evident custody chain. |

All three share a common utility layer (`common/`), a BSR2 integration layer
(`crypto/`), vendored BSR2 primitives (`vendor/`), and a Tkinter desktop GUI
(`gui/`). A single dispatcher (`cli.py`) launches any tool or the GUI.

---

## Quick Start

Python 3.10 or newer. No third-party dependencies.

The floor is 3.10 rather than 3.9 because vendored BSR2 uses `int | None`
annotations that Python evaluates at import time. Patching the vendored file
would break byte-identical vendoring, so the floor moved instead.

```bash
git clone https://github.com/JasonBrisart/BrisartIdentityTools.git
cd BrisartIdentityTools
```

The repository is one flat tree with fully-qualified imports throughout, so one
runner drives every suite:

```bash
python run_tests.py          # full suite across biometrics, vault, and packages
python run_tests.py -v       # verbose
```

### Unified CLI and desktop GUI

Every tool is reachable through one dispatcher, and the GUI covers all three in
one window:

```bash
python cli.py biometrics ...   # local biometric enroll/verify
python cli.py vault ...         # encrypted record store
python cli.py package ...       # identity-bound packages
python cli.py gui               # launch the desktop GUI (also: python -m gui.app)
python cli.py version           # print the ecosystem version
python cli.py help
```

The commands below use each tool directly; the same commands work through
`python cli.py <tool> ...`.

### Biometrics: enroll and verify local voice, fingerprint, and video samples

```bash
cd biometrics
python app.py make-samples ci-enroll
python app.py make-samples ci-other

# Voice (WAV PCM), fingerprint (PGM), and video (BRVID) together
python app.py enroll jason-1 --label "Jason" \
  --voice data/samples/ci-enroll_voice.wav \
  --fingerprint data/samples/ci-enroll_fingerprint.pgm \
  --video data/samples/ci-enroll_video.brvid
python app.py verify jason-1 \
  --voice data/samples/ci-enroll_voice.wav \
  --fingerprint data/samples/ci-enroll_fingerprint.pgm \
  --video data/samples/ci-enroll_video.brvid           # MATCH
python app.py verify jason-1 \
  --voice data/samples/ci-other_voice.wav \
  --fingerprint data/samples/ci-other_fingerprint.pgm \
  --video data/samples/ci-other_video.brvid             # NO MATCH
python app.py list
python app.py inspect jason-1
```

Re-enrolling an existing identity is refused outright. There is no
`--overwrite` flag; delete the identity first with `python app.py delete jason-1`,
then enroll again, if you need to replace its stored template.

### Vault: store and read local records

```bash
python -m vault.app --vault vault.json init
python -m vault.app --vault vault.json upsert "Researcher One" \
  --kind identity --payload '{"value": "record-value"}'
python -m vault.app --vault vault.json list
python -m vault.app --vault vault.json get RECORD_ID
```

`--vault` is a global option, so it goes before the subcommand.

`init` prints a **recovery code once**. Write it down: without it or the
passphrase, the vault cannot be opened by anyone, including you.

Every command that touches record values unlocks the vault first, which runs
BSR2's slow key derivation — expect roughly a minute per invocation. `list`
reads record shells only, so it does not prompt for a passphrase.

`vault/app.py` always prompts for the passphrase via `getpass`. There is
currently no environment-variable bypass built into the CLI; for scripting,
pipe the passphrase in on stdin instead (`getpass` falls back to a plain
stdin read, with a warning, when stdin isn't a terminal):

```bash
printf 'my-passphrase\n' | python -m vault.app --vault vault.json list
```

To seal whole files, folders, or drives into the vault, see
[docs/README_FULL_FILE_ENCRYPTION.md](docs/README_FULL_FILE_ENCRYPTION.md).

### Packages: bind a payload to a set of recipient identities

```bash
cd packages
python main.py demo
```

The demo creates a package sealed to one identity, adds a second recipient,
opens it, and prints its custody chain. It performs real BSR2 derivations, so
it takes a little while end to end.

Creating a package requires every recipient's identity to be **unlocked**,
which is a consequence of symmetric-only crypto rather than an oversight; see
`packages/package.py`.

---

## Security Model

These tools provide identity-based authorization, integrity checking, custody
tracking, and audit logging across three local biometric modes: voice
recordings (PCM WAV), fingerprint images (PGM/PNG), and video (a minimal,
custom frame-sequence container, not a standard video format).

### Confidentiality

Confidentiality is provided by **BSR2** ([BrisartSecurityResearch](https://github.com/JasonBrisart/BrisartSecurityResearch)),
vendored unmodified in `vendor/`. No cryptographic primitive is implemented in
this repository, and there are still zero third-party dependencies: BSR2 is
standard library only, as is everything here.

> **Note:** the digest-pin test that verified `vendor/` was byte-identical to
> upstream (`tests/test_bsr2_vendor_integrity.py`) was dropped during the 1.0.0
> restructure and has not yet been recreated. Until it (or an equivalent digest
> check) is re-added, an accidental edit to `vendor/` will not be caught by CI.
> Re-adding it is an open item — see `docs/BSR2_INTEGRATION.md` and
> `vendor/README.md`.

What is encrypted at rest:

| Data | Protected under | Notes |
| --- | --- | --- |
| Vault record values | Passphrase-derived master key | Record *shells* (id, kind, label, timestamps) stay readable |
| Biometric templates | Local device key | Bound to identity id + modality |
| Package payloads | Per-package random content key | Content key wrapped once per recipient |

Every sealed object is bound to a **context string** naming what it is, so a
ciphertext cannot be moved between records, identities, modalities, or
recipients. A moved envelope fails authentication rather than decrypting into
the wrong slot. Plaintext is length-prefixed and padded to 256-byte blocks
before sealing, so ciphertext size does not reveal the exact length of a
credential.

Passphrases go through BSR2's `derive_password_key`. It is slow on purpose:
measured at roughly 85-90 seconds per derivation on the development machine, at
BSR2's enforced 10,000-iteration minimum. Rather than pay that per operation, a
random 32-byte master key is wrapped under the passphrase and again under an
offline recovery code, so unlocking costs one derivation per session and every
subsequent operation is fast. **Losing both the passphrase and the recovery
code is unrecoverable by design.**

The iteration count is recorded in the keyring header and validated on read, so
editing it downward to force a cheap derivation is rejected rather than honoured.

Factor protection is split by input entropy: low-entropy secrets (passphrases,
spoken phrases) get the slow KDF, while high-entropy ones (template digests,
signature blobs) get a fast keyed MAC under the master key. Stretching a
high-entropy input buys nothing; applying a fast MAC to a low-entropy one is a
real weakness. See `crypto/factors.py`.

Digest comparisons use constant-time equality, so verification does not leak
match length through timing. Online guessing is bounded by a caller-persisted
attempt limiter (`crypto/throttle.py`).

### What this does not protect against

Stated plainly rather than left implied:

- **The biometrics device key sits beside the data it protects.** Biometrics
  runs as an unattended verification service with no human present to enter a
  passphrase, so anyone with filesystem read access to its data directory can
  decrypt every template. Use an encrypted volume or restrictive file
  permissions if that matters. See `biometrics/identity/device_key.py`.
- **Package creation requires every recipient unlocked.** BSR2 is symmetric and
  this project takes no third-party dependencies, so there is no public-key
  mechanism to seal a payload to a recipient the creator cannot open.
- **The package custody chain is tamper-evident, not a digital signature.**
  Each entry's `actor_label` is a caller-supplied string, not cryptographically
  bound to a signing key. Editing, deleting, or reordering a past entry breaks
  the hash chain and is detectable, but the chain does not *prove* who
  performed an action at the time it happened.
- **Biometric matching is threshold-based on hand-rolled DSP features**, not a
  trained model, and there is no liveness / anti-spoofing gate.

Upstream BSR2's own `SECURITY.md` states it is research software and should not
be used as the sole protection for credentials, identity records, or recovery
secrets. That caveat applies here too. Full threat model:
[docs/BSR2_INTEGRATION.md](docs/BSR2_INTEGRATION.md).

### Key material and the repository

`device_key.json`, `*.identity`, `*.ibp`, and the runtime `data/` directories
are gitignored. A device key decrypts every template in its directory, so it
must never be committed.

---

## Repository Status

Active research project, at its first production/stable release (1.0.0).

"Production/stable" describes the code's own maturity — stable formats, a full
test suite, and no data migration between releases — not an assurance about the
underlying research cryptography, which remains unreviewed (see the Security
Model above). Features may still change as new research directions emerge.

---

## License

See LICENSE file for repository licensing information.

---

## Brisart Ecosystem

```text
BrisartIdentityTools
        │
        ▼
BrisartDevTools
        │
        ▼
Brisart Research Archive
        │
        ▼
BrisartPreservationTools
```
