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

## Current Research Areas

### Identity Records

Create and manage local identity records.

Examples:

- User identities
- Device identities
- Research identities
- Service identities

---

### Credential Verification

Validate locally stored credentials.

Examples:

- Password verification
- Passphrase verification
- Credential comparison
- Authentication records

---

### Physical Identity Tokens

Explore possession-based identity systems.

Examples:

- USB authentication tokens
- Offline access tokens
- Removable media credentials
- Physical verification workflows

---

### Verification Reports

Generate verification reports showing:

- Verification status
- Validation results
- Timestamp information
- Audit details

---

### Local Trust Models

Research methods for establishing trust without relying on cloud infrastructure.

Examples:

- Local trust stores
- Credential manifests
- Verification chains
- Offline validation systems

---

## Future Research

Potential future experiments include:

### Multi-Factor Authentication

Combining multiple local authentication methods.

Examples:

- Password + token
- Passphrase + removable media
- Device + credential verification

### Smart Card Integration

Exploration of offline credential devices.

### Certificate-Based Workflows

Local certificate generation and validation.

### Air-Gapped Authentication

Authentication methods designed for isolated environments.

### Biometric Research

Identity experiments using local biometric methods.

Potential examples:

- Facial verification research
- Identity template comparison
- Offline biometric experiments

Experimental biometric features should not be considered production security systems without independent validation and testing.

---

## Philosophy

BrisartIdentityTools follows a simple belief:

> Ownership should include identity.

If software, archives, and research can be controlled locally, identity should be capable of the same.

The objective is not to replace enterprise authentication platforms.

The objective is to explore transparent, understandable, and locally controlled identity systems.

---

## Repository Goals

- Build understandable identity tools.
- Promote local-first workflows.
- Remain dependency-conscious.
- Encourage auditability.
- Support offline environments.
- Experiment responsibly.

---

## Quick Start

Python 3.9 or newer. No third-party dependencies.

```bash
git clone https://github.com/JasonBrisart/BrisartIdentityTools.git
cd BrisartIdentityTools
```

### Run the tests

The three tools use different import roots, so one runner drives all of them:

```bash
python run_tests.py          # 91 tests across the three suites
python run_tests.py -v       # verbose
```

### LabID: enroll and verify local face, voice, fingerprint, and video samples

```bash
cd LabID_Beta
python app.py make-samples

# Face (PNG or PGM)
python app.py enroll jason-face "Jason Face" data/samples/sample_face_enroll.png --modality face
python app.py verify jason-face data/samples/sample_face_verify_close.png --modality face   # MATCH
python app.py verify jason-face data/samples/sample_face_verify_far.png --modality face     # NO_MATCH

# Voice (WAV PCM)
python app.py enroll jason-voice "Jason Voice" data/samples/sample_voice_enroll.wav --modality voice
python app.py verify jason-voice data/samples/sample_voice_verify_close.wav --modality voice # MATCH
python app.py verify jason-voice data/samples/sample_voice_verify_far.wav --modality voice   # NO_MATCH

# Fingerprint (PNG)
python app.py enroll jason-finger "Jason Finger" data/samples/sample_fingerprint_enroll.png --modality fingerprint
python app.py verify jason-finger data/samples/sample_fingerprint_verify_close.png --modality fingerprint # MATCH
python app.py verify jason-finger data/samples/sample_fingerprint_verify_far.png --modality fingerprint   # NO_MATCH

python app.py enroll jason-video "Jason Video" data/samples/sample_video_enroll.avi --modality video
python app.py verify jason-video data/samples/sample_video_verify_close.avi --modality video # MATCH
python app.py verify jason-video data/samples/sample_video_verify_far.avi --modality video   # NO_MATCH

# A recording of a still photo scores a near-perfect face match, so liveness
# is a gate, not a score term. This one is rejected as LIVENESS_FAILED.
python app.py verify jason-video data/samples/sample_video_photo_replay.avi --modality video

# Build a recording from frames already on disk, then use it for FaceID.
# Camera capture needs a platform driver, which would mean a dependency.
python app.py record-video my_clip.avi frame1.png frame2.png frame3.png
python app.py probe-video my_clip.avi

python app.py list
```

Re-enrolling an existing identity is refused unless you pass `--overwrite`,
because it replaces that identity's stored biometric template.

### IdentityVault: store and read local records

```bash
python -m IdentityVault_beta.app --vault vault.json init
python -m IdentityVault_beta.app --vault vault.json add \
    --kind identity --label "Researcher One" --value "record-value"
python -m IdentityVault_beta.app --vault vault.json list
python -m IdentityVault_beta.app --vault vault.json verify
```

`--vault` is a global option, so it goes before the subcommand.

`init` prints a **recovery code once**. Write it down: without it or the
passphrase, the vault cannot be opened by anyone, including you.

Every command that touches record values unlocks the vault first, which runs
BSR2's slow key derivation — expect roughly a minute per invocation, and about
three for `init` (it derives both the passphrase and recovery wrappers). That is
the KDF working as intended, not a hang. `list` and `verify` read record shells
only, so they do not need the passphrase.

For scripting, `IDENTITY_VAULT_PASSPHRASE` is honoured instead of the prompt.
Convenient and less secret: environment variables are visible to other processes
of the same user and often land in shell history and CI logs.

### Identity-bound packages: bind a message to an identity

```bash
cd identity_bound_packages
python main.py demo
```

The demo creates an identity, seals a package to it, records a custody transfer,
opens it, then shows a wrong passphrase being refused. It performs three BSR2
derivations, so it takes several minutes end to end.

Creating a package requires every recipient's identity to be **unlocked**, which
is a consequence of symmetric-only crypto rather than an oversight; see
`identity_bound_packages/package.py`.

---

## Security Model

These tools provide identity-based authorization, integrity checking, custody
tracking, and audit logging across four local biometric modes: face images
(PGM or PNG), voice recordings (PCM WAV), fingerprint images (PNG), and
video FaceID recordings (uncompressed AVI).

### Confidentiality

Confidentiality is provided by **BSR2**
([BrisartSecurityResearch](https://github.com/JasonBrisart/BrisartSecurityResearch)),
vendored unmodified in `bsr2_vendor/` and pinned by digest in
`tests/test_bsr2_vendor_integrity.py`. No cryptographic primitive is
implemented in this repository, and there are still zero third-party
dependencies: BSR2 is standard library only, as is everything here.

What is encrypted at rest:

| Data | Protected under | Notes |
| --- | --- | --- |
| Vault record values | Passphrase-derived master key | Record *shells* (id, kind, label, timestamps) stay readable |
| LabID biometric templates | Local device key | Bound to identity id + modality |
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
subsequent operation is fast. Vault `init` derives both wrappers and so takes
about three minutes. **Losing both the passphrase and the recovery code is
unrecoverable by design.**

The iteration count is recorded in the keyring header and validated on read, so
editing it downward to force a cheap derivation is rejected rather than honoured.

Factor protection is split by input entropy: low-entropy secrets (passphrases,
spoken phrases) get the slow KDF, while high-entropy ones (template digests,
signature blobs) get a fast keyed MAC under the master key. Stretching a
high-entropy input buys nothing; applying a fast MAC to a low-entropy one is a
real weakness. See `brisart_bsr2/factors.py`.

Digest comparisons use constant-time equality, so verification does not leak
match length through timing. Online guessing is bounded by a caller-persisted
attempt limiter (`brisart_bsr2/throttle.py`).

### What this does not protect against

Stated plainly rather than left implied:

- **Vault record labels are readable while locked.** Listing and searching work
  without unlocking, so the vault reveals that a record labelled `bank-login`
  exists while protecting its value. Hiding labels would require decrypting
  every record for any lookup.
- **The LabID device key sits beside the data it protects.** LabID is an
  unattended verification service with no human present to enter a passphrase,
  so anyone with filesystem read access to its data directory can decrypt every
  template. Use an encrypted volume or restrictive file permissions if that
  matters. See `LabID_Beta/identity/device_key.py`.
- **Package creation requires every recipient unlocked.** BSR2 is symmetric and
  this project takes no third-party dependencies, so there is no public-key
  mechanism to seal a payload to a recipient the creator cannot open.
- **The package `signature` field is a shared-secret hash, not a digital
  signature.** It detects alteration; it does not prove origin.
- **Biometric matching is threshold-based on hand-rolled DSP features**, not a
  trained model. Liveness is enforced as a gate for video, but these are
  research-grade matchers.

Upstream BSR2's own `SECURITY.md` states it is research software and should not
be used as the sole protection for credentials, identity records, or recovery
secrets. That caveat applies here too. Full threat model:
[`docs/BSR2_INTEGRATION.md`](docs/BSR2_INTEGRATION.md).

### Key material and the repository

`device_key.json`, `*.identity`, `*.ibp`, and the runtime `data/` directories
are gitignored. A device key decrypts every template in its directory, so it
must never be committed.

---

## Repository Status

Active Research Project.

This repository is intended for experimentation, education, research, and local identity workflows.

Features may change as new ideas and research directions emerge.

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