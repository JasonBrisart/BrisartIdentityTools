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

### Identity-bound packages: bind a message to an identity

```bash
cd identity_bound_packages
python main.py demo
```

---

## Security Model

These tools provide identity-based authorization, integrity checking, custody
tracking, and audit logging across three local biometric modes: face images
(PGM or PNG), voice recordings (PCM WAV), fingerprint images (PNG), and
video FaceID recordings (uncompressed AVI).

They do not provide confidentiality. Vault records and package payloads are
stored as plaintext by design so they stay inspectable. Factor hashes are
unsalted single-pass SHA-256, which is adequate for a workflow demo but is not a
secure credential store. A production deployment needs a slow salted KDF
(Argon2 or scrypt), protected biometric templates, and liveness detection.

Digest comparisons use `hmac.compare_digest`, so verification does not leak
match length through timing.

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