# What This Is

Beta software for local-first identity verification experiments.

LabID is a Python-based, offline identity toolkit focused on local records,
biometric-style verification templates, and readable verification reports.

No external services.
No cloud login.
No hosted identity provider.
No third-party Python packages.

Just standard-library Python.

---

## What This Includes

A dependency-free biometric verification prototype covering four modalities:

| Modality | Input | Notes |
|---|---|---|
| Face | `.pgm`, `.png` | grid intensity + gradient features |
| Voice | `.wav` | framed energy / zero-crossing / spectral features |
| Fingerprint | `.pgm`, `.png` | ridge-orientation features |
| Video FaceID | `.avi` | per-frame face features, aggregated |

The typical workflow is:

1. Generate or provide a controlled sample file.
2. Enroll a local identity.
3. Build a local verification template (sealed on disk, see below).
4. Verify a candidate against the enrolled identity.
5. Generate a JSON verification report.

PNG decoding, WAV parsing, and AVI assembly are all implemented against the
standard library only. There is no ML model anywhere in the pipeline; these are
hand-written signal-processing features, which is why the scores are useful for
workflow research and not for real identification.

---

## Template Encryption

Verification templates are **encrypted at rest** with
[BSR2](https://github.com/JasonBrisart/BrisartSecurityResearch), vendored
byte-identical in `bsr2_vendor/` at the repository root and pinned by digest.

Templates are derived feature data, not raw images, but they are still biometric
material about a person, so they are sealed before touching disk:

```json
{
  "format": "brisart-identity-tools/labid-template/v2",
  "identity_id": "researcher_001",
  "modality": "face",
  "sealed_template": {
    "algorithm": "BSR2-ARX-SPONGE-ETM",
    "version": 1,
    "ciphertext": "f94bb2b1357055124f839d80396fbea0...",
    "nonce": "...",
    "salt": "...",
    "tag": "..."
  }
}
```

Each template is bound to its identity id **and** modality, so a sealed template
cannot be copied into another identity's file or presented as a different
modality without failing authentication. Identity records and verification
reports stay readable, so `list` and `inspect` work without any key.

### Device key, not a passphrase

LabID is an **unattended local verification service**. There is no human present
at unlock time, and the CLI is invoked repeatedly, so a passphrase prompt paying
BSR2's minute-plus key derivation on every call would make the tool unusable.

Instead, a random 32-byte device key is created on first use at
`data/device_key.json`, mode `0600`, written owner-only from the moment it is
created rather than being chmod'ed afterwards.

Be clear about what that does and does not buy you:

- **Protects against** casual disclosure of biometric feature data, tampering
  with a template, and substituting one identity's template for another's.
- **Does not protect against** anyone who can read the key file. The key sits
  next to the data it protects. That is inherent to unattended operation, not a
  defect in this module, and no arrangement of local files fixes it. If you need
  protection from local filesystem access, the key has to live somewhere LabID
  cannot silently read it.

The key file is git-ignored. Do not commit it, and do not copy it alongside
template files.

Deleting `data/device_key.json` permanently orphans every sealed template. There
is no recovery path, by design.

### Migration

Legacy plaintext templates still load, are flagged
`storage_protection: "unprotected_legacy_plaintext"`, and are re-sealed on the
next write.

---

## Important Beta Scope

This is beta software.

It performs controlled local verification. It does not perform full identity
platform management, cloud authentication, or enterprise access control, and its
biometric scoring is not suitable for real identification decisions.

---

## Repository Layout

```text
LabID_Beta/
    app.py
    README.md
    config/
        settings.py
    core/
        pgm.py
        png.py
        image_tools.py
        template_engine.py
        scoring.py
        voice_features.py
        fingerprint_features.py
        video_features.py
        wav.py
        avi.py
    identity/
        identity_record.py
        identity_store.py
        device_key.py
    biometrics/
        enrollment.py
        verification.py
        modalities.py
    reports/
        report_writer.py
    samples/
        sample_generator.py
    data/
        identities/
        templates/
        reports/
        device_key.json      # created on first use, git-ignored
```

---

## Quick Start

LabID uses flat imports, so run it from inside `LabID_Beta/`:

```bash
cd LabID_Beta
```

Generate sample files for every modality:

```bash
python app.py make-samples
```

Enroll and verify a face:

```bash
python app.py enroll researcher_001 "Researcher One" data/samples/sample_face_enroll.png
python app.py verify researcher_001 data/samples/sample_face_verify_close.png
python app.py verify researcher_001 data/samples/sample_face_verify_far.png
```

Other modalities are selected by file type:

```bash
python app.py enroll researcher_002 "Researcher Two" data/samples/sample_voice_enroll.wav
python app.py verify researcher_002 data/samples/sample_voice_verify_close.wav

python app.py enroll researcher_003 "Researcher Three" data/samples/sample_fingerprint_enroll.png
python app.py verify researcher_003 data/samples/sample_fingerprint_verify_close.png
```

Video FaceID (`record-video` takes the output path first, then the frames):

```bash
python app.py enroll researcher_004 "Researcher Four" data/samples/sample_video_enroll.avi
python app.py verify researcher_004 data/samples/sample_video_verify_close.avi

python app.py probe-video data/samples/sample_video_enroll.avi
python app.py record-video data/samples/my_clip.avi frame_01.png frame_02.png --fps 15
```

The generated samples include `sample_video_photo_replay.avi`, a still image
replayed as a video, for exercising the presentation-attack check.

Inspect and list (no device key needed):

```bash
python app.py inspect researcher_001
python app.py list
```

---

## Why PGM and PNG?

PGM is a trivially parseable grayscale format. PNG support is implemented on top
of `zlib`, which is standard library, so common images work without adding a
dependency. JPEG is deliberately not supported: decoding it correctly without a
third-party library is a much larger job than it looks.

---

## Current Verification Method

For face and fingerprint input the engine reads the image, resizes to a fixed
internal size, normalizes brightness, extracts grid intensity and gradient or
ridge-orientation features, seals the template, and compares candidates by
distance scoring. Voice uses framed time and spectral features; video aggregates
per-frame face features across the recording.

---

## Generated Data

```text
data/
    identities/
        researcher_001.json
    templates/
        researcher_001_template.json      # sealed
    reports/
        researcher_001_YYYYMMDD_HHMMSS_report.json
    device_key.json                        # git-ignored
```

---

## Project Direction

BrisartIdentityTools is intended to grow into a local-first identity toolkit for
local identity records, offline credential experiments, physical token workflows,
biometric verification experiments, identity reports, and air-gapped research
environments.

---

## Status

Beta software.

BSR2 is unreviewed research cryptography. Upstream's `SECURITY.md` states it
should not be used as the sole protection for credentials, identity records, or
recovery secrets, and that caveat is inherited here rather than softened. The
full threat model, including the device-key boundary above, is in
[`docs/BSR2_INTEGRATION.md`](../docs/BSR2_INTEGRATION.md).
