# LabID

Beta software for local-first identity verification experiments.

LabID is a Python-based, offline identity toolkit focused on local records, biometric-style verification templates, and readable verification reports.

No external services.
No cloud login.
No hosted identity provider.
No third-party Python packages.

Just standard-library Python.

---

## What This Includes

This beta includes a dependency-free biometric verification prototype that works with grayscale `.pgm` images.

The current workflow is:

1. Generate or provide a controlled grayscale PGM enrollment image.
2. Enroll a local identity.
3. Build a local verification template.
4. Verify a candidate image against the enrolled identity.
5. Generate a JSON verification report.

---

## Important Beta Scope

This is beta software.

This project currently performs controlled local image verification. It does not perform full identity platform management, cloud authentication, or enterprise access control.

---

## Repository Layout

```text
LabID/
    app.py
    README.md
    config/
        settings.py
    core/
        pgm.py
        image_tools.py
        template_engine.py
        scoring.py
    identity/
        identity_record.py
        identity_store.py
    biometrics/
        enrollment.py
        verification.py
    reports/
        report_writer.py
    samples/
        sample_generator.py
    data/
        identities/
        templates/
        reports/
```

---

## Quick Start

Generate sample images:

```bash
python app.py make-samples
```

Enroll an identity:

```bash
python app.py enroll researcher_001 "Researcher One" sample_enroll.pgm
```

Verify a close sample:

```bash
python app.py verify researcher_001 sample_verify_close.pgm
```

Verify a far sample:

```bash
python app.py verify researcher_001 sample_verify_far.pgm
```

Inspect an identity:

```bash
python app.py inspect researcher_001
```

List identities:

```bash
python app.py list
```

---

## Why PGM Images?

PGM is a simple grayscale image format that can be parsed using only the Python standard library.

Most common image formats such as PNG and JPG require more complex decoding logic or external packages. This beta intentionally keeps the image pipeline dependency-free.

---

## Current Verification Method

The beta verification engine:

- reads a local grayscale PGM image
- resizes it to a fixed internal size
- normalizes brightness
- extracts grid intensity features
- extracts simple gradient features
- stores a local JSON template
- compares candidate templates using distance scoring
- writes a verification report

---

## Generated Data

After enrollment and verification, the tool creates:

```text
data/
    identities/
        researcher_001.json
    templates/
        researcher_001_template.json
    reports/
        researcher_001_YYYYMMDD_HHMMSS_report.json
```

---

## Project Direction

BrisartIdentityTools is intended to grow into a local-first identity toolkit for:

- local identity records
- offline credential experiments
- physical token workflows
- biometric verification experiments
- identity reports
- air-gapped research environments

---

## Status

Beta software.
