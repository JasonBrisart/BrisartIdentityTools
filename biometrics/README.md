# Biometrics

Local, multimodal biometric enrollment and verification for
BrisartIdentityTools. No cloud services, no third-party imaging/audio/ML
libraries — decoding, feature extraction, and matching are all hand-rolled
Python over the standard library.

---

## What it does

Biometrics enrolls an identity against one or more of three modalities, then
verifies a fresh capture against the stored templates:

| Modality | Input format | Feature summary |
| --- | --- | --- |
| Voice | WAV (PCM) | Framed, windowed energy / zero-crossing-rate / band-energy DCT coefficients, averaged across the recording |
| Fingerprint | PGM or PNG | Grid of local ridge-orientation (cos/sin) + magnitude estimates from Sobel gradients |
| Video | BRVID (a minimal custom frame-sequence container — see below) | Per-frame block-mean spatial summary + frame-to-frame motion-energy summary |

Every extractor produces a **fixed-length vector** regardless of the input's
original size or duration, so a 2-second and a 20-second recording — or a
64x64 and a 4000x3000 image — compare on equal footing. Matching is cosine
similarity against a per-modality default threshold (`biometrics/engine/modalities.py`),
deliberately conservative: this is a research/reference implementation, not a
tuned production biometric system, and there is no learned model or
liveness/anti-spoofing gate.

### BRVID: why not just use a real video format

There's no dependency on an actual video codec (no H.264, no container
muxer) because none is needed here: video enrollment is a short sequence of
grayscale frames, not general playback. `biometrics/codecs/video.py` defines
the smallest format that can hold that — a fixed header (magic, width,
height, frame count, frame rate) followed by concatenated raw grayscale
frames, no per-frame compression. `record-video` assembles a BRVID file from
individual PGM/PNG frames already on disk; there's no live camera capture,
since that would need a platform-specific driver (i.e. a dependency).

---

## CLI

All commands are also reachable via the repo-root dispatcher:
`python cli.py biometrics <command> ...`.

```bash
cd biometrics

# Generate deterministic synthetic samples for testing/demo purposes
python app.py make-samples my-seed
python app.py make-samples my-seed --modalities voice fingerprint --output-dir data/samples

# Enroll an identity against one or more modalities at once
python app.py enroll alice --label "Alice" \
  --voice data/samples/my-seed_voice.wav \
  --fingerprint data/samples/my-seed_fingerprint.pgm \
  --video data/samples/my-seed_video.brvid

# Verify a probe against a stored identity
python app.py verify alice --voice probe.wav                     # single modality
python app.py verify alice --voice probe.wav --fingerprint probe.pgm   # requires ALL by default
python app.py verify alice --voice probe.wav --fingerprint probe.pgm --any-match  # any ONE suffices

python app.py inspect alice     # non-secret summary: id, label, enrolled modalities
python app.py list              # every enrolled identity
python app.py delete alice

# Build/inspect a BRVID clip from individual frame images
python app.py record-video clip.brvid frame1.png frame2.png frame3.png
python app.py probe-video clip.brvid
```

Re-enrolling an identity that already exists is refused outright — there is
no overwrite flag. Delete the identity first if you need to replace its
stored templates.

On first run in a fresh data directory, `enroll`/`verify` create a local
keyring and prompt you to set a passphrase, printing a one-time recovery code
to stderr. See **Storage Model** below.

---

## Storage Model

Templates are sealed under a local BSR2 keyring (`crypto/keyring.py`), the
same master-key-wrapped-under-a-passphrase-and-recovery-code construction
`vault/` uses. Each template is additionally bound to a context string naming
the identity id and modality (`crypto/context.py`), so a template sealed for
one identity or modality can never be swapped into another's slot — a moved
envelope fails authentication instead of decrypting into the wrong place.

Identity **records** (id, label, which modalities are enrolled) stay
readable in the clear so `list`/`inspect` work without unlocking. Template
**payloads** — the actual feature vectors — are what's encrypted.

This is an unattended-friendly design (the keyring unlock still needs a human
passphrase once per session, unlike the vendored device-key pattern used
elsewhere), but the full threat model — what BSR2 does and does not protect
against here — is documented centrally in
[docs/BSR2_INTEGRATION.md](../docs/BSR2_INTEGRATION.md). Read that before
relying on this for anything real.

---

## Repository Layout

```
biometrics/
├── app.py                       CLI entry point
├── config/
│   └── settings.py              paths, template dimensions, default threshold
├── codecs/                      format decode/encode, zero dependencies
│   ├── dsp.py                   framing, windowing, DCT, band energies (voice)
│   ├── image_loader.py          dispatches to pgm.py / png.py by extension
│   ├── image_tools.py           resize, crop, normalize, block-grid-means, Sobel
│   ├── pgm.py                   binary PGM (P5) reader/writer
│   ├── png.py                   minimal 8-bit grayscale PNG reader/writer
│   ├── video.py                 BRVID container reader/writer
│   └── wave_tools.py            WAV PCM reader/writer (8/16/32-bit, mono downmix)
├── engine/
│   ├── enrollment.py            extract -> seal -> attach template
│   ├── modalities.py            per-modality dispatch table (extract/compare/threshold)
│   └── verification.py          open template -> extract probe -> score -> accept/reject
├── features/
│   ├── voice_features.py        MFCC-adjacent summary vector + cosine compare
│   ├── fingerprint_features.py  ridge-orientation grid + cosine compare
│   └── video_features.py        spatial + motion-energy grid + cosine compare
├── identity/
│   ├── device_key.py            weak machine-fingerprint binding (defense in depth only)
│   ├── identity_record.py       record shape/validation, no file I/O
│   └── identity_store.py        one JSON file per identity, atomic writes
├── reports/
│   └── report_writer.py         append-only enrollment/verification audit reports
├── samples/
│   └── sample_generator.py      deterministic synthetic voice/fingerprint/video samples
└── tests/
```

---

## Status

Research-grade. Matching is threshold-based hand-rolled DSP, not a trained
model, and there is currently no liveness or anti-spoofing check for any
modality — a recording or synthetic sample that reproduces the feature
vector closely enough will verify. Do not treat this as a production
biometric authentication system.
