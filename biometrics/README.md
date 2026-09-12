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
64x64 and a 4000x3000 image — compare on equal footing. Matching is
**normalized Euclidean distance** (`biometrics/features/similarity.py`'s
`distance_similarity`, in `(0.0, 1.0]`) against a per-modality default
threshold (`biometrics/engine/modalities.py`), deliberately conservative:
this is a research/reference implementation, not a tuned production biometric
system, and there is no learned model.

Matching used plain cosine similarity through 1.0.x, which measured only the
*angle* between two feature vectors and not how far apart their actual values
were. For these magnitude-heavy feature spaces that let two different people's
vectors score a near-perfect match; 1.1.0 switched all three modalities to the
distance-based score above (see `docs/CHANGELOG.md` [1.1.0] for the measured
before/after impostor scores).

### Liveness gate (video only)

Since 1.3.0 the video modality has a **motion-presence liveness gate**
(`biometrics/features/liveness.py`). A static clip — a photograph, or any clip
built from a single repeated frame — scores zero motion and is refused at
enrollment and reported as a non-match at verification, before its similarity
score is ever trusted. `--allow-static` overrides the gate on both `enroll`
and `verify`.

This is a **motion-presence check, not general anti-spoofing.** It does *not*
catch a played-back video recording of the real person, a physically wobbled
photograph, or a high-quality mask/deepfake with natural micro-motion. It
closes only the specific "one repeated still frame" gap. The default threshold
is also calibrated only against this project's own synthetic sample generator,
not real camera hardware — see `docs/KNOWN_ISSUES.md` KI-001 and the
`liveness.py` module docstring for the full scope statement.

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

# Skip the video liveness gate (score a static clip anyway)
python app.py enroll alice --label "Alice" --video clip.brvid --allow-static
python app.py verify alice --video clip.brvid --allow-static

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

On first run in a fresh data directory, enroll/verify create a local
keyring and prompt you to set a passphrase, printing a one-time recovery code
to stderr. See **Storage Model** below.

---

## Storage Model

Templates are sealed under a local BSR2 keyring (`crypto/keyring.py`), the
same master-key-wrapped-under-a-passphrase-and-recovery-code construction
`vault/` uses. Unlocking runs the slow KDF once per session (via `getpass`);
every template seal/open after that is fast. Each template is additionally
bound to a context string naming the identity id and modality
(`crypto/context.py`), so a template sealed for one identity or modality can
never be swapped into another's slot — a moved envelope fails authentication
instead of decrypting into the wrong place.

The keyring itself (`keyring.json`) holds the BSR2-wrapped master key. Since
1.3.2 it is written with owner-only (`0600`) permissions on POSIX platforms,
and the loader warns to stderr if it is found more permissive than that (a
no-op on Windows — see `common/atomic_io.py`'s docstring for why POSIX
permission bits are not meaningfully enforceable there). This is filesystem
defense-in-depth; BSR2's own encryption is what actually protects the wrapped
key inside.

Since LTS-2028-SEC-2 (forward-ported to main in 1.9.0), repeated failed unlock attempts against the biometrics
keyring are throttled identically to the vault's own throttling (5
attempts, exponential backoff, a 15-minute lockout), via
`biometrics/identity/keyring_access.py`. Both the CLI and the GUI unlock
through this same module, so neither interface can be used to bypass the
throttling the other enforces.

A separate, weaker **device binding** (`biometrics/identity/device_key.py`)
records a keyed-MAC of machine-specific fingerprint material (hostname,
platform, MAC address) under the master key, as one more thing an attacker
must also reproduce on a different machine. It is explicitly *not* a strong
boundary and *not* a stored key file — only a bound value is kept, never a
recoverable device key.

Identity **records** (id, label, which modalities are enrolled) stay
readable in the clear so `list`/`inspect` work without unlocking. Template
**payloads** — the actual feature vectors — are what's encrypted.

The full threat model — what BSR2 does and does not protect against here —
is documented centrally in
[docs/BSR2_INTEGRATION.md](../docs/BSR2_INTEGRATION.md). Read that before
relying on this for anything real.

---

## Repository Layout

```text
biometrics/
├── app.py                       CLI entry point (keyring unlock, enroll/verify/attach)
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
│   ├── attachments.py           attach arbitrary raw files to an identity
│   ├── bulk_attachments.py      chunked multi-file/folder/drive attachments
│   ├── enrollment.py            extract -> (liveness gate) -> seal -> attach template
│   ├── modalities.py            per-modality dispatch table (extract/compare/threshold)
│   └── verification.py          open template -> (liveness gate) -> extract probe -> score
├── features/
│   ├── similarity.py            shared normalized-Euclidean distance_similarity()
│   ├── voice_features.py        MFCC-adjacent summary vector + distance compare
│   ├── fingerprint_features.py  ridge-orientation grid + distance compare
│   ├── video_features.py        spatial + motion-energy grid + distance compare
│   └── liveness.py              video motion-presence gate (1.3.0)
├── identity/
│   ├── device_key.py            weak machine-fingerprint binding (defense in depth only)
│   ├── identity_record.py       record shape/validation, no file I/O
│   ├── identity_store.py        one JSON file per identity, atomic writes
│   └── keyring_access.py        shared, attempt-throttled keyring unlock (LTS-2028-SEC-2, fwd-ported 1.9.0; CLI + GUI)
├── reports/
│   └── report_writer.py         append-only enrollment/verification audit reports
├── samples/
│   └── sample_generator.py      deterministic synthetic voice/fingerprint/video samples
└── tests/
```

---

## Status

Research-grade. Matching is threshold-based hand-rolled DSP, not a trained
model. The video liveness gate (1.3.0) closes the "static repeated frame" gap
only and is uncalibrated against real cameras; no other modality has any
liveness or anti-spoofing check, and a recording or synthetic sample that
reproduces the feature vector closely enough will still verify. Do not treat
this as a production biometric authentication system.

