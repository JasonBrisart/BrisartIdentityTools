"""
File: biometrics/features/liveness.py

PURPOSE
Reintroduces a liveness/anti-spoofing GATE for the video modality, filling
the gap explicitly documented in biometrics/README.md's Status section
("there is currently no liveness or anti-spoofing check for any modality --
a recording or synthetic sample that reproduces the feature vector closely
enough will verify") and in docs/BSR2_INTEGRATION.md's Residual Risks item 7.

This is NOT a resurrection of the old 0.6.0-beta LabID_Beta/core/video.py
liveness code -- that code parsed real AVI files and no longer exists; this
repository's current video pipeline stores frames in the from-scratch BRVID
container (biometrics/codecs/video.py), which never had liveness logic. This
module is a new implementation built against BRVID's actual frame data.

WHAT IT DETECTS
A still photograph (or any perfectly static scene) held in front of a camera,
or a synthetic clip built from a single repeated frame, produces near-zero
frame-to-frame pixel change. A live capture -- even someone sitting still --
always has some non-zero change from sensor noise, micro-movement, and
lighting flicker. This module measures exactly that: mean absolute pixel
difference between consecutive frames, averaged across the whole clip.

WHAT IT DOES NOT DETECT
This is a MOTION-PRESENCE check, not a liveness/anti-spoofing check in the
research sense. It will NOT catch:
  - A video replay attack (playing a real recorded video of the enrolled
    person back at the camera) -- that has real motion and passes this gate.
  - A high-quality 3D mask or deepfake with natural micro-motion.
  - A photo that is itself physically wobbled/panned in front of the camera
    to fake motion.
This is stated plainly rather than left implied, matching this project's
existing "Research-grade" framing (biometrics/README.md's Status section):
this closes the specific "one repeated still frame" gap, not the general
liveness/anti-spoofing problem.

COMMUNICATION RELATIONSHIPS
- biometrics.engine.verification.verify_modality calls assess_liveness()
  for the "video" modality only, BEFORE trusting the similarity score,
  using the exact same decoded frame list biometrics.codecs.video.decode()
  already produced (no second file read, no second decode).
- biometrics.engine.enrollment.enroll_modality calls assess_liveness() for
  the "video" modality at enrollment time too, so a static clip cannot be
  baked into a template in the first place -- mirroring the 0.6.0-beta
  design decision ("Static-recording enrollment is refused by default, so a
  photograph cannot be baked into a template and make the verification-time
  gate meaningless"), re-implemented here against the current codebase.
- Both call sites accept an `allow_static: bool = False` parameter that
  callers thread through from a new --allow-static CLI flag
  (see biometrics/app.py), mirroring the original 0.6.0-beta
  --allow-static override exactly by name and behavior.

PARAMETERS
DEFAULT_LIVENESS_THRESHOLD (float, default 0.75)
    Minimum required mean absolute per-pixel difference (0-255 grayscale
    scale) between consecutive frames, averaged across every consecutive
    pair in the clip. Chosen as a low floor deliberately: it only needs to
    separate "genuinely zero motion" (a static photo, or a hand-built clip
    of one repeated frame -- which score exactly 0.0) from "any real
    motion at all," not to distinguish subtle liveness cues. This value has
    NOT been calibrated against a real camera; it is calibrated only
    against this project's own synthetic sample generator
    (biometrics.samples.sample_generator), which is the same caveat this
    project's BSR2 cryptography carries for a different reason (see
    docs/BSR2_INTEGRATION.md) -- a mechanism proven correct against its own
    test fixtures, not against real-world adversarial input.
MIN_FRAMES_FOR_LIVENESS (int, default 2)
    A clip with fewer than this many frames has no frame-to-frame
    difference to measure at all. Rather than silently reporting "live"
    for a single-frame clip (which would defeat the entire point of this
    gate), such a clip is always reported as NOT live, consistent with how
    biometrics.features.video_features.extract_from_frames already
    zeroes its own motion component for a single-frame clip.

EDGE-CASE BEHAVIOR
- Empty frame list: raises LivenessError. Every other function in this
  codebase's biometrics.codecs.video module already refuses to construct a
  BRVID container with zero frames (VideoFormatError), so a caller reaching
  this function with an empty list indicates a bug upstream, not a
  legitimate "no frames" liveness case.
- All-identical frames (a hand-built or synthetic all-static clip): scores
  exactly 0.0, always fails the gate. Verified directly in
  biometrics/tests/test_liveness.py.
- Frames of mismatched dimensions: raises LivenessError before any
  comparison is attempted, rather than letting a bytes-length mismatch
  produce a confusing IndexError deep inside the comparison loop.
"""
from biometrics.codecs import image_tools

DEFAULT_LIVENESS_THRESHOLD = 0.75
MIN_FRAMES_FOR_LIVENESS = 2


class LivenessError(ValueError):
    """Raised when liveness cannot be assessed due to malformed input."""


def _mean_absolute_frame_difference(width: int, height: int, previous: bytes, current: bytes) -> float:
    frame_bytes = width * height
    if len(previous) != frame_bytes or len(current) != frame_bytes:
        raise LivenessError(
            f"frame byte length does not match {width}x{height} dimensions."
        )
    total_difference = sum(abs(a - b) for a, b in zip(previous, current))
    return total_difference / frame_bytes


def compute_motion_energy(width: int, height: int, frames: list) -> float:
    """Mean absolute per-pixel frame-to-frame difference across a clip.

    Returns 0.0 for a clip with fewer than MIN_FRAMES_FOR_LIVENESS frames,
    since there is no consecutive pair to compare -- this is a real zero,
    not a missing-data sentinel, and callers should treat it as "no motion
    detected" rather than special-casing it further.
    """
    if width <= 0 or height <= 0:
        raise LivenessError("width and height must be positive.")
    if not frames:
        raise LivenessError("at least one frame is required to assess liveness.")
    if len(frames) < MIN_FRAMES_FOR_LIVENESS:
        return 0.0
    differences = [
        _mean_absolute_frame_difference(width, height, previous, current)
        for previous, current in zip(frames, frames[1:])
    ]
    return sum(differences) / len(differences)


def assess_liveness(
    width: int,
    height: int,
    frames: list,
    threshold: float = DEFAULT_LIVENESS_THRESHOLD,
) -> dict:
    """Assess whether a decoded BRVID frame sequence shows real motion.

    Returns {"motion_energy", "threshold", "is_live"}. `is_live` is the
    single field every caller should actually branch on; `motion_energy`
    and `threshold` are included so a verification/enrollment report can
    record the actual measured value rather than just a pass/fail bit,
    matching this project's existing convention of recording scores
    alongside thresholds (see biometrics.reports.report_writer's
    per-modality result shape).
    """
    if threshold <= 0:
        raise LivenessError("threshold must be positive.")
    motion_energy = compute_motion_energy(width, height, frames)
    return {
        "motion_energy": motion_energy,
        "threshold": threshold,
        "is_live": motion_energy >= threshold,
    }
