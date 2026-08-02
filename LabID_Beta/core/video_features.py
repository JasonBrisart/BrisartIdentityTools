"""Video FaceID templates built from an uncompressed AVI recording.

A video recording carries two things a still image cannot: several samples of
the same face, and evidence that the subject moved. Both are used here.

Frame selection: frames are scored by contrast (population standard deviation
of pixel intensity) and the strongest ones are kept, so heavily under- or
over-exposed frames do not drag the template down.

Face features: each kept frame goes through the same resize / normalise /
block-average / gradient pipeline the still-image face path uses, then the
per-frame vectors are averaged. That keeps a video template comparable in shape
to a still template while being less sensitive to a single bad frame.

Motion features: mean and peak absolute frame-to-frame difference plus the
fraction of pixels that changed, recorded as a liveness signal. A recording of
a printed photograph produces near-zero motion, so the signal is meaningful
even though it is not a substitute for real liveness detection.
"""

import hashlib
import json
import statistics
from pathlib import Path

from core.image_tools import block_averages, gradient_grid, normalize_pixels, resize_nearest
from core.video import read_avi_grayscale_frames

VIDEO_TEMPLATE_VERSION = "0.1.0-beta"
VIDEO_MODE = "local_video_face_verification_beta"

TEMPLATE_WIDTH = 64
TEMPLATE_HEIGHT = 64
GRID_SIZE = 8

# How many frames to read, and how many of the best to keep.
MAX_FRAMES_READ = 300
KEY_FRAME_COUNT = 8
MIN_FRAMES_REQUIRED = 2

# A pixel counts as "changed" above this absolute difference.
MOTION_PIXEL_THRESHOLD = 12

# Minimum mean frame-to-frame difference a live recording must show. A recording
# of a printed photo or a still frame held in front of the lens sits at ~0.0.
# Measured sample recordings sit around 2.2, so 0.35 separates them with room to
# spare without demanding that the subject move dramatically.
MIN_LIVENESS_MOTION = 0.35
MIN_LIVENESS_PIXEL_RATIO = 0.002



class VideoTemplateError(Exception):
    """Raised when a video template cannot be built."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _select_key_frames(frames, keep: int):
    """Keep the highest-contrast frames, back in their original order."""
    if len(frames) <= keep:
        return list(range(len(frames))), list(frames)

    scored = []
    for index, frame in enumerate(frames):
        scored.append((statistics.pstdev(frame), index))
    scored.sort(reverse=True)

    chosen = sorted(index for _score, index in scored[:keep])
    return chosen, [frames[index] for index in chosen]


def _motion_features(width: int, height: int, frames) -> dict:
    """Frame-to-frame difference statistics across the whole recording."""
    if len(frames) < 2:
        return {
            "motion_mean": 0.0,
            "motion_peak": 0.0,
            "motion_pixel_ratio": 0.0,
        }

    pixel_count = width * height
    per_frame_means = []
    per_frame_ratios = []

    for previous, current in zip(frames, frames[1:]):
        total = 0
        changed = 0
        for a, b in zip(previous, current):
            difference = a - b
            if difference < 0:
                difference = -difference
            total += difference
            if difference >= MOTION_PIXEL_THRESHOLD:
                changed += 1
        per_frame_means.append(total / float(pixel_count))
        per_frame_ratios.append(changed / float(pixel_count))

    return {
        "motion_mean": round(statistics.fmean(per_frame_means), 6),
        "motion_peak": round(max(per_frame_means), 6),
        "motion_pixel_ratio": round(statistics.fmean(per_frame_ratios), 6),
    }


def _average_vectors(vectors) -> list:
    """Element-wise mean of equal-length feature vectors."""
    length = len(vectors[0])
    for vector in vectors:
        if len(vector) != length:
            raise VideoTemplateError("Per-frame feature vectors have inconsistent lengths.")

    return [
        round(statistics.fmean([vector[index] for vector in vectors]), 4)
        for index in range(length)
    ]


def create_video_template(video_path: str) -> dict:
    """Build a face template from an uncompressed AVI recording."""
    path = Path(video_path)
    width, height, frames = read_avi_grayscale_frames(str(path), max_frames=MAX_FRAMES_READ)

    if len(frames) < MIN_FRAMES_REQUIRED:
        raise VideoTemplateError(
            f"Video recording has {len(frames)} frame(s); at least "
            f"{MIN_FRAMES_REQUIRED} are needed to build a video template."
        )

    motion = _motion_features(width, height, frames)
    key_indexes, key_frames = _select_key_frames(frames, KEY_FRAME_COUNT)

    intensity_vectors = []
    gradient_vectors = []
    for frame in key_frames:
        resized = resize_nearest(width, height, frame, TEMPLATE_WIDTH, TEMPLATE_HEIGHT)
        normalized = normalize_pixels(resized)
        intensity_vectors.append(
            block_averages(normalized, TEMPLATE_WIDTH, TEMPLATE_HEIGHT, GRID_SIZE)
        )
        gradient_vectors.append(
            gradient_grid(normalized, TEMPLATE_WIDTH, TEMPLATE_HEIGHT, GRID_SIZE)
        )

    features = {
        "intensity_grid": _average_vectors(intensity_vectors),
        "gradient_grid": _average_vectors(gradient_vectors),
        "motion_mean": motion["motion_mean"],
        "motion_peak": motion["motion_peak"],
        "motion_pixel_ratio": motion["motion_pixel_ratio"],
        "frame_count": len(frames),
        "key_frame_count": len(key_frames),
        "frame_width": width,
        "frame_height": height,
    }

    template = {
        "template_version": VIDEO_TEMPLATE_VERSION,
        "mode": VIDEO_MODE,
        "source_video_sha256": sha256_file(path),
        "source_format": "AVI uncompressed DIB",
        "width": TEMPLATE_WIDTH,
        "height": TEMPLATE_HEIGHT,
        "grid_size": GRID_SIZE,
        "key_frame_indexes": key_indexes,
        "features": features,
    }

    stable_features = json.dumps(features, sort_keys=True).encode("utf-8")
    template["template_sha256"] = sha256_bytes(stable_features)
    return template


def liveness_assessment(template: dict) -> dict:
    """Judge whether a video template shows a moving subject.

    This is a movement check, not real liveness detection: it defeats a still
    photograph held up to the lens, but not a replayed video of the subject.
    That limitation is recorded in the report rather than papered over.
    """
    features = template["features"]
    motion_mean = float(features["motion_mean"])
    pixel_ratio = float(features["motion_pixel_ratio"])

    passed = (
        motion_mean >= MIN_LIVENESS_MOTION
        and pixel_ratio >= MIN_LIVENESS_PIXEL_RATIO
    )

    if passed:
        reason = "Frame-to-frame motion is consistent with a live recording."
    elif motion_mean < MIN_LIVENESS_MOTION:
        reason = (
            f"Mean frame-to-frame motion {motion_mean:.4f} is below the "
            f"{MIN_LIVENESS_MOTION} minimum; the recording looks static, which "
            "is what a photograph or a frozen frame produces."
        )
    else:
        reason = (
            f"Only {pixel_ratio:.4%} of pixels changed between frames, below "
            f"the {MIN_LIVENESS_PIXEL_RATIO:.2%} minimum."
        )

    return {
        "passed": passed,
        "motion_mean": round(motion_mean, 6),
        "motion_pixel_ratio": round(pixel_ratio, 6),
        "motion_minimum": MIN_LIVENESS_MOTION,
        "pixel_ratio_minimum": MIN_LIVENESS_PIXEL_RATIO,
        "reason": reason,
    }
