import hashlib
import json
import math
from pathlib import Path
from typing import Optional

from core.fingerprint_features import FINGERPRINT_MODE, create_fingerprint_template
from core.image_loader import read_grayscale_image
from core.image_tools import block_averages, gradient_grid, normalize_pixels, resize_nearest
from core.video_features import VIDEO_MODE, create_video_template, liveness_assessment
from core.voice_features import VOICE_MODE, create_voice_template


FACE_MODE = "local_biometric_verification_beta"
FACE_TEMPLATE_VERSION = "0.3.0-beta"
FACE_TEMPLATE_WIDTH = 64
FACE_TEMPLATE_HEIGHT = 64
FACE_GRID_SIZE = 8


SUPPORTED_MODALITIES = ('face', 'video', 'voice', 'fingerprint')

DEFAULT_THRESHOLDS = {
    'face': 0.94,
    'video': 0.94,
    'voice': 0.94,
    'fingerprint': 0.975,
}


class BiometricModalityError(Exception):
    """Raised when a modality is unsupported or incompatible."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_face_template(image_path: str) -> dict:
    width, height, pixels = read_grayscale_image(image_path)
    resized = resize_nearest(width, height, pixels, FACE_TEMPLATE_WIDTH, FACE_TEMPLATE_HEIGHT)
    normalized = normalize_pixels(resized)

    features = {
        "intensity_grid": block_averages(normalized, FACE_TEMPLATE_WIDTH, FACE_TEMPLATE_HEIGHT, FACE_GRID_SIZE),
        "gradient_grid": gradient_grid(normalized, FACE_TEMPLATE_WIDTH, FACE_TEMPLATE_HEIGHT, FACE_GRID_SIZE),
    }

    template = {
        "template_version": FACE_TEMPLATE_VERSION,
        "mode": FACE_MODE,
        "source_image_sha256": _sha256_file(Path(image_path)),
        "source_format": Path(image_path).suffix.lower().lstrip('.') or 'image',
        "width": FACE_TEMPLATE_WIDTH,
        "height": FACE_TEMPLATE_HEIGHT,
        "grid_size": FACE_GRID_SIZE,
        "features": features,
    }
    stable_features = json.dumps(features, sort_keys=True).encode("utf-8")
    template["template_sha256"] = _sha256_bytes(stable_features)
    return template


def _euclidean_distance(values_a, values_b) -> float:
    if len(values_a) != len(values_b):
        raise ValueError("Feature vectors must be the same length.")
    return math.sqrt(sum((float(a) - float(b)) ** 2 for a, b in zip(values_a, values_b)))


def _vector_similarity(values_a, values_b, scale: float) -> float:
    distance = _euclidean_distance(values_a, values_b)
    return 1.0 - min(1.0, distance / float(scale))


def face_similarity(stored_template: dict, candidate_template: dict) -> float:
    stored = stored_template["features"]
    candidate = candidate_template["features"]
    intensity = _vector_similarity(stored["intensity_grid"], candidate["intensity_grid"], math.sqrt(len(stored["intensity_grid"]) * (255 ** 2)))
    gradient = _vector_similarity(stored["gradient_grid"], candidate["gradient_grid"], math.sqrt(len(stored["gradient_grid"]) * (255 ** 2)))
    return round((0.70 * intensity) + (0.30 * gradient), 6)


def video_similarity(stored_template: dict, candidate_template: dict) -> float:
    """Face similarity across averaged key frames.

    Motion is deliberately not folded into this score. A replayed photograph can
    score a near-perfect face match, so movement is enforced as a separate gate
    in ``requires_liveness`` / ``liveness_assessment`` rather than being diluted
    into a weighted average that a strong face match would overwhelm.
    """
    stored = stored_template["features"]
    candidate = candidate_template["features"]
    intensity = _vector_similarity(stored["intensity_grid"], candidate["intensity_grid"], math.sqrt(len(stored["intensity_grid"]) * (255 ** 2)))
    gradient = _vector_similarity(stored["gradient_grid"], candidate["gradient_grid"], math.sqrt(len(stored["gradient_grid"]) * (255 ** 2)))
    return round((0.70 * intensity) + (0.30 * gradient), 6)


def voice_similarity(stored_template: dict, candidate_template: dict) -> float:
    stored = stored_template["features"]
    candidate = candidate_template["features"]
    mean_score = _vector_similarity(stored["mfcc_mean"], candidate["mfcc_mean"], 250.0)
    stdev_score = _vector_similarity(stored["mfcc_stdev"], candidate["mfcc_stdev"], 120.0)
    pitch_distance = abs(float(stored["pitch_mean_hz"]) - float(candidate["pitch_mean_hz"]))
    pitch_score = 1.0 - min(1.0, pitch_distance / 180.0)
    energy_score = 1.0 - min(1.0, abs(float(stored["energy_mean"]) - float(candidate["energy_mean"])) / 0.35)
    zcr_score = 1.0 - min(1.0, abs(float(stored["zcr_mean"]) - float(candidate["zcr_mean"])) / 0.35)
    return round((0.55 * mean_score) + (0.15 * stdev_score) + (0.15 * pitch_score) + (0.10 * energy_score) + (0.05 * zcr_score), 6)


def fingerprint_similarity(stored_template: dict, candidate_template: dict) -> float:
    stored = stored_template["features"]
    candidate = candidate_template["features"]
    intensity = _vector_similarity(stored["intensity_grid"], candidate["intensity_grid"], math.sqrt(len(stored["intensity_grid"]) * (255 ** 2)))
    orientation = _vector_similarity(stored["orientation_grid"], candidate["orientation_grid"], math.sqrt(len(stored["orientation_grid"]) * (1.0 ** 2)))
    coherence = _vector_similarity(stored["coherence_grid"], candidate["coherence_grid"], math.sqrt(len(stored["coherence_grid"]) * (255 ** 2)))
    endings = _vector_similarity(stored["ending_grid"], candidate["ending_grid"], math.sqrt(len(stored["ending_grid"]) * (255 ** 2)))
    bifurcations = _vector_similarity(stored["bifurcation_grid"], candidate["bifurcation_grid"], math.sqrt(len(stored["bifurcation_grid"]) * (255 ** 2)))
    return round((0.30 * intensity) + (0.20 * orientation) + (0.20 * coherence) + (0.15 * endings) + (0.15 * bifurcations), 6)


def detect_modality(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix == '.wav':
        return 'voice'
    if suffix == '.avi':
        return 'video'
    if suffix in ('.png', '.pgm'):
        return 'face'
    raise BiometricModalityError(
        f"Cannot infer modality from {suffix or '(no extension)'}. Use an explicit modality."
    )


def normalize_modality(modality: Optional[str], path: str) -> str:
    candidate = (modality or '').strip().lower()
    if not candidate:
        return detect_modality(path)
    if candidate not in SUPPORTED_MODALITIES:
        raise BiometricModalityError(
            f"Unsupported modality: {modality}. "
            f"Supported: {', '.join(SUPPORTED_MODALITIES)}."
        )
    return candidate


def requires_liveness(modality: str) -> bool:
    """Video is the only modality carrying a temporal liveness signal."""
    return modality == 'video'


def assess_liveness(template: dict) -> dict:
    return liveness_assessment(template)


def default_threshold_for_modality(modality: str) -> float:
    try:
        return DEFAULT_THRESHOLDS[modality]
    except KeyError as exc:
        raise BiometricModalityError(f"Unsupported modality: {modality}") from exc


def create_template(modality: str, source_path: str) -> dict:
    if modality == 'face':
        return create_face_template(source_path)
    if modality == 'video':
        return create_video_template(source_path)
    if modality == 'voice':
        return create_voice_template(source_path)
    if modality == 'fingerprint':
        return create_fingerprint_template(source_path)
    raise BiometricModalityError(f"Unsupported modality: {modality}")


def template_similarity(stored_template: dict, candidate_template: dict) -> float:
    mode = stored_template.get('mode')
    if mode != candidate_template.get('mode'):
        raise BiometricModalityError(
            f"Stored template mode {mode!r} does not match candidate mode {candidate_template.get('mode')!r}."
        )
    if mode == FACE_MODE:
        return face_similarity(stored_template, candidate_template)
    if mode == VIDEO_MODE:
        return video_similarity(stored_template, candidate_template)
    if mode == VOICE_MODE:
        return voice_similarity(stored_template, candidate_template)
    if mode == FINGERPRINT_MODE:
        return fingerprint_similarity(stored_template, candidate_template)
    raise BiometricModalityError(f"Unsupported stored template mode: {mode}")
