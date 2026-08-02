import hashlib
import json
import math
from pathlib import Path

from core.image_loader import read_grayscale_image
from core.image_tools import block_averages, normalize_pixels, resize_nearest


FINGERPRINT_TEMPLATE_VERSION = "0.1.0-beta"
FINGERPRINT_MODE = "local_fingerprint_verification_beta"
TEMPLATE_WIDTH = 96
TEMPLATE_HEIGHT = 96
GRID_SIZE = 12


class FingerprintTemplateError(Exception):
    """Raised when a fingerprint template cannot be built."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _orientation_and_coherence(pixels, width: int, height: int):
    orientation = [0.0] * (width * height)
    coherence = [0.0] * (width * height)

    for y in range(1, height - 1):
        for x in range(1, width - 1):
            left = pixels[y * width + (x - 1)]
            right = pixels[y * width + (x + 1)]
            up = pixels[(y - 1) * width + x]
            down = pixels[(y + 1) * width + x]

            gx = float(right) - float(left)
            gy = float(down) - float(up)

            idx = y * width + x
            orientation[idx] = (math.atan2(gy, gx) + math.pi) / (2.0 * math.pi)
            coherence[idx] = min(255.0, math.sqrt(gx * gx + gy * gy))

    return orientation, coherence


def _local_minutiae_proxy(pixels, width: int, height: int):
    binary = [1 if value < 110 else 0 for value in pixels]
    endings = [0.0] * (width * height)
    bifurcations = [0.0] * (width * height)

    neighbors = [
        (-1, -1), (0, -1), (1, -1),
        (1, 0), (1, 1), (0, 1),
        (-1, 1), (-1, 0),
    ]

    for y in range(1, height - 1):
        for x in range(1, width - 1):
            idx = y * width + x
            if not binary[idx]:
                continue
            ring = []
            for dx, dy in neighbors:
                ring.append(binary[(y + dy) * width + (x + dx)])
            transitions = 0
            for left, right in zip(ring, ring[1:] + ring[:1]):
                if left == 0 and right == 1:
                    transitions += 1
            if transitions == 1:
                endings[idx] = 255.0
            elif transitions >= 3:
                bifurcations[idx] = 255.0

    return endings, bifurcations


def create_fingerprint_template(image_path: str) -> dict:
    path = Path(image_path)
    width, height, pixels = read_grayscale_image(str(path))

    resized = resize_nearest(width, height, pixels, TEMPLATE_WIDTH, TEMPLATE_HEIGHT)
    normalized = normalize_pixels(resized)
    orientation, coherence = _orientation_and_coherence(normalized, TEMPLATE_WIDTH, TEMPLATE_HEIGHT)
    endings, bifurcations = _local_minutiae_proxy(normalized, TEMPLATE_WIDTH, TEMPLATE_HEIGHT)

    features = {
        "intensity_grid": block_averages(normalized, TEMPLATE_WIDTH, TEMPLATE_HEIGHT, GRID_SIZE),
        "orientation_grid": block_averages(orientation, TEMPLATE_WIDTH, TEMPLATE_HEIGHT, GRID_SIZE),
        "coherence_grid": block_averages(coherence, TEMPLATE_WIDTH, TEMPLATE_HEIGHT, GRID_SIZE),
        "ending_grid": block_averages(endings, TEMPLATE_WIDTH, TEMPLATE_HEIGHT, GRID_SIZE),
        "bifurcation_grid": block_averages(bifurcations, TEMPLATE_WIDTH, TEMPLATE_HEIGHT, GRID_SIZE),
    }

    template = {
        "template_version": FINGERPRINT_TEMPLATE_VERSION,
        "mode": FINGERPRINT_MODE,
        "source_image_sha256": sha256_file(path),
        "source_format": path.suffix.lower().lstrip('.') or 'image',
        "width": TEMPLATE_WIDTH,
        "height": TEMPLATE_HEIGHT,
        "grid_size": GRID_SIZE,
        "features": features,
    }

    stable_features = json.dumps(features, sort_keys=True).encode("utf-8")
    template["template_sha256"] = sha256_bytes(stable_features)
    return template
