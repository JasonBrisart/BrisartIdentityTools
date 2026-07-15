import hashlib
import json
from pathlib import Path

from config.settings import GRID_SIZE, TEMPLATE_HEIGHT, TEMPLATE_WIDTH
from core.image_tools import block_averages, gradient_grid, normalize_pixels, resize_nearest
from core.pgm import read_pgm


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_template(image_path: str) -> dict:
    width, height, pixels = read_pgm(image_path)

    resized = resize_nearest(width, height, pixels, TEMPLATE_WIDTH, TEMPLATE_HEIGHT)
    normalized = normalize_pixels(resized)

    intensity_features = block_averages(normalized, TEMPLATE_WIDTH, TEMPLATE_HEIGHT, GRID_SIZE)
    gradient_features = gradient_grid(normalized, TEMPLATE_WIDTH, TEMPLATE_HEIGHT, GRID_SIZE)

    features = {
        "intensity_grid": intensity_features,
        "gradient_grid": gradient_features,
    }

    template = {
        "template_version": "0.2.0-beta",
        "mode": "local_biometric_verification_beta",
        "source_image_sha256": sha256_file(Path(image_path)),
        "source_format": "PGM grayscale",
        "width": TEMPLATE_WIDTH,
        "height": TEMPLATE_HEIGHT,
        "grid_size": GRID_SIZE,
        "features": features,
    }

    stable_features = json.dumps(features, sort_keys=True).encode("utf-8")
    template["template_sha256"] = sha256_bytes(stable_features)

    return template
