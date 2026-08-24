"""Fingerprint feature extraction: a grayscale image reduced to a ridge-
orientation summary vector.

Real fingerprint matching systems use minutiae extraction (ridge endings and
bifurcations located precisely in the image). That is a substantially more
complex pipeline than a dependency-free, auditable implementation can
responsibly cover. This module instead computes a coarser but still
meaningful summary: local ridge-orientation and ridge-density estimates over
a fixed grid, derived from Sobel gradients. It is a legitimate, well-known
class of fingerprint descriptor (orientation-field based), just not a
minutiae-based one.

The output is a fixed-length vector regardless of input image resolution.
"""
import math

from biometrics.codecs import image_loader, image_tools

TARGET_WIDTH = 128
TARGET_HEIGHT = 128
GRID_SIZE = 8

# orientation (as cos, sin pair) + magnitude, per grid cell
FEATURE_VECTOR_LENGTH = GRID_SIZE * GRID_SIZE * 3


class FingerprintFeatureError(ValueError):
    """Raised when fingerprint feature extraction cannot proceed."""


def _cell_bounds(total: int, parts: int) -> list:
    base, remainder = divmod(total, parts)
    bounds = []
    cursor = 0
    for index in range(parts):
        size = base + (1 if index < remainder else 0)
        bounds.append((cursor, cursor + size))
        cursor += size
    return bounds


def _orientation_field(width: int, height: int, pixels: bytes) -> list:
    """Estimate local ridge orientation and strength for one grid cell.

    Uses the standard gradient-based orientation estimator: average the
    doubled gradient-angle vector over the cell so that opposing gradient
    directions (which represent the same ridge orientation, 180 degrees
    apart) reinforce rather than cancel.
    """
    gradients_x = []
    gradients_y = []

    def at(row: int, col: int) -> int:
        row = min(max(row, 0), height - 1)
        col = min(max(col, 0), width - 1)
        return pixels[row * width + col]

    for row in range(height):
        for col in range(width):
            gx = at(row, col + 1) - at(row, col - 1)
            gy = at(row + 1, col) - at(row - 1, col)
            gradients_x.append(gx)
            gradients_y.append(gy)

    sin_sum = 0.0
    cos_sum = 0.0
    magnitude_sum = 0.0
    count = len(gradients_x)
    for gx, gy in zip(gradients_x, gradients_y):
        angle = math.atan2(gy, gx)
        magnitude = (gx * gx + gy * gy) ** 0.5
        sin_sum += math.sin(2 * angle) * magnitude
        cos_sum += math.cos(2 * angle) * magnitude
        magnitude_sum += magnitude
    if count == 0:
        return 0.0, 0.0, 0.0
    average_magnitude = magnitude_sum / count
    if magnitude_sum == 0:
        return 0.0, 0.0, average_magnitude
    return cos_sum / magnitude_sum, sin_sum / magnitude_sum, average_magnitude


def extract_from_pixels(width: int, height: int, pixels: bytes) -> list:
    """Extract a fixed-length ridge-orientation vector from a grayscale image."""
    if width <= 0 or height <= 0:
        raise FingerprintFeatureError("width and height must be positive.")
    if len(pixels) != width * height:
        raise FingerprintFeatureError("pixel buffer does not match dimensions.")
    resized = image_tools.resize_nearest(
        width, height, pixels, TARGET_WIDTH, TARGET_HEIGHT
    )
    normalized = image_tools.normalize(resized)

    row_bounds = _cell_bounds(TARGET_HEIGHT, GRID_SIZE)
    col_bounds = _cell_bounds(TARGET_WIDTH, GRID_SIZE)

    vector = []
    for row_start, row_end in row_bounds:
        for col_start, col_end in col_bounds:
            cell_height = row_end - row_start
            cell_width = col_end - col_start
            cell = bytearray(cell_width * cell_height)
            for row in range(cell_height):
                source_offset = (row_start + row) * TARGET_WIDTH + col_start
                cell[row * cell_width:(row + 1) * cell_width] = normalized[
                    source_offset:source_offset + cell_width
                ]
            cos_component, sin_component, magnitude = _orientation_field(
                cell_width, cell_height, bytes(cell)
            )
            vector.extend([cos_component, sin_component, magnitude])
    return vector


def extract_from_image(path) -> list:
    """Load an image file and extract its fingerprint feature vector."""
    loaded = image_loader.load_image(path)
    return extract_from_pixels(loaded["width"], loaded["height"], loaded["pixels"])


def compare(vector_a: list, vector_b: list) -> float:
    """Cosine similarity between two fingerprint feature vectors.

    The orientation components already encode angle as a unit-circle
    (cos, sin) pair, so cosine similarity naturally rewards matching
    orientation fields regardless of overall ridge contrast.
    """
    if len(vector_a) != len(vector_b):
        raise FingerprintFeatureError("feature vectors must be the same length.")
    dot_product = sum(a * b for a, b in zip(vector_a, vector_b))
    magnitude_a = sum(a * a for a in vector_a) ** 0.5
    magnitude_b = sum(b * b for b in vector_b) ** 0.5
    if magnitude_a == 0 or magnitude_b == 0:
        return 0.0
    return dot_product / (magnitude_a * magnitude_b)
