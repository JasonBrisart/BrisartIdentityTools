"""Format-agnostic image loading, dispatched by file extension.

Every other part of biometrics that needs a still image (fingerprint capture,
a frame lifted from ``video.py``, a generated sample) should go through this
module rather than importing ``pgm`` or ``png`` directly. That keeps the
"which codec handles this file" decision in exactly one place, so adding a
third still-image format later is a one-file change instead of a search
across the codebase.
"""
from pathlib import Path

from biometrics.codecs import pgm, png

SUPPORTED_SUFFIXES = (".pgm", ".png")


class UnsupportedImageFormatError(ValueError):
    """Raised when a file's extension does not map to a known image codec."""


def load_image(path) -> dict:
    """Load an image file, returning ``{"width", "height", "pixels", "path"}``.

    ``pixels`` is always flat 8-bit grayscale bytes, row-major, regardless of
    which codec produced it, so callers never need to branch on format.
    """
    resolved = Path(path)
    suffix = resolved.suffix.lower()
    if suffix == ".pgm":
        decoded = pgm.read_pgm(resolved)
        if decoded["maxval"] != 255:
            decoded = _rescale_to_255(decoded)
    elif suffix == ".png":
        decoded = png.read_png(resolved)
    else:
        raise UnsupportedImageFormatError(
            f"unsupported image extension {suffix!r}; expected one of "
            f"{SUPPORTED_SUFFIXES}."
        )
    return {
        "width": decoded["width"],
        "height": decoded["height"],
        "pixels": decoded["pixels"],
        "path": str(resolved),
    }


def save_image(path, width: int, height: int, pixels: bytes) -> None:
    """Save flat grayscale pixel data, choosing the codec by file extension."""
    resolved = Path(path)
    suffix = resolved.suffix.lower()
    if suffix == ".pgm":
        pgm.write_pgm(resolved, width, height, pixels)
    elif suffix == ".png":
        png.write_png(resolved, width, height, pixels)
    else:
        raise UnsupportedImageFormatError(
            f"unsupported image extension {suffix!r}; expected one of "
            f"{SUPPORTED_SUFFIXES}."
        )


def _rescale_to_255(decoded: dict) -> dict:
    """Rescale a PGM with maxval < 255 up to the 0-255 range."""
    maxval = decoded["maxval"]
    pixels = decoded["pixels"]
    scaled = bytes(min(255, (value * 255) // maxval) for value in pixels)
    return {"width": decoded["width"], "height": decoded["height"], "pixels": scaled}
