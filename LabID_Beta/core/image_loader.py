from pathlib import Path

from core.pgm import read_pgm
from core.png import read_png_grayscale


class ImageLoadError(Exception):
    """Raised when an image format is unsupported or cannot be decoded."""


def read_grayscale_image(path: str):
    image_path = Path(path)
    suffix = image_path.suffix.lower()

    if suffix == ".pgm":
        return read_pgm(str(image_path))
    if suffix == ".png":
        return read_png_grayscale(str(image_path))

    raise ImageLoadError(
        f"Unsupported image format: {image_path.suffix or '(no extension)'}. "
        "Supported formats are .pgm and .png."
    )
