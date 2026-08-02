from pathlib import Path

from config import settings
from config.settings import ensure_data_dirs
from core.pgm import write_pgm


def _face_like_pattern(width: int, height: int, shift: int = 0, contrast: int = 0):
    pixels = []
    center_x = width / 2 + shift
    center_y = height / 2

    for y in range(height):
        for x in range(width):
            dx = (x - center_x) / (width / 2)
            dy = (y - center_y) / (height / 2)
            head_shape = max(0, 1 - (dx * dx + dy * dy))
            value = 220 - int(head_shape * 95)

            if abs(y - height * 0.38) < 3 and (
                abs(x - (center_x - width * 0.16)) < 4 or abs(x - (center_x + width * 0.16)) < 4
            ):
                value = 45

            if abs(x - center_x) < 2 and height * 0.42 < y < height * 0.62:
                value = 105

            if abs(y - height * 0.70) < 2 and abs(x - center_x) < width * 0.18:
                value = 65

            pixels.append(max(0, min(255, value + contrast)))

    return pixels


def _far_pattern(width: int, height: int):
    base = _face_like_pattern(width, height, shift=30, contrast=70)
    pixels = []
    for index, value in enumerate(base):
        x = index % width
        y = index // width
        stripe = 60 if (x // 8 + y // 8) % 2 == 0 else -60
        pixels.append(max(0, min(255, value + stripe)))
    return pixels


def generate_samples(output_dir=None) -> list:
    """Write the demo PGM files into the data directory.

    These used to be written to the current working directory, which put
    generated artifacts wherever the CLI happened to be invoked from and made
    them easy to commit by accident.
    """
    width = 96
    height = 96

    ensure_data_dirs()
    target_dir = (
        Path(output_dir) if output_dir else settings.SAMPLE_DIR
    )
    target_dir.mkdir(parents=True, exist_ok=True)

    files = [
        ("sample_enroll.pgm", _face_like_pattern(width, height, shift=0, contrast=0)),
        ("sample_verify_close.pgm", _face_like_pattern(width, height, shift=2, contrast=3)),
        ("sample_verify_far.pgm", _far_pattern(width, height)),
    ]

    written = []
    for file_name, pixels in files:
        output_path = target_dir / file_name
        write_pgm(str(output_path), width, height, pixels)
        written.append(str(output_path))

    return written
