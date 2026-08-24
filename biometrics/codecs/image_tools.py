"""Pure-Python grayscale image manipulation used to prepare template inputs.

Every biometric template in this project is ultimately a fixed-size grid of
values derived from a variable-size input (a captured image, a decoded video
frame). These functions do the two things every feature extractor needs
before it can compute anything: get the image to a known size, and reduce it
to a ``grid_size x grid_size`` block-mean summary. No third-party imaging
library is used; everything here is nested-loop arithmetic over flat
``bytes``.
"""
MIN_DIMENSION = 1
MAX_DIMENSION = 8192


class ImageToolsError(ValueError):
    """Raised on invalid dimensions or malformed pixel buffers."""


def _check_image(width: int, height: int, pixels: bytes) -> None:
    if width < MIN_DIMENSION or height < MIN_DIMENSION:
        raise ImageToolsError("width and height must be at least 1.")
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        raise ImageToolsError("width or height exceeds the supported maximum.")
    if len(pixels) != width * height:
        raise ImageToolsError(
            f"expected {width * height} pixel bytes, got {len(pixels)}."
        )


def crop_center(width: int, height: int, pixels: bytes, target_width: int, target_height: int) -> tuple:
    """Crop the centered ``target_width x target_height`` region.

    If the source is smaller than the target in either dimension, the image is
    first padded with black (0) pixels so the crop never reads out of bounds.
    """
    _check_image(width, height, pixels)
    if target_width < MIN_DIMENSION or target_height < MIN_DIMENSION:
        raise ImageToolsError("target dimensions must be at least 1.")
    pad_width = max(width, target_width)
    pad_height = max(height, target_height)
    if pad_width != width or pad_height != height:
        width, height, pixels = _pad_to(width, height, pixels, pad_width, pad_height)
    left = (width - target_width) // 2
    top = (height - target_height) // 2
    out = bytearray(target_width * target_height)
    for row in range(target_height):
        source_start = (top + row) * width + left
        out[row * target_width:(row + 1) * target_width] = pixels[
            source_start:source_start + target_width
        ]
    return target_width, target_height, bytes(out)


def _pad_to(width: int, height: int, pixels: bytes, new_width: int, new_height: int) -> tuple:
    left = (new_width - width) // 2
    top = (new_height - height) // 2
    out = bytearray(new_width * new_height)
    for row in range(height):
        destination_start = (top + row) * new_width + left
        out[destination_start:destination_start + width] = pixels[
            row * width:(row + 1) * width
        ]
    return new_width, new_height, bytes(out)


def resize_nearest(width: int, height: int, pixels: bytes, target_width: int, target_height: int) -> bytes:
    """Resize via nearest-neighbor sampling.

    Nearest neighbor is chosen over interpolation deliberately: it never
    invents a pixel value that was not present in the source, which keeps
    template generation reproducible without floating-point rounding
    differences across platforms.
    """
    _check_image(width, height, pixels)
    if target_width < MIN_DIMENSION or target_height < MIN_DIMENSION:
        raise ImageToolsError("target dimensions must be at least 1.")
    out = bytearray(target_width * target_height)
    for target_row in range(target_height):
        source_row = min(height - 1, (target_row * height) // target_height)
        row_offset = source_row * width
        out_offset = target_row * target_width
        for target_col in range(target_width):
            source_col = min(width - 1, (target_col * width) // target_width)
            out[out_offset + target_col] = pixels[row_offset + source_col]
    return bytes(out)


def normalize(pixels: bytes) -> bytes:
    """Stretch pixel values to fill the full 0-255 range.

    A flat (constant) input is returned unchanged rather than divided by a
    zero range, since there is no meaningful contrast to stretch.
    """
    if not pixels:
        return pixels
    low = min(pixels)
    high = max(pixels)
    if high == low:
        return bytes(pixels)
    scale = 255.0 / (high - low)
    return bytes(int(round((value - low) * scale)) for value in pixels)


def block_grid_means(width: int, height: int, pixels: bytes, grid_size: int) -> list:
    """Reduce an image to a ``grid_size x grid_size`` grid of block-mean values.

    This is the core dimensionality reduction behind every image-derived
    template in this project: it turns a variable-resolution capture into a
    fixed, small, comparable summary. Rows and columns are divided as evenly
    as integer arithmetic allows so every block width differs from its
    neighbors by at most one pixel.
    """
    _check_image(width, height, pixels)
    if grid_size < 1:
        raise ImageToolsError("grid_size must be at least 1.")
    row_bounds = _partition(height, grid_size)
    col_bounds = _partition(width, grid_size)
    means = []
    for row_start, row_end in row_bounds:
        for col_start, col_end in col_bounds:
            total = 0
            count = 0
            for row in range(row_start, row_end):
                offset = row * width
                total += sum(pixels[offset + col_start:offset + col_end])
                count += col_end - col_start
            means.append(total / count if count else 0.0)
    return means


def _partition(total: int, parts: int) -> list:
    base, remainder = divmod(total, parts)
    bounds = []
    cursor = 0
    for index in range(parts):
        size = base + (1 if index < remainder else 0)
        bounds.append((cursor, cursor + size))
        cursor += size
    return bounds


def sobel_gradient_magnitude(width: int, height: int, pixels: bytes) -> list:
    """Approximate edge strength at every pixel using a 3x3 Sobel operator.

    Used by the fingerprint feature extractor to build a ridge-orientation
    summary. Border pixels use replicated edge padding rather than being
    skipped, so the output has the same dimensions as the input.
    """
    _check_image(width, height, pixels)

    def at(row: int, col: int) -> int:
        row = min(max(row, 0), height - 1)
        col = min(max(col, 0), width - 1)
        return pixels[row * width + col]

    magnitudes = [0.0] * (width * height)
    for row in range(height):
        for col in range(width):
            gx = (
                at(row - 1, col + 1) + 2 * at(row, col + 1) + at(row + 1, col + 1)
                - at(row - 1, col - 1) - 2 * at(row, col - 1) - at(row + 1, col - 1)
            )
            gy = (
                at(row + 1, col - 1) + 2 * at(row + 1, col) + at(row + 1, col + 1)
                - at(row - 1, col - 1) - 2 * at(row - 1, col) - at(row - 1, col + 1)
            )
            magnitudes[row * width + col] = (gx * gx + gy * gy) ** 0.