"""PNG reading and writing using only the Python standard library.

This is a real PNG codec, not a wrapper: it parses the chunk stream, verifies
CRC-32 on every chunk, inflates the IDAT payload with zlib, and reverses the
five PNG scanline filters defined in RFC 2083. Grayscale, truecolour, indexed
and alpha formats are all handled, at 8 or 16 bits per sample.

Only zlib, struct and hashlib-free stdlib pieces are used, so LabID keeps its
"base Python only" guarantee while accepting the format people actually have.

Reference: https://www.w3.org/TR/png/ (PNG spec, second edition)
"""

import struct
import zlib
from pathlib import Path

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# Colour type -> number of samples per pixel.
_CHANNELS = {
    0: 1,  # grayscale
    2: 3,  # truecolour RGB
    3: 1,  # indexed (palette lookup)
    4: 2,  # grayscale + alpha
    6: 4,  # RGBA
}

# Rec. 709 luma coefficients, scaled to integers to keep this exact.
_LUMA_R = 2126
_LUMA_G = 7152
_LUMA_B = 722
_LUMA_TOTAL = _LUMA_R + _LUMA_G + _LUMA_B


class PNGError(Exception):
    """Raised when a PNG image cannot be parsed or written."""


def _iter_chunks(data: bytes):
    """Yield (type, payload) for each chunk, verifying length and CRC."""
    offset = len(PNG_SIGNATURE)
    total = len(data)

    while offset < total:
        if offset + 8 > total:
            raise PNGError("Truncated PNG: incomplete chunk header.")

        (length,) = struct.unpack(">I", data[offset:offset + 4])
        chunk_type = data[offset + 4:offset + 8]

        if length > 0x7FFFFFFF:
            raise PNGError("PNG chunk length exceeds the maximum allowed size.")

        payload_start = offset + 8
        payload_end = payload_start + length
        if payload_end + 4 > total:
            raise PNGError(
                f"Truncated PNG: chunk {chunk_type.decode('ascii', 'replace')} "
                "claims more data than the file contains."
            )

        payload = data[payload_start:payload_end]
        (expected_crc,) = struct.unpack(">I", data[payload_end:payload_end + 4])
        actual_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF

        if actual_crc != expected_crc:
            raise PNGError(
                f"PNG chunk {chunk_type.decode('ascii', 'replace')} failed its "
                f"CRC check (expected {expected_crc:08x}, got {actual_crc:08x}). "
                "The file is corrupt."
            )

        yield chunk_type, payload
        offset = payload_end + 4


def _paeth(a: int, b: int, c: int) -> int:
    """PNG Paeth predictor: pick whichever neighbour the gradient favours."""
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def _unfilter(raw: bytes, height: int, stride: int, bytes_per_pixel: int) -> bytearray:
    """Reverse the per-scanline filters, returning packed sample bytes."""
    expected = (stride + 1) * height
    if len(raw) < expected:
        raise PNGError(
            f"PNG pixel data is short: expected {expected} bytes after "
            f"decompression, found {len(raw)}."
        )

    out = bytearray(stride * height)
    previous = bytearray(stride)
    position = 0

    for row in range(height):
        filter_type = raw[position]
        position += 1
        line = bytearray(raw[position:position + stride])
        position += stride

        if filter_type == 0:
            pass
        elif filter_type == 1:  # Sub
            for i in range(bytes_per_pixel, stride):
                line[i] = (line[i] + line[i - bytes_per_pixel]) & 0xFF
        elif filter_type == 2:  # Up
            for i in range(stride):
                line[i] = (line[i] + previous[i]) & 0xFF
        elif filter_type == 3:  # Average
            for i in range(stride):
                left = line[i - bytes_per_pixel] if i >= bytes_per_pixel else 0
                line[i] = (line[i] + ((left + previous[i]) >> 1)) & 0xFF
        elif filter_type == 4:  # Paeth
            for i in range(stride):
                if i >= bytes_per_pixel:
                    left = line[i - bytes_per_pixel]
                    upper_left = previous[i - bytes_per_pixel]
                else:
                    left = 0
                    upper_left = 0
                line[i] = (line[i] + _paeth(left, previous[i], upper_left)) & 0xFF
        else:
            raise PNGError(
                f"Unknown PNG filter type {filter_type} on row {row}. "
                "Valid types are 0-4."
            )

        out[row * stride:(row + 1) * stride] = line
        previous = line

    return out


def _unpack_samples(data: bytearray, width: int, height: int,
                    channels: int, bit_depth: int) -> list:
    """Expand packed scanline bytes into one integer per sample."""
    if bit_depth == 8:
        return list(data)

    if bit_depth == 16:
        # Big-endian 16-bit samples, scaled down to 8-bit range.
        return [
            (data[i] << 8 | data[i + 1]) >> 8
            for i in range(0, len(data), 2)
        ]

    # Sub-byte depths (1, 2, 4) are packed several samples per byte and each
    # scanline is padded to a byte boundary.
    samples_per_byte = 8 // bit_depth
    mask = (1 << bit_depth) - 1
    stride = (width * channels * bit_depth + 7) // 8
    maximum = mask

    values = []
    for row in range(height):
        row_start = row * stride
        row_values = []
        for index in range(width * channels):
            byte = data[row_start + index // samples_per_byte]
            shift = 8 - bit_depth * (index % samples_per_byte + 1)
            row_values.append((byte >> shift) & mask)
        values.extend(row_values)

    # Rescale so callers always see a 0..255 range regardless of depth.
    if maximum != 255:
        values = [value * 255 // maximum for value in values]
    return values


def read_png_grayscale(path: str) -> tuple:
    """Read a PNG and return (width, height, grayscale pixels 0..255).

    Colour images are converted with Rec. 709 luma weights. Alpha, when
    present, is composited against white so a transparent background does not
    read as solid black and skew the biometric features.
    """
    image_path = Path(path)
    try:
        data = image_path.read_bytes()
    except OSError as exc:
        raise PNGError(f"Unable to read PNG image: {image_path}") from exc

    if not data.startswith(PNG_SIGNATURE):
        raise PNGError(
            f"Not a PNG file (bad signature): {image_path}"
        )

    header = None
    palette = b""
    transparency = None
    idat = bytearray()
    saw_end = False

    for chunk_type, payload in _iter_chunks(data):
        if chunk_type == b"IHDR":
            if len(payload) != 13:
                raise PNGError("PNG IHDR chunk must be 13 bytes.")
            header = struct.unpack(">IIBBBBB", payload)
        elif chunk_type == b"PLTE":
            palette = payload
        elif chunk_type == b"tRNS":
            transparency = payload
        elif chunk_type == b"IDAT":
            idat.extend(payload)
        elif chunk_type == b"IEND":
            saw_end = True
            break

    if header is None:
        raise PNGError("PNG is missing its IHDR header chunk.")
    if not saw_end:
        raise PNGError("PNG is missing its IEND chunk; the file is truncated.")

    width, height, bit_depth, colour_type, compression, filter_method, interlace = header

    if width == 0 or height == 0:
        raise PNGError("PNG width and height must both be non-zero.")
    if compression != 0:
        raise PNGError(f"Unsupported PNG compression method: {compression}.")
    if filter_method != 0:
        raise PNGError(f"Unsupported PNG filter method: {filter_method}.")
    if interlace != 0:
        raise PNGError(
            "Interlaced (Adam7) PNG images are not supported. Re-save the "
            "image without interlacing."
        )
    if colour_type not in _CHANNELS:
        raise PNGError(f"Unsupported PNG colour type: {colour_type}.")

    valid_depths = {
        0: (1, 2, 4, 8, 16),
        2: (8, 16),
        3: (1, 2, 4, 8),
        4: (8, 16),
        6: (8, 16),
    }[colour_type]
    if bit_depth not in valid_depths:
        raise PNGError(
            f"PNG bit depth {bit_depth} is not valid for colour type "
            f"{colour_type}."
        )
    if not idat:
        raise PNGError("PNG contains no IDAT image data.")

    channels = _CHANNELS[colour_type]

    try:
        raw = zlib.decompress(bytes(idat))
    except zlib.error as exc:
        raise PNGError(f"PNG image data could not be decompressed: {exc}") from exc

    stride = (width * channels * bit_depth + 7) // 8
    bytes_per_pixel = max(1, (channels * bit_depth) // 8)

    unfiltered = _unfilter(raw, height, stride, bytes_per_pixel)
    samples = _unpack_samples(unfiltered, width, height, channels, bit_depth)

    expected_samples = width * height * channels
    if len(samples) < expected_samples:
        raise PNGError(
            f"PNG sample count mismatch: expected {expected_samples}, "
            f"found {len(samples)}."
        )

    return width, height, _to_grayscale(
        samples, width, height, colour_type, palette, transparency, bit_depth
    )


def _to_grayscale(samples, width, height, colour_type,
                  palette, transparency, bit_depth) -> list:
    """Collapse decoded samples to a single 0..255 channel per pixel."""
    count = width * height
    pixels = []

    if colour_type == 0:  # grayscale
        pixels = samples[:count]

    elif colour_type == 4:  # grayscale + alpha
        for i in range(count):
            grey = samples[i * 2]
            alpha = samples[i * 2 + 1]
            pixels.append(_composite(grey, alpha))

    elif colour_type == 2:  # RGB
        for i in range(count):
            r, g, b = samples[i * 3:i * 3 + 3]
            pixels.append(_luma(r, g, b))

    elif colour_type == 6:  # RGBA
        for i in range(count):
            r, g, b, alpha = samples[i * 4:i * 4 + 4]
            pixels.append(_composite(_luma(r, g, b), alpha))

    elif colour_type == 3:  # indexed
        if not palette:
            raise PNGError("Indexed PNG is missing its PLTE palette chunk.")
        if len(palette) % 3:
            raise PNGError("PNG palette length must be a multiple of 3.")

        entries = len(palette) // 3
        # _unpack_samples rescaled sub-byte indices to 0..255; undo that so the
        # values address the palette again.
        maximum = (1 << bit_depth) - 1
        for value in samples[:count]:
            index = value * maximum // 255 if maximum != 255 else value
            if index >= entries:
                raise PNGError(
                    f"PNG palette index {index} is out of range for a "
                    f"{entries}-entry palette."
                )
            r = palette[index * 3]
            g = palette[index * 3 + 1]
            b = palette[index * 3 + 2]
            grey = _luma(r, g, b)

            if transparency is not None and index < len(transparency):
                grey = _composite(grey, transparency[index])
            pixels.append(grey)

    if len(pixels) != count:
        raise PNGError(
            f"Decoded {len(pixels)} pixels but the header declares {count}."
        )
    return pixels


def _luma(r: int, g: int, b: int) -> int:
    return (r * _LUMA_R + g * _LUMA_G + b * _LUMA_B) // _LUMA_TOTAL


def _composite(grey: int, alpha: int) -> int:
    """Composite a grey value over a white background."""
    if alpha >= 255:
        return grey
    return (grey * alpha + 255 * (255 - alpha)) // 255


def write_png_grayscale(path: str, width: int, height: int, pixels) -> None:
    """Write an 8-bit grayscale PNG. Used to produce test and sample images."""
    if width <= 0 or height <= 0:
        raise PNGError("PNG width and height must be positive.")

    values = [int(value) for value in pixels]
    if len(values) != width * height:
        raise PNGError(
            f"Pixel count mismatch. Expected {width * height}, "
            f"found {len(values)}."
        )
    if any(value < 0 or value > 255 for value in values):
        raise PNGError("All output pixels must be between 0 and 255.")

    raw = bytearray()
    for row in range(height):
        raw.append(0)  # filter type 0 (None)
        raw.extend(values[row * width:(row + 1) * width])

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    body = (
        PNG_SIGNATURE
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_path.write_bytes(body)
    except OSError as exc:
        raise PNGError(f"Unable to write PNG image: {output_path}") from exc
