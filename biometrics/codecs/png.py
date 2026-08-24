"""Minimal 8-bit grayscale PNG encoder and decoder.

Only what is actually needed is implemented: an unpaletted, uninterlaced,
8-bit grayscale image, one IDAT chunk, no ancillary chunks. That is a small
enough slice of the PNG specification to implement correctly and audit in one
sitting, at the cost of not reading arbitrary PNGs found in the wild -- which
these codecs are not asked to do; every PNG in this system was written by
this module in the first place.

Compression is ``zlib`` and checksums are ``binascii.crc32`` /
``zlib.adler32``, both from the Python standard library. That is consistent
with the project's zero-third-party-dependency rule: nothing here is
installed from PyPI, only what ships with the interpreter itself.
"""
import struct
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
COLOR_TYPE_GRAYSCALE = 0
BIT_DEPTH = 8
FILTER_NONE = 0
MAX_DIMENSION = 8192


class PngFormatError(ValueError):
    """Raised when data does not parse as a supported grayscale PNG file."""


def _chunk(chunk_type: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + chunk_type
        + payload
        + struct.pack(">I", zlib.crc32(chunk_type + payload) & 0xFFFFFFFF)
    )


def _read_chunks(data: bytes):
    offset = len(PNG_SIGNATURE)
    length = len(data)
    while offset < length:
        if offset + 8 > length:
            raise PngFormatError("truncated chunk header.")
        chunk_length = struct.unpack(">I", data[offset:offset + 4])[0]
        chunk_type = data[offset + 4:offset + 8]
        payload_start = offset + 8
        payload_end = payload_start + chunk_length
        crc_end = payload_end + 4
        if crc_end > length:
            raise PngFormatError("truncated chunk payload or CRC.")
        payload = data[payload_start:payload_end]
        stored_crc = struct.unpack(">I", data[payload_end:crc_end])[0]
        calculated_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if stored_crc != calculated_crc:
            raise PngFormatError(f"CRC mismatch in {chunk_type!r} chunk.")
        yield chunk_type, payload
        offset = crc_end
        if chunk_type == b"IEND":
            return


def _unfilter(raw: bytes, width: int, height: int) -> bytes:
    stride = width
    out_rows = []
    previous = bytes(stride)
    position = 0
    for _ in range(height):
        if position >= len(raw):
            raise PngFormatError("scanline data is truncated.")
        filter_type = raw[position]
        position += 1
        row = bytearray(raw[position:position + stride])
        if len(row) != stride:
            raise PngFormatError("scanline is shorter than the image width.")
        position += stride
        if filter_type == 0:
            pass
        elif filter_type == 1:  # Sub
            for index in range(1, stride):
                row[index] = (row[index] + row[index - 1]) & 0xFF
        elif filter_type == 2:  # Up
            for index in range(stride):
                row[index] = (row[index] + previous[index]) & 0xFF
        elif filter_type == 3:  # Average
            for index in range(stride):
                left = row[index - 1] if index > 0 else 0
                row[index] = (row[index] + ((left + previous[index]) // 2)) & 0xFF
        elif filter_type == 4:  # Paeth
            for index in range(stride):
                left = row[index - 1] if index > 0 else 0
                up = previous[index]
                up_left = previous[index - 1] if index > 0 else 0
                predictor = left + up - up_left
                distance_left = abs(predictor - left)
                distance_up = abs(predictor - up)
                distance_up_left = abs(predictor - up_left)
                if distance_left <= distance_up and distance_left <= distance_up_left:
                    nearest = left
                elif distance_up <= distance_up_left:
                    nearest = up
                else:
                    nearest = up_left
                row[index] = (row[index] + nearest) & 0xFF
        else:
            raise PngFormatError(f"unsupported scanline filter type {filter_type}.")
        out_rows.append(bytes(row))
        previous = row
    return b"".join(out_rows)


def _filter_none(pixels: bytes, width: int, height: int) -> bytes:
    rows = []
    for row_index in range(height):
        start = row_index * width
        rows.append(bytes([FILTER_NONE]) + pixels[start:start + width])
    return b"".join(rows)


def decode(data: bytes) -> dict:
    """Decode 8-bit grayscale PNG bytes into ``{"width", "height", "pixels"}``."""
    if not isinstance(data, (bytes, bytearray)):
        raise PngFormatError("PNG data must be bytes.")
    data = bytes(data)
    if not data.startswith(PNG_SIGNATURE):
        raise PngFormatError("not a PNG file (bad signature).")
    width = height = None
    idat_parts = []
    saw_ihdr = False
    for chunk_type, payload in _read_chunks(data):
        if chunk_type == b"IHDR":
            if len(payload) != 13:
                raise PngFormatError("IHDR chunk has an invalid length.")
            (width, height, bit_depth, color_type, compression,
             filter_method, interlace) = struct.unpack(">IIBBBBB", payload)
            if bit_depth != BIT_DEPTH or color_type != COLOR_TYPE_GRAYSCALE:
                raise PngFormatError(
                    "only 8-bit grayscale PNG images are supported."
                )
            if compression != 0 or filter_method != 0 or interlace != 0:
                raise PngFormatError("unsupported PNG encoding options.")
            if width <= 0 or height <= 0:
                raise PngFormatError("width and height must be positive.")
            if width > MAX_DIMENSION or height > MAX_DIMENSION:
                raise PngFormatError("width or height exceeds the supported maximum.")
            saw_ihdr = True
        elif chunk_type == b"IDAT":
            idat_parts.append(payload)
        elif chunk_type == b"IEND":
            break
    if not saw_ihdr:
        raise PngFormatError("missing IHDR chunk.")
    if not idat_parts:
        raise PngFormatError("missing IDAT chunk.")
    try:
        raw = zlib.decompress(b"".join(idat_parts))
    except zlib.error as exc:
        raise PngFormatError("IDAT stream failed to decompress.") from exc
    pixels = _unfilter(raw, width, height)
    return {"width": width, "height": height, "pixels": pixels}


def encode(width: int, height: int, pixels: bytes) -> bytes:
    """Encode flat grayscale pixel data as an 8-bit grayscale PNG file."""
    if width <= 0 or height <= 0:
        raise PngFormatError("width and height must be positive.")
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        raise PngFormatError("width or height exceeds the supported maximum.")
    if not isinstance(pixels, (bytes, bytearray)):
        raise PngFormatError("pixels must be bytes.")
    expected_bytes = width * height
    if len(pixels) != expected_bytes:
        raise PngFormatError(
            f"expected {expected_bytes} pixel bytes, got {len(pixels)}."
        )
    ihdr = struct.pack(
        ">IIBBBBB", width, height, BIT_DEPTH, COLOR_TYPE_GRAYSCALE, 0, 0, 0
    )
    filtered = _filter_none(bytes(pixels), width, height)
    idat = zlib.compress(filtered, level=9)
    return (
        PNG_SIGNATURE
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", idat)
        + _chunk(b"IEND", b"")
    )


def read_png(path) -> dict:
    """Read and decode a grayscale PNG file from disk."""
    with open(path, "rb") as handle:
        return decode(handle.read())


def write_png(path, width: int, height: int, pixels: bytes) -> None:
    """Encode and write flat grayscale pixel data as a PNG file."""
    encoded = encode(width, height, pixels)
    with open(path, "wb") as handle:
        handle.write(encoded)
