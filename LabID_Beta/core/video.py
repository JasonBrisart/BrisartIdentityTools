"""Uncompressed AVI reading and writing using only the standard library.

There is no video codec in the Python standard library, so LabID uses the one
video container that can be parsed honestly without dependencies: uncompressed
AVI (RIFF) holding raw DIB frames. This module is a real RIFF/AVI parser. It
walks the chunk tree, reads the stream format header, and decodes each frame in
the ``movi`` list into grayscale pixels.

Supported frame formats: 8-bit palettised DIB (``biBitCount == 8``) and 24-bit
BGR DIB (``biBitCount == 24``), both uncompressed (``biCompression == 0``).
Those are the formats an uncompressed capture or ``ffmpeg -c:v rawvideo``
export produces, and the formats this module writes.

DIB rows are padded to a 4-byte boundary and, for a positive ``biHeight``, are
stored bottom-up. Both are handled here so callers get top-down pixels.

Reference: OpenDML AVI File Format Extensions, and BITMAPINFOHEADER (wingdi.h).
"""

import struct
from pathlib import Path

RIFF_MAGIC = b"RIFF"
AVI_MAGIC = b"AVI "

# Rec. 709 luma coefficients as integers, matching core/png.py.
_LUMA_R = 2126
_LUMA_G = 7152
_LUMA_B = 722
_LUMA_TOTAL = _LUMA_R + _LUMA_G + _LUMA_B

# Guard rails so a malformed header cannot exhaust memory.
MAX_FRAME_COUNT = 3600
MAX_DIMENSION = 4096


class VideoError(Exception):
    """Raised when a video file cannot be parsed or written."""


def _row_stride(width: int, bit_count: int) -> int:
    """DIB scanlines are padded up to a 4-byte boundary."""
    return ((width * bit_count + 31) // 32) * 4


def _iter_riff(data: bytes, start: int, end: int):
    """Yield (fourcc, payload_start, payload_end, list_type) inside a range."""
    offset = start
    while offset + 8 <= end:
        fourcc = data[offset:offset + 4]
        (size,) = struct.unpack_from("<I", data, offset + 4)
        payload_start = offset + 8
        payload_end = payload_start + size

        if payload_end > end:
            raise VideoError(
                f"Truncated AVI: chunk {fourcc.decode('ascii', 'replace')} "
                "claims more data than the file contains."
            )

        list_type = None
        if fourcc in (b"LIST", b"RIFF"):
            if payload_start + 4 > end:
                raise VideoError("Truncated AVI: LIST is missing its type.")
            list_type = data[payload_start:payload_start + 4]

        yield fourcc, payload_start, payload_end, list_type

        # Chunks are word aligned: an odd size is followed by a pad byte.
        offset = payload_end + (size & 1)


def _find_stream_format(data: bytes, hdrl_start: int, hdrl_end: int) -> tuple:
    """Return (width, height, raw_height, bit_count, palette) from strf.

    ``raw_height`` keeps the signed BITMAPINFOHEADER value, because a positive
    height means the DIB rows are stored bottom-up.
    """
    for fourcc, start, end, list_type in _iter_riff(data, hdrl_start + 4, hdrl_end):
        if fourcc == b"LIST" and list_type == b"strl":
            for inner, inner_start, inner_end, _ in _iter_riff(data, start + 4, end):
                if inner != b"strf":
                    continue
                if inner_end - inner_start < 40:
                    raise VideoError("AVI strf chunk is too small to be a BITMAPINFOHEADER.")

                (
                    _size, width, raw_height, _planes, bit_count, compression,
                ) = struct.unpack_from("<IiiHHI", data, inner_start)

                if compression != 0:
                    raise VideoError(
                        f"Only uncompressed AVI video is supported "
                        f"(biCompression {compression} is not BI_RGB). "
                        "Re-export the file as rawvideo."
                    )

                palette = data[inner_start + 40:inner_end]
                header = (width, abs(raw_height), raw_height, bit_count, palette)
                _validate_stream_header(header)
                return header

    raise VideoError("AVI file has no video stream format (strf) chunk.")


def _decode_frame(payload: bytes, width: int, height: int,
                  bit_count: int, palette: bytes, bottom_up: bool) -> list:
    """Decode one uncompressed DIB frame to top-down grayscale pixels."""
    stride = _row_stride(width, bit_count)
    needed = stride * height
    if len(payload) < needed:
        raise VideoError(
            f"AVI frame is short: expected {needed} bytes, found {len(payload)}."
        )

    rows = []
    for row in range(height):
        row_start = row * stride
        line = payload[row_start:row_start + stride]

        if bit_count == 8:
            indices = line[:width]
            if palette:
                pixels = []
                for index in indices:
                    base = index * 4
                    if base + 3 > len(palette):
                        raise VideoError(
                            f"AVI palette index {index} is out of range."
                        )
                    blue = palette[base]
                    green = palette[base + 1]
                    red = palette[base + 2]
                    pixels.append(_luma(red, green, blue))
            else:
                pixels = list(indices)
        elif bit_count == 24:
            pixels = []
            for x in range(width):
                base = x * 3
                blue = line[base]
                green = line[base + 1]
                red = line[base + 2]
                pixels.append(_luma(red, green, blue))
        else:
            raise VideoError(
                f"Unsupported AVI bit depth: {bit_count}. Supported depths are "
                "8-bit palettised and 24-bit BGR uncompressed DIB."
            )

        rows.append(pixels)

    if bottom_up:
        rows.reverse()

    flat = []
    for row_pixels in rows:
        flat.extend(row_pixels)
    return flat


def _luma(r: int, g: int, b: int) -> int:
    return (r * _LUMA_R + g * _LUMA_G + b * _LUMA_B) // _LUMA_TOTAL


def read_avi_grayscale_frames(path: str, max_frames: int = 0) -> tuple:
    """Read an uncompressed AVI and return (width, height, [frame pixels]).

    Each frame is a flat list of grayscale values 0..255 in top-down order,
    the same shape ``core.png.read_png_grayscale`` returns.
    """
    video_path = Path(path)
    try:
        data = video_path.read_bytes()
    except OSError as exc:
        raise VideoError(f"Unable to read video file: {video_path}") from exc

    if len(data) < 12:
        raise VideoError(f"File is too small to be an AVI: {video_path}")
    if data[0:4] != RIFF_MAGIC or data[8:12] != AVI_MAGIC:
        raise VideoError(f"Not an AVI file (bad RIFF/AVI signature): {video_path}")

    (riff_size,) = struct.unpack_from("<I", data, 4)
    end = min(len(data), 8 + riff_size)

    header = None
    frames = []

    for fourcc, start, chunk_end, list_type in _iter_riff(data, 12, end):
        if fourcc != b"LIST":
            continue

        if list_type == b"hdrl":
            header = _find_stream_format(data, start, chunk_end)

        elif list_type == b"movi":
            if header is None:
                raise VideoError("AVI movi list appears before the stream format header.")

            width, height, raw_height, bit_count, palette = header
            bottom_up = raw_height > 0

            for inner, inner_start, inner_end, inner_type in _iter_riff(data, start + 4, chunk_end):
                if inner == b"LIST" and inner_type == b"rec ":
                    # Interleaved records wrap the real frame chunks.
                    scan = _iter_riff(data, inner_start + 4, inner_end)
                else:
                    scan = [(inner, inner_start, inner_end, inner_type)]

                for tag, payload_start, payload_end, _ in scan:
                    # 'db' = uncompressed DIB, 'dc' = compressed DIB.
                    if tag[2:4] not in (b"db", b"dc"):
                        continue
                    frames.append(_decode_frame(
                        data[payload_start:payload_end],
                        width, height, bit_count, palette, bottom_up,
                    ))
                    if max_frames and len(frames) >= max_frames:
                        break
                if max_frames and len(frames) >= max_frames:
                    break

        if max_frames and len(frames) >= max_frames:
            break

    if header is None:
        raise VideoError("AVI file is missing its hdrl header list.")
    if not frames:
        raise VideoError("AVI file contains no decodable video frames.")

    width, height, _raw_height, _bit_count, _palette = header
    return width, height, frames


def probe_avi_grayscale(path: str) -> tuple:
    """Return (width, height, frame_count) without keeping every frame.

    Decoding a long recording just to count its frames would hold the whole
    thing in memory, so this reuses the reader and discards the pixels.
    """
    width, height, frames = read_avi_grayscale_frames(path)
    return width, height, len(frames)


def _validate_stream_header(header) -> None:
    width, height, _raw_height, bit_count, _palette = header
    if width <= 0 or height <= 0:
        raise VideoError("AVI frame dimensions must be positive.")
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        raise VideoError(
            f"AVI frame is {width}x{height}, which exceeds the "
            f"{MAX_DIMENSION}px limit."
        )
    if bit_count not in (8, 24):
        raise VideoError(f"Unsupported AVI bit depth: {bit_count}.")


def write_avi_grayscale(path: str, width: int, height: int,
                        frames, frames_per_second: int = 15) -> None:
    """Write an uncompressed 8-bit grayscale AVI from top-down frames.

    Used to produce sample and test recordings, and to prove the reader against
    bytes this module laid out itself.
    """
    if width <= 0 or height <= 0:
        raise VideoError("Video width and height must be positive.")
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        raise VideoError(f"Video frame exceeds the {MAX_DIMENSION}px limit.")

    frame_list = [list(frame) for frame in frames]
    if not frame_list:
        raise VideoError("Cannot write a video with no frames.")
    if len(frame_list) > MAX_FRAME_COUNT:
        raise VideoError(f"Cannot write more than {MAX_FRAME_COUNT} frames.")
    if frames_per_second <= 0:
        raise VideoError("Frames per second must be positive.")

    expected = width * height
    for index, frame in enumerate(frame_list):
        if len(frame) != expected:
            raise VideoError(
                f"Frame {index} has {len(frame)} pixels, expected {expected}."
            )
        if any(int(value) < 0 or int(value) > 255 for value in frame):
            raise VideoError(f"Frame {index} has pixels outside 0..255.")

    stride = _row_stride(width, 8)
    padding = b"\x00" * (stride - width)

    frame_payloads = []
    for frame in frame_list:
        body = bytearray()
        # DIB rows are bottom-up when biHeight is positive.
        for row in range(height - 1, -1, -1):
            body.extend(bytes(int(value) for value in frame[row * width:(row + 1) * width]))
            body.extend(padding)
        frame_payloads.append(bytes(body))

    frame_size = len(frame_payloads[0])
    frame_count = len(frame_payloads)
    microseconds_per_frame = int(round(1_000_000 / float(frames_per_second)))

    # Grayscale palette: 256 BGRA entries where B == G == R.
    palette = bytearray()
    for level in range(256):
        palette.extend(bytes((level, level, level, 0)))

    avih = struct.pack(
        "<IIIIIIIIIIIIIIII",
        microseconds_per_frame,
        frame_size * frames_per_second,  # max bytes per second
        0,                               # padding granularity
        0x00000010,                      # AVIF_HASINDEX
        frame_count,
        0,                               # initial frames
        1,                               # streams
        frame_size,                      # suggested buffer size
        width,
        height,
        0, 0, 0, 0, 0, 0,                # reserved
    )

    strh = struct.pack(
        "<4s4sIHHIIIIIIIihhhh",
        b"vids",
        b"DIB ",
        0,                 # flags
        0,                 # priority
        0,                 # language
        0,                 # initial frames
        1,                 # scale
        frames_per_second,  # rate
        0,                 # start
        frame_count,       # length
        frame_size,        # suggested buffer size
        0,                 # quality
        0,                 # sample size
        0, 0, width, height,  # rcFrame
    )

    strf = struct.pack(
        "<IiiHHIIiiII",
        40,                # biSize
        width,
        height,            # positive: bottom-up rows
        1,                 # biPlanes
        8,                 # biBitCount
        0,                 # biCompression = BI_RGB
        frame_size,        # biSizeImage
        0, 0,              # pixels per metre
        256,               # biClrUsed
        0,                 # biClrImportant
    ) + bytes(palette)

    def chunk(tag: bytes, payload: bytes) -> bytes:
        body = struct.pack("<4sI", tag, len(payload)) + payload
        if len(payload) & 1:
            body += b"\x00"
        return body

    def list_chunk(list_type: bytes, payload: bytes) -> bytes:
        return struct.pack("<4sI", b"LIST", len(payload) + 4) + list_type + payload

    strl = list_chunk(b"strl", chunk(b"strh", strh) + chunk(b"strf", strf))
    hdrl = list_chunk(b"hdrl", chunk(b"avih", avih) + strl)

    movi_body = bytearray()
    index_entries = bytearray()
    offset = 4  # offsets in idx1 are relative to the start of the movi list type
    for payload in frame_payloads:
        movi_body.extend(chunk(b"00db", payload))
        index_entries.extend(struct.pack(
            "<4sIII", b"00db", 0x00000010, offset, len(payload)
        ))
        offset += 8 + len(payload) + (len(payload) & 1)

    movi = list_chunk(b"movi", bytes(movi_body))
    idx1 = chunk(b"idx1", bytes(index_entries))

    body = AVI_MAGIC + hdrl + movi + idx1
    riff = struct.pack("<4sI", RIFF_MAGIC, len(body)) + body

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_path.write_bytes(riff)
    except OSError as exc:
        raise VideoError(f"Unable to write video file: {output_path}") from exc
