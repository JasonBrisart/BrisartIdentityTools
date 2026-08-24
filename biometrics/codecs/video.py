"""A minimal, custom frame-sequence container for the video modality.

There is no dependency on a real video codec here (no H.264, no container
muxer, no third-party library) because none is needed: video enrollment is a
short sequence of grayscale frames captured or generated for a single
identity, not general-purpose video playback. This module defines the
smallest format that can hold that: a fixed header followed by concatenated
raw grayscale frames, each exactly ``width * height`` bytes, with no
per-frame compression.

Format layout::

    magic          8 bytes   b"BRVID001"
    width          4 bytes   big-endian unsigned int
    height         4 bytes   big-endian unsigned int
    frame_count    4 bytes   big-endian unsigned int
    frame_rate     4 bytes   big-endian unsigned int (frames per second)
    frames         frame_count * width * height bytes, concatenated
"""
import struct
from pathlib import Path

MAGIC = b"BRVID001"
HEADER_STRUCT = struct.Struct(">8sIIII")
MAX_DIMENSION = 8192
MAX_FRAME_COUNT = 100_000  # generous ceiling; guards a corrupt header from
# driving an unbounded read.


class VideoFormatError(ValueError):
    """Raised when data does not parse as a well-formed BRVID container."""


def encode(width: int, height: int, frame_rate: int, frames: list) -> bytes:
    """Serialise a list of equal-sized grayscale frames into BRVID bytes."""
    if width <= 0 or height <= 0:
        raise VideoFormatError("width and height must be positive.")
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        raise VideoFormatError("width or height exceeds the supported maximum.")
    if frame_rate <= 0:
        raise VideoFormatError("frame_rate must be positive.")
    if not frames:
        raise VideoFormatError("at least one frame is required.")
    if len(frames) > MAX_FRAME_COUNT:
        raise VideoFormatError(
            f"frame count exceeds the supported maximum of {MAX_FRAME_COUNT}."
        )
    frame_bytes = width * height
    body = bytearray()
    for index, frame in enumerate(frames):
        if not isinstance(frame, (bytes, bytearray)):
            raise VideoFormatError(f"frame {index} is not bytes.")
        if len(frame) != frame_bytes:
            raise VideoFormatError(
                f"frame {index} has {len(frame)} bytes, expected {frame_bytes}."
            )
        body += frame
    header = HEADER_STRUCT.pack(MAGIC, width, height, len(frames), frame_rate)
    return header + bytes(body)


def decode(data: bytes) -> dict:
    """Parse BRVID bytes into ``{"width", "height", "frame_rate", "frames"}``.

    ``frames`` is a list of flat grayscale ``bytes`` objects, one per frame.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise VideoFormatError("video data must be bytes.")
    data = bytes(data)
    if len(data) < HEADER_STRUCT.size:
        raise VideoFormatError("data is too short to contain a valid header.")
    magic, width, height, frame_count, frame_rate = HEADER_STRUCT.unpack(
        data[:HEADER_STRUCT.size]
    )
    if magic != MAGIC:
        raise VideoFormatError("not a BRVID container (bad magic).")
    if width <= 0 or height <= 0:
        raise VideoFormatError("width and height must be positive.")
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        raise VideoFormatError("width or height exceeds the supported maximum.")
    if frame_count <= 0:
        raise VideoFormatError("frame_count must be positive.")
    if frame_count > MAX_FRAME_COUNT:
        raise VideoFormatError(
            f"frame count exceeds the supported maximum of {MAX_FRAME_COUNT}."
        )
    if frame_rate <= 0:
        raise VideoFormatError("frame_rate must be positive.")
    frame_bytes = width * height
    expected_body = frame_count * frame_bytes
    body = data[HEADER_STRUCT.size:]
    if len(body) != expected_body:
        raise VideoFormatError(
            f"expected {expected_body} bytes of frame data, found {len(body)}."
        )
    frames = [
        body[index * frame_bytes:(index + 1) * frame_bytes]
        for index in range(frame_count)
    ]
    return {
        "width": width,
        "height": height,
        "frame_rate": frame_rate,
        "frames": frames,
    }


def probe(path) -> dict:
    """Read only the header, returning metadata without loading frame data.

    Used by ``biometrics.app``'s "probe" command so inspecting a large capture
    does not require reading the whole file into memory.
    """
    resolved = Path(path)
    with open(resolved, "rb") as handle:
        header_bytes = handle.read(HEADER_STRUCT.size)
    if len(header_bytes) != HEADER_STRUCT.size:
        raise VideoFormatError("data is too short to contain a valid header.")
    magic, width, height, frame_count, frame_rate = HEADER_STRUCT.unpack(header_bytes)
    if magic != MAGIC:
        raise VideoFormatError("not a BRVID container (bad magic).")
    file_size = resolved.stat().st_size
    expected_size = HEADER_STRUCT.size + frame_count * width * height
    return {
        "path": str(resolved),
        "width": width,
        "height": height,
        "frame_count": frame_count,
        "frame_rate": frame_rate,
        "file_size_bytes": file_size,
        "size_matches_header": file_size == expected_size,
    }


def read_video(path) -> dict:
    """Read and decode a BRVID file from disk."""
    with open(path, "rb") as handle:
        return decode(handle.read())


def write_video(path, width: int, height: int, frame_rate: int, frames: list) -> None:
    """Encode and write a list of grayscale frames as a BRVID file."""
    encoded = encode(width, height, frame_rate, frames)
    with open(path, "wb") as handle:
        handle.write(encoded)