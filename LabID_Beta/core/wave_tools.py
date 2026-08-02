"""WAV (RIFF) audio reading and writing using only the standard library.

Built on the stdlib ``wave`` module for container parsing, with sample decoding
done here by hand. ``audioop`` is deliberately not used: it was removed in
Python 3.13 (PEP 594), and LabID supports 3.9 through 3.13 from one codebase.

Samples are returned as floats in -1.0..1.0, mixed down to mono, which is the
form the feature extractors expect. 8-bit PCM is unsigned with a 128 offset,
while 16/24/32-bit PCM is signed little-endian two's complement.
"""

import struct
import wave
from pathlib import Path

# Guard rails so a malformed or hostile header cannot exhaust memory.
MAX_DURATION_SECONDS = 600
MIN_SAMPLE_RATE = 1000
MAX_SAMPLE_RATE = 384000


class WaveError(Exception):
    """Raised when audio cannot be parsed or written."""


def _decode_pcm(raw: bytes, sample_width: int, channels: int) -> list:
    """Decode interleaved PCM bytes to mono floats in -1.0..1.0."""
    frame_size = sample_width * channels
    if frame_size == 0:
        raise WaveError("Audio frame size cannot be zero.")

    usable = len(raw) - (len(raw) % frame_size)
    raw = raw[:usable]
    frame_count = usable // frame_size

    samples = []

    if sample_width == 1:
        # 8-bit WAV PCM is unsigned, centred on 128.
        for frame in range(frame_count):
            base = frame * frame_size
            total = 0
            for channel in range(channels):
                total += raw[base + channel] - 128
            samples.append(total / (channels * 128.0))

    elif sample_width == 2:
        scale = float(1 << 15)
        # struct.unpack_from in a loop is faster than slicing per channel.
        for frame in range(frame_count):
            base = frame * frame_size
            total = 0
            for channel in range(channels):
                (value,) = struct.unpack_from("<h", raw, base + channel * 2)
                total += value
            samples.append(total / (channels * scale))

    elif sample_width == 3:
        # 24-bit has no struct format code; assemble it and sign-extend.
        scale = float(1 << 23)
        for frame in range(frame_count):
            base = frame * frame_size
            total = 0
            for channel in range(channels):
                offset = base + channel * 3
                value = raw[offset] | (raw[offset + 1] << 8) | (raw[offset + 2] << 16)
                if value & 0x800000:
                    value -= 0x1000000
                total += value
            samples.append(total / (channels * scale))

    elif sample_width == 4:
        scale = float(1 << 31)
        for frame in range(frame_count):
            base = frame * frame_size
            total = 0
            for channel in range(channels):
                (value,) = struct.unpack_from("<i", raw, base + channel * 4)
                total += value
            samples.append(total / (channels * scale))

    else:
        raise WaveError(
            f"Unsupported sample width: {sample_width * 8}-bit. "
            "Supported widths are 8, 16, 24 and 32-bit PCM."
        )

    return samples


def read_wav_mono(path: str) -> tuple:
    """Read a WAV file and return (sample_rate, mono samples as floats).

    Multi-channel audio is averaged to mono. Sample values are normalised to
    -1.0..1.0 so downstream feature extraction is independent of bit depth.
    """
    audio_path = Path(path)
    if not audio_path.exists():
        raise WaveError(f"Audio file not found: {audio_path}")

    try:
        with wave.open(str(audio_path), "rb") as handle:
            channels = handle.getnchannels()
            sample_width = handle.getsampwidth()
            sample_rate = handle.getframerate()
            frame_count = handle.getnframes()
            compression = handle.getcomptype()

            if compression != "NONE":
                raise WaveError(
                    f"Only uncompressed PCM WAV audio is supported, got "
                    f"'{compression}'. Re-export the file as PCM."
                )
            if channels < 1:
                raise WaveError("WAV file reports zero channels.")
            if not MIN_SAMPLE_RATE <= sample_rate <= MAX_SAMPLE_RATE:
                raise WaveError(
                    f"WAV sample rate {sample_rate} Hz is outside the supported "
                    f"range {MIN_SAMPLE_RATE}..{MAX_SAMPLE_RATE} Hz."
                )
            if frame_count <= 0:
                raise WaveError("WAV file contains no audio frames.")

            duration = frame_count / float(sample_rate)
            if duration > MAX_DURATION_SECONDS:
                raise WaveError(
                    f"WAV file is {duration:.1f}s long, which exceeds the "
                    f"{MAX_DURATION_SECONDS}s limit."
                )

            raw = handle.readframes(frame_count)
    except wave.Error as exc:
        raise WaveError(f"Unable to parse WAV file {audio_path}: {exc}") from exc
    except OSError as exc:
        raise WaveError(f"Unable to read WAV file {audio_path}: {exc}") from exc

    samples = _decode_pcm(raw, sample_width, channels)
    if not samples:
        raise WaveError("WAV file decoded to zero samples.")

    return sample_rate, samples


def write_wav_mono(path: str, sample_rate: int, samples) -> None:
    """Write mono 16-bit PCM. Values outside -1.0..1.0 are clipped."""
    if not MIN_SAMPLE_RATE <= int(sample_rate) <= MAX_SAMPLE_RATE:
        raise WaveError(
            f"Sample rate {sample_rate} Hz is outside the supported range."
        )

    values = list(samples)
    if not values:
        raise WaveError("Cannot write a WAV file with no samples.")

    limit = (1 << 15) - 1
    frames = bytearray()
    for value in values:
        scaled = int(round(float(value) * limit))
        scaled = max(-limit, min(limit, scaled))
        frames.extend(struct.pack("<h", scaled))

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with wave.open(str(output_path), "wb") as handle:
            handle.setnchannels(1)
            handle.setsampwidth(2)
            handle.setframerate(int(sample_rate))
            handle.writeframes(bytes(frames))
    except (wave.Error, OSError) as exc:
        raise WaveError(f"Unable to write WAV file {output_path}: {exc}") from exc


def audio_duration_seconds(sample_rate: int, samples) -> float:
    return round(len(samples) / float(sample_rate), 6)
