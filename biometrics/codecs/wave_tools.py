"""WAV audio reading and writing for the voice modality.

Uses only the ``wave`` and ``struct`` modules from the Python standard
library -- no third-party audio libraries. Samples are always normalised to
mono ``int`` PCM in the caller-facing functions, because every downstream
consumer (``dsp.py``, ``voice_features.py``) works on a single channel of
integers and should not need to know how many channels or what sample width
the original file used.
"""
import struct
import wave

SUPPORTED_SAMPLE_WIDTHS = (1, 2, 4)  # bytes per sample: 8, 16, 32-bit PCM
MAX_DURATION_SECONDS = 600  # guards against an absurd allocation from a
# corrupt or hostile header claiming an enormous frame count.
MAX_SAMPLE_RATE = 768_000  # ceiling on a declared sample rate. Real PCM tops
# out around 384 kHz even for extreme professional audio; 768 kHz leaves
# generous headroom while stopping a hostile header from declaring an
# astronomically large rate. frame_count is bounded RELATIVE to sample_rate
# (see MAX_DURATION_SECONDS above), so an unbounded sample_rate would let a
# corrupt/hostile header neutralize that frame-count guard entirely -- the
# same "individually-valid field, unbounded target" class fixed for the
# BRVID container and the PNG IDAT stream in 1.3.3.


class WaveFormatError(ValueError):
    """Raised when audio data cannot be parsed or does not fit expectations."""


def _unpack_samples(raw: bytes, sample_width: int, channel_count: int) -> list:
    if sample_width == 1:
        # WAV stores 8-bit PCM as unsigned, centered at 128.
        return [byte - 128 for byte in raw]
    if sample_width == 2:
        count = len(raw) // 2
        return list(struct.unpack(f"<{count}h", raw[:count * 2]))
    if sample_width == 4:
        count = len(raw) // 4
        return list(struct.unpack(f"<{count}i", raw[:count * 4]))
    raise WaveFormatError(f"unsupported sample width: {sample_width} bytes.")


def _mix_down(samples: list, channel_count: int) -> list:
    if channel_count == 1:
        return samples
    frame_count = len(samples) // channel_count
    mixed = [0] * frame_count
    for frame_index in range(frame_count):
        base = frame_index * channel_count
        mixed[frame_index] = sum(samples[base:base + channel_count]) // channel_count
    return mixed


def read_wave(path) -> dict:
    """Read a WAV file, returning a mono ``int`` sample stream.

    Returns ``{"sample_rate", "sample_width", "channel_count", "samples"}``.
    ``samples`` is always a single-channel list of signed integers, downmixed
    by simple averaging if the source had more than one channel.
    """
    try:
        with wave.open(str(path), "rb") as handle:
            channel_count = handle.getnchannels()
            sample_width = handle.getsampwidth()
            sample_rate = handle.getframerate()
            frame_count = handle.getnframes()
            if sample_width not in SUPPORTED_SAMPLE_WIDTHS:
                raise WaveFormatError(
                    f"unsupported sample width: {sample_width} bytes."
                )
            if sample_rate <= 0:
                raise WaveFormatError("sample rate must be positive.")
            # Fix 1 (2026-09-11): bound the declared sample rate BEFORE the
            # duration guard below. frame_count is only ever checked relative
            # to sample_rate, so a hostile header declaring an astronomically
            # large rate could push the MAX_DURATION_SECONDS ceiling
            # arbitrarily high and read an enormous frame body. A legitimate
            # recording's real rate is far under this cap.
            if sample_rate > MAX_SAMPLE_RATE:
                raise WaveFormatError(
                    f"sample rate {sample_rate} exceeds the supported "
                    f"maximum of {MAX_SAMPLE_RATE}."
                )
            if frame_count > sample_rate * MAX_DURATION_SECONDS:
                raise WaveFormatError(
                    f"audio exceeds the supported {MAX_DURATION_SECONDS}s maximum."
                )
            raw = handle.readframes(frame_count)
    except wave.Error as exc:
        raise WaveFormatError(f"failed to read WAV file: {exc}") from exc
    interleaved = _unpack_samples(raw, sample_width, channel_count)
    samples = _mix_down(interleaved, channel_count)
    return {
        "sample_rate": sample_rate,
        "sample_width": sample_width,
        "channel_count": channel_count,
        "samples": samples,
    }


def write_wave(path, sample_rate: int, samples: list, sample_width: int = 2) -> None:
    """Write a mono ``int`` sample stream as a 16-bit (default) PCM WAV file."""
    if sample_rate <= 0:
        raise WaveFormatError("sample rate must be positive.")
    if sample_rate > MAX_SAMPLE_RATE:
        raise WaveFormatError(
            f"sample rate {sample_rate} exceeds the supported "
            f"maximum of {MAX_SAMPLE_RATE}."
        )
    if sample_width not in SUPPORTED_SAMPLE_WIDTHS:
        raise WaveFormatError(f"unsupported sample width: {sample_width} bytes.")
    if sample_width == 1:
        clamped = [max(-128, min(127, value)) + 128 for value in samples]
        raw = bytes(clamped)
    elif sample_width == 2:
        clamped = [max(-32768, min(32767, value)) for value in samples]
        raw = struct.pack(f"<{len(clamped)}h", *clamped)
    else:
        clamped = [max(-2147483648, min(2147483647, value)) for value in samples]
        raw = struct.pack(f"<{len(clamped)}i", *clamped)
    with wave.open(str(path), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(sample_width)
        handle.setframerate(sample_rate)
        handle.writeframes(raw)
