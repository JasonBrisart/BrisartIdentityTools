"""Synthetic sample generation for testing and demos.

Real biometric captures require real hardware (a microphone, a fingerprint
scanner, a camera). To exercise enrollment and verification without any of
that, this module deterministically generates PGM images, WAV audio, and
BRVID video from a seed string -- the same seed always produces the same
sample, and two different seeds produce visibly/audibly different samples,
which is exactly what the test suite and the CLI's "make-samples" command
need: reproducible positive and negative test fixtures with zero external
dependencies (no camera, no microphone, no image/audio library).

None of this is meant to resemble a real fingerprint, voice, or face. It is
patterned synthetic data sized and shaped like the real thing, sufficient to
drive the feature extractors end-to-end.
"""
import math
import struct

from biometrics.codecs import pgm, video, wave_tools

DEFAULT_IMAGE_SIZE = 128
DEFAULT_SAMPLE_RATE = 8000
DEFAULT_AUDIO_SECONDS = 2
DEFAULT_VIDEO_FRAME_COUNT = 10
DEFAULT_VIDEO_FRAME_RATE = 5


class SampleGeneratorError(ValueError):
    """Raised on invalid sample generation parameters."""


def _seed_to_int(seed: str) -> int:
    """Turn an arbitrary seed string into a deterministic integer.

    Uses only ``struct``/built-in arithmetic (no hashlib requirement here,
    though hashlib would also be standard-library-only): a simple polynomial
    rolling accumulator is sufficient since this only needs to be
    deterministic and seed-sensitive, not cryptographically strong.
    """
    if not isinstance(seed, str) or not seed:
        raise SampleGeneratorError("seed must be a non-empty string.")
    accumulator = 0
    for character in seed:
        accumulator = (accumulator * 131 + ord(character)) & 0xFFFFFFFF
    return accumulator


def generate_fingerprint_image(seed: str, size: int = DEFAULT_IMAGE_SIZE) -> bytes:
    """Generate a synthetic grayscale "fingerprint-like" ridge pattern as PGM bytes.

    Produces concentric sinusoidal ridges whose frequency and phase are
    derived from the seed, which gives each seed a visually and numerically
    distinct ridge-orientation field -- the property
    ``fingerprint_features.py`` actually measures.
    """
    if size < 8:
        raise SampleGeneratorError("size must be at least 8.")
    seed_value = _seed_to_int(seed)
    frequency = 0.15 + (seed_value % 50) / 200.0
    phase = (seed_value % 628) / 100.0
    center = size / 2.0
    pixels = bytearray(size * size)
    for row in range(size):
        for col in range(size):
            distance = math.hypot(col - center, row - center)
            angle = math.atan2(row - center, col - center)
            value = math.sin(distance * frequency + angle * 2 + phase)
            pixels[row * size + col] = int((value + 1.0) * 127.5)
    return pgm.encode(size, size, bytes(pixels))


def generate_voice_sample(
    seed: str,
    sample_rate: int = DEFAULT_SAMPLE_RATE,
    duration_seconds: float = DEFAULT_AUDIO_SECONDS,
) -> dict:
    """Generate a synthetic "voice-like" waveform as raw samples.

    Returns ``{"sample_rate", "samples"}`` ready for
    ``biometrics.codecs.wave_tools.write_wave``. The waveform is a sum of a
    few harmonics whose base frequency and amplitude envelope are derived
    from the seed, giving each seed a distinct energy and spectral profile
    for ``voice_features.py`` to measure.
    """
    if sample_rate <= 0:
        raise SampleGeneratorError("sample_rate must be positive.")
    if duration_seconds <= 0:
        raise SampleGeneratorError("duration_seconds must be positive.")
    seed_value = _seed_to_int(seed)
    base_frequency = 80.0 + (seed_value % 120)
    sample_count = int(sample_rate * duration_seconds)
    samples = []
    for index in range(sample_count):
        time = index / sample_rate
        envelope = 0.5 * (1.0 - math.cos(2 * math.pi * min(time / 0.05, 1.0)))
        value = (
            math.sin(2 * math.pi * base_frequency * time)
            + 0.5 * math.sin(2 * math.pi * base_frequency * 2 * time)
            + 0.25 * math.sin(2 * math.pi * base_frequency * 3 * time)
        )
        samples.append(int(value * envelope * 8000))
    return {"sample_rate": sample_rate, "samples": samples}


def write_voice_sample(path, seed: str, sample_rate: int = DEFAULT_SAMPLE_RATE) -> None:
    """Generate and write a synthetic voice sample as a WAV file."""
    generated = generate_voice_sample(seed, sample_rate)
    wave_tools.write_wave(path, generated["sample_rate"], generated["samples"])


def generate_video_frames(
    seed: str,
    width: int = DEFAULT_IMAGE_SIZE,
    height: int = DEFAULT_IMAGE_SIZE,
    frame_count: int = DEFAULT_VIDEO_FRAME_COUNT,
) -> list:
    """Generate a sequence of synthetic grayscale frames with seed-driven motion.

    Each frame is a moving sinusoidal pattern; the direction and speed of
    motion are derived from the seed, giving ``video_features.py``'s
    motion-energy summary something seed-distinct to measure across frames.
    """
    if width < 8 or height < 8:
        raise SampleGeneratorError("width and height must be at least 8.")
    if frame_count < 1:
        raise SampleGeneratorError("frame_count must be at least 1.")
    seed_value = _seed_to_int(seed)
    frequency = 0.1 + (seed_value % 40) / 200.0
    drift_x = ((seed_value % 7) - 3) * 0.6
    drift_y = ((seed_value % 5) - 2) * 0.6
    frames = []
    for frame_index in range(frame_count):
        pixels = bytearray(width * height)
        offset_x = frame_index * drift_x
        offset_y = frame_index * drift_y
        for row in range(height):
            for col in range(width):
                value = math.sin((col + offset_x) * frequency) * math.cos(
                    (row + offset_y) * frequency
                )
                pixels[row * width + col] = int((value + 1.0) * 127.5)
        frames.append(bytes(pixels))
    return frames


def write_video_sample(
    path,
    seed: str,
    width: int = DEFAULT_IMAGE_SIZE,
    height: int = DEFAULT_IMAGE_SIZE,
    frame_count: int = DEFAULT_VIDEO_FRAME_COUNT,
    frame_rate: int = DEFAULT_VIDEO_FRAME_RATE,
) -> None:
    """Generate and write a synthetic video sample as a BRVID file."""
    frames = generate_video_frames(seed, width, height, frame_count)
    video.write_video(path, width, height, frame_rate, frames)


def write_fingerprint_sample(path, seed: str, size: int = DEFAULT_IMAGE_SIZE) -> None:
    """Generate and write a synthetic fingerprint-like image as a PGM file."""
    encoded = generate_fingerprint_image(seed, size)
    with open(path, "wb") as handle:
        handle.write(encoded)
