import math
from pathlib import Path

from config import settings
from config.settings import ensure_data_dirs
from core.pgm import write_pgm
from core.png import write_png_grayscale
from core.video import write_avi_grayscale
from core.wave_tools import write_wav_mono


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


def _far_pattern(width: int, height: int, shift: int = 0):
    base = _face_like_pattern(width, height, shift=30 + shift, contrast=70)
    pixels = []
    for index, value in enumerate(base):
        x = index % width
        y = index // width
        stripe = 60 if (x // 8 + y // 8) % 2 == 0 else -60
        pixels.append(max(0, min(255, value + stripe)))
    return pixels


def _voice_pattern(sample_rate: int, base_hz: float, harmonic_hz: float, wobble: float = 0.0, seconds: float = 1.2):
    samples = []
    total = int(sample_rate * seconds)
    for t in range(total):
        phase = t / sample_rate
        mod = math.sin(2.0 * math.pi * 3.0 * phase) * wobble
        value = (
            0.72 * math.sin(2.0 * math.pi * (base_hz + mod) * phase)
            + 0.18 * math.sin(2.0 * math.pi * harmonic_hz * phase)
        )
        fade = min(1.0, phase * 10.0, (seconds - phase) * 10.0)
        samples.append(max(-1.0, min(1.0, value * fade)))
    return samples


def _fingerprint_pattern(width: int, height: int, shift: int = 0, bend: float = 2.0, mode: str = "arch"):
    pixels = []
    center_x = width / 2 + shift
    center_y = height * 0.58
    for y in range(height):
        for x in range(width):
            if mode == "whorl":
                dx = x - center_x
                dy = y - center_y
                radius = math.sqrt(dx * dx + dy * dy)
                angle = math.atan2(dy, dx)
                ridge = math.sin(radius * 0.72 + angle * 3.2)
                bowl = ((radius / max(width, height)) * 40.0)
                value = 230 if ridge > 0 else 28
                value = int(value - bowl)
            else:
                ridge = math.sin((x - center_x) * 0.55 + math.sin(y * 0.12) * bend)
                arch = ((y - center_y) / (height * 0.8)) ** 2
                value = 235 if ridge > 0 else 35
                value = int(value - arch * 30)
            pixels.append(max(0, min(255, value)))
    return pixels


def _video_frames(width: int, height: int, frame_count: int, drift: float,
                  contrast: int = 0, blink_every: int = 0):
    """A short face recording: the head drifts, and optionally blinks.

    Motion is what separates a genuine recording from a photograph held up to
    the lens, so the sample recordings actually move.
    """
    frames = []
    for index in range(frame_count):
        shift = int(round(math.sin(index * drift) * 3.0))
        frame = _face_like_pattern(width, height, shift=shift, contrast=contrast)

        if blink_every and index % blink_every == 0:
            # Close the eyes for one frame by filling the eye band with skin tone.
            center_x = width / 2 + shift
            for y in range(height):
                if abs(y - height * 0.38) >= 3:
                    continue
                for x in range(width):
                    if (abs(x - (center_x - width * 0.16)) < 4
                            or abs(x - (center_x + width * 0.16)) < 4):
                        frame[y * width + x] = 200

        frames.append(frame)
    return frames


def _far_video_frames(width: int, height: int, frame_count: int, drift: float):
    """A different subject, moving. Fails on face score, passes liveness."""
    frames = []
    for index in range(frame_count):
        shift = int(round(math.sin(index * drift) * 3.0))
        frames.append(_far_pattern(width, height, shift=shift))
    return frames


def _static_video_frames(width: int, height: int, frame_count: int):
    """A recording of a still photo: identical frames, so motion is zero."""
    single = _face_like_pattern(width, height, shift=0, contrast=0)
    return [list(single) for _ in range(frame_count)]


def generate_samples(output_dir=None) -> list:
    """Write demo face, video, voice, and fingerprint samples to the data dir."""
    width = 96
    height = 96
    sample_rate = 16000

    ensure_data_dirs()
    target_dir = Path(output_dir) if output_dir else settings.SAMPLE_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    written = []

    face_files = [
        ("sample_face_enroll.pgm", _face_like_pattern(width, height, shift=0, contrast=0), write_pgm),
        ("sample_face_verify_close.pgm", _face_like_pattern(width, height, shift=2, contrast=3), write_pgm),
        ("sample_face_verify_far.pgm", _far_pattern(width, height), write_pgm),
        ("sample_face_enroll.png", _face_like_pattern(width, height, shift=0, contrast=0), write_png_grayscale),
        ("sample_face_verify_close.png", _face_like_pattern(width, height, shift=2, contrast=3), write_png_grayscale),
        ("sample_face_verify_far.png", _far_pattern(width, height), write_png_grayscale),
    ]
    for file_name, pixels, writer in face_files:
        output_path = target_dir / file_name
        writer(str(output_path), width, height, pixels)
        written.append(str(output_path))

    voice_files = [
        ("sample_voice_enroll.wav", _voice_pattern(sample_rate, 220.0, 440.0, wobble=1.5)),
        ("sample_voice_verify_close.wav", _voice_pattern(sample_rate, 223.0, 446.0, wobble=1.6)),
        ("sample_voice_verify_far.wav", _voice_pattern(sample_rate, 330.0, 660.0, wobble=4.5)),
    ]
    for file_name, samples in voice_files:
        output_path = target_dir / file_name
        write_wav_mono(str(output_path), sample_rate, samples)
        written.append(str(output_path))

    finger_width = 120
    finger_height = 120
    finger_files = [
        ("sample_fingerprint_enroll.png", _fingerprint_pattern(finger_width, finger_height, shift=0, bend=2.0, mode="arch")),
        ("sample_fingerprint_verify_close.png", _fingerprint_pattern(finger_width, finger_height, shift=1, bend=2.2, mode="arch")),
        ("sample_fingerprint_verify_far.png", _fingerprint_pattern(finger_width, finger_height, shift=0, bend=0.0, mode="whorl")),
    ]
    for file_name, pixels in finger_files:
        output_path = target_dir / file_name
        write_png_grayscale(str(output_path), finger_width, finger_height, pixels)
        written.append(str(output_path))

    video_files = [
        ("sample_video_enroll.avi", _video_frames(width, height, 12, 0.55, contrast=0, blink_every=5)),
        ("sample_video_verify_close.avi", _video_frames(width, height, 12, 0.58, contrast=3, blink_every=6)),
        # A different subject, but genuinely moving: this must be rejected on
        # face score, not waved through or blocked by the liveness gate.
        ("sample_video_verify_far.avi", _far_video_frames(width, height, 12, 0.6)),
        ("sample_video_photo_replay.avi", _static_video_frames(width, height, 12)),
    ]
    for file_name, frames in video_files:
        output_path = target_dir / file_name
        write_avi_grayscale(str(output_path), width, height, frames, frames_per_second=15)
        written.append(str(output_path))

    return written
