import hashlib
import json
import math
from pathlib import Path

from core.dsp import (
    apply_window,
    autocorrelation_pitch,
    frame_signal,
    hann_window,
    mfcc,
    pre_emphasis,
    rms_energy,
    zero_crossing_rate,
)
from core.wave_tools import audio_duration_seconds, read_wav_mono


VOICE_TEMPLATE_VERSION = "0.1.0-beta"
VOICE_MODE = "local_voice_verification_beta"


class VoiceTemplateError(Exception):
    """Raised when a voice template cannot be built."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mean(values) -> float:
    return sum(values) / len(values) if values else 0.0


def _stdev(values) -> float:
    if len(values) < 2:
        return 0.0
    mean = _mean(values)
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return math.sqrt(variance)


def _median(values) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _voice_activity_segments(samples, frame_size: int, hop_size: int):
    frames = frame_signal(samples, frame_size, hop_size)
    if not frames:
        return []

    energies = [rms_energy(frame) for frame in frames]
    energy_floor = max(0.01, _median(energies) * 0.35)
    kept = [frame for frame, energy in zip(frames, energies) if energy >= energy_floor]
    return kept or frames


def create_voice_template(audio_path: str) -> dict:
    path = Path(audio_path)
    sample_rate, samples = read_wav_mono(str(path))
    duration = audio_duration_seconds(sample_rate, samples)

    if duration < 0.25:
        raise VoiceTemplateError("Audio sample is too short; need at least 0.25 seconds.")

    frame_size = max(256, int(sample_rate * 0.025))
    hop_size = max(128, int(sample_rate * 0.010))
    voiced_frames = _voice_activity_segments(samples, frame_size, hop_size)
    window = hann_window(frame_size)

    frame_mfccs = []
    frame_pitch = []
    frame_energy = []
    frame_zcr = []

    for frame in voiced_frames:
        if len(frame) != frame_size:
            continue
        emphasized = pre_emphasis(frame)
        windowed = apply_window(emphasized, window)
        frame_mfccs.append(mfcc(windowed, sample_rate, filters=24, coefficients=13))
        frame_pitch.append(autocorrelation_pitch(frame, sample_rate))
        frame_energy.append(rms_energy(frame))
        frame_zcr.append(zero_crossing_rate(frame))

    if not frame_mfccs:
        raise VoiceTemplateError("Unable to extract any valid voice frames from the audio sample.")

    mfcc_means = []
    mfcc_stdevs = []
    for index in range(len(frame_mfccs[0])):
        values = [vector[index] for vector in frame_mfccs]
        mfcc_means.append(round(_mean(values), 6))
        mfcc_stdevs.append(round(_stdev(values), 6))

    pitch_nonzero = [value for value in frame_pitch if value > 0.0]
    features = {
        "mfcc_mean": mfcc_means,
        "mfcc_stdev": mfcc_stdevs,
        "pitch_mean_hz": round(_mean(pitch_nonzero), 6),
        "pitch_stdev_hz": round(_stdev(pitch_nonzero), 6),
        "energy_mean": round(_mean(frame_energy), 6),
        "energy_stdev": round(_stdev(frame_energy), 6),
        "zcr_mean": round(_mean(frame_zcr), 6),
        "zcr_stdev": round(_stdev(frame_zcr), 6),
        "duration_seconds": duration,
        "sample_rate": sample_rate,
        "voiced_frames": len(frame_mfccs),
    }

    template = {
        "template_version": VOICE_TEMPLATE_VERSION,
        "mode": VOICE_MODE,
        "source_audio_sha256": sha256_file(path),
        "source_format": "WAV PCM",
        "features": features,
    }
    stable_features = json.dumps(features, sort_keys=True).encode("utf-8")
    template["template_sha256"] = sha256_bytes(stable_features)
    return template
