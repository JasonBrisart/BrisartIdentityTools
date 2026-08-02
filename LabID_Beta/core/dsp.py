"""Pure-Python DSP helpers for audio feature extraction.

No numpy/scipy dependency: this module provides the small subset we need for
voice verification using only stdlib ``math`` and ``cmath``.

Implemented here:
- pre-emphasis
- framing with overlap and zero-pad of the final short frame
- Hann window
- radix-2 Cooley-Tukey FFT (with a zero-padded fallback length)
- power spectrum
- mel filterbank
- DCT-II for MFCCs
- zero crossing rate, RMS energy, simple autocorrelation pitch estimate
"""

import cmath
import math
from typing import Optional


def next_power_of_two(value: int) -> int:
    if value <= 1:
        return 1
    size = 1
    while size < value:
        size <<= 1
    return size


def pre_emphasis(samples, coefficient: float = 0.97) -> list:
    values = [float(sample) for sample in samples]
    if not values:
        return []
    out = [values[0]]
    for index in range(1, len(values)):
        out.append(values[index] - coefficient * values[index - 1])
    return out


def frame_signal(samples, frame_size: int, hop_size: int) -> list:
    if frame_size <= 0 or hop_size <= 0:
        raise ValueError("frame_size and hop_size must be positive integers.")

    values = [float(sample) for sample in samples]
    if not values:
        return []

    frames = []
    index = 0
    length = len(values)
    while index < length:
        frame = values[index:index + frame_size]
        if len(frame) < frame_size:
            frame = frame + [0.0] * (frame_size - len(frame))
        frames.append(frame)
        if index + frame_size >= length:
            break
        index += hop_size
    return frames


def hann_window(length: int) -> list:
    if length <= 0:
        raise ValueError("window length must be positive.")
    if length == 1:
        return [1.0]
    return [0.5 - 0.5 * math.cos((2.0 * math.pi * n) / (length - 1)) for n in range(length)]


def apply_window(frame, window) -> list:
    if len(frame) != len(window):
        raise ValueError("frame and window must be the same length.")
    return [float(sample) * float(weight) for sample, weight in zip(frame, window)]


def fft(values) -> list:
    """Radix-2 FFT. Caller pads to a power of two before calling."""
    length = len(values)
    if length == 0:
        return []
    if length == 1:
        return [complex(values[0])]
    if length & (length - 1):
        raise ValueError("fft length must be a power of two.")

    even = fft(values[0::2])
    odd = fft(values[1::2])
    out = [0j] * length
    half = length // 2
    for k in range(half):
        twiddle = cmath.exp(-2j * math.pi * k / length) * odd[k]
        out[k] = even[k] + twiddle
        out[k + half] = even[k] - twiddle
    return out


def power_spectrum(frame) -> list:
    size = next_power_of_two(len(frame))
    padded = [complex(value) for value in frame] + [0j] * (size - len(frame))
    bins = fft(padded)
    scale = float(size)
    half = size // 2 + 1
    return [((bin_.real ** 2) + (bin_.imag ** 2)) / scale for bin_ in bins[:half]]


def hz_to_mel(hz: float) -> float:
    return 2595.0 * math.log10(1.0 + hz / 700.0)


def mel_to_hz(mel: float) -> float:
    return 700.0 * (10 ** (mel / 2595.0) - 1.0)


def mel_filterbank(sample_rate: int, spectrum_bins: int,
                   filters: int = 26, low_hz: float = 20.0,
                   high_hz: Optional[float] = None) -> list:
    if sample_rate <= 0:
        raise ValueError("sample_rate must be positive.")
    if spectrum_bins < 2:
        raise ValueError("spectrum_bins must be at least 2.")
    if filters <= 0:
        raise ValueError("filters must be positive.")

    nyquist = sample_rate / 2.0
    high_hz = nyquist if high_hz is None else min(float(high_hz), nyquist)
    if not 0 <= low_hz < high_hz:
        raise ValueError("low_hz must be non-negative and below high_hz.")

    low_mel = hz_to_mel(low_hz)
    high_mel = hz_to_mel(high_hz)
    mel_points = [low_mel + (high_mel - low_mel) * i / (filters + 1) for i in range(filters + 2)]
    hz_points = [mel_to_hz(value) for value in mel_points]

    fft_size = (spectrum_bins - 1) * 2
    bins = [min(spectrum_bins - 1, max(0, int(math.floor((fft_size + 1) * hz / sample_rate)))) for hz in hz_points]

    bank = []
    for i in range(filters):
        left, center, right = bins[i], bins[i + 1], bins[i + 2]
        row = [0.0] * spectrum_bins

        if center == left:
            center += 1
        if right == center:
            right += 1

        for j in range(left, min(center, spectrum_bins)):
            row[j] = (j - left) / float(max(1, center - left))
        for j in range(center, min(right, spectrum_bins)):
            row[j] = (right - j) / float(max(1, right - center))
        bank.append(row)
    return bank


def apply_filterbank(spectrum, bank) -> list:
    energies = []
    for filt in bank:
        total = 0.0
        for sample, weight in zip(spectrum, filt):
            total += float(sample) * float(weight)
        energies.append(max(total, 1e-12))
    return energies


def dct_type_2(values, coefficients: int) -> list:
    if coefficients <= 0:
        raise ValueError("coefficients must be positive.")
    n = len(values)
    if n == 0:
        return [0.0] * coefficients
    out = []
    for k in range(coefficients):
        total = 0.0
        for i, value in enumerate(values):
            total += float(value) * math.cos(math.pi * k * (i + 0.5) / n)
        out.append(total)
    return out


def mfcc(frame, sample_rate: int, filters: int = 26, coefficients: int = 13) -> list:
    spectrum = power_spectrum(frame)
    bank = mel_filterbank(sample_rate, len(spectrum), filters=filters)
    mel_energies = apply_filterbank(spectrum, bank)
    log_mel = [math.log(value) for value in mel_energies]
    return dct_type_2(log_mel, coefficients)


def rms_energy(samples) -> float:
    values = [float(sample) for sample in samples]
    if not values:
        return 0.0
    return math.sqrt(sum(value * value for value in values) / len(values))


def zero_crossing_rate(samples) -> float:
    values = [float(sample) for sample in samples]
    if len(values) < 2:
        return 0.0
    crossings = 0
    for left, right in zip(values, values[1:]):
        if (left < 0 <= right) or (left > 0 >= right):
            crossings += 1
    return crossings / float(len(values) - 1)


def autocorrelation_pitch(samples, sample_rate: int,
                          min_hz: float = 60.0,
                          max_hz: float = 400.0) -> float:
    values = [float(sample) for sample in samples]
    if len(values) < 4 or sample_rate <= 0:
        return 0.0

    min_lag = max(1, int(sample_rate / max_hz))
    max_lag = min(len(values) - 1, int(sample_rate / min_hz))
    if min_lag >= max_lag:
        return 0.0

    mean = sum(values) / len(values)
    centered = [value - mean for value in values]
    energy = sum(value * value for value in centered)
    if energy <= 1e-12:
        return 0.0

    best_lag = 0
    best_score = 0.0
    for lag in range(min_lag, max_lag + 1):
        score = 0.0
        for i in range(len(centered) - lag):
            score += centered[i] * centered[i + lag]
        score /= energy
        if score > best_score:
            best_score = score
            best_lag = lag

    if best_lag == 0 or best_score < 0.15:
        return 0.0
    return sample_rate / float(best_lag)
