"""Voice feature extraction: a WAV recording reduced to a fixed-length vector.

The pipeline is deliberately classical rather than learned, because this
project has no dependency on a machine-learning library and no training data
to fit one with: frame the signal, window each frame, summarise it in a few
complementary ways (energy, zero-crossing rate, band-energy DCT
coefficients), then average those per-frame summaries across the whole
recording. The result is a fixed-length vector regardless of how long the
input recording was, which is what ``engine/modalities.py`` needs to compare
two recordings of different lengths.

None of this claims to be state-of-the-art speaker verification. It is a
transparent, fully auditable, dependency-free feature set suitable for the
threshold-based matching this project performs.
"""
from biometrics.codecs import dsp, wave_tools

FRAME_SIZE = 512
HOP_SIZE = 256
BAND_COUNT = 8
DCT_COEFFICIENT_COUNT = 12

# energy + zero-crossing-rate + band energies + DCT coefficients
FEATURE_VECTOR_LENGTH = 1 + 1 + BAND_COUNT + DCT_COEFFICIENT_COUNT


class VoiceFeatureError(ValueError):
    """Raised when voice feature extraction cannot proceed."""


def extract_from_samples(samples: list, sample_rate: int) -> list:
    """Extract a fixed-length feature vector from mono integer samples."""
    if sample_rate <= 0:
        raise VoiceFeatureError("sample_rate must be positive.")
    if not samples:
        raise VoiceFeatureError("samples must not be empty.")
    frames = dsp.frame_signal(samples, FRAME_SIZE, HOP_SIZE)
    if not frames:
        raise VoiceFeatureError("no frames could be extracted from the recording.")

    energy_sum = 0.0
    zcr_sum = 0.0
    band_sums = [0.0] * BAND_COUNT
    dct_sums = [0.0] * DCT_COEFFICIENT_COUNT

    for frame in frames:
        windowed = dsp.apply_hamming_window(frame)
        energy_sum += dsp.short_time_energy(windowed)
        zcr_sum += dsp.zero_crossing_rate(frame)
        bands = dsp.band_energies(windowed, BAND_COUNT)
        for index, value in enumerate(bands):
            band_sums[index] += value
        dct = dsp.discrete_cosine_transform(bands, DCT_COEFFICIENT_COUNT)
        for index, value in enumerate(dct):
            dct_sums[index] += value

    frame_count = len(frames)
    vector = (
        [energy_sum / frame_count]
        + [zcr_sum / frame_count]
        + [value / frame_count for value in band_sums]
        + [value / frame_count for value in dct_sums]
    )
    return dsp.normalize_vector(vector)


def extract_from_wav(path) -> list:
    """Read a WAV file and extract its fixed-length voice feature vector."""
    decoded = wave_tools.read_wave(path)
    return extract_from_samples(decoded["samples"], decoded["sample_rate"])


def compare(vector_a: list, vector_b: list) -> float:
    """Cosine similarity between two feature vectors, in ``[-1.0, 1.0]``.

    Cosine similarity is used rather than Euclidean distance because it is
    insensitive to the overall scale of the two vectors, only their
    direction -- appropriate here since ``normalize_vector`` already removes
    absolute scale but two recordings can still differ in relative loudness
    per-band.
    """
    if len(vector_a) != len(vector_b):
        raise VoiceFeatureError("feature vectors must be the same length.")
    dot_product = sum(a * b for a, b in zip(vector_a, vector_b))
    magnitude_a = sum(a * a for a in vector_a) ** 0.5
    magnitude_b = sum(b * b for b in vector_b) ** 0.5
    if magnitude_a == 0 or magnitude_b == 0:
        return 0.0
    return dot_product / (magnitude_a * magnitude_b)