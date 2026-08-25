"""Video feature extraction: a BRVID frame sequence reduced to a fixed-length
vector.

The approach is to treat video as "images plus motion": each frame
contributes a coarse spatial summary (a block-mean grid, the same technique
``image_tools.block_grid_means`` uses for still images), and consecutive
frame differences contribute a motion-energy summary. The two are
concatenated and averaged across the sequence, producing one fixed-length
vector independent of how many frames the source video contained.
"""
from biometrics.codecs import image_tools, video
from biometrics.features.similarity import distance_similarity

GRID_SIZE = 6
MAX_FRAMES_SAMPLED = 60  # bounds extraction cost for a very long capture;
# frames beyond this are evenly subsampled rather than all processed.
# per-frame grid means + motion-energy grid means
FEATURE_VECTOR_LENGTH = (GRID_SIZE * GRID_SIZE) * 2


class VideoFeatureError(ValueError):
    """Raised when video feature extraction cannot proceed."""


def _subsample(frames: list) -> list:
    if len(frames) <= MAX_FRAMES_SAMPLED:
        return frames
    step = len(frames) / MAX_FRAMES_SAMPLED
    indices = sorted({int(index * step) for index in range(MAX_FRAMES_SAMPLED)})
    return [frames[index] for index in indices]


def _frame_difference(width: int, height: int, previous: bytes, current: bytes) -> bytes:
    return bytes(abs(a - b) for a, b in zip(previous, current))


def extract_from_frames(width: int, height: int, frames: list) -> list:
    """Extract a fixed-length spatial+motion vector from grayscale frames."""
    if width <= 0 or height <= 0:
        raise VideoFeatureError("width and height must be positive.")
    if not frames:
        raise VideoFeatureError("at least one frame is required.")
    for index, frame in enumerate(frames):
        if len(frame) != width * height:
            raise VideoFeatureError(
                f"frame {index} does not match the given dimensions."
            )
    sampled = _subsample(frames)
    cell_count = GRID_SIZE * GRID_SIZE
    spatial_sums = [0.0] * cell_count
    motion_sums = [0.0] * cell_count
    for frame in sampled:
        normalized = image_tools.normalize(frame)
        means = image_tools.block_grid_means(width, height, normalized, GRID_SIZE)
        for index, value in enumerate(means):
            spatial_sums[index] += value
    motion_frame_count = 0
    for previous, current in zip(sampled, sampled[1:]):
        difference = _frame_difference(width, height, previous, current)
        means = image_tools.block_grid_means(width, height, difference, GRID_SIZE)
        for index, value in enumerate(means):
            motion_sums[index] += value
        motion_frame_count += 1
    spatial_average = [value / len(sampled) for value in spatial_sums]
    if motion_frame_count > 0:
        motion_average = [value / motion_frame_count for value in motion_sums]
    else:
        # A single-frame capture has no motion to measure; report zero rather
        # than dividing by zero.
        motion_average = [0.0] * cell_count
    return spatial_average + motion_average


def extract_from_video(path) -> list:
    """Read a BRVID file and extract its fixed-length video feature vector."""
    decoded = video.read_video(path)
    return extract_from_frames(decoded["width"], decoded["height"], decoded["frames"])


def compare(vector_a: list, vector_b: list) -> float:
    """Distance-based similarity between two video feature vectors, in
    (0.0, 1.0].

    Previously used raw cosine similarity. Video features are largely raw
    pixel-brightness block-means (mostly positive, roughly 0-255), so any
    two videos' vectors point in a similar direction through positive
    space regardless of content, producing false high scores (confirmed:
    0.9159 between two different people's clips, above the 0.75 default
    threshold -- see biometrics/features/similarity.py's module
    docstring for the full verification). Switched to normalized
    Euclidean distance, confirmed to push the same impostor pair down to
    0.4393 while a genuine self-match stays at 1.0000.
    """
    if len(vector_a) != len(vector_b):
        raise VideoFeatureError("feature vectors must be the same length.")
    return distance_similarity(vector_a, vector_b)
