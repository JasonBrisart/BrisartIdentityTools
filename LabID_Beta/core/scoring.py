import math


def euclidean_distance(values_a, values_b) -> float:
    if len(values_a) != len(values_b):
        raise ValueError("Feature vectors must be the same length.")
    return math.sqrt(sum((float(a) - float(b)) ** 2 for a, b in zip(values_a, values_b)))


def vector_similarity(values_a, values_b) -> float:
    distance = euclidean_distance(values_a, values_b)
    max_distance = math.sqrt(len(values_a) * (255 ** 2))
    return 1.0 - min(1.0, distance / max_distance)


def template_similarity(stored_template: dict, candidate_template: dict) -> float:
    stored_intensity = stored_template["features"]["intensity_grid"]
    candidate_intensity = candidate_template["features"]["intensity_grid"]

    stored_gradient = stored_template["features"]["gradient_grid"]
    candidate_gradient = candidate_template["features"]["gradient_grid"]

    intensity_score = vector_similarity(stored_intensity, candidate_intensity)
    gradient_score = vector_similarity(stored_gradient, candidate_gradient)

    final_score = (0.70 * intensity_score) + (0.30 * gradient_score)
    return round(final_score, 6)
