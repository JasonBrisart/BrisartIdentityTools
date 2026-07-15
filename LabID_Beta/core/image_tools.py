import statistics


def resize_nearest(width: int, height: int, pixels, new_width: int, new_height: int):
    if width == new_width and height == new_height:
        return list(pixels)

    resized = []
    for y in range(new_height):
        src_y = min(height - 1, int(y * height / new_height))
        for x in range(new_width):
            src_x = min(width - 1, int(x * width / new_width))
            resized.append(pixels[src_y * width + src_x])
    return resized


def normalize_pixels(pixels):
    mean = statistics.fmean(pixels)
    stdev = statistics.pstdev(pixels) or 1.0
    normalized = []

    for value in pixels:
        z_score = (value - mean) / stdev
        normalized_value = 128 + z_score * 32
        normalized.append(max(0, min(255, round(normalized_value))))

    return normalized


def block_averages(pixels, width: int, height: int, grid_size: int):
    features = []
    block_width = width / grid_size
    block_height = height / grid_size

    for grid_y in range(grid_size):
        y0 = int(round(grid_y * block_height))
        y1 = int(round((grid_y + 1) * block_height))
        for grid_x in range(grid_size):
            x0 = int(round(grid_x * block_width))
            x1 = int(round((grid_x + 1) * block_width))

            values = []
            for y in range(y0, min(y1, height)):
                start = y * width
                values.extend(pixels[start + x0:start + min(x1, width)])

            features.append(round(statistics.fmean(values), 4) if values else 0.0)

    return features


def gradient_grid(pixels, width: int, height: int, grid_size: int):
    gradients = [0] * (width * height)

    for y in range(1, height - 1):
        for x in range(1, width - 1):
            left = pixels[y * width + (x - 1)]
            right = pixels[y * width + (x + 1)]
            up = pixels[(y - 1) * width + x]
            down = pixels[(y + 1) * width + x]
            gradients[y * width + x] = min(255, abs(right - left) + abs(down - up))

    return block_averages(gradients, width, height, grid_size)
