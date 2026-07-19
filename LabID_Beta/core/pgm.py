from pathlib import Path


class PGMError(Exception):
    """Raised when a PGM image cannot be parsed or written."""


def _read_token(data: bytes, index: int) -> tuple[str, int]:
    length = len(data)
    while index < length:
        byte = data[index]
        if byte in b" \t\r\n":
            index += 1
            continue
        if byte == ord("#"):
            while index < length and data[index] not in b"\r\n":
                index += 1
            continue
        break

    if index >= length:
        raise PGMError("Unexpected end of file while reading PGM header.")

    start = index
    while index < length and data[index] not in b" \t\r\n#":
        index += 1

    try:
        token = data[start:index].decode("ascii")
    except UnicodeDecodeError as exc:
        raise PGMError("PGM header contains non-ASCII data.") from exc

    return token, index


def _positive_integer(value: str, field: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise PGMError(f"PGM {field} must be an integer.") from exc
    if number <= 0:
        raise PGMError(f"PGM {field} must be positive.")
    return number


def _consume_binary_separator(data: bytes, index: int) -> int:
    if index >= len(data) or data[index] not in b" \t\r\n":
        raise PGMError("Binary PGM header is missing its data separator.")

    if data[index:index + 2] == b"\r\n":
        return index + 2
    return index + 1


def _read_ascii_pixels(data: bytes, index: int) -> list[int]:
    try:
        text = data[index:].decode("ascii")
    except UnicodeDecodeError as exc:
        raise PGMError("P2 pixel data contains non-ASCII bytes.") from exc

    values: list[int] = []
    for line in text.splitlines():
        content = line.split("#", 1)[0]
        for token in content.split():
            try:
                values.append(int(token))
            except ValueError as exc:
                raise PGMError(f"Invalid P2 pixel value: {token}") from exc
    return values


def read_pgm(path: str) -> tuple[int, int, list[int]]:
    image_path = Path(path)
    try:
        raw = image_path.read_bytes()
    except OSError as exc:
        raise PGMError(f"Unable to read PGM image: {image_path}") from exc

    index = 0
    magic, index = _read_token(raw, index)
    if magic not in ("P2", "P5"):
        raise PGMError("Only P2 and P5 grayscale PGM images are supported.")

    width_token, index = _read_token(raw, index)
    height_token, index = _read_token(raw, index)
    max_token, index = _read_token(raw, index)

    width = _positive_integer(width_token, "width")
    height = _positive_integer(height_token, "height")
    max_value = _positive_integer(max_token, "maximum value")
    if max_value > 65535:
        raise PGMError("PGM maximum value cannot exceed 65535.")

    expected_pixels = width * height
    if magic == "P2":
        values = _read_ascii_pixels(raw, index)
        if len(values) != expected_pixels:
            raise PGMError(
                f"P2 pixel count mismatch. Expected {expected_pixels}, "
                f"found {len(values)}."
            )
    else:
        index = _consume_binary_separator(raw, index)
        bytes_per_pixel = 1 if max_value < 256 else 2
        expected_bytes = expected_pixels * bytes_per_pixel
        payload = raw[index:index + expected_bytes]
        if len(payload) != expected_bytes:
            raise PGMError(
                f"P5 payload size mismatch. Expected {expected_bytes} bytes, "
                f"found {len(payload)}."
            )
        trailing = raw[index + expected_bytes:]
        if trailing and trailing.strip(b" \t\r\n"):
            raise PGMError("P5 image contains unexpected trailing data.")

        if bytes_per_pixel == 1:
            values = list(payload)
        else:
            values = [
                (payload[offset] << 8) + payload[offset + 1]
                for offset in range(0, expected_bytes, 2)
            ]

    for value in values:
        if not 0 <= value <= max_value:
            raise PGMError(
                f"PGM pixel value {value} is outside 0..{max_value}."
            )

    if max_value != 255:
        values = [round((value / max_value) * 255) for value in values]

    return width, height, [max(0, min(255, value)) for value in values]


def write_pgm(path: str, width: int, height: int, pixels) -> None:
    if width <= 0 or height <= 0:
        raise PGMError("PGM width and height must be positive.")

    values = [int(value) for value in pixels]
    expected = width * height
    if len(values) != expected:
        raise PGMError(
            f"Pixel count mismatch. Expected {expected}, found {len(values)}."
        )
    if any(value < 0 or value > 255 for value in values):
        raise PGMError("All output pixels must be between 0 and 255.")

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("w", encoding="ascii", newline="\n") as handle:
            handle.write("P2\n")
            handle.write(f"{width} {height}\n")
            handle.write("255\n")
            for y in range(height):
                row = values[y * width:(y + 1) * width]
                handle.write(" ".join(str(value) for value in row))
                handle.write("\n")
    except OSError as exc:
        raise PGMError(f"Unable to write PGM image: {output_path}") from exc
