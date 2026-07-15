from pathlib import Path


class PGMError(Exception):
    pass


def _read_token(data: bytes, index: int):
    n = len(data)
    while index < n:
        byte = data[index]
        if byte in b" \t\r\n":
            index += 1
            continue
        if byte == ord("#"):
            while index < n and data[index] not in b"\r\n":
                index += 1
            continue
        break

    if index >= n:
        raise PGMError("Unexpected end of file while reading PGM header.")

    start = index
    while index < n and data[index] not in b" \t\r\n#":
        index += 1

    return data[start:index].decode("ascii"), index


def read_pgm(path: str):
    image_path = Path(path)
    raw = image_path.read_bytes()
    index = 0

    magic, index = _read_token(raw, index)
    if magic not in ("P2", "P5"):
        raise PGMError("Only P2 and P5 grayscale PGM images are supported.")

    width_token, index = _read_token(raw, index)
    height_token, index = _read_token(raw, index)
    max_token, index = _read_token(raw, index)

    width = int(width_token)
    height = int(height_token)
    max_value = int(max_token)

    if width <= 0 or height <= 0:
        raise PGMError("PGM width and height must be positive.")

    if max_value <= 0 or max_value > 65535:
        raise PGMError("Unsupported PGM max value.")

    expected_pixels = width * height

    if magic == "P2":
        text = raw[index:].decode("ascii", errors="ignore")
        values = []
        for line in text.splitlines():
            line = line.split("#", 1)[0]
            for part in line.split():
                values.append(int(part))

        if len(values) < expected_pixels:
            raise PGMError(f"Incomplete PGM pixel data. Expected {expected_pixels}, found {len(values)}.")
        values = values[:expected_pixels]

    else:
        while index < len(raw) and raw[index] in b" \t\r\n":
            index += 1

        if max_value < 256:
            payload = raw[index:index + expected_pixels]
            if len(payload) < expected_pixels:
                raise PGMError("Incomplete binary PGM pixel data.")
            values = list(payload)
        else:
            expected_bytes = expected_pixels * 2
            payload = raw[index:index + expected_bytes]
            if len(payload) < expected_bytes:
                raise PGMError("Incomplete 16-bit binary PGM pixel data.")
            values = []
            for i in range(0, expected_bytes, 2):
                values.append((payload[i] << 8) + payload[i + 1])

    if max_value != 255:
        values = [round((value / max_value) * 255) for value in values]

    values = [max(0, min(255, int(value))) for value in values]
    return width, height, values


def write_pgm(path: str, width: int, height: int, pixels) -> None:
    output_path = Path(path)
    with output_path.open("w", encoding="ascii") as handle:
        handle.write("P2\n")
        handle.write(f"{width} {height}\n")
        handle.write("255\n")
        for y in range(height):
            row = pixels[y * width:(y + 1) * width]
            handle.write(" ".join(str(max(0, min(255, int(value)))) for value in row))
            handle.write("\n")
