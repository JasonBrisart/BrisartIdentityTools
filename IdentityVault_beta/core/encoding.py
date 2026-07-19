import base64
import binascii


class EncodingError(ValueError):
    """Raised when canonical URL-safe Base64 data is invalid."""


def b64e(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise EncodingError("Base64 input must be bytes.")
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    if not isinstance(data, str):
        raise EncodingError(
            "Base64 input must be a string."
        )

    try:
        encoded = data.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EncodingError(
            "Base64 input must contain ASCII characters only."
        ) from exc

    try:
        decoded = base64.b64decode(
            encoded,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise EncodingError(
            "Base64 input is malformed."
        ) from exc

    if b64e(decoded) != data:
        raise EncodingError(
            "Base64 input is not in canonical form."
        )

    return decoded
