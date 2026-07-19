import hashlib
import hmac
import secrets

from IdentityVault_beta.config.settings import (
    BCE1_ALGORITHM,
    BCE1_MAX_CIPHERTEXT_BYTES,
    BCE1_MAX_PLAINTEXT_BYTES,
    BCE1_NONCE_BYTES,
    BCE1_RECORD_SALT_BYTES,
    BCE1_TAG_BYTES,
    BCE1_VERSION,
    KEY_BYTES,
    PBKDF2_ALGORITHM,
    PBKDF2_ITERATIONS,
    SALT_BYTES,
)
from IdentityVault_beta.core.encoding import b64d, b64e


class VaultCryptoError(Exception):
    """Raised when vault encryption or authentication fails."""


_DOMAIN_EXTRACT = b"BCE1/extract/v1"
_DOMAIN_ENCRYPTION_KEY = b"BCE1/encryption-key/v1"
_DOMAIN_AUTHENTICATION_KEY = b"BCE1/authentication-key/v1"
_DOMAIN_KEYSTREAM = b"BCE1/keystream/v1"
_DOMAIN_TAG = b"BCE1/tag/v1"
_DOMAIN_PASSWORD_CHECK = b"BCE1/password-check/v1"


def random_salt() -> bytes:
    return secrets.token_bytes(SALT_BYTES)


def random_nonce() -> bytes:
    return secrets.token_bytes(BCE1_NONCE_BYTES)


def random_record_salt() -> bytes:
    return secrets.token_bytes(BCE1_RECORD_SALT_BYTES)


def derive_master_key(
    password: str,
    salt: bytes,
    iterations: int = PBKDF2_ITERATIONS,
) -> bytes:
    if not isinstance(password, str):
        raise VaultCryptoError("password must be a string.")
    if not password:
        raise VaultCryptoError("password cannot be empty.")
    if not isinstance(salt, bytes):
        raise VaultCryptoError("salt must be bytes.")
    if len(salt) != SALT_BYTES:
        raise VaultCryptoError(
            f"salt must contain exactly {SALT_BYTES} bytes."
        )
    if not isinstance(iterations, int):
        raise VaultCryptoError("iterations must be an integer.")
    if iterations < PBKDF2_ITERATIONS:
        raise VaultCryptoError(
            "KDF iteration count is below the supported minimum."
        )

    return hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM,
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=KEY_BYTES,
    )


def _frame_bytes(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise VaultCryptoError("framed value must be bytes.")
    return len(value).to_bytes(8, "big") + value


def _frame_text(value: str) -> bytes:
    if not isinstance(value, str):
        raise VaultCryptoError("framed text value must be a string.")
    return _frame_bytes(value.encode("utf-8"))


def authentication_context(
    record_id: str,
    kind: str,
    label: str,
) -> bytes:
    return b"".join(
        (
            _frame_text(BCE1_ALGORITHM),
            BCE1_VERSION.to_bytes(4, "big"),
            _frame_text(record_id),
            _frame_text(kind),
            _frame_text(label),
        )
    )


def _validate_master_key(master_key: bytes) -> None:
    if not isinstance(master_key, bytes):
        raise VaultCryptoError("master key must be bytes.")
    if len(master_key) != KEY_BYTES:
        raise VaultCryptoError(
            f"master key must contain exactly {KEY_BYTES} bytes."
        )


def _extract_record_key(
    master_key: bytes,
    record_salt: bytes,
) -> bytes:
    _validate_master_key(master_key)
    if len(record_salt) != BCE1_RECORD_SALT_BYTES:
        raise VaultCryptoError("record salt has an invalid length.")
    return hmac.new(
        record_salt,
        _DOMAIN_EXTRACT + master_key,
        hashlib.sha256,
    ).digest()


def _expand_key(
    record_key: bytes,
    purpose: bytes,
) -> bytes:
    return hmac.new(
        record_key,
        purpose + b"\x01",
        hashlib.sha256,
    ).digest()


def _record_subkeys(
    master_key: bytes,
    record_salt: bytes,
) -> tuple[bytes, bytes]:
    record_key = _extract_record_key(master_key, record_salt)
    encryption_key = _expand_key(
        record_key,
        _DOMAIN_ENCRYPTION_KEY,
    )
    authentication_key = _expand_key(
        record_key,
        _DOMAIN_AUTHENTICATION_KEY,
    )
    return encryption_key, authentication_key


def _keystream_block(
    encryption_key: bytes,
    nonce: bytes,
    counter: int,
) -> bytes:
    if len(nonce) != BCE1_NONCE_BYTES:
        raise VaultCryptoError("nonce has an invalid length.")
    if not isinstance(counter, int) or counter < 0:
        raise VaultCryptoError(
            "keystream counter must be a non-negative integer."
        )
    if counter >= 2 ** 64:
        raise VaultCryptoError("keystream counter exhausted.")

    return hmac.new(
        encryption_key,
        _DOMAIN_KEYSTREAM
        + nonce
        + counter.to_bytes(8, "big"),
        hashlib.sha256,
    ).digest()


def _xor_with_keystream(
    encryption_key: bytes,
    nonce: bytes,
    data: bytes,
) -> bytes:
    output = bytearray(len(data))
    offset = 0
    counter = 0

    while offset < len(data):
        block = _keystream_block(
            encryption_key,
            nonce,
            counter,
        )
        chunk_length = min(len(block), len(data) - offset)

        for index in range(chunk_length):
            output[offset + index] = (
                data[offset + index] ^ block[index]
            )

        offset += chunk_length
        counter += 1

    return bytes(output)


def _tag_input(
    context: bytes,
    record_salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    return b"".join(
        (
            _DOMAIN_TAG,
            _frame_bytes(context),
            _frame_bytes(record_salt),
            _frame_bytes(nonce),
            _frame_bytes(ciphertext),
        )
    )


def _authentication_tag(
    authentication_key: bytes,
    context: bytes,
    record_salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    return hmac.new(
        authentication_key,
        _tag_input(
            context,
            record_salt,
            nonce,
            ciphertext,
        ),
        hashlib.sha256,
    ).digest()


def _decode_field(
    encrypted: dict,
    field: str,
    expected_length: int | None = None,
    maximum_length: int | None = None,
) -> bytes:
    value = encrypted.get(field)
    if not isinstance(value, str):
        raise VaultCryptoError(
            f"encrypted field {field!r} must be a string."
        )

    try:
        decoded = b64d(value)
    except Exception as exc:
        raise VaultCryptoError(
            f"encrypted field {field!r} is invalid."
        ) from exc

    if expected_length is not None and len(decoded) != expected_length:
        raise VaultCryptoError(
            f"encrypted field {field!r} has an invalid length."
        )
    if maximum_length is not None and len(decoded) > maximum_length:
        raise VaultCryptoError(
            f"encrypted field {field!r} exceeds the size limit."
        )
    return decoded


def _validate_encrypted_object(encrypted: dict) -> None:
    if not isinstance(encrypted, dict):
        raise VaultCryptoError("encrypted payload must be an object.")

    required = {
        "algorithm",
        "version",
        "record_salt",
        "nonce",
        "ciphertext",
        "tag",
    }
    unknown = set(encrypted).difference(required)
    missing = required.difference(encrypted)

    if missing:
        raise VaultCryptoError(
            f"encrypted payload is missing fields: {sorted(missing)}"
        )
    if unknown:
        raise VaultCryptoError(
            f"encrypted payload has unknown fields: {sorted(unknown)}"
        )
    if encrypted["algorithm"] != BCE1_ALGORITHM:
        raise VaultCryptoError(
            "encrypted payload uses an unsupported algorithm."
        )
    if encrypted["version"] != BCE1_VERSION:
        raise VaultCryptoError(
            "encrypted payload uses an unsupported version."
        )


def encrypt_payload(
    master_key: bytes,
    record_id: str,
    kind: str,
    label: str,
    plaintext: bytes,
) -> dict:
    _validate_master_key(master_key)
    if not isinstance(plaintext, bytes):
        raise VaultCryptoError("plaintext must be bytes.")
    if len(plaintext) > BCE1_MAX_PLAINTEXT_BYTES:
        raise VaultCryptoError("plaintext exceeds the size limit.")

    context = authentication_context(record_id, kind, label)
    record_salt = random_record_salt()
    nonce = random_nonce()
    encryption_key, authentication_key = _record_subkeys(
        master_key,
        record_salt,
    )
    ciphertext = _xor_with_keystream(
        encryption_key,
        nonce,
        plaintext,
    )
    tag = _authentication_tag(
        authentication_key,
        context,
        record_salt,
        nonce,
        ciphertext,
    )

    return {
        "algorithm": BCE1_ALGORITHM,
        "version": BCE1_VERSION,
        "record_salt": b64e(record_salt),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "tag": b64e(tag),
    }


def decrypt_payload(
    master_key: bytes,
    record_id: str,
    kind: str,
    label: str,
    encrypted: dict,
) -> bytes:
    _validate_master_key(master_key)
    _validate_encrypted_object(encrypted)

    record_salt = _decode_field(
        encrypted,
        "record_salt",
        expected_length=BCE1_RECORD_SALT_BYTES,
    )
    nonce = _decode_field(
        encrypted,
        "nonce",
        expected_length=BCE1_NONCE_BYTES,
    )
    ciphertext = _decode_field(
        encrypted,
        "ciphertext",
        maximum_length=BCE1_MAX_CIPHERTEXT_BYTES,
    )
    provided_tag = _decode_field(
        encrypted,
        "tag",
        expected_length=BCE1_TAG_BYTES,
    )

    context = authentication_context(record_id, kind, label)
    encryption_key, authentication_key = _record_subkeys(
        master_key,
        record_salt,
    )
    expected_tag = _authentication_tag(
        authentication_key,
        context,
        record_salt,
        nonce,
        ciphertext,
    )

    if not hmac.compare_digest(expected_tag, provided_tag):
        raise VaultCryptoError(
            "authentication failed: wrong key or modified data."
        )

    return _xor_with_keystream(
        encryption_key,
        nonce,
        ciphertext,
    )


def password_check_value(master_key: bytes) -> str:
    _validate_master_key(master_key)
    check = hmac.new(
        master_key,
        _DOMAIN_PASSWORD_CHECK,
        hashlib.sha256,
    ).digest()
    return b64e(check)


def verify_password_check(
    master_key: bytes,
    expected: str,
) -> bool:
    _validate_master_key(master_key)
    if not isinstance(expected, str) or not expected:
        return False
    calculated = password_check_value(master_key)
    return hmac.compare_digest(calculated, expected)
