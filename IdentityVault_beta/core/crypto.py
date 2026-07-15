import hashlib
import hmac
import secrets

from config.settings import KEY_BYTES, NONCE_BYTES, PBKDF2_ALGORITHM, PBKDF2_ITERATIONS, SALT_BYTES
from core.encoding import b64d, b64e


class VaultCryptoError(Exception):
    pass


def random_salt() -> bytes:
    return secrets.token_bytes(SALT_BYTES)


def random_nonce() -> bytes:
    return secrets.token_bytes(NONCE_BYTES)


def derive_master_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    if not password:
        raise VaultCryptoError("password cannot be empty.")
    return hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM,
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=KEY_BYTES,
    )


def derive_subkey(master_key: bytes, purpose: bytes) -> bytes:
    return hmac.new(master_key, purpose, hashlib.sha256).digest()


def keystream_block(encryption_key: bytes, nonce: bytes, counter: int) -> bytes:
    counter_bytes = counter.to_bytes(8, "big")
    return hmac.new(encryption_key, nonce + counter_bytes, hashlib.sha256).digest()


def xor_bytes(data: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, stream))


def stream_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    output = bytearray()
    counter = 0
    index = 0
    while index < len(data):
        block = keystream_block(key, nonce, counter)
        chunk = data[index:index + len(block)]
        output.extend(xor_bytes(chunk, block[:len(chunk)]))
        index += len(chunk)
        counter += 1
    return bytes(output)


def auth_tag(auth_key: bytes, record_id: str, kind: str, label: str, nonce: bytes, ciphertext: bytes) -> bytes:
    context = "|".join([record_id, kind, label]).encode("utf-8")
    return hmac.new(auth_key, context + nonce + ciphertext, hashlib.sha256).digest()


def encrypt_payload(master_key: bytes, record_id: str, kind: str, label: str, plaintext: bytes) -> dict:
    encryption_key = derive_subkey(master_key, b"IdentityVault encryption key")
    authentication_key = derive_subkey(master_key, b"IdentityVault authentication key")
    nonce = random_nonce()
    ciphertext = stream_xor(encryption_key, nonce, plaintext)
    tag = auth_tag(authentication_key, record_id, kind, label, nonce, ciphertext)
    return {
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "tag": b64e(tag),
    }


def decrypt_payload(master_key: bytes, record_id: str, kind: str, label: str, encrypted: dict) -> bytes:
    encryption_key = derive_subkey(master_key, b"IdentityVault encryption key")
    authentication_key = derive_subkey(master_key, b"IdentityVault authentication key")
    nonce = b64d(encrypted["nonce"])
    ciphertext = b64d(encrypted["ciphertext"])
    expected_tag = auth_tag(authentication_key, record_id, kind, label, nonce, ciphertext)
    provided_tag = b64d(encrypted["tag"])
    if not hmac.compare_digest(expected_tag, provided_tag):
        raise VaultCryptoError("authentication tag mismatch. Wrong password or modified vault data.")
    return stream_xor(encryption_key, nonce, ciphertext)


def password_check_value(master_key: bytes) -> str:
    return b64e(hmac.new(master_key, b"IdentityVault password check", hashlib.sha256).digest())


def verify_password_check(master_key: bytes, expected: str) -> bool:
    return hmac.compare_digest(password_check_value(master_key), expected)
