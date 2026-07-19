import copy
import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from IdentityVault_beta.config.settings import (
    BCE1_ALGORITHM,
    PBKDF2_ITERATIONS,
)
from IdentityVault_beta.core.crypto import (
    VaultCryptoError,
    decrypt_payload,
    derive_master_key,
    encrypt_payload,
    password_check_value,
    random_salt,
    verify_password_check,
)
from IdentityVault_beta.core.encoding import b64d, b64e


class BCE1CryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.master_key = derive_master_key(
            "correct horse battery staple",
            random_salt(),
            PBKDF2_ITERATIONS,
        )
        self.arguments = {
            "record_id": "vault_test_record",
            "kind": "secret",
            "label": "test-label",
        }
        self.plaintext = (
            "BCE1 test payload: café, laboratory, archive."
        ).encode("utf-8")

    def encrypt(self) -> dict:
        return encrypt_payload(
            master_key=self.master_key,
            plaintext=self.plaintext,
            **self.arguments,
        )

    def decrypt(self, encrypted: dict) -> bytes:
        return decrypt_payload(
            master_key=self.master_key,
            encrypted=encrypted,
            **self.arguments,
        )

    def test_round_trip(self) -> None:
        encrypted = self.encrypt()
        self.assertEqual(encrypted["algorithm"], BCE1_ALGORITHM)
        self.assertEqual(self.decrypt(encrypted), self.plaintext)

    def test_same_plaintext_encrypts_differently(self) -> None:
        first = self.encrypt()
        second = self.encrypt()
        self.assertNotEqual(first["record_salt"], second["record_salt"])
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])

    def test_empty_plaintext(self) -> None:
        encrypted = encrypt_payload(
            master_key=self.master_key,
            plaintext=b"",
            **self.arguments,
        )
        decrypted = decrypt_payload(
            master_key=self.master_key,
            encrypted=encrypted,
            **self.arguments,
        )
        self.assertEqual(decrypted, b"")

    def test_every_protected_binary_field_detects_tampering(self) -> None:
        for field in ("record_salt", "nonce", "ciphertext", "tag"):
            with self.subTest(field=field):
                encrypted = self.encrypt()
                raw = bytearray(b64d(encrypted[field]))
                if raw:
                    raw[0] ^= 1
                else:
                    raw.extend(b"x")
                encrypted[field] = b64e(bytes(raw))
                with self.assertRaises(VaultCryptoError):
                    self.decrypt(encrypted)

    def test_context_tampering_detected(self) -> None:
        encrypted = self.encrypt()
        for field, changed in (
            ("record_id", "different-record"),
            ("kind", "identity"),
            ("label", "different-label"),
        ):
            with self.subTest(field=field):
                arguments = dict(self.arguments)
                arguments[field] = changed
                with self.assertRaises(VaultCryptoError):
                    decrypt_payload(
                        master_key=self.master_key,
                        encrypted=encrypted,
                        **arguments,
                    )

    def test_algorithm_and_version_tampering_rejected(self) -> None:
        encrypted = self.encrypt()
        changed_algorithm = copy.deepcopy(encrypted)
        changed_algorithm["algorithm"] = "BCE0"
        with self.assertRaises(VaultCryptoError):
            self.decrypt(changed_algorithm)

        changed_version = copy.deepcopy(encrypted)
        changed_version["version"] = 999
        with self.assertRaises(VaultCryptoError):
            self.decrypt(changed_version)

    def test_unknown_and_missing_fields_rejected(self) -> None:
        encrypted = self.encrypt()
        extra = copy.deepcopy(encrypted)
        extra["unexpected"] = "value"
        with self.assertRaises(VaultCryptoError):
            self.decrypt(extra)

        missing = copy.deepcopy(encrypted)
        del missing["tag"]
        with self.assertRaises(VaultCryptoError):
            self.decrypt(missing)

    def test_wrong_master_key_rejected(self) -> None:
        encrypted = self.encrypt()
        wrong_key = derive_master_key(
            "wrong password",
            random_salt(),
            PBKDF2_ITERATIONS,
        )
        with self.assertRaises(VaultCryptoError):
            decrypt_payload(
                master_key=wrong_key,
                encrypted=encrypted,
                **self.arguments,
            )

    def test_password_check(self) -> None:
        expected = password_check_value(self.master_key)
        self.assertTrue(
            verify_password_check(self.master_key, expected)
        )
        self.assertFalse(
            verify_password_check(self.master_key, b64e(b"x" * 32))
        )

    def test_noncanonical_base64_rejected(self) -> None:
        encrypted = self.encrypt()
        encrypted["nonce"] = encrypted["nonce"].rstrip("=")
        with self.assertRaises(VaultCryptoError):
            self.decrypt(encrypted)


if __name__ == "__main__":
    unittest.main()
