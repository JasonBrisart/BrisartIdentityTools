from pathlib import Path


APP_NAME = "IdentityVault"
APP_VERSION = "0.5.0-beta"
FORMAT_VERSION = 1

DATA_DIR = Path("data")
VAULT_DIR = DATA_DIR / "vaults"
DEFAULT_VAULT_PATH = VAULT_DIR / "main_vault.json"

PBKDF2_ALGORITHM = "sha256"
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 32
KEY_BYTES = 32

BCE1_ALGORITHM = "BCE1-HMAC-SHA256-CTR-ETM"
BCE1_VERSION = 1
BCE1_RECORD_SALT_BYTES = 32
BCE1_NONCE_BYTES = 32
BCE1_TAG_BYTES = 32
BCE1_MAX_PLAINTEXT_BYTES = 16 * 1024 * 1024
BCE1_MAX_CIPHERTEXT_BYTES = BCE1_MAX_PLAINTEXT_BYTES

SUPPORTED_RECORD_KINDS = frozenset(
    {
        "access_token",
        "biometric_template",
        "certificate_note",
        "credential",
        "general",
        "identity",
        "recovery_note",
        "secret",
        "verification_metadata",
    }
)
