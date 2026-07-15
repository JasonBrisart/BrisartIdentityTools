from pathlib import Path

APP_NAME = "IdentityVault"
APP_VERSION = "0.1.0-beta"

DEFAULT_VAULT_PATH = Path("data") / "vaults" / "identity_vault.json"
PBKDF2_ALGORITHM = "sha256"
PBKDF2_ITERATIONS = 240_000
SALT_BYTES = 32
NONCE_BYTES = 32
KEY_BYTES = 32

SUPPORTED_RECORD_KINDS = {
    "secret",
    "identity",
    "biometric_template",
    "token",
    "certificate_note",
    "recovery_note",
    "general",
}
