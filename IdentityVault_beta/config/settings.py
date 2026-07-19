from pathlib import Path

APP_NAME = "IdentityVault"
APP_VERSION = "0.6.0-beta-plaintext"
FORMAT_VERSION = 1

DATA_DIR = Path("data")
VAULT_DIR = DATA_DIR / "vaults"
DEFAULT_VAULT_PATH = VAULT_DIR / "main_vault.json"

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