from pathlib import Path

APP_NAME = "IdentityVault"
APP_VERSION = "0.7.0-beta-bsr2"
FORMAT_VERSION = 2

# Storage modes recorded on the vault header and on each record.
#
# Records written before BSR2 carry PLAINTEXT_STORAGE_MODE. They are still
# readable, so an existing vault is not bricked by upgrading, but they are
# reported as unprotected by ``verify`` and are re-sealed on next write.
PLAINTEXT_STORAGE_MODE = "plaintext_json_beta"
SEALED_STORAGE_MODE = "bsr2_sealed"

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
