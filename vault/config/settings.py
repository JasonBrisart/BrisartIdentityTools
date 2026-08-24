"""Configuration constants for the vault.

``APP_VERSION`` intentionally pulls from the single root
``version.__version__`` rather than hardcoding its own string -- the same
fix already applied to ``biometrics/config/settings.py`` -- so the two tools
never drift into reporting different version numbers for what is one
ecosystem release.
"""
from pathlib import Path

from version import __version__

APP_NAME = "Vault"
APP_VERSION = __version__

DATA_DIR = Path("data") / "vault"
VAULT_FILE = DATA_DIR / "vault.json"
AUDIT_DIR = DATA_DIR / "audit"


def ensure_data_dirs() -> None:
    for directory in (DATA_DIR, AUDIT_DIR):
        directory.mkdir(parents=True, exist_ok=True)
