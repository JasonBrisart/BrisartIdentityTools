from pathlib import Path

APP_NAME = "BrisartIdentityTools"
APP_VERSION = "0.2.0-beta"

DATA_DIR = Path("data")
IDENTITY_DIR = DATA_DIR / "identities"
TEMPLATE_DIR = DATA_DIR / "templates"
REPORT_DIR = DATA_DIR / "reports"

TEMPLATE_WIDTH = 64
TEMPLATE_HEIGHT = 64
GRID_SIZE = 8
DEFAULT_THRESHOLD = 0.94


def ensure_data_dirs() -> None:
    IDENTITY_DIR.mkdir(parents=True, exist_ok=True)
    TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
