from pathlib import Path

from version import __version__

APP_NAME = "Biometrics"
APP_VERSION = __version__

DATA_DIR = Path("data")
IDENTITY_DIR = DATA_DIR / "identities"
TEMPLATE_DIR = DATA_DIR / "templates"
REPORT_DIR = DATA_DIR / "reports"
SAMPLE_DIR = DATA_DIR / "samples"

TEMPLATE_WIDTH = 64
TEMPLATE_HEIGHT = 64
GRID_SIZE = 8
DEFAULT_THRESHOLD = 0.94


def ensure_data_dirs() -> None:
    for directory in (
        IDENTITY_DIR,
        TEMPLATE_DIR,
        REPORT_DIR,
        SAMPLE_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)