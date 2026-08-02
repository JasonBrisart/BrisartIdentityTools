"""Make both application trees importable no matter where pytest is invoked.

IdentityVault_beta uses absolute ``IdentityVault_beta.*`` imports, so the
repository root must be on sys.path. LabID_Beta uses root-relative imports
(``config.settings``, ``core.pgm``), so the LabID_Beta directory itself must be
on sys.path. identity_bound_packages likewise uses flat imports.

Without this, ``pytest`` from the repository root failed with
ModuleNotFoundError and the suites could only be run by cd-ing into a
subdirectory first.
"""

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent

_IMPORT_PATHS = (
    REPOSITORY_ROOT,
    REPOSITORY_ROOT / "LabID_Beta",
    REPOSITORY_ROOT / "identity_bound_packages",
)

for path in _IMPORT_PATHS:
    path_text = str(path)
    if path_text not in sys.path:
        sys.path.insert(0, path_text)
