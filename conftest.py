"""Make the flat repository tree importable no matter where pytest is invoked.

Every subpackage here (biometrics, vault, packages, crypto, common, vendor)
is a namespace package rooted directly at the repository root, and every
internal import is fully qualified from that root (e.g. ``biometrics.config``,
``vault.store.vault_service``, ``crypto.envelope``). That means only the
repository root itself needs to be on sys.path -- there is no longer a
separate tree per tool.
"""
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent

_ROOT_TEXT = str(REPOSITORY_ROOT)
if _ROOT_TEXT not in sys.path:
    sys.path.insert(0, _ROOT_TEXT)
