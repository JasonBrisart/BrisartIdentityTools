"""Import shim for the vendored BSR2 modules.

The vendored files use flat imports of each other (``from
brisart_security_primitives import ...``), exactly as they do upstream. Editing
them into package-relative imports would fork the vendored code and break the
integrity check, so instead ``bsr2_vendor/`` is placed on ``sys.path`` once here
and every consumer imports through this module.

Keeping the path manipulation in one file means there is a single place to audit,
rather than a scattering of ``sys.path`` edits across the codebase.
"""

import sys
from pathlib import Path

_VENDOR_DIR = Path(__file__).resolve().parent.parent / "bsr2_vendor"

if not _VENDOR_DIR.is_dir():
    raise ImportError(
        f"vendored BSR2 directory is missing: {_VENDOR_DIR}. "
        "See bsr2_vendor/README.md for how to restore it."
    )

_VENDOR_PATH = str(_VENDOR_DIR)

if _VENDOR_PATH not in sys.path:
    sys.path.insert(0, _VENDOR_PATH)

from brisart_security_drbg import (  # noqa: E402
    MAX_BYTES_BEFORE_RESEED,
    MAX_REQUEST_BYTES,
    MINIMUM_PERSONALIZATION_BYTES,
    MINIMUM_SEED_BYTES,
    RESEED_INTERVAL,
    BrisartDRBG,
    BrisartDRBGError,
)
from brisart_security_entropy import (  # noqa: E402
    BrisartEntropyError,
    system_entropy,
)
from brisart_security_envelope import (  # noqa: E402
    ALGORITHM,
    MAX_CONTEXT_BYTES,
    MAX_PLAINTEXT_BYTES,
    NONCE_BYTES,
    SALT_BYTES,
    TAG_BYTES,
    VERSION,
    BrisartEnvelopeError,
    decrypt,
    encrypt,
)
from brisart_security_primitives import (  # noqa: E402
    BrisartPrimitiveError,
    constant_time_equal,
    derive_password_key,
    derive_subkey,
    frame,
    hex_decode,
    hex_encode,
    keyed_mac,
    sponge_hash,
    stream_bytes,
    xor_bytes,
)

__all__ = [
    "ALGORITHM",
    "MAX_BYTES_BEFORE_RESEED",
    "MAX_CONTEXT_BYTES",
    "MAX_PLAINTEXT_BYTES",
    "MAX_REQUEST_BYTES",
    "MINIMUM_PERSONALIZATION_BYTES",
    "MINIMUM_SEED_BYTES",
    "NONCE_BYTES",
    "RESEED_INTERVAL",
    "SALT_BYTES",
    "TAG_BYTES",
    "VERSION",
    "BrisartDRBG",
    "BrisartDRBGError",
    "BrisartEntropyError",
    "BrisartEnvelopeError",
    "BrisartPrimitiveError",
    "constant_time_equal",
    "decrypt",
    "derive_password_key",
    "derive_subkey",
    "encrypt",
    "frame",
    "hex_decode",
    "hex_encode",
    "keyed_mac",
    "sponge_hash",
    "stream_bytes",
    "system_entropy",
    "xor_bytes",
]
