"""BSR2 factor protection, split by the entropy of the input.

This replaces the unsalted single-pass SHA-256 previously used for every factor
hash. That construction had two concrete problems: identical factors produced
identical digests, so stored values revealed which identities shared a
passphrase and one precomputed table cracked all of them at once; and a single
SHA-256 runs billions of times per second on a GPU, so any factor drawn from a
realistic wordlist fell immediately.

Both are fixed here, but not by the same mechanism, because the factors are not
the same kind of secret.

**Low-entropy secrets** (a human-chosen passphrase or spoken phrase) are
guessable by construction. They need a deliberately expensive derivation so that
each guess costs real time. :func:`hash_factor` uses BSR2's
``derive_password_key`` for this. It is slow on purpose: roughly 70 seconds per
call at BSR2's enforced minimum of 10,000 iterations.

**High-entropy secrets** (biometric template digests, signature blobs, device
identifiers) are not guessable, so stretching them buys nothing. What they need
is a *keyed* digest, so that stealing the stored file does not let an attacker
confirm a candidate template offline. :func:`bind_factor` uses
``derive_subkey`` plus ``keyed_mac`` for this, at roughly 15 milliseconds.

Why the split matters in practice: an identity-bound package verifies several
factors. Running the expensive KDF on all of them would cost minutes per package
open and hours across the test suite, while adding no security for the inputs
that already carry far more entropy than the KDF contributes. Applying an
expensive KDF to a high-entropy input is cost without benefit; applying a fast
MAC to a low-entropy one is a real weakness. Each factor gets the treatment its
entropy actually calls for.

Both paths use only vendored BSR2 primitives.

Encoded forms::

    bsr2$derive_password_key$iterations=10000$<hex salt>$<hex digest>
    bsr2$keyed_mac$<factor name>$<hex digest>
"""
from brisart_bsr2.errors import Bsr2IntegrationError
from brisart_bsr2.vendor import (
    BrisartPrimitiveError,
    constant_time_equal,
    derive_password_key,
    derive_subkey,
    frame,
    hex_decode,
    hex_encode,
    keyed_mac,
    system_entropy,
)

PREFIX = "bsr2"
KDF_ALGORITHM = "derive_password_key"
MAC_ALGORITHM = "keyed_mac"
SALT_BYTES = 32
DIGEST_BYTES = 32
ITERATIONS = 10_000
MINIMUM_ITERATIONS = 10_000
# Legitimate factor hashes use 10,000 (the BSR2 floor) up to a few times BSR2's
# 120,000 default. This ceiling sits far above any real setting yet bounds the
# work a tampered hash can demand: without it, a stored value carrying e.g.
# iterations=100_000_000_000 makes verify_factor run the KDF for years before
# the digest can even mismatch. An over-large count is treated as malformed.
MAXIMUM_ITERATIONS = 1_000_000
_KDF_FIELD_COUNT = 5
_MAC_FIELD_COUNT = 4


# --------------------------------------------------------------------------
# Low-entropy secrets: expensive derivation
# --------------------------------------------------------------------------
def hash_factor(secret: str, iterations: int = ITERATIONS) -> str:
    """Hash a low-entropy secret with a fresh random salt.

    Use for human-chosen passphrases and spoken phrases only. Expensive by
    design; see the module docstring for why that cost is the point here and
    wasted elsewhere.
    """
    if not isinstance(secret, str) or not secret:
        raise Bsr2IntegrationError("factor secret must be a non-empty string.")
    if type(iterations) is not int:
        raise Bsr2IntegrationError("iterations must be an integer.")
    if iterations < MINIMUM_ITERATIONS:
        raise Bsr2IntegrationError(
            f"iteration count is below the {MINIMUM_ITERATIONS} minimum."
        )
    if iterations > MAXIMUM_ITERATIONS:
        raise Bsr2IntegrationError(
            f"iteration count is above the {MAXIMUM_ITERATIONS} maximum."
        )
    salt = system_entropy(SALT_BYTES)
    digest = derive_password_key(
        secret, salt, iterations=iterations, output_bytes=DIGEST_BYTES
    )
    return "$".join(
        (
            PREFIX,
            KDF_ALGORITHM,
            f"iterations={iterations}",
            hex_encode(salt),
            hex_encode(digest),
        )
    )


def _parse_kdf(encoded: str) -> dict:
    if not isinstance(encoded, str):
        raise Bsr2IntegrationError("factor hash must be a string.")
    fields = encoded.split("$")
    if len(fields) != _KDF_FIELD_COUNT:
        raise Bsr2IntegrationError("factor hash is malformed.")
    prefix, algorithm, parameter_text, salt_text, digest_text = fields
    if prefix != PREFIX:
        raise Bsr2IntegrationError("factor hash is not a BSR2 factor hash.")
    if algorithm != KDF_ALGORITHM:
        raise Bsr2IntegrationError(
            f"unsupported factor hash algorithm: {algorithm!r}"
        )
    if not parameter_text.startswith("iterations="):
        raise Bsr2IntegrationError("factor hash parameters are malformed.")
    try:
        iterations = int(parameter_text[len("iterations="):])
    except ValueError as exc:
        raise Bsr2IntegrationError(
            "factor hash iteration count is not an integer."
        ) from exc
    if iterations < MINIMUM_ITERATIONS:
        # A tampered hash string could otherwise request a cheap verification.
        raise Bsr2IntegrationError(
            "factor hash iteration count is below the supported minimum."
        )
    if iterations > MAXIMUM_ITERATIONS:
        # The opposite tamper: an astronomical count that makes verify_factor
        # run the KDF for years before the digest can mismatch.
        raise Bsr2IntegrationError(
            "factor hash iteration count is above the supported maximum."
        )
    try:
        salt = hex_decode(salt_text)
        digest = hex_decode(digest_text)
    except BrisartPrimitiveError as exc:
        raise Bsr2IntegrationError("factor hash encoding is invalid.") from exc
    if len(salt) != SALT_BYTES:
        raise Bsr2IntegrationError("factor hash salt has an invalid length.")
    if len(digest) != DIGEST_BYTES:
        raise Bsr2IntegrationError("factor hash digest has an invalid length.")
    return {"iterations": iterations, "salt": salt, "digest": digest}


def verify_factor(secret, encoded: str) -> bool:
    """Check a low-entropy secret against an encoded hash, in constant time.

    Returns ``False`` for malformed input rather than raising, so a corrupted
    stored hash reads as "does not verify" instead of crashing an auth path.
    """
    if not isinstance(secret, str) or not secret:
        return False
    try:
        parsed = _parse_kdf(encoded)
    except Bsr2IntegrationError:
        return False
    try:
        calculated = derive_password_key(
            secret,
            parsed["salt"],
            iterations=parsed["iterations"],
            output_bytes=DIGEST_BYTES,
        )
    except BrisartPrimitiveError:
        return False
    return constant_time_equal(calculated, parsed["digest"])


# --------------------------------------------------------------------------
# High-entropy secrets: keyed digest under the master key
# --------------------------------------------------------------------------
def _factor_mac(master_key: bytes, factor_name: str, value: str) -> bytes:
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) < 32:
        raise Bsr2IntegrationError("master key must be at least 32 bytes.")
    if not isinstance(factor_name, str) or not factor_name:
        raise Bsr2IntegrationError("factor name must be a non-empty string.")
    if "$" in factor_name:
        # The encoded form is dollar-delimited, so a name containing one would
        # make the record ambiguous to parse.
        raise Bsr2IntegrationError("factor name cannot contain '$'.")
    if not isinstance(value, str):
        raise Bsr2IntegrationError("factor value must be a string.")
    # A distinct subkey per factor name means a template bound as "face" cannot
    # be replayed into the "fingerprint" slot.
    subkey = derive_subkey(
        bytes(master_key),
        factor_name.encode("utf-8"),
        b"BrisartIdentityTools/factor/v1",
        32,
    )
    # Framed so that the name and value cannot be shifted across the boundary
    # between them to produce a colliding MAC input.
    message = frame(factor_name.encode("utf-8")) + frame(value.encode("utf-8"))
    return keyed_mac(subkey, message, DIGEST_BYTES)


def bind_factor(master_key: bytes, factor_name: str, value: str) -> str:
    """Bind a high-entropy factor value under the master key.

    Use for biometric template digests, signature blobs, and device
    identifiers. Fast, and keyed, so the stored record cannot be tested against
    candidate values without the master key.
    """
    digest = _factor_mac(master_key, factor_name, value)
    return "$".join((PREFIX, MAC_ALGORITHM, factor_name, hex_encode(digest)))


def _parse_mac(encoded: str) -> dict:
    if not isinstance(encoded, str):
        raise Bsr2IntegrationError("bound factor must be a string.")
    fields = encoded.split("$")
    if len(fields) != _MAC_FIELD_COUNT:
        raise Bsr2IntegrationError("bound factor is malformed.")
    prefix, algorithm, factor_name, digest_text = fields
    if prefix != PREFIX:
        raise Bsr2IntegrationError("bound factor is not a BSR2 record.")
    if algorithm != MAC_ALGORITHM:
        raise Bsr2IntegrationError(
            f"unsupported bound factor algorithm: {algorithm!r}"
        )
    if not factor_name:
        raise Bsr2IntegrationError("bound factor name is empty.")
    try:
        digest = hex_decode(digest_text)
    except BrisartPrimitiveError as exc:
        raise Bsr2IntegrationError("bound factor encoding is invalid.") from exc
    if len(digest) != DIGEST_BYTES:
        raise Bsr2IntegrationError("bound factor digest has an invalid length.")
    return {"factor_name": factor_name, "digest": digest}


def verify_bound_factor(
    master_key: bytes, factor_name: str, value, encoded: str
) -> bool:
    """Check a high-entropy factor value against a bound record.

    The stored record's factor name must match the one supplied, so a record
    cannot be moved between factor slots even by an attacker who can edit the
    file.
    """
    if not isinstance(value, str):
        return False
    try:
        parsed = _parse_mac(encoded)
    except Bsr2IntegrationError:
        return False
    if not constant_time_equal(
        parsed["factor_name"].encode("utf-8"), factor_name.encode("utf-8")
    ):
        return False
    try:
        calculated = _factor_mac(master_key, factor_name, value)
    except (Bsr2IntegrationError, BrisartPrimitiveError):
        return False
    return constant_time_equal(calculated, parsed["digest"])


# --------------------------------------------------------------------------
# Inspection
# --------------------------------------------------------------------------
def is_factor_hash(value) -> bool:
    """Report whether ``value`` is a BSR2 KDF factor hash."""
    if not isinstance(value, str):
        return False
    try:
        _parse_kdf(value)
    except Bsr2IntegrationError:
        return False
    return True


def is_bound_factor(value) -> bool:
    """Report whether ``value`` is a BSR2 keyed factor record."""
    if not isinstance(value, str):
        return False
    try:
        _parse_mac(value)
    except Bsr2IntegrationError:
        return False
    return True


def is_legacy_digest(value) -> bool:
    """Report whether ``value`` looks like a bare legacy SHA-256 hex digest.

    Used by migration code to identify records written before BSR2, which are
    64 hex characters with no algorithm marker.
    """
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(character in "0123456789abcdefABCDEF" for character in value)


def needs_rehash(encoded: str) -> bool:
    """Report whether a stored KDF hash is weaker than this build now produces."""
    try:
        parsed = _parse_kdf(encoded)
    except Bsr2IntegrationError:
        return True
    return parsed["iterations"] < ITERATIONS


__all__ = [
    "DIGEST_BYTES",
    "ITERATIONS",
    "MINIMUM_ITERATIONS",
    "MAXIMUM_ITERATIONS",
    "bind_factor",
    "hash_factor",
    "is_bound_factor",
    "is_factor_hash",
    "is_legacy_digest",
    "needs_rehash",
    "verify_bound_