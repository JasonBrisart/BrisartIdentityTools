"""
verification.py
---------------
Identity factor verification for the Identity-Bound Package BETA prototype.

Currently active factors:  passphrase, voice phrase.
Placeholder factors:       face, fingerprint (template-hash comparison).

*** RESEARCH / DEMO ONLY ***
These are plain equality checks on SHA-256 hashes. They demonstrate the
gate logic only. Real biometric verification needs template protection,
liveness/anti-spoofing, and tolerance-based matching (not exact equality).
"""

from crypto import hash_text


def verify_passphrase(identity, candidate: str) -> bool:
    return identity.passphrase_hash == hash_text(candidate)


def verify_voice(identity, candidate: str) -> bool:
    return identity.voice_hash == hash_text(candidate)


def verify_face(identity, candidate_template: str) -> bool:
    # Placeholder for a future release.
    if identity.face_hash is None:
        return True
    return identity.face_hash == hash_text(candidate_template)


def verify_fingerprint(identity, candidate_template: str) -> bool:
    # Placeholder for a future release.
    if identity.fingerprint_hash is None:
        return True
    return identity.fingerprint_hash == hash_text(candidate_template)


def verify_identity(identity, passphrase: str, voice_phrase: str) -> bool:
    """Require all currently-active factors to pass."""
    return (
        verify_passphrase(identity, passphrase)
        and verify_voice(identity, voice_phrase)
    )
