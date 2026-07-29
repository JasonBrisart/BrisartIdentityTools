"""
identity.py
-----------
Identity model + creation/loading for the Identity-Bound Package
BETA prototype.

An identity stores only *hashes* of its factors (passphrase / voice
phrase), never the raw values. Face and fingerprint fields are left as
optional template-hash placeholders for a future release.

*** RESEARCH / DEMO ONLY ***
Storing factor hashes like this is fine for a workflow demo but is NOT
a secure credential store. A production version needs salted, slow
password hashing (e.g. Argon2/scrypt) and protected biometric templates.
"""

import json
import uuid
from pathlib import Path

from crypto import hash_text

IDENTITY_DIR = Path(__file__).parent / "identities"
IDENTITY_DIR.mkdir(exist_ok=True)


class IdentityProfile:
    def __init__(self, data: dict):
        self.identity_id = data["identity_id"]
        self.name = data["name"]
        self.passphrase_hash = data["passphrase_hash"]
        self.voice_hash = data["voice_hash"]
        # Optional future factors:
        self.face_hash = data.get("face_hash")
        self.fingerprint_hash = data.get("fingerprint_hash")

    @classmethod
    def load(cls, filepath: str) -> "IdentityProfile":
        with open(filepath, "r", encoding="utf-8") as f:
            return cls(json.load(f))


def create_identity(name: str, passphrase: str, voice_phrase: str) -> str:
    """Create an identity file and return its path."""
    identity_id = str(uuid.uuid4())
    profile = {
        "identity_id": identity_id,
        "name": name,
        "passphrase_hash": hash_text(passphrase),
        "voice_hash": hash_text(voice_phrase),
        "face_hash": None,
        "fingerprint_hash": None,
    }

    out = IDENTITY_DIR / f"{identity_id}.identity"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=4)

    print(f"Created identity '{name}'")
    print(f"  ID:   {identity_id}")
    print(f"  File: {out}")
    return str(out)


if __name__ == "__main__":
    name = input("Name: ")
    passphrase = input("Passphrase: ")
    voice = input("Voice phrase: ")
    create_identity(name, passphrase, voice)
