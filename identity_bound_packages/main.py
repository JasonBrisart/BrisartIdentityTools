"""
main.py
-------
Command-line entry point for the Identity-Bound Package (IBP) BETA.

*** RESEARCH / DEMO ONLY ***
This is a workflow / architecture prototype focused on identity-based
authorization, integrity checking, custody tracking, and audit logging.

The payload and the per-recipient content-key wrapping are encrypted with
vendored BSR2 (see ``package.py`` and ``crypto.py``). The parts that remain
prototype-grade are stated plainly rather than hidden: ``signature`` is a
shared-secret hash, not a real digital signature, and creating an encrypted
package requires every recipient's identity to be unlocked at creation time
because BSR2 is symmetric-only. See ``package.py``'s module docstring for
both.

Unlocking an identity by passphrase runs BSR2's deliberately slow key
derivation (on the order of a minute or more). ``new-identity`` and ``open``
both pay that cost; that is expected, not a hang.

Usage:
    python main.py new-identity
    python main.py new-package
    python main.py transfer
    python main.py open
    python main.py demo          # runs an end-to-end example
"""

import sys

from identity import IdentityProfile, create_identity
from package import create_package, open_package, transfer_package


def cmd_new_identity():
    name = input("Name: ")
    passphrase = input("Passphrase: ")
    voice = input("Voice phrase: ")

    print("\nDeriving keys with BSR2. This takes several minutes.\n")
    path, recovery_code = create_identity(name, passphrase, voice)

    print(f"Created identity '{name}'")
    print(f"  File: {path}")
    print("\n  RECOVERY CODE (write this down, it is shown only once):")
    print(f"    {recovery_code}")
    print(
        "\n  Without the passphrase or this recovery code, the identity "
        "cannot be opened by anyone, including you."
    )


def cmd_new_package():
    recips = input("Recipient identity IDs (comma-separated): ")
    recipients = [r.strip() for r in recips.split(",") if r.strip()]
    mode = (input("Policy mode [ANY/ALL/THRESHOLD] (default ANY): ")
            or "ANY").upper()
    required = 1
    if mode == "THRESHOLD":
        required = int(input("Required approvals: "))
    message = input("Message to seal: ")

    # A symmetric scheme cannot wrap the content key to an identity the creator
    # cannot open, so every recipient must be unlocked here. See package.py.
    print(
        f"\nEach of the {len(recipients)} recipient identities must be "
        "unlocked to receive a key slot."
    )
    unlocked = []
    for recipient_id in recipients:
        identity_file = input(f"  Identity file for {recipient_id}: ")
        passphrase = input(f"  Passphrase for {recipient_id}: ")
        identity = IdentityProfile.load(identity_file)
        if identity.identity_id != recipient_id:
            print(
                f"\n[ABORTED] {identity_file} is identity "
                f"{identity.identity_id}, not {recipient_id}."
            )
            return
        print("  Unlocking with BSR2; this takes a while.")
        try:
            identity.unlock(passphrase)
        except Exception as exc:
            print(f"\n[ABORTED] could not unlock {recipient_id}: {exc}")
            return
        unlocked.append(identity)

    create_package(recipients, message, actor="creator",
                   location="origin", mode=mode, required=required,
                   unlocked_identities=unlocked)


def cmd_transfer():
    path = input("Package file (.ibp): ")
    actor = input("Handed to (actor): ")
    location = input("New location: ")
    transfer_package(path, actor, location)


def cmd_open():
    path = input("Package file (.ibp): ")
    identity_file = input("Identity file (.identity): ")
    passphrase = input("Passphrase: ")
    voice = input("Voice phrase: ")

    identity = IdentityProfile.load(identity_file)

    try:
        content = open_package(path, identity, passphrase, voice)
    except Exception as e:
        print(f"\n[DENIED] {e}")
        return

    print("\n=== PACKAGE CONTENT ===")
    print(content)
    print("=======================")


def cmd_demo():
    """End-to-end example so you can see the whole flow work at once.

    Slow: creating and opening an identity each run BSR2's passphrase
    derivation, so expect this to take several minutes rather than seconds.
    """
    passphrase = "archive-omega"
    voice = "knowledge survives"

    print(">> Creating identity 'Jason'... (BSR2 derivation, several minutes)")
    id_path, recovery_code = create_identity(
        "Jason Brisart", passphrase, voice
    )
    identity = IdentityProfile.load(id_path)
    print(f"   Recovery code (shown once): {recovery_code}")

    print("\n>> Unlocking Jason to receive a key slot...")
    identity.unlock(passphrase)

    print("\n>> Creating an encrypted package bound to Jason...")
    pkg_path = create_package(
        [identity.identity_id],
        "This message is bound to an identity, not a location.",
        actor="Jason", location="Research Lab",
        unlocked_identities=[identity],
    )

    print("\n>> Recording a transfer...")
    transfer_package(pkg_path, actor="Courier", location="Vault-02")

    print("\n>> Opening with correct factors...")
    content = open_package(pkg_path, identity, passphrase, voice)
    print(f"   OPENED -> {content}")

    print("\n>> Attempting open with WRONG passphrase...")
    try:
        open_package(pkg_path, identity, "wrong-pass", voice)
    except Exception as e:
        print(f"   DENIED -> {e}")

    print("\nDemo complete. See logs/audit.log for the audit trail.")


COMMANDS = {
    "new-identity": cmd_new_identity,
    "new-package": cmd_new_package,
    "transfer": cmd_transfer,
    "open": cmd_open,
    "demo": cmd_demo,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        return
    COMMANDS[sys.argv[1]]()


if __name__ == "__main__":
    main()
