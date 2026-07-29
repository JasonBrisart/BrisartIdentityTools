"""
main.py
-------
Command-line entry point for the Identity-Bound Package (IBP) BETA.

*** RESEARCH / DEMO ONLY ***
This is a workflow / architecture prototype focused on identity-based
authorization, integrity checking, custody tracking, and audit logging.
It does NOT provide encryption. Use a dedicated security framework
(e.g. BSR2 from BrisartSecurityResearch) if confidentiality is required.

Usage:
    python main.py new-identity
    python main.py new-package
    python main.py transfer
    python main.py open
    python main.py demo          # runs an end-to-end example
"""

import sys

from identity import create_identity, IdentityProfile
from package import create_package, transfer_package, open_package


def cmd_new_identity():
    name = input("Name: ")
    passphrase = input("Passphrase: ")
    voice = input("Voice phrase: ")
    create_identity(name, passphrase, voice)


def cmd_new_package():
    recips = input("Recipient identity IDs (comma-separated): ")
    recipients = [r.strip() for r in recips.split(",") if r.strip()]
    mode = (input("Policy mode [ANY/ALL/THRESHOLD] (default ANY): ")
            or "ANY").upper()
    required = 1
    if mode == "THRESHOLD":
        required = int(input("Required approvals: "))
    message = input("Message to seal: ")
    create_package(recipients, message, actor="creator",
                   location="origin", mode=mode, required=required)


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
    """End-to-end example so you can see the whole flow work at once."""
    print(">> Creating identity 'Jason'...")
    id_path = create_identity("Jason Brisart", "archive-omega",
                              "knowledge survives")
    identity = IdentityProfile.load(id_path)

    print("\n>> Creating a package bound to Jason...")
    pkg_path = create_package(
        [identity.identity_id],
        "This message is bound to an identity, not a location.",
        actor="Jason", location="Research Lab",
    )

    print("\n>> Recording a transfer...")
    transfer_package(pkg_path, actor="Courier", location="Vault-02")

    print("\n>> Opening with correct factors...")
    content = open_package(pkg_path, identity, "archive-omega",
                           "knowledge survives")
    print(f"   OPENED -> {content}")

    print("\n>> Attempting open with WRONG passphrase...")
    try:
        open_package(pkg_path, identity, "wrong-pass", "knowledge survives")
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
