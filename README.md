# BrisartIdentityTools

Local-first identity, authentication, and verification tools for offline and air-gapped environments.

No cloud services.
No hosted infrastructure.
No vendor lock-in.
Just Python.

---

## Why This Exists

Modern identity systems are often built around external providers:

- Cloud authentication
- Third-party identity services
- Hosted login systems
- Subscription-based security platforms
- Continuous internet connectivity

BrisartIdentityTools explores a different approach.

The goal is simple:

> If identity matters, you should be able to manage and verify it yourself.

This repository focuses on local-first, transparent, and auditable identity workflows designed for environments that prioritize ownership, control, and long-term accessibility.

---

## Design Principles

### Local First
Identity should function without requiring external services.

### Offline Capable
Systems should remain usable in disconnected and air-gapped environments.

### Human Readable
Identity records and configuration should be understandable by humans.

### Source Available
Users should be able to inspect how verification occurs.

### Audit Friendly
Verification logic should be transparent and reviewable.

### Long-Term Maintainability
Identity systems should remain understandable years from now.

---

## What Is An Identity?

For this project, an identity can represent:

- A researcher
- A developer
- A laboratory member
- An archivist
- A workstation
- A server
- A device
- A removable media token

Identity is intentionally broader than just people.

---

## The Three Tools

| Tool | What it does |
| --- | --- |
| **Vault** (`vault/`) | An encrypted, local, single-file record store. Record values are sealed; record shells stay readable so the vault lists without unlocking. Also seals arbitrary files, folders, and drives. |
| **Biometrics** (`biometrics/`) | Local multimodal biometric enrollment and verification (voice / fingerprint / video), with sealed templates and arbitrary file attachments. |
| **Packages** (`packages/`) | Identity-Bound Packages: content sealed so only a specific set of recipient identities can open it, with a tamper-evident custody chain. |

All three share a common utility layer (`common/`), a BSR2 integration layer
(`crypto/`), vendored BSR2 primitives (`vendor/`), and a modular Tkinter desktop GUI.
The GUI entry point is the root-level `app.py`; its reusable implementation is split
across `gui/core/`, `gui/widgets/`, and `gui/tabs/`. The command-line tools remain
available through the unified dispatcher in `cli.py`.


---

## Desktop GUI Architecture

The desktop interface is no longer maintained as one large GUI module. Version
1.2.0 keeps the executable shell small and separates the interface by
responsibility:

```text
app.py
└── gui/
    ├── core/
    │   ├── constants.py
    │   └── busy.py
    ├── widgets/
    │   ├── dialogs.py
    │   └── path_panel.py
    └── tabs/
        ├── tab_vault.py
        ├── tab_biometrics.py
        └── tab_packages.py
```

- `app.py` creates the main window, assembles the three tabs, builds the menu,
  and provides `main()`.
- `gui/core/constants.py` owns shared GUI constants, file-type filters, and the
  repository-root import bootstrap.
- `gui/core/busy.py` owns the modal busy dialog and background-operation runner.
- `gui/widgets/` contains reusable dialogs and path-selection controls.
- `gui/tabs/` contains one module for each application area.

The GUI remains a presentation layer. Cryptography, validation, storage, and
identity rules remain in the existing Vault, Biometrics, Packages, Crypto, and
Common application modules.

Run it from the repository root:

```bash
python app.py
```

---

## Quick Start

Python 3.10 or newer. No third-party dependencies.

The floor is 3.10 rather than 3.9 because vendored BSR2 uses `int | None`
annotations that Python evaluates at import time. Patching the vendored file
would break byte-identical vendoring, so the floor moved instead.

```bash
git clone https://github.com/JasonBrisart/BrisartIdentityTools.git
cd BrisartIdentityTools