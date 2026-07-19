# IdentityVault

Plaintext local identity record storage for BrisartIdentityTools.

IdentityVault stores identity records, notes, metadata, biometric references,
and related information as readable JSON files.

No cloud services.

No external infrastructure.

No third-party Python packages.

No encryption layer.

Standard-library Python only.

---

## Purpose

IdentityVault is intended to provide:

- local identity records
- biometric template references
- verification metadata
- audit logging
- manifests
- local record management

IdentityVault is currently a plaintext JSON storage system.

Encryption is not performed inside this repository.

Future Brisart applications may instead rely on BSR2 from
BrisartSecurityResearch when encryption is required.

---

## Current Storage Model

Records are stored directly inside JSON files.

Example:

```json
{
  "record_id": "vault_123456",
  "kind": "identity",
  "label": "Researcher One",
  "payload": {
    "value": "example record",
    "notes": "",
    "metadata": {}
  }
}
```

Files are human-readable and auditable.

---

## Storage Modes

Current mode:

```text
plaintext_json_beta
```

No encryption.

No password protection.

No ciphertext.

No cryptographic tags.

---

## Quick Start

Initialize a vault:

```bash
python app.py init \
--vault data/vaults/main_vault.json
```

Add a record:

```bash
python app.py add \
--vault data/vaults/main_vault.json \
--kind identity \
--label "Researcher One" \
--value "example"
```

List records:

```bash
python app.py list \
--vault data/vaults/main_vault.json
```

Read a record:

```bash
python app.py get \
--vault data/vaults/main_vault.json \
RECORD_ID
```

Verify structure:

```bash
python app.py verify \
--vault data/vaults/main_vault.json
```

Export manifest:

```bash
python app.py manifest \
--vault data/vaults/main_vault.json
```

---

## Repository Layout

```text
IdentityVault_beta/
├── app.py
├── config/
│   └── settings.py
├── core/
│   ├── ids.py
│   └── time_tools.py
├── records/
│   └── record_model.py
├── reports/
│   └── audit_log.py
├── vault/
│   ├── vault_file.py
│   └── vault_service.py
└── README.md
```

---

## Status

Beta software.

IdentityVault currently focuses on readable
local-first record storage.

Security functionality, when required,
is expected to come from dedicated security tooling
rather than being embedded directly into this repository.