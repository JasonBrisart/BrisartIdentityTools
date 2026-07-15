# IdentityVault

Beta software for local encrypted identity storage.

IdentityVault is a dependency-free Python vault for storing local identity-related records, biometric template references, secrets, notes, and verification metadata.

No cloud services.
No hosted provider.
No third-party Python packages.
No internet required.

Standard-library Python only.

---

## What IdentityVault Covers

IdentityVault is intended to be the storage/security side of BrisartIdentityTools.

It is where identity-related data can be protected locally:

- identity records
- biometric template references
- local credentials
- recovery notes
- access tokens
- certificate notes
- encrypted metadata
- vault manifests
- audit logs

In the broader architecture:

```text
IdentityCore  = verification / biometric processing
IdentityVault = encrypted local storage
```

---

## Status

Beta software.

---

## Quick Start

Initialize a vault:

```bash
python app.py init --vault data/vaults/main_vault.json
```

Add an encrypted record:

```bash
python app.py add --vault data/vaults/main_vault.json --kind secret --label "Lab Door Token" --value "example-token-value"
```

List records:

```bash
python app.py list --vault data/vaults/main_vault.json
```

Read a record:

```bash
python app.py get --vault data/vaults/main_vault.json RECORD_ID
```

Verify vault integrity:

```bash
python app.py verify --vault data/vaults/main_vault.json
```

Export a non-secret manifest:

```bash
python app.py manifest --vault data/vaults/main_vault.json
```

Change the vault password:

```bash
python app.py change-password --vault data/vaults/main_vault.json
```

---

## Repository Layout

```text
IdentityVault/
    app.py
    README.md
    LICENSE
    config/
        settings.py
    core/
        crypto.py
        encoding.py
        ids.py
        time_tools.py
    vault/
        vault_file.py
        vault_service.py
    records/
        record_model.py
    reports/
        audit_log.py
    data/
        vaults/
```

---

## Design Notes

IdentityVault uses Python standard-library primitives:

- `hashlib.pbkdf2_hmac` for password-based key derivation
- `hmac` for authentication tags
- `hashlib.sha256` for deterministic keystream generation
- `secrets` for salts, nonces, and record IDs
- `json` for readable storage format

The vault file is human-inspectable as JSON, but record payloads are encrypted.

---

## Beta Boundary

This is beta software. It is designed for local-first development, offline testing, and BrisartIdentityTools integration work.

