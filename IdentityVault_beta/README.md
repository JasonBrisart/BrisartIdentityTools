# IdentityVault

Local identity record storage for BrisartIdentityTools, encrypted at rest with
BSR2.

IdentityVault stores identity records, notes, metadata, biometric references,
and related information in a single local JSON file. Record **values** are
sealed with authenticated encryption; record **shells** stay readable so the
vault can be listed and audited without unlocking.

No cloud services.

No external infrastructure.

No third-party Python packages.

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

---

## Storage Model

Encryption is [BSR2](https://github.com/JasonBrisart/BrisartSecurityResearch),
vendored byte-identical in `bsr2_vendor/` at the repository root and pinned by
digest. No cryptographic primitive is implemented here.

A vault holds a **keyring**: a random 32-byte master key, sealed once under a
passphrase-derived key and once under an offline recovery code. Record payloads
are encrypted under that master key, never directly under the passphrase.

The shape below is real output from a sealed vault, abbreviated:

```json
{
  "app": "IdentityVault",
  "format_version": 2,
  "storage_mode": "bsr2_sealed",
  "keyring": {
    "format": "brisart-identity-tools/bsr2-keyring/v1",
    "kdf": "BSR2/derive_password_key",
    "iterations": 10000,
    "master_key_check": "...",
    "passphrase": { "salt": "...", "wrapped_master_key": { "algorithm": "BSR2-ARX-SPONGE-ETM", "...": "..." } },
    "recovery":   { "salt": "...", "wrapped_master_key": { "algorithm": "BSR2-ARX-SPONGE-ETM", "...": "..." } }
  },
  "records": {
    "vault_4d146f1b5c6ad2d34a56": {
      "record_id": "vault_4d146f1b5c6ad2d34a56",
      "kind": "identity",
      "label": "CI Record",
      "created_at": "2026-08-04T00:42:53+00:00",
      "updated_at": "2026-08-04T00:42:53+00:00",
      "storage_mode": "bsr2_sealed",
      "sealed_payload": {
        "algorithm": "BSR2-ARX-SPONGE-ETM",
        "ciphertext": "5a109452b1662b15...",
        "nonce": "...",
        "salt": "...",
        "tag": "..."
      }
    }
  }
}
```

`iterations` is recorded in the keyring and **validated on read**, so a tampered
header cannot ask for a cheap derivation. `master_key_check` lets a wrong
passphrase be reported as such instead of surfacing as corrupt records.

Each payload is bound to a context string derived from its record id, kind, and
label, so a ciphertext cannot be moved between records without failing
authentication. Plaintext is padded to 256-byte blocks before sealing, so
ciphertext length does not reveal the exact length of a stored value.

### What is readable while locked

`record_id`, `kind`, `label`, and timestamps — which is what `list` and
`manifest` report, so neither needs a passphrase.

This is a deliberate trade-off. It means the vault discloses that a record
labelled `bank-login` exists while protecting its value. Encrypting labels would
require decrypting every record for any lookup, which would make listing
unusable. If a label is itself sensitive, do not put the secret in the label.

`get` and `verify` do read record values, so both unlock and both pay the KDF
cost — `verify` decrypts every record precisely so that it can prove each one
still authenticates.

---

## Unlock cost

BSR2's password KDF is slow on purpose: roughly **one minute** per derivation,
and about **three minutes** for `init`, which derives both the passphrase and
recovery wrappers. That is the KDF working as intended, not a hang.

Key wrapping is what makes this workable. One derivation unwraps the master key,
and every record operation after that is fast — which is why `verify` can check
an entire vault for the price of a single unlock.

---

## Recovery

`init` prints a recovery code **once**: 40 characters of Crockford base32, 200
bits of entropy. Write it down and store it offline.

- It is a **second full-strength path** to the master key. Anyone holding it has
  the access the passphrase gives.
- It is never stored anywhere, which is why it cannot be shown again.
- **Losing both the passphrase and the recovery code means the vault cannot be
  opened by anyone, including you.** There is no third path, by design.

---

## Quick Start

`--vault` is a **global** option, so it goes before the subcommand.

Initialize a vault (prompts for a passphrase, prints the recovery code):

```bash
python -m IdentityVault_beta.app --vault data/vaults/main_vault.json init
```

Add a record:

```bash
python -m IdentityVault_beta.app --vault data/vaults/main_vault.json add \
  --kind identity \
  --label "Researcher One" \
  --value "example"
```

List records (no passphrase needed):

```bash
python -m IdentityVault_beta.app --vault data/vaults/main_vault.json list
```

Read a record (unlocks, so expect the KDF cost):

```bash
python -m IdentityVault_beta.app --vault data/vaults/main_vault.json get RECORD_ID
```

Delete a record:

```bash
python -m IdentityVault_beta.app --vault data/vaults/main_vault.json delete RECORD_ID
```

Verify integrity (decrypts every record, so it unlocks):

```bash
python -m IdentityVault_beta.app --vault data/vaults/main_vault.json verify
```

Export manifest (no passphrase needed):

```bash
python -m IdentityVault_beta.app --vault data/vaults/main_vault.json manifest
```

### Scripting

`IDENTITY_VAULT_PASSPHRASE` is honoured instead of the interactive prompt:

```bash
IDENTITY_VAULT_PASSPHRASE="..." python -m IdentityVault_beta.app \
  --vault data/vaults/main_vault.json list
```

Convenient and less secret. Environment variables are visible to other processes
running as the same user and frequently end up in shell history and CI logs.
Prefer the prompt for anything real.

---

## Migration

Legacy plaintext vaults still load, and are migrated to sealed storage on the
first write. Reading an old vault does not rewrite it, so a vault stays plaintext
until something changes it.

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

BSR2 is unreviewed research cryptography. Upstream's `SECURITY.md` states it
should not be used as the sole protection for credentials, identity records, or
recovery secrets, and that caveat is inherited here rather than softened. The
full threat model, including what this encryption does not protect against, is in
[`docs/BSR2_INTEGRATION.md`](../docs/BSR2_INTEGRATION.md).
