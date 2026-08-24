# Vault

Local identity record storage for BrisartIdentityTools, encrypted at rest with
BSR2.

Vault stores identity records, notes, metadata, biometric references, and
related information in a single local JSON file. Record **values** are sealed
with authenticated encryption; record **shells** stay readable so the vault
can be listed without unlocking.

No cloud services.
No external infrastructure.
No third-party Python packages.
Standard-library Python only.

---

## Purpose

Vault is intended to provide:

- local identity records
- biometric template references
- verification metadata
- audit logging
- local record management

---

## Storage Model

Encryption is [BSR2](https://github.com/JasonBrisart/BrisartSecurityResearch),
vendored byte-identical in `vendor/` at the repository root. No cryptographic
primitive is implemented here.

> **Note:** the digest-pin test that used to verify `vendor/` is byte-identical
> to upstream (`tests/test_bsr2_vendor_integrity.py`) was dropped during the
> 1.0.0 restructure and has not yet been recreated. Until it is, an accidental
> edit to `vendor/` will not be caught by CI. See `vendor/README.md` and
> `docs/BSR2_INTEGRATION.md`.

A vault holds a **keyring**: a random 32-byte master key, sealed once under a
passphrase-derived key and once under an offline recovery code. Record payloads
are encrypted under that master key, never directly under the passphrase.

The shape below is real output from a sealed vault, abbreviated:

```json
{
  "format": "brisart-identity-tools/vault-file/v1",
  "keyring": {
    "format": "brisart-identity-tools/bsr2-keyring/v1",
    "kdf": "BSR2/derive_password_key",
    "iterations": 10000,
    "master_key_check": "...",
    "passphrase": { "salt": "...", "wrapped_master_key": { "algorithm": "BSR2-ARX-SPONGE-ETM", "...": "..." } },
    "recovery":   { "salt": "...", "wrapped_master_key": { "algorithm": "BSR2-ARX-SPONGE-ETM", "...": "..." } }
  },
  "records": {
    "a1b2c3d4e5f6...": {
      "format": "brisart-identity-tools/vault-record/v1",
      "record_id": "a1b2c3d4e5f6...",
      "kind": "identity",
      "label": "CI Record",
      "created_at": "2026-08-04T00:42:53+00:00",
      "updated_at": "2026-08-04T00:42:53+00:00",
      "payload": {
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

`iterations` is recorded in the keyring and **validated on read**, so a
tampered header cannot ask for a cheap derivation. `master_key_check` lets a
wrong passphrase be reported as such instead of surfacing as corrupt records.

Each payload is bound to a context string derived from its record id, kind, and
label, so a ciphertext cannot be moved between records without failing
authentication. Plaintext is padded to 256-byte blocks before sealing, so
ciphertext length does not reveal the exact length of a stored value.

Files, folders, and whole drives can also be sealed into the vault as file
records and chunked bundles (any size), via the `encrypt-file` / `encrypt-paths`
CLI commands or the GUI's "Files / Folders / Drives" tab. See
[docs/README_FULL_FILE_ENCRYPTION.md](../docs/README_FULL_FILE_ENCRYPTION.md).

### What is readable while locked

`record_id`, `kind`, `label`, and timestamps — which is what `list` reports,
so it does not need a passphrase.

This is a deliberate trade-off. It means the vault discloses that a record
labelled `bank-login` exists while protecting its value. Encrypting labels would
require decrypting every record for any lookup, which would make listing
unusable. If a label is itself sensitive, do not put the secret in the label.

`get` does read a record's value, so it unlocks and pays the KDF cost.

### Unlock cost

BSR2's password KDF is slow on purpose: roughly **one minute** per derivation.
`init` derives both the passphrase and recovery wrappers, so it costs about
twice that. That is the KDF working as intended, not a hang.

Key wrapping is what makes this workable. One derivation unwraps the master key,
and every record operation after that is fast.

### Recovery

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
python -m vault.app --vault data/vaults/main_vault.json init
```

Create or update a record:

```bash
python -m vault.app --vault data/vaults/main_vault.json upsert \
  "Researcher One" --kind identity --payload '{"value": "example"}'
```

Re-running `upsert` with the same `--record-id` updates that record's payload
in place instead of creating a new one; omitting `--record-id` always creates
a new record.

List records (no passphrase needed):

```bash
python -m vault.app --vault data/vaults/main_vault.json list
```

Read a record (unlocks, so expect the KDF cost):

```bash
python -m vault.app --vault data/vaults/main_vault.json get RECORD_ID
```

Delete a record:

```bash
python -m vault.app --vault data/vaults/main_vault.json delete RECORD_ID
```

Batch-create or update many records from a JSON array file in one pass (one
save instead of one per item):

```bash
python -m vault.app --vault data/vaults/main_vault.json batch-upsert items.json
```

All commands are also reachable via the repo-root dispatcher, e.g.
`python cli.py vault --vault data/vaults/main_vault.json list`.

### Scripting

`vault/app.py` always prompts for the passphrase via `getpass`, and there is
currently no environment-variable bypass built into the CLI. `getpass` falls
back to a plain stdin read (with a warning) when stdin isn't a terminal, so
piping the passphrase in works for non-interactive use:

```bash
printf 'my-passphrase\n' | python -m vault.app --vault data/vaults/main_vault.json list
```

Piped input lands in shell history and process listings just like an
environment variable would; prefer the interactive prompt for anything real.

### Repository Layout

```text
vault/
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
├── store/
│   ├── bulk_file_service.py
│   ├── vault_file.py
│   └── vault_service.py
├── tests/
└── README.md
```

## Status

Part of the 1.0.0 production/stable release. Stored formats are stable; vaults
written by earlier betas load unchanged.

BSR2 itself is unreviewed research cryptography. Upstream's `SECURITY.md` states
it should not be used as the sole protection for credentials, identity records,
or recovery secrets, and that caveat is inherited here rather than softened. The
full threat model, including what this encryption does not protect against, is
in [docs/BSR2_INTEGRATION.md](../docs/BSR2_INTEGRATION.md).
