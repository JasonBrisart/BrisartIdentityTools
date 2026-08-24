# Packages

Identity-Bound Packages: content sealed so that only a specific set of
recipient identities can open it, with a tamper-evident history traveling
inside the package itself. No cloud services, no third-party dependencies —
BSR2 (vendored in `vendor/`) provides the encryption.

---

## How it works

Every package separates the secret that protects the **payload** from the
secrets that protect **access** to that secret:

1. A random 32-byte **content key** seals the actual payload once
   (`packages/ciphers.py`).
2. That content key is itself sealed once per recipient, each under that
   recipient's own master key, in that recipient's own **key slot**.

Adding or removing a recipient only ever touches that recipient's key slot —
the payload is never re-encrypted, and no other recipient's slot is touched.
Losing every recipient's master key makes the package permanently unopenable;
there is no back door.

**Consequence worth knowing up front:** because BSR2 is symmetric and this
project takes no third-party dependencies, there is no public-key mechanism
to seal a payload to a recipient the creator cannot open. Creating a package,
and adding a recipient to an existing one, both require that recipient's
identity to be unlocked at that moment.

### Custody chain vs. audit trail — two different histories

These solve different problems and are easy to conflate:

- **`custody.py`** — a tamper-evident history that travels **inside** the
  package's own state. Every lifecycle event (`created`, `recipient_added`,
  `recipient_removed`, `opened`) commits to the previous event's hash, so
  editing, deleting, or reordering a past entry is detectable by recomputing
  the chain (`verify_chain`). This is integrity evidence, not access
  control, and not a digital signature — an entry's `actor_label` is a
  caller-supplied string, not cryptographically bound to a signing key.
- **`audit.py`** — an external, append-only log written to a separate audit
  directory on disk. Losing or never having the package file at all still
  leaves this trail intact, which is what distinguishes it from the custody
  chain. Never contains content keys, master keys, or sealed payload bytes —
  only package id, action, and actor label.

---

## CLI

```bash
cd packages

# Create a package with one initial recipient. --payload is a JSON object string.
python main.py create pkg.json --package-id demo-1 \
  --identity-id alice --label "Alice" --payload '{"message": "hello"}'

# Add a recipient (requires an existing, authorized recipient to authorize it)
python main.py add-recipient pkg.json --identity-id bob --label "Bob" \
  --opener-identity-id alice

# Remove a recipient (cannot remove the last one)
python main.py remove-recipient pkg.json --identity-id bob --opener-identity-id alice

# Open the payload as an authorized recipient
python main.py open pkg.json --identity-id alice

python main.py list-recipients pkg.json
python main.py verify-custody pkg.json

# Full create -> add-recipient -> open cycle with generated keys, no setup required
python main.py demo
```

Every command that touches a master key prompts for it via `getpass` (any
text you type is stretched to a fixed-length key for demo purposes — a real
integration should supply an actual 32-byte master key, e.g. one unlocked
from `crypto.keyring.Keyring`, instead of typed text).

---

## Repository Layout

```
packages/
├── main.py            CLI entry point
├── package.py          orchestration: create, add/remove recipient, open, validate
├── ciphers.py          content-key generation, per-recipient key-slot seal/unwrap
├── identity.py         recipient descriptor shape/validation (id + label, no key material)
├── verification.py     fast "does this master key belong to this recipient" check
├── custody.py          in-package tamper-evident hash chain
├── audit.py            external, append-only audit trail
└── tests/
```

---

## Security notes

- Package validation runs cheap structural checks (format, custody chain,
  recipient/key-slot consistency) **before** expensive factor verification,
  so a tampered package is rejected without paying for a key derivation.
- Digest and MAC comparisons throughout use constant-time equality.
- Malformed input (a truncated custody chain, a missing signed field) is
  reported as a validation failure rather than crashing with a raw
  `KeyError`/`TypeError` — see `docs/CHANGELOG.md` for the specific
  hardening passes this went through.

Full threat model, including what encryption here does and does not protect
against: [docs/BSR2_INTEGRATION.md](../docs/BSR2_INTEGRATION.md).
