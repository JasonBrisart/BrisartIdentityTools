# BSR2 Integration and Threat Model

This document records how BrisartIdentityTools uses BSR2, what each protection
actually buys, and where the boundaries are. It is the reference an auditor
should read before trusting any claim made elsewhere in the repository.

## What is vendored, and why

The cryptography is [BSR2](https://github.com/JasonBrisart/BrisartSecurityResearch)
(Brisart Security Research, scheme 2), vendored **unmodified** in `vendor/`:

| File | Role |
| --- | --- |
| `brisart_security_primitives.py` | Sponge hash, keyed MAC, subkey derivation, password KDF, constant-time compare, hex, framing |
| `brisart_security_envelope.py` | Authenticated encryption (`BSR2-ARX-SPONGE-ETM`) |
| `brisart_security_drbg.py` | Deterministic random bit generator |
| `brisart_security_entropy.py` | Operating-system entropy collection |

No cryptographic primitive is implemented in this repository. `crypto/` is
an integration layer only.

Vendored rather than depended on, for three reasons: the repository's
zero-dependency rule is absolute, the vendored files are standard-library only
so vendoring costs nothing, and pinning the exact bytes means an upstream change
cannot silently alter what this repository ships.

The files are byte-identical to a pinned upstream commit and verified by
`tests/test_bsr2_vendor_integrity.py`, which SHA-256s every file in `vendor/`
against a pinned digest and fails the suite if any file drifts, is edited, or an
unpinned `.py` file appears. The pins are the raw-byte SHA-256 of each file, so
the check runs cleanly on every platform (see `.github/workflows/tests.yml`).

They use flat imports of each other exactly as upstream does; rather than edit
them into package-relative imports (which would fork the code and break the
digest pin), `crypto/vendor.py` puts `vendor/` on `sys.path` once and
re-exports. One place to audit instead of scattered path edits.

`vendor/` should be excluded from any autoformatter, so a formatting autofix
cannot break the digest pin.

## Upstream's own caveat

BSR2's `SECURITY.md` states it is research software and, in its own words, that
you should **not use it as the sole protection for credentials, identity
records, recovery secrets**, or comparable material.

That caveat is inherited here and is not softened. This repository is an active
research project. It has not had third-party cryptanalysis, and BSR2's
constructions are original rather than standardised. If you need protection you
can stake real consequences on, use audited, standardised primitives.

What this integration does claim: the protections below are implemented
deliberately, bound correctly, and tested — not that the underlying scheme has
the assurance of a reviewed standard.

## The KDF cost problem, and key wrapping

BSR2's `derive_password_key` enforces a 10,000-iteration floor and defaults to
120,000. In pure Python that measures at roughly **85-90 seconds at the floor**
on the development machine, and around **14 minutes at the default**. Lowering it
below the floor is refused by BSR2 itself.

Deriving a key from the passphrase on every operation would make the tools
unusable. The answer is standard key wrapping, the same approach full-disk
encryption has always used:

- Data is encrypted under a random 32-byte **master key**, never directly under
  a passphrase-derived key.
- The master key is sealed twice: once under a passphrase-derived key, once
  under a key derived from an offline **recovery code**.
- Unlocking runs one derivation, unwraps the master key, and holds it for the
  session. Every subsequent seal and open is fast.

Consequences, all deliberate:

- Changing the passphrase re-wraps the master key. It does not re-encrypt data,
  because the master key does not change.
- The recovery code is a **second full-strength path** to the master key. Anyone
  holding it has the access the passphrase gives. That is the price of
  recoverability, which is why it is displayed once and never stored.
- Losing both is unrecoverable. There is no third path, by design.
- The recovery code is 40 characters of Crockford base32 (200 bits) from
  `secrets.choice`. It gets no attempt limiting once an attacker holds the
  keyring file, so it is sized beyond brute-force reach.

Iteration counts are recorded per keyring and **validated on read**. A tampered
keyring header requesting a cheap derivation is rejected rather than honoured,
which would otherwise make the KDF trivially brute-forceable; an astronomically
large count is likewise rejected before it can turn an unlock into a years-long
derivation.

## Factor protection is split by entropy

Both are fixed by treating factors differently based on entropy, because they
are not the same kind of secret:

| Input | Treatment | Cost | Rationale |
| --- | --- | --- | --- |
| Passphrases, spoken phrases | `derive_password_key`, random 32-byte salt | ~85-90 s | Guessable by construction, so each guess must cost real time |
| Template digests, signature blobs, device ids | `derive_subkey` + `keyed_mac` | ~15 ms | Already high-entropy; stretching adds nothing, but a *keyed* digest stops offline confirmation of a candidate |

Applying an expensive KDF to a high-entropy input is cost without benefit;
applying a fast MAC to a low-entropy one is a real weakness. Each factor gets
the treatment its entropy calls for. A package verifying several factors would
otherwise cost minutes per open and hours across the test suite.

Each factor name derives a distinct subkey, so a template bound as `voice`
cannot be replayed into the `fingerprint` slot. Name and value are
length-framed before MAC'ing, so bytes cannot be shifted across the boundary
to collide.

See `crypto/factors.py`.

## Context binding

Every sealed object is bound to a canonical context string naming what it is,
for example a vault record, a biometric template, a package payload, a
per-recipient key slot, or a keyring wrapper. BSR2 authenticates the context
alongside the ciphertext, so a moved envelope fails authentication instead of
decrypting into the wrong slot. This is what makes cross-identity substitution
detectable: a template sealed for one identity cannot be dropped into another
identity's record, and a vault record's payload cannot be swapped with another
record's.

`|` and NUL are rejected inside field values, so no combination of field
contents can forge a different context. See `crypto/context.py`.

## Length-hiding padding

A BSR2 envelope's ciphertext is exactly as long as its plaintext, because the
construction XORs a keystream with no block structure. For identity data that
leaks more than it appears to: a 41-byte ciphertext narrows the stored value
considerably, and across many records the size pattern alone distinguishes a
short credential from a long recovery note.

Plaintext is therefore length-prefixed (8 bytes) and padded to a 256-byte
multiple before sealing. Ciphertext size reveals only which bucket the plaintext
fell into.

The padding sits **inside** the BSR2 plaintext, so it is covered by the
authentication tag. Length recovery happens only after the tag verifies, which
means a forged envelope can never steer the unpadding logic. See
`crypto/envelope.py`.

## DRBG lifecycle

`brisart_security_envelope.encrypt` requires a caller-supplied generator and
deliberately does not create one, leaving seeding to the caller. BSR2's DRBG
expands seed material but cannot create entropy, so a weak seed means weak salts
and nonces regardless of expansion quality.

`crypto/rng.py` seeds from `secrets.token_bytes` at 128 bytes (double
upstream's 64-byte minimum) and wraps the generator so upstream's lifecycle
limits trigger a transparent reseed from fresh OS entropy rather than a hard
failure. Upstream raises at those limits by design; a long-lived enrollment
process should not crash on record 100,001. If upstream's continuous health
check destroys the generator, it is rebuilt from fresh entropy — retrying a dead
instance would raise forever.

## Attempt limiting

The slow KDF raises the cost of *offline* guessing but does nothing about an
attacker calling a verify function in a loop against a running process.
`crypto/throttle.py` provides an `AttemptLimiter` for that.

Limiter state is **persisted by the caller**, not held in memory. An in-memory
counter resets whenever the process restarts, which an attacker controls for
free. Since 1.3.7, `crypto/attempt_store.py` is that persistence adapter, and
it is wired into both unlock paths that exist in this codebase:

- `vault.store.vault_service.VaultService.unlock()` and
  `.unlock_with_recovery_code()` persist state as a plain
  `"unlock_attempts"` field directly inside `vault.json`, checked *before*
  a `Keyring` is even constructed from the stored wrapper. Both methods
  share one counter, so alternating between a passphrase guess and a
  recovery-code guess does not reset an attacker's budget.
- `biometrics.identity.keyring_access.unlock_with_passphrase()` does the
  same for the biometrics `keyring.json`, and is the single shared entry
  point both the CLI (`biometrics/app.py`) and the GUI
  (`gui/tabs/tab_biometrics.py`) unlock through, so neither interface can
  be used to bypass the throttling the other enforces.

Defaults (from `crypto.throttle.AttemptLimiter`'s own constructor
defaults, unchanged by either integration): 5 attempts before lockout,
exponential backoff starting at 1 second and capping at 300 seconds
between attempts, and a 900-second (15-minute) lockout once the 5th
failure is reached.

The identity-bound package flow (`packages/`) is intentionally out of
scope for this wiring: a package's master key is not a low-entropy human
passphrase in the same sense a vault or keyring passphrase is, and its
recipient check (`packages/verification.py`) is already a fast keyed-MAC
rather than a KDF.

## Error handling

Callers only ever need to catch `Bsr2IntegrationError` and its subclasses, never
a vendor exception type. `crypto/envelope.py` catches the vendored
`BrisartEnvelopeError` and re-raises `EnvelopeAuthenticationError`, preserving
the original as `__cause__`.

Authentication failures are deliberately **uniform**. A modified ciphertext, the
wrong key, and the wrong context are indistinguishable to the verifier, and are
reported identically so a failure does not reveal which occurred. Keyring unlock
failures likewise do not disclose whether the wrapper was structurally valid,
because that tells an attacker whether a guess was partially correct.

Malformed stored data is kept distinct from authentication failure: callers need
to treat "this is not shaped like a keyring" as a data bug and "the tag did not
verify" as a security event.

## What is protected, per tool

### Vault

Record **payloads** are sealed under the vault master key. Record **shells** —
`record_id`, `kind`, `label`, timestamps — stay readable in the clear.

That is a deliberate trade. The vault leaks that a record labelled `bank-login`
exists while protecting its value. Encrypting labels would require decrypting
every record for any lookup, making the CLI unusable for listing and searching.

The vault file (`vault.json`) holds the BSR2-wrapped master key (both the
passphrase- and recovery-code-wrapped copies) in its `keyring` section. Since
1.3.2 it is written with owner-only (`0600`) permissions on POSIX platforms via
`common/atomic_io.py`'s `file_mode` parameter, and its permissions are checked
on load (`warn_if_permissive`), so a file predating this fix or widened by hand
is flagged to stderr. This is filesystem defense-in-depth, not a strengthening
of BSR2 — see the note under **Biometrics** below on how that permission is
applied and its one limitation.

### Biometrics

Biometric templates are sealed under a local **passphrase keyring**
(`crypto/keyring.py`), the same master-key-wrapping construction the vault uses,
bound to identity id and modality via `crypto/context.py`. Enrolling or
verifying unlocks the keyring once per invocation through `getpass` and holds
the master key for that run. Identity records stay readable so `list` and
`inspect` work without unlocking; only the template payloads are encrypted.

The keyring file (`biometrics/data/keyring.json`) holds the BSR2-wrapped master
key. Since 1.3.2 it is created with owner-only (`0600`) permissions on POSIX
platforms and checked on load, exactly as the vault file is. **How that 0600 is
applied:** both files are written by `common/atomic_io.py`, which creates a
uniquely-named temp file (under the process umask), writes and fsyncs it,
`os.replace`s it into position, and then `chmod`s the result to `0600`. The
chmod happens immediately after the atomic rename, not at creation time, so
there is a brief window in which the temp file exists at umask permissions
before it is tightened — this is filesystem hardening, not an atomic
`open(..., 0o600)` guarantee. On Windows the whole mechanism is a no-op, since
`os.chmod` cannot express POSIX owner/group/other bits; protecting these files
there is a filesystem/ACL concern outside what this code claims.

A separate, deliberately weak **device binding**
(`biometrics/identity/device_key.py`) records a keyed-MAC of machine-specific
fingerprint material (hostname, platform string, MAC address) under the master
key. It is one more thing an attacker must reproduce on a different machine, not
a security boundary in its own right, and it stores only a bound value — there
is no separate device-key file to protect.

**This protects against:** template contents disclosed through a copied file, a
backup, a stale disk image, or a bug-report attachment; silent tampering to
weaken a match; substitution of templates between identities or modalities.

**This does not protect against:** anyone who can read the keyring file *and*
knows the passphrase, or who can observe the master key in the process's memory
while it is unlocked. The keyring sits beside the data it protects, so the
passphrase (or recovery code) is the real boundary; use an encrypted volume or
restrict the directory to the service account if the on-disk keyring itself must
be protected at rest beyond its `0600` mode.

### Packages

A random per-package **content key** encrypts the payload once. That content key
is then wrapped once per recipient under each recipient's master key. Opening
reverses it: unlock your identity, unwrap the content key from your own slot,
decrypt the payload.

The consequence is stated rather than hidden: **creating an encrypted package
requires every recipient's identity to be unlocked at creation time.** BSR2 is
symmetric and this project takes no third-party dependencies, so there is no
public-key mechanism to seal a payload to a recipient the creator cannot open.
Adding a recipient later needs that recipient unlocked. This is a real
limitation of symmetric-only crypto.

Package integrity is provided by an internal, hash-chained **custody chain**
(`packages/custody.py`), not a separate signature field: every lifecycle event
(created, recipient added/removed, opened) commits to the previous event's
hash, so editing, deleting, or reordering a past entry is detectable. This is
tamper-evidence, not proof of origin — the `actor_label` recorded in each
entry is a caller-supplied string, not cryptographically bound to a signing
key.

Open order matters: cheap structural checks (format, custody chain,
authorization, key-slot presence) run before the recipient's factor
verification, so a structurally tampered package is rejected without doing
unnecessary cryptographic work.

## Key material and the repository

The runtime `data/` directories under `biometrics/`, `vault/`, and `packages/`
are gitignored. They hold real identity records, sealed biometric templates
(including the biometrics `keyring.json`), verification reports, sealed vault
files, and sealed packages. A keyring decrypts every template beside it once its
passphrase is known; none of this belongs in version control. `*.identity`,
`*.ibp`, and a legacy `device_key.json` name are also gitignored for defense in
depth (the current biometrics build stores a keyring, not a device-key file, but
the ignore entry is kept so no such file could ever be committed by accident).

## Residual risks

1. **BSR2 is unreviewed research crypto.** Original constructions, no
   third-party cryptanalysis. This is the dominant risk and no amount of correct
   integration reduces it.
2. **Pure-Python timing.** Constant-time comparison is used for digests, but
   Python cannot guarantee constant-time behaviour throughout.
3. **Master key in process memory.** Held for the session after unlock, with no
   guarded allocation or protection against a memory-reading attacker or a core
   dump.
4. **Vault labels readable while locked.** Metadata disclosure, accepted for
   usability.
5. **Keyrings co-located with the data they protect.** Both the vault and the
   biometrics keyring sit beside their own encrypted data, protected at rest by
   BSR2 and by a `0600` file mode on POSIX. Anyone who can read the keyring file
   and knows the passphrase (or holds the recovery code) has full access; the
   `0600` mode is defense-in-depth, not the boundary.
6. **No forward secrecy.** Compromising a master key exposes everything ever
   sealed under it.
7. **Biometric matching is threshold-based hand-rolled DSP**, not a trained
   model. The video modality has a motion-presence liveness gate (1.3.0) that
   refuses static single-frame clips, but it is not general anti-spoofing (it
   does not detect a played-back recording, a wobbled photo, or a mask/deepfake)
   and is uncalibrated against real camera hardware. No other modality has any
   liveness or anti-spoofing check.
8. **Attempt throttling (1.3.7) is process-local and file-based, not
   distributed.** The attempt limiter stops a single attacker driving one
   CLI or GUI process against one vault/keyring file in a loop. It does not
   protect against an attacker who copies the vault/keyring file elsewhere
   and resets its `"unlock_attempts"` field by hand -- a local attacker with
   write access to the file can always do this, since the field is
   plaintext and unauthenticated, exactly like every other vault-shell or
   keyring-shell field. It only raises the cost of guessing against a file
   the attacker cannot freely edit, e.g. one they can only interact with
   through the CLI/GUI's own unlock prompt.
