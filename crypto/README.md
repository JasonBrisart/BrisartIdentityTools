# Crypto

The integration layer between vendored BSR2 and the three tools (`biometrics/`,
`vault/`, `packages/`). No cryptographic primitive is implemented in this
directory — everything here composes the vendored primitives in `vendor/`
into the higher-level operations the rest of the repo actually calls:
sealing/opening a payload, wrapping a master key, hashing a factor, binding an
object to a context, rate-limiting an unlock attempt.

If you're auditing the cryptography, start at
[docs/BSR2_INTEGRATION.md](../docs/BSR2_INTEGRATION.md) for the full threat
model and rationale. This README is a map of the module, not a replacement
for that document.

---

## Module map

| File | Role |
| --- | --- |
| `vendor.py` | Puts `vendor/` on `sys.path` once and re-exports the vendored primitives. The single place that knows the vendored files use flat imports of each other. |
| `errors.py` | The exception family every caller catches: `Bsr2IntegrationError` and subclasses (`KeyringFormatError`, `KeyringAuthenticationError`, `KeyringLockedError`, `EnvelopeAuthenticationError`). Callers never import a vendor exception type directly. |
| `context.py` | Canonical context strings (`record_context`, `template_context`, `package_context`, `key_slot_context`, `keyring_context`, ...). Every sealed object is bound to one of these, so a ciphertext cannot be moved between records, identities, modalities, or recipients without failing authentication. |
| `envelope.py` | `seal_bytes`/`open_bytes`/`seal_json`/`open_json` on top of the vendored envelope: adds length-hiding padding (8-byte prefix, 256-byte blocks) inside the authenticated plaintext, and canonical (sorted-key) JSON serialisation. |
| `keyring.py` | Master-key wrapping: a random 32-byte master key sealed once under a passphrase-derived key and once under an offline recovery code, so unlocking costs one slow KDF derivation per session instead of one per operation. Used by `vault/` and `biometrics/`. |
| `factors.py` | Factor protection split by input entropy — `hash_factor`/`verify_factor` (slow KDF, for passphrases and spoken phrases) versus `bind_factor`/`verify_bound_factor` (fast keyed MAC, for template digests and device ids). Also bounds KDF iteration counts above *and* below the sane range, so a tampered stored value can't force a cheap derivation or a years-long one. |
| `rng.py` | `ManagedGenerator` / `new_generator`: seeds the vendored DRBG from `secrets.token_bytes` and transparently reseeds before upstream's own request/byte lifecycle limits, so a long-lived process doesn't crash mid-run. |
| `throttle.py` | `AttemptLimiter`: exponential-backoff + lockout for *online* guessing against a running process, on top of what the slow KDF already does for *offline* guessing. State is caller-persisted, not held in memory. |

---

## Why this layer exists at all

BSR2 (vendored in `vendor/`) is a research construction that implements the
actual cryptographic primitives — a sponge hash, a keyed MAC, a password KDF,
an authenticated envelope, a DRBG. It is deliberately minimal and has no
opinion about application concerns like "what should a template's context
string look like" or "how many failed unlock attempts should trigger a
lockout." Everything in this directory is that missing application layer,
kept separate from the vendored files so upstream can be re-synced (see
`vendor/README.md`) without touching a single line of integration logic.

## A note on trust

Every fix and hardening pass in this layer — bounding iteration counts,
rejecting non-finite limiter state, uniform authentication-failure messages —
reduces the ways *this code* can misuse BSR2. None of it increases confidence
in BSR2 itself. BSR2's own `SECURITY.md` says it should not be the sole
protection for credentials, identity records, or recovery secrets, and that
caveat is inherited here without softening.
