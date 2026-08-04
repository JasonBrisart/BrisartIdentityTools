# Vendored BSR2

These four files are copied **byte-identical** from BrisartSecurityResearch.

```text
Upstream:   https://github.com/JasonBrisart/BrisartSecurityResearch
Commit:     656d962c447b7ac69d76b717820c34ae8e56b38a
Release:    0.3.0-alpha (BSR2 Alpha 3)
Algorithm:  BSR2-ARX-SPONGE-ETM
Envelope:   version 2
```

| File | Role |
| --- | --- |
| `brisart_security_primitives.py` | permutation, sponge hash, keyed MAC, password KDF, subkey derivation, stream, hex, constant-time compare |
| `brisart_security_drbg.py` | deterministic random bit generator |
| `brisart_security_entropy.py` | operating-system entropy boundary |
| `brisart_security_envelope.py` | authenticated encrypt-then-MAC envelope |

## Do not edit these files

Local changes would silently fork the construction and invalidate upstream's
known-answer vectors. `tests/test_bsr2_vendor_integrity.py` hashes every file
and fails if one is modified, so an accidental edit is caught by CI rather than
discovered later.

To take an upstream update: re-copy all four files, update the commit SHA above
and the digests in the integrity test, then run the full suite.

## Re-syncing

```bash
git clone https://github.com/JasonBrisart/BrisartSecurityResearch.git /tmp/bsr
cp /tmp/bsr/brisart_security_{primitives,drbg,entropy,envelope}.py bsr2_vendor/
python3 -c "
import hashlib, pathlib
for name in sorted(pathlib.Path('bsr2_vendor').glob('brisart_security_*.py')):
    print(name.name, hashlib.sha256(name.read_bytes()).hexdigest())
"
```

## Upstream status

BSR2 is **experimental research**. Upstream's own SECURITY.md states it has had
no independent cryptanalysis, formal verification, or production review, and
directs that it not be used as the sole protection for credentials or identity
records. `docs/BSR2_INTEGRATION.md` in this repository records how that applies
here and what it means for this project's threat model.
