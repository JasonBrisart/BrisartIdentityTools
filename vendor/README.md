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
known-answer vectors.

**Note (2026-08-24):** `tests/test_bsr2_vendor_integrity.py` -- referenced
below and in `docs/BSR2_INTEGRATION.md` as the mechanism that hashes every
file and fails the suite on modification -- does not currently exist in this
tree. It appears to have been dropped during the LabID/IdentityVault →
biometrics/vault restructuring and has not been recreated. Until it is
rewritten and added back, **an accidental edit to a file in this directory
will not be caught by CI.** Re-adding it (or an equivalent digest check in
`run_tests.py`) should be treated as an open item, not an implemented
protection.

To take an upstream update: re-copy all four files, update the commit SHA
above, then run the full suite.

## Re-syncing

```bash
git clone https://github.com/JasonBrisart/BrisartSecurityResearch.git /tmp/bsr
cp /tmp/bsr/brisart_security_{primitives,drbg,entropy,envelope}.py vendor/
python3 -c "
import hashlib, pathlib
for name in sorted(pathlib.Path('vendor').glob('brisart_security_*.py')):
    print(name.name, hashlib.sha256(name.read_bytes()).hexdigest())
"
```

<!--
BUG FIX (2026-08-24): the two commands above previously targeted
`bsr2_vendor/` (the directory's name before the LabID/IdentityVault ->
biometrics/vault/vendor restructuring). The actual directory in this
repository is `vendor/`. Anyone following the old instructions verbatim
would `cp` the freshly cloned files into a directory that does not exist,
and the verification one-liner's glob would silently match zero files and
print nothing, without any error indicating the sync had failed.
-->

## Upstream status

BSR2 is **experimental research**. Upstream's own `SECURITY.md` states it has had
no independent cryptanalysis, formal verification, or production review, and
directs that it not be used as the sole protection for credentials or identity
records. `docs/BSR2_INTEGRATION.md` in this repository records how that applies
here and what it means for this project's threat model.
