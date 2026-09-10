# Security Policy

BrisartIdentityTools (`biometrics/`, `vault/`, `packages/`, `crypto/`, `vendor/`,
`gui/`) handles identity records, biometric templates, encryption keyrings, and
identity-bound package payloads. If you find a security issue anywhere in this
repository, please report it privately rather than opening a public issue.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security report.** Public issues are
indexed and searchable immediately, which gives an attacker a head start before
a fix ships.

Instead, use one of the following:

1. **Preferred: GitHub Private Vulnerability Reporting.**
   Go to this repository's **Security** tab -> **Report a vulnerability**. This
   opens a private advisory thread visible only to the maintainer and you,
   and lets you attach proof-of-concept code or data directly.
2. **Fallback: Direct contact.**
   If private reporting is unavailable to you for any reason, contact the
   maintainer, Jason Brisart, through a private channel (e.g. a direct message
   through the maintainer's listed contact on the GitHub profile) rather than
   a public one.

Please include, where possible:
- Which component is affected (`biometrics`, `vault`, `packages`, `crypto`,
  `vendor`, `gui`, or the CLI/GUI layer around them).
- Steps to reproduce, or a minimal proof of concept.
- What you believe the impact is (e.g. authentication bypass, key/template
  disclosure, integrity bypass, denial of service).
- Whether you believe the issue lives in this repository's integration code
  (`crypto/`) or in the vendored BSR2 primitives (`vendor/`) themselves.

## Response Expectations

This is a solo-maintained research project, not a company with a security
team on call. On a best-effort basis:
- Acknowledgement of a private report: within a few days.
- An initial assessment (confirmed / not applicable / needs more information):
  within roughly two weeks.
- A fix or mitigation timeline once a report is confirmed, communicated
  directly in the private advisory thread.

There is no bug bounty program at this time.

## Coordinated Disclosure

Please allow a reasonable window to investigate and ship a fix before any
public disclosure or write-up. Once a fix is released, the advisory can be
made public and credit given to the reporter (by name or handle, or
anonymously, whichever you prefer) unless you request otherwise.

## Scope

**In scope:**
- `crypto/` — the BSR2 integration layer (envelope sealing/opening, keyring
  wrapping, factor hashing, context binding, DRBG management, attempt
  throttling).
- `biometrics/`, `vault/`, `packages/` — how each tool uses that integration
  layer to protect identity records, templates, vault payloads, and
  identity-bound package content.
- `gui/` and the CLI entry points (`app.py`, `cli.py`) — how user input reaches
  the above, including path handling, file/bundle chunking, and any place
  untrusted input is parsed.

**Out of scope, but still worth reporting if you find something:**
- `vendor/brisart_security_*.py` — these files are vendored **byte-identical**
  from [BrisartSecurityResearch](https://github.com/JasonBrisart/BrisartSecurityResearch)
  and pinned by `tests/test_bsr2_vendor_integrity.py`. A cryptographic flaw in
  BSR2 itself should ideally be reported upstream in that repository, but a
  report here will still be read and forwarded.

## A Standing Caveat, Stated Plainly

BSR2 (`vendor/`) is original, unreviewed research cryptography. It has not had
independent cryptanalysis, formal verification, or production security review.
Upstream's own `SECURITY.md` states it should not be the sole protection for
credentials, identity records, or recovery secrets — and that caveat is
inherited here without being softened. See
[`docs/BSR2_INTEGRATION.md`](docs/BSR2_INTEGRATION.md) for the full threat
model, what each protection actually buys, and the documented residual risks.
Reports that point out gaps between what that document claims and what the
code actually does are especially welcome.

## Supported Versions

BrisartIdentityTools is maintained as two parallel release lines so that
institutions can choose between long-term stability and access to the latest
capabilities.

- **Long-Term Support (LTS).** A feature-frozen, pure-Python, dependency-free
  generation intended for offline and air-gapped research environments. An LTS
  release receives security, critical correctness, and data-integrity fixes for
  the duration of its published support window. No new features, no hardware or
  device integration, and no third-party dependencies are introduced into an LTS
  line for the life of that line. This purity is a deliberate, maintained
  guarantee, not an incidental property of a given release.

- **Current (`main`).** The active development line, where new functionality —
  including hardware and device support that may require platform drivers or
  optional dependencies — is delivered. The Current line is not covered by the
  LTS dependency-free guarantee.

The following releases receive security fixes:

| Release | Line | Support status | Security fixes |
| --- | --- | --- | --- |
| LTS-2028 (1.3.x) | Long-Term Support | Supported through 1 January 2028 | ✅ |
| Latest release on `main` | Current | Supported | ✅ |
| Pre-1.3.0 and superseded releases | — | End of Support | ❌ |

### Lifecycle

An LTS release is feature-locked at publication and maintained on a
security-and-correctness basis only for its published window. Fixes are applied
where they can be made safely without altering the frozen architecture; where a
defect cannot be remediated within that architecture, migration to a currently
supported release may be required and will be documented.

On reaching its published end-of-support date, an LTS release enters
**End of Support**. It remains permanently available as a historical,
dependency-free reference — supporting reproducibility, archival, and prior
validation records — but receives no further maintenance, including security
updates. Availability of a release should not be interpreted as continued
support; institutions requiring ongoing maintenance should adopt the next LTS
release or a currently supported version.

### Scope and assurances

This policy governs maintenance commitments only. It does not modify the
underlying cryptographic caveats described in
[`docs/BSR2_INTEGRATION.md`](docs/BSR2_INTEGRATION.md): BSR2 remains unreviewed research
cryptography and should not be relied upon as the sole protection for
high-value or irreplaceable secrets, in any release line.
