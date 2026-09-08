# Known Issues

This file tracks open, non-trivial issues in BrisartIdentityTools that are not
yet resolved. Each entry follows a standardized bug-report template (modeled
on GitHub Issues / Jira) so severity, scope, and next steps stay consistent
and easy to scan.

For the deeper, ongoing research-cryptography caveats that apply to the whole
project by design (BSR2 being unreviewed research crypto, no forward secrecy,
vault labels readable while locked, etc.), see the **Residual Risks** section
of [`docs/BSR2_INTEGRATION.md`](docs/BSR2_INTEGRATION.md) instead — those are
documented, accepted design tradeoffs, not open bugs.

---

## KI-001: Video liveness threshold is uncalibrated against real camera hardware

- **Reported date:** 2026-09-03
- **Severity:** Medium
- **Environment:** All platforms; affects the `video` biometric modality only.
- **Component:** `biometrics/features/liveness.py`, `biometrics/engine/enrollment.py`, `biometrics/engine/verification.py`
- **Steps to Reproduce:**
  1. Enroll or verify a `video` modality probe recorded from a real camera
     rather than the project's synthetic sample generator.
  2. Observe the `motion_energy` value reported in the liveness result.
- **Expected behavior:** `DEFAULT_LIVENESS_THRESHOLD` (0.75) should reliably
  separate a genuinely static clip from a live capture across real hardware,
  lighting, and sensor noise conditions.
- **Actual behavior:** The threshold has only been validated against this
  project's own synthetic sample generator (`biometrics/samples/sample_generator.py`),
  which is a much cleaner signal than a real camera. It is unknown whether
  0.75 produces false rejections (genuine live captures with low sensor
  noise) or false acceptances (a wobbled photo) on real hardware.
- **Tried / Ruled out:** The gate itself (motion-presence detection via
  mean absolute frame-to-frame pixel difference) is unit-tested and correct
  against hand-built static and moving frame sequences — see
  `biometrics/tests/test_liveness.py`. The gap is calibration data, not logic.
- **Next step:** Collect real-camera liveness samples (live captures vs.
  static photo replays) across a few devices, measure `motion_energy` on
  each, and re-tune `DEFAULT_LIVENESS_THRESHOLD` (or make it configurable
  per deployment) once real data exists.

---

## KI-002: GUI had no automated test coverage

- **Reported date:** 2026-09-04
- **Severity:** Low
- **Environment:** All platforms; affects `gui/` only (CLI and application
  layers are unaffected and already covered by `biometrics/tests/`,
  `vault/tests/`, `packages/tests/`, `crypto/tests/`, `common/tests/`).
- **Component:** `gui/core/`, `gui/widgets/`, `gui/tabs/`
- **Steps to Reproduce:** Run `python tests/run_tests.py` before this issue
  was addressed; no test files existed under any `gui/` subdirectory.
- **Expected behavior:** Every application layer that other tools' tests
  hold to a professional bar should have at least baseline regression
  coverage, consistent with the rest of the repository's test discipline.
- **Actual behavior:** `gui/` was the one subsystem with zero test files,
  meaning a regression in the repo-root bootstrap logic, the background
  worker/queue mechanism, or the path-selection panel's dedup logic could
  ship silently.
- **Tried / Ruled out:** N/A — this was a coverage gap, not a defect.
- **Next step:** **Partially resolved.** Initial coverage was added under
  `gui/tests/` (`test_constants.py`, `test_busy.py`, `test_path_panel.py`),
  covering the repo-root bootstrap walk, the background-thread/queue
  contract in `run_in_background`, and `PathSelectionPanel`'s path add/
  dedup/remove/clear logic. Tk-dependent tests skip gracefully on a
  headless runner with no display. Remaining gap: `gui/tabs/*.py` (the
  actual Vault/Biometrics/Packages tab wiring) still has no direct
  coverage and should be added incrementally.

---

## KI-003: Bulk file/folder/drive encryption throughput ceiling (~1.4 KB/s)

- **Reported date:** 2026-08-25
- **Severity:** Low (documented limitation, not a defect)
- **Environment:** All platforms; affects `vault/store/bulk_file_service.py`
  and `biometrics/engine/bulk_attachments.py`.
- **Component:** Bulk file/folder/drive encryption (chunked BSR2 sealing)
- **Steps to Reproduce:** Encrypt a folder or drive larger than a few tens
  of MB via `encrypt-paths` / `attach-paths` and measure elapsed time.
- **Expected behavior:** N/A — this is a performance characteristic of the
  pure-Python BSR2 primitives, not a bug to "fix" without changing the
  cryptographic implementation itself.
- **Actual behavior:** Measured throughput is roughly 1.4 KB/s for both
  sealing and restoring, because `stream_bytes` runs a full sponge-based
  keyed MAC every 64 bytes of output in plain Python. A 100 MB folder takes
  on the order of 21 hours; a full multi-hundred-GB drive would take weeks.
- **Tried / Ruled out:** The chunking/manifest logic itself is correct and
  tested (`vault/tests/test_bulk_file_service.py`,
  `biometrics/tests/test_bulk_attachments.py`); the ceiling is inherent to
  BSR2, not the chunking layer built on top of it.
- **Next step:** Already documented explicitly in
  [`docs/README_FULL_FILE_ENCRYPTION.md`](docs/README_FULL_FILE_ENCRYPTION.md)
  so users size expectations correctly (individual files/folders, not full
  drives, in a reasonable timeframe). No code change planned unless a
  faster (still dependency-free) primitive is adopted.

---

## Template

Use this template for new entries:

```markdown
## KI-XXX: <short title>

- **Reported date:** YYYY-MM-DD
- **Severity:** Critical / High / Medium / Low
- **Environment:** <OS / Python version / affected modality or tool>
- **Component:** <file(s) or module(s)>
- **Steps to Reproduce:**
  1. ...
- **Expected behavior:** ...
- **Actual behavior:** ...
- **Tried / Ruled out:** ...
- **Next step:** ...
```
