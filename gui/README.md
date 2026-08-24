# GUI

A single-window Tkinter desktop front-end for all three tools (`vault/`,
`biometrics/`, `packages/`), added in 1.0.0. Standard library only —
`tkinter` ships with Python, so this adds no new dependency and keeps the
zero-third-party-dependency rule intact.

No logic lives here. Every button calls directly into the same service
classes and functions the CLIs use (`vault.store.vault_service.VaultService`,
`biometrics.engine.enrollment`/`verification`, `packages.package`) — this
module is wiring, not a second implementation of anything.

---

## Running it

```bash
python -m gui.app
```

or via the unified dispatcher:

```bash
python cli.py gui
```

---

## Why every slow operation runs on a background thread

BSR2's password KDF is deliberately slow — tens of seconds to a couple of
minutes per call (see [`docs/BSR2_INTEGRATION.md`](../docs/BSR2_INTEGRATION.md)).
Vault init/unlock, the biometrics keyring create/unlock, and every package
operation all pay that cost. Calling any of them directly from a button
handler would freeze the whole window for the duration of the derivation,
which on a GUI reads as a hang rather than "the KDF is working as intended."

`run_in_background()` is the one path every such call goes through: it starts
a daemon thread, shows a small modal `BusyDialog` with an indeterminate
progress bar, and polls a `queue.Queue` on the main thread via `after()` until
the thread finishes. Tkinter widgets are never touched from the background
thread itself — only the main thread ever calls back into a widget, which is
what Tkinter requires.

---

## Layout

```
gui/
├── app.py       Everything: dialogs, the three tabs, and the App shell (for now)
└── README.md
```

Kept as one file. Three tabs sharing one small set of dialog
helpers (`TextPromptDialog`, `TextViewDialog`, `BusyDialog`, `RecordDialog`,
`ModalityPathDialog`) is a small enough surface that splitting it into
several modules would mean more import boilerplate than the tabs themselves
contain. im too lazy to do this right now so i'll let it slide in order to keep this 1.0.0 release on schedule

### Tabs

- **Vault** — choose/create a vault file, init, unlock, lock, list records
  (works while locked, since record shells stay readable — see
  `vault/README.md`), create a new record with a JSON payload editor, view
  (decrypt) or delete a selected record.
- **Biometrics** — create/unlock the local keyring, enroll an identity
  against voice/fingerprint/video files (each with a file-picker), verify a
  probe against a stored identity with an "any modality matches" checkbox,
  inspect a non-secret summary, delete an identity, and generate synthetic
  test samples.
- **Packages** — choose/create a package file, create a package with an
  initial recipient, add or remove recipients (each requiring an existing
  recipient's master key to authorize), open a package as a recipient,
  verify and display the custody chain, and run the same
  create → add-recipient → open demo cycle as `packages/main.py demo`.

### A note on package master keys

The Packages tab follows the same convention `packages/main.py`'s CLI does:
a "master key text" field accepts any typed text and stretches it to a
32-byte key via `hashlib.sha256`. That is a demo/test convenience, not a real
key-management path — a production integration should supply an actual
32-byte master key (for example, one unlocked from `crypto.keyring.Keyring`)
rather than typed text. This is called out in the GUI's field labels and in
the code comment on `PackagesTab._derive_master_key`.

---

## What this does not add

No new storage format, no new crypto, no new validation rules, and no new
CLI-invisible behavior. Everything a button in this GUI does is something the
corresponding CLI (`vault/app.py`, `biometrics/app.py`, `packages/main.py`)
already does — this is only a second way to drive the same application
layer, for anyone who would rather click through a window than remember
subcommand syntax.
