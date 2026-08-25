# GUI

BrisartIdentityTools includes a standard-library-only Tkinter desktop interface
for Vault, Biometrics, and Packages. The GUI remains local-first, works without
cloud services, and adds no third-party dependency.

Version 1.2.0 replaces the former single-module GUI layout with a small root
entry point and focused GUI submodules. This keeps the interface easier to
inspect, test, change, and maintain without duplicating application logic.

---

## Run the GUI

From the repository root:

```bash
python app.py
```

The root-level `app.py` is the GUI application shell. It creates the main
window, adds the Vault, Biometrics, and Packages tabs, builds the menu bar, and
starts Tkinter's event loop.

---

## Layout

```text
app.py
└── gui/
    ├── README.md
    ├── core/
    │   ├── constants.py
    │   └── busy.py
    ├── widgets/
    │   ├── dialogs.py
    │   └── path_panel.py
    └── tabs/
        ├── tab_vault.py
        ├── tab_biometrics.py
        └── tab_packages.py
```

### `app.py`

The executable shell only. It owns the main `tk.Tk` window, notebook assembly,
File and Help menus, About dialog, and `main()` entry point.

### `gui/core/constants.py`

Provides shared constants and modality file-type filters. It also locates the
repository root by walking upward until it finds `version.py`, then makes that
root importable before any tab imports Vault, Biometrics, or Packages.

### `gui/core/busy.py`

Provides the shared busy dialog and background-operation runner used for slow
operations. Worker code runs away from Tkinter's main thread, while all widget
updates remain on the main thread.

### `gui/widgets/dialogs.py`

Contains reusable modal-dialog helpers shared by the three tabs.

### `gui/widgets/path_panel.py`

Contains the shared file, folder, and drive selection panel used by bulk Vault
operations and biometric attachments.

### `gui/tabs/tab_vault.py`

Contains the Vault interface, including record operations and the Files /
Folders / Drives workflow.

### `gui/tabs/tab_biometrics.py`

Contains biometric enrollment, verification, inspection, deletion, sample
generation, and attachment workflows.

### `gui/tabs/tab_packages.py`

Contains identity-bound package creation, recipient management, opening,
verification, custody-chain display, and demo workflows.

---

## Architecture Rule

No cryptography, validation, identity policy, or persistence implementation
belongs in `app.py` or `gui/`. GUI controls call the same application and
service layers used by the command-line tools:

- `vault.store.vault_service`
- `biometrics.engine.enrollment`
- `biometrics.engine.verification`
- `packages.package`

The GUI is wiring and presentation, not a second implementation of the system.

---

## Slow Operations

BSR2 key derivation and large encrypted-data operations can take noticeable
time. Operations that would block the interface use the shared background
runner in `gui/core/busy.py` and display a modal working indicator.

Tkinter widgets are only read or changed on the main thread. Background workers
return results through the shared runner, which schedules completion handling
back onto Tkinter's event loop.

---

## File, Folder, and Drive Selection

The shared `PathSelectionPanel` supports the GUI workflows that accept files,
folders, or drive roots. Selection uses Tkinter's standard file and directory
pickers. Native drag-and-drop support is not part of the 1.2.0 GUI layout.

---

## Dependency Policy

The GUI uses only Python's standard library:

- `tkinter`
- `threading`
- `queue`
- `pathlib`

It does not require a GUI framework, package manager install, cloud service, or
network connection.
