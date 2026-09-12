# Hardware

Optional device integration layer for BrisartIdentityTools.

No hardware driver in this folder is required to use BrisartIdentityTools.
Vault, Biometrics, and Packages function identically with `hardware/`
entirely absent from a checkout.

---

## Architecture

```text
hardware/
├── base/
│   ├── device_base.py       DeviceBase -- name/connect/disconnect/health_check
│   ├── camera_base.py       CameraBase(DeviceBase) + capture_image()
│   ├── biometric_base.py    BiometricBase(DeviceBase) + scan()
│   ├── reader_base.py       ReaderBase(DeviceBase) + read_card()
│   └── pcsc_binding.py      PCSCBinding -- contract only, no implementation
├── registry.py               Plain dict: name -> driver class
├── hardware_manager.py       HardwareManager.create_device(name)
├── exceptions.py             HardwareError and subclasses
├── cameras/
│   ├── placeholder_camera.py
│   └── onvif_camera.py       Real driver -- 100% standard library
├── card_readers/
│   ├── placeholder_reader.py
│   └── pcsc_reader.py        Real driver -- pure Python, requires a
│                              caller-supplied PCSCBinding (see below)
├── biometric/
│   └── placeholder_biometric.py
└── drivers/                  Reserved for future low-level drivers
```

A shared conformance suite (`hardware/tests/test_device_contract.py`)
does not exist in this repository yet. Adding one — verifying every
driver actually satisfies `DeviceBase`/`CameraBase`/`ReaderBase`, rather
than trusting the right method names exist — is open, tracked work, not
something currently shipped.

## The contract

Every device satisfies `DeviceBase`:

```python
class DeviceBase(ABC):
    name            # property
    connect()       # -> bool, never raises for "device unreachable"
    disconnect()    # -> None, never raises
    health_check()  # -> bool
```

Plus exactly one modality-specific method: `CameraBase.capture_image()`,
`BiometricBase.scan()`, or `ReaderBase.read_card()`.

## Dependency status, per driver

```text
placeholder_*.py    -- zero dependencies, reference implementations only
onvif_camera.py     -- ZERO third-party packages. Implemented entirely
                        with the standard library (urllib, xml.etree,
                        hashlib). No OS-proprietary layer applies to
                        ONVIF -- it is XML over HTTP, which stdlib
                        already handles completely.
pcsc_reader.py       -- ZERO third-party packages, ZERO OS calls of its
                        own. Contains all PC/SC logic (reader matching,
                        retries, APDU construction, status-word
                        checking) in pure Python. Requires a
                        PCSCBinding instance supplied by the caller --
                        see "Why the OS binding is not shipped" below.
```

## Why the OS binding is not shipped (PC/SC specifically)

ONVIF and PC/SC hit a genuinely different wall:

```text
ONVIF (cameras):
    Network protocol (XML/SOAP over HTTP/TCP sockets)
    → sockets are a universal, OS-neutral standard library facility
    → nothing OS-proprietary to reach; stdlib goes all the way

PC/SC (card readers):
    Requires a call into the OS's OWN smart-card service:
        winscard.dll    (Windows -- closed source, part of the OS)
        PCSC.framework  (macOS -- closed source, part of the OS)
        libpcsclite     (Linux -- BSD licensed, part of the OS)
    → there is no stdlib path to a smart card reader on any platform
      that skips this OS-level service; every PC/SC application
      (including Windows' own built-in smart card support) goes
      through it
```

Rather than have `hardware/card_readers/pcsc_reader.py` itself decide
which platform it's on and load an OS-owned library, this project draws
the line one step earlier: `pcsc_reader.py` contains 100% of the *logic*
(pure Python, fully unit-testable with a fake binding, zero OS calls),
and `hardware/base/pcsc_binding.py` defines the five-method contract for
the one remaining piece — actually talking to the OS. Implementing that
contract, for the specific OS(es) a deployment actually runs on, is the
responsibility of the organization deploying BrisartIdentityTools:

```python
from hardware.base.pcsc_binding import PCSCBinding

class MyPCSCBinding(PCSCBinding):
    def establish_context(self): ...   # calls YOUR OS's PC/SC service
    def release_context(self): ...
    def list_readers(self): ...
    def connect(self, reader_name): ...
    def disconnect(self): ...
    def get_atr(self): ...
    def transmit(self, apdu): ...
```

```python
from hardware.card_readers.pcsc_reader import PCSCReader

reader = PCSCReader(binding=MyPCSCBinding())
```

This means: no lab that only uses ONVIF cameras ever needs to write or
audit any OS-calling code at all. A lab that wants PC/SC card readers
writes (or audits) exactly one small file — their own `PCSCBinding` —
scoped to the one OS they actually run, rather than inheriting a
generic, multi-platform OS-calling layer they didn't write and may not
need in its entirety.

## Writing your own driver

A lab that wants a vendor-specific driver not covered here does not need
to touch `hardware/base/`, `registry.py`, or anything outside one new
file — same pattern as `CameraBase`/`BiometricBase`/`ReaderBase`
subclasses always have.

## Testing

No `hardware/tests/` suite currently exists in this repository. When
added, `onvif_camera.py` is fully testable with zero dependencies and
zero real hardware (it is pure stdlib), and `pcsc_reader.py`'s logic —
retry policy, APDU construction, status-word checking — is fully
testable against a minimal fake `PCSCBinding`, with no real OS call and
no real hardware required.

## Status

`onvif_camera.py` is a complete, dependency-free ONVIF client but has
not been validated against physical camera hardware as part of this
repository's own test suite. `pcsc_reader.py`'s logic layer is fully
testable in isolation; its correctness against a *real* PC/SC binding
depends entirely on the quality of the binding an operator supplies,
which is intentionally outside this repository's scope.
