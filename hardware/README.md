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
│   ├── device_base.py         DeviceBase -- name/connect/disconnect/health_check
│   ├── camera_base.py         CameraBase(DeviceBase) + capture_image()
│   ├── biometric_base.py      BiometricBase(DeviceBase) + scan()
│   ├── reader_base.py         ReaderBase(DeviceBase) + read_card()
│   ├── pcsc_binding.py        PCSCBinding -- contract only, no implementation
│   ├── onvif_transport.py     ONVIFTransport -- contract only, no implementation
│   └── biometric_binding.py   BiometricBinding -- contract only, no implementation
├── registry.py                 Plain dict: name -> driver class
├── hardware_manager.py         HardwareManager.create_device(name, *args, **kwargs)
├── exceptions.py               HardwareError and subclasses
├── cameras/
│   ├── placeholder_camera.py
│   └── onvif_camera.py         Real driver -- pure Python, requires a
│                                caller-supplied ONVIFTransport (see below)
├── card_readers/
│   ├── placeholder_reader.py
│   └── pcsc_reader.py          Real driver -- pure Python, requires a
│                                caller-supplied PCSCBinding (see below)
├── biometric/
│   ├── placeholder_biometric.py
│   └── fingerprint_scanner.py  Real driver -- pure Python, requires a
│                                caller-supplied BiometricBinding (see below)
└── drivers/                    Reserved for future low-level drivers
```

A shared conformance suite (`hardware/tests/test_device_contract.py`)
does not exist in this repository yet. Adding one is open, tracked work.

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

## The one rule every real driver in this project follows

**Brisart owns protocol and logic. The organization deploying this
software owns the literal connection to the outside world.** Every real
driver in `hardware/` is split into two files along that exact line:

| Subsystem | Brisart-owned (protocol/logic, pure Python) | Organization-owned (the actual connection) |
|---|---|---|
| Cameras | `cameras/onvif_camera.py` | an `ONVIFTransport` implementation you supply |
| Card readers | `card_readers/pcsc_reader.py` | a `PCSCBinding` implementation you supply |
| Biometrics | `biometric/fingerprint_scanner.py` | a `BiometricBinding` implementation you supply |

In all three cases:

- The Brisart-owned file contains 100% of the protocol logic (SOAP/XML
  construction and parsing, APDU construction and status-word checking,
  device-name matching, retry policy, result-shape validation) and
  makes **zero network calls, zero OS calls, and imports zero
  third-party packages.**
- The driver's constructor **requires** the binding/transport object as
  an argument and raises `TypeError` immediately if it is missing or
  the wrong type. There is no default, no silent fallback, and no
  partially-working mode.
- The organization deploying BrisartIdentityTools is the party that
  actually opens a socket, makes an HTTP request, or calls into an
  OS-level library (`winscard.dll`, `PCSC.framework`, `libpcsclite`,
  the Windows Biometric Framework, `libfprint`/`fprintd`, or a vendor
  SDK). **This project never makes that connection itself, for any of
  the three device categories.**

This is true even for ONVIF, which -- unlike PC/SC and biometric
scanners -- has no OS-proprietary layer standing in the way (see "Why
ONVIF is split the same way despite having no proprietary wall" below).
The architecture is intentionally uniform across all three subsystems
rather than only where a proprietary wall forces it.

## Why the OS binding/transport is not shipped, per subsystem

```text
PC/SC (card readers):
    Requires a call into the OS's OWN smart-card service:
        winscard.dll    (Windows -- closed source, part of the OS)
        PCSC.framework  (macOS -- closed source, part of the OS)
        libpcsclite     (Linux -- BSD licensed, part of the OS)
    -> no application on any platform reaches a smart-card reader
       without going through this layer.

Biometric scanners:
    Requires a call into an OS-owned biometric framework or a vendor
    SDK:
        Windows Biometric Framework / WinBio  (Windows, closed source)
        libfprint + fprintd                    (Linux, open source, but
                                                 still a real library wall)
        a vendor SDK                           (where no OS framework
                                                 exists at all)
    -> no application reaches a real fingerprint scanner without going
       through one of these.

ONVIF (cameras):
    Has NO equivalent OS-proprietary wall. ONVIF is XML/SOAP over a
    plain HTTP socket, which Python's standard library already speaks
    completely (urllib, xml.etree.ElementTree, hashlib, base64). There
    is no proprietary code standing between this project and a camera.
```

## Why ONVIF is split the same way despite having no proprietary wall

Because PC/SC and biometric scanners *require* stopping at a
binding/transport boundary, and this project wants one consistent rule
across all three device categories rather than a different posture per
subsystem, `onvif_camera.py` is split identically even though nothing
proprietary forced it: **BrisartIdentityTools never opens a network
connection to a camera itself.** An organization deploying this
software supplies an `ONVIFTransport` implementation -- built on
`urllib`, an internal proxy-aware HTTP client, a camera gateway, or
whatever mechanism fits their network policy -- and that implementation
is what actually reaches the camera. `onvif_camera.py` owns every line
of SOAP generation, WS-Security digest computation, and XML parsing,
and calls `self._transport.post(...)` / `self._transport.get(...)`
instead of `urllib.request.urlopen(...)` directly.

## Writing your own binding, transport, or driver

Each contract is a small, fixed set of methods. For example, PC/SC:

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

The same pattern applies to `ONVIFTransport` (see
`hardware/base/onvif_transport.py`) and `BiometricBinding` (see
`hardware/base/biometric_binding.py`). A lab that wants a vendor-specific
driver not covered here at all does not need to touch `hardware/base/`,
`registry.py`, or anything outside one new file — same pattern as any
`CameraBase`/`BiometricBase`/`ReaderBase` subclass always has.

## Using HardwareManager with a real driver

`HardwareManager.create_device()` forwards any arguments through to the
registered class's constructor, so a real driver's required
binding/transport is supplied the same way as calling the class
directly:

```python
from hardware.registry import register
from hardware.hardware_manager import HardwareManager
from hardware.card_readers.pcsc_reader import PCSCReader

register("my-reader", PCSCReader)

manager = HardwareManager()
reader = manager.create_device("my-reader", binding=MyPCSCBinding())
```

`HardwareManager` itself never imports, constructs, or knows about any
concrete binding/transport implementation -- it has no knowledge of
networks, sockets, or operating-system libraries of any kind.

## Dependency status, per driver

```text
placeholder_*.py         -- zero dependencies, reference implementations only
onvif_camera.py           -- ZERO third-party packages, ZERO network calls
                             of its own. All SOAP/WS-Security/XML logic in
                             pure Python. Requires a caller-supplied
                             ONVIFTransport.
pcsc_reader.py             -- ZERO third-party packages, ZERO OS calls of
                             its own. All APDU/status-word logic in pure
                             Python. Requires a caller-supplied PCSCBinding.
fingerprint_scanner.py     -- ZERO third-party packages, ZERO OS/SDK calls
                             of its own. All device-matching/retry/
                             shape-validation logic in pure Python.
                             Requires a caller-supplied BiometricBinding.
```

## Testing

No `hardware/tests/` suite currently exists in this repository. When
added: `onvif_camera.py`, `pcsc_reader.py`, and `fingerprint_scanner.py`
are all fully testable against a minimal fake transport/binding, with
zero real network access, zero real OS calls, and zero real hardware
required for any of the three.

## Status

None of the three real drivers (`onvif_camera.py`, `pcsc_reader.py`,
`fingerprint_scanner.py`) has been validated against a physical device
as part of this repository's own test suite. Each is correct against
its documented protocol/contract; real-world validation against a
specific vendor's hardware and a specific organization's
binding/transport implementation is open, in the same spirit as
`docs/KNOWN_ISSUES.md`'s KI-001.
