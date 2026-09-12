"""
File: hardware/card_readers/pcsc_reader.py

Purpose:
    A ReaderBase implementation for any PC/SC-compliant smart card
    reader, containing every piece of logic this project can implement
    in pure Python with zero OS calls: reader-name matching, retry
    policy, GET_UID APDU construction, status-word validation, and hex
    encoding of the ATR/UID. This file deliberately goes no further than
    that boundary. It does not import ctypes, does not detect the
    platform, and does not call winscard.dll, PCSC.framework, or
    libpcsclite itself.

    The one operation this file cannot do in pure Python -- actually
    talking to the OS's PC/SC service -- is delegated to a
    hardware.base.pcsc_binding.PCSCBinding instance supplied by the
    caller at construction time. This project ships the contract for
    that binding (hardware/base/pcsc_binding.py) but no implementation
    of it. See hardware/README.md, "Why the OS binding is not shipped,"
    for why that line is drawn here specifically.

Communication relationships:
    Called by: hardware.hardware_manager.HardwareManager, once
    registered via hardware.registry.register() (not automatic -- see
    hardware/README.md), and constructed with a PCSCBinding instance the
    operator supplies.

    Calls out to: ONLY the PCSCBinding instance passed into its
    constructor. This file contains no ctypes import, no
    sys.platform check, and no OS library name anywhere in its source.
    Every method on this class is plain Python: string matching,
    integer/byte comparisons, retry loops, and hex encoding.

    Does NOT call into biometrics/, vault/, packages/, or crypto/.

Why the binding is required, not optional, at construction:
    A caller with no PCSCBinding implementation cannot use this class,
    by design -- there is no default, no silent fallback, and no
    partially-working mode. Requiring the binding explicitly is what
    keeps this file itself free of any OS call: it never has to ask
    "which platform am I on" because it never makes a platform-specific
    decision at all.

Parameters / settings:
    CONNECT_RETRY_COUNT (int, 1):
        One retry absorbs a transient "card present but not yet
        settled" condition without masking a genuinely absent or
        faulty reader. This retry is pure Python control flow -- it
        does not touch the binding differently on retry than on first
        attempt.

Edge-case behavior:
    - __init__ raises TypeError immediately if `binding` is not a
      PCSCBinding instance, so a misconfigured caller fails at
      construction, not on the first real read_card() call.
    - connect() calls binding.establish_context() and
      binding.list_readers(); a PCSCBindingError from either is
      translated into DeviceConnectionError with the original exception
      attached as __cause__, and connect() itself returns False rather
      than propagating the exception, consistent with DeviceBase's
      contract that connect() is a boolean probe.
    - read_card() returns raw ATR and UID bytes as hex strings --
      decode-only, no interpretation of what the UID means to the
      caller, matching this project's existing image/biometric codec
      convention of separating transport decoding from meaning.
    - A "no card present" condition (the binding's connect() or
      transmit() raising PCSCBindingError) raises CardAbsentError
      (a DeviceConnectionError subclass), never returns None, so a
      caller cannot mistake "no card" for "card returned no data."
    - This file does not know or care whether its binding is a real
      OS-calling implementation, a mock used for testing, or a
      simulator -- it only ever calls the five PCSCBinding methods, so
      hardware/tests/test_device_contract.py can exercise this entire
      class's logic (retry, APDU construction, status-word checking)
      against a fake in-memory binding with zero OS involvement at all.
"""
from hardware.base.pcsc_binding import PCSCBinding, PCSCBindingError
from hardware.base.reader_base import ReaderBase
from hardware.exceptions import DeviceConnectionError

CONNECT_RETRY_COUNT = 1

# Widely-supported PC/SC APDU to request a card's UID from most
# contactless (ISO 14443) cards. Not universal across every card type.
_GET_UID_APDU = bytes([0xFF, 0xCA, 0x00, 0x00, 0x00])
_STATUS_OK = (0x90, 0x00)


class CardAbsentError(DeviceConnectionError):
    """Raised when read_card() is called but no card is present, or the
    presented card did not respond to the GET_UID APDU."""


class PCSCReader(ReaderBase):
    """A ReaderBase adapter for any PC/SC-compliant smart card reader.

    Contains 100% pure Python logic: reader-name matching, retries,
    APDU construction, and status-word checking. Makes zero OS calls
    itself -- every operation that must touch winscard.dll,
    PCSC.framework, or libpcsclite is delegated to the required
    `binding` argument, an implementation of
    hardware.base.pcsc_binding.PCSCBinding supplied by the caller.
    """

    def __init__(self, binding: PCSCBinding, reader_name_contains=None):
        if not isinstance(binding, PCSCBinding):
            raise TypeError(
                "PCSCReader requires a hardware.base.pcsc_binding."
                "PCSCBinding instance; got "
                f"{type(binding).__name__!r} instead. This project "
                "ships the binding CONTRACT only -- see "
                "hardware/README.md, 'Why the OS binding is not "
                "shipped,' for how to supply one."
            )
        self._binding = binding
        self._reader_name_contains = reader_name_contains
        self._reader_name = None
        self._connected = False
        self.last_error = None

    @property
    def name(self) -> str:
        if self._reader_name is not None:
            return f"PC/SC Reader ({self._reader_name})"
        return "PC/SC Reader (not connected)"

    def connect(self) -> bool:
        try:
            self._binding.establish_context()
            self._connected = True
            reader_name = self._find_reader_name()
            if reader_name is None:
                raise DeviceConnectionError(
                    "no PC/SC readers were reported by the binding, or "
                    f"none matched {self._reader_name_contains!r}."
                )
            self._reader_name = reader_name
            self.last_error = None
            return True
        except (PCSCBindingError, DeviceConnectionError) as exc:
            self.last_error = exc
            self.disconnect()
            return False

    def _find_reader_name(self):
        try:
            names = self._binding.list_readers()
        except PCSCBindingError as exc:
            raise DeviceConnectionError(
                f"binding.list_readers() failed: {exc}"
            ) from exc
        if not names:
            return None
        if self._reader_name_contains:
            needle = self._reader_name_contains.lower()
            matches = [n for n in names if needle in n.lower()]
            return matches[0] if matches else None
        return names[0]

    def disconnect(self) -> None:
        try:
            self._binding.disconnect()
        except PCSCBindingError:
            pass  # best-effort teardown
        if self._connected:
            try:
                self._binding.release_context()
            except PCSCBindingError:
                pass  # best-effort teardown
        self._connected = False
        self._reader_name = None

    def health_check(self) -> bool:
        if self._reader_name is None or not self._connected:
            return False
        try:
            current_name = self._find_reader_name()
            self.last_error = None
            return current_name == self._reader_name
        except DeviceConnectionError as exc:
            self.last_error = exc
            return False

    def read_card(self) -> dict:
        if self._reader_name is None:
            raise DeviceConnectionError(
                f"{self.name} is not connected; call connect() first."
            )
        last_exception = None
        for _attempt in range(CONNECT_RETRY_COUNT + 1):
            try:
                self._binding.connect(self._reader_name)
                atr_bytes = self._binding.get_atr()
                raw_response = self._binding.transmit(_GET_UID_APDU)
                if len(raw_response) < 2:
                    raise DeviceConnectionError(
                        "binding.transmit() returned fewer than 2 "
                        "bytes; no status word present."
                    )
                response_body, sw1, sw2 = (
                    raw_response[:-2], raw_response[-2], raw_response[-1]
                )
                if (sw1, sw2) != _STATUS_OK:
                    raise DeviceConnectionError(
                        f"GET_UID APDU failed with status "
                        f"{sw1:02X}{sw2:02X}."
                    )
                self.last_error = None
                return {
                    "atr_hex": atr_bytes.hex().upper(),
                    "uid_hex": response_body.hex().upper(),
                }
            except (PCSCBindingError, DeviceConnectionError) as exc:
                last_exception = exc
        self.last_error = last_exception
        raise CardAbsentError(
            f"no card detected on {self.name}: {last_exception}"
        )
