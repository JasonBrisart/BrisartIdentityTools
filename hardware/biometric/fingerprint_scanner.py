"""
File: hardware/biometric/fingerprint_scanner.py

Purpose:
    A BiometricBase implementation for any fingerprint scanner reachable
    through an organization-supplied biometric binding, containing every
    piece of logic this project can implement in pure Python with zero
    OS or SDK calls: device-name matching, retry policy, and validation
    of a capture result's shape before handing it back to the caller.
    This file deliberately goes no further than that boundary. It does
    not import ctypes, does not detect the platform, does not speak
    D-Bus, and does not import any vendor SDK.

    The one operation this file cannot do in pure Python -- actually
    talking to a physical fingerprint scanner through the OS's own
    biometric subsystem or a vendor SDK -- is delegated to a
    hardware.base.biometric_binding.BiometricBinding instance supplied
    by the caller at construction time. This project ships the contract
    for that binding (hardware/base/biometric_binding.py) but no
    implementation of it, mirroring the same boundary
    hardware/card_readers/pcsc_reader.py already draws for smart-card
    readers. See hardware/README.md, "Why the biometric binding is not
    shipped," for why that line is drawn here specifically.

Communication relationships:
    Called by: hardware.hardware_manager.HardwareManager, once
    registered via hardware.registry.register() (not automatic -- see
    hardware/README.md), and constructed with a BiometricBinding
    instance the operator supplies.

    Calls out to: ONLY the BiometricBinding instance passed into its
    constructor. This file contains no WinBio call, no D-Bus/fprintd
    call, no vendor SDK import, and no sys.platform check anywhere in
    its source. Every method on this class is plain Python: string
    matching, retry loops, and dict-shape validation.

    Does NOT call into biometrics/ (the application-layer enroll/verify
    engine), vault/, packages/, or crypto/. This file has zero knowledge
    of identity records, sealed templates, or BSR2 -- it produces a raw
    grayscale image, matching the same flat-buffer convention
    biometrics/codecs/image_tools.py already uses, and nothing more.
    Wiring a captured image into that engine's enroll_identity/
    verify_identity pipeline is the caller's responsibility, not this
    file's.

Why the binding is required, not optional, at construction:
    A caller with no BiometricBinding implementation cannot use this
    class, by design -- there is no default, no silent fallback, and no
    partially-working mode. Requiring the binding explicitly is what
    keeps this file itself free of any OS or SDK call: it never has to
    ask "which platform am I on" or "which vendor SDK is installed"
    because it never makes that decision at all.

Parameters / settings:
    CAPTURE_RETRY_COUNT (int, 1):
        One retry absorbs a transient "finger not fully placed / lifted
        too early" condition without masking a genuinely absent finger
        or faulty scanner. This retry is pure Python control flow -- it
        does not touch the binding differently on retry than on first
        attempt.

Edge-case behavior:
    - __init__ raises TypeError immediately if `binding` is not a
      BiometricBinding instance, so a misconfigured caller fails at
      construction, not on the first real scan() call.
    - connect() calls binding.open_session() and binding.list_devices();
      a BiometricBindingError from either is translated into
      DeviceConnectionError, and connect() itself returns False rather
      than propagating the exception, consistent with DeviceBase's
      contract that connect() is a boolean probe.
    - scan() validates the binding's capture() return value has the
      exact expected shape ("width", "height", "pixels" keys, and
      len(pixels) == width * height) before returning it, raising
      DeviceConnectionError with a specific message if a binding
      returns a malformed result -- so a buggy binding fails loudly at
      this boundary rather than handing a silently-corrupt image
      downstream into biometrics/codecs/image_tools.py.
    - A "no finger presented" condition (the binding's capture()
      raising BiometricBindingError) raises FingerNotPresentError (a
      DeviceConnectionError subclass), never returns None or a blank
      buffer, so a caller cannot mistake "no finger" for "finger that
      scanned as all-black."
    - This file does not know or care whether its binding is a real
      OS/SDK-calling implementation, a mock used for testing, or a
      simulator -- it only ever calls the six BiometricBinding methods,
      so this entire class's logic (retry, shape validation) is fully
      testable against a minimal fake binding with zero OS or SDK
      involvement at all.
"""
from hardware.base.biometric_base import BiometricBase
from hardware.base.biometric_binding import (
    BiometricBinding,
    BiometricBindingError,
)
from hardware.exceptions import DeviceConnectionError

CAPTURE_RETRY_COUNT = 1


class FingerNotPresentError(DeviceConnectionError):
    """Raised when scan() is called but no finger was presented to the
    scanner within the binding's own timeout, or the binding otherwise
    failed to produce a capture."""


class FingerprintScanner(BiometricBase):
    """A BiometricBase adapter for any fingerprint scanner reachable
    through an organization-supplied binding.

    Contains 100% pure Python logic: device-name matching, retries, and
    capture-result shape validation. Makes zero OS or SDK calls itself
    -- every operation that must touch WinBio, libfprint/fprintd, or a
    vendor SDK is delegated to the required `binding` argument, an
    implementation of hardware.base.biometric_binding.BiometricBinding
    supplied by the caller.
    """

    def __init__(self, binding: BiometricBinding, device_name_contains=None):
        if not isinstance(binding, BiometricBinding):
            raise TypeError(
                "FingerprintScanner requires a hardware.base."
                "biometric_binding.BiometricBinding instance; got "
                f"{type(binding).__name__!r} instead. This project "
                "ships the binding CONTRACT only -- see "
                "hardware/README.md, 'Why the biometric binding is "
                "not shipped,' for how to supply one."
            )
        self._binding = binding
        self._device_name_contains = device_name_contains
        self._device_name = None
        self._session_open = False
        self.last_error = None

    @property
    def name(self) -> str:
        if self._device_name is not None:
            return f"Fingerprint Scanner ({self._device_name})"
        return "Fingerprint Scanner (not connected)"

    def connect(self) -> bool:
        try:
            self._binding.open_session()
            self._session_open = True
            device_name = self._find_device_name()
            if device_name is None:
                raise DeviceConnectionError(
                    "no fingerprint scanners were reported by the "
                    f"binding, or none matched "
                    f"{self._device_name_contains!r}."
                )
            self._binding.open_device(device_name)
            self._device_name = device_name
            self.last_error = None
            return True
        except (BiometricBindingError, DeviceConnectionError) as exc:
            self.last_error = exc
            self.disconnect()
            return False

    def _find_device_name(self):
        try:
            names = self._binding.list_devices()
        except BiometricBindingError as exc:
            raise DeviceConnectionError(
                f"binding.list_devices() failed: {exc}"
            ) from exc
        if not names:
            return None
        if self._device_name_contains:
            needle = self._device_name_contains.lower()
            matches = [n for n in names if needle in n.lower()]
            return matches[0] if matches else None
        return names[0]

    def disconnect(self) -> None:
        try:
            self._binding.close_device()
        except BiometricBindingError:
            pass  # best-effort teardown
        if self._session_open:
            try:
                self._binding.close_session()
            except BiometricBindingError:
                pass  # best-effort teardown
        self._session_open = False
        self._device_name = None

    def health_check(self) -> bool:
        if self._device_name is None or not self._session_open:
            return False
        try:
            current_name = self._find_device_name()
            self.last_error = None
            return current_name == self._device_name
        except DeviceConnectionError as exc:
            self.last_error = exc
            return False

    def scan(self) -> dict:
        if self._device_name is None:
            raise DeviceConnectionError(
                f"{self.name} is not connected; call connect() first."
            )
        last_exception = None
        for _attempt in range(CAPTURE_RETRY_COUNT + 1):
            try:
                result = self._binding.capture()
                self._validate_capture_shape(result)
                self.last_error = None
                return result
            except (BiometricBindingError, DeviceConnectionError) as exc:
                last_exception = exc
        self.last_error = last_exception
        raise FingerNotPresentError(
            f"no finger detected on {self.name}: {last_exception}"
        )

    @staticmethod
    def _validate_capture_shape(result) -> None:
        if not isinstance(result, dict):
            raise DeviceConnectionError(
                "binding.capture() must return a dict; got "
                f"{type(result).__name__!r}."
            )
        missing = {"width", "height", "pixels"} - result.keys()
        if missing:
            raise DeviceConnectionError(
                f"binding.capture() result is missing key(s): "
                f"{sorted(missing)}."
            )
        width, height, pixels = (
            result["width"], result["height"], result["pixels"]
        )
        if not isinstance(width, int) or not isinstance(height, int):
            raise DeviceConnectionError(
                "binding.capture()'s width/height must be int."
            )
        if not isinstance(pixels, (bytes, bytearray)):
            raise DeviceConnectionError(
                "binding.capture()'s pixels must be bytes."
            )
        if len(pixels) != width * height:
            raise DeviceConnectionError(
                f"binding.capture() returned {len(pixels)} pixel "
                f"bytes; expected width*height = {width * height}."
            )
