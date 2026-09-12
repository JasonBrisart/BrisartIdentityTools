"""
File: hardware/base/biometric_binding.py

Purpose:
    Defines the contract for the ONE operation this project deliberately
    does not implement: the raw call into an operating system's own
    biometric subsystem (the Windows Biometric Framework/WinBio on
    Windows, libfprint + fprintd on Linux, or an equivalent vendor SDK
    where no OS-level framework exists). Every other piece of
    fingerprint-scanner logic -- device-name matching, retry policy,
    capture-result validation, and translation into this project's own
    exception hierarchy -- is implemented in pure Python, with zero OS
    or SDK calls, in hardware/biometric/fingerprint_scanner.py, and
    needs no binding at all to exercise that logic in isolation.

    Unlike ONVIF (an open network protocol with no OS-proprietary
    layer, see hardware/cameras/onvif_camera.py), there is no
    equivalent open wire protocol for fingerprint scanners. Every real
    capture path goes through an OS-owned biometric framework or a
    vendor SDK -- the same category of unavoidable wall PC/SC presents
    for smart-card readers. This module mirrors
    hardware/base/pcsc_binding.py's contract for exactly that reason.

    A BiometricBinding implementation is the one piece of code in this
    project's fingerprint-scanner support path that must call into
    OS-owned or vendor-owned, non-Brisart code. This project ships the
    CONTRACT only. Implementing it -- actually calling WinBio,
    libfprint/fprintd, or a vendor SDK -- is left to the organization
    deploying this software, on their own machine, under their own
    audit posture. See hardware/README.md, "Why the biometric binding
    is not shipped," for the full reasoning.

Communication relationships:
    Implemented by: an organization-supplied binding class (not part of
    this repository's shipped code), constructed and passed into
    hardware.biometric.fingerprint_scanner.FingerprintScanner's
    constructor.

    Called by: hardware.biometric.fingerprint_scanner.FingerprintScanner,
    which is the only file in this project that calls a
    BiometricBinding's methods. fingerprint_scanner.py contains no
    WinBio call, no D-Bus/fprintd call, no vendor SDK import, and no
    platform detection of its own -- all of that lives entirely on
    whichever binding an operator supplies.

Parameters / settings:
    None. This module defines an interface only; it has no
    configuration of its own.

Edge-case behavior:
    - BiometricBindingError is the single exception type a binding is
      expected to raise for any low-level failure (session
      establishment failure, device not found, capture timeout, no
      finger presented, sensor read failure, etc).
      fingerprint_scanner.py catches BiometricBindingError specifically
      and translates it into this project's own DeviceConnectionError
      hierarchy, so a caller of FingerprintScanner never needs to know
      or handle binding-specific exception types.
    - list_devices() is expected to return an empty list (not raise)
      when no scanners are attached; fingerprint_scanner.py treats
      that as "no device found," not as an error condition.
    - capture() is expected to return the FULL raw grayscale image as
      a dict of {"width": int, "height": int, "pixels": bytes}, with
      len(pixels) == width * height, one byte per pixel -- the same
      flat-grayscale-buffer convention
      biometrics/codecs/image_tools.py already uses throughout this
      project. The binding must not return a compressed format (JPEG,
      PNG, WSQ), a color image, or a partial buffer; converting a
      sensor's native output into this flat grayscale form is the
      binding's responsibility, not fingerprint_scanner.py's.
    - capture() must raise BiometricBindingError (not return an empty
      or all-zero buffer) if no finger was presented within the
      binding's own timeout, so fingerprint_scanner.py can distinguish
      "nothing happened" from "a genuinely blank capture."
"""
from abc import ABC, abstractmethod


class BiometricBindingError(Exception):
    """Raised by a BiometricBinding implementation for any low-level
    failure (session establishment, device listing, device open,
    capture timeout, no finger presented, or sensor read failure).
    fingerprint_scanner.py catches this exception type specifically
    and translates it into DeviceConnectionError / FingerNotPresentError."""


class BiometricBinding(ABC):
    """The raw biometric-subsystem operations
    hardware/biometric/fingerprint_scanner.py needs. An implementation
    of this class is the only place in a deployment of
    BrisartIdentityTools where OS-level or vendor-SDK biometric code
    (WinBio, libfprint/fprintd, or a vendor SDK) is called. This
    project ships no implementation of this class -- see
    hardware/README.md.
    """

    @abstractmethod
    def open_session(self) -> None:
        """Open a session with the biometric subsystem. Raise
        BiometricBindingError on failure."""

    @abstractmethod
    def close_session(self) -> None:
        """Close a previously opened session. Must not raise if no
        session is currently held."""

    @abstractmethod
    def list_devices(self) -> list:
        """Return a list of device name strings currently visible to
        the subsystem. Return an empty list (not an exception) if none
        are attached."""

    @abstractmethod
    def open_device(self, device_name: str) -> None:
        """Open the named scanner device. Raise BiometricBindingError
        if the device does not exist or fails to open."""

    @abstractmethod
    def close_device(self) -> None:
        """Close the currently open device, if any. Must not raise if
        nothing is currently open."""

    @abstractmethod
    def capture(self) -> dict:
        """Capture one fingerprint image from the currently open
        device and return {"width": int, "height": int, "pixels":
        bytes} -- flat, row-major, 8-bit grayscale, with
        len(pixels) == width * height. Raise BiometricBindingError if
        no finger is presented within the binding's own timeout, or on
        any other capture failure."""
