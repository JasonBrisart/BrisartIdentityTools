"""
File: hardware/base/pcsc_binding.py

Purpose:
    Defines the contract for the ONE operation this project deliberately
    does not implement: the raw call into an operating system's own
    PC/SC service (winscard.dll on Windows, PCSC.framework on macOS,
    libpcsclite on Linux). Every other piece of smart-card logic --
    reader-name matching, retry policy, APDU construction, status-word
    checking, hex encoding -- is implemented in pure Python, with zero
    OS calls, in hardware/card_readers/pcsc_reader.py, and needs no
    binding at all to run its own unit tests.

    A PCSCBinding implementation is the one piece of code in this
    project's smart-card support path that must call into OS-owned,
    non-Brisart code. This project ships the CONTRACT only.
    Implementing it -- actually calling winscard.dll, PCSC.framework, or
    libpcsclite -- is left to the organization deploying this software,
    on their own machine, under their own audit posture. See
    hardware/README.md, "Why the OS binding is not shipped," for the
    full reasoning.

Communication relationships:
    Implemented by: an organization-supplied binding class (not part of
    this repository's shipped code), constructed and passed into
    hardware.card_readers.pcsc_reader.PCSCReader's constructor.

    Called by: hardware.card_readers.pcsc_reader.PCSCReader, which is
    the only file in this project that calls a PCSCBinding's methods.
    pcsc_reader.py contains no ctypes, no platform detection, and no
    OS-library loading of its own -- all of that lives entirely on
    whichever binding an operator supplies.

Parameters / settings:
    None. This module defines an interface only; it has no
    configuration of its own.

Edge-case behavior:
    - PCSCBindingError is the single exception type a binding is
      expected to raise for any low-level failure (context
      establishment failure, reader not found, transmit failure, etc).
      pcsc_reader.py catches PCSCBindingError specifically and
      translates it into this project's own DeviceConnectionError
      hierarchy, so a caller of PCSCReader never needs to know or
      handle binding-specific exception types.
    - list_readers() is expected to return an empty list (not raise)
      when no readers are attached; pcsc_reader.py treats that as "no
      reader found," not as an error condition.
    - transmit() is expected to return the FULL raw response including
      the trailing two-byte status word (SW1 SW2); pcsc_reader.py, not
      the binding, is responsible for splitting the status word from
      the response body.
"""
from abc import ABC, abstractmethod


class PCSCBindingError(Exception):
    """Raised by a PCSCBinding implementation for any low-level PC/SC
    failure (context establishment, reader listing, connect, transmit).
    pcsc_reader.py catches this exception type specifically and
    translates it into DeviceConnectionError / CardAbsentError."""


class PCSCBinding(ABC):
    """The raw PC/SC operations hardware/card_readers/pcsc_reader.py
    needs. An implementation of this class is the only place in a
    deployment of BrisartIdentityTools where OS-level PC/SC code
    (winscard.dll / PCSC.framework / libpcsclite) is called. This
    project ships no implementation of this class -- see
    hardware/README.md.
    """

    @abstractmethod
    def establish_context(self) -> None:
        """Open a PC/SC context. Raise PCSCBindingError on failure."""

    @abstractmethod
    def release_context(self) -> None:
        """Release a previously established context. Must not raise if
        no context is currently held."""

    @abstractmethod
    def list_readers(self) -> list:
        """Return a list of reader name strings currently visible to
        the OS. Return an empty list (not an exception) if none are
        attached."""

    @abstractmethod
    def connect(self, reader_name: str) -> None:
        """Connect to the card currently present in the named reader.
        Raise PCSCBindingError if no card is present or the connect
        fails for any other reason."""

    @abstractmethod
    def disconnect(self) -> None:
        """Disconnect from the currently connected card, if any. Must
        not raise if nothing is currently connected."""

    @abstractmethod
    def get_atr(self) -> bytes:
        """Return the ATR (Answer To Reset) of the currently connected
        card. Raise PCSCBindingError if nothing is connected."""

    @abstractmethod
    def transmit(self, apdu: bytes) -> bytes:
        """Send an APDU to the currently connected card and return the
        FULL raw response, including the trailing SW1 SW2 status word.
        Raise PCSCBindingError on any transmission failure."""
