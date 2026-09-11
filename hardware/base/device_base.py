"""
File: hardware/base/device_base.py

Purpose
-------
Defines the root interface used by all hardware devices.

All future hardware integrations must inherit from DeviceBase so
the remainder of BrisartIdentityTools can communicate with hardware
through a consistent API.

This file intentionally contains no vendor-specific logic.
"""

from abc import ABC, abstractmethod


class DeviceBase(ABC):
    """
    Base class for all supported hardware devices.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def connect(self) -> bool:
        pass

    @abstractmethod
    def disconnect(self) -> None:
        pass

    @abstractmethod
    def health_check(self) -> bool:
        pass