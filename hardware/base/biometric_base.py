"""
Base interface for biometric devices.
"""

from abc import abstractmethod

from hardware.base.device_base import DeviceBase


class BiometricBase(DeviceBase):

    @abstractmethod
    def scan(self):
        pass