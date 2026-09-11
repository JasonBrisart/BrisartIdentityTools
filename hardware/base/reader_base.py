"""
Base interface for access card readers.
"""

from abc import abstractmethod

from hardware.base.device_base import DeviceBase


class ReaderBase(DeviceBase):

    @abstractmethod
    def read_card(self):
        pass