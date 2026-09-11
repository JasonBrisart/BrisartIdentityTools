"""
Base interface for camera devices.
"""

from abc import abstractmethod

from hardware.base.device_base import DeviceBase


class CameraBase(DeviceBase):

    @abstractmethod
    def capture_image(self):
        pass