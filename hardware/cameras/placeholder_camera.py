"""
Placeholder camera implementation.

Used only for testing architecture until
real camera vendors are supported.
"""

from hardware.base.camera_base import CameraBase


class PlaceholderCamera(CameraBase):

    @property
    def name(self):
        return "Placeholder Camera"

    def connect(self):
        return True

    def disconnect(self):
        pass

    def health_check(self):
        return True

    def capture_image(self):
        return None