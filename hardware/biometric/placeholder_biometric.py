"""
Placeholder biometric implementation.
"""

from hardware.base.biometric_base import BiometricBase


class PlaceholderBiometric(BiometricBase):

    @property
    def name(self):
        return "Placeholder Biometric"

    def connect(self):
        return True

    def disconnect(self):
        pass

    def health_check(self):
        return True

    def scan(self):
        return None
