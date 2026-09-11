"""
Hardware-related exceptions.
"""


class HardwareError(Exception):
    pass


class DeviceConnectionError(HardwareError):
    pass


class UnsupportedDeviceError(HardwareError):
    pass