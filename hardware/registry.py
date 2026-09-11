"""
Stores available device registrations.
"""

_DEVICE_REGISTRY = {}


def register(device_name: str, device_class):
    _DEVICE_REGISTRY[device_name] = device_class


def get(device_name: str):
    return _DEVICE_REGISTRY.get(device_name)


def list_registered():
    return sorted(_DEVICE_REGISTRY.keys())