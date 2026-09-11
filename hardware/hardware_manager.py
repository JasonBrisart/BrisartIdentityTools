"""
Central hardware manager.

Acts as the single entry point between BrisartIdentityTools
and hardware implementations.
"""

from hardware.registry import get


class HardwareManager:

    def create_device(self, device_name: str):
        device_class = get(device_name)

        if device_class is None:
            raise ValueError(
                f"Hardware device '{device_name}' is not registered."
            )

        return device_class()