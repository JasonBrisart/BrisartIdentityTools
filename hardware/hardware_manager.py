"""
File: hardware/hardware_manager.py

Purpose:
    Central hardware manager. The single entry point between the rest
    of BrisartIdentityTools and any registered hardware driver.

    This file never constructs a driver's network/OS connection itself
    -- it only looks up whatever class was registered under a name and
    instantiates it with whatever arguments the caller supplies. For a
    zero-argument placeholder (PlaceholderCamera, PlaceholderReader,
    PlaceholderBiometric), that means create_device(name) alone is
    enough. For a real driver (PCSCReader, ONVIFCamera,
    FingerprintScanner), each of which requires a caller-supplied
    binding/transport object at construction time (see
    hardware/base/pcsc_binding.py, hardware/base/onvif_transport.py,
    hardware/base/biometric_binding.py), the caller passes that object
    through create_device() exactly as they would to the driver class
    directly.

    HardwareManager itself never imports, constructs, or knows about
    any concrete PCSCBinding, ONVIFTransport, or BiometricBinding
    implementation. It has no knowledge of networks, sockets, or
    operating-system libraries of any kind.

Communication relationships:
    Called by: any code that wants a device by its registered name
    instead of importing and constructing a driver class directly.

    Calls out to: hardware.registry.get(), and then whatever class that
    lookup returns. Does not call into biometrics/, vault/, packages/,
    or crypto/.

Parameters / settings:
    None.

Edge-case behavior:
    - create_device() raises ValueError if the requested name was never
      registered via hardware.registry.register() -- this is
      unchanged from before.
    - create_device() forwards *args/**kwargs directly to the
      registered class's constructor. A caller instantiating a real
      driver (PCSCReader, ONVIFCamera, FingerprintScanner) must supply
      that driver's required binding/transport argument here, the same
      way they would calling the class directly -- HardwareManager
      does not supply a default, a mock, or any fallback of its own.
    - A registered class whose constructor requirements are not met by
      the arguments passed to create_device() raises whatever error
      that class's own __init__ raises (e.g. PCSCReader/ONVIFCamera/
      FingerprintScanner's own TypeError for a missing or wrong-typed
      binding/transport) -- HardwareManager does not catch or
      reinterpret that error.
"""
from hardware.registry import get


class HardwareManager:
    def create_device(self, device_name: str, *args, **kwargs):
        device_class = get(device_name)
        if device_class is None:
            raise ValueError(
                f"Hardware device '{device_name}' is not registered."
            )
        return device_class(*args, **kwargs)
