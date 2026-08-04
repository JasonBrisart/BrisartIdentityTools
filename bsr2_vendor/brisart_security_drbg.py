from brisart_security_primitives import frame, sponge_hash


MINIMUM_SEED_BYTES = 64
MINIMUM_PERSONALIZATION_BYTES = 16
MAX_REQUEST_BYTES = 1024 * 1024
MAX_BYTES_BEFORE_RESEED = 16 * 1024 * 1024
RESEED_INTERVAL = 100_000


class BrisartDRBGError(ValueError):
    pass


class BrisartDRBG:
    """Fully custom deterministic research generator.

    This generator expands caller-provided seed material. It cannot create
    entropy. Its security cannot exceed the unpredictability of the seed.
    """

    def __init__(self, seed: bytes, personalization: bytes):
        self._require_seed(seed, "seed")
        if not isinstance(personalization, bytes):
            raise BrisartDRBGError("personalization must be bytes")
        if len(personalization) < MINIMUM_PERSONALIZATION_BYTES:
            raise BrisartDRBGError(
                "personalization must contain at least "
                f"{MINIMUM_PERSONALIZATION_BYTES} bytes"
            )

        initial = sponge_hash(
            frame(seed) + frame(personalization),
            128,
            b"BSR2/drbg-v2/instantiate",
        )
        self._state = bytearray(initial)
        self._counter = 0
        self._requests = 0
        self._generated_bytes = 0
        self._previous_block = None
        self._destroyed = False

    @staticmethod
    def _require_seed(seed: bytes, name: str) -> None:
        if not isinstance(seed, bytes):
            raise BrisartDRBGError(f"{name} must be bytes")
        if len(seed) < MINIMUM_SEED_BYTES:
            raise BrisartDRBGError(
                f"{name} must contain at least {MINIMUM_SEED_BYTES} bytes"
            )

    def _require_active(self) -> None:
        if self._destroyed:
            raise BrisartDRBGError("generator state has been destroyed")
        if self._requests >= RESEED_INTERVAL:
            raise BrisartDRBGError("generator reached its reseed interval")
        if self._generated_bytes >= MAX_BYTES_BEFORE_RESEED:
            raise BrisartDRBGError("generator reached its byte limit")

    def _preupdate(self, additional_input: bytes) -> None:
        self._state[:] = sponge_hash(
            frame(bytes(self._state))
            + frame(additional_input)
            + self._counter.to_bytes(16, "big"),
            128,
            b"BSR2/drbg-v2/preupdate",
        )

    def _next_block(self) -> bytes:
        counter = self._counter.to_bytes(16, "big")
        block = sponge_hash(
            frame(bytes(self._state)) + counter,
            64,
            b"BSR2/drbg-v2/output",
        )
        if self._previous_block is not None and block == self._previous_block:
            self.destroy()
            raise BrisartDRBGError(
                "continuous health check detected a repeated block"
            )

        next_state = sponge_hash(
            frame(bytes(self._state))
            + frame(block)
            + counter,
            128,
            b"BSR2/drbg-v2/postupdate",
        )
        self._state[:] = next_state
        self._previous_block = block
        self._counter += 1
        return block

    def generate(self, length: int, additional_input: bytes) -> bytes:
        self._require_active()
        if not isinstance(length, int) or length <= 0:
            raise BrisartDRBGError("length must be a positive integer")
        if length > MAX_REQUEST_BYTES:
            raise BrisartDRBGError("request exceeds the size limit")
        if not isinstance(additional_input, bytes) or not additional_input:
            raise BrisartDRBGError(
                "non-empty additional input is required for each request"
            )
        if self._generated_bytes + length > MAX_BYTES_BEFORE_RESEED:
            raise BrisartDRBGError("request would exceed the reseed byte limit")

        self._preupdate(additional_input)
        output = bytearray()
        while len(output) < length:
            output.extend(self._next_block())

        self._requests += 1
        self._generated_bytes += length
        return bytes(output[:length])

    def reseed(self, seed: bytes, additional_input: bytes) -> None:
        self._require_seed(seed, "reseed material")
        if not isinstance(additional_input, bytes) or not additional_input:
            raise BrisartDRBGError(
                "non-empty reseed additional input is required"
            )
        self._state[:] = sponge_hash(
            frame(bytes(self._state))
            + frame(seed)
            + frame(additional_input),
            128,
            b"BSR2/drbg-v2/reseed",
        )
        self._counter = 0
        self._requests = 0
        self._generated_bytes = 0
        self._previous_block = None
        self._destroyed = False

    def destroy(self) -> None:
        for index in range(len(self._state)):
            self._state[index] = 0
        self._counter = 0
        self._requests = RESEED_INTERVAL
        self._generated_bytes = MAX_BYTES_BEFORE_RESEED
        self._previous_block = None
        self._destroyed = True
