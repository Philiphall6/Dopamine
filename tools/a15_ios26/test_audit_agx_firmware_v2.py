import unittest
from types import SimpleNamespace

from audit_agx_firmware_v2 import (
    BASE_ENCODING,
    BASE_VTABLE,
    OBSERVED_ENCODING,
    OBSERVED_TARGET,
    OBSERVED_VTABLE,
    SLOT_OFFSET,
    verify_static_link,
)


class FakeImage:
    def __init__(self, observed_encoding=OBSERVED_ENCODING):
        self.slots = {
            OBSERVED_VTABLE + SLOT_OFFSET: observed_encoding,
            BASE_VTABLE + SLOT_OFFSET: BASE_ENCODING,
        }
        self.instructions = {
            0xfffffff00884bde8: ("add", "x16, x16, #0xaa8"),
            0xfffffff00884bdec: ("add", "x16, x16, #0x10"),
            0xfffffff00884bdfc: ("str", "x16, [x19]"),
            0xfffffff0087fd464: ("ldr", "x0, [x8, #0x4a0]"),
            0xfffffff0087fd488: ("ldr", "x1, [x10]"),
            0xfffffff0087fd4b4: ("ldr", "x9, [x16, #0x210]"),
            0xfffffff0087fd4c4: ("blraa", "x9, x17"),
            0xfffffff0087fd4cc: ("str", "x0, [x21]"),
            OBSERVED_TARGET: ("bti", "c"),
            OBSERVED_TARGET + 4: ("mov", "x0, x1"),
            OBSERVED_TARGET + 8: ("ret", ""),
        }

    def read_u64(self, address):
        return self.slots.get(address)

    def references_to(self, address):
        return [SimpleNamespace(address=0xfffffff00884bde8)] if address == OBSERVED_VTABLE - 0x10 else []

    def instruction_at(self, address):
        return SimpleNamespace(mnemonic=self.instructions[address][0], op_str=self.instructions[address][1])


class FirmwareLinkTests(unittest.TestCase):
    def test_exact_link(self):
        self.assertEqual(verify_static_link(FakeImage())["callback_target"], f"{OBSERVED_TARGET:#x}")

    def test_different_live_slot_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_static_link(FakeImage(observed_encoding=BASE_ENCODING))

    def test_changed_caller_is_rejected(self):
        image = FakeImage()
        image.instructions[0xfffffff0087fd4b4] = ("ldr", "x9, [x16, #0x218]")
        with self.assertRaises(ValueError):
            verify_static_link(image)


if __name__ == "__main__":
    unittest.main()
