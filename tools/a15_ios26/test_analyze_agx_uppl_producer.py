import unittest
from types import SimpleNamespace

from analyze_agx_uppl_producer import (
    _recent_register_immediate,
    _recent_w2_immediate,
    collect_state_materializations,
    decode_frame_type_policy_record,
    decode_patch_descriptor_bytes,
    recover_selector_type_pairs,
)


def instruction(address: int, mnemonic: str, op_str: str = "") -> dict:
    return {
        "address": address,
        "size": 4,
        "mnemonic": mnemonic,
        "op_str": op_str,
    }


def object_instruction(address: int, mnemonic: str, op_str: str = ""):
    return SimpleNamespace(address=address, mnemonic=mnemonic, op_str=op_str)


class PatchDescriptorTests(unittest.TestCase):
    def test_decodes_only_the_declared_value_width(self) -> None:
        raw = b"StpG" + (8).to_bytes(4, "little") + (0x4000).to_bytes(8, "little")
        self.assertEqual(
            decode_patch_descriptor_bytes(raw),
            {"tag": "StpG", "width": 8, "default": 0x4000},
        )

    def test_rejects_unknown_width(self) -> None:
        with self.assertRaises(ValueError):
            decode_patch_descriptor_bytes(b"BAD!" + (3).to_bytes(4, "little") + b"abc")

    def test_decodes_frame_type_mapping_policy(self) -> None:
        raw = bytearray(0x60)
        raw[:3] = bytes((1, 3, 0))
        raw[8:16] = (0x84).to_bytes(8, "little")
        raw[0x10] = 2
        self.assertEqual(
            decode_frame_type_policy_record(bytes(raw), 0x22),
            {
                "frame_type": 0x22,
                "flags": 1,
                "policy_class": 3,
                "state_flags": 0,
                "allowed_domain_bitmap": 0x84,
                "maximum_mapping_class": 2,
            },
        )


class StateReferenceTests(unittest.TestCase):
    def test_classifies_adrp_add_read(self) -> None:
        body = [
            instruction(0x1000, "adrp", "x8, #0x5000"),
            instruction(0x1004, "add", "x8, x8, #0x148"),
            instruction(0x1008, "ldp", "x9, x10, [x8]"),
        ]
        references = collect_state_materializations(body, 0x5148)
        self.assertEqual(len(references), 1)
        self.assertEqual(references[0]["kind"], "read")

    def test_classifies_direct_page_store(self) -> None:
        body = [
            instruction(0x2000, "adrp", "x9, #0x6000"),
            instruction(0x2004, "stp", "x0, x1, [x9, #0x148]"),
        ]
        references = collect_state_materializations(body, 0x6148)
        self.assertEqual(len(references), 1)
        self.assertEqual(references[0]["kind"], "write")


class RegistrationCallTests(unittest.TestCase):
    def test_recovers_existing_region_type_selector_pair(self) -> None:
        body = [
            object_instruction(0x2FD0, "cmp", "w8, #2"),
            object_instruction(0x2FD4, "b.eq", "#0x2fe0"),
            object_instruction(0x2FD8, "nop"),
            object_instruction(0x2FE0, "mov", "w8, #1"),
        ]
        self.assertEqual(
            recover_selector_type_pairs(body),
            [
                {
                    "existing_region_type": 2,
                    "registration_selector": 1,
                    "compare": 0x2FD0,
                    "selector_assignment": 0x2FE0,
                }
            ],
        )

    def test_recovers_w1_type_selector_before_call(self) -> None:
        body = [
            object_instruction(0x2FF0, "mov", "x0, x19"),
            object_instruction(0x2FF4, "mov", "w1, #0x42"),
            object_instruction(0x2FF8, "bl", "#0x9000"),
        ]
        self.assertEqual(_recent_register_immediate(body, 2, "w1"), 0x42)

    def test_recovers_selector_before_registration_call(self) -> None:
        body = [
            object_instruction(0x3000, "mov", "x0, x19"),
            object_instruction(0x3004, "mov", "w2, #2"),
            object_instruction(0x3008, "bl", "#0x9000"),
        ]
        self.assertEqual(_recent_w2_immediate(body, 2), 2)

    def test_selector_search_is_bounded(self) -> None:
        body = [object_instruction(0x4000, "mov", "w2, #1")]
        body.extend(
            object_instruction(0x4004 + index * 4, "nop") for index in range(12)
        )
        body.append(object_instruction(0x4034, "bl", "#0x9000"))
        self.assertIsNone(_recent_w2_immediate(body, len(body) - 1))


if __name__ == "__main__":
    unittest.main()
