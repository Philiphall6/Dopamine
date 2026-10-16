import unittest
from types import SimpleNamespace

from analyze_agx_uppl_producer import (
    _recent_register_immediate,
    _recent_w2_immediate,
    analyze_gfx_handoff_consumers,
    analyze_gxf_map_producer,
    classify_retype_callback,
    collect_frame_type_names,
    collect_state_materializations,
    decode_domain_bitmap,
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
        raw[0x11] = 1
        raw[0x48:0x50] = (0x1111).to_bytes(8, "little")
        raw[0x50:0x58] = (0x2222).to_bytes(8, "little")
        self.assertEqual(
            decode_frame_type_policy_record(bytes(raw), 0x22),
            {
                "frame_type": 0x22,
                "flags": 1,
                "policy_class": 3,
                "state_flags": 0,
                "allowed_domain_bitmap": 0x84,
                "maximum_mapping_class": 2,
                "mapping_policy_byte_0x11": 1,
                "retype_in_encoded": 0x1111,
                "retype_out_encoded": 0x2222,
            },
        )

    def test_decodes_named_and_unknown_policy_domains(self) -> None:
        self.assertEqual(
            decode_domain_bitmap(0x84, {7: "uat"}),
            [{"id": 2, "name": None}, {"id": 7, "name": "uat"}],
        )

    def test_classifies_null_retype_callback(self) -> None:
        self.assertEqual(
            classify_retype_callback(
                [
                    object_instruction(0x1000, "bti", "c"),
                    object_instruction(0x1004, "ret"),
                ]
            ),
            "NO_OP",
        )

    def test_classifies_type_0x11_metadata_clear_callback(self) -> None:
        self.assertEqual(
            classify_retype_callback(
                [
                    object_instruction(0x2000, "bti", "c"),
                    object_instruction(0x2004, "ldrb", "w8, [x0, #2]"),
                    object_instruction(0x2008, "cmp", "w8, #0x11"),
                    object_instruction(0x200C, "b.ne", "#0x2014"),
                    object_instruction(0x2010, "strh", "wzr, [x0, #4]"),
                    object_instruction(0x2014, "ret"),
                ]
            ),
            "TYPE_0X11_METADATA_CLEAR",
        )

    def test_recovers_authenticated_frame_type_name_table(self) -> None:
        content = bytearray(0x200)
        names = {0: (0x100, "SPTM_UNTYPED"), 0xB: (0x108, "XNU_DEFAULT")}
        for frame_type, (address, _) in names.items():
            content[0x20 + frame_type * 8 : 0x28 + frame_type * 8] = (
                address.to_bytes(8, "little")
            )
        image = SimpleNamespace(
            binary=SimpleNamespace(
                sections=[
                    SimpleNamespace(content=content, virtual_address=0x2000)
                ]
            ),
            find_string=lambda value: [0x100] if value == "SPTM_UNTYPED" else [],
            resolve_chained_pointer=lambda encoded: encoded or None,
            read_u64=lambda address: int.from_bytes(
                content[address - 0x2000 : address - 0x2000 + 8], "little"
            ),
            read_cstring=lambda address: next(
                (name for target, name in names.values() if target == address), None
            ),
        )
        result = collect_frame_type_names(image)
        self.assertEqual(result["status"], "FRAME_TYPE_NAME_TABLE_CONFIRMED")
        self.assertEqual(result["table"], 0x2020)
        self.assertEqual(result["entries"][0xB]["name"], "XNU_DEFAULT")


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


class GxfProducerTests(unittest.TestCase):
    def test_traces_command_constructor_to_bootstrap_producer(self) -> None:
        instructions = [
            instruction(0x1000, "pacibsp"),
            instruction(0x1004, "mov", "w8, #0x10"),
            instruction(0x1008, "stur", "w8, [x29, #-0x10]"),
            instruction(0x100C, "bl", "#0x2000"),
            instruction(0x1010, "retab"),
            instruction(0x2000, "pacibsp"),
            instruction(0x2004, "bl", "#0x3000"),
            instruction(0x2008, "retab"),
            instruction(0x4000, "pacibsp"),
            instruction(0x4004, "bl", "#0x1000"),
            instruction(0x4008, "retab"),
            instruction(0x5000, "pacibsp"),
            instruction(0x5004, "bl", "#0x4000"),
            instruction(0x5008, "msr", "ttbr0_el1, x8"),
            instruction(0x500C, "retab"),
        ]
        image = SimpleNamespace(
            symbols={
                "__mmu_gxf_enter": 0x3000,
                "__rtk_arm_start_bootstrap_area": 0x5000,
            },
            segments=[SimpleNamespace(vmaddr=0x8000, content=b"\0" * 64)],
        )

        result = analyze_gxf_map_producer(image, instructions)

        self.assertEqual(result["constructor"], 0x1000)
        self.assertEqual(result["submit_wrapper"], 0x2000)
        self.assertEqual(result["serialized_wrapper"], 0x4000)
        self.assertEqual(
            result["producer_functions"],
            [
                {
                    "function": 0x5000,
                    "symbol": "__rtk_arm_start_bootstrap_area",
                    "role": "rtkit_bootstrap_translation_setup",
                    "markers": ["writes_ttbr0_el1"],
                    "callsites": [0x5004],
                }
            ],
        )
        self.assertFalse(result["direct_named_message_ingress_observed"])

    def test_recovers_handoff_queue_contract(self) -> None:
        instructions = [
            instruction(0x1000, "pacibsp"),
            instruction(0x1004, "cmp", "w21, #0x40"),
            instruction(0x1008, "mov", "w8, #0x18"),
            instruction(0x100C, "ldr", "w8, [x22, #0x20]!"),
            instruction(0x1010, "ldr", "x0, [x22, #8]"),
            instruction(0x1014, "ldr", "x1, [x22, #0x10]"),
            instruction(0x1018, "str", "w8, [x22]"),
            instruction(0x101C, "str", "w20, [x22]"),
            instruction(0x1020, "str", "wzr, [x19, #0x14]"),
            instruction(0x1024, "strb", "wzr, [x19, #0x11]"),
            instruction(0x1028, "retab"),
            instruction(0x2000, "pacibsp"),
            instruction(0x2004, "strb", "w8, [x19, #0x638]"),
            instruction(0x2008, "retab"),
            instruction(0x3000, "pacibsp"),
            instruction(0x3004, "strb", "wzr, [x19, #0x638]"),
            instruction(0x3008, "retab"),
        ]
        result = analyze_gfx_handoff_consumers(
            instructions,
            {
                "__rtk_mmu_uat_flush_request": 0x1000,
                "__rtk_mmu_uat_idle": 0x2000,
                "__rtk_mmu_uat_wake": 0x3000,
            },
        )

        self.assertEqual(result["status"], "HANDOFF_65_RECORD_FLUSH_QUEUE_CONFIRMED")
        self.assertEqual(result["record_count"], 65)
        self.assertEqual(result["record_payload_offsets"], [8, 0x10])


if __name__ == "__main__":
    unittest.main()
