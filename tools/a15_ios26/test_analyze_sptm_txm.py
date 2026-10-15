#!/usr/bin/env python3

import types
import unittest

import capstone
from capstone.arm64 import (
    ARM64_REG_W0,
    ARM64_REG_W2,
    ARM64_REG_W9,
    ARM64_REG_W10,
    ARM64_REG_X0,
    ARM64_REG_X1,
    ARM64_REG_X2,
    ARM64_REG_X3,
    ARM64_REG_X9,
    ARM64_REG_X10,
    ARM64_REG_X16,
)

import analyze_sptm_txm as analyzer


def reg(register: int):
    return types.SimpleNamespace(type=capstone.CS_OP_REG, reg=register)


def imm(value: int, shift: int = 0):
    return types.SimpleNamespace(
        type=capstone.CS_OP_IMM,
        imm=value,
        shift=types.SimpleNamespace(value=shift),
    )


def mem(base: int, displacement: int):
    return types.SimpleNamespace(
        type=capstone.CS_OP_MEM,
        mem=types.SimpleNamespace(base=base, disp=displacement),
    )


def instruction(
    address,
    instruction_id,
    mnemonic,
    operands,
    raw=b"\0\0\0\0",
    op_str="",
    register_names=None,
):
    result = types.SimpleNamespace(
        address=address,
        id=instruction_id,
        mnemonic=mnemonic,
        operands=operands,
        bytes=raw,
        op_str=op_str,
    )
    result.reg_name = lambda register: (register_names or {}).get(register, "")
    return result


class ResolverTests(unittest.TestCase):
    def test_resolves_direct_adr_with_memory_displacement(self):
        image = analyzer.MachOImage.__new__(analyzer.MachOImage)
        base_register = 10
        image.instructions = [
            instruction(
                0x1000,
                analyzer.ARM64_INS_ADR,
                "adr",
                [reg(base_register), imm(0x5000)],
            ),
            instruction(
                0x1004,
                analyzer.ARM64_INS_LDRB,
                "ldrb",
                [reg(11), mem(base_register, 0x26)],
            ),
        ]
        image._instruction_index = {
            item.address: i for i, item in enumerate(image.instructions)
        }

        self.assertEqual(image.resolve_data_reference(0x1004), 0x5026)


class FrameTypePolicyTests(unittest.TestCase):
    def test_collects_movk_immediate_masks(self):
        frame_register = 9
        mask_register = 10
        source = instruction(
            0x2000,
            analyzer.ARM64_INS_LDRB,
            "ldrb",
            [reg(frame_register), mem(8, 2)],
        )
        image = types.SimpleNamespace()
        image.instructions = [
            source,
            instruction(
                0x2004,
                analyzer.ARM64_INS_CMP,
                "cmp",
                [reg(frame_register), imm(20)],
            ),
            instruction(
                0x2008,
                analyzer.ARM64_INS_MOV,
                "mov",
                [reg(mask_register), imm(0x100)],
            ),
            instruction(0x200C, 1, "movk", [reg(mask_register), imm(0x6, 16)]),
            instruction(0x2010, 1, "tst", [reg(frame_register), reg(mask_register)]),
            instruction(
                0x2014,
                analyzer.ARM64_INS_MOV,
                "mov",
                [reg(mask_register), imm(0x200)],
            ),
            instruction(0x2018, 1, "movk", [reg(mask_register), imm(0x18, 16)]),
            instruction(0x201C, 1, "tst", [reg(frame_register), reg(mask_register)]),
        ]
        image._instruction_index = {
            item.address: i for i, item in enumerate(image.instructions)
        }

        policy = analyzer._collect_immediate_mask_policy(image, source)

        self.assertEqual(policy["kind"], "immediate_bitmask")
        self.assertEqual(policy["frame_type_source_offset"], 2)
        self.assertEqual(policy["max_frame_type"], 20)
        self.assertEqual(
            [entry["mask"] for entry in policy["mask_tests"]],
            [0x00060100, 0x00180200],
        )


class EntrySequenceTests(unittest.TestCase):
    def test_decodes_apple_genter_immediates(self):
        self.assertEqual(
            analyzer._decode_apple_genter_immediate(bytes.fromhex("20142000")),
            0,
        )
        self.assertEqual(
            analyzer._decode_apple_genter_immediate(bytes.fromhex("24142000")),
            4,
        )
        self.assertIsNone(
            analyzer._decode_apple_genter_immediate(bytes.fromhex("00142000"))
        )

    def test_decodes_apple_gexit_separately(self):
        self.assertEqual(
            analyzer._decode_apple_gexit_immediate(bytes.fromhex("00142000")),
            0,
        )
        self.assertIsNone(
            analyzer._decode_apple_gexit_immediate(bytes.fromhex("20142000"))
        )

    def test_collects_only_svc_zero(self):
        image = analyzer.MachOImage.__new__(analyzer.MachOImage)
        image.instructions = [
            instruction(
                0x3000,
                analyzer.ARM64_INS_SVC,
                "svc",
                [imm(0)],
                bytes.fromhex("010000d4"),
                "#0",
            ),
            instruction(
                0x3004,
                analyzer.ARM64_INS_SVC,
                "svc",
                [imm(0x25)],
                bytes.fromhex("a10400d4"),
                "#0x25",
            ),
        ]
        image._instruction_index = {
            item.address: i for i, item in enumerate(image.instructions)
        }
        image.function_start = lambda address: 0x3000
        image.branches_to = lambda address: []
        image.window = lambda address, before, after: [f"window:{address:x}"]

        entries = analyzer._collect_svc_zero_entries(image)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["address"], 0x3000)
        self.assertEqual(entries[0]["opcode"], "010000d4")

    def test_reconstructs_complete_x16_movk_constant(self):
        x16 = 16
        names = {x16: "x16"}
        image = analyzer.MachOImage.__new__(analyzer.MachOImage)
        image.instructions = [
            instruction(
                0x4000,
                1,
                "movk",
                [reg(x16), imm(0, 48)],
                op_str="x16, #0, lsl #48",
                register_names=names,
            ),
            instruction(
                0x4004,
                1,
                "movk",
                [reg(x16), imm(1, 32)],
                op_str="x16, #1, lsl #32",
                register_names=names,
            ),
            instruction(
                0x4008,
                1,
                "movk",
                [reg(x16), imm(0, 16)],
                op_str="x16, #0, lsl #16",
                register_names=names,
            ),
            instruction(
                0x400C,
                1,
                "movk",
                [reg(x16), imm(3)],
                op_str="x16, #3",
                register_names=names,
            ),
            instruction(0x4010, analyzer.ARM64_INS_B, "b", [imm(0x5000)]),
        ]
        image._instruction_index = {
            item.address: i for i, item in enumerate(image.instructions)
        }

        descriptor = analyzer._reconstruct_x16_constant_before(image, 0x4010)

        self.assertEqual(descriptor["value"], 0x0000000100000003)
        self.assertEqual(len(descriptor["writes"]), 4)


class DispatchMetadataTests(unittest.TestCase):
    def test_collects_candidates_ingress_and_guards(self):
        image = analyzer.MachOImage.__new__(analyzer.MachOImage)
        image.instructions = [
            instruction(0x3000, 1, "pacibsp", []),
            instruction(
                0x3004,
                analyzer.ARM64_INS_CMP,
                "cmp",
                [reg(1), imm(16)],
                op_str="w1, #0x10",
            ),
            instruction(0x3008, 1, "b.hs", [imm(0x3040)], op_str="#0x3040"),
            instruction(0x300C, 1, "retab", []),
            instruction(0x3100, 1, "pacibsp", []),
        ]
        image._instruction_index = {
            item.address: i for i, item in enumerate(image.instructions)
        }
        image.function_start = lambda address: 0x3000
        image.calls_to = lambda address: [0x2000]
        image.branches_to = lambda address: [0x2000, 0x2010]
        image.references_to = lambda address: []
        image.window = lambda address, before=6, after=8: [f"window:{address:x}"]

        anchors, functions = analyzer._annotate_dispatch_anchors(
            image,
            [
                {
                    "address": 0x5000,
                    "value": "validate_sptm_dispatch_table_id",
                    "references": [
                        {"address": 0x3008, "target": 0x5000, "kind": "adr"}
                    ],
                }
            ],
        )

        self.assertEqual(anchors[0]["function_candidates"], [0x3000])
        self.assertEqual(functions[0]["direct_calls"], [0x2000])
        self.assertEqual(functions[0]["direct_branches"], [0x2010])
        self.assertEqual(
            [guard["mnemonic"] for guard in functions[0]["guards"]],
            ["cmp", "b.hs"],
        )
        self.assertEqual(functions[0]["guards"][1]["branch_target"], 0x3040)

    def test_collects_signed_pointer_registration_context(self):
        x16 = 16
        names = {ARM64_REG_W0: "w0", ARM64_REG_W2: "w2", x16: "x16"}
        image = analyzer.MachOImage.__new__(analyzer.MachOImage)
        image.instructions = [
            instruction(
                0x1000,
                analyzer.ARM64_INS_ADR,
                "adr",
                [reg(x16), imm(0x3000)],
            ),
            instruction(
                0x1004,
                1,
                "paciza",
                [reg(x16)],
                op_str="x16",
                register_names=names,
            ),
            instruction(
                0x1008,
                analyzer.ARM64_INS_MOV,
                "mov",
                [reg(ARM64_REG_W0), imm(1)],
                op_str="w0, #1",
                register_names=names,
            ),
            instruction(
                0x100C,
                analyzer.ARM64_INS_MOV,
                "mov",
                [reg(ARM64_REG_W2), imm(4)],
                op_str="w2, #4",
                register_names=names,
            ),
            instruction(
                0x1010,
                analyzer.ARM64_INS_BL,
                "bl",
                [imm(0x2000)],
                op_str="#0x2000",
                register_names=names,
            ),
        ]
        image._instruction_index = {
            item.address: i for i, item in enumerate(image.instructions)
        }
        image.references_to = lambda target: [
            analyzer.Reference(0x1000, target, "adr")
        ]
        image.function_start = lambda address: 0x1000
        image.window = lambda address, before=6, after=8: [f"window:{address:x}"]

        references = analyzer._collect_pointer_references(image, 0x3000)

        self.assertEqual(references[0]["nearby_auth"][0]["mnemonic"], "paciza")
        self.assertEqual(references[0]["nearby_calls"][0]["target"], 0x2000)
        self.assertEqual(
            references[0]["nearby_calls"][0]["arguments"]["x0"]["value"],
            1,
        )
        self.assertEqual(
            references[0]["nearby_calls"][0]["arguments"]["x2"]["value"],
            4,
        )

    def test_preserves_dynamic_registration_argument_sources(self):
        names = {
            ARM64_REG_X0: "x0",
            ARM64_REG_X1: "x1",
            ARM64_REG_X2: "x2",
            ARM64_REG_X3: "x3",
        }
        image = analyzer.MachOImage.__new__(analyzer.MachOImage)
        image.instructions = [
            instruction(
                0x2000,
                analyzer.ARM64_INS_MOV,
                "mov",
                [reg(ARM64_REG_X0), reg(ARM64_REG_X1)],
                op_str="x0, x1",
                register_names=names,
            ),
            instruction(
                0x2004,
                analyzer.ARM64_INS_MOV,
                "mov",
                [reg(ARM64_REG_X2), reg(ARM64_REG_X3)],
                op_str="x2, x3",
                register_names=names,
            ),
            instruction(
                0x2008,
                analyzer.ARM64_INS_BL,
                "bl",
                [imm(0x3000)],
                op_str="#0x3000",
                register_names=names,
            ),
        ]
        image._instruction_index = {
            item.address: i for i, item in enumerate(image.instructions)
        }

        x0 = analyzer._recover_immediate_argument(image, 0x2008, 0)
        x2 = analyzer._recover_immediate_argument(image, 0x2008, 2)

        self.assertIsNone(x0["value"])
        self.assertEqual(x0["source_register"], "x1")
        self.assertIsNone(x2["value"])
        self.assertEqual(x2["source_register"], "x3")

    def test_recovers_static_adr_argument(self):
        names = {ARM64_REG_X1: "x1"}
        image = analyzer.MachOImage.__new__(analyzer.MachOImage)
        image.instructions = [
            instruction(
                0x2100,
                analyzer.ARM64_INS_ADR,
                "adr",
                [reg(ARM64_REG_X1), imm(0x9000)],
                op_str="x1, #0x9000",
                register_names=names,
            ),
            instruction(
                0x2104,
                analyzer.ARM64_INS_BL,
                "bl",
                [imm(0x3000)],
                op_str="#0x3000",
                register_names=names,
            ),
        ]
        image._instruction_index = {
            item.address: i for i, item in enumerate(image.instructions)
        }

        argument = analyzer._recover_immediate_argument(image, 0x2104, 1)

        self.assertEqual(argument["value"], 0x9000)
        self.assertIsNone(argument["source_register"])

    def test_skips_non_writing_branch_when_tracing_argument(self):
        base = 22
        names = {ARM64_REG_X2: "x2", base: "x22"}
        image = analyzer.MachOImage.__new__(analyzer.MachOImage)
        image.instructions = [
            instruction(
                0x2200,
                analyzer.ARM64_INS_LDR,
                "ldr",
                [reg(ARM64_REG_X2), mem(base, 0x38)],
                op_str="x2, [x22, #0x38]",
                register_names=names,
            ),
            instruction(
                0x2204,
                1,
                "cbz",
                [reg(ARM64_REG_X2), imm(0x2300)],
                op_str="x2, #0x2300",
                register_names=names,
            ),
            instruction(
                0x2208,
                analyzer.ARM64_INS_BL,
                "bl",
                [imm(0x3000)],
                op_str="#0x3000",
                register_names=names,
            ),
        ]
        image._instruction_index = {
            item.address: i for i, item in enumerate(image.instructions)
        }

        argument = analyzer._recover_immediate_argument(image, 0x2208, 2)

        self.assertEqual(argument["definition"]["address"], 0x2200)
        self.assertEqual(argument["definition"]["mnemonic"], "ldr")

    def test_collects_authenticated_tail_trampoline(self):
        image = analyzer.MachOImage.__new__(analyzer.MachOImage)
        image.instructions = [
            instruction(0x3000, 1, "pacibsp", []),
            instruction(
                0x3004,
                analyzer.ARM64_INS_B,
                "b",
                [imm(0x5000)],
                op_str="#0x5000",
            ),
            instruction(0x3100, 1, "pacibsp", []),
            instruction(0x5000, 1, "bti", [], op_str="c"),
            instruction(0x5004, 1, "blraaz", [reg(11)], op_str="x11"),
            instruction(0x5008, 1, "retab", []),
        ]
        image._instruction_index = {
            item.address: i for i, item in enumerate(image.instructions)
        }
        image.window = lambda address, before=6, after=8: [f"window:{address:x}"]

        paths = analyzer._collect_authenticated_transfer_paths(image, 0x3000)

        self.assertEqual(paths["tail_trampolines"][0]["target"], 0x5000)
        self.assertEqual(
            paths["tail_trampolines"][0]["authenticated_transfers"][0][
                "mnemonic"
            ],
            "blraaz",
        )


class IommuDescriptorTests(unittest.TestCase):
    def test_decodes_null_terminated_authenticated_endpoint_table(self):
        table = 0x3000
        imagebase = 0x100000000
        values = {
            table: 0x8020000000000120,
            table + 8: 0,
            table + 0x10: 0x84C0000000000240,
            table + 0x18: 7,
            table + 0x20: 0,
            table + 0x28: 0,
        }
        image = types.SimpleNamespace(
            read_u64=lambda address: values.get(address),
            resolve_chained_pointer=lambda encoded: (
                imagebase + (encoded & 0xFFFFFFFF) if encoded else None
            ),
        )

        result = analyzer._summarize_iommu_endpoint_table(
            image,
            table,
            {imagebase + 0x120: ["sptm_uat_init_state"]},
        )

        self.assertEqual(result["entry_stride"], 0x10)
        self.assertEqual(result["entry_count"], 2)
        self.assertTrue(result["terminated_by_null_entry"])
        self.assertEqual(
            result["entries"][0]["pointer_encoding"],
            "authenticated_chained",
        )
        self.assertEqual(
            result["entries"][0]["anchors"],
            ["sptm_uat_init_state"],
        )
        self.assertEqual(
            result["entries"][0]["primary_anchors"],
            ["sptm_uat_init_state"],
        )
        self.assertEqual(result["entries"][1]["metadata"], 7)

    def test_decodes_dispatch_ids_and_permission_masks(self):
        descriptor = 0x2000
        imagebase = 0x100000000
        values = {
            descriptor: 0x1000000000000120,
            descriptor + 0x30: 3,
            descriptor + 0x38: 0x3000000000000300,
            descriptor + 0x40: 0x3000000000000400,
        }
        image = types.SimpleNamespace(
            imagebase=imagebase,
            read_u64=lambda address: values.get(address, 0),
            resolve_chained_pointer=lambda encoded: (
                imagebase + (encoded & 0xFFFFFFFF) if encoded else None
            ),
            read_cstring=lambda address: (
                "t8110dart" if address == imagebase + 0x120 else None
            ),
        )

        result = analyzer._summarize_iommu_descriptor(
            image, descriptor, (2, 8)
        )

        self.assertEqual(result["name"], "t8110dart")
        self.assertEqual(result["table_id_offset"], 0x30)
        self.assertEqual(
            [entry["table_id"] for entry in result["registrations"]],
            [3, 4],
        )
        self.assertEqual(
            [entry["permission_mask"] for entry in result["registrations"]],
            [2, 8],
        )

    def test_recovers_permission_masks_from_registration_stores(self):
        image = analyzer.MachOImage.__new__(analyzer.MachOImage)
        image.instructions = [
            instruction(
                0x3000,
                analyzer.ARM64_INS_MOV,
                "mov",
                [reg(ARM64_REG_W10), imm(2)],
                op_str="w10, #2",
                register_names={ARM64_REG_W10: "w10"},
            ),
            instruction(
                0x3004,
                1,
                "stp",
                [reg(ARM64_REG_X16), reg(ARM64_REG_X10), mem(12, 0)],
                op_str="x16, x10, [x12]",
                register_names={
                    ARM64_REG_X16: "x16",
                    ARM64_REG_X10: "x10",
                },
            ),
            instruction(
                0x3008,
                analyzer.ARM64_INS_MOV,
                "mov",
                [reg(ARM64_REG_W9), imm(8)],
                op_str="w9, #8",
                register_names={ARM64_REG_W9: "w9"},
            ),
            instruction(
                0x300C,
                1,
                "stp",
                [reg(ARM64_REG_X16), reg(ARM64_REG_X9), mem(8, 0)],
                op_str="x16, x9, [x8]",
                register_names={
                    ARM64_REG_X16: "x16",
                    ARM64_REG_X9: "x9",
                },
            ),
        ]
        image._instruction_index = {
            item.address: i for i, item in enumerate(image.instructions)
        }

        result = analyzer._collect_stored_permission_masks(image, 0x3000)

        self.assertEqual(result, [2, 8])


if __name__ == "__main__":
    unittest.main()
