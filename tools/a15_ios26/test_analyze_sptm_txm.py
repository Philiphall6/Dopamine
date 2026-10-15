#!/usr/bin/env python3

import types
import unittest

import capstone

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


if __name__ == "__main__":
    unittest.main()
