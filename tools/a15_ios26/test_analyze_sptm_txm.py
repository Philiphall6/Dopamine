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


def instruction(address, instruction_id, mnemonic, operands):
    return types.SimpleNamespace(
        address=address,
        id=instruction_id,
        mnemonic=mnemonic,
        operands=operands,
    )


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


if __name__ == "__main__":
    unittest.main()
