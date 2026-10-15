import unittest

from analyze_titan import (
    classify_linear_range_guard,
    classify_pacga_chain,
    conditional_branch_target,
    direct_branch_target,
    instruction_window,
    parse_immediate_operand,
    parse_shifted_immediate_operands,
    reconstruct_w_immediate_return,
)


def instruction(address: int, mnemonic: str, op_str: str = "") -> dict:
    return {
        "address": address,
        "size": 4,
        "mnemonic": mnemonic,
        "op_str": op_str,
    }


class GfxSecurityControlTests(unittest.TestCase):
    def test_classifies_comparison_guard(self) -> None:
        following = [
            instruction(0x1000, "ldr", "x2, [sp, #0x340]"),
            instruction(0x1004, "cmp", "x1, x2"),
            instruction(0x1008, "b.ne", "#0x1008"),
        ]
        self.assertEqual(
            classify_pacga_chain(following),
            "comparison_guard_candidate",
        )

    def test_classifies_signature_storage(self) -> None:
        following = [instruction(0x1000, "str", "x1, [x0, #0x340]")]
        self.assertEqual(
            classify_pacga_chain(following),
            "signature_storage_candidate",
        )

    def test_does_not_overclassify_unrelated_control_flow(self) -> None:
        following = [instruction(0x1000, "ret")]
        self.assertEqual(classify_pacga_chain(following), "unclassified")

    def test_instruction_window_is_bounded(self) -> None:
        instructions = [instruction(0x1000 + index * 4, "nop") for index in range(5)]
        self.assertEqual(
            instruction_window(instructions, 0x1008, before=1, after=1),
            ["0x1004: nop", "0x1008: nop", "0x100c: nop"],
        )

    def test_parses_capstone_immediate(self) -> None:
        self.assertEqual(parse_immediate_operand("#0x21"), 0x21)
        self.assertEqual(parse_immediate_operand("-1"), -1)
        self.assertIsNone(parse_immediate_operand("x8"))
        self.assertEqual(
            parse_shifted_immediate_operands(["#8", "lsl #12"]),
            0x8000,
        )

    def test_resolves_only_direct_branch_targets(self) -> None:
        self.assertEqual(
            direct_branch_target(instruction(0x1000, "bl", "#0x2000")),
            0x2000,
        )
        self.assertIsNone(direct_branch_target(instruction(0x1004, "braaz", "x4")))
        self.assertEqual(
            conditional_branch_target(
                instruction(0x1008, "cbz", "x4, #0x1040")
            ),
            0x1040,
        )

    def test_reconstructs_split_w0_error_status(self) -> None:
        body = [
            instruction(0x1000, "mov", "w0, #0xb"),
            instruction(0x1004, "movk", "w0, #0x8000, lsl #16"),
            instruction(0x1008, "ret"),
        ]
        self.assertEqual(
            reconstruct_w_immediate_return(body, 0x1000),
            0x8000000B,
        )

    def test_classifies_bounded_range_guard(self) -> None:
        body = [
            instruction(0x1000, "adds", "x21, x0, x1"),
            instruction(0x1004, "b.hs", "#0x1040"),
            instruction(0x1008, "cmp", "x11, x21"),
            instruction(0x100C, "ccmp", "x10, x20, #0, lo"),
            instruction(0x1010, "lsr", "x8, x8, #0x1c"),
            instruction(0x1014, "movk", "w0, #0x8003, lsl #16"),
        ]
        result = classify_linear_range_guard(body)
        self.assertEqual(result["status"], "RANGE_GUARD_CANDIDATE")
        self.assertTrue(result["high_address_limit"])

    def test_does_not_classify_plain_add_as_range_guard(self) -> None:
        result = classify_linear_range_guard(
            [instruction(0x1000, "adds", "x0, x0, x1")]
        )
        self.assertEqual(result["status"], "NOT_CLASSIFIED")


if __name__ == "__main__":
    unittest.main()
