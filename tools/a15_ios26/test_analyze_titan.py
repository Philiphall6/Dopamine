import unittest

from analyze_titan import classify_pacga_chain, instruction_window


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


if __name__ == "__main__":
    unittest.main()
