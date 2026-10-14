#!/usr/bin/env python3
"""Inspect field accesses made by methods referenced from a kernel vtable.

This is an offline diagnostic. It decodes the low 32-bit target used by the
authenticated chained pointers in the inspected iOS 26 kernelcache and never
executes code from the image.
"""

from __future__ import annotations

import argparse
import pathlib
import struct
import sys

import lief


def mapped_bytes(binary, address: int, size: int) -> bytes | None:
    for segment in binary.segments:
        start = int(segment.virtual_address)
        content = bytes(segment.content)
        offset = address - start
        if 0 <= offset and offset + size <= len(content):
            return content[offset : offset + size]
    return None


def fileset_mapped_bytes(container, address: int, size: int):
    """Return the fileset and bytes that own an unslid virtual address."""
    for binary in container.filesets:
        content = mapped_bytes(binary, address, size)
        if content is not None:
            return binary, content
    return None, None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernelcache", type=pathlib.Path)
    parser.add_argument("vtable", type=lambda value: int(value, 0))
    parser.add_argument(
        "--kernel-base",
        type=lambda value: int(value, 0),
        help="fileset-container image base (defaults to the Mach-O image base)",
    )
    parser.add_argument("--fileset", default="com.apple.AGXG14P")
    parser.add_argument("--entries", type=int, default=96)
    parser.add_argument("--max-method-size", type=lambda value: int(value, 0), default=0x1000)
    parser.add_argument("--fields", nargs="+", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--base-registers", nargs="+")
    parser.add_argument("--capstone-path", type=pathlib.Path)
    args = parser.parse_args()

    if args.capstone_path:
        sys.path.insert(0, str(args.capstone_path.resolve()))
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
    from capstone.arm64 import ARM64_OP_MEM

    lief.logging.disable()
    container = lief.parse(str(args.kernelcache))
    kernel_base = args.kernel_base or int(container.imagebase)
    binary = next(entry for entry in container.filesets if entry.fileset_name == args.fileset)
    raw_vtable = mapped_bytes(binary, args.vtable, args.entries * 8)
    if raw_vtable is None:
        raise SystemExit(f"vtable 0x{args.vtable:x} is not mapped")

    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    disassembler.detail = True
    seen: set[int] = set()
    hits = 0
    for index, encoded in enumerate(struct.unpack(f"<{args.entries}Q", raw_vtable)):
        if encoded == 0:
            continue
        target = kernel_base + (encoded & 0xFFFFFFFF)
        if target in seen:
            continue
        seen.add(target)
        method_binary, code = fileset_mapped_bytes(container, target, args.max_method_size)
        if code is None:
            continue
        instructions = []
        for instruction in disassembler.disasm(code, target):
            instructions.append(instruction)
            if instruction.mnemonic in {"ret", "retab"}:
                break
        for instruction_index, instruction in enumerate(instructions):
            memory_operands = [
                operand
                for operand in instruction.operands
                if operand.type == ARM64_OP_MEM and operand.mem.disp in args.fields
            ]
            if args.base_registers:
                memory_operands = [
                    operand
                    for operand in memory_operands
                    if instruction.reg_name(operand.mem.base) in args.base_registers
                ]
            if not memory_operands:
                continue
            for operand in memory_operands:
                hits += 1
                base = instruction.reg_name(operand.mem.base)
                print(
                    f"entry=0x{index * 8:x} method=0x{target:x} "
                    f"fileset={method_binary.fileset_name} "
                    f"field=0x{operand.mem.disp:x} base={base} "
                    f"access=0x{instruction.address:x}"
                )
                for context in instructions[
                    max(0, instruction_index - 5) : min(len(instructions), instruction_index + 6)
                ]:
                    marker = ">" if context.address == instruction.address else " "
                    print(
                        f"{marker} 0x{context.address:x}: "
                        f"{context.mnemonic:<9} {context.op_str}"
                    )
                print()

    print(f"scanned_methods={len(seen)} field_accesses={hits}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
