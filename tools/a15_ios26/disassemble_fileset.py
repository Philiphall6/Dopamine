#!/usr/bin/env python3
"""Disassemble an unslid virtual-address range from an Apple fileset kernelcache."""

from __future__ import annotations

import argparse
import pathlib
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernelcache", type=pathlib.Path)
    parser.add_argument("addresses", nargs="+", type=lambda value: int(value, 0))
    parser.add_argument("--size", type=lambda value: int(value, 0), default=0x80)
    parser.add_argument("--capstone-path", type=pathlib.Path)
    args = parser.parse_args()

    if args.capstone_path:
        sys.path.insert(0, str(args.capstone_path.resolve()))
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

    lief.logging.disable()
    container = lief.parse(str(args.kernelcache))
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    for address in args.addresses:
        owner = None
        code = None
        for binary in container.filesets:
            code = mapped_bytes(binary, address, args.size)
            if code is not None:
                owner = binary
                break
        if code is None:
            print(f"address=0x{address:x}: not mapped")
            continue

        print(f"address=0x{address:x} fileset={owner.fileset_name}")
        for instruction in disassembler.disasm(code, address):
            print(
                f"  0x{instruction.address:x}: "
                f"{instruction.mnemonic:<9} {instruction.op_str}"
            )
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
