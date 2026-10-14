#!/usr/bin/env python3
"""Locate ARM64 code references to stripped vtable addresses in a fileset kernelcache."""

from __future__ import annotations

import argparse
import pathlib
import struct
import sys

import lief

UINT64_MASK = (1 << 64) - 1


def decode_adrp(address: int, instruction: int) -> int:
    immhi = (instruction >> 5) & 0x7FFFF
    immlo = (instruction >> 29) & 0x3
    immediate = ((immhi << 2) | immlo) << 12
    if immediate & (1 << 32):
        immediate -= 1 << 33
    return ((address & ~0xFFF) + immediate) & UINT64_MASK


def decode_add(adrp_address: int, adrp: int, add: int) -> int | None:
    if adrp & 0x9F000000 != 0x90000000:
        return None
    if add & 0xFF000000 != 0x91000000:
        return None
    register = adrp & 0x1F
    if ((add >> 5) & 0x1F) != register:
        return None
    shift = 12 if ((add >> 22) & 1) else 0
    immediate = ((add >> 10) & 0xFFF) << shift
    return (decode_adrp(adrp_address, adrp) + immediate) & UINT64_MASK


def decode_ldr(adrp_address: int, adrp: int, ldr: int) -> int | None:
    """Decode an ADRP followed by a 64-bit unsigned-immediate LDR."""
    if adrp & 0x9F000000 != 0x90000000:
        return None
    if ldr & 0xFFC00000 != 0xF9400000:
        return None
    register = adrp & 0x1F
    if ((ldr >> 5) & 0x1F) != register:
        return None
    immediate = ((ldr >> 10) & 0xFFF) << 3
    return (decode_adrp(adrp_address, adrp) + immediate) & UINT64_MASK


def segment_bytes(binary, name: str) -> tuple[int, bytes]:
    segment = next(segment for segment in binary.segments if segment.name == name)
    return int(segment.virtual_address), bytes(segment.content)


def mapped_bytes(binary, address: int, size: int) -> bytes | None:
    for segment in binary.segments:
        start = int(segment.virtual_address)
        content = bytes(segment.content)
        offset = address - start
        if 0 <= offset and offset + size <= len(content):
            return content[offset : offset + size]
    return None


def mapped_string(binary, address: int) -> str | None:
    for section in binary.sections:
        start = int(section.virtual_address)
        content = bytes(section.content)
        offset = address - start
        if offset < 0 or offset >= len(content):
            continue
        end = content.find(b"\0", offset, min(len(content), offset + 160))
        if end < 0:
            return None
        raw = content[offset:end]
        if len(raw) < 4 or any(byte < 0x20 or byte > 0x7E for byte in raw):
            return None
        return raw.decode("ascii")
    return None


def nearby_strings(binary, text_address: int, text: bytes, hit: int) -> list[tuple[int, str]]:
    start = max(0, hit - text_address - 0x300)
    end = min(len(text) - 8, hit - text_address + 0x300)
    strings: dict[int, str] = {}
    for offset in range(start - (start % 4), end + 1, 4):
        first, second = struct.unpack_from("<II", text, offset)
        target = decode_add(text_address + offset, first, second)
        if target is None:
            continue
        value = mapped_string(binary, target)
        if value is not None:
            strings[target] = value
    return sorted(strings.items())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("kernelcache", type=pathlib.Path)
    parser.add_argument("targets", nargs="+", type=lambda value: int(value, 0))
    parser.add_argument("--fileset", default="com.apple.AGXG14P")
    parser.add_argument("--capstone-path", type=pathlib.Path)
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--context-before", type=lambda value: int(value, 0), default=0x40)
    parser.add_argument("--context-after", type=lambda value: int(value, 0), default=0x60)
    parser.add_argument("--field-offset", type=lambda value: int(value, 0))
    parser.add_argument("--base-register")
    parser.add_argument("--dump-qwords", type=int, default=0)
    args = parser.parse_args()

    if args.capstone_path:
        sys.path.insert(0, str(args.capstone_path.resolve()))
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

    lief.logging.disable()
    container = lief.parse(str(args.kernelcache))
    binary = next(entry for entry in container.filesets if entry.fileset_name == args.fileset)
    text_address, text = segment_bytes(binary, "__TEXT_EXEC")
    targets = set(args.targets)
    hits: list[tuple[int, int]] = []

    if args.dump_qwords:
        for target in args.targets:
            content = mapped_bytes(binary, target, args.dump_qwords * 8)
            if content is None:
                print(f"target=0x{target:x}: not mapped")
                continue
            print(f"target=0x{target:x} qwords:")
            for index, value in enumerate(struct.unpack(f"<{args.dump_qwords}Q", content)):
                print(f"  +0x{index * 8:03x}: 0x{value:016x}")

    for offset in range(0, len(text) - 8, 4):
        first, second = struct.unpack_from("<II", text, offset)
        target = decode_add(text_address + offset, first, second)
        if target is None:
            target = decode_ldr(text_address + offset, first, second)
        if target in targets:
            hits.append((text_address + offset, target))

    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    print(f"fileset={binary.fileset_name} text=0x{text_address:x} hits={len(hits)}")
    for address, target in hits:
        print(f"\ntarget=0x{target:x} xref=0x{address:x}")
        if not args.summary:
            context_start = max(text_address, address - args.context_before)
            context_end = min(text_address + len(text), address + args.context_after)
            context = text[context_start - text_address : context_end - text_address]
            instructions = list(disassembler.disasm(context, context_start))
            if args.field_offset is None:
                selected = {instruction.address for instruction in instructions}
            else:
                needle = (
                    f"[{args.base_register}, #0x{args.field_offset:x}]"
                    if args.base_register
                    else f"#0x{args.field_offset:x}]"
                )
                matches = [
                    index
                    for index, instruction in enumerate(instructions)
                    if needle in instruction.op_str
                ]
                selected = {
                    instructions[index].address
                    for match in matches
                    for index in range(max(0, match - 6), min(len(instructions), match + 7))
                }
            previous_printed = None
            for instruction in instructions:
                if instruction.address not in selected:
                    continue
                if previous_printed is not None and instruction.address != previous_printed + 4:
                    print("  ...")
                marker = ">" if instruction.address == address else " "
                print(
                    f"{marker} 0x{instruction.address:x}: "
                    f"{instruction.mnemonic:<9} {instruction.op_str}"
                )
                previous_printed = instruction.address
        strings = nearby_strings(binary, text_address, text, address)
        if strings:
            print("  nearby strings:")
            for string_address, value in strings:
                print(f"    0x{string_address:x}: {value}")


if __name__ == "__main__":
    main()
