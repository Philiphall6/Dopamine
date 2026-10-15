#!/usr/bin/env python3
"""Resolve image-relative panic offsets against Mach-O symbol tables."""

from __future__ import annotations

import argparse
import bisect
import json
import pathlib
import struct
import uuid


FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_UUID = 0x1B
N_STAB = 0xE0
N_TYPE = 0x0E
N_SECT = 0x0E


def require_range(data: bytes, offset: int, size: int, label: str) -> memoryview:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"{label} exceeds file bounds")
    return memoryview(data)[offset : offset + size]


def select_arm64_slice(data: bytes) -> tuple[memoryview, int, int]:
    if len(data) < 8:
        raise ValueError("file is too small")
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return memoryview(data), 0, len(data)

    nfat_arch = struct.unpack_from(">I", data, 4)[0]
    arch_size = 32 if magic == FAT_MAGIC_64 else 20
    table_size = 8 + nfat_arch * arch_size
    require_range(data, 0, table_size, "fat architecture table")
    candidates: list[tuple[int, int, int]] = []
    for index in range(nfat_arch):
        cursor = 8 + index * arch_size
        if magic == FAT_MAGIC_64:
            cputype, cpusubtype, offset, size, _, _ = struct.unpack_from(">iiQQII", data, cursor)
        else:
            cputype, cpusubtype, offset, size, _ = struct.unpack_from(">iiIII", data, cursor)
        require_range(data, offset, size, "fat Mach-O slice")
        if cputype == CPU_TYPE_ARM64:
            candidates.append((cpusubtype, offset, size))
    if not candidates:
        raise ValueError("fat binary has no arm64 slice")

    # Prefer arm64e (subtype 2) when present because the on-device process uses it.
    cpusubtype, offset, size = next(
        (candidate for candidate in candidates if candidate[0] & 0x00FFFFFF == 2),
        candidates[0],
    )
    return require_range(data, offset, size, "selected Mach-O slice"), offset, cpusubtype


def c_string(data: memoryview, offset: int, limit: int) -> str:
    raw = bytes(require_range(data, offset, limit - offset, "string table entry"))
    terminator = raw.find(b"\0")
    if terminator < 0:
        raise ValueError("unterminated string table entry")
    return raw[:terminator].decode("utf-8", errors="replace")


def load_symbols(path: pathlib.Path) -> dict[str, object]:
    file_data = path.read_bytes()
    data, slice_offset, cpusubtype = select_arm64_slice(file_data)
    if len(data) < 32:
        raise ValueError("Mach-O slice is smaller than its header")

    magic, cputype, thin_subtype, _, ncmds, sizeofcmds, _, _ = struct.unpack_from(
        "<IiiIIIII", data, 0
    )
    if magic != MH_MAGIC_64 or cputype != CPU_TYPE_ARM64:
        raise ValueError("selected slice is not a little-endian 64-bit arm64 Mach-O")
    if slice_offset == 0:
        cpusubtype = thin_subtype

    command_offset = 32
    command_end = command_offset + sizeofcmds
    require_range(data, command_offset, sizeofcmds, "load command table")
    text_vmaddr: int | None = None
    symtab: tuple[int, int, int, int] | None = None
    image_uuid: str | None = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", require_range(data, command_offset, 8, "load command"))
        if cmdsize < 8 or command_offset + cmdsize > command_end:
            raise ValueError("invalid load command size")
        command = require_range(data, command_offset, cmdsize, "load command")
        if cmd == LC_SEGMENT_64 and cmdsize >= 72:
            segname = bytes(command[8:24]).split(b"\0", 1)[0]
            if segname == b"__TEXT":
                text_vmaddr = struct.unpack_from("<Q", command, 24)[0]
        elif cmd == LC_SYMTAB and cmdsize >= 24:
            _, _, symoff, nsyms, stroff, strsize = struct.unpack_from("<IIIIII", command)
            symtab = (symoff, nsyms, stroff, strsize)
        elif cmd == LC_UUID and cmdsize >= 24:
            image_uuid = str(uuid.UUID(bytes=bytes(command[8:24]))).upper()
        command_offset += cmdsize

    if text_vmaddr is None or symtab is None:
        raise ValueError("Mach-O lacks __TEXT or LC_SYMTAB")
    symoff, nsyms, stroff, strsize = symtab
    require_range(data, symoff, nsyms * 16, "symbol table")
    require_range(data, stroff, strsize, "string table")

    symbols: list[tuple[int, str]] = []
    for index in range(nsyms):
        strx, n_type, _, _, n_value = struct.unpack_from("<IBBHQ", data, symoff + index * 16)
        if n_type & N_STAB or (n_type & N_TYPE) != N_SECT or not n_value or strx >= strsize:
            continue
        name = c_string(data, stroff + strx, stroff + strsize) if strx else ""
        if name and n_value >= text_vmaddr:
            symbols.append((n_value - text_vmaddr, name.lstrip("_")))
    symbols.sort()
    return {
        "path": str(path),
        "uuid": image_uuid,
        "cpusubtype": cpusubtype,
        "text_vmaddr": text_vmaddr,
        "symbols": symbols,
    }


def symbolicate(image: dict[str, object], offsets: list[int]) -> dict[str, object]:
    symbols = image["symbols"]
    assert isinstance(symbols, list)
    addresses = [entry[0] for entry in symbols]
    resolved = []
    for offset in offsets:
        index = bisect.bisect_right(addresses, offset) - 1
        if index < 0:
            resolved.append({"offset": f"0x{offset:x}", "symbol": None})
            continue
        symbol_offset, name = symbols[index]
        resolved.append(
            {
                "offset": f"0x{offset:x}",
                "symbol": name,
                "symbol_offset": f"0x{offset - symbol_offset:x}",
                "symbol_address": f"0x{symbol_offset:x}",
            }
        )
    return {
        "path": image["path"],
        "uuid": image["uuid"],
        "cpusubtype": image["cpusubtype"],
        "text_vmaddr": f"0x{image['text_vmaddr']:x}",
        "resolved": resolved,
    }


def parse_offset(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("offset", nargs="+", type=parse_offset)
    args = parser.parse_args()
    result = symbolicate(load_symbols(args.binary), args.offset)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
