#!/usr/bin/env python3
"""Inspect a 64-bit little-endian Mach-O without loading or executing it."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import struct
import uuid


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D
LC_BUILD_VERSION = 0x32
N_EXT = 0x01
N_TYPE = 0x0E
N_UNDF = 0x00


def require_range(data: bytes, offset: int, size: int, label: str) -> memoryview:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"{label} exceeds file bounds")
    return memoryview(data)[offset : offset + size]


def c_string(data: bytes, offset: int, limit: int) -> str:
    raw = require_range(data, offset, limit - offset, "string table entry")
    terminator = bytes(raw).find(b"\0")
    if terminator < 0:
        raise ValueError("unterminated string table entry")
    return bytes(raw[:terminator]).decode("utf-8", errors="replace")


def packed_version(value: int) -> str:
    return f"{value >> 16}.{(value >> 8) & 0xff}.{value & 0xff}"


def classify_import(name: str) -> str:
    normalized = name.lstrip("_")
    if normalized.startswith("IOSurface"):
        return "iosurface"
    if normalized.startswith(("IOConnect", "IOService", "IOObject", "IOMaster")):
        return "iokit"
    if normalized.startswith(("mach_", "vm_")):
        return "mach_vm"
    if normalized in {"socket", "connect", "bind", "setsockopt", "getsockopt"}:
        return "socket"
    if normalized in {"open", "close", "read", "write", "pread", "pwrite", "mmap", "munmap"}:
        return "file_memory"
    if normalized.startswith(("dispatch_", "pthread_")):
        return "concurrency"
    return "other"


def analyze(path: pathlib.Path) -> dict[str, object]:
    data = path.read_bytes()
    if len(data) < 32:
        raise ValueError("file is smaller than a Mach-O 64 header")

    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
        "<IiiIIIII", data, 0
    )
    if magic != MH_MAGIC_64:
        raise ValueError(f"unsupported Mach-O magic 0x{magic:08x}")
    require_range(data, 32, sizeofcmds, "load command table")

    symtab: tuple[int, int, int, int] | None = None
    dysymtab: tuple[int, int, int, int, int, int] | None = None
    build_version: dict[str, object] | None = None
    image_uuid: str | None = None
    code_signature: dict[str, int] | None = None
    command_offset = 32
    command_end = command_offset + sizeofcmds
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", require_range(data, command_offset, 8, "load command"))
        if cmdsize < 8 or command_offset + cmdsize > command_end:
            raise ValueError("invalid load command size")
        command = require_range(data, command_offset, cmdsize, "load command")
        if cmd == LC_SYMTAB and cmdsize >= 24:
            _, _, symoff, nsyms, stroff, strsize = struct.unpack_from("<IIIIII", command)
            symtab = (symoff, nsyms, stroff, strsize)
        elif cmd == LC_DYSYMTAB and cmdsize >= 80:
            values = struct.unpack_from("<" + "I" * 20, command)
            dysymtab = tuple(values[2:8])
        elif cmd == LC_UUID and cmdsize >= 24:
            image_uuid = str(uuid.UUID(bytes=bytes(command[8:24]))).upper()
        elif cmd == LC_BUILD_VERSION and cmdsize >= 24:
            _, _, platform, minos, sdk, ntools = struct.unpack_from("<IIIIII", command)
            build_version = {
                "platform": platform,
                "minimum_os": packed_version(minos),
                "sdk": packed_version(sdk),
                "tool_count": ntools,
            }
        elif cmd == LC_CODE_SIGNATURE and cmdsize >= 16:
            _, _, dataoff, datasize = struct.unpack_from("<IIII", command)
            require_range(data, dataoff, datasize, "code signature")
            code_signature = {"offset": dataoff, "size": datasize}
        command_offset += cmdsize
    if command_offset != command_end:
        raise ValueError("load commands do not consume sizeofcmds")
    if symtab is None or dysymtab is None:
        raise ValueError("Mach-O has no complete symbol metadata")

    symoff, nsyms, stroff, strsize = symtab
    require_range(data, symoff, nsyms * 16, "symbol table")
    require_range(data, stroff, strsize, "string table")
    ilocalsym, nlocalsym, iextdefsym, nextdefsym, iundefsym, nundefsym = dysymtab

    def symbol_at(index: int) -> tuple[str, int, int, int, int]:
        if index < 0 or index >= nsyms:
            raise ValueError("symbol index exceeds symbol table")
        strx, n_type, n_sect, n_desc, n_value = struct.unpack_from("<IBBHQ", data, symoff + index * 16)
        if strx >= strsize:
            raise ValueError("symbol string offset exceeds string table")
        name = c_string(data, stroff + strx, stroff + strsize) if strx else ""
        return name, n_type, n_sect, n_desc, n_value

    imports: list[str] = []
    for index in range(iundefsym, iundefsym + nundefsym):
        name, n_type, _, _, _ = symbol_at(index)
        if name and (n_type & N_TYPE) == N_UNDF:
            imports.append(name)

    exports: list[str] = []
    for index in range(iextdefsym, iextdefsym + nextdefsym):
        name, n_type, _, _, _ = symbol_at(index)
        if name and n_type & N_EXT and (n_type & N_TYPE) != N_UNDF:
            exports.append(name)

    categories: dict[str, list[str]] = {}
    for name in sorted(set(imports)):
        categories.setdefault(classify_import(name), []).append(name)

    return {
        "schema": "dopamine.a15-ios26.macho-preflight.v1",
        "path": path.name,
        "sha256": hashlib.sha256(data).hexdigest().upper(),
        "size": len(data),
        "mach_o": {
            "cputype": cputype,
            "cpusubtype": cpusubtype,
            "arm64": cputype == CPU_TYPE_ARM64,
            "filetype": filetype,
            "flags": flags,
            "reserved": reserved,
            "uuid": image_uuid,
            "build_version": build_version,
            "code_signature": code_signature,
        },
        "symbols": {
            "total": nsyms,
            "local_count": nlocalsym,
            "export_count": len(exports),
            "import_count": len(imports),
            "exports": sorted(set(exports)),
            "imports_by_category": categories,
        },
        "execution": "NOT_PERFORMED",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    report = analyze(args.binary)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
