#!/usr/bin/env python3
"""List GPU-related nodes from a decompressed Apple DeviceTree image."""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import struct


@dataclasses.dataclass
class Node:
    properties: dict[str, bytes]
    children: list["Node"]

    @property
    def name(self) -> str:
        value = self.properties.get("name", b"")
        return value.split(b"\0", 1)[0].decode("utf-8", errors="replace") or "?"


def align4(value: int) -> int:
    return (value + 3) & ~3


def parse_node(blob: bytes, offset: int = 0) -> tuple[Node, int]:
    if offset + 8 > len(blob):
        raise ValueError("truncated node header")
    property_count, child_count = struct.unpack_from("<II", blob, offset)
    offset += 8
    if property_count > 4096 or child_count > 4096:
        raise ValueError("invalid DeviceTree node counts")

    properties: dict[str, bytes] = {}
    for _ in range(property_count):
        if offset + 36 > len(blob):
            raise ValueError("truncated property header")
        raw_name = blob[offset : offset + 32]
        length_flags = struct.unpack_from("<I", blob, offset + 32)[0]
        length = length_flags & 0x00FFFFFF
        offset += 36
        if offset + length > len(blob):
            raise ValueError("truncated property value")
        name = raw_name.split(b"\0", 1)[0].decode("utf-8", errors="replace")
        properties[name] = blob[offset : offset + length]
        offset += align4(length)

    children = []
    for _ in range(child_count):
        child, offset = parse_node(blob, offset)
        children.append(child)
    return Node(properties, children), offset


def printable(value: bytes) -> str | None:
    stripped = value.rstrip(b"\0")
    if not stripped:
        return None
    if all(byte in b"\t\r\n" or 0x20 <= byte < 0x7F for byte in stripped):
        return stripped.replace(b"\0", b" | ").decode("ascii", errors="replace")
    return None


def describe(value: bytes) -> str:
    text = printable(value)
    if text is not None:
        return repr(text)
    if len(value) <= 64 and len(value) % 8 == 0:
        values = struct.unpack(f"<{len(value) // 8}Q", value)
        return "u64[" + ", ".join(f"0x{item:x}" for item in values) + "]"
    if len(value) <= 64 and len(value) % 4 == 0:
        values = struct.unpack(f"<{len(value) // 4}I", value)
        return "u32[" + ", ".join(f"0x{item:x}" for item in values) + "]"
    return f"{len(value)} bytes: {value[:32].hex()}"


def walk(node: Node, parent: str = ""):
    path = f"{parent}/{node.name}" if parent else f"/{node.name}"
    yield path, node
    for child in node.children:
        yield from walk(child, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=pathlib.Path)
    parser.add_argument(
        "--terms",
        nargs="+",
        default=["gpu", "agx", "gfx", "sgx"],
        help="case-insensitive terms matched against paths, property names, and text values",
    )
    parser.add_argument(
        "--paths",
        nargs="+",
        help="exact DeviceTree paths to print instead of term matching",
    )
    args = parser.parse_args()

    blob = args.image.read_bytes()
    root, end = parse_node(blob)
    if any(blob[end:]):
        raise ValueError(f"non-zero trailing data at 0x{end:x}")

    nodes = list(walk(root))
    if args.paths:
        requested = set(args.paths)
        matches = [(path, node) for path, node in nodes if path in requested]
        missing = requested - {path for path, _ in matches}
        if missing:
            raise ValueError(f"DeviceTree path(s) not found: {', '.join(sorted(missing))}")
    else:
        terms = tuple(term.lower() for term in args.terms)
        matches = []
        for path, node in nodes:
            searchable = [path.lower(), *(name.lower() for name in node.properties)]
            searchable.extend(
                text.lower()
                for value in node.properties.values()
                if (text := printable(value)) is not None
            )
            if any(term in item for term in terms for item in searchable):
                matches.append((path, node))

    for path, node in matches:
        print(path)
        for name, value in node.properties.items():
            print(f"  {name}: {describe(value)}")
        print()
    print(f"matched {len(matches)} node(s); parsed 0x{end:x} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
