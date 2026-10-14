#!/usr/bin/env python3
"""Reproduce Titan's kernel and GFX patchfinders against firmware files.

This tool is diagnostic-only. It never changes the supplied images and never
executes Titan, an IOKit call, or code from the inspected firmware.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import struct
from collections.abc import Callable, Sequence

try:
    import lief
except ImportError as exc:  # pragma: no cover - host dependency
    raise SystemExit("Install LIEF first: python -m pip install lief") from exc

lief.logging.disable()

MACHO64_MAGIC = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
UINT64_MASK = (1 << 64) - 1
RTKIT_MARKER = struct.pack("<Q", 0x7777777777777700)

LIVE_EXPECTED_OFFSETS = {
    "AGXFirmwareKextG14RTBuddy.firmware_asc": 0x160,
    "AGXFirmwareKextG14RTBuddy.accelerator": 0x168,
    "AGXArmFirmwareASC.accelerator_primary": 0x118,
    "AGXArmFirmwareASC.accelerator_secondary": 0x120,
    "AGXArmFirmwareASC.allocation": 0x128,
    "AGXArmFirmwareASC.secure_memory_map": 0x130,
    "AGXArmFirmwareASC.event_machine": 0x148,
}


@dataclasses.dataclass(frozen=True)
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    content: bytes

    @property
    def end(self) -> int:
        return self.vmaddr + len(self.content)


@dataclasses.dataclass(frozen=True)
class Pattern:
    name: str
    instructions: tuple[int, ...]
    masks: tuple[int, ...]


class MappedImage:
    def __init__(
        self,
        label: str,
        segments: Sequence[Segment],
        symbols: dict[str, int] | None = None,
    ) -> None:
        self.label = label
        self.segments = list(segments)
        self.symbols = symbols or {}

    @classmethod
    def from_lief(cls, label: str, binary) -> "MappedImage":
        return cls(
            label,
            [
                Segment(
                    segment.name,
                    int(segment.virtual_address),
                    int(segment.virtual_size),
                    bytes(segment.content),
                )
                for segment in binary.segments
            ],
            {symbol.name: int(symbol.value) for symbol in binary.symbols},
        )

    def segment(self, name: str) -> Segment:
        match = next((segment for segment in self.segments if segment.name == name), None)
        if match is None:
            raise ValueError(f"{self.label} has no {name} segment")
        return match

    def read(self, address: int, size: int) -> bytes:
        for segment in self.segments:
            if segment.vmaddr <= address and address + size <= segment.end:
                offset = address - segment.vmaddr
                return segment.content[offset : offset + size]
        raise ValueError(
            f"0x{address:x}..0x{address + size:x} is not mapped in {self.label}"
        )

    def read_u32(self, address: int) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]

    def read_u64(self, address: int) -> int:
        return struct.unpack("<Q", self.read(address, 8))[0]

    def find_pattern(self, segment_name: str, pattern: Pattern) -> list[int]:
        segment = self.segment(segment_name)
        hits: list[int] = []
        byte_length = len(pattern.instructions) * 4
        for offset in range(0, len(segment.content) - byte_length + 1, 4):
            if all(
                (struct.unpack_from("<I", segment.content, offset + index * 4)[0] & mask)
                == (instruction & mask)
                for index, (instruction, mask) in enumerate(
                    zip(pattern.instructions, pattern.masks, strict=True)
                )
            ):
                hits.append(segment.vmaddr + offset)
        return hits

    def closest_pattern(self, segment_name: str, pattern: Pattern) -> dict:
        segment = self.segment(segment_name)
        byte_length = len(pattern.instructions) * 4
        best_score = -1
        best_address = None
        for offset in range(0, len(segment.content) - byte_length + 1, 4):
            score = sum(
                (struct.unpack_from("<I", segment.content, offset + index * 4)[0] & mask)
                == (instruction & mask)
                for index, (instruction, mask) in enumerate(
                    zip(pattern.instructions, pattern.masks, strict=True)
                )
                if mask
            )
            if score > best_score:
                best_score = score
                best_address = segment.vmaddr + offset
        return {
            "address": best_address,
            "matched_words": best_score,
            "significant_words": sum(mask != 0 for mask in pattern.masks),
        }


def decode_ldr_str_offset(instruction: int) -> int:
    return ((instruction >> 10) & 0xFFF) << (instruction >> 30)


def decode_ldr_literal_offset(instruction: int) -> int:
    offset = (instruction >> 3) & 0x1FFFFC
    return offset | ~0xFFFFF if offset & 0x100000 else offset


def decode_adrp(address: int, instruction: int) -> int:
    immhi = (instruction >> 5) & 0x7FFFF
    immlo = (instruction >> 29) & 0x3
    immediate = ((immhi << 2) | immlo) << 12
    if immediate & (1 << 32):
        immediate -= 1 << 33
    return ((address & ~0xFFF) + immediate) & UINT64_MASK


def decode_adrp_add(address: int, adrp: int, add: int) -> int:
    return (decode_adrp(address, adrp) + ((add >> 10) & 0xFFF)) & UINT64_MASK


def hex_value(value: int | None) -> str:
    return "-" if value is None else f"0x{value:x}"


def read_u32_or_none(image: MappedImage, address: int) -> int | None:
    try:
        return image.read_u32(address)
    except ValueError:
        return None


def read_u64_or_none(image: MappedImage, address: int) -> int | None:
    try:
        return image.read_u64(address)
    except ValueError:
        return None


def pattern_result(
    image: MappedImage,
    segment_name: str,
    pattern: Pattern,
    derive: Callable[[MappedImage, int], dict] | None = None,
) -> dict:
    hits = image.find_pattern(segment_name, pattern)
    result: dict = {
        "name": pattern.name,
        "status": "PASS" if hits else "FAIL",
        "hits": hits,
    }
    if not hits:
        result["closest"] = image.closest_pattern(segment_name, pattern)
        return result
    if derive is not None:
        try:
            derived = derive(image, hits[0])
            valid = derived.pop("valid", True)
            result["derived"] = derived
            if not valid:
                result["status"] = "FAIL"
        except (ValueError, struct.error) as exc:
            result["status"] = "FAIL"
            result["error"] = str(exc)
    return result


def derive_delete_command_queue(image: MappedImage, hit: int) -> dict:
    value = decode_ldr_str_offset(image.read_u32(hit + 8))
    return {"IOGPUDeviceUserClient.IOGPUDevice": value, "valid": value != 0}


def derive_free_gpu_va(image: MappedImage, hit: int) -> dict:
    store = None
    for index in range(10):
        instruction = image.read_u32(hit + index * 4)
        if instruction & 0xFFC0001F == 0xF900001F:
            store = hit + index * 4
            break
    value = decode_ldr_str_offset(image.read_u32(store)) if store else None
    return {
        "store": store,
        "IOGPUMemoryMap.GPUVirtualAddress": value,
        "valid": value not in {None, 0},
    }


def derive_process_kernel_command(image: MappedImage, hit: int) -> dict:
    values = {
        "IOGPUDevice.MDSID_map": decode_ldr_str_offset(image.read_u32(hit)),
        "IOGPUDevice.IOGPU": decode_ldr_str_offset(image.read_u32(hit + 8)),
        "IOGPU.dsids_supported": decode_ldr_str_offset(image.read_u32(hit + 12)),
    }
    return {**values, "valid": all(value != 0 for value in values.values())}


def derive_fence_offsets(image: MappedImage, hit: int) -> dict:
    fence_value = (image.read_u32(hit) >> 5) & 0xFFFF
    index = 1
    found_mov = False
    memory_map = None
    while index < 50:
        instruction = image.read_u32(hit + index * 4)
        index += 1
        if instruction & 0xFFE0001F == 0x52800008:
            if found_mov:
                memory_map = (instruction >> 5) & 0xFFFF
                break
            found_mov = True

    marker = None
    buffer_offset = None
    while index < 50:
        instruction = image.read_u32(hit + index * 4)
        index += 1
        if instruction == 0xF2E63531:
            marker = hit + (index - 1) * 4
            buffer_offset = decode_ldr_str_offset(image.read_u32(marker + 8))
            break
    return {
        "IOGPU.fence_value": fence_value,
        "IOGPU.IOGPUMemoryMap": memory_map,
        "buffer_marker": marker,
        "IOGPU.buffer_offset": buffer_offset,
        "valid": all(
            value not in {None, 0}
            for value in (fence_value, memory_map, buffer_offset)
        ),
    }


def derive_create_shmem(image: MappedImage, hit: int) -> dict:
    namespace_load = None
    index = 0
    while index < 30:
        instruction = image.read_u32(hit + index * 4)
        index += 1
        if instruction >> 26 == 37:
            namespace_load = hit + index * 4 - 12
            break
    value = (
        decode_ldr_str_offset(image.read_u32(namespace_load))
        if namespace_load is not None
        else None
    )
    return {
        "namespace_load": namespace_load,
        "IOGPUDevice.IOGPUNamespace": value,
        "valid": value not in {None, 0},
    }


def derive_alloc_handles(image: MappedImage, hit: int) -> dict:
    value = decode_ldr_str_offset(image.read_u32(hit))
    return {"IOGPUWeakNamespace.handles": value, "valid": value != 0}


def derive_get_kernel_data(image: MappedImage, hit: int) -> dict:
    source = hit + 12
    value = decode_ldr_str_offset(image.read_u32(source))
    return {
        "offset_source": source,
        "IOGPUDeviceShmem.map": value,
        "valid": value != 0,
    }


def derive_wire_range(image: MappedImage, hit: int) -> dict:
    value = decode_ldr_str_offset(image.read_u32(hit))
    return {
        "IOMemoryMap.fAddress": value,
        "candidateRejected": value > 0x100,
        "valid": 0 < value <= 0x100,
    }


def derive_iomemorymap_address_accessor(image: MappedImage, hit: int) -> dict:
    value = decode_ldr_str_offset(image.read_u32(hit + 4))
    return {
        "accessor": hit,
        "IOMemoryMap.fAddress": value,
        "valid": 0 < value <= 0x100,
    }


def derive_userclient_vtable(image: MappedImage, hit: int) -> dict:
    adrp_address = None
    for index in range(30):
        address = hit - index * 4
        if image.read_u32(address) & 0x1F000000 == 0x10000000:
            adrp_address = address
            break
    value = None
    if adrp_address is not None:
        value = decode_adrp_add(
            adrp_address,
            image.read_u32(adrp_address),
            image.read_u32(adrp_address + 4),
        )
    return {
        "adrp_add": adrp_address,
        "IOGPUDeviceUserClient_vtable": value,
        "valid": value not in {None, 0},
    }


KERNEL_PATTERNS = {
    "delete": Pattern(
        "IOGPUDeviceUserClient::s_delete_command_queue",
        (0xF9401048, 0xB9400100, 0xF9400008, 0xF9400000),
        (0xFFFFFFFF, 0xFFFFFFE0, 0xFFC0001F, 0xFFC0001F),
    ),
    "free": Pattern(
        "IOGPUMemoryMap::freeGPUVirtualAddress", (0xF2F5F020,), (0xFFFFFFE0,)
    ),
    "process": Pattern(
        "AGXCommandQueue::processKernelCommand",
        (0xF9400000, 0xB4000000, 0xF9400000, 0xB9400000, 0x34000000),
        (0xFFC00000, 0xFF000000, 0xFFC00000, 0xFFC00000, 0xFF000000),
    ),
    "fence": Pattern(
        "AGXCommandQueue fence sequence",
        (0x52800008, 0xB8686809, 0x11040129, 0xB8286809, 0x52800008, 0x8B000000),
        (0xFFE0001F, 0xFFFFFC1F, 0xFFFFFFFF, 0xFFFFFC1F, 0xFFE0001F, 0xFFE0FC00),
    ),
    "shmem": Pattern(
        "IOGPUDevice::create_shmem",
        (0xF900001F, 0xB900001F, 0xB900001F, 0, 0, 0, 0x14000000),
        (0xFFFFFC1F, 0xFFFFFC1F, 0xFFFFFC1F, 0, 0, 0, 0xFC000000),
    ),
    "handles": Pattern(
        "IOGPUWeakNamespace::alloc_handles",
        (0xF9000000, 0xB4000000, 0, 0x94000000, 0xF9000000),
        (0xFFC0001F, 0xFF00001F, 0, 0xFC000000, 0xFFC0001F),
    ),
    "kernel_data": Pattern(
        "IOGPUKernelMappedMemory::getKernelData",
        (0x11000000, 0x29000000),
        (0xFFC00000, 0xFFC00000),
    ),
    "wire": Pattern(
        "IOMemoryMap::wireRange",
        (0xF9400008, 0x8B020108),
        (0xFFC003FF, 0xFFFFFFFF),
    ),
    "map_address_ios26": Pattern(
        "iOS 26 IOMemoryMap address accessor",
        (
            0xD503245F,
            0xF9400000,
            0xD65F03C0,
            0xD503237F,
            0xD10003FF,
            0xA90157F6,
            0xA9024FF4,
            0xA9037BFD,
            0x9100C3FD,
            0xAA0003F3,
        ),
        (
            0xFFFFFFFF,
            0xFFC003FF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0xFFC003FF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
        ),
    ),
    "vtable": Pattern(
        "AGXDeviceUserClient vtable reference",
        (0xF2F9B431, 0xDAC10A30, 0xF9000010, 0x3904C01F),
        (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
    ),
}


def find_fileset(container, *, exact: str | None = None, prefix: str | None = None):
    for entry in container.filesets:
        if exact is not None and entry.fileset_name == exact:
            return entry
        if prefix is not None and entry.fileset_name.startswith(prefix):
            return entry
    requested = exact if exact is not None else f"{prefix}*"
    raise ValueError(f"kernelcache has no fileset named {requested}")


def analyze_kernel(path: pathlib.Path) -> dict:
    container = lief.parse(str(path))
    if container is None or not isinstance(container, lief.MachO.Binary):
        raise ValueError(f"{path} is not an Apple fileset kernelcache")
    iogpu_binary = find_fileset(container, exact="com.apple.iokit.IOGPUFamily")
    agxg_binary = find_fileset(container, prefix="com.apple.AGXG")
    kernel_binary = find_fileset(container, exact="com.apple.kernel")
    iogpu = MappedImage.from_lief(iogpu_binary.fileset_name, iogpu_binary)
    agxg = MappedImage.from_lief(agxg_binary.fileset_name, agxg_binary)
    kernel = MappedImage.from_lief(kernel_binary.fileset_name, kernel_binary)
    checks = [
        pattern_result(iogpu, "__TEXT_EXEC", KERNEL_PATTERNS["delete"], derive_delete_command_queue),
        pattern_result(iogpu, "__TEXT_EXEC", KERNEL_PATTERNS["free"], derive_free_gpu_va),
        pattern_result(agxg, "__TEXT_EXEC", KERNEL_PATTERNS["process"], derive_process_kernel_command),
        pattern_result(agxg, "__TEXT_EXEC", KERNEL_PATTERNS["fence"], derive_fence_offsets),
        pattern_result(iogpu, "__TEXT_EXEC", KERNEL_PATTERNS["shmem"], derive_create_shmem),
        pattern_result(iogpu, "__TEXT_EXEC", KERNEL_PATTERNS["handles"], derive_alloc_handles),
        pattern_result(iogpu, "__TEXT_EXEC", KERNEL_PATTERNS["kernel_data"], derive_get_kernel_data),
        pattern_result(kernel, "__TEXT_EXEC", KERNEL_PATTERNS["wire"], derive_wire_range),
        pattern_result(
            kernel,
            "__TEXT_EXEC",
            KERNEL_PATTERNS["map_address_ios26"],
            derive_iomemorymap_address_accessor,
        ),
        pattern_result(agxg, "__TEXT_EXEC", KERNEL_PATTERNS["vtable"], derive_userclient_vtable),
    ]
    first_failure = next((item["name"] for item in checks if item["status"] != "PASS"), None)
    ios26_candidates = analyze_ios26_agx_candidates(agxg)
    legacy_only_names = {
        "AGXCommandQueue::processKernelCommand",
        "AGXCommandQueue fence sequence",
        "IOMemoryMap::wireRange",
    }
    adapted_dependencies_pass = all(
        item["status"] == "PASS"
        for item in checks
        if item["name"] not in legacy_only_names
    )
    adapted_status = (
        "PASS"
        if adapted_dependencies_pass and ios26_candidates["status"] == "CANDIDATE"
        else "FAIL"
    )
    return {
        "path": str(path),
        "filesets": {
            "iogpu": iogpu_binary.fileset_name,
            "agxg": agxg_binary.fileset_name,
            "kernel": kernel_binary.fileset_name,
        },
        "status": "PASS" if first_failure is None else "FAIL",
        "adapted_status": adapted_status,
        "first_failure": first_failure,
        "checks": checks,
        "ios26_candidates": ios26_candidates,
    }


def decode_move_wide(instruction: int, previous: int = 0) -> int | None:
    opcode = instruction & 0x7F800000
    immediate = ((instruction >> 5) & 0xFFFF) << (((instruction >> 21) & 0x3) * 16)
    if opcode == 0x52800000:  # MOVZ Wd
        return immediate & 0xFFFFFFFF
    if opcode == 0x72800000:  # MOVK Wd
        shift = ((instruction >> 21) & 0x3) * 16
        mask = 0xFFFF << shift
        return ((previous & ~mask) | immediate) & 0xFFFFFFFF
    return None


def decode_add_immediate(instruction: int) -> int | None:
    if instruction & 0x7F000000 != 0x11000000:
        return None
    value = (instruction >> 10) & 0xFFF
    if instruction & (1 << 22):
        value <<= 12
    return value


def is_ldr_unsigned_immediate(instruction: int, *, bits: int) -> bool:
    expected = 0xF9400000 if bits == 64 else 0xB9400000
    return instruction & 0xFFC00000 == expected


def derive_ios26_kernel_command(image: MappedImage, hit: int) -> dict:
    command_register = image.read_u32(hit) & 0x1F
    movk_register = image.read_u32(hit + 4) & 0x1F
    compare_register = (image.read_u32(hit + 8) >> 16) & 0x1F

    gpu_device_offset = decode_ldr_str_offset(image.read_u32(hit + 0x54))
    mdsid_map_offset = decode_ldr_str_offset(image.read_u32(hit + 0x58))
    iogpu_offset = decode_ldr_str_offset(image.read_u32(hit + 0x60))
    dsids_supported = decode_move_wide(image.read_u32(hit + 0x64))

    fence_page = decode_add_immediate(image.read_u32(hit + 0x84))
    fence_remainder = decode_add_immediate(image.read_u32(hit + 0x88))
    fence_value = (
        fence_page + fence_remainder
        if fence_page is not None and fence_remainder is not None
        else None
    )

    state_base = decode_move_wide(image.read_u32(hit + 0x8C))
    state_pointer_load = decode_ldr_str_offset(image.read_u32(hit + 0xD0))
    state_pointer = (
        state_base + state_pointer_load
        if state_base is not None
        else None
    )

    nested_slot = decode_move_wide(image.read_u32(hit + 0xD4))
    if nested_slot is not None:
        nested_slot = decode_move_wide(image.read_u32(hit + 0xD8), nested_slot)
    memory_map = decode_ldr_str_offset(image.read_u32(hit + 0xE0))
    buffer_offset = decode_ldr_str_offset(image.read_u32(hit + 0x11C))

    valid = (
        command_register == movk_register == compare_register
        and gpu_device_offset == 0x490
        and is_ldr_unsigned_immediate(image.read_u32(hit + 0x54), bits=64)
        and is_ldr_unsigned_immediate(image.read_u32(hit + 0x58), bits=64)
        and is_ldr_unsigned_immediate(image.read_u32(hit + 0x60), bits=64)
        and is_ldr_unsigned_immediate(image.read_u32(hit + 0xD0), bits=64)
        and is_ldr_unsigned_immediate(image.read_u32(hit + 0xE0), bits=64)
        and is_ldr_unsigned_immediate(image.read_u32(hit + 0x11C), bits=32)
        and all(
            value not in {None, 0}
            for value in (
                mdsid_map_offset,
                iogpu_offset,
                dsids_supported,
                fence_value,
                state_pointer,
                nested_slot,
                memory_map,
                buffer_offset,
            )
        )
    )
    return {
        "AGXCommandQueue.IOGPUDevice": gpu_device_offset,
        "IOGPUDevice.MDSID_map": mdsid_map_offset,
        "IOGPUDevice.IOGPU": iogpu_offset,
        "IOGPU.dsids_supported": dsids_supported,
        "IOGPU.fence_value": fence_value,
        "IOGPU.state": state_pointer,
        "IOGPUState.memory_map_slot": nested_slot,
        "IOGPUMapSlot.memory_map": memory_map,
        "IOGPUState.buffer_offset": buffer_offset,
        "valid": valid,
    }


def analyze_ios26_agx_candidates(agx: MappedImage) -> dict:
    relaxed_fence = Pattern(
        "iOS 26 relaxed AGX fence sequence",
        (0x52800008, 0xB8686809, 0x11040129, 0xB8286809),
        (0xFFE0001F, 0xFFFFFC1F, 0xFFFFFFFF, 0xFFFFFC1F),
    )
    hits = agx.find_pattern("__TEXT_EXEC", relaxed_fence)
    kernel_command = Pattern(
        "iOS 26 AGX kernel command 0x10002",
        (0x52800040, 0x72A00020, 0x6B00001F, 0x54000001),
        (0xFFFFFFE0, 0xFFFFFFE0, 0xFFE0FC1F, 0xFF00001F),
    )
    command_hits = agx.find_pattern("__TEXT_EXEC", kernel_command)
    result: dict = {
        "status": (
            "CANDIDATE"
            if len(hits) == 1 and len(command_hits) == 1
            else "AMBIGUOUS"
        ),
        "relaxed_fence_hits": hits,
        "kernel_command_0x10002_hits": command_hits,
        "note": (
            "Evidence only: XNU 25 keeps the MDSID command but replaces Titan's "
            "direct IOGPU.IOGPUMemoryMap field with a nested state/slot access."
        ),
    }
    if len(hits) != 1 or len(command_hits) != 1:
        return result

    hit = hits[0]
    fence_offset = (agx.read_u32(hit) >> 5) & 0xFFFF
    intermediate_load = hit + 0x28
    intermediate_offset = decode_ldr_str_offset(agx.read_u32(intermediate_load))
    nested_offset = decode_move_wide(agx.read_u32(hit + 0x2C))
    if nested_offset is not None:
        nested_offset = decode_move_wide(agx.read_u32(hit + 0x30), nested_offset)
    slot_map_offset = decode_ldr_str_offset(agx.read_u32(hit + 0x38))

    marker = None
    buffer_offset = None
    for index in range(4, 80):
        address = hit + index * 4
        if agx.read_u32(address) == 0xF2E63531:
            marker = address
            buffer_offset = decode_ldr_str_offset(agx.read_u32(address + 8))
            break
    command = derive_ios26_kernel_command(agx, command_hits[0])
    command_valid = command.pop("valid")
    result["derived"] = {
        "helper.fence_value": fence_offset,
        "intermediate_load": intermediate_load,
        "intermediate_offset": intermediate_offset,
        "nested_slot_offset": nested_offset,
        "slot_map_offset": slot_map_offset,
        "buffer_marker": marker,
        "helper.buffer_offset": buffer_offset,
        **command,
    }
    cross_valid = (
        nested_offset == command["IOGPUState.memory_map_slot"]
        and slot_map_offset == command["IOGPUMapSlot.memory_map"]
        and buffer_offset == command["IOGPUState.buffer_offset"]
    )
    result["cross_method_validation"] = "PASS" if cross_valid else "FAIL"
    if not command_valid or not cross_valid:
        result["status"] = "AMBIGUOUS"
    return result


def parse_macho(label: str, blob: bytes) -> MappedImage:
    if len(blob) < 32 or struct.unpack_from("<I", blob)[0] != MACHO64_MAGIC:
        raise ValueError(f"{label} is not a 64-bit little-endian Mach-O")
    _, _, _, _, command_count, command_size, _, _ = struct.unpack_from(
        "<IiiIIIII", blob
    )
    cursor = 32
    command_end = cursor + command_size
    segments: list[Segment] = []
    for _ in range(command_count):
        if cursor + 8 > len(blob) or cursor >= command_end:
            raise ValueError(f"{label} has truncated Mach-O load commands")
        command, size = struct.unpack_from("<II", blob, cursor)
        if size < 8 or cursor + size > len(blob):
            raise ValueError(f"{label} has an invalid Mach-O load command")
        if command == LC_SEGMENT_64:
            values = struct.unpack_from("<II16sQQQQiiII", blob, cursor)
            name = values[2].split(b"\0", 1)[0].decode("ascii", errors="replace")
            vmaddr, vmsize, file_offset, file_size = values[3:7]
            if file_offset + file_size > len(blob):
                raise ValueError(f"{label} segment {name} extends beyond its blob")
            segments.append(
                Segment(name, vmaddr, vmsize, blob[file_offset : file_offset + file_size])
            )
        cursor += size
    symbols: dict[str, int] = {}
    parsed = lief.MachO.parse(blob)
    if parsed is not None and len(parsed) > 0:
        binary = parsed.at(0)
        symbols = {symbol.name: int(symbol.value) for symbol in binary.symbols}
    return MappedImage(label, segments, symbols)


def parse_gfx_images(path: pathlib.Path) -> list[MappedImage]:
    data = path.read_bytes()
    if data[0x20:0x28] == b"rkosftab":
        count = struct.unpack_from("<I", data, 0x28)[0]
        images = []
        for index in range(count):
            cursor = 0x30 + index * 16
            tag = data[cursor : cursor + 4].decode("ascii", errors="replace")
            offset = struct.unpack_from("<I", data, cursor + 4)[0]
            size = struct.unpack_from("<Q", data, cursor + 8)[0]
            images.append(parse_macho(tag, data[offset : offset + size]))
        return images
    offset = data.find(struct.pack("<I", MACHO64_MAGIC))
    if offset < 0:
        raise ValueError(f"{path} contains no 64-bit Mach-O")
    return [parse_macho(path.name, data[offset:])]


GFX_PATTERNS = {
    "hibernate": Pattern(
        "arm_hibernate",
        (0xD503201F, 0x58000000, 0xD503201F, 0x58000001, 0x14000000),
        (0xFFFFFFFF, 0xFF00001F, 0xFFFFFFFF, 0xFF00001F, 0xFC000000),
    ),
    "tpidrro": Pattern("TPIDRRO_EL0 gadget", (0xD53BD061,), (0xFFFFFFFF,)),
    "write": Pattern(
        "STR X1, [X0, X2]; RET gadget",
        (0xF8226801, 0xD65F03C0),
        (0xFFFFFFFF, 0xFFFFFFFF),
    ),
    "invoke": Pattern("ROP invocation gadget", (0x910443E1,), (0xFFFFFFFF,)),
    "tlb": Pattern(
        "TLB flush gadget",
        (0xD508831F, 0xD5033F9F, 0xD5033FDF, 0xD65F03C0),
        (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
    ),
    "cache": Pattern(
        "cache flush gadget",
        (0xD5033F9F, 0xD5033FDF, 0xD65F03C0),
        (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
    ),
    "spin": Pattern("spin gadget", (0x14000000,), (0xFFFFFFFF,)),
    "power": Pattern(
        "power thread reference",
        (0x528007C5, 0x94000000, 0x90000000, 0xF9000000),
        (0xFFFFFFFF, 0xFC000000, 0x9F000000, 0xFFC0001F),
    ),
    "resume": Pattern(
        "arm_arch_resume",
        (0xD53800A2, 0, 0xAA0003E5),
        (0xFFFFFFFF, 0, 0xFFFFFFFC),
    ),
    "hibernate_ios26": Pattern(
        "iOS 26 arm_arch_hibernate_uat",
        (
            0xA9BF7BFD,
            0xF81F8FFC,
            0xD53800BC,
            0xD3401F9C,
            0x9000001D,
            0x910003BD,
            0xF83C7BA0,
            0x9000001D,
            0x910003BD,
            0xF83C7BA1,
            0xF100003F,
        ),
        (
            0xFFFFFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0x9F00001F,
            0xFFC003FF,
            0xFFFFFFFF,
            0x9F00001F,
            0xFFC003FF,
            0xFFFFFFFF,
            0xFFFFFFFF,
        ),
    ),
}


def derive_power_thread(image: MappedImage, hit: int) -> dict:
    adrp_address = hit + 8
    pointer = (
        decode_adrp(adrp_address, image.read_u32(adrp_address))
        + decode_ldr_str_offset(image.read_u32(adrp_address + 4))
    ) & UINT64_MASK
    return {
        "pointer": pointer,
        "file_value": read_u64_or_none(image, pointer),
        "valid": pointer != 0,
    }


def derive_hibernation_context(image: MappedImage, hit: int) -> dict:
    load_address = hit + 4
    pointer = (
        load_address + decode_ldr_literal_offset(image.read_u32(load_address))
    ) & UINT64_MASK
    return {
        "pointer": pointer,
        "file_value": read_u64_or_none(image, pointer),
        "valid": pointer != 0,
    }


def derive_arm_hb_context(image: MappedImage, hit: int) -> dict:
    load_address = hit + 12
    limit = load_address + 0x1000
    while load_address < limit:
        instruction = read_u32_or_none(image, load_address)
        if instruction is None:
            break
        if instruction & 0xFC000000 == 0x58000000:
            pointer = (load_address + decode_ldr_literal_offset(instruction)) & UINT64_MASK
            return {
                "literal_load": load_address,
                "pointer": pointer,
                "file_value": read_u64_or_none(image, pointer),
                "valid": pointer != 0,
            }
        load_address += 4
    return {"literal_load": None, "pointer": None, "file_value": None, "valid": False}


def resolve_gfx_data_pointer(image: MappedImage, value: int) -> int | None:
    data = image.segment("__DATA")
    if data.vmaddr <= value < data.end:
        return value

    text_base = image.segment("__TEXT").vmaddr
    resolved = text_base + (value & 0xFFFFFFFF)
    return resolved if data.vmaddr <= resolved < data.end else None


def derive_ios26_hibernation_contexts(image: MappedImage, hit: int) -> dict:
    hb_adrp = image.read_u32(hit + 0x10)
    hb_add = image.read_u32(hit + 0x14)
    fp_adrp = image.read_u32(hit + 0x1C)
    fp_add = image.read_u32(hit + 0x20)
    hb_address_array = decode_adrp_add(hit + 0x10, hb_adrp, hb_add)
    fp_address_array = decode_adrp_add(hit + 0x1C, fp_adrp, fp_add)

    hb_descriptor = hb_address_array - 0x220
    fp_descriptor = fp_address_array - 0x18
    hb_raw = read_u64_or_none(image, hb_descriptor)
    fp_raw = read_u64_or_none(image, fp_descriptor)
    hb_context = (
        resolve_gfx_data_pointer(image, hb_raw) if hb_raw is not None else None
    )
    fp_context = (
        resolve_gfx_data_pointer(image, fp_raw) if fp_raw is not None else None
    )

    valid = (
        hb_adrp & 0x9F000000 == 0x90000000
        and hb_add & 0xFFC00000 == 0x91000000
        and fp_adrp & 0x9F000000 == 0x90000000
        and fp_add & 0xFFC00000 == 0x91000000
        and fp_address_array == hb_address_array + 8
        and hb_context == hb_address_array - 0x388
        and fp_context == fp_address_array - 0x220
    )
    return {
        "arm_hb_context_addr_array": hb_address_array,
        "arm_fp_context_addr_array": fp_address_array,
        "arm_hb_context_descriptor": hb_descriptor,
        "arm_fp_context_descriptor": fp_descriptor,
        "hibernation_context": hb_context,
        "fp_context": fp_context,
        "abi_x0_store": "arm_hb_context",
        "abi_x1_store": "arm_fp_context",
        "abi_x1_null_check": True,
        "valid": valid,
    }


def analyze_ios26_gfx_candidate(image: MappedImage) -> dict:
    result = pattern_result(
        image,
        "__TEXT",
        GFX_PATTERNS["hibernate_ios26"],
        derive_ios26_hibernation_contexts,
    )
    hit_count = len(result["hits"])
    return {
        **result,
        "status": "CANDIDATE" if result["status"] == "PASS" and hit_count == 1 else "AMBIGUOUS",
        "note": (
            "Static-only ABI validation: X0 is the hibernation context and X1 is "
            "the FP context on this firmware build."
        ),
    }


def analyze_static_rtkit_marker(image: MappedImage) -> dict:
    hits = []
    for segment in image.segments:
        cursor = 0
        while True:
            offset = segment.content.find(RTKIT_MARKER, cursor)
            if offset < 0:
                break
            hits.append(
                {
                    "segment": segment.name,
                    "address": segment.vmaddr + offset,
                }
            )
            cursor = offset + 1

    executable_only = bool(hits) and all(hit["segment"] == "__TEXT" for hit in hits)
    return {
        "status": (
            "EXECUTABLE_IMAGE_OCCURRENCES_ONLY"
            if executable_only
            else "NO_STATIC_MARKER" if not hits else "REVIEW_REQUIRED"
        ),
        "hits": hits,
        "runtime_values_available": False,
        "note": (
            "Static occurrences are inside the packaged executable image. They are "
            "not the live reset-vector structure that Titan reads after GPU reset."
        ),
    }


def analyze_gfx(path: pathlib.Path) -> dict:
    slices = []
    for image in parse_gfx_images(path):
        checks = [
            pattern_result(image, "__TEXT", GFX_PATTERNS["hibernate"], derive_hibernation_context),
            pattern_result(image, "__TEXT", GFX_PATTERNS["tpidrro"]),
            pattern_result(image, "__TEXT", GFX_PATTERNS["write"]),
            pattern_result(image, "__TEXT", GFX_PATTERNS["invoke"]),
            pattern_result(image, "__TEXT", GFX_PATTERNS["tlb"]),
            pattern_result(image, "__TEXT", GFX_PATTERNS["cache"]),
            pattern_result(image, "__TEXT", GFX_PATTERNS["spin"]),
            pattern_result(image, "__TEXT", GFX_PATTERNS["power"], derive_power_thread),
            pattern_result(image, "__TEXT", GFX_PATTERNS["resume"], derive_arm_hb_context),
        ]
        first_failure = next(
            (item["name"] for item in checks if item["status"] != "PASS"), None
        )
        ios26_candidate = analyze_ios26_gfx_candidate(image)
        adapted_dependencies = {
            "TPIDRRO_EL0 gadget",
            "STR X1, [X0, X2]; RET gadget",
            "ROP invocation gadget",
            "TLB flush gadget",
            "cache flush gadget",
            "spin gadget",
            "power thread reference",
        }
        adapted_dependencies_pass = all(
            item["status"] == "PASS"
            for item in checks
            if item["name"] in adapted_dependencies
        )
        adapted_status = (
            "PASS"
            if adapted_dependencies_pass and ios26_candidate["status"] == "CANDIDATE"
            else "FAIL"
        )
        slices.append(
            {
                "name": image.label,
                "status": "PASS" if first_failure is None else "FAIL",
                "adapted_status": adapted_status,
                "first_failure": first_failure,
                "checks": checks,
                "ios26_hibernate_candidate": ios26_candidate,
                "rtkit_marker_scope": analyze_static_rtkit_marker(image),
                "ios26_symbol_candidates": {
                    name: image.symbols[name]
                    for name in (
                        "__arm_arch_hibernate_uat",
                        "__hb_context",
                        "__fp_context",
                        "_arm_hb_context",
                        "_arm_fp_context",
                    )
                    if name in image.symbols
                },
                "runtime_only": {
                    "target_job": "requires live GFX page tables and job-list contents",
                    "gfx_data_pa": "requires live RTKit state",
                    "gfx_ttbr_pa": "requires live RTKit state",
                },
            }
        )
    return {
        "path": str(path),
        "status": "PASS" if slices and any(item["status"] == "PASS" for item in slices) else "FAIL",
        "adapted_status": (
            "PASS"
            if slices and any(item["adapted_status"] == "PASS" for item in slices)
            else "FAIL"
        ),
        "slices": slices,
    }


def format_derived(derived: dict | None) -> str:
    if not derived:
        return "-"
    return ", ".join(
        f"{key}={hex_value(value) if isinstance(value, int) else value}"
        for key, value in derived.items()
    )


def append_check_table(lines: list[str], checks: list[dict]) -> None:
    lines.extend(
        [
            "| Finder | Status | First hit | Derived value(s) |",
            "|---|---:|---:|---|",
        ]
    )
    for check in checks:
        hit = check["hits"][0] if check["hits"] else None
        details = format_derived(check.get("derived"))
        if not check["hits"] and check.get("closest"):
            closest = check["closest"]
            details = (
                f"closest={hex_value(closest['address'])}, "
                f"{closest['matched_words']}/{closest['significant_words']} words"
            )
        lines.append(
            f"| `{check['name']}` | **{check['status']}** | "
            f"`{hex_value(hit)}` | {details} |"
        )


def parse_manifest_integer(value: object, field: str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"{field} must be an integer or hexadecimal string")


def analyze_live_layout(path: pathlib.Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1:
        raise ValueError(f"{path} has an unsupported live-layout schema")
    if data.get("mode") != "read-only":
        raise ValueError(f"{path} is not marked as read-only evidence")

    supplied_offsets = data.get("offsets")
    if not isinstance(supplied_offsets, dict):
        raise ValueError(f"{path} has no offsets object")

    checks = []
    for name, expected in LIVE_EXPECTED_OFFSETS.items():
        actual_raw = supplied_offsets.get(name)
        actual = (
            parse_manifest_integer(actual_raw, f"offsets.{name}")
            if actual_raw is not None
            else None
        )
        checks.append(
            {
                "name": name,
                "expected": expected,
                "actual": actual,
                "status": "PASS" if actual == expected else "FAIL",
            }
        )

    iorvbar = data.get("iorvbar")
    if not isinstance(iorvbar, dict):
        raise ValueError(f"{path} has no iorvbar object")
    mapping_status = str(iorvbar.get("mapping_status", "UNKNOWN")).upper()
    io_registry = data.get("io_registry")
    registry_checks = []
    if io_registry is not None:
        if not isinstance(io_registry, dict):
            raise ValueError(f"{path} io_registry must be an object")
        dictionary_layout = io_registry.get("dictionary_layout")
        if not isinstance(dictionary_layout, dict):
            raise ValueError(f"{path} io_registry has no dictionary_layout object")
        expected_registry = {
            "service_class": "AppleARMIODevice",
            "property_table_class": "OSDictionary",
        }
        for name, expected in expected_registry.items():
            actual = io_registry.get(name)
            registry_checks.append(
                {
                    "name": name,
                    "expected": expected,
                    "actual": actual,
                    "status": "PASS" if actual == expected else "FAIL",
                }
            )
        expected_dictionary_layout = {
            "options": 0x10,
            "count": 0x14,
            "capacity": 0x18,
            "capacity_increment": 0x1C,
            "entries": 0x20,
            "entry_size": 0x10,
            "key": 0,
            "value": 8,
        }
        for name, expected in expected_dictionary_layout.items():
            actual_raw = dictionary_layout.get(name)
            actual = (
                parse_manifest_integer(actual_raw, f"io_registry.dictionary_layout.{name}")
                if actual_raw is not None
                else None
            )
            registry_checks.append(
                {
                    "name": f"OSDictionary.{name}",
                    "expected": expected,
                    "actual": actual,
                    "status": "PASS" if actual == expected else "FAIL",
                }
            )
    registry_status = (
        "PASS"
        if registry_checks and all(item["status"] == "PASS" for item in registry_checks)
        else "NOT_RECORDED" if not registry_checks else "FAIL"
    )
    layout_status = "PASS" if all(item["status"] == "PASS" for item in checks) else "FAIL"
    if layout_status != "PASS":
        end_to_end_status = "INVALID_LIVE_LAYOUT"
    elif mapping_status != "VALIDATED":
        end_to_end_status = "BLOCKED_IORVBAR"
    else:
        end_to_end_status = "MAPPING_VALIDATED_TITAN_EXECUTION_BLOCKED"

    return {
        "path": str(path),
        "device": data.get("device"),
        "soc": data.get("soc"),
        "ios": data.get("ios"),
        "build": data.get("build"),
        "mode": data.get("mode"),
        "rtbuddy_vtable_unslid": parse_manifest_integer(
            data.get("rtbuddy_vtable_unslid"), "rtbuddy_vtable_unslid"
        ),
        "layout_status": layout_status,
        "registry_status": registry_status,
        "iorvbar_status": mapping_status,
        "end_to_end_status": end_to_end_status,
        "checks": checks,
        "iorvbar": iorvbar,
        "io_registry": io_registry,
        "registry_checks": registry_checks,
        "static_layout": data.get("static_layout"),
    }


def render_markdown(report: dict) -> str:
    kernel = report["kernel"]
    gfx = report["gfx"]
    live_layout = report.get("live_layout")
    lines = [
        "# Titan static compatibility report",
        "",
        "This report reproduces Titan's exact masked instruction searches without",
        "executing Titan or modifying the firmware images.",
        "",
        "## Summary",
        "",
        f"- Legacy kernel IOGPU/AGX patchfinders: **{kernel['status']}**",
        f"- iOS 26 adapted kernel fallback (static only): **{kernel['adapted_status']}**",
        f"- Legacy GFX patchfinders (at least one firmware slice): **{gfx['status']}**",
        f"- iOS 26 adapted GFX fallback (static only): **{gfx['adapted_status']}**",
        "- Live GFX state and physical-write primitive: **NOT TESTED**",
        "",
    ]
    if live_layout:
        lines.extend(
            [
                f"- Live RTBuddy/ASC layout: **{live_layout['layout_status']}**",
                f"- Live IORegistry layout: **{live_layout['registry_status']}**",
                f"- Live IORVBAR mapping: **{live_layout['iorvbar_status']}**",
                f"- End-to-end Titan status: **{live_layout['end_to_end_status']}**",
                "",
            ]
        )
    if kernel["first_failure"]:
        lines.extend([f"First kernel failure: `{kernel['first_failure']}`", ""])
    lines.extend(
        [
            "## Kernel patchfinders",
            "",
            f"Filesets: `{kernel['filesets']['iogpu']}`, `{kernel['filesets']['agxg']}`, "
            f"`{kernel['filesets']['kernel']}`.",
            "",
        ]
    )
    append_check_table(lines, kernel["checks"])
    candidate = kernel["ios26_candidates"]
    lines.extend(
        [
            "",
            "### iOS 26 AGX candidate",
            "",
            f"Status: **{candidate['status']}**. {candidate['note']}",
            "",
        ]
    )
    if candidate.get("derived"):
        lines.append(format_derived(candidate["derived"]))
        lines.append(
            "Cross-method nested-layout validation: "
            f"**{candidate.get('cross_method_validation', 'NOT_RUN')}**."
        )
    for item in gfx["slices"]:
        lines.extend(
            [
                "",
                f"## GFX slice `{item['name']}`",
                "",
                f"Overall static result: **{item['status']}**",
                f"iOS 26 adapted static result: **{item['adapted_status']}**",
                "",
            ]
        )
        append_check_table(lines, item["checks"])
        candidate = item["ios26_hibernate_candidate"]
        lines.extend(
            [
                "",
                "### iOS 26 hibernation candidate",
                "",
                f"Status: **{candidate['status']}**. {candidate['note']}",
                "",
            ]
        )
        if candidate.get("derived"):
            lines.append(format_derived(candidate["derived"]))
        if item["ios26_symbol_candidates"]:
            symbols = ", ".join(
                f"`{name}`={hex_value(value)}"
                for name, value in item["ios26_symbol_candidates"].items()
            )
            lines.extend(
                [
                    "",
                    "Symbol-backed iOS 26 candidates (offline evidence only): " + symbols,
                ]
            )
        marker = item["rtkit_marker_scope"]
        locations = ", ".join(
            f"`{hit['segment']}` at {hex_value(hit['address'])}"
            for hit in marker["hits"]
        ) or "none"
        lines.extend(
            [
                "",
                "### RTKit marker scope",
                "",
                f"Status: **{marker['status']}**. {marker['note']}",
                f"Static locations: {locations}.",
                "Runtime `gfx_data_pa` and `gfx_ttbr_pa`: **NOT AVAILABLE OFFLINE**.",
            ]
        )
    if live_layout:
        lines.extend(
            [
                "",
                "## Read-only live layout evidence",
                "",
                f"Sample: `{live_layout['device']}` / `{live_layout['build']}` / "
                f"iOS `{live_layout['ios']}`. Probe mode: `{live_layout['mode']}`.",
                "",
                "| Field | Status | Expected | Observed |",
                "|---|---:|---:|---:|",
            ]
        )
        for check in live_layout["checks"]:
            lines.append(
                f"| `{check['name']}` | **{check['status']}** | "
                f"`{hex_value(check['expected'])}` | `{hex_value(check['actual'])}` |"
            )
        if live_layout["registry_checks"]:
            lines.extend(
                [
                    "",
                    "### IORegistry device-memory path",
                    "",
                    "The `gfx-asc` service is an `AppleARMIODevice`. Its property table is an "
                    "`OSDictionary`. A count-bounded read enumerated the live property table and "
                    "resolved `IODeviceMemory`; the table below records the validated layout "
                    "used for that read.",
                    "",
                    "| Field | Status | Expected | Observed |",
                    "|---|---:|---:|---:|",
                ]
            )
            for check in live_layout["registry_checks"]:
                expected = (
                    hex_value(check["expected"])
                    if isinstance(check["expected"], int)
                    else check["expected"]
                )
                actual = (
                    hex_value(check["actual"])
                    if isinstance(check["actual"], int)
                    else check["actual"]
                )
                lines.append(
                    f"| `{check['name']}` | **{check['status']}** | "
                    f"`{expected}` | `{actual}` |"
                )
            io_registry = live_layout["io_registry"]
            lines.extend(
                [
                    "",
                    f"Metadata probe: **{io_registry['metadata_probe_status']}**. "
                    f"`IODeviceMemory`: **{io_registry['io_device_memory_status']}**.",
                    f"Properties enumerated: `{io_registry.get('property_count', 'unknown')}`. "
                    f"`IODeviceMemory` key index: "
                    f"`{io_registry.get('io_device_memory_key_index', 'unknown')}`. "
                    f"Value: `{io_registry.get('io_device_memory_value_class', 'unknown')}` "
                    f"with `{io_registry.get('io_device_memory_count', 'unknown')}` entries.",
                ]
            )
            segment_properties = io_registry.get("segment_properties")
            if isinstance(segment_properties, dict):
                segment_names = segment_properties.get("segment_names", {})
                segment_ranges = segment_properties.get("segment_ranges", {})
                osdata_layout = segment_properties.get("osdata_layout", {})
                lines.extend(
                    [
                        "",
                        "### RTBuddy segment properties",
                        "",
                        "The adjacent IORegistry properties were identified by exact-length "
                        "key reads. Both values are target-kernel `OSData` objects. The ranges "
                        "payload was read only after its length was validated.",
                        "",
                        f"Value class: `{segment_properties.get('value_class', 'unknown')}`; "
                        f"vtable `{segment_properties.get('value_vtable_unslid', 'unknown')}`; "
                        f"object size `{segment_properties.get('object_size', 'unknown')}`.",
                        "OSData layout: "
                        f"length `{osdata_layout.get('length', 'unknown')}`, "
                        f"capacity/sentinel "
                        f"`{osdata_layout.get('capacity_or_external_sentinel', 'unknown')}`, "
                        f"data `{osdata_layout.get('data', 'unknown')}`.",
                        f"`segment-names`: key index "
                        f"`{segment_names.get('key_index', 'unknown')}`, length "
                        f"`{segment_names.get('length', 'unknown')}`, content "
                        f"**{segment_names.get('content_status', 'UNKNOWN')}**.",
                        f"`segment-ranges`: key index "
                        f"`{segment_ranges.get('key_index', 'unknown')}`, length "
                        f"`{segment_ranges.get('length', 'unknown')}`, descriptor size "
                        f"`{segment_ranges.get('descriptor_size', 'unknown')}`, count "
                        f"`{segment_ranges.get('descriptor_count', 'unknown')}`, semantics "
                        f"**{segment_ranges.get('semantic_status', 'UNKNOWN')}**.",
                    ]
                )
                segment_descriptors = segment_ranges.get("descriptors", [])
                if segment_descriptors:
                    lines.extend(
                        [
                            "",
                            "| Index | Field +0x00 | Field +0x08 | Field +0x10 | Length | Raw flags |",
                            "|---:|---:|---:|---:|---:|---:|",
                        ]
                    )
                    for descriptor in segment_descriptors:
                        lines.append(
                            f"| `{descriptor.get('index', 'unknown')}` | "
                            f"`{descriptor.get('field_00', 'unknown')}` | "
                            f"`{descriptor.get('field_08', 'unknown')}` | "
                            f"`{descriptor.get('field_10', 'unknown')}` | "
                            f"`{descriptor.get('length', 'unknown')}` | "
                            f"`{descriptor.get('flags_raw', 'unknown')}` |"
                        )
                if segment_properties.get("probe_guardrail"):
                    lines.extend(
                        [
                            "",
                            f"Segment-property guardrail: "
                            f"{segment_properties['probe_guardrail']}",
                        ]
                    )
            descriptors = io_registry.get("memory_descriptors", [])
            if descriptors:
                lines.extend(
                    [
                        "",
                        "| Index | Class | Physical | Length | Ranges | Mappings | Role |",
                        "|---:|---|---:|---:|---:|---|---|",
                    ]
                )
                for descriptor in descriptors:
                    lines.append(
                        f"| `{descriptor.get('index', 'unknown')}` | "
                        f"`{io_registry.get('memory_descriptor_class', 'unknown')}` | "
                        f"`{descriptor.get('physical', 'unknown')}` | "
                        f"`{descriptor.get('length', 'unknown')}` | "
                        f"`{descriptor.get('ranges_count', 'unknown')}` | "
                        f"**{descriptor.get('mappings_status', 'UNKNOWN')}** | "
                        f"`{descriptor.get('role', '')}` |"
                    )
            mapping_collection = io_registry.get("mapping_collection")
            if isinstance(mapping_collection, dict):
                live_sample = mapping_collection.get("live_sample", {})
                field_offsets = mapping_collection.get("field_offsets", {})
                lines.extend(
                    [
                        "",
                        "Count-bounded mapping collection: "
                        f"`{mapping_collection.get('set_class', 'unknown')}` members at "
                        f"`{mapping_collection.get('set_members_offset', 'unknown')}` -> "
                        f"`{mapping_collection.get('array_class', 'unknown')}` with count "
                        f"`{mapping_collection.get('array_count', 'unknown')}` and capacity "
                        f"`{mapping_collection.get('array_capacity', 'unknown')}`. Element: "
                        f"**{mapping_collection.get('element_status', 'UNKNOWN')}**; address: "
                        f"**{mapping_collection.get('address_status', 'UNKNOWN')}**.",
                        "Validated `IOMemoryMap`: vtable "
                        f"`{mapping_collection.get('element_vtable_unslid', 'unknown')}`, "
                        f"object size `{mapping_collection.get('element_object_size', 'unknown')}`, "
                        f"`fAddress` at `{field_offsets.get('fAddress', 'unknown')}`.",
                        "Live linkage: "
                        f"`fMemory={live_sample.get('fMemory', 'unknown')}`, "
                        f"`fOffset={live_sample.get('fOffset', 'unknown')}`, "
                        f"`fAddress={live_sample.get('fAddress', 'unknown')}`, "
                        f"`fLength={live_sample.get('fLength', 'unknown')}`.",
                    ]
                )
            if io_registry.get("mapping_probe_guardrail"):
                lines.extend(
                    [
                        "",
                        f"Mapping guardrail: {io_registry['mapping_probe_guardrail']}",
                    ]
                )
        if live_layout["iorvbar_status"] == "VALIDATED":
            lines.extend(
                [
                    "",
                    "The RTBuddy-to-ASC object chain is validated for this sample. The "
                    "IORVBAR physical address remains outside the observed PAPT ranges, and "
                    "`AGXArmFirmwareASC + 0x188` is non-canonical and is not a mapping. A "
                    "count-bounded traversal instead proved an existing `IOMemoryMap`, linked "
                    "it to descriptor 1, and validated its kernel virtual address "
                    f"`{live_layout['iorvbar'].get('kernel_virtual_address', 'unknown')}` with "
                    "length `0x8`. That MMIO address was not dereferenced.",
                ]
            )
        else:
            lines.extend(
                [
                    "",
                    "The RTBuddy-to-ASC object chain is validated for this sample, but the "
                    "IORVBAR physical address is outside the observed PAPT ranges. "
                    "`AGXArmFirmwareASC + 0x188` is non-canonical and is not a mapping. The "
                    "matching `IOGeneralMemoryDescriptor` mapping remains unvalidated.",
                ]
            )
        if live_layout.get("static_layout"):
            static_layout = live_layout["static_layout"]
            lines.extend(
                [
                    "",
                    "Constructor analysis places `+0x180/+0x188` inside the embedded "
                    f"subobject `{static_layout['embedded_subobject_start']}.."
                    f"{static_layout['embedded_subobject_next']}` with vtable "
                    f"`{static_layout['embedded_subobject_vtable_pointer']}`. They are not the "
                    "`AppleASCWrapV4` map/address pair used by older Titan assumptions.",
                ]
            )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A PASS only means the static instruction relationships used by Titan still",
            "resolve. `target_job`, live RTKit addresses, command-buffer setup, the GFX ROP",
            "trigger, and unrestricted physical writes require a separate device probe.",
            "No support range should be widened from this report alone.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=pathlib.Path)
    parser.add_argument("--gfx", required=True, type=pathlib.Path)
    parser.add_argument("--live-layout", type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--json-output", required=True, type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = {
        "diagnostic_only": True,
        "kernel": analyze_kernel(args.kernel.resolve()),
        "gfx": analyze_gfx(args.gfx.resolve()),
    }
    if args.live_layout:
        report["live_layout"] = analyze_live_layout(args.live_layout.resolve())
        report["end_to_end_status"] = report["live_layout"]["end_to_end_status"]
    else:
        report["end_to_end_status"] = "NOT_EVALUATED"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown = render_markdown(report)
    args.output.write_text(markdown, encoding="utf-8")
    args.json_output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
