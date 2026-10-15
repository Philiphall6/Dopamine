#!/usr/bin/env python3
"""Static checks for XPF's SPTM/TXM finders against extracted Mach-O images.

This tool is deliberately diagnostic-only. It does not patch a binary or execute
any kernel/SPTM/TXM code. It reports the anchors and instruction relationships
used by BaseBin/XPF/src/sptm_txm.c so a new firmware can be evaluated before its
support range is changed.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import re
import sys
from collections.abc import Iterable, Sequence

try:
    import lief
except ImportError as exc:  # pragma: no cover - depends on the analyst's host
    raise SystemExit("Install LIEF first: python -m pip install lief") from exc

lief.logging.disable()

try:
    import capstone
    from capstone.arm64 import ARM64_INS_ADD, ARM64_INS_ADR, ARM64_INS_ADRP
    from capstone.arm64 import ARM64_INS_B, ARM64_INS_BL
    from capstone.arm64 import ARM64_INS_CMP, ARM64_INS_MOV
    from capstone.arm64 import ARM64_INS_LDR, ARM64_INS_LDRB
    from capstone.arm64 import ARM64_INS_STR, ARM64_INS_STRB
    from capstone.arm64 import ARM64_REG_WZR, ARM64_REG_XZR
except ImportError as exc:  # pragma: no cover - depends on the analyst's host
    raise SystemExit("Install Capstone first: python -m pip install capstone") from exc


UINT64_MASK = (1 << 64) - 1


@dataclasses.dataclass(frozen=True)
class Reference:
    address: int
    target: int
    kind: str


class MachOImage:
    def __init__(self, path: pathlib.Path, fileset_name: str | None = None) -> None:
        self.path = path
        self.data = path.read_bytes()
        self.container = lief.parse(str(path))
        if self.container is None or not isinstance(
            self.container, lief.MachO.Binary
        ):
            raise ValueError(f"{path} is not a Mach-O binary")
        if fileset_name is None:
            self.binary = self.container
        else:
            self.binary = next(
                (
                    entry
                    for entry in self.container.filesets
                    if entry.fileset_name == fileset_name
                ),
                None,
            )
            if self.binary is None:
                raise ValueError(f"{path} has no fileset named {fileset_name}")

        self.disassembler = capstone.Cs(
            capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN
        )
        self.disassembler.detail = True
        # arm64e images can contain instructions unknown to the host Capstone
        # build. Keep four-byte alignment and continue past those instructions.
        self.disassembler.skipdata = True
        self.instructions = []
        for section in self.binary.sections:
            if section.name not in {"__text", "__bootcode"}:
                continue
            self.instructions.extend(
                self.disassembler.disasm(
                    bytes(section.content), int(section.virtual_address)
                )
            )
        self.instructions.sort(key=lambda instruction: instruction.address)
        self._instruction_index = {
            instruction.address: index
            for index, instruction in enumerate(self.instructions)
        }
        self._references = self._build_references()

    @property
    def imagebase(self) -> int:
        return int(self.binary.imagebase)

    def file_offset_to_vmaddr(self, offset: int) -> int | None:
        for section in self.binary.sections:
            start = int(section.offset)
            end = start + int(section.size)
            if start <= offset < end:
                return int(section.virtual_address) + offset - start
        return None

    def find_string(self, value: str) -> list[int]:
        needle = value.encode("utf-8") + b"\0"
        addresses = []
        offset = self.data.find(needle)
        while offset >= 0:
            vmaddr = self.file_offset_to_vmaddr(offset)
            if vmaddr is not None:
                addresses.append(vmaddr)
            offset = self.data.find(needle, offset + 1)
        return addresses

    def references_to(self, target: int) -> list[Reference]:
        return [
            reference for reference in self._references if reference.target == target
        ]

    def referenced_strings(self, pattern: str) -> list[dict]:
        matcher = re.compile(pattern, re.IGNORECASE)
        entries = []
        for section in self.binary.sections:
            if section.name != "__cstring":
                continue
            content = bytes(section.content)
            cursor = 0
            while cursor < len(content):
                end = content.find(b"\0", cursor)
                if end < 0:
                    end = len(content)
                raw = content[cursor:end]
                if raw:
                    value = raw.decode("utf-8", errors="replace")
                    address = int(section.virtual_address) + cursor
                    references = self.references_to(address)
                    if references and matcher.search(value):
                        entries.append(
                            {
                                "address": address,
                                "value": value,
                                "references": [
                                    dataclasses.asdict(reference)
                                    for reference in references
                                ],
                            }
                        )
                cursor = end + 1
        return entries

    def _build_references(self) -> list[Reference]:
        references: list[Reference] = []
        for index, instruction in enumerate(self.instructions):
            if instruction.id == ARM64_INS_ADR and len(instruction.operands) >= 2:
                target = self._imm(instruction.operands[1])
                references.append(Reference(instruction.address, target, "adr"))
                continue

            if instruction.id != ARM64_INS_ADRP or len(instruction.operands) < 2:
                continue

            register = instruction.operands[0].reg
            page = self._imm(instruction.operands[1])
            for candidate in self.instructions[index + 1 : index + 7]:
                if candidate.address - instruction.address > 24:
                    break
                if candidate.id == 0:
                    continue
                resolved = self._resolve_page_reference(candidate, register, page)
                if resolved is not None:
                    references.append(
                        Reference(candidate.address, resolved, candidate.mnemonic)
                    )
                    break
                if self._writes_register(candidate, register):
                    break
        return self._deduplicate_references(references)

    def calls_to(self, target: int) -> list[int]:
        return [
            instruction.address
            for instruction in self.instructions
            if instruction.id == ARM64_INS_BL
            and instruction.operands
            and self._imm(instruction.operands[0]) == target
        ]

    def instruction_at(self, address: int):
        index = self._instruction_index.get(address)
        return None if index is None else self.instructions[index]

    def branches_to(self, target: int) -> list[int]:
        result = []
        for instruction in self.instructions:
            if instruction.id == 0:
                continue
            if instruction.id not in {ARM64_INS_B, ARM64_INS_BL}:
                groups = set(instruction.groups)
                if capstone.CS_GRP_JUMP not in groups:
                    continue
            for operand in instruction.operands:
                if operand.type == capstone.CS_OP_IMM and self._imm(operand) == target:
                    result.append(instruction.address)
                    break
        return result

    def function_start(self, address: int) -> int | None:
        index = self._index_at_or_before(address)
        if index is None:
            return None
        for instruction in reversed(self.instructions[max(0, index - 512) : index + 1]):
            if instruction.mnemonic in {"pacibsp", "paciasp"}:
                return instruction.address
        return None

    def previous_instruction(
        self,
        address: int,
        instruction_ids: set[int],
        limit: int,
        predicate=None,
    ):
        index = self._index_at_or_before(address)
        if index is None:
            return None
        for instruction in reversed(self.instructions[max(0, index - limit) : index]):
            if instruction.id not in instruction_ids:
                continue
            if predicate is None or predicate(instruction):
                return instruction
        return None

    def next_instruction(
        self, address: int, instruction_ids: set[int], limit: int, predicate=None
    ):
        index = self._index_at_or_before(address)
        if index is None:
            return None
        for instruction in self.instructions[index + 1 : index + 1 + limit]:
            if instruction.id not in instruction_ids:
                continue
            if predicate is None or predicate(instruction):
                return instruction
        return None

    def resolve_data_reference(self, address: int) -> int | None:
        index = self._instruction_index.get(address)
        if index is None:
            return None
        instruction = self.instructions[index]
        memory_operands = [
            operand
            for operand in instruction.operands
            if operand.type == capstone.CS_OP_MEM
        ]
        if not memory_operands:
            return None
        memory = memory_operands[-1].mem
        register = memory.base
        offset = int(memory.disp)
        for previous in reversed(self.instructions[max(0, index - 100) : index]):
            if not self._writes_register(previous, register):
                continue
            if previous.id == ARM64_INS_ADR and len(previous.operands) >= 2:
                return (self._imm(previous.operands[1]) + offset) & UINT64_MASK
            if previous.id == ARM64_INS_ADRP and len(previous.operands) >= 2:
                return (self._imm(previous.operands[1]) + offset) & UINT64_MASK
            if previous.id == ARM64_INS_ADD and len(previous.operands) >= 3:
                source = previous.operands[1]
                immediate = previous.operands[2]
                if (
                    source.type == capstone.CS_OP_REG
                    and immediate.type == capstone.CS_OP_IMM
                ):
                    register = source.reg
                    offset += int(immediate.imm)
                    continue
            return None
        return None

    def window(self, address: int, before: int = 6, after: int = 8) -> list[str]:
        index = self._index_at_or_before(address)
        if index is None:
            return []
        result = []
        for instruction in self.instructions[
            max(0, index - before) : index + after + 1
        ]:
            marker = ">" if instruction.address == address else " "
            result.append(
                f"{marker} 0x{instruction.address:016x}: "
                f"{instruction.mnemonic:<9} {instruction.op_str}"
            )
        return result

    def _index_at_or_before(self, address: int) -> int | None:
        if address in self._instruction_index:
            return self._instruction_index[address]
        candidates = [
            index
            for index, instruction in enumerate(self.instructions)
            if instruction.address <= address
        ]
        return candidates[-1] if candidates else None

    @staticmethod
    def _imm(operand) -> int:
        return int(operand.imm) & UINT64_MASK

    @staticmethod
    def _writes_register(instruction, register: int) -> bool:
        if instruction.id == 0 or not instruction.operands:
            return False
        return (
            instruction.operands[0].type == capstone.CS_OP_REG
            and instruction.operands[0].reg == register
        )

    @staticmethod
    def _resolve_page_reference(instruction, register: int, page: int) -> int | None:
        if instruction.id == ARM64_INS_ADD and len(instruction.operands) >= 3:
            if (
                instruction.operands[1].type == capstone.CS_OP_REG
                and instruction.operands[1].reg == register
                and instruction.operands[2].type == capstone.CS_OP_IMM
            ):
                return (page + int(instruction.operands[2].imm)) & UINT64_MASK
        for operand in instruction.operands:
            if operand.type == capstone.CS_OP_MEM and operand.mem.base == register:
                return (page + int(operand.mem.disp)) & UINT64_MASK
        return None

    @staticmethod
    def _deduplicate_references(references: Iterable[Reference]) -> list[Reference]:
        unique = {}
        for reference in references:
            unique[(reference.address, reference.target, reference.kind)] = reference
        return list(unique.values())


def _is_strb_wzr(instruction) -> bool:
    return (
        instruction.id == ARM64_INS_STRB
        and instruction.operands
        and instruction.operands[0].type == capstone.CS_OP_REG
        and instruction.operands[0].reg in {ARM64_REG_WZR, ARM64_REG_XZR}
    )


def _is_plain_str(instruction) -> bool:
    return instruction.id == ARM64_INS_STR and any(
        operand.type == capstone.CS_OP_MEM for operand in instruction.operands
    )


def _collect_immediate_mask_policy(
    image: MachOImage, frame_type_source_load
) -> dict | None:
    source_index = image._instruction_index[frame_type_source_load.address]
    constants: dict[int, int] = {}
    mask_tests = []
    max_frame_type = None
    frame_type_register = frame_type_source_load.operands[0].reg
    for instruction in image.instructions[source_index + 1 : source_index + 41]:
        operands = instruction.operands if instruction.id != 0 else []
        if (
            instruction.mnemonic == "cmp"
            and len(operands) >= 2
            and operands[0].type == capstone.CS_OP_REG
            and operands[0].reg == frame_type_register
            and operands[1].type == capstone.CS_OP_IMM
        ):
            max_frame_type = int(operands[1].imm)
        elif (
            instruction.mnemonic == "mov"
            and len(operands) >= 2
            and operands[0].type == capstone.CS_OP_REG
            and operands[1].type == capstone.CS_OP_IMM
        ):
            constants[operands[0].reg] = int(operands[1].imm) & 0xFFFFFFFF
            continue
        elif (
            instruction.mnemonic == "movk"
            and len(operands) >= 2
            and operands[0].type == capstone.CS_OP_REG
            and operands[1].type == capstone.CS_OP_IMM
        ):
            register = operands[0].reg
            shift = int(operands[1].shift.value)
            field_mask = (0xFFFF << shift) & 0xFFFFFFFF
            immediate = (int(operands[1].imm) << shift) & field_mask
            constants[register] = (
                constants.get(register, 0) & ~field_mask
            ) | immediate
            continue
        elif instruction.mnemonic == "tst":
            constant_operands = [
                operand
                for operand in operands
                if operand.type == capstone.CS_OP_REG
                and operand.reg in constants
            ]
            if constant_operands:
                mask_tests.append(
                    {
                        "instruction": instruction.address,
                        "mask": constants[constant_operands[-1].reg],
                    }
                )
                if len(mask_tests) == 2:
                    break

        if operands and operands[0].type == capstone.CS_OP_REG:
            constants.pop(operands[0].reg, None)

    if not mask_tests:
        return None
    return {
        "kind": "immediate_bitmask",
        "frame_type_source_load": frame_type_source_load.address,
        "frame_type_source_offset": 2,
        "max_frame_type": max_frame_type,
        "mask_tests": mask_tests,
    }


def analyze_txm(image: MachOImage) -> dict:
    result: dict = {
        "path": str(image.path),
        "imagebase": image.imagebase,
        "anchors": {},
        "device_tree_trust_cache_range": {},
        "trustcache_root_candidates": [],
        "developer_mode_storage_candidates": [],
    }

    for anchor in (
        "/chosen/memory-map",
        "research.com.apple.license-to-operate",
    ):
        addresses = image.find_string(anchor)
        result["anchors"][anchor] = [
            {
                "address": address,
                "references": [
                    dataclasses.asdict(reference)
                    for reference in image.references_to(address)
                ],
            }
            for address in addresses
        ]

    memory_map_entries = result["anchors"].get("/chosen/memory-map", [])
    memory_map_references = (
        memory_map_entries[0].get("references", []) if memory_map_entries else []
    )
    if memory_map_references:
        string_xref = memory_map_references[0]["address"]
        function = image.function_start(string_xref)
        result["device_tree_trust_cache_range"] = {
            "string_xref": string_xref,
            "function": function,
            "window": image.window(string_xref),
        }
        if function is not None:
            for call in image.calls_to(function):
                strb = image.previous_instruction(
                    call, {ARM64_INS_STRB}, 100, _is_strb_wzr
                )
                plain_str = (
                    image.next_instruction(strb.address, {ARM64_INS_STR}, 10, _is_plain_str)
                    if strb is not None
                    else None
                )
                result["trustcache_root_candidates"].append(
                    {
                        "call": call,
                        "branches_to_call": image.branches_to(call),
                        "strb_wzr": strb.address if strb is not None else None,
                        "str": plain_str.address if plain_str is not None else None,
                        "candidate": (
                            image.resolve_data_reference(plain_str.address)
                            if plain_str is not None
                            else None
                        ),
                        "window": image.window(call, before=16, after=5),
                    }
                )

    developer_entries = result["anchors"].get(
        "research.com.apple.license-to-operate", []
    )
    for entry in developer_entries:
        for reference in entry["references"]:
            xref = reference["address"]
            branch_sources = image.branches_to(xref)
            search_from = min(
                branch_sources,
                key=lambda address: abs(address - xref),
                default=xref,
            )
            ldrb = image.previous_instruction(
                search_from, {ARM64_INS_LDRB}, 20
            )
            result["developer_mode_storage_candidates"].append(
                {
                    "string_xref": xref,
                    "branch_sources": branch_sources,
                    "ldrb": ldrb.address if ldrb is not None else None,
                    "candidate": (
                        image.resolve_data_reference(ldrb.address)
                        if ldrb is not None
                        else None
                    ),
                    "window": image.window(search_from, before=12, after=8),
                }
            )

    return result


def analyze_sptm(image: MachOImage) -> dict:
    anchors = ("papt_ranges_update",)
    result: dict = {
        "path": str(image.path),
        "imagebase": image.imagebase,
        "anchors": {},
        "papt_compressed_tables": {},
        "related_referenced_strings": image.referenced_strings(
            r"papt|frame table|frame type|first_phys|last_phys|"
            r"get_page_table_refcnt|libsptm|wfe_timeout"
        ),
    }
    for anchor in anchors:
        entries = []
        for address in image.find_string(anchor):
            references = image.references_to(address)
            entries.append(
                {
                    "address": address,
                    "references": [
                        dataclasses.asdict(reference) for reference in references
                    ],
                    "function_candidates": [
                        image.function_start(reference.address)
                        for reference in references
                    ],
                    "windows": [
                        image.window(reference.address) for reference in references
                    ],
                }
            )
        result["anchors"][anchor] = entries

    papt_entries = result["anchors"].get("papt_ranges_update", [])
    function_candidates = [
        function
        for entry in papt_entries
        for function in entry["function_candidates"]
        if function is not None
    ]
    if function_candidates:
        result["papt_compressed_tables"] = _analyze_papt_compressed_tables(
            image, function_candidates[0]
        )
    return result


def analyze_kernel(image: MachOImage) -> dict:
    anchors = (
        "Debug Header address: %p\n",
        "sptm_get_page_table_refcnt",
        "wfe_events_sec",
        "%s: unexpected pmap_enter_pv ret code: %d. new_pve_p=%p pmap=%p @%s:%d",
        "pv_alloc",
    )
    result: dict = {
        "path": str(image.path),
        "fileset": image.binary.fileset_name,
        "imagebase": image.imagebase,
        "anchors": {},
        "sptm_get_page_table_refcnt": {},
        "refcnt_dependents": {},
        "wfe_timeout_configure": {},
        "libsptm_init": {},
        "sptm_args": {},
    }
    for anchor in anchors:
        entries = []
        for address in image.find_string(anchor):
            references = image.references_to(address)
            entries.append(
                {
                    "address": address,
                    "references": [
                        dataclasses.asdict(reference) for reference in references
                    ],
                    "function_candidates": [
                        image.function_start(reference.address)
                        for reference in references
                    ],
                }
            )
        result["anchors"][anchor] = entries

    refcnt_entries = result["anchors"].get("sptm_get_page_table_refcnt", [])
    refcnt_references = [
        reference
        for entry in refcnt_entries
        for reference in entry["references"]
    ]
    if refcnt_references:
        string_xref = refcnt_references[0]["address"]
        branch_sources = image.branches_to(string_xref - 0x10)
        before_bl = branch_sources[0] if branch_sources else string_xref
        call = image.previous_instruction(before_bl, {ARM64_INS_BL}, 10)
        target = None
        if call is not None and call.operands:
            target = image._imm(call.operands[0])
        result["sptm_get_page_table_refcnt"] = {
            "string_xref": string_xref,
            "branch_sources": branch_sources,
            "call": call.address if call is not None else None,
            "function": target,
            "window": image.window(before_bl, before=12, after=8),
        }
        if target is not None:
            result["refcnt_dependents"] = _analyze_refcnt_dependents(
                image, target
            )

    wfe_entries = result["anchors"].get("wfe_events_sec", [])
    wfe_references = [
        reference for entry in wfe_entries for reference in entry["references"]
    ]
    if wfe_references:
        string_xref = wfe_references[-1]["address"]
        result["wfe_timeout_configure"] = {
            "string_xref": string_xref,
            "function": image.function_start(string_xref),
            "window": image.window(string_xref),
        }

        wfe_function = result["wfe_timeout_configure"]["function"]
        if wfe_function is not None:
            wfe_calls = image.calls_to(wfe_function)
            if wfe_calls:
                call = wfe_calls[0]
                previous_branch = image.previous_instruction(
                    call, {ARM64_INS_B, ARM64_INS_BL}, 20
                )
                libsptm_init = None
                if previous_branch is not None and previous_branch.operands:
                    immediate_operands = [
                        operand
                        for operand in previous_branch.operands
                        if operand.type == capstone.CS_OP_IMM
                    ]
                    if immediate_operands:
                        libsptm_init = image._imm(immediate_operands[0])
                stores = []
                if libsptm_init is not None:
                    start_index = image._instruction_index.get(libsptm_init, 0)
                    for instruction in image.instructions[start_index:]:
                        if instruction.mnemonic not in {"str", "strb", "strh"}:
                            continue
                        stores.append(
                            {
                                "instruction": instruction.address,
                                "target": image.resolve_data_reference(
                                    instruction.address
                                ),
                            }
                        )
                        if len(stores) == 2:
                            break
                result["libsptm_init"] = {
                    "wfe_call": call,
                    "preceding_branch": (
                        previous_branch.address
                        if previous_branch is not None
                        else None
                    ),
                    "function": libsptm_init,
                    "first_stores": stores,
                    "window": (
                        image.window(libsptm_init, before=0, after=20)
                        if libsptm_init is not None
                        else []
                    ),
                }

    debug_entries = result["anchors"].get("Debug Header address: %p\n", [])
    debug_references = [
        reference for entry in debug_entries for reference in entry["references"]
    ]
    if debug_references:
        string_xref = debug_references[0]["address"]
        index = image._index_at_or_before(string_xref - 4)
        adrp = None
        if index is not None:
            for instruction in reversed(
                image.instructions[max(0, index - 20) : index]
            ):
                if instruction.id == ARM64_INS_ADRP:
                    adrp = instruction
                    break
        load = None
        target = None
        if adrp is not None:
            register = adrp.operands[0].reg
            adrp_index = image._instruction_index[adrp.address]
            for instruction in image.instructions[adrp_index + 1 : adrp_index + 21]:
                memory_operands = [
                    operand
                    for operand in instruction.operands
                    if operand.type == capstone.CS_OP_MEM
                ] if instruction.id != 0 else []
                if (
                    instruction.mnemonic.startswith("ldr")
                    and memory_operands
                    and memory_operands[-1].mem.base == register
                ):
                    load = instruction
                    target = image.resolve_data_reference(instruction.address)
                    break
        result["sptm_args"] = {
            "string_xref": string_xref,
            "adrp": adrp.address if adrp is not None else None,
            "load": load.address if load is not None else None,
            "target": target,
            "window": image.window(string_xref, before=20, after=5),
        }
    return result


def _analyze_refcnt_dependents(image: MachOImage, function: int) -> dict:
    start_index = image._instruction_index.get(function)
    if start_index is None:
        return {"error": "refcount helper is outside decoded text"}

    loads = []
    for instruction in image.instructions[start_index : start_index + 256]:
        if instruction.id == 0 or not instruction.mnemonic.startswith("ldr"):
            continue
        if not any(
            operand.type == capstone.CS_OP_MEM for operand in instruction.operands
        ):
            continue
        loads.append(instruction)

    def load_target(index: int) -> int | None:
        if index >= len(loads):
            return None
        return image.resolve_data_reference(loads[index].address)

    frame_type_source_load = next(
        (
            instruction
            for instruction in image.instructions[start_index : start_index + 256]
            if instruction.mnemonic == "ldrb"
            and any(
                operand.type == capstone.CS_OP_MEM and operand.mem.disp == 2
                for operand in instruction.operands
            )
        ),
        None,
    )
    ldrb_one = next(
        (
            instruction
            for instruction in image.instructions[start_index : start_index + 256]
            if instruction.mnemonic == "ldrb"
            and any(
                operand.type == capstone.CS_OP_MEM and operand.mem.disp == 1
                for operand in instruction.operands
            )
        ),
        None,
    )
    frame_type_load = None
    frame_type_params = None
    descriptor_size = None
    frame_type_policy: dict = {"kind": "unresolved"}
    if ldrb_one is not None:
        frame_type_load = image.previous_instruction(
            ldrb_one.address,
            {ARM64_INS_LDR, ARM64_INS_LDRB},
            10,
            lambda instruction: instruction.mnemonic.startswith("ldr"),
        )
        if frame_type_load is not None:
            frame_type_params = image.resolve_data_reference(frame_type_load.address)
            frame_type_index = image._instruction_index[frame_type_load.address]
            size_instruction = image.instructions[frame_type_index + 1]
            if (
                size_instruction.mnemonic == "mov"
                and len(size_instruction.operands) >= 2
                and size_instruction.operands[1].type == capstone.CS_OP_IMM
            ):
                descriptor_size = int(size_instruction.operands[1].imm)
        if frame_type_params is not None and descriptor_size is not None:
            frame_type_policy = {
                "kind": "descriptor_table",
                "frame_type_source_load": (
                    frame_type_source_load.address
                    if frame_type_source_load is not None
                    else None
                ),
                "frame_type_source_offset": 2,
                "table": frame_type_params,
                "descriptor_size": descriptor_size,
                "policy_load": ldrb_one.address,
                "policy_byte_offset": 1,
            }

    if frame_type_policy["kind"] == "unresolved" and frame_type_source_load:
        immediate_policy = _collect_immediate_mask_policy(
            image, frame_type_source_load
        )
        if immediate_policy is not None:
            frame_type_policy = immediate_policy

    frame_table_pattern = None
    frame_table_load = None
    frame_table = None
    search = image.instructions[start_index :]
    search_end = function + 0x100
    for index, instruction in enumerate(search):
        if instruction.address >= search_end:
            break
        if instruction.mnemonic != "lsr" or len(instruction.operands) < 3:
            continue
        shift = instruction.operands[2]
        if shift.type != capstone.CS_OP_IMM:
            continue
        following = search[index + 1 : index + 3]
        is_ios18_pattern = (
            int(shift.imm) == 14
            and following
            and following[0].mnemonic == "add"
            and "lsl #4" in following[0].op_str
        )
        is_ios17_pattern = (
            int(shift.imm) == 10
            and len(following) == 2
            and following[0].mnemonic == "and"
            and following[1].mnemonic == "add"
        )
        if is_ios18_pattern or is_ios17_pattern:
            frame_table_pattern = instruction.address
            frame_table_load = image.previous_instruction(
                instruction.address,
                {ARM64_INS_LDR, ARM64_INS_LDRB},
                10,
                lambda candidate: candidate.mnemonic.startswith("ldr"),
            )
            if frame_table_load is not None:
                frame_table = image.resolve_data_reference(frame_table_load.address)
            break

    return {
        "load_sequence": [
            {
                "instruction": instruction.address,
                "mnemonic": instruction.mnemonic,
                "target": image.resolve_data_reference(instruction.address),
            }
            for instruction in loads[:6]
        ],
        "vm_first_phys": load_target(1),
        "vm_last_phys": load_target(2),
        "libsptm_frame_type_params": frame_type_params,
        "frame_type_descriptor_size": descriptor_size,
        "frame_type_policy": frame_type_policy,
        "frame_type_load": (
            frame_type_load.address if frame_type_load is not None else None
        ),
        "libsptm_frame_table": frame_table,
        "frame_table_pattern": frame_table_pattern,
        "frame_table_load": (
            frame_table_load.address if frame_table_load is not None else None
        ),
        "window": image.window(function, before=0, after=72),
    }


def _analyze_papt_compressed_tables(image: MachOImage, function: int) -> dict:
    start_index = image._instruction_index.get(function)
    if start_index is None:
        return {"error": "function start is outside decoded text"}

    compare = None
    for instruction in image.instructions[start_index : start_index + 30]:
        if instruction.id != ARM64_INS_CMP or len(instruction.operands) < 2:
            continue
        if (
            instruction.operands[1].type == capstone.CS_OP_IMM
            and int(instruction.operands[1].imm) == 1
        ):
            compare = instruction
            break
    if compare is None:
        return {"error": "cmp w?, #1 was not found in the first 30 instructions"}

    cursor = compare.address
    last_jump_target = None
    terminator = None
    for _ in range(50):
        instruction = image.instruction_at(cursor)
        if instruction is None:
            break
        if instruction.mnemonic == "b" and instruction.operands:
            target_operands = [
                operand
                for operand in instruction.operands
                if operand.type == capstone.CS_OP_IMM
            ]
            if target_operands:
                last_jump_target = image._imm(target_operands[0])
                cursor = last_jump_target
                continue
        if (
            instruction.id == ARM64_INS_MOV
            and len(instruction.operands) >= 2
            and instruction.reg_name(instruction.operands[0].reg) == "x17"
            and instruction.operands[1].type == capstone.CS_OP_IMM
            and int(instruction.operands[1].imm) == 0xE4FE
        ):
            terminator = instruction.address
            break
        cursor += 4

    range_start = last_jump_target or compare.address
    range_end = terminator or cursor
    address_refs = []
    for instruction in image.instructions:
        if instruction.address < range_start:
            continue
        if instruction.address >= range_end:
            break
        if instruction.id not in {ARM64_INS_ADR, ARM64_INS_ADRP}:
            continue
        if instruction.id == ARM64_INS_ADR:
            target = image._imm(instruction.operands[1])
        else:
            following = image.instruction_at(instruction.address + 4)
            target = None
            if following is not None and following.id != 0:
                target = image._resolve_page_reference(
                    following,
                    instruction.operands[0].reg,
                    image._imm(instruction.operands[1]),
                )
        address_refs.append(
            {
                "instruction": instruction.address,
                "target": target,
                "window": image.window(instruction.address, before=2, after=3),
            }
        )
        if len(address_refs) == 2:
            break

    return {
        "compare": compare.address,
        "range_start": range_start,
        "range_end": range_end,
        "n_papt_ranges_compressed": (
            address_refs[0]["target"] if len(address_refs) > 0 else None
        ),
        "papt_ranges_compressed": (
            address_refs[1]["target"] if len(address_refs) > 1 else None
        ),
        "references": address_refs,
    }


def _format_address(value: int | None) -> str:
    return "not resolved" if value is None else f"0x{value:016x}"


def _append_window(lines: list[str], window: Sequence[str]) -> None:
    if not window:
        return
    lines.extend(("", "```asm", *window, "```"))


def render_markdown(txm: dict, sptm: dict, kernel: dict | None) -> str:
    txm_static_ok = bool(
        txm["device_tree_trust_cache_range"].get("function")
        and any(
            candidate.get("candidate")
            for candidate in txm["trustcache_root_candidates"]
        )
        and any(
            candidate.get("candidate")
            for candidate in txm["developer_mode_storage_candidates"]
        )
    )
    sptm_static_ok = bool(
        sptm["papt_compressed_tables"].get("n_papt_ranges_compressed")
        and sptm["papt_compressed_tables"].get("papt_ranges_compressed")
    )
    frame_type_policy = (
        kernel["refcnt_dependents"].get("frame_type_policy", {})
        if kernel
        else {}
    )
    frame_type_policy_ok = bool(
        (
            frame_type_policy.get("kind") == "descriptor_table"
            and frame_type_policy.get("table")
            and frame_type_policy.get("descriptor_size")
            and frame_type_policy.get("policy_byte_offset") is not None
        )
        or (
            frame_type_policy.get("kind") == "immediate_bitmask"
            and frame_type_policy.get("mask_tests")
        )
    )
    kernel_static_ok = bool(
        kernel
        and kernel["sptm_get_page_table_refcnt"].get("function")
        and kernel["refcnt_dependents"].get("libsptm_frame_table")
        and frame_type_policy_ok
        and kernel["libsptm_init"].get("function")
        and kernel["sptm_args"].get("target")
    )
    lines = [
        "# SPTM/TXM static compatibility report",
        "",
        "This report is diagnostic-only. Addresses are unslid virtual addresses",
        "from the extracted firmware images.",
        "",
        "## Result",
        "",
        f"- TXM XPF relationships: {'PASS' if txm_static_ok else 'INCOMPLETE'}",
        f"- SPTM-image XPF relationships: {'PASS' if sptm_static_ok else 'INCOMPLETE'}",
        f"- Kernel-side SPTM relationships: {'PASS' if kernel_static_ok else 'INCOMPLETE'}",
        "- SPTM bypass primitive: NOT PROVIDED by this analysis",
        "",
        "## TXM",
        "",
        f"- Image base: `{_format_address(txm['imagebase'])}`",
    ]

    for anchor, entries in txm["anchors"].items():
        if not entries:
            lines.append(f"- Anchor `{anchor}`: missing")
            continue
        reference_count = sum(len(entry["references"]) for entry in entries)
        lines.append(
            f"- Anchor `{anchor}`: {len(entries)} occurrence(s), "
            f"{reference_count} code reference(s)"
        )

    device_tree = txm["device_tree_trust_cache_range"]
    lines.extend(
        (
            "",
            "### Trust cache path",
            "",
            "- `txm_deviceTreeTrustCacheRange`: "
            + _format_address(device_tree.get("function")),
        )
    )
    _append_window(lines, device_tree.get("window", []))

    candidates = txm["trustcache_root_candidates"]
    if not candidates:
        lines.append("- `txm_trustcache_root`: no candidate")
    for index, candidate in enumerate(candidates, start=1):
        lines.extend(
            (
                f"- Candidate {index} call: `{_format_address(candidate['call'])}`",
                f"- Candidate {index} root: `{_format_address(candidate['candidate'])}`",
                f"- Candidate {index} predecessor branches: "
                + ", ".join(
                    f"`{_format_address(address)}`"
                    for address in candidate["branches_to_call"]
                )
                if candidate["branches_to_call"]
                else f"- Candidate {index} predecessor branches: none",
            )
        )
        _append_window(lines, candidate["window"])

    lines.extend(("", "### Developer mode path", ""))
    developer_candidates = txm["developer_mode_storage_candidates"]
    if not developer_candidates:
        lines.append("- `txm_developer_mode_storage`: no candidate")
    for index, candidate in enumerate(developer_candidates, start=1):
        lines.append(
            f"- Candidate {index}: `{_format_address(candidate['candidate'])}` "
            f"from LDRB `{_format_address(candidate['ldrb'])}`"
        )
        _append_window(lines, candidate["window"])

    lines.extend(
        (
            "",
            "## SPTM",
            "",
            f"- Image base: `{_format_address(sptm['imagebase'])}`",
        )
    )
    for anchor, entries in sptm["anchors"].items():
        if not entries:
            lines.append(f"- Anchor `{anchor}`: missing")
            continue
        reference_count = sum(len(entry["references"]) for entry in entries)
        functions = sorted(
            {
                function
                for entry in entries
                for function in entry["function_candidates"]
                if function is not None
            }
        )
        lines.append(
            f"- Anchor `{anchor}`: {len(entries)} occurrence(s), "
            f"{reference_count} reference(s), functions "
            + (", ".join(f"`{_format_address(value)}`" for value in functions) or "none")
        )
        for entry in entries:
            for window in entry["windows"]:
                _append_window(lines, window)

    papt_tables = sptm["papt_compressed_tables"]
    lines.extend(("", "### Compressed PAPT tables", ""))
    if "error" in papt_tables:
        lines.append(f"- Error: {papt_tables['error']}")
    elif papt_tables:
        lines.extend(
            (
                "- `n_papt_ranges_compressed`: "
                + _format_address(papt_tables["n_papt_ranges_compressed"]),
                "- `papt_ranges_compressed`: "
                + _format_address(papt_tables["papt_ranges_compressed"]),
                "- Finder range: "
                + f"`{_format_address(papt_tables['range_start'])}` to "
                + f"`{_format_address(papt_tables['range_end'])}`",
            )
        )
        for reference in papt_tables["references"]:
            _append_window(lines, reference["window"])
    else:
        lines.append("- Not analyzed")

    lines.extend(("", "### Related referenced strings", ""))
    related_strings = sptm["related_referenced_strings"]
    if not related_strings:
        lines.append("- No matching directly referenced string")
    for entry in related_strings:
        references = ", ".join(
            f"`{_format_address(reference['address'])}`"
            for reference in entry["references"]
        )
        lines.append(
            f"- `{entry['value']}` at `{_format_address(entry['address'])}`; "
            f"references: {references}"
        )

    if kernel is not None:
        lines.extend(
            (
                "",
                "## Kernel-side SPTM anchors",
                "",
                f"- Fileset: `{kernel['fileset']}`",
                f"- Image base: `{_format_address(kernel['imagebase'])}`",
            )
        )
        for anchor, entries in kernel["anchors"].items():
            if not entries:
                lines.append(f"- Anchor `{anchor.rstrip()}`: missing")
                continue
            reference_count = sum(len(entry["references"]) for entry in entries)
            lines.append(
                f"- Anchor `{anchor.rstrip()}`: {len(entries)} occurrence(s), "
                f"{reference_count} reference(s)"
            )

        refcnt = kernel["sptm_get_page_table_refcnt"]
        lines.extend(
            (
                "",
                "### Page-table refcount helper",
                "",
                "- `sptm_get_page_table_refcnt`: "
                + _format_address(refcnt.get("function")),
            )
        )
        _append_window(lines, refcnt.get("window", []))

        dependents = kernel["refcnt_dependents"]
        if dependents:
            policy = dependents.get("frame_type_policy", {})
            lines.extend(
                (
                    "",
                    "### Refcount-dependent globals",
                    "",
                    "- `vm_first_phys`: "
                    + _format_address(dependents.get("vm_first_phys")),
                    "- `vm_last_phys`: "
                    + _format_address(dependents.get("vm_last_phys")),
                    "- `libsptm_frame_table`: "
                    + _format_address(dependents.get("libsptm_frame_table")),
                    "- `libsptm_frame_type_params`: "
                    + _format_address(
                        dependents.get("libsptm_frame_type_params")
                    ),
                    "- `sptm_frame_type_descriptor.struct_size`: "
                    + str(dependents.get("frame_type_descriptor_size") or "not resolved"),
                    "- `frame_type_policy.kind`: "
                    + str(policy.get("kind", "unresolved")),
                )
            )
            if policy.get("kind") == "descriptor_table":
                lines.extend(
                    (
                        "- `frame_type_policy.table`: "
                        + _format_address(policy.get("table")),
                        "- `frame_type_policy.descriptor_size`: "
                        + str(policy.get("descriptor_size")),
                        "- `frame_type_policy.policy_byte_offset`: "
                        + str(policy.get("policy_byte_offset")),
                    )
                )
            elif policy.get("kind") == "immediate_bitmask":
                masks = ", ".join(
                    f"`0x{entry['mask']:08x}`"
                    for entry in policy.get("mask_tests", [])
                )
                lines.extend(
                    (
                        "- `frame_type_policy.frame_type_source_offset`: "
                        + str(policy.get("frame_type_source_offset")),
                        "- `frame_type_policy.max_frame_type`: "
                        + str(policy.get("max_frame_type")),
                        "- `frame_type_policy.masks`: " + (masks or "none"),
                    )
                )
            _append_window(lines, dependents.get("window", []))

        wfe = kernel["wfe_timeout_configure"]
        lines.extend(
            (
                "",
                "### libsptm initialization anchor",
                "",
                "- `wfe_timeout_configure`: "
                + _format_address(wfe.get("function")),
            )
        )
        _append_window(lines, wfe.get("window", []))

        libsptm = kernel["libsptm_init"]
        if libsptm:
            lines.append(
                "- `libsptm_init`: "
                + _format_address(libsptm.get("function"))
            )
            for index, store in enumerate(libsptm.get("first_stores", [])):
                name = "libsptm_n_papt_ranges" if index == 0 else "libsptm_papt_ranges"
                lines.append(
                    f"- `{name}`: {_format_address(store.get('target'))}"
                )
            _append_window(lines, libsptm.get("window", []))

        sptm_args = kernel["sptm_args"]
        lines.extend(
            (
                "",
                "### SPTM argument block",
                "",
                "- `SPTMArgs`: " + _format_address(sptm_args.get("target")),
            )
        )
        _append_window(lines, sptm_args.get("window", []))

    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--txm", type=pathlib.Path, required=True)
    parser.add_argument("--sptm", type=pathlib.Path, required=True)
    parser.add_argument("--kernel", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--json-output", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    txm = analyze_txm(MachOImage(args.txm))
    sptm = analyze_sptm(MachOImage(args.sptm))
    kernel = (
        analyze_kernel(MachOImage(args.kernel, fileset_name="com.apple.kernel"))
        if args.kernel
        else None
    )
    markdown = render_markdown(txm, sptm, kernel)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(markdown, encoding="utf-8")
    else:
        print(markdown)

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps({"txm": txm, "sptm": sptm, "kernel": kernel}, indent=2),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
