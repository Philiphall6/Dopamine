#!/usr/bin/env python3
"""Compare the AGX/SPTM handoff with the iOS 26 GFX UPPL state.

This tool is diagnostic-only. It reads extracted firmware images, records
direct static references, and never executes firmware or emits a protected
component request.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import struct
from collections import Counter
from collections.abc import Sequence

import lief

from analyze_sptm_txm import MachOImage, _collect_iommu_registration_topology
from analyze_titan import (
    MappedImage,
    disassemble_gfx_text,
    parse_gfx_images,
    parse_immediate_operand,
)


HANDOFF_PATTERN = (
    r"microPPL|gfx-handoff-(?:base|size)|gpu-iouat|"
    r"uat-enforce-gpu-carveout|uat_register_gfx_data_segment|"
    r"handoff_region->powered_off|%s-data-(?:base|size)|data segment"
)
RELEVANT_PATCH_SYMBOLS = (
    "__rtk_patch_uat_gptbat_base",
    "__rtk_patch_uat_gptbat_size",
    "__rtk_patch_uat_ppl_shared_base",
    "__rtk_patch_uat_ppl_shared_l2_phys",
)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def decode_patch_descriptor_bytes(raw: bytes) -> dict:
    """Decode an RTKit 4-byte tag, value width, and inline default value."""
    if len(raw) < 8:
        raise ValueError("patch descriptor is shorter than its 8-byte header")
    width = struct.unpack_from("<I", raw, 4)[0]
    if width not in {1, 2, 4, 8}:
        raise ValueError(f"unsupported patch descriptor width {width}")
    if len(raw) < 8 + width:
        raise ValueError("patch descriptor does not contain its complete value")
    return {
        "tag": raw[:4].decode("ascii", errors="replace"),
        "width": width,
        "default": int.from_bytes(raw[8 : 8 + width], "little"),
    }


def decode_frame_type_policy_record(raw: bytes, frame_type: int) -> dict:
    if len(raw) < 0x58:
        raise ValueError("frame-type policy record is shorter than 0x58 bytes")
    return {
        "frame_type": frame_type,
        "flags": raw[0],
        "policy_class": raw[1],
        "state_flags": raw[2],
        "allowed_domain_bitmap": struct.unpack_from("<Q", raw, 8)[0],
        "maximum_mapping_class": raw[0x10],
        "mapping_policy_byte_0x11": raw[0x11],
        "retype_in_encoded": struct.unpack_from("<Q", raw, 0x48)[0],
        "retype_out_encoded": struct.unpack_from("<Q", raw, 0x50)[0],
    }


def decode_domain_bitmap(bitmap: int, names: dict[int, str]) -> list[dict]:
    return [
        {"id": domain, "name": names.get(domain)}
        for domain in range(64)
        if bitmap & (1 << domain)
    ]


def collect_frame_type_names(image: MachOImage, count: int = 0x40) -> dict:
    anchors = image.find_string("SPTM_UNTYPED")
    if not anchors:
        return {"status": "NOT_FOUND", "table": None, "entries": []}
    target = anchors[0]
    for section in image.binary.sections:
        content = bytes(section.content)
        section_address = int(section.virtual_address)
        for offset in range(0, len(content) - 7, 8):
            encoded = struct.unpack_from("<Q", content, offset)[0]
            if image.resolve_chained_pointer(encoded) != target:
                continue
            table = section_address + offset
            entries = []
            for frame_type in range(count):
                name_address = image.resolve_chained_pointer(
                    image.read_u64(table + frame_type * 8)
                )
                entries.append(
                    {
                        "frame_type": frame_type,
                        "name": (
                            image.read_cstring(name_address)
                            if name_address is not None
                            else None
                        ),
                    }
                )
            names = {entry["frame_type"]: entry["name"] for entry in entries}
            if names.get(0) == "SPTM_UNTYPED" and names.get(0xB) == "XNU_DEFAULT":
                return {
                    "status": "FRAME_TYPE_NAME_TABLE_CONFIRMED",
                    "table": table,
                    "entries": entries,
                }
    return {"status": "NOT_FOUND", "table": None, "entries": []}


def classify_retype_callback(instructions: Sequence) -> str:
    body = [
        instruction
        for instruction in instructions
        if instruction.mnemonic not in {"bti", "nop"}
    ]
    if body and body[0].mnemonic in {"ret", "retab"}:
        return "NO_OP"

    has_type_read = any(
        instruction.mnemonic == "ldrb" and instruction.op_str == "w8, [x0, #2]"
        for instruction in body
    )
    has_type_0x11_compare = any(
        instruction.mnemonic == "cmp" and instruction.op_str == "w8, #0x11"
        for instruction in body
    )
    has_metadata_clear = any(
        instruction.mnemonic == "strh" and instruction.op_str == "wzr, [x0, #4]"
        for instruction in body
    )
    if has_type_read and has_type_0x11_compare and has_metadata_clear:
        return "TYPE_0X11_METADATA_CLEAR"
    return "NONTRIVIAL"


def _retype_callback_body(image: MachOImage, address: int, limit: int = 16) -> list:
    index = image._instruction_index.get(address)
    if index is None:
        return []
    body = []
    for instruction in image.instructions[index : index + limit]:
        body.append(instruction)
        if instruction.mnemonic in {"ret", "retab"}:
            break
    return body


def _retype_callback_names(image: MachOImage) -> dict[int, str]:
    names: dict[int, str] = {}
    for entry in image.referenced_strings(r"retype_(?:in|out)"):
        for reference in entry["references"]:
            function = image.function_start(reference["address"])
            if function is not None:
                names.setdefault(function, entry["value"])
    return names


def decode_retype_callback(
    image: MachOImage, encoded: int, names: dict[int, str]
) -> dict:
    address = image.resolve_chained_pointer(encoded)
    if address is None:
        return {"encoded": encoded, "address": None, "behavior": "UNRESOLVED"}
    body = _retype_callback_body(image, address)
    return {
        "encoded": encoded,
        "address": address,
        "name": names.get(address),
        "behavior": classify_retype_callback(body),
        "preview": [
            {
                "address": instruction.address,
                "mnemonic": instruction.mnemonic,
                "op_str": instruction.op_str,
            }
            for instruction in body
        ],
    }


def decode_patch_descriptor(image: MappedImage, name: str) -> dict:
    address = image.symbols[name]
    header = image.read(address, 8)
    width = struct.unpack_from("<I", header, 4)[0]
    decoded = decode_patch_descriptor_bytes(header + image.read(address + 8, width))
    return {"symbol": name, "address": address, **decoded}


def _memory_offset(op_str: str, register: str) -> int | None:
    match = re.search(
        rf"\[{re.escape(register)}(?:,\s*#(?P<offset>-?0x[0-9a-f]+|-?\d+))?\]",
        op_str.lower(),
    )
    if not match:
        return None
    value = match.group("offset")
    return 0 if value is None else int(value, 0)


def _access_kind(mnemonic: str) -> str:
    if mnemonic.startswith("st"):
        return "write"
    if mnemonic.startswith("ld"):
        return "read"
    return "unknown"


def collect_state_materializations(
    instructions: Sequence[dict], target: int
) -> list[dict]:
    """Collect bounded ADRP-based references to one exact GFX state object."""
    references = []
    for index, first in enumerate(instructions):
        if first["mnemonic"] != "adrp":
            continue
        parts = [part.strip().lower() for part in first["op_str"].split(",")]
        if len(parts) != 2:
            continue
        register = parts[0]
        page = parse_immediate_operand(parts[1])
        if page is None:
            continue

        for candidate_index in range(index + 1, min(index + 7, len(instructions))):
            candidate = instructions[candidate_index]
            candidate_parts = [
                part.strip().lower() for part in candidate["op_str"].split(",")
            ]
            resolved = None
            access_register = register
            access = candidate

            if candidate["mnemonic"] == "add" and len(candidate_parts) == 3:
                if candidate_parts[1] == register:
                    offset = parse_immediate_operand(candidate_parts[2])
                    if offset is not None:
                        resolved = page + offset
                        access_register = candidate_parts[0]
                        for following in instructions[
                            candidate_index + 1 : candidate_index + 9
                        ]:
                            if _memory_offset(following["op_str"], access_register) is not None:
                                access = following
                                break
            else:
                offset = _memory_offset(candidate["op_str"], register)
                if offset is not None:
                    resolved = page + offset

            if resolved != target:
                continue
            references.append(
                {
                    "materialization": first["address"],
                    "resolution": candidate["address"],
                    "access": access["address"],
                    "instruction": f"{access['mnemonic']} {access['op_str']}".strip(),
                    "kind": _access_kind(access["mnemonic"]),
                }
            )
            break

    unique = {
        (item["materialization"], item["resolution"], item["access"]): item
        for item in references
    }
    return list(unique.values())


def _function_body(image: MachOImage, start: int, limit: int = 384):
    index = image._instruction_index.get(start)
    if index is None:
        return []
    body = []
    for instruction in image.instructions[index : index + limit]:
        if instruction.address != start and instruction.mnemonic in {"pacibsp", "paciasp"}:
            break
        body.append(instruction)
    return body


def _reconstruct_handoff_magic(body: Sequence) -> int | None:
    values: dict[str, int] = {}
    for instruction in body[:64]:
        parts = [part.strip().lower() for part in instruction.op_str.split(",")]
        if len(parts) < 2 or not parts[0].startswith("x"):
            continue
        register = parts[0]
        immediate = parse_immediate_operand(parts[1])
        if immediate is None:
            continue
        if instruction.mnemonic == "mov":
            values[register] = immediate & ((1 << 64) - 1)
        elif instruction.mnemonic == "movk" and register in values:
            shift = 0
            if len(parts) >= 3:
                shift_parts = parts[2].split()
                if len(shift_parts) != 2 or shift_parts[0] != "lsl":
                    continue
                parsed = parse_immediate_operand(shift_parts[1])
                if parsed is None:
                    continue
                shift = parsed
            mask = 0xFFFF << shift
            values[register] = (values[register] & ~mask) | (immediate << shift)
            if values[register] >> 48 == 0x4B1D:
                return values[register]
    return None


def _branch_target(instruction) -> int | None:
    if instruction.mnemonic not in {"b", "bl"} and not instruction.mnemonic.startswith(
        "b."
    ):
        return None
    return parse_immediate_operand(instruction.op_str)


def _gfx_branch_target(instruction: dict) -> int | None:
    if instruction["mnemonic"] not in {"b", "bl"}:
        return None
    return parse_immediate_operand(instruction["op_str"])


def _gfx_function_start(instructions: Sequence[dict], index: int) -> int | None:
    """Recover a bounded GFX function start from its PAC prologue."""
    for candidate_index in range(index, max(-1, index - 4096), -1):
        candidate = instructions[candidate_index]
        if candidate["mnemonic"] in {"pacibsp", "paciasp"}:
            return candidate["address"]
    return None


def _gfx_function_body(
    instructions: Sequence[dict], start: int, limit: int = 4096
) -> list[dict]:
    index = next(
        (i for i, instruction in enumerate(instructions) if instruction["address"] == start),
        None,
    )
    if index is None:
        return []
    body = []
    for instruction in instructions[index : index + limit]:
        if (
            instruction["address"] != start
            and instruction["mnemonic"] in {"pacibsp", "paciasp"}
        ):
            break
        body.append(instruction)
        if instruction["mnemonic"] in {"ret", "retab"}:
            break
    return body


def _gfx_direct_callers(
    instructions: Sequence[dict], target: int
) -> list[dict]:
    callers = []
    for index, instruction in enumerate(instructions):
        if _gfx_branch_target(instruction) != target:
            continue
        function = _gfx_function_start(instructions, index)
        callers.append(
            {
                "callsite": instruction["address"],
                "function": function,
                "branch_kind": instruction["mnemonic"],
            }
        )
    return callers


def _gfx_exact_pointer_references(image: MappedImage, target: int) -> list[int]:
    encoded = struct.pack("<Q", target)
    references = []
    for segment in image.segments:
        start = 0
        while True:
            offset = segment.content.find(encoded, start)
            if offset < 0:
                break
            references.append(segment.vmaddr + offset)
            start = offset + 1
    return references


def _gfx_function_markers(body: Sequence[dict]) -> list[str]:
    markers = []
    operands = "\n".join(instruction["op_str"].lower() for instruction in body)
    for marker, operand in (
        ("writes_ttbr0_el1", "ttbr0_el1"),
        ("writes_tcr_el1", "tcr_el1"),
        ("writes_sctlr_el1", "sctlr_el1"),
    ):
        if operand in operands:
            markers.append(marker)
    return markers


def analyze_gxf_map_producer(
    image: MappedImage, instructions: Sequence[dict]
) -> dict:
    """Trace the local producer of direct GXF command 0x10.

    The result records static call provenance only. It deliberately does not
    treat the GXF packet as an SPTM endpoint request.
    """
    enter = image.symbols.get("__mmu_gxf_enter")
    constructor = None
    command_assignment = None
    command_store = None
    submit_wrapper = None

    for index, instruction in enumerate(instructions):
        if instruction["mnemonic"] != "mov" or instruction["op_str"] != "w8, #0x10":
            continue
        function = _gfx_function_start(instructions, index)
        if function is None:
            continue
        body = _gfx_function_body(instructions, function, 128)
        local_index = next(
            (
                i
                for i, candidate in enumerate(body)
                if candidate["address"] == instruction["address"]
            ),
            None,
        )
        if local_index is None:
            continue
        store = next(
            (
                candidate
                for candidate in body[local_index + 1 : local_index + 5]
                if candidate["mnemonic"].startswith("st")
                and candidate["op_str"].startswith("w8, ")
            ),
            None,
        )
        call = next(
            (
                candidate
                for candidate in body[local_index + 1 : local_index + 16]
                if candidate["mnemonic"] == "bl"
            ),
            None,
        )
        if store is None or call is None:
            continue
        candidate_wrapper = _gfx_branch_target(call)
        wrapper_body = (
            _gfx_function_body(instructions, candidate_wrapper, 128)
            if candidate_wrapper is not None
            else []
        )
        if enter is None or not any(
            _gfx_branch_target(candidate) == enter for candidate in wrapper_body
        ):
            continue
        constructor = function
        command_assignment = instruction["address"]
        command_store = store["address"]
        submit_wrapper = candidate_wrapper
        break

    if constructor is None:
        return {
            "status": "GXF_MAP_CONSTRUCTOR_NOT_FOUND",
            "command": 0x10,
            "constructor": None,
        }

    constructor_callers = _gfx_direct_callers(instructions, constructor)
    serialized_wrapper = (
        constructor_callers[0]["function"]
        if len({item["function"] for item in constructor_callers}) == 1
        else None
    )
    wrapper_callers = (
        _gfx_direct_callers(instructions, serialized_wrapper)
        if serialized_wrapper is not None
        else []
    )
    symbols_by_address = {address: name for name, address in image.symbols.items()}
    producer_functions = []
    for function in sorted(
        {item["function"] for item in wrapper_callers if item["function"] is not None}
    ):
        body = _gfx_function_body(instructions, function)
        symbol = symbols_by_address.get(function)
        markers = _gfx_function_markers(body)
        if symbol == "__rtk_arm_start_bootstrap_area":
            role = "rtkit_bootstrap_translation_setup"
        elif markers:
            role = "translation_setup"
        else:
            role = "internal_memory_map_path"
        producer_functions.append(
            {
                "function": function,
                "symbol": symbol,
                "role": role,
                "markers": markers,
                "callsites": [
                    item["callsite"]
                    for item in wrapper_callers
                    if item["function"] == function
                ],
            }
        )

    return {
        "status": "GXF_MAP_LOCAL_PRODUCER_CONFIRMED",
        "command": 0x10,
        "constructor": constructor,
        "command_assignment": command_assignment,
        "command_store": command_store,
        "submit_wrapper": submit_wrapper,
        "gxf_enter": enter,
        "serialized_wrapper": serialized_wrapper,
        "constructor_callers": constructor_callers,
        "producer_functions": producer_functions,
        "constructor_exact_pointer_references": _gfx_exact_pointer_references(
            image, constructor
        ),
        "serialized_wrapper_exact_pointer_references": (
            _gfx_exact_pointer_references(image, serialized_wrapper)
            if serialized_wrapper is not None
            else []
        ),
        "direct_named_message_ingress_observed": any(
            item["symbol"]
            and any(
                token in item["symbol"].lower()
                for token in ("message", "endpoint", "ep_work")
            )
            for item in producer_functions
        ),
    }


def analyze_gfx_handoff_consumers(
    instructions: Sequence[dict], symbols: dict[str, int]
) -> dict:
    flush_start = symbols.get("__rtk_mmu_uat_flush_request")
    idle_start = symbols.get("__rtk_mmu_uat_idle")
    wake_start = symbols.get("__rtk_mmu_uat_wake")
    if None in {flush_start, idle_start, wake_start}:
        return {"status": "HANDOFF_CONSUMERS_NOT_FOUND"}

    flush_body = _gfx_function_body(instructions, flush_start, 256)
    idle_body = _gfx_function_body(instructions, idle_start, 128)
    wake_body = _gfx_function_body(instructions, wake_start, 128)
    stride_assignment = next(
        (
            instruction["address"]
            for instruction in flush_body
            if instruction["mnemonic"] == "mov"
            and instruction["op_str"] == "w8, #0x18"
        ),
        None,
    )
    maximum_context_check = next(
        (
            instruction["address"]
            for instruction in flush_body
            if instruction["mnemonic"] == "cmp"
            and instruction["op_str"] == "w21, #0x40"
        ),
        None,
    )
    record_access = next(
        (
            instruction["address"]
            for instruction in flush_body
            if instruction["mnemonic"] == "ldr"
            and instruction["op_str"] == "w8, [x22, #0x20]!"
        ),
        None,
    )
    payload_loads = [
        instruction["address"]
        for instruction in flush_body
        if instruction["mnemonic"] == "ldr"
        and instruction["op_str"]
        in {
            "x0, [x22, #8]",
            "x1, [x22, #0x10]",
            "x0, [x8, #0x28]",
            "x1, [x8, #0x30]",
        }
    ]
    completion_writes = [
        instruction["address"]
        for instruction in flush_body
        if instruction["mnemonic"] == "str"
        and instruction["op_str"] in {"w8, [x22]", "w20, [x22]"}
    ]
    owner_flag_set = next(
        (
            instruction["address"]
            for instruction in idle_body
            if instruction["mnemonic"] == "strb"
            and instruction["op_str"] == "w8, [x19, #0x638]"
        ),
        None,
    )
    owner_flag_clear = next(
        (
            instruction["address"]
            for instruction in wake_body
            if instruction["mnemonic"] == "strb"
            and instruction["op_str"] == "wzr, [x19, #0x638]"
        ),
        None,
    )
    handshake_clears = [
        instruction["address"]
        for instruction in flush_body
        if instruction["mnemonic"] in {"str", "strb"}
        and instruction["op_str"] in {"wzr, [x19, #0x14]", "wzr, [x19, #0x11]"}
    ]

    confirmed = all(
        value is not None
        for value in (
            stride_assignment,
            maximum_context_check,
            record_access,
            owner_flag_set,
            owner_flag_clear,
        )
    ) and len(payload_loads) == 2
    return {
        "status": (
            "HANDOFF_65_RECORD_FLUSH_QUEUE_CONFIRMED"
            if confirmed
            else "HANDOFF_CONSUMERS_PARTIAL"
        ),
        "flush_function": flush_start,
        "idle_function": idle_start,
        "wake_function": wake_start,
        "record_table_offset": 0x20,
        "record_stride": 0x18,
        "maximum_context_id": 0x40,
        "record_count": 65,
        "record_state_offset": 0,
        "record_payload_offsets": [8, 0x10],
        "stride_assignment": stride_assignment,
        "maximum_context_check": maximum_context_check,
        "record_access": record_access,
        "payload_loads": payload_loads,
        "completion_writes": completion_writes,
        "handoff_busy_offset": 0x14,
        "handoff_busy_byte_offset": 0x11,
        "handshake_clears": handshake_clears,
        "owner_flag_offset": 0x638,
        "owner_flag_set": owner_flag_set,
        "owner_flag_clear": owner_flag_clear,
    }


def recover_selector_type_pairs(body: Sequence) -> list[dict]:
    """Recover exact existing-region-type to registration-selector branches."""
    by_address = {instruction.address: instruction for instruction in body}
    pairs = []
    for index, instruction in enumerate(body[:-1]):
        parts = [part.strip().lower() for part in instruction.op_str.split(",")]
        if instruction.mnemonic != "cmp" or len(parts) != 2 or parts[0] != "w8":
            continue
        region_type = parse_immediate_operand(parts[1])
        branch = body[index + 1]
        if region_type is None or branch.mnemonic != "b.eq":
            continue
        target = _branch_target(branch)
        target_instruction = by_address.get(target)
        if target_instruction is None or target_instruction.mnemonic not in {"mov", "movz"}:
            continue
        target_parts = [
            part.strip().lower() for part in target_instruction.op_str.split(",")
        ]
        if len(target_parts) != 2 or target_parts[0] != "w8":
            continue
        selector = parse_immediate_operand(target_parts[1])
        if selector is not None:
            pairs.append(
                {
                    "existing_region_type": region_type,
                    "registration_selector": selector,
                    "compare": instruction.address,
                    "selector_assignment": target_instruction.address,
                }
            )
    return pairs


def _recent_register_immediate(
    body: Sequence, index: int, register: str
) -> int | None:
    for instruction in reversed(body[max(0, index - 12) : index]):
        parts = [part.strip().lower() for part in instruction.op_str.split(",")]
        if (
            instruction.mnemonic in {"mov", "movz"}
            and len(parts) >= 2
            and parts[0] == register.lower()
        ):
            return parse_immediate_operand(parts[1])
    return None


def _recent_w2_immediate(body: Sequence, index: int) -> int | None:
    return _recent_register_immediate(body, index, "w2")


def recover_argument_bindings(body: Sequence, limit: int = 32) -> dict[str, str]:
    """Recover the entry-register saves made by a function prologue."""
    bindings: dict[str, str] = {}
    for instruction in body[:limit]:
        if instruction.mnemonic != "mov":
            continue
        parts = [part.strip().lower() for part in instruction.op_str.split(",")]
        if len(parts) != 2 or not re.fullmatch(r"x(?:1[9]|2[0-8])", parts[0]):
            continue
        if re.fullmatch(r"x[0-7]", parts[1]):
            bindings.setdefault(parts[1], parts[0])
    return bindings


def recover_uat_leaf_mapping_contract(
    body: Sequence, register_mapping: int
) -> dict:
    """Recover the leaf address and class arguments at UAT registration."""
    for index, instruction in enumerate(body):
        if instruction.mnemonic != "bl" or _branch_target(instruction) != register_mapping:
            continue
        window = body[max(0, index - 80) : index]
        address_mask = next(
            (
                parse_immediate_operand(parts[2])
                for candidate in reversed(window)
                if candidate.mnemonic == "and"
                and len(parts := [
                    part.strip().lower() for part in candidate.op_str.split(",")
                ]) == 3
                and parts[:2] == ["x23", "x27"]
            ),
            None,
        )
        map_options_read = next(
            (
                candidate.address
                for candidate in window
                if candidate.mnemonic == "ldr"
                and candidate.op_str.lower() == "w8, [x19, #0x40]"
            ),
            None,
        )
        class_seed = next(
            (
                candidate.address
                for candidate in window
                if candidate.mnemonic == "mov"
                and candidate.op_str.lower() == "w9, #1"
            ),
            None,
        )
        class_increment = next(
            (
                candidate.address
                for candidate in window
                if candidate.mnemonic == "cinc"
                and candidate.op_str.lower() == "w9, w9, eq"
            ),
            None,
        )
        class_argument = next(
            (
                candidate.address
                for candidate in window
                if candidate.mnemonic == "and"
                and candidate.op_str.lower() == "w1, w9, #0xff"
            ),
            None,
        )
        address_argument = next(
            (
                candidate.address
                for candidate in window
                if candidate.mnemonic == "mov"
                and candidate.op_str.lower() == "x0, x23"
            ),
            None,
        )
        confirmed = all(
            value is not None
            for value in (
                address_mask,
                map_options_read,
                class_seed,
                class_increment,
                class_argument,
                address_argument,
            )
        )
        return {
            "status": "UAT_LEAF_MAPPING_CONTRACT_CONFIRMED" if confirmed else "PARTIAL",
            "register_mapping_call": instruction.address,
            "physical_address_source": "x27",
            "physical_page_mask": address_mask,
            "map_options_offset": 0x40 if map_options_read is not None else None,
            "map_options_read": map_options_read,
            "mapping_class_seed": class_seed,
            "mapping_class_increment": class_increment,
            "mapping_class_argument": class_argument,
            "physical_address_argument": address_argument,
            "requested_mapping_classes": [1, 2] if confirmed else [],
        }
    return {"status": "NOT_FOUND", "requested_mapping_classes": []}


def recover_legacy_uat_leaf_mapping_contract(
    body: Sequence, register_mapping: int
) -> dict:
    """Recover the pre-policy-table UAT registration call contract."""
    for index, instruction in enumerate(body):
        if instruction.mnemonic != "bl" or _branch_target(instruction) != register_mapping:
            continue
        window = body[max(0, index - 80) : index]
        address_mask = next(
            (
                parse_immediate_operand(parts[2])
                for candidate in reversed(window)
                if candidate.mnemonic == "and"
                and len(parts := [
                    part.strip().lower() for part in candidate.op_str.split(",")
                ]) == 3
                and parts[:2] == ["x23", "x20"]
            ),
            None,
        )
        registration_modes = {
            immediate
            for candidate in window
            if candidate.mnemonic == "mov"
            and len(parts := [
                part.strip().lower() for part in candidate.op_str.split(",")
            ]) == 2
            and parts[0] == "w1"
            and (immediate := parse_immediate_operand(parts[1])) in {0, 1}
        }
        for candidate_index, candidate in enumerate(body):
            if candidate.mnemonic != "mov":
                continue
            parts = [part.strip().lower() for part in candidate.op_str.split(",")]
            if len(parts) != 2 or parts[0] != "w1":
                continue
            immediate = parse_immediate_operand(parts[1])
            if immediate not in {0, 1}:
                continue
            if any(
                branch.mnemonic == "b"
                and _branch_target(branch) == instruction.address - 4
                for branch in body[candidate_index + 1 : candidate_index + 3]
            ):
                registration_modes.add(immediate)
        registration_modes = sorted(registration_modes)
        confirmed = address_mask is not None and registration_modes == [0, 1]
        return {
            "status": (
                "LEGACY_UAT_LEAF_MAPPING_CONTRACT_CONFIRMED"
                if confirmed
                else "PARTIAL"
            ),
            "register_mapping_call": instruction.address,
            "physical_address_source": "x20",
            "physical_page_mask": address_mask,
            "legacy_registration_modes": registration_modes,
            "requested_mapping_classes": [],
        }
    return {
        "status": "NOT_FOUND",
        "legacy_registration_modes": [],
        "requested_mapping_classes": [],
    }


def recover_legacy_register_mapping_policy(body: Sequence) -> dict:
    """Recover direct frame-type allow branches used before policy tables."""
    type_read_index = next(
        (
            index
            for index, instruction in enumerate(body)
            if instruction.mnemonic == "ldrb"
            and re.fullmatch(r"w\d+, \[x0, #2\]", instruction.op_str.lower())
        ),
        None,
    )
    if type_read_index is None:
        return {"status": "NOT_FOUND", "accepted_frame_types": []}

    type_read = body[type_read_index]
    type_register = type_read.op_str.split(",", 1)[0].strip().lower()
    accepted = []
    for index in range(type_read_index + 1, min(len(body), type_read_index + 32)):
        instruction = body[index]
        parts = [part.strip().lower() for part in instruction.op_str.split(",")]
        if instruction.mnemonic != "cmp" or len(parts) != 2:
            continue
        if parts[0] != type_register:
            continue
        frame_type = parse_immediate_operand(parts[1])
        if frame_type is None:
            continue
        branch = next(
            (
                candidate
                for candidate in body[index + 1 : index + 3]
                if candidate.mnemonic == "b.eq"
            ),
            None,
        )
        if branch is None:
            continue
        accepted.append(
            {
                "frame_type": frame_type,
                "frame_type_name": {
                    0x0B: "XNU_DEFAULT",
                    0x19: "XNU_IO",
                }.get(frame_type),
                "compare": instruction.address,
                "accepted_branch": branch.address,
                "accepted_target": _branch_target(branch),
            }
        )

    return {
        "status": (
            "LEGACY_DIRECT_FRAME_TYPE_POLICY_CONFIRMED"
            if [entry["frame_type"] for entry in accepted] == [0x0B, 0x19]
            else "PARTIAL"
        ),
        "frame_type_offset": 2,
        "frame_type_read": type_read.address,
        "accepted_frame_types": accepted,
    }


def summarize_domain_mapping_policy(
    records: Sequence[dict],
    domain_id: int,
    requested_classes: Sequence[int],
    frame_type_names: dict[int, str],
) -> dict:
    source_domain_records = [
        record
        for record in records
        if record["allowed_domain_bitmap"] & (1 << domain_id)
    ]
    domain_records = [
        {
            "frame_type": record["frame_type"],
            "frame_type_name": record.get("frame_type_name"),
            "allowed_domain_bitmap": record["allowed_domain_bitmap"],
            "maximum_mapping_class": record["maximum_mapping_class"],
        }
        for record in source_domain_records
    ]
    candidates = []
    for mapping_class in requested_classes:
        candidates.append(
            {
                "mapping_class": mapping_class,
                "frame_types": [
                    {
                        "frame_type": record["frame_type"],
                        "frame_type_name": record.get("frame_type_name"),
                        "maximum_mapping_class": record["maximum_mapping_class"],
                    }
                    for record in domain_records
                    if record["maximum_mapping_class"] >= mapping_class
                ],
            }
        )
    allowed_ids = {record["frame_type"] for record in domain_records}
    focus = []
    for frame_type in (
        0x0B,
        0x17,
        0x19,
        0x1A,
        0x1F,
        0x20,
        0x22,
        0x23,
        0x24,
        0x25,
    ):
        focus.append(
            {
                "frame_type": frame_type,
                "frame_type_name": frame_type_names.get(frame_type),
                "allowed_for_domain": frame_type in allowed_ids,
            }
        )
    return {
        "domain_id": domain_id,
        "requested_mapping_classes": list(requested_classes),
        "allowed_frame_types": domain_records,
        "candidates_by_mapping_class": candidates,
        "focus_frame_types": focus,
    }


def recover_genter_dispatch_routes(instructions: Sequence) -> list[dict]:
    """Recover the bounded guest-enter target-to-service switch."""

    routes = []
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic != "cmp":
            continue
        parts = [part.strip().lower() for part in instruction.op_str.split(",")]
        if len(parts) != 2 or parts[0] != "w8":
            continue
        dispatch_target = parse_immediate_operand(parts[1])
        if dispatch_target not in {0x1B, 0x1C}:
            continue
        for candidate in instructions[index + 1 : index + 5]:
            candidate_parts = [
                part.strip().lower() for part in candidate.op_str.split(",")
            ]
            if (
                candidate.mnemonic == "mov"
                and len(candidate_parts) == 2
                and candidate_parts[0] == "w8"
            ):
                service = parse_immediate_operand(candidate_parts[1])
                if service is not None:
                    routes.append(
                        {
                            "dispatch_target": dispatch_target,
                            "service_index": service,
                            "target_compare": instruction.address,
                            "service_assignment": candidate.address,
                        }
                    )
                break
    return routes


def recover_stage2_root_retype_contract(instructions: Sequence) -> dict:
    """Recover the bounded metadata contract for a Stage-2 root retype."""

    root_frame_type = None
    vmid_field_shift = None
    vmid_validation_mask = None
    vmid_validation_value = None
    maximum_attribute_index = None
    virtualization_attribute_index = None
    vmid_claim = None
    vmid_store = None
    attribute_store = None
    for index, instruction in enumerate(instructions):
        parts = [part.strip().lower() for part in instruction.op_str.split(",")]
        if instruction.mnemonic == "cmp" and len(parts) == 2:
            immediate = parse_immediate_operand(parts[1])
            if parts[0] == "w1" and immediate == 0x1F:
                root_frame_type = immediate
            elif parts[0] == "w11" and immediate == 5:
                maximum_attribute_index = immediate
            elif parts[0] == "w11" and immediate == 1:
                virtualization_attribute_index = immediate
            elif parts[0] == "w9" and vmid_validation_mask is not None:
                vmid_validation_value = immediate
        elif (
            instruction.mnemonic == "lsr"
            and len(parts) == 3
            and parts[:2] == ["x8", "x2"]
        ):
            vmid_field_shift = parse_immediate_operand(parts[2])
        elif (
            instruction.mnemonic == "mov"
            and len(parts) == 2
            and parts[0] == "w9"
        ):
            immediate = parse_immediate_operand(parts[1])
            if immediate == 0xFF01:
                vmid_validation_mask = immediate
        elif instruction.mnemonic == "ldset":
            vmid_claim = instruction.address
        elif instruction.mnemonic == "strh" and instruction.op_str == "w8, [x19, #4]":
            vmid_store = instruction.address
        elif instruction.mnemonic == "strb" and instruction.op_str == "w20, [x19, #0xa]":
            attribute_store = instruction.address

    confirmed = all(
        value is not None
        for value in (
            root_frame_type,
            vmid_field_shift,
            vmid_validation_mask,
            vmid_validation_value,
            maximum_attribute_index,
            virtualization_attribute_index,
            vmid_claim,
            vmid_store,
            attribute_store,
        )
    )
    return {
        "status": "STAGE2_ROOT_RETYPE_CONTRACT_CONFIRMED" if confirmed else "PARTIAL",
        "frame_type": root_frame_type,
        "attribute_index_maximum": maximum_attribute_index,
        "virtualization_gated_attribute_index": virtualization_attribute_index,
        "vmid_field_shift": vmid_field_shift,
        "vmid_validation_mask": vmid_validation_mask,
        "vmid_validation_value": vmid_validation_value,
        "vmid_claim_operation": vmid_claim,
        "vmid_duplicate_rejected": vmid_claim is not None,
        "vmid_store": vmid_store,
        "attribute_store": attribute_store,
    }


def recover_stage2_page_retype_contract(instructions: Sequence) -> dict:
    """Recover the bounded subtype contract for a Stage-2 page table."""

    subtype_limit = None
    subtype_store = None
    for instruction in instructions:
        parts = [part.strip().lower() for part in instruction.op_str.split(",")]
        if (
            instruction.mnemonic == "cmp"
            and len(parts) == 2
            and parts[0] == "w8"
        ):
            immediate = parse_immediate_operand(parts[1])
            if immediate == 4:
                subtype_limit = immediate
        elif instruction.mnemonic == "strb" and instruction.op_str == "w2, [x0, #4]":
            subtype_store = instruction.address
    return {
        "status": (
            "STAGE2_PAGE_RETYPE_CONTRACT_CONFIRMED"
            if subtype_limit is not None and subtype_store is not None
            else "PARTIAL"
        ),
        "frame_type": 0x20,
        "subtype_maximum_exclusive": subtype_limit,
        "subtype_store": subtype_store,
    }


def recover_stage2_root_acquire_contract(instructions: Sequence) -> dict:
    """Recover the checks applied before a Stage-2 root can be consumed."""

    alignment_mask = None
    expected_frame_type = None
    in_flight_increment = None
    tracked_range_check = False
    for index, instruction in enumerate(instructions):
        parts = [part.strip().lower() for part in instruction.op_str.split(",")]
        if (
            instruction.mnemonic == "tst"
            and len(parts) == 2
            and parts[0] == "x0"
        ):
            alignment_mask = parse_immediate_operand(parts[1])
        elif (
            instruction.mnemonic == "cmp"
            and len(parts) == 2
            and parts[0] == "x8"
        ):
            immediate = parse_immediate_operand(parts[1])
            if immediate == 0x1F:
                expected_frame_type = immediate
        elif instruction.mnemonic == "ldaddah":
            for candidate in reversed(instructions[max(0, index - 3) : index]):
                candidate_parts = [
                    part.strip().lower() for part in candidate.op_str.split(",")
                ]
                if (
                    candidate.mnemonic == "mov"
                    and len(candidate_parts) == 2
                    and candidate_parts[0] == "w8"
                ):
                    in_flight_increment = parse_immediate_operand(candidate_parts[1])
                    break
        elif instruction.mnemonic == "subs" and instruction.op_str == "x10, x0, x8":
            tracked_range_check = True

    return {
        "status": (
            "STAGE2_ROOT_ACQUIRE_CONTRACT_CONFIRMED"
            if alignment_mask == 0x3FFF
            and expected_frame_type == 0x1F
            and in_flight_increment == 2
            and tracked_range_check
            else "PARTIAL"
        ),
        "alignment": alignment_mask + 1 if alignment_mask is not None else None,
        "tracked_physical_range_required": tracked_range_check,
        "expected_frame_type": expected_frame_type,
        "in_flight_increment": in_flight_increment,
    }


def _collect_chained_pointer_slots(image: MachOImage, target: int) -> list[dict]:
    slots = []
    for section in image.binary.sections:
        content = bytes(section.content)
        section_address = int(section.virtual_address)
        for offset in range(0, len(content) - 7, 8):
            encoded = struct.unpack_from("<Q", content, offset)[0]
            if image.resolve_chained_pointer(encoded) != target:
                continue
            slots.append(
                {
                    "address": section_address + offset,
                    "section": section.name,
                    "encoded": encoded,
                }
            )
    return slots


def _collect_dispatch_state_names(image: MachOImage, count: int = 0x17) -> dict:
    anchors = image.find_string("STATE_SPTM_BOOTSTRAP")
    if not anchors:
        return {"status": "NOT_FOUND", "table": None, "entries": []}
    target = anchors[0]
    for section in image.binary.sections:
        content = bytes(section.content)
        section_address = int(section.virtual_address)
        for offset in range(0, len(content) - count * 8 + 1, 8):
            encoded = struct.unpack_from("<Q", content, offset)[0]
            if image.resolve_chained_pointer(encoded) != target:
                continue
            table = section_address + offset
            entries = []
            for state_id in range(count):
                name_address = image.resolve_chained_pointer(
                    image.read_u64(table + state_id * 8)
                )
                entries.append(
                    {
                        "id": state_id,
                        "name": (
                            image.read_cstring(name_address)
                            if name_address is not None
                            else None
                        ),
                    }
                )
            names = {entry["id"]: entry["name"] for entry in entries}
            if names.get(5) == "STATE_XNU" and names.get(6) == "STATE_XNU_GUEST":
                return {
                    "status": "DISPATCH_STATE_NAMES_CONFIRMED",
                    "table": table,
                    "entries": entries,
                }
    return {"status": "NOT_FOUND", "table": None, "entries": []}


def _function_from_exact_anchor(image: MachOImage, value: str) -> int | None:
    function, _ = _function_from_string_anchor(image, rf"^{re.escape(value)}$")
    return function


def analyze_sptm_stage2_service_table(
    image: MachOImage, guest_functions: dict[str, dict]
) -> dict:
    """Recover the registered SPTM endpoints that front the guest helpers."""

    va_to_ipa = guest_functions.get("sptm_guest_va_to_ipa", {})
    va_to_ipa_slots = va_to_ipa.get("pointer_slots", [])
    if not va_to_ipa_slots:
        return {"status": "NOT_FOUND", "entries": []}

    entry_stride = 0x10
    table_base = va_to_ipa_slots[0]["address"] - 0x18 * entry_stride
    registry_slots = _collect_chained_pointer_slots(image, table_base)
    registry_entry = next(
        (slot for slot in registry_slots if slot["section"] == "__late_const"),
        None,
    )

    anchored_functions = {
        "sptm_guest_va_to_ipa": _function_from_exact_anchor(
            image, "sptm_guest_va_to_ipa"
        ),
        "sptm_guest_stage1_tlb_op": _function_from_exact_anchor(
            image, "sptm_guest_stage1_tlb_op"
        ),
        "sptm_guest_dispatch": _function_from_exact_anchor(
            image, "sptm_guest_dispatch"
        ),
        "sptm_guest_exit": _function_from_exact_anchor(image, "sptm_guest_exit"),
    }
    acquire_root = _function_from_exact_anchor(image, "acquire_stage2_root_pt")
    broadcast_tlbi = _function_from_exact_anchor(image, "sptm_broadcast_tlbi")
    stage2_tlb_function = image.resolve_chained_pointer(
        image.read_u64(table_base + 0x1A * entry_stride)
    )
    stage2_tlb_calls = (
        {
            target
            for instruction in _function_body(image, stage2_tlb_function, 512)
            if instruction.mnemonic == "bl"
            for target in [_branch_target(instruction)]
            if target is not None
        }
        if stage2_tlb_function is not None
        else set()
    )
    inferred_stage2_tlb = bool(
        stage2_tlb_function is not None
        and acquire_root in stage2_tlb_calls
        and broadcast_tlbi in stage2_tlb_calls
    )

    definitions = (
        (0x18, "sptm_guest_va_to_ipa", "string-anchor"),
        (0x19, "sptm_guest_stage1_tlb_op", "string-anchor"),
        (
            0x1A,
            "sptm_guest_stage2_tlb_op" if inferred_stage2_tlb else None,
            "inferred-acquire-root-plus-broadcast-tlbi",
        ),
        (0x1B, "sptm_guest_dispatch", "string-anchor"),
        (0x1C, "sptm_guest_exit", "string-anchor"),
    )
    entries = []
    for endpoint, name, name_source in definitions:
        address = table_base + endpoint * entry_stride
        function = image.resolve_chained_pointer(image.read_u64(address))
        entries.append(
            {
                "endpoint": endpoint,
                "address": address,
                "function": function,
                "name": name,
                "name_source": name_source,
                "flags": (image.mapped_bytes(address + 8, 1) or b"\0")[0],
            }
        )

    retype_function = image.resolve_chained_pointer(
        image.read_u64(table_base + entry_stride)
    )
    retype_anchor = _function_from_exact_anchor(image, "sptm_retype")
    dispatcher_function = None
    endpoint_count = None
    if registry_entry is not None:
        for reference in image.references_to(registry_entry["address"]):
            function = image.function_start(reference.address)
            if function is None:
                continue
            body = _function_body(image, function, 512)
            for instruction in body:
                parts = [
                    part.strip().lower() for part in instruction.op_str.split(",")
                ]
                if (
                    instruction.mnemonic == "cmp"
                    and len(parts) == 2
                    and parts[0] == "x8"
                    and parse_immediate_operand(parts[1]) == 0x32
                ):
                    dispatcher_function = function
                    endpoint_count = 0x32
                    break
            if endpoint_count is not None:
                break

    expected = {
        endpoint: (
            stage2_tlb_function
            if endpoint == 0x1A
            else anchored_functions.get(name)
        )
        for endpoint, name, _ in definitions
    }
    entries_match = all(
        entry["function"] is not None
        and entry["function"] == expected.get(entry["endpoint"])
        for entry in entries
    )
    guest_enter_function = guest_functions.get("sptm_guest_enter", {}).get("function")
    guest_enter_endpoint = next(
        (
            endpoint
            for endpoint in range(endpoint_count or 0)
            if image.resolve_chained_pointer(
                image.read_u64(table_base + endpoint * entry_stride)
            )
            == guest_enter_function
        ),
        None,
    )
    return {
        "status": (
            "STAGE2_SERVICE_TABLE_CONFIRMED"
            if entries_match
            and registry_entry is not None
            and endpoint_count == 0x32
            and retype_function == retype_anchor
            and inferred_stage2_tlb
            else "PARTIAL"
        ),
        "table_id": 0 if registry_entry is not None else None,
        "table": table_base,
        "entry_stride": entry_stride,
        "endpoint_count": endpoint_count,
        "registry_entry": registry_entry,
        "dispatcher": dispatcher_function,
        "retype_endpoint": {
            "endpoint": 1,
            "function": retype_function,
            "name": "sptm_retype" if retype_function == retype_anchor else None,
        },
        "entries": entries,
        "guest_enter_exposed_as_endpoint": guest_enter_endpoint is not None,
        "guest_enter_endpoint": guest_enter_endpoint,
    }


def analyze_sptm_stage2_surface(
    image: MachOImage, uat_frame_policy: dict
) -> dict:
    """Describe the bounded Stage-2 surface without invoking protected code."""

    virtualization_anchors = image.referenced_strings(r"^has-virtualization$")
    guest_names = (
        "acquire_stage2_root_pt",
        "sptm_guest_enter",
        "sptm_guest_exit",
        "sptm_guest_dispatch",
        "sptm_guest_va_to_ipa",
    )
    guest_functions = {
        name: _function_from_exact_anchor(image, name) for name in guest_names
    }
    if not virtualization_anchors and not any(guest_functions.values()):
        return {
            "status": "NOT_FOUND",
            "has_virtualization_property": False,
            "guest_functions": {},
            "frame_policy_rows": [],
        }

    references_by_instruction = {
        reference.address: reference for reference in image._references
    }
    property_reference = None
    property_value_load = None
    boolean_store = None
    virtualization_flag = None
    if virtualization_anchors and virtualization_anchors[0]["references"]:
        property_reference = virtualization_anchors[0]["references"][0]["address"]
        index = image._instruction_index.get(property_reference)
        if index is not None:
            for instruction in image.instructions[index : index + 20]:
                if instruction.mnemonic == "ldr" and instruction.op_str == "w8, [x8]":
                    property_value_load = instruction.address
                if instruction.mnemonic != "strb":
                    continue
                reference = references_by_instruction.get(instruction.address)
                if reference is not None:
                    boolean_store = instruction.address
                    virtualization_flag = reference.target
                    break

    gate_roles = (
        "cpu_root_table_retype_in",
        "genter_dispatch_entry",
        "sptm_surt_alloc",
    )
    role_functions = {
        role: _function_from_exact_anchor(image, role) for role in gate_roles
    }
    gate_readers = []
    if virtualization_flag is not None:
        roles_by_function = {
            function: role
            for role, function in role_functions.items()
            if function is not None
        }
        for reference in image.references_to(virtualization_flag):
            instruction = image.instruction_at(reference.address)
            if instruction is None or not instruction.mnemonic.startswith("ldr"):
                continue
            function = image.function_start(reference.address)
            gate_readers.append(
                {
                    "address": reference.address,
                    "function": function,
                    "role": roles_by_function.get(function),
                    "instruction": (
                        f"{instruction.mnemonic} {instruction.op_str}".strip()
                    ),
                }
            )

    function_records = {}
    for name, function in guest_functions.items():
        if function is None:
            continue
        direct_calls = image.calls_to(function)
        direct_call_set = set(direct_calls)
        function_records[name] = {
            "function": function,
            "direct_calls": direct_calls,
            "direct_branches": [
                address
                for address in image.branches_to(function)
                if address not in direct_call_set
            ],
            "pointer_slots": _collect_chained_pointer_slots(image, function),
        }

    service_table = analyze_sptm_stage2_service_table(image, function_records)

    genter_function = role_functions.get("genter_dispatch_entry")
    genter_body = (
        _function_body(image, genter_function, 512)
        if genter_function is not None
        else []
    )
    genter_routes = recover_genter_dispatch_routes(genter_body)
    dispatch_function = None
    for index, instruction in enumerate(genter_body[:-1]):
        if instruction.mnemonic != "adr" or not instruction.op_str.startswith("x30,"):
            continue
        candidate = genter_body[index + 1]
        if candidate.mnemonic == "b":
            dispatch_function = _branch_target(candidate)
            if dispatch_function is not None:
                break

    state_names = _collect_dispatch_state_names(image)
    state_name_by_id = {
        entry["id"]: entry["name"] for entry in state_names.get("entries", [])
    }
    dispatch_table = None
    state_stride = None
    service_stride = None
    domain_count = None
    service_count = None
    dispatch_transitions = []
    if dispatch_function is not None:
        dispatch_body = _function_body(image, dispatch_function, 512)
        dispatch_addresses = {instruction.address for instruction in dispatch_body}
        const_candidates = []
        for reference in image._references:
            if reference.address not in dispatch_addresses:
                continue
            instruction = image.instruction_at(reference.address)
            if (
                instruction is not None
                and instruction.mnemonic == "add"
                and instruction.op_str.startswith("x9, x9,")
                and image.mapped_bytes(reference.target, 0x20) is not None
            ):
                const_candidates.append((reference.address, reference.target))
        if const_candidates:
            dispatch_table = sorted(const_candidates)[0][1]
        if any(
            instruction.mnemonic == "lsl" and instruction.op_str == "x8, x0, #9"
            for instruction in dispatch_body
        ) and any(
            instruction.mnemonic == "sub"
            and instruction.op_str == "x8, x8, x0, lsl #5"
            for instruction in dispatch_body
        ):
            state_stride = 0x1E0
        if any(
            instruction.mnemonic == "ubfiz"
            and instruction.op_str == "x8, x21, #5, #0x20"
            for instruction in dispatch_body
        ):
            service_stride = 0x20
        for instruction in dispatch_body:
            if instruction.mnemonic != "cmp":
                continue
            if instruction.op_str == "x0, #0x17":
                domain_count = 0x17
            elif instruction.op_str == "w21, #0xf":
                service_count = 0xF

    if all(
        value is not None
        for value in (dispatch_table, state_stride, service_stride, domain_count)
    ):
        for route in genter_routes:
            service = route["service_index"]
            for origin_domain in range(domain_count):
                entry = (
                    dispatch_table
                    + origin_domain * state_stride
                    + service * service_stride
                )
                raw_handler = image.read_u64(entry + 8)
                handler = image.resolve_chained_pointer(raw_handler)
                if handler is None:
                    continue
                target_domain_raw = image.mapped_bytes(entry, 1)
                callable_raw = image.mapped_bytes(entry + 0x10, 1)
                target_domain = target_domain_raw[0] if target_domain_raw else None
                dispatch_transitions.append(
                    {
                        **route,
                        "entry": entry,
                        "origin_domain_id": origin_domain,
                        "origin_domain": state_name_by_id.get(origin_domain),
                        "target_domain_id": target_domain,
                        "target_domain": state_name_by_id.get(target_domain),
                        "handler": handler,
                        "callable": callable_raw[0] if callable_raw else None,
                        "flags": image.read_u64(entry + 0x18),
                    }
                )

    mapping_policy = uat_frame_policy.get("mapping_policy", {})
    policy_table = mapping_policy.get("descriptor_table")
    frame_names = {
        entry["frame_type"]: entry["name"]
        for entry in mapping_policy.get("frame_type_names", {}).get("entries", [])
    }
    known_domains = mapping_policy.get("known_iommu_domains", {})
    uat_domain_id = next(
        (domain_id for domain_id, name in known_domains.items() if name == "uat"),
        None,
    )
    callback_names = _retype_callback_names(image)
    frame_policy_rows = []
    if policy_table is not None:
        for frame_type in (0x1F, 0x20):
            raw = image.mapped_bytes(policy_table + frame_type * 0x60, 0x60)
            if raw is None:
                continue
            record = decode_frame_type_policy_record(raw, frame_type)
            retype_in = decode_retype_callback(
                image, record.pop("retype_in_encoded"), callback_names
            )
            retype_out = decode_retype_callback(
                image, record.pop("retype_out_encoded"), callback_names
            )
            record.update(
                {
                    "frame_type_name": frame_names.get(frame_type),
                    "retype_in_callback": {
                        key: retype_in.get(key)
                        for key in ("address", "name", "behavior")
                    },
                    "retype_out_callback": {
                        key: retype_out.get(key)
                        for key in ("address", "name", "behavior")
                    },
                    "direct_uat_mapping_allowed": bool(
                        uat_domain_id is not None
                        and record["allowed_domain_bitmap"] & (1 << uat_domain_id)
                        and record["maximum_mapping_class"] > 0
                    ),
                }
            )
            frame_policy_rows.append(record)

    row_by_type = {row["frame_type"]: row for row in frame_policy_rows}
    root_row = row_by_type.get(0x1F, {})
    page_row = row_by_type.get(0x20, {})
    root_retype_in = root_row.get("retype_in_callback", {}).get("address")
    root_retype_out = root_row.get("retype_out_callback", {}).get("address")
    page_retype_in = page_row.get("retype_in_callback", {}).get("address")
    page_retype_out = page_row.get("retype_out_callback", {}).get("address")
    acquire_root = guest_functions.get("acquire_stage2_root_pt")
    root_in_body = (
        _function_body(image, root_retype_in, 512)
        if root_retype_in is not None
        else []
    )
    root_out_body = (
        _function_body(image, root_retype_out, 512)
        if root_retype_out is not None
        else []
    )
    page_in_body = (
        _function_body(image, page_retype_in, 64)
        if page_retype_in is not None
        else []
    )
    page_out_body = (
        _function_body(image, page_retype_out, 256)
        if page_retype_out is not None
        else []
    )
    acquire_body = (
        _function_body(image, acquire_root, 256) if acquire_root is not None else []
    )
    root_retype_contract = recover_stage2_root_retype_contract(root_in_body)
    page_retype_contract = recover_stage2_page_retype_contract(page_in_body)
    root_acquire_contract = recover_stage2_root_acquire_contract(acquire_body)
    root_retype_contract.update(
        {
            "callback": root_retype_in,
            "out_callback": root_retype_out,
            "out_requires_zero_mapping_refcount": any(
                instruction.mnemonic == "ldrh"
                and instruction.op_str == "w9, [x0, #6]"
                for instruction in root_out_body
            ),
            "out_performs_stage2_tlb_invalidation": any(
                instruction.mnemonic == "tlbi"
                and instruction.op_str == "vmalls12e1is"
                for instruction in root_out_body
            ),
            "out_releases_vmid_bitmap": any(
                instruction.mnemonic == "ldclr" for instruction in root_out_body
            ),
        }
    )
    page_retype_contract.update(
        {
            "callback": page_retype_in,
            "out_callback": page_retype_out,
            "out_requires_zero_mapping_refcount": any(
                instruction.mnemonic == "ldrh"
                and instruction.op_str == "w9, [x0, #8]"
                for instruction in page_out_body
            ),
            "out_requires_zero_nested_refcount": any(
                instruction.mnemonic == "ldrh"
                and instruction.op_str == "w10, [x0, #6]"
                for instruction in page_out_body
            ),
        }
    )

    return {
        "status": (
            "STAGE2_SURFACE_PRESENT_SEPARATE_FROM_UAT"
            if virtualization_flag is not None
            and len(function_records) == len(guest_names)
            and dispatch_transitions
            and frame_policy_rows
            and not any(
                row["direct_uat_mapping_allowed"] for row in frame_policy_rows
            )
            else "PARTIAL"
        ),
        "has_virtualization_property": bool(virtualization_anchors),
        "virtualization_gate": {
            "property_reference": property_reference,
            "property_value_load": property_value_load,
            "boolean_store": boolean_store,
            "flag": virtualization_flag,
            "readers": gate_readers,
        },
        "guest_functions": function_records,
        "service_table": service_table,
        "genter_dispatch": {
            "function": genter_function,
            "low_level_branches": (
                image.branches_to(genter_function)
                if genter_function is not None
                else []
            ),
            "routes": genter_routes,
            "universal_dispatcher": dispatch_function,
            "table": dispatch_table,
            "state_stride": state_stride,
            "service_stride": service_stride,
            "domain_count": domain_count,
            "service_count": service_count,
            "state_names": state_names,
            "transitions": dispatch_transitions,
        },
        "frame_policy_rows": frame_policy_rows,
        "typed_root_lifecycle": {
            "status": (
                "TYPED_STAGE2_ROOT_REQUIRED"
                if root_retype_contract["status"]
                == "STAGE2_ROOT_RETYPE_CONTRACT_CONFIRMED"
                and page_retype_contract["status"]
                == "STAGE2_PAGE_RETYPE_CONTRACT_CONFIRMED"
                and root_acquire_contract["status"]
                == "STAGE2_ROOT_ACQUIRE_CONTRACT_CONFIRMED"
                else "PARTIAL"
            ),
            "root_retype": root_retype_contract,
            "page_retype": page_retype_contract,
            "root_acquire": root_acquire_contract,
        },
        "uat_separation": {
            "uat_domain_id": uat_domain_id,
            "stage2_frame_types_direct_uat_mapping_allowed": any(
                row["direct_uat_mapping_allowed"] for row in frame_policy_rows
            ),
        },
    }


def _function_from_string_anchor(
    image: MachOImage, pattern: str
) -> tuple[int | None, list[dict]]:
    anchors = image.referenced_strings(pattern)
    if not anchors or not anchors[0]["references"]:
        return None, anchors
    return image.function_start(anchors[0]["references"][0]["address"]), anchors


def analyze_sptm_uat_frame_policy(image: MachOImage) -> dict:
    """Recover the protected frame-type checks on the UAT map path."""
    map_continue, map_anchors = _function_from_string_anchor(
        image, r"^sptm_uat_map_continue$"
    )
    frame_acquire, acquire_anchors = _function_from_string_anchor(
        image, r"^iommu_frame_acquire_type$"
    )
    frame_acquire_api = "iommu_frame_acquire_type"
    if frame_acquire is None:
        frame_acquire, acquire_anchors = _function_from_string_anchor(
            image, r"^iommu_frame_acquire$"
        )
        frame_acquire_api = "iommu_frame_acquire"
    register_mapping, register_anchors = _function_from_string_anchor(
        image, r"^iommu_register_mapping$"
    )
    if None in {map_continue, frame_acquire, register_mapping}:
        return {
            "status": "NOT_FOUND",
            "anchors": {
                "map_continue": map_anchors,
                "frame_acquire": acquire_anchors,
                "register_mapping": register_anchors,
            },
        }

    map_body = _function_body(image, map_continue, 1024)
    register_body = _function_body(image, register_mapping, 512)
    acquire_body = _function_body(image, frame_acquire, 512)
    typed_frame_acquire = frame_acquire_api == "iommu_frame_acquire_type"
    leaf_mapping_contract = (
        recover_uat_leaf_mapping_contract(map_body, register_mapping)
        if typed_frame_acquire
        else recover_legacy_uat_leaf_mapping_contract(map_body, register_mapping)
    )
    legacy_mapping_policy = (
        {"status": "NOT_APPLICABLE", "accepted_frame_types": []}
        if typed_frame_acquire
        else recover_legacy_register_mapping_policy(register_body)
    )

    producer_anchor_functions: dict[int, set[str]] = {}
    for entry in image.referenced_strings(
        r"^(?:acquire_uat_segments_page|uat_copy_segments_locally|"
        r"segments_page|num_segments|validate_uat_map_options|map_options)$"
    ):
        for reference in entry["references"]:
            function = image.function_start(reference["address"])
            if function is not None:
                producer_anchor_functions.setdefault(function, set()).add(
                    entry["value"]
                )

    map_acquire_calls = []
    register_calls = []
    for index, instruction in enumerate(map_body):
        target = _branch_target(instruction)
        if instruction.mnemonic != "bl" or target is None:
            continue
        if target == frame_acquire:
            map_acquire_calls.append(
                {
                    "address": instruction.address,
                    "requested_type": (
                        _recent_register_immediate(map_body, index, "w1")
                        if typed_frame_acquire
                        else None
                    ),
                }
            )
        elif target == register_mapping:
            register_calls.append({"address": instruction.address})

    register_acquire_calls = []
    for index, instruction in enumerate(register_body):
        if instruction.mnemonic == "bl" and _branch_target(instruction) == frame_acquire:
            register_acquire_calls.append(
                {
                    "address": instruction.address,
                    "requested_type": (
                        _recent_register_immediate(register_body, index, "w1")
                        if typed_frame_acquire
                        else None
                    ),
                }
            )

    request_producers = []
    seen_callers = set()
    for instruction in image.instructions:
        if (
            instruction.mnemonic not in {"b", "bl"}
            or _branch_target(instruction) != map_continue
        ):
            continue
        caller = image.function_start(instruction.address)
        if caller is None or caller == map_continue or caller in seen_callers:
            continue
        seen_callers.add(caller)
        caller_body = _function_body(image, caller, 1024)
        descriptor_acquires = []
        for index, candidate in enumerate(caller_body):
            if candidate.mnemonic == "bl" and _branch_target(candidate) == frame_acquire:
                descriptor_acquires.append(
                    {
                        "address": candidate.address,
                        "requested_type": (
                            _recent_register_immediate(caller_body, index, "w1")
                            if typed_frame_acquire
                            else None
                        ),
                    }
                )
        request_producers.append(
            {
                "function": caller,
                "map_continue_call": instruction.address,
                "map_continue_call_kind": (
                    "tail-call" if instruction.mnemonic == "b" else "call"
                ),
                "frame_acquire_calls": descriptor_acquires,
                "role": (
                    "acquire_uat_segments_page"
                    if "acquire_uat_segments_page"
                    in producer_anchor_functions.get(caller, set())
                    else (
                        "legacy_uat_map_request"
                        if instruction.mnemonic == "b"
                        else None
                    )
                ),
                "diagnostic_anchors": sorted(
                    producer_anchor_functions.get(caller, set())
                ),
                "argument_bindings": recover_argument_bindings(caller_body),
                "named_input_arguments": (
                    {
                        "segments_page": "x2",
                        "num_segments": "x3",
                        "map_options": "x4",
                    }
                    if "acquire_uat_segments_page"
                    in producer_anchor_functions.get(caller, set())
                    or instruction.mnemonic == "b"
                    else {}
                ),
            }
        )

    frame_type_read = next(
        (
            instruction.address
            for instruction in acquire_body
            if instruction.mnemonic == "ldrb" and instruction.op_str == "w8, [x0, #2]"
        ),
        None,
    )
    frame_domain_read = next(
        (
            instruction.address
            for instruction in acquire_body
            if instruction.mnemonic == "ldrb" and instruction.op_str == "w9, [x0, #6]"
        ),
        None,
    )
    policy_type_read = next(
        (
            instruction.address
            for instruction in register_body
            if instruction.mnemonic == "ldrb" and instruction.op_str == "w8, [x21, #2]"
        ),
        None,
    )
    policy_stride = next(
        (
            parse_immediate_operand(instruction.op_str.split(",", 1)[1].strip())
            for instruction in register_body
            if instruction.mnemonic == "mov" and instruction.op_str.startswith("w10, #")
        ),
        None,
    )
    domain_bitmap_read = next(
        (
            instruction.address
            for instruction in register_body
            if instruction.mnemonic == "ldr" and instruction.op_str == "x8, [x8, #8]"
        ),
        None,
    )
    mapping_class_limit_read = next(
        (
            instruction.address
            for instruction in register_body
            if instruction.mnemonic == "ldrb" and instruction.op_str == "w22, [x10, #0x10]"
        ),
        None,
    )
    policy_table = None
    if policy_type_read is not None:
        policy_index = next(
            (
                index
                for index, instruction in enumerate(register_body)
                if instruction.address == policy_type_read
            ),
            None,
        )
        if policy_index is not None:
            window = register_body[policy_index : policy_index + 12]
            for index, instruction in enumerate(window[:-1]):
                if instruction.mnemonic != "adrp":
                    continue
                parts = [part.strip().lower() for part in instruction.op_str.split(",")]
                following = window[index + 1]
                following_parts = [
                    part.strip().lower() for part in following.op_str.split(",")
                ]
                if (
                    len(parts) == 2
                    and parts[0] == "x9"
                    and following.mnemonic == "add"
                    and len(following_parts) == 3
                    and following_parts[:2] == ["x9", "x9"]
                ):
                    page = parse_immediate_operand(parts[1])
                    offset = parse_immediate_operand(following_parts[2])
                    if page is not None and offset is not None:
                        policy_table = page + offset
                        break
    policy_records = []
    frame_type_names = collect_frame_type_names(image)
    frame_name_by_type = {
        entry["frame_type"]: entry["name"]
        for entry in frame_type_names["entries"]
    }
    if policy_table is not None:
        callback_names = _retype_callback_names(image)
        for frame_type in range(0x40):
            raw = image.mapped_bytes(policy_table + frame_type * 0x60, 0x60)
            if raw is None:
                break
            record = decode_frame_type_policy_record(raw, frame_type)
            record["frame_type_name"] = frame_name_by_type.get(frame_type)
            record["retype_in_callback"] = decode_retype_callback(
                image, record.pop("retype_in_encoded"), callback_names
            )
            record["retype_out_callback"] = decode_retype_callback(
                image, record.pop("retype_out_encoded"), callback_names
            )
            policy_records.append(record)
    allowed_policy_records = [
        record
        for record in policy_records
        if record["allowed_domain_bitmap"] or record["maximum_mapping_class"]
    ]
    wildcard_compare = next(
        (
            instruction.address
            for instruction in acquire_body
            if instruction.mnemonic == "cmp" and instruction.op_str == "w20, #0x42"
        ),
        None,
    )

    return {
        "status": (
            "FRAME_TYPE_AND_MAPPING_POLICY_CONFIRMED"
            if typed_frame_acquire
            and map_acquire_calls
            and register_calls
            and register_acquire_calls
            and frame_type_read is not None
            and policy_type_read is not None
            else "LEGACY_DIRECT_TYPE_POLICY_CONFIRMED"
            if not typed_frame_acquire
            and map_acquire_calls
            and register_calls
            and register_acquire_calls
            and legacy_mapping_policy["status"]
            == "LEGACY_DIRECT_FRAME_TYPE_POLICY_CONFIRMED"
            else "PARTIAL"
        ),
        "functions": {
            "sptm_uat_map_continue": map_continue,
            "frame_acquire_api": frame_acquire_api,
            "iommu_frame_acquire": frame_acquire,
            "iommu_frame_acquire_type": (
                frame_acquire if typed_frame_acquire else None
            ),
            "iommu_register_mapping": register_mapping,
        },
        "map_continue_frame_acquire_calls": map_acquire_calls,
        "map_continue_register_mapping_calls": register_calls,
        "leaf_mapping_contract": leaf_mapping_contract,
        "register_mapping_frame_acquire_calls": register_acquire_calls,
        "map_request_producers": request_producers,
        "frame_metadata": {
            "type_offset": 2,
            "type_read": frame_type_read,
            "domain_offset": 6,
            "domain_read": frame_domain_read,
            "wildcard_type_selector": 0x42 if wildcard_compare is not None else None,
            "wildcard_compare": wildcard_compare,
        },
        "mapping_policy": {
            "frame_type_read": policy_type_read,
            "per_type_record_stride": policy_stride,
            "descriptor_table": policy_table,
            "frame_type_names": frame_type_names,
            "allowed_domain_bitmap_offset": 8,
            "allowed_domain_bitmap_read": domain_bitmap_read,
            "maximum_mapping_class_offset": 0x10,
            "maximum_mapping_class_read": mapping_class_limit_read,
            "allowed_frame_types": allowed_policy_records,
        },
        "legacy_mapping_policy": legacy_mapping_policy,
    }


def analyze_sptm_registration_contract(image: MachOImage, anchors: Sequence[dict]) -> dict:
    handoff_anchor = next(
        (entry for entry in anchors if entry["value"] == "gfx-handoff-base"),
        None,
    )
    if handoff_anchor is None or not handoff_anchor["references"]:
        return {"status": "NOT_FOUND"}

    reference = handoff_anchor["references"][0]["address"]
    start = image.function_start(reference)
    if start is None:
        return {"status": "FUNCTION_UNRESOLVED", "reference": reference}
    body = _function_body(image, start, 4096)

    candidate_calls = []
    for index, instruction in enumerate(body):
        target = _branch_target(instruction)
        selector = _recent_w2_immediate(body, index)
        if instruction.mnemonic == "bl" and target is not None and selector in {0, 1, 2}:
            candidate_calls.append(
                {"address": instruction.address, "target": target, "selector": selector}
            )
    target_counts = Counter(item["target"] for item in candidate_calls)
    registration_helper = (
        target_counts.most_common(1)[0][0] if target_counts else None
    )
    registration_calls = [
        item for item in candidate_calls if item["target"] == registration_helper
    ]
    helper_body = (
        _function_body(image, registration_helper, 1024)
        if registration_helper is not None
        else []
    )
    selector_type_pairs = recover_selector_type_pairs(helper_body)

    dynamic_anchor = next(
        (entry for entry in anchors if entry["value"] == "%s-data-base"),
        None,
    )
    dynamic_reference = (
        dynamic_anchor["references"][0]["address"]
        if dynamic_anchor is not None and dynamic_anchor["references"]
        else None
    )
    dynamic_call = next(
        (
            item
            for item in registration_calls
            if dynamic_reference is not None and item["address"] > dynamic_reference
        ),
        None,
    )
    dynamic_region_type = next(
        (
            pair["existing_region_type"]
            for pair in selector_type_pairs
            if dynamic_call is not None
            and pair["registration_selector"] == dynamic_call["selector"]
        ),
        None,
    )

    magic = _reconstruct_handoff_magic(body)
    magic_write = next(
        (
            instruction.address
            for instruction in body
            if instruction.mnemonic == "str" and instruction.op_str == "x9, [x0]"
        ),
        None,
    )
    owner_flag_write = next(
        (
            instruction.address
            for instruction in body
            if instruction.mnemonic == "strb"
            and instruction.op_str == "w9, [x0, #0x638]"
        ),
        None,
    )
    owner_aux_clear = next(
        (
            instruction.address
            for instruction in body
            if instruction.mnemonic == "str"
            and instruction.op_str == "xzr, [x0, #0x640]"
        ),
        None,
    )
    record_loop_limit = next(
        (
            parse_immediate_operand(instruction.op_str.split(",", 1)[1].strip())
            for instruction in body
            if instruction.mnemonic == "cmp"
            and instruction.op_str.startswith("x8, #0x618")
        ),
        None,
    )
    dynamic_record_base = next(
        (
            instruction.address
            for instruction in body
            if instruction.mnemonic == "add" and instruction.op_str.endswith(", #0xb8")
        ),
        None,
    )
    dynamic_record_stride = next(
        (
            0x10
            for instruction in body
            if instruction.mnemonic == "add"
            and "lsl #4" in instruction.op_str
            and dynamic_record_base is not None
            and instruction.address > dynamic_record_base
        ),
        None,
    )

    return {
        "status": "PRESENT" if magic_write is not None else "PARTIAL",
        "initialization_function": start,
        "registration_helper": registration_helper,
        "registration_calls": registration_calls,
        "registration_selector_counts": dict(
            sorted(Counter(item["selector"] for item in registration_calls).items())
        ),
        "existing_region_type_selectors": selector_type_pairs,
        "dynamic_gfx_segments": {
            "present": dynamic_reference is not None,
            "name_pattern": "gfx, gfx1, gfx2, ..." if dynamic_reference is not None else None,
            "record_base_offset": 0xB8 if dynamic_record_base is not None else None,
            "record_stride": dynamic_record_stride,
            "physical_base_offset": 0 if dynamic_record_base is not None else None,
            "page_count_offset": 8 if dynamic_record_base is not None else None,
            "registration_call": dynamic_call,
            "accepted_existing_region_type": dynamic_region_type,
        },
        "shared_handoff": {
            "magic": magic,
            "sptm_magic_offset": 0,
            "gfx_peer_magic_offset": 8,
            "status_offset": 0x18,
            "record_base_offset": 0x20,
            "record_stride": 0x18,
            "record_count": (
                record_loop_limit // 0x18 if record_loop_limit is not None else None
            ),
            "owner_flag_offset": 0x638,
            "owner_aux_offset": 0x640,
            "magic_write": magic_write,
            "owner_flag_write": owner_flag_write,
            "owner_aux_clear": owner_aux_clear,
        },
    }


def analyze_agx_firmware_provider(path: pathlib.Path, label: str) -> dict:
    image = MachOImage(path, "com.apple.AGXFirmwareKextG14PRTBuddy")
    entries = image.referenced_strings(r"requestFirmwareBinary")
    if not entries:
        return {"label": label, "status": "NOT_FOUND", "path": str(path)}

    reference = entries[0]["references"][0]
    start = image.function_start(reference["address"])
    body = _function_body(image, start) if start is not None else []
    configuration_stores = [
        instruction.address
        for instruction in body
        if instruction.mnemonic.startswith("st") and "[x0," in instruction.op_str
    ]
    success_returns = [
        instruction.address
        for instruction in body
        if instruction.mnemonic == "mov" and instruction.op_str == "w0, #1"
    ]
    unimplemented_refs = {
        reference["address"]
        for entry in image.referenced_strings(r"!!! Unimplemented")
        for reference in entry["references"]
    }
    body_addresses = {instruction.address for instruction in body}
    reaches_unimplemented = bool(unimplemented_refs & body_addresses)
    status = (
        "ROLE_GATED_IMPLEMENTATION"
        if configuration_stores and success_returns
        else "UNIMPLEMENTED_STUB" if reaches_unimplemented else "UNRESOLVED"
    )
    return {
        "label": label,
        "path": str(path),
        "sha256": sha256_file(path),
        "status": status,
        "signature": entries[0]["value"],
        "function": start,
        "instruction_count": len(body),
        "configuration_store_count": len(configuration_stores),
        "success_return_observed": bool(success_returns),
        "unimplemented_path_observed": reaches_unimplemented,
    }


def analyze_sptm_handoff(path: pathlib.Path, label: str) -> dict:
    image = MachOImage(path)
    anchors = image.referenced_strings(HANDOFF_PATTERN)
    invalid_magic = next(
        (entry for entry in anchors if "Invalid microPPL magic" in entry["value"]),
        None,
    )
    functions = []
    magic = None
    if invalid_magic is not None:
        for reference in invalid_magic["references"]:
            start = image.function_start(reference["address"])
            if start is None or start in functions:
                continue
            functions.append(start)
            magic = magic or _reconstruct_handoff_magic(_function_body(image, start))

    registration_contract = analyze_sptm_registration_contract(image, anchors)
    uat_frame_policy = analyze_sptm_uat_frame_policy(image)
    iommu_topology = _collect_iommu_registration_topology(image)
    domain_names = {
        registration["table_id"]: descriptor["name"]
        for descriptor in iommu_topology.get("descriptors", [])
        for registration in descriptor.get("registrations", [])
    }
    mapping_policy = uat_frame_policy.get("mapping_policy", {})
    for record in mapping_policy.get("allowed_frame_types", []):
        record["allowed_domains"] = decode_domain_bitmap(
            record["allowed_domain_bitmap"], domain_names
        )
    mapping_policy["known_iommu_domains"] = domain_names
    uat_domain_id = next(
        (domain_id for domain_id, name in domain_names.items() if name == "uat"),
        None,
    )
    if uat_domain_id is not None:
        frame_type_names = {
            entry["frame_type"]: entry["name"]
            for entry in mapping_policy.get("frame_type_names", {}).get(
                "entries", []
            )
        }
        mapping_policy["uat_domain_policy"] = summarize_domain_mapping_policy(
            mapping_policy.get("allowed_frame_types", []),
            uat_domain_id,
            uat_frame_policy.get("leaf_mapping_contract", {}).get(
                "requested_mapping_classes", []
            ),
            frame_type_names,
        )
    stage2_surface = analyze_sptm_stage2_surface(image, uat_frame_policy)
    return {
        "label": label,
        "path": str(path),
        "sha256": sha256_file(path),
        "status": "PRESENT" if invalid_magic is not None else "NOT_FOUND",
        "magic": magic,
        "magic_check_functions": functions,
        "mapping_record_stride": (
            registration_contract.get("shared_handoff", {}).get("record_stride")
        ),
        "anchors": [
            {
                "value": entry["value"],
                "address": entry["address"],
                "references": entry["references"],
            }
            for entry in anchors
        ],
        "gfx_data_segment_registration_anchor": any(
            entry["value"] == "uat_register_gfx_data_segment" for entry in anchors
        ),
        "dynamic_gfx_data_properties": all(
            any(entry["value"] == value for entry in anchors)
            for value in ("%s-data-base", "%s-data-size")
        ),
        "registration_contract": registration_contract,
        "uat_frame_policy": uat_frame_policy,
        "stage2_surface": stage2_surface,
    }


def _gfx_slice_metadata(path: pathlib.Path) -> dict[str, dict]:
    data = path.read_bytes()
    blobs = []
    if data[0x20:0x28] == b"rkosftab":
        count = struct.unpack_from("<I", data, 0x28)[0]
        for index in range(count):
            cursor = 0x30 + index * 16
            label = data[cursor : cursor + 4].decode("ascii", errors="replace")
            offset = struct.unpack_from("<I", data, cursor + 4)[0]
            size = struct.unpack_from("<Q", data, cursor + 8)[0]
            blobs.append((label, data[offset : offset + size]))
    else:
        blobs.append((path.name, data))

    result = {}
    for label, blob in blobs:
        parsed = lief.MachO.parse(blob)
        if parsed is None or len(parsed) == 0:
            continue
        binary = parsed.at(0)
        symbol = next(
            (
                item
                for item in binary.symbols
                if item.name == "__rtk_uppl_client_dispatch"
            ),
            None,
        )
        if symbol is None:
            continue
        section = next(
            (
                item
                for item in binary.sections
                if int(item.virtual_address)
                <= int(symbol.value)
                < int(item.virtual_address) + int(item.size)
            ),
            None,
        )
        result[label] = {
            "symbol_description": int(symbol.description),
            "weak_definition": bool(int(symbol.description) & 0x80),
            "section": (
                f"{section.segment_name},{section.name}" if section else None
            ),
            "section_relocations": len(section.relocations) if section else None,
            "total_relocations": sum(
                len(item.relocations) for item in binary.sections
            ),
            "dyld_chained_fixups": bool(binary.has_dyld_chained_fixups),
        }
    return result


def analyze_gfx_uppl(path: pathlib.Path) -> dict:
    metadata_by_slice = _gfx_slice_metadata(path)
    slices = []
    for image in parse_gfx_images(path):
        instructions = disassemble_gfx_text(image)
        gxf_map_producer = analyze_gxf_map_producer(image, instructions)
        handoff_consumers = analyze_gfx_handoff_consumers(
            instructions, image.symbols
        )
        descriptors = [
            decode_patch_descriptor(image, name)
            for name in sorted(image.symbols)
            if name.startswith("__rtk_patch_")
        ]
        state = image.symbols.get("__rtk_uppl_client_dispatch")
        state_bytes = image.read(state, 16) if state is not None else None
        references = (
            collect_state_materializations(instructions, state)
            if state is not None
            else []
        )
        writes = [item for item in references if item["kind"] == "write"]
        named_uppl_patch = [
            item
            for item in descriptors
            if "uppl_client_dispatch" in item["symbol"].lower()
        ]
        metadata = metadata_by_slice.get(image.label, {})
        shared_patch = next(
            (
                item
                for item in descriptors
                if item["symbol"] == "__rtk_patch_uat_ppl_shared_base"
            ),
            None,
        )
        shared_value_references = (
            collect_state_materializations(instructions, shared_patch["address"] + 8)
            if shared_patch is not None
            else []
        )
        shared_reference_address = (
            shared_value_references[0]["access"] if shared_value_references else None
        )
        shared_reference_index = next(
            (
                index
                for index, instruction in enumerate(instructions)
                if instruction["address"] == shared_reference_address
            ),
            None,
        )
        handoff_pointer_state = None
        if shared_reference_index is not None:
            window = instructions[shared_reference_index : shared_reference_index + 80]
            for local_index, first in enumerate(window):
                if first["mnemonic"] != "adrp":
                    continue
                parts = [part.strip().lower() for part in first["op_str"].split(",")]
                if len(parts) != 2:
                    continue
                register = parts[0]
                page = parse_immediate_operand(parts[1])
                if page is None:
                    continue
                for candidate in window[local_index + 1 : local_index + 5]:
                    candidate_parts = [
                        part.strip().lower()
                        for part in candidate["op_str"].split(",")
                    ]
                    if (
                        candidate["mnemonic"] == "add"
                        and len(candidate_parts) == 3
                        and candidate_parts[0] == register
                        and candidate_parts[1] == register
                    ):
                        offset = parse_immediate_operand(candidate_parts[2])
                        if offset is None:
                            continue
                        target = page + offset
                        if any(
                            following["mnemonic"] == "str"
                            and following["op_str"] == f"x22, [{register}]"
                            for following in window[local_index + 1 : local_index + 12]
                        ):
                            handoff_pointer_state = target
                            break
                if handoff_pointer_state is not None:
                    break
        handoff_pointer_references = (
            collect_state_materializations(instructions, handoff_pointer_state)
            if handoff_pointer_state is not None
            else []
        )
        peer_magic_write = next(
            (
                instruction["address"]
                for instruction in instructions
                if instruction["mnemonic"] == "str"
                and instruction["op_str"] == "x8, [x22, #8]"
            ),
            None,
        )
        owner_flag_clear = next(
            (
                instruction["address"]
                for instruction in instructions
                if instruction["mnemonic"] == "strb"
                and instruction["op_str"] == "wzr, [x22, #0x638]"
            ),
            None,
        )
        owner_flag_set = next(
            (
                instruction["address"]
                for instruction in instructions
                if instruction["mnemonic"] == "strb"
                and instruction["op_str"] == "w8, [x19, #0x638]"
            ),
            None,
        )
        context_guard_read = next(
            (
                instruction["address"]
                for instruction in instructions
                if instruction["mnemonic"] == "ldrb"
                and instruction["op_str"] == "w8, [x21, #0x638]"
            ),
            None,
        )
        peer_magic_compare = next(
            (
                instructions[index + 2]["address"]
                for index, instruction in enumerate(instructions[:-2])
                if instruction["mnemonic"] == "ldr"
                and instruction["op_str"] == "x8, [x0]"
                and instructions[index + 1]["mnemonic"] == "ldr"
                and instructions[index + 1]["op_str"] == "x9, [x0, #8]"
                and instructions[index + 2]["mnemonic"] == "cmp"
            ),
            None,
        )
        no_relocation_producer = (
            metadata.get("section_relocations") == 0
            and metadata.get("total_relocations") == 0
            and not metadata.get("dyld_chained_fixups", False)
        )
        slices.append(
            {
                "name": image.label,
                "dispatch_state": state,
                "static_handler_count": (
                    struct.unpack_from("<Q", state_bytes, 0)[0]
                    if state_bytes is not None
                    else None
                ),
                "static_handler_table": (
                    struct.unpack_from("<Q", state_bytes, 8)[0]
                    if state_bytes is not None
                    else None
                ),
                "direct_references": references,
                "direct_writer_count": len(writes),
                "patch_descriptor_count": len(descriptors),
                "relevant_patch_descriptors": [
                    item for item in descriptors if item["symbol"] in RELEVANT_PATCH_SYMBOLS
                ],
                "uppl_state_patch_descriptors": named_uppl_patch,
                "symbol_metadata": metadata,
                "shared_handoff": {
                    "ppl_shared_base_value": (
                        shared_patch["address"] + 8 if shared_patch is not None else None
                    ),
                    "ppl_shared_base_reads": shared_value_references,
                    "pointer_state": handoff_pointer_state,
                    "pointer_state_references": handoff_pointer_references,
                    "gfx_peer_magic_offset": 8,
                    "peer_magic_write": peer_magic_write,
                    "peer_magic_compare": peer_magic_compare,
                    "owner_flag_offset": 0x638,
                    "owner_flag_clear": owner_flag_clear,
                    "owner_flag_set": owner_flag_set,
                    "context_guard_read": context_guard_read,
                    "status": (
                        "SPTM_GFX_SHARED_HANDOFF_CONFIRMED"
                        if all(
                            value is not None
                            for value in (
                                handoff_pointer_state,
                                peer_magic_write,
                                peer_magic_compare,
                                owner_flag_clear,
                                context_guard_read,
                            )
                        )
                        else "REVIEW_REQUIRED"
                    ),
                },
                "gxf_map_producer": gxf_map_producer,
                "handoff_consumers": handoff_consumers,
                "producer_status": (
                    "ZERO_WEAK_DEFAULT_NO_PRODUCER_OBSERVED"
                    if state_bytes == bytes(16)
                    and not writes
                    and not named_uppl_patch
                    and metadata.get("weak_definition")
                    and no_relocation_producer
                    else "REVIEW_REQUIRED"
                ),
            }
        )
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "slices": slices,
    }


def build_report(args) -> dict:
    providers = [
        analyze_agx_firmware_provider(args.ios17_kernel, "iOS 17.1.1 / 21B91"),
        analyze_agx_firmware_provider(args.ios26_kernel, "iOS 26.0.1 / 23A355"),
    ]
    handoffs = [
        analyze_sptm_handoff(args.ios17_sptm, "iOS 17.1.1 / 21B91"),
        analyze_sptm_handoff(args.ios26_sptm, "iOS 26.0.1 / 23A355"),
    ]
    gfx = analyze_gfx_uppl(args.ios26_gfx)
    ios26_dynamic_type = handoffs[1]["registration_contract"].get(
        "dynamic_gfx_segments", {}
    ).get("accepted_existing_region_type")
    ios26_allowed_types = {
        record["frame_type"]
        for record in handoffs[1]["uat_frame_policy"].get("mapping_policy", {}).get(
            "allowed_frame_types", []
        )
    }
    return {
        "schema": "a15-agx-uppl-producer-v9",
        "scope": "offline-static-only",
        "agx_firmware_providers": providers,
        "sptm_handoffs": handoffs,
        "ios26_gfx_uppl": gfx,
        "conclusion": {
            "handoff_magic_changed": handoffs[0]["magic"] != handoffs[1]["magic"],
            "legacy_firmware_provider_changed": providers[0]["status"]
            != providers[1]["status"],
            "patchbay_populates_uppl_state": any(
                item["uppl_state_patch_descriptors"]
                for item in gfx["slices"]
            ),
            "dynamic_gfx_region_direct_uat_mapping_allowed": (
                ios26_dynamic_type in ios26_allowed_types
                if ios26_dynamic_type is not None
                else None
            ),
            "stage2_frame_types_direct_uat_mapping_allowed": bool(
                {0x1F, 0x20} & ios26_allowed_types
            ),
            "stage2_surface_status": handoffs[1]["stage2_surface"]["status"],
            "route": (
                "The legacy AGX firmware-provider method is no longer usable. PatchBay "
                "supplies GPTBAT/PPL-shared addresses and the PPL-shared base feeds the "
                "cross-version SPTM/GFX handoff. The UPPL object remains a separate zero "
                "weak default with no local writer, relocation, fixup, or named patch. "
                "The iOS 26 addition established here is SPTM's dynamic registration of "
                "one or more GFX data segments in its protected-frame registry. The UAT "
                "consumer still enforces page-table frame type 0x17. Mapping "
                "registration uses wildcard selector 0x42, then reads the actual frame "
                "type and applies per-type domain/mapping policy. In the GFX image, "
                "direct command 0x10 is now traced to a local serialized wrapper. "
                "Its proven producers are RTKit bootstrap translation setup and an "
                "internal memory-map path; no direct named RTKit message ingress is "
                "observed in that call chain. The SPTM name table identifies restricted "
                "types 0x22/0x23 as XNU_CPUTRACE_PA_BUFFER and "
                "XNU_CPUTRACE_VA_BUFFER; their domain-7 permission is a CPU-trace/UAT "
                "route, not an unidentified AGX leaf type. Type 0x3b is "
                "TXM_SEP_SECURE_CHANNEL and is likewise unrelated to the immediate "
                "AGX mapping path. The direct protected producer is identified as "
                "acquire_uat_segments_page. It validates a default-type descriptor "
                "page and feeds segment count and map options into map continuation. "
                "That continuation registers leaf pages with mapping class 1 or 2. "
                "For UAT domain 7, XNU_IO is eligible while XNU_PROTECTED_IO is not. "
                "The exact iOS 17 predecessor uses the untyped iommu_frame_acquire "
                "API and a direct two-type allow switch for XNU_DEFAULT/XNU_IO with "
                "registration modes 0/1; iOS 26 replaces that switch with typed "
                "acquisition plus domain/class policy. The iOS 26 Stage-2 surface is "
                "separate: has-virtualization gates root retyping, SURT allocation, "
                "and GENTER dispatch; GENTER targets 0x1b/0x1c select services 0xc/0xd "
                "for the XNU/guest state transitions. Registered SPTM table 0 contains "
                "50 endpoints; its bounded guest subset is 0x18 through 0x1c, while "
                "guest-enter remains an internal helper. Consuming a guest root "
                "requires an aligned, tracked frame already typed 0x1f. Retyping "
                "claims a unique VMID, and retype-out performs a Stage-2-wide TLB "
                "invalidation before releasing that VMID. Stage-2 frame types retain "
                "dedicated lifecycle callbacks but have no direct UAT mapping policy."
            ),
            "limitation": (
                "Static evidence does not show that the exact A15 payload ever replaces "
                "the weak UPPL default, publish handler indices, or prove a privilege-"
                "elevation path."
            ),
        },
    }


def render_markdown(report: dict) -> str:
    def format_address(value: int | None) -> str:
        return "-" if value is None else f"0x{value:x}"

    lines = [
        "# A15 AGX / SPTM / UPPL Producer Comparison",
        "",
        "This report is generated from extracted images only. It performs no live",
        "protected-component call and does not enable a jailbreak stage.",
        "",
        "## AGX firmware provider",
        "",
        "| Build | Status | Function | Config stores | Success return | Unimplemented path |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for item in report["agx_firmware_providers"]:
        function = "-" if item.get("function") is None else f"0x{item['function']:x}"
        lines.append(
            f"| {item['label']} | `{item['status']}` | `{function}` | "
            f"{item.get('configuration_store_count', 0)} | "
            f"{item.get('success_return_observed', False)} | "
            f"{item.get('unimplemented_path_observed', False)} |"
        )

    lines.extend(
        [
            "",
            "## SPTM handoff",
            "",
            "| Build | microPPL handoff | Magic | GFX segment registration | Dynamic base/size keys |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for item in report["sptm_handoffs"]:
        magic = "-" if item["magic"] is None else f"0x{item['magic']:016x}"
        lines.append(
            f"| {item['label']} | `{item['status']}` | `{magic}` | "
            f"{item['gfx_data_segment_registration_anchor']} | "
            f"{item['dynamic_gfx_data_properties']} |"
        )
    lines.extend(["", "### Shared handoff and protected registration", ""])
    for item in report["sptm_handoffs"]:
        contract = item["registration_contract"]
        shared = contract.get("shared_handoff", {})
        dynamic = contract.get("dynamic_gfx_segments", {})
        function = contract.get("initialization_function")
        helper = contract.get("registration_helper")
        lines.extend(
            [
                f"- **{item['label']}**: init="
                f"`{'-' if function is None else f'0x{function:x}'}`, helper="
                f"`{'-' if helper is None else f'0x{helper:x}'}`, selectors="
                f"`{contract.get('registration_selector_counts', {})}`; shared layout "
                f"magic offsets `+0x0/+0x8`, records `+0x20` x "
                f"`{shared.get('record_count')}` with stride `0x{shared.get('record_stride', 0):x}`, "
                f"owner state `+0x{shared.get('owner_flag_offset', 0):x}`; dynamic GFX "
                f"records `{dynamic.get('present')}`, selector-1 accepted existing "
                f"region type `{dynamic.get('accepted_existing_region_type')}`.",
            ]
        )
    lines.extend(
        [
            "",
            "The microPPL handoff magic is unchanged. iOS 26 adds a directly",
            "referenced `uat_register_gfx_data_segment` diagnostic anchor, so the",
            "difference is in the protected mapping lifecycle rather than the mere",
            "existence of a handoff region.",
            "",
            "### Protected UAT frame policy",
            "",
        ]
    )
    for item in report["sptm_handoffs"]:
        policy = item["uat_frame_policy"]
        functions = policy.get("functions", {})
        map_types = [
            call.get("requested_type")
            for call in policy.get("map_continue_frame_acquire_calls", [])
            if call.get("requested_type") is not None
        ]
        register_types = [
            call.get("requested_type")
            for call in policy.get("register_mapping_frame_acquire_calls", [])
            if call.get("requested_type") is not None
        ]
        map_function = functions.get("sptm_uat_map_continue")
        acquire_api = functions.get("frame_acquire_api")
        mapping_policy = policy.get("mapping_policy", {})
        allowed_types = [
            f"0x{record['frame_type']:x}"
            for record in mapping_policy.get("allowed_frame_types", [])
        ]
        lines.append(
            f"- **{item['label']}**: `{policy['status']}`; map-continue="
            f"`{'-' if map_function is None else f'0x{map_function:x}'}`, "
            f"acquisition API=`{acquire_api or '-'}`, typed acquisition "
            f"selectors=`{map_types}`, registration acquisition "
            f"selectors=`{register_types}`."
        )
        leaf_contract = policy.get("leaf_mapping_contract", {})
        if leaf_contract.get("register_mapping_call") is not None:
            mask = leaf_contract.get("physical_page_mask")
            lines.append(
                f"  Leaf contract: `{leaf_contract.get('status')}` at "
                f"`0x{leaf_contract['register_mapping_call']:x}`; physical mask "
                f"`{'-' if mask is None else f'0x{mask:x}'}`; requested mapping "
                f"classes `{leaf_contract.get('requested_mapping_classes', [])}`."
            )
            if leaf_contract.get("legacy_registration_modes"):
                lines.append(
                    "  Legacy registration modes: "
                    f"`{leaf_contract['legacy_registration_modes']}`; these are "
                    "not the iOS 26 mapping-class values."
                )
        legacy_policy = policy.get("legacy_mapping_policy", {})
        if legacy_policy.get("accepted_frame_types"):
            accepted = [
                entry.get("frame_type_name") or f"0x{entry['frame_type']:x}"
                for entry in legacy_policy["accepted_frame_types"]
            ]
            lines.append(
                f"  Direct legacy type policy: `{legacy_policy['status']}`; "
                f"accepted frame types `{accepted}`."
            )
        if mapping_policy.get("descriptor_table") is not None:
            lines.append(
                f"  Policy table: `0x{mapping_policy['descriptor_table']:x}`; "
                f"frame types with a nonzero domain bitmap or mapping class: "
                f"`{allowed_types}`."
            )
            for record in mapping_policy.get("allowed_frame_types", []):
                bitmap = record["allowed_domain_bitmap"]
                if bitmap in {0, (1 << 64) - 1}:
                    continue
                domains = ", ".join(
                    f"{domain['id']} ({domain['name'] or 'unknown'})"
                    for domain in record.get("allowed_domains", [])
                )
                lines.append(
                    f"  Restricted type `0x{record['frame_type']:x}` "
                    f"(`{record.get('frame_type_name') or 'unknown'}`): bitmap "
                    f"`0x{bitmap:x}` -> domains `{domains}`."
                )
                callback_text = []
                for direction in ("in", "out"):
                    callback = record.get(f"retype_{direction}_callback", {})
                    address = callback.get("address")
                    label = callback.get("name") or callback.get("behavior", "unknown")
                    callback_text.append(
                        f"{direction}={label}@"
                        f"{'-' if address is None else f'0x{address:x}'}"
                    )
                lines.append(
                    "  Retype callbacks: `" + ", ".join(callback_text) + "`; "
                    f"policy byte `+0x11=0x{record['mapping_policy_byte_0x11']:x}`."
                )
            uat_policy = mapping_policy.get("uat_domain_policy", {})
            if uat_policy:
                for entry in uat_policy.get("candidates_by_mapping_class", []):
                    candidate_names = [
                        candidate.get("frame_type_name")
                        or f"0x{candidate['frame_type']:x}"
                        for candidate in entry["frame_types"]
                    ]
                    lines.append(
                        f"  UAT domain `{uat_policy['domain_id']}`, mapping class "
                        f"`{entry['mapping_class']}` candidates: `{candidate_names}`."
                    )
                focus = {
                    entry.get("frame_type_name"): entry["allowed_for_domain"]
                    for entry in uat_policy.get("focus_frame_types", [])
                }
                lines.append(
                    "  Protected-I/O split: "
                    f"`XNU_IO={focus.get('XNU_IO')}`, "
                    f"`XNU_PROTECTED_IO={focus.get('XNU_PROTECTED_IO')}`."
                )
                lines.append(
                    "  Stage-2 split: "
                    f"`XNU_STAGE2_ROOT_TABLE="
                    f"{focus.get('XNU_STAGE2_ROOT_TABLE')}`, "
                    f"`XNU_STAGE2_PAGE_TABLE="
                    f"{focus.get('XNU_STAGE2_PAGE_TABLE')}`."
                )
        for producer in policy.get("map_request_producers", []):
            descriptor_types = [
                call.get("requested_type")
                for call in producer.get("frame_acquire_calls", [])
            ]
            lines.append(
                f"  Direct request producer "
                f"`{producer.get('role') or 'unresolved'}`: "
                f"`0x{producer['function']:x}` calls "
                f"map continuation at `0x{producer['map_continue_call']:x}`; "
                f"descriptor-frame selectors=`{descriptor_types}`; inputs="
                f"`{producer.get('named_input_arguments', {})}`."
            )
    lines.extend(
        [
            "",
            "On `23A355`, map continuation acquires page-table frames as type",
            "`0x17`. `iommu_register_mapping` passes `0x42` as a wildcard selector,",
            "then reads the actual frame type before consulting per-type domain and",
            "mapping-type policy. Dynamic GFX registration therefore feeds protected",
            "metadata; it does not by itself authorize an arbitrary UAT mapping.",
            "The direct producer is `acquire_uat_segments_page`: it validates the",
            "descriptor page as `XNU_DEFAULT (0xb)`, copies segment descriptors, and",
            "passes `num_segments` plus `map_options` into map continuation. The leaf",
            "physical address is page-masked and registered with class `1` or `2`.",
            "For named UAT domain 7, `XNU_IO (0x19)` is eligible for both classes,",
            "while `XNU_PROTECTED_IO (0x1a)` is not eligible in this policy table.",
            "The selector-1 GFX-data compatibility type is `2`; its policy row has",
            "a zero domain bitmap and zero maximum mapping class, so this registered",
            "region is not itself accepted as a direct UAT leaf-mapping target.",
            "On exact `21B91`, the corresponding route uses the older",
            "`iommu_frame_acquire` signature. `iommu_register_mapping` reads the",
            "actual frame type directly and has accepting branches only for",
            "`XNU_DEFAULT (0xb)` and `XNU_IO (0x19)`. Its `0/1` registration-mode",
            "argument is structurally distinct from the `1/2` class argument on",
            "`23A355`. This is the concrete version transition; it is not evidence",
            "that either policy can be bypassed.",
            "",
            "### Bounded Stage-2 surface",
            "",
            "| Build | Status | Device-tree gate | Guest functions | Direct UAT mapping |",
            "|---|---|---:|---:|---:|",
        ]
    )
    for item in report["sptm_handoffs"]:
        stage2 = item["stage2_surface"]
        lines.append(
            f"| {item['label']} | `{stage2['status']}` | "
            f"{stage2.get('has_virtualization_property', False)} | "
            f"{len(stage2.get('guest_functions', {}))} | "
            f"{stage2.get('uat_separation', {}).get('stage2_frame_types_direct_uat_mapping_allowed')} |"
        )
        if stage2["status"] == "NOT_FOUND":
            continue
        gate = stage2["virtualization_gate"]
        lines.append(
            f"  `{item['label']}` gate: property reference "
            f"`{format_address(gate['property_reference'])}`, value load "
            f"`{format_address(gate['property_value_load'])}`, boolean store "
            f"`{format_address(gate['boolean_store'])}` -> flag "
            f"`{format_address(gate['flag'])}`."
        )
        for reader in gate["readers"]:
            lines.append(
                f"  Gate reader `{reader.get('role') or 'unresolved'}`: "
                f"`0x{reader['address']:x}` in "
                f"`{format_address(reader['function'])}`."
            )
        dispatch = stage2["genter_dispatch"]
        lines.append(
            f"  GENTER dispatcher `{format_address(dispatch['function'])}` reaches universal "
            f"dispatcher `{format_address(dispatch['universal_dispatcher'])}`; state table "
            f"`{format_address(dispatch['table'])}`, strides "
            f"`{format_address(dispatch['state_stride'])}` / "
            f"`{format_address(dispatch['service_stride'])}`."
        )
        for transition in dispatch["transitions"]:
            lines.append(
                f"  Target `0x{transition['dispatch_target']:x}` -> service "
                f"`0x{transition['service_index']:x}`: "
                f"`{transition['origin_domain']}` -> `{transition['target_domain']}`, "
                f"handler `0x{transition['handler']:x}`."
            )
        for name, function in stage2["guest_functions"].items():
            slots = ", ".join(
                f"0x{slot['address']:x}" for slot in function["pointer_slots"]
            ) or "-"
            lines.append(
                f"  Guest function `{name}`: `0x{function['function']:x}`; "
                f"direct callers `{len(function['direct_calls'])}`; pointer slots "
                f"`{slots}`."
            )
        services = stage2.get("service_table", {})
        registry = services.get("registry_entry") or {}
        lines.append(
            f"  SPTM endpoint table `{format_address(services.get('table'))}`: "
            f"status `{services.get('status')}`, table id "
            f"`{services.get('table_id')}`, count "
            f"`{services.get('endpoint_count')}`, registry slot "
            f"`{format_address(registry.get('address'))}`; guest-enter exposed "
            f"`{services.get('guest_enter_exposed_as_endpoint')}`."
        )
        for endpoint in services.get("entries", []):
            lines.append(
                f"  Endpoint `0x{endpoint['endpoint']:x}`: "
                f"`{endpoint.get('name') or 'unresolved'}` at "
                f"`{format_address(endpoint.get('function'))}` "
                f"({endpoint.get('name_source')}, flags "
                f"`0x{endpoint.get('flags', 0):x}`)."
            )
        lifecycle = stage2.get("typed_root_lifecycle", {})
        root = lifecycle.get("root_retype", {})
        page = lifecycle.get("page_retype", {})
        acquire = lifecycle.get("root_acquire", {})
        lines.append(
            f"  Typed-root lifecycle `{lifecycle.get('status')}`: acquire alignment "
            f"`{format_address(acquire.get('alignment'))}`, required type "
            f"`{format_address(acquire.get('expected_frame_type'))}`, tracked range "
            f"`{acquire.get('tracked_physical_range_required')}`."
        )
        lines.append(
            f"  Root retype: VMID field shift "
            f"`{format_address(root.get('vmid_field_shift'))}`, validation "
            f"`(vmid & {format_address(root.get('vmid_validation_mask'))}) == "
            f"{format_address(root.get('vmid_validation_value'))}`; unique bitmap "
            f"claim `{root.get('vmid_duplicate_rejected')}`, retype-out TLBI "
            f"`{root.get('out_performs_stage2_tlb_invalidation')}`, VMID release "
            f"`{root.get('out_releases_vmid_bitmap')}`."
        )
        lines.append(
            f"  Page-table retype: subtype limit "
            f"`{page.get('subtype_maximum_exclusive')}`; retype-out requires zero "
            f"mapping/nested refs "
            f"`{page.get('out_requires_zero_mapping_refcount')}/"
            f"{page.get('out_requires_zero_nested_refcount')}`."
        )
        for row in stage2["frame_policy_rows"]:
            lines.append(
                f"  Frame type `0x{row['frame_type']:x}` "
                f"(`{row['frame_type_name']}`): domain bitmap "
                f"`0x{row['allowed_domain_bitmap']:x}`, maximum mapping class "
                f"`{row['maximum_mapping_class']}`, direct UAT mapping "
                f"`{row['direct_uat_mapping_allowed']}`."
            )
    lines.extend(
        [
            "",
            "The Stage-2 evidence is a typed, private guest-context state machine,",
            "not a second UAT leaf interface. The device-tree boolean gates the",
            "root-table retype, SURT allocation, and GENTER paths. The root must",
            "already be a tracked 0x1f frame with a unique SPTM-owned VMID before",
            "guest-enter can consume it; guest-enter is not a public table endpoint.",
            "The two Stage-2 frame types have dedicated lifecycle callbacks but zero",
            "IOMMU-domain bitmap and zero maximum mapping class, so this report does",
            "not identify a UAT-to-Stage-2 shortcut or a protected-memory bypass.",
            "",
            "## iOS 26 GFX PatchBay and UPPL state",
            "",
        ]
    )
    for item in report["ios26_gfx_uppl"]["slices"]:
        lines.extend(
            [
                f"### Slice `{item['name']}`",
                "",
                f"Producer status: **{item['producer_status']}**.",
                f"Dispatch state: `0x{item['dispatch_state']:x}`; packaged count/table: "
                f"`{item['static_handler_count']}` / `0x{item['static_handler_table']:x}`.",
                f"Direct references: `{len(item['direct_references'])}`; direct writers: "
                f"`{item['direct_writer_count']}`.",
                f"Weak definition: `{item['symbol_metadata'].get('weak_definition')}`; "
                f"relocations: `{item['symbol_metadata'].get('total_relocations')}`; "
                f"chained fixups: `{item['symbol_metadata'].get('dyld_chained_fixups')}`.",
                "",
                "| Patch symbol | Tag | Width | Default |",
                "|---|---:|---:|---:|",
            ]
        )
        for patch in item["relevant_patch_descriptors"]:
            lines.append(
                f"| `{patch['symbol']}` | `{patch['tag']}` | `{patch['width']}` | "
                f"`0x{patch['default']:x}` |"
            )
        lines.append("")
        lines.append(
            "Named PatchBay descriptors for the UPPL dispatch object: "
            + ("present." if item["uppl_state_patch_descriptors"] else "none.")
        )
        shared = item["shared_handoff"]
        lines.append(
            "PPL shared handoff: "
            f"**{shared['status']}**; PatchBay value reads="
            f"`{len(shared['ppl_shared_base_reads'])}`, pointer state="
            f"`{'-' if shared['pointer_state'] is None else f'0x{shared['pointer_state']:x}'}`, "
            f"peer magic write="
            f"`{'-' if shared['peer_magic_write'] is None else f'0x{shared['peer_magic_write']:x}'}`, "
            f"context guard read="
            f"`{'-' if shared['context_guard_read'] is None else f'0x{shared['context_guard_read']:x}'}`."
        )
        consumers = item["handoff_consumers"]
        if consumers.get("record_count") is not None:
            lines.append(
                "Handoff queue: "
                f"**{consumers['status']}**; `{consumers['record_count']}` records at "
                f"`+0x{consumers['record_table_offset']:x}`, stride "
                f"`0x{consumers['record_stride']:x}`, context IDs "
                f"`0..0x{consumers['maximum_context_id']:x}`, state `+0x0`, payload "
                f"`+0x8/+0x10`; flush `0x{consumers['flush_function']:x}`, idle "
                f"`0x{consumers['idle_function']:x}`, wake "
                f"`0x{consumers['wake_function']:x}`."
            )
        gxf = item["gxf_map_producer"]
        if gxf.get("constructor") is not None:
            lines.extend(
                [
                    "",
                    "Direct GXF map producer: "
                    f"**{gxf['status']}**; command `0x{gxf['command']:x}`, "
                    f"constructor `0x{gxf['constructor']:x}`, serialized wrapper "
                    f"`0x{gxf['serialized_wrapper']:x}`, submit wrapper "
                    f"`0x{gxf['submit_wrapper']:x}`, GXF enter "
                    f"`0x{gxf['gxf_enter']:x}`.",
                    "",
                    "| Producer function | Symbol | Role | Callsites | Markers |",
                    "|---:|---|---|---|---|",
                ]
            )
            for producer in gxf["producer_functions"]:
                symbol = producer["symbol"] or "-"
                callsites = ", ".join(
                    f"0x{address:x}" for address in producer["callsites"]
                )
                markers = ", ".join(producer["markers"]) or "-"
                lines.append(
                    f"| `0x{producer['function']:x}` | `{symbol}` | "
                    f"`{producer['role']}` | `{callsites}` | `{markers}` |"
                )
            lines.extend(
                [
                    "",
                    "This is a local firmware call chain. No direct named RTKit "
                    "message/endpoint ingress or exact data pointer to the constructor "
                    "was observed, so it is not evidence that command `0x10` is a "
                    "translated SPTM UAT endpoint-4/5 request.",
                ]
            )

    conclusion = report["conclusion"]
    lines.extend(
        [
            "",
            "## Consequence for the elevation route",
            "",
            conclusion["route"],
            "",
            "This rules out the simple route of reusing the old firmware-provider",
            "method or treating PatchBay as the UPPL handler publisher. The shared",
            "handoff is now directly linked on both sides, but its layout already exists",
            "on iOS 17. The next static target is the protected-frame consumer reached by",
            "iOS 26's `gfx-data-base`/`gfx-data-size` registration. The UPPL route remains",
            "classified as inactive/unresolved until a replacement for the weak default",
            "is directly observed.",
            "",
            f"Limitation: {conclusion['limitation']}",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ios17-kernel", type=pathlib.Path, required=True)
    parser.add_argument("--ios17-sptm", type=pathlib.Path, required=True)
    parser.add_argument("--ios26-kernel", type=pathlib.Path, required=True)
    parser.add_argument("--ios26-sptm", type=pathlib.Path, required=True)
    parser.add_argument("--ios26-gfx", type=pathlib.Path, required=True)
    parser.add_argument("--json-output", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()

    report = build_report(args)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.output.write_text(render_markdown(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
