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

from analyze_sptm_txm import MachOImage
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
    if len(raw) < 0x18:
        raise ValueError("frame-type policy record is shorter than 0x18 bytes")
    return {
        "frame_type": frame_type,
        "flags": raw[0],
        "policy_class": raw[1],
        "state_flags": raw[2],
        "allowed_domain_bitmap": struct.unpack_from("<Q", raw, 8)[0],
        "maximum_mapping_class": raw[0x10],
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
                    "requested_type": _recent_register_immediate(
                        map_body, index, "w1"
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
                    "requested_type": _recent_register_immediate(
                        register_body, index, "w1"
                    ),
                }
            )

    request_producers = []
    seen_callers = set()
    for instruction in image.instructions:
        if instruction.mnemonic != "bl" or _branch_target(instruction) != map_continue:
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
                        "requested_type": _recent_register_immediate(
                            caller_body, index, "w1"
                        ),
                    }
                )
        request_producers.append(
            {
                "function": caller,
                "map_continue_call": instruction.address,
                "frame_acquire_calls": descriptor_acquires,
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
    if policy_table is not None:
        for frame_type in range(0x40):
            raw = image.mapped_bytes(policy_table + frame_type * 0x60, 0x60)
            if raw is None:
                break
            policy_records.append(decode_frame_type_policy_record(raw, frame_type))
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
            if map_acquire_calls
            and register_calls
            and register_acquire_calls
            and frame_type_read is not None
            and policy_type_read is not None
            else "PARTIAL"
        ),
        "functions": {
            "sptm_uat_map_continue": map_continue,
            "iommu_frame_acquire_type": frame_acquire,
            "iommu_register_mapping": register_mapping,
        },
        "map_continue_frame_acquire_calls": map_acquire_calls,
        "map_continue_register_mapping_calls": register_calls,
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
            "allowed_domain_bitmap_offset": 8,
            "allowed_domain_bitmap_read": domain_bitmap_read,
            "maximum_mapping_class_offset": 0x10,
            "maximum_mapping_class_read": mapping_class_limit_read,
            "allowed_frame_types": allowed_policy_records,
        },
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
        "schema": "a15-agx-uppl-producer-v3",
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
            "route": (
                "The legacy AGX firmware-provider method is no longer usable. PatchBay "
                "supplies GPTBAT/PPL-shared addresses and the PPL-shared base feeds the "
                "cross-version SPTM/GFX handoff. The UPPL object remains a separate zero "
                "weak default with no local writer, relocation, fixup, or named patch. "
                "The iOS 26 addition established here is SPTM's dynamic registration of "
                "one or more GFX data segments in its protected-frame registry. The UAT "
                "consumer still enforces page-table frame type 0x17. Mapping "
                "registration uses wildcard selector 0x42, then reads the actual frame "
                "type and applies per-type domain/mapping policy."
            ),
            "limitation": (
                "Static evidence does not show that the exact A15 payload ever replaces "
                "the weak UPPL default, publish handler indices, or prove a privilege-"
                "elevation path."
            ),
        },
    }


def render_markdown(report: dict) -> str:
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
        ]
        register_types = [
            call.get("requested_type")
            for call in policy.get("register_mapping_frame_acquire_calls", [])
        ]
        map_function = functions.get("sptm_uat_map_continue")
        mapping_policy = policy.get("mapping_policy", {})
        allowed_types = [
            f"0x{record['frame_type']:x}"
            for record in mapping_policy.get("allowed_frame_types", [])
        ]
        lines.append(
            f"- **{item['label']}**: `{policy['status']}`; map-continue="
            f"`{'-' if map_function is None else f'0x{map_function:x}'}`, "
            f"frame acquisition selectors=`{map_types}`, mapping registration "
            f"selectors=`{register_types}`."
        )
        if mapping_policy.get("descriptor_table") is not None:
            lines.append(
                f"  Policy table: `0x{mapping_policy['descriptor_table']:x}`; "
                f"frame types with a nonzero domain bitmap or mapping class: "
                f"`{allowed_types}`."
            )
        for producer in policy.get("map_request_producers", []):
            descriptor_types = [
                call.get("requested_type")
                for call in producer.get("frame_acquire_calls", [])
            ]
            lines.append(
                f"  Direct request producer: `0x{producer['function']:x}` calls "
                f"map continuation at `0x{producer['map_continue_call']:x}`; "
                f"descriptor-frame selectors=`{descriptor_types}`."
            )
    lines.extend(
        [
            "",
            "On `23A355`, map continuation acquires page-table frames as type",
            "`0x17`. `iommu_register_mapping` passes `0x42` as a wildcard selector,",
            "then reads the actual frame type before consulting per-type domain and",
            "mapping-type policy. Dynamic GFX registration therefore feeds protected",
            "metadata; it does not by itself authorize an arbitrary UAT mapping.",
            "The selector-1 GFX-data compatibility type is `2`; its policy row has",
            "a zero domain bitmap and zero maximum mapping class, so this registered",
            "region is not itself accepted as a direct UAT leaf-mapping target.",
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
