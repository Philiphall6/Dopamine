#!/usr/bin/env python3
"""Link a bounded live AGX firmware identity read to the exact static callback."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from analyze_sptm_txm import MachOImage
from triage_agx_firmware_probe import triage
from triage_agx_metadata_probe import load_events


IMAGE_SHA256 = "8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1"
AGX_IMAGE = "com.apple.AGXG14P"
STATIC_BASE = 0xfffffff007004000
OBSERVED_VTABLE = 0xfffffff007b19ab8
BASE_VTABLE = 0xfffffff007b18e58
SLOT_OFFSET = 0x210
OBSERVED_ENCODING = 0x801192500183dd6c
BASE_ENCODING = 0x8011925001630720
OBSERVED_TARGET = 0xfffffff008841d6c
BASE_TARGET = 0xfffffff008634720


def require_instruction(image: MachOImage, address: int, mnemonic: str, operands: str) -> None:
    instruction = image.instruction_at(address)
    if instruction is None or (instruction.mnemonic, instruction.op_str) != (mnemonic, operands):
        actual = None if instruction is None else (instruction.mnemonic, instruction.op_str)
        raise ValueError(f"instruction {address:#x}: expected {(mnemonic, operands)}, got {actual}")


def verify_static_link(image: MachOImage) -> dict:
    for label, slot, expected_encoding, expected_target in (
        ("observed", OBSERVED_VTABLE + SLOT_OFFSET, OBSERVED_ENCODING, OBSERVED_TARGET),
        ("base", BASE_VTABLE + SLOT_OFFSET, BASE_ENCODING, BASE_TARGET),
    ):
        encoded = image.read_u64(slot)
        target = None if encoded is None else STATIC_BASE + (encoded & 0xffffffff)
        if (encoded, target) != (expected_encoding, expected_target):
            raise ValueError(f"{label} firmware slot {slot:#x}: got {encoded} -> {target}")

    if not any(ref.address == 0xfffffff00884bde8
               for ref in image.references_to(OBSERVED_VTABLE - 0x10)):
        raise ValueError("observed vtable constructor reference missing")
    for address, mnemonic, operands in (
        (0xfffffff00884bde8, "add", "x16, x16, #0xaa8"),
        (0xfffffff00884bdec, "add", "x16, x16, #0x10"),
        (0xfffffff00884bdfc, "str", "x16, [x19]"),
        (0xfffffff0087fd464, "ldr", "x0, [x8, #0x4a0]"),
        (0xfffffff0087fd488, "ldr", "x1, [x10]"),
        (0xfffffff0087fd4b4, "ldr", "x9, [x16, #0x210]"),
        (0xfffffff0087fd4c4, "blraa", "x9, x17"),
        (0xfffffff0087fd4cc, "str", "x0, [x21]"),
        (OBSERVED_TARGET, "bti", "c"),
        (OBSERVED_TARGET + 4, "mov", "x0, x1"),
        (OBSERVED_TARGET + 8, "ret", ""),
    ):
        require_instruction(image, address, mnemonic, operands)

    return {
        "observed_vtable_unslid": f"{OBSERVED_VTABLE:#x}",
        "callback_slot": f"{OBSERVED_VTABLE + SLOT_OFFSET:#x}",
        "callback_target": f"{OBSERVED_TARGET:#x}",
        "callback_effect": "returns x1 unchanged; caller stores result",
        "constructor_installs_observed_vtable": True,
        "live_packet_or_parser_observed": False,
    }


def audit(kernelcache: Path, journal: Path) -> dict:
    image_hash = hashlib.sha256(kernelcache.read_bytes()).hexdigest()
    if image_hash != IMAGE_SHA256:
        raise ValueError(f"kernelcache SHA-256 mismatch: {image_hash}")
    raw = journal.read_bytes()
    events = load_events(raw)
    if not events:
        raise ValueError("empty journal")
    report = triage(events, events[-1]["run_id"])
    if (report["verdict"] != "firmware_identity_observed" or
            report["firmware_vtable_unslid"] != f"{OBSERVED_VTABLE:#x}" or
            report["first_blocker"] is not None or report["forbidden_stages"]):
        raise ValueError("journal does not establish the expected bounded firmware identity")

    result = verify_static_link(MachOImage(kernelcache, AGX_IMAGE))
    result.update({
        "build": "23A355",
        "kernelcache_sha256": image_hash,
        "journal_sha256": hashlib.sha256(raw).hexdigest(),
        "run_id": report["run_id"],
        "journal_verdict": report["verdict"],
        "limits": "Static callback link only; no live packet, protected write, or SPTM/TXM access.",
    })
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernelcache", type=Path)
    parser.add_argument("journal", type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.kernelcache, args.journal), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
