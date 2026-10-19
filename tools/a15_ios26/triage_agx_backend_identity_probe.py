#!/usr/bin/env python3
"""Triage bounded AGX backend identity reads, never packet submission."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from triage_agx_firmware_probe import triage as firmware_triage
from triage_agx_metadata_probe import fields, load_events, numbered
from triage_agx_owned_queue_probe import detail


REVISION = "self-page-write-v1+agx-backend-identity-v2+rtkit-mmio-disabled-v1"
META_VTABLE = 0xfffffff007b16de0
SLOTS = {
    "factory": 0xfffffff0087e4280,
    "allocate": 0xfffffff0087f630c,
    "prepare": 0xfffffff0087f5ca8,
}
SLOT_ADDRESSES = {
    "factory": 0xfffffff007b1e690,
    "allocate": 0xfffffff007b16e48,
    "prepare": 0xfffffff007b16db0,
}
REQUIRED = (
    ("titan.backend-identity", "START"),
    ("titan.backend-identity.metaclass", "PASS"),
    ("titan.backend-identity.metaclass-repeat", "PASS"),
    ("titan.backend-identity.metaclass-identity", "PASS"),
    *((f"titan.backend-identity.{name}{suffix}", "PASS")
      for name in SLOTS for suffix in ("-read", "-repeat", "")),
    ("titan.backend-identity", "PASS"),
    ("titan.backend-identity", "STOP"),
)


def triage(events: list[dict], run_id: str, *, revision: str = REVISION) -> dict:
    report = firmware_triage(events, run_id, revision=revision)
    run = [event for event in events if event["run_id"] == run_id]
    sequence = [(event["stage"], event["status"]) for event in run]
    ordered = False
    try:
        position = sequence.index(("titan.own-queue.firmware-read", "PASS")) + 1
        for checkpoint in REQUIRED:
            position = sequence.index(checkpoint, position) + 1
        ordered = position <= sequence.index(("titan.own-queue", "PASS"))
    except ValueError:
        pass

    metaclass = numbered(detail(run, "titan.backend-identity.metaclass"), "value")
    meta_stable = bool(metaclass and metaclass == numbered(
        detail(run, "titan.backend-identity.metaclass-repeat"), "value"))
    identity = detail(run, "titan.backend-identity.metaclass-identity")
    meta_type = bool(meta_stable and
                     numbered(identity, "value") == metaclass and
                     numbered(identity, "unslid") == META_VTABLE and
                     numbered(identity, "expected") == META_VTABLE)
    slide = metaclass - META_VTABLE if meta_type else 0

    slots_ok = True
    for name, target in SLOTS.items():
        prefix = f"titan.backend-identity.{name}"
        first = detail(run, prefix + "-read")
        second = detail(run, prefix + "-repeat")
        summary = detail(run, prefix)
        slot = numbered(summary, "slot")
        raw = numbered(first, "value")
        slots_ok &= bool(meta_type and slot == SLOT_ADDRESSES[name] + slide and
                         raw and raw == numbered(second, "value") and
                         numbered(first, "source") == slot and
                         numbered(second, "source") == slot and
                         numbered(first, "offset") == 0 and
                         numbered(second, "offset") == 0 and
                         numbered(summary, "unslid") == target and
                         numbered(summary, "expected") == target)

    backend_ok = bool(ordered and meta_type and slots_ok)
    report["backend_identity_ok"] = backend_ok
    report["metaclass"] = f"{metaclass:#x}" if backend_ok else None
    if report["verdict"] == "firmware_identity_observed":
        report["verdict"] = ("agx_backend_identity_observed" if backend_ok else
                             "incomplete_or_blocked")
    report["limits"] = (
        "Only same-client queue, firmware object, metaclass, and code slots are observed. "
        "No backend method, selector 25, GPU packet, parser, protected write, or SPTM/TXM access."
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path)
    parser.add_argument("--run-id", help="Select a run; default is the last run in file order")
    args = parser.parse_args()
    raw = args.jsonl.read_bytes()
    events = load_events(raw)
    report = triage(events, args.run_id or events[-1]["run_id"])
    report["source_sha256"] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
