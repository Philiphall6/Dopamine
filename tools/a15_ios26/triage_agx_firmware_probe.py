#!/usr/bin/env python3
"""Triage the bounded AGX firmware identity read without inferring submission."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from triage_agx_metadata_probe import fields, load_events, numbered
from triage_agx_owned_queue_probe import detail, triage as queue_triage


REVISION = "self-page-write-v1+agx-firmware-read-v2+rtkit-mmio-disabled-v1"
FIRMWARE_REQUIRED = (
    ("titan.own-queue.firmware-read", "START"),
    ("titan.own-queue.firmware-object", "PASS"),
    ("titan.own-queue.firmware-object-repeat", "PASS"),
    ("titan.own-queue.firmware-vtable-read", "PASS"),
    ("titan.own-queue.firmware-vtable-repeat", "PASS"),
    ("titan.own-queue.firmware-vtable", "INFO"),
    ("titan.own-queue.firmware-read", "PASS"),
)


def triage(events: list[dict], run_id: str) -> dict:
    report = queue_triage(events, run_id, revision=REVISION)
    run = [event for event in events if event["run_id"] == run_id]
    sequence = [(event["stage"], event["status"]) for event in run]
    ordered = False
    try:
        position = sequence.index(("titan.own-queue.identity", "PASS")) + 1
        for checkpoint in FIRMWARE_REQUIRED:
            position = sequence.index(checkpoint, position) + 1
        ordered = position <= sequence.index(("titan.own-queue", "PASS"))
    except ValueError:
        pass

    object_address = numbered(detail(run, "titan.own-queue.firmware-object"), "value")
    object_repeat = numbered(detail(run, "titan.own-queue.firmware-object-repeat"), "value")
    raw_vtable = numbered(detail(run, "titan.own-queue.firmware-vtable-read"), "value")
    raw_repeat = numbered(detail(run, "titan.own-queue.firmware-vtable-repeat"), "value")
    summary = fields(detail(run, "titan.own-queue.firmware-vtable", "INFO"))
    unslid = numbered(detail(run, "titan.own-queue.firmware-vtable", "INFO"), "unslid")
    firmware_ok = bool(
        ordered and object_address and object_address == object_repeat and
        raw_vtable and raw_vtable == raw_repeat and unslid and
        numbered(detail(run, "titan.own-queue.firmware-vtable", "INFO"), "object") == object_address and
        summary.get("static-ASC-base-match") in {"yes", "no"} and
        (summary["static-ASC-base-match"] == "yes") ==
        (unslid == 0xfffffff007b18e58)
    )
    report["firmware_identity_ok"] = firmware_ok
    report["firmware_vtable_unslid"] = f"{unslid:#x}" if firmware_ok else None
    report["static_asc_base_match"] = (
        summary["static-ASC-base-match"] == "yes" if firmware_ok else None
    )
    if report["verdict"] == "owned_queue_and_buffer_observed":
        report["verdict"] = ("firmware_identity_observed" if firmware_ok else
                             "incomplete_or_blocked")
    report["limits"] = (
        "Only own-client queue and firmware identity reads are observed. "
        "No packet submission, parser consumption, physical write, "
        "protected-memory modification, or SPTM/TXM bypass is proved."
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path)
    parser.add_argument("--run-id", help="Select a run; default is the last run in file order")
    args = parser.parse_args()
    raw = args.jsonl.read_bytes()
    events = load_events(raw)
    report = triage(events, args.run_id or events[-1]["run_id"])
    report["source_sha256"] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
