#!/usr/bin/env python3
"""Triage read-only AGX command-buffer and firmware callback identities."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from triage_agx_backend_identity_probe import triage as backend_triage
from triage_agx_metadata_probe import fields, load_events, numbered
from triage_agx_owned_queue_probe import detail


REVISION = "self-page-write-v1+agx-packet-route-identity-v1+rtkit-mmio-disabled-v1"
COMMAND_VTABLE = 0xfffffff007b17410
COMMAND_CALLBACK = 0xfffffff0087fd300
FIRMWARE_VTABLE = 0xfffffff007b19ab8
FIRMWARE_CALLBACK = 0xfffffff008841d6c
REQUIRED = (
    ("titan.packet-route-identity", "START"),
    ("titan.packet-route-identity.command-buffer", "PASS"),
    ("titan.packet-route-identity.command-buffer-repeat", "PASS"),
    ("titan.packet-route-identity.command-vtable", "PASS"),
    ("titan.packet-route-identity.command-vtable-repeat", "PASS"),
    ("titan.packet-route-identity.command-type", "PASS"),
    ("titan.packet-route-identity.command-device", "PASS"),
    ("titan.packet-route-identity.command-device-repeat", "PASS"),
    ("titan.packet-route-identity.device-link", "PASS"),
    ("titan.packet-route-identity.command-callback-read", "PASS"),
    ("titan.packet-route-identity.command-callback-repeat", "PASS"),
    ("titan.packet-route-identity.command-callback", "PASS"),
    ("titan.packet-route-identity.firmware-type", "PASS"),
    ("titan.packet-route-identity.firmware-vtable-repeat", "PASS"),
    ("titan.packet-route-identity.firmware-callback-read", "PASS"),
    ("titan.packet-route-identity.firmware-callback-repeat", "PASS"),
    ("titan.packet-route-identity.firmware-callback", "PASS"),
    ("titan.packet-route-identity.command-buffer-final", "PASS"),
    ("titan.packet-route-identity.firmware-final", "PASS"),
    ("titan.packet-route-identity.stability", "PASS"),
    ("titan.packet-route-identity", "PASS"),
    ("titan.packet-route-identity", "STOP"),
)


def _slot_ok(run: list[dict], name: str, address: int, target: int) -> bool:
    prefix = f"titan.packet-route-identity.{name}"
    first = detail(run, prefix + "-read")
    repeat = detail(run, prefix + "-repeat")
    summary = detail(run, prefix)
    raw = numbered(first, "value")
    return bool(
        raw and raw == numbered(repeat, "value") and
        numbered(first, "source") == address and
        numbered(repeat, "source") == address and
        numbered(first, "offset") == numbered(repeat, "offset") == 0 and
        numbered(summary, "slot") == address and
        numbered(summary, "unslid") == target and
        numbered(summary, "expected") == target
    )


def triage(events: list[dict], run_id: str) -> dict:
    report = backend_triage(events, run_id, revision=REVISION)
    run = [event for event in events if event["run_id"] == run_id]
    sequence = [(event["stage"], event["status"]) for event in run]
    ordered = False
    try:
        position = sequence.index(("titan.backend-identity", "STOP")) + 1
        for checkpoint in REQUIRED:
            position = sequence.index(checkpoint, position) + 1
        ordered = position <= sequence.index(("titan.own-queue", "PASS"))
    except ValueError:
        pass

    metaclass = detail(run, "titan.backend-identity.metaclass-identity")
    slide = (numbered(metaclass, "value") or 0) - (numbered(metaclass, "unslid") or 0)
    command = numbered(detail(run, "titan.packet-route-identity.command-buffer"), "value")
    command_type = detail(run, "titan.packet-route-identity.command-type")
    command_raw = numbered(detail(run, "titan.packet-route-identity.command-vtable"), "value")
    device = numbered(detail(run, "titan.own-queue.device"), "value")
    command_device = numbered(detail(run, "titan.packet-route-identity.command-device"), "value")
    firmware = numbered(detail(run, "titan.own-queue.firmware-object"), "value")
    firmware_raw = numbered(detail(run, "titan.own-queue.firmware-vtable-read"), "value")
    firmware_type = detail(run, "titan.packet-route-identity.firmware-type")
    stability = fields(detail(run, "titan.packet-route-identity.stability"))
    route_ok = bool(
        ordered and report["backend_identity_ok"] and slide > 0 and
        command and command == numbered(detail(run, "titan.packet-route-identity.command-buffer-repeat"), "value") and
        command == numbered(detail(run, "titan.packet-route-identity.command-buffer-final"), "value") and
        command_raw and command_raw == numbered(detail(run, "titan.packet-route-identity.command-vtable-repeat"), "value") and
        numbered(command_type, "object") == command and
        numbered(command_type, "unslid") == numbered(command_type, "expected") == COMMAND_VTABLE and
        device and command_device == device and
        command_device == numbered(detail(run, "titan.packet-route-identity.command-device-repeat"), "value") and
        numbered(detail(run, "titan.packet-route-identity.device-link"), "command-device") == device and
        numbered(detail(run, "titan.packet-route-identity.device-link"), "expected") == device and
        _slot_ok(run, "command-callback", COMMAND_VTABLE + slide + 0x98, COMMAND_CALLBACK) and
        firmware and firmware == numbered(detail(run, "titan.packet-route-identity.firmware-final"), "value") and
        report["firmware_vtable_unslid"] == f"{FIRMWARE_VTABLE:#x}" and
        numbered(firmware_type, "object") == firmware and
        numbered(firmware_type, "unslid") == numbered(firmware_type, "expected") == FIRMWARE_VTABLE and
        firmware_raw and firmware_raw == numbered(detail(run, "titan.packet-route-identity.firmware-vtable-repeat"), "value") and
        _slot_ok(run, "firmware-callback", FIRMWARE_VTABLE + slide + 0x210, FIRMWARE_CALLBACK) and
        stability.get("command") == stability.get("firmware") == "same"
    )
    report["packet_route_identity_ok"] = route_ok
    report["command_buffer"] = f"{command:#x}" if route_ok else None
    if report["verdict"] == "agx_backend_identity_observed":
        report["verdict"] = ("agx_packet_route_identity_observed" if route_ok else
                             "incomplete_or_blocked")
    report["limits"] = (
        "Only same-client objects and callback code slots were read. No method call, "
        "selector 25, GPU packet, parser consumption, physical write, or SPTM/TXM access."
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
