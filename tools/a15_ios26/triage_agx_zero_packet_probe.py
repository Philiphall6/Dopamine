#!/usr/bin/env python3
"""Triage one bounded selector-25 empty-record observation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from triage_agx_metadata_probe import fields, load_events, numbered
from triage_agx_owned_queue_probe import detail
from triage_agx_packet_route_identity_probe import triage as route_triage


REVISION = "self-page-write-v1+agx-zero-packet-abi-v2+rtkit-mmio-disabled-v1"
REQUIRED = (
    ("titan.zero-packet", "START"),
    ("titan.zero-packet.command-buffer", "PASS"),
    ("titan.zero-packet.firmware", "PASS"),
    ("titan.zero-packet.buffer", "PASS"),
    ("titan.zero-packet.identities", "PASS"),
    ("titan.zero-packet.buffer-preflight", "PASS"),
    ("titan.zero-packet.pool-before", "PASS"),
    ("titan.zero-packet.queue-before", "PASS"),
    ("titan.zero-packet.pool-before-repeat", "PASS"),
    ("titan.zero-packet.preflight-stability", "PASS"),
    ("titan.zero-packet.record-size", "PASS"),
    ("titan.zero-packet.record-size-repeat", "PASS"),
    ("titan.zero-packet.record-contract", "PASS"),
    ("titan.zero-packet.call", "START"),
    ("titan.zero-packet.call", "PASS"),
    ("titan.zero-packet.pool-after", "PASS"),
    ("titan.zero-packet.queue-after", "PASS"),
    ("titan.zero-packet.pool-after-repeat", "PASS"),
    ("titan.zero-packet.queue-after-repeat", "PASS"),
    ("titan.zero-packet.cleanup-state", "PASS"),
    ("titan.zero-packet.command-buffer-final", "PASS"),
    ("titan.zero-packet.firmware-final", "PASS"),
    ("titan.zero-packet.buffer-final", "PASS"),
    ("titan.zero-packet.postflight", "PASS"),
    ("titan.zero-packet", "PASS"),
    ("titan.zero-packet", "STOP"),
)


def _pool_digest(run: list[dict], stage: str) -> int | None:
    entry = detail(run, stage)
    return numbered(entry, "digest") if numbered(entry, "read") == 0 else None


def triage(events: list[dict], run_id: str) -> dict:
    report = route_triage(events, run_id, revision=REVISION)
    run = [event for event in events if event["run_id"] == run_id]
    sequence = [(event["stage"], event["status"]) for event in run]

    ordered = False
    try:
        position = sequence.index(("titan.packet-route-identity", "STOP")) + 1
        for checkpoint in REQUIRED:
            position = sequence.index(checkpoint, position) + 1
        ordered = position <= sequence.index(("titan.own-queue", "PASS"), position)
    except ValueError:
        pass

    call_start_count = sequence.count(("titan.zero-packet.call", "START"))
    call_pass_count = sequence.count(("titan.zero-packet.call", "PASS"))
    call = detail(run, "titan.zero-packet.call")
    call_ok = bool(
        call_start_count == call_pass_count == 1 and
        numbered(call, "kr") == 0 and
        numbered(call, "output-count") == 1 and
        fields(call).get("attempt") == "1/1"
    )

    record_contract = fields(detail(run, "titan.zero-packet.record-contract"))
    record_ok = bool(
        numbered(detail(run, "titan.zero-packet.record-size"), "value") == 0x30 and
        numbered(detail(run, "titan.zero-packet.record-size-repeat"), "value") == 0x30 and
        record_contract.get("device+0x268") == "0x30/0x30" and
        numbered(detail(run, "titan.zero-packet.record-contract"), "expected") == 0x30
    )

    preflight = fields(detail(run, "titan.zero-packet.buffer-preflight"))
    preflight_stability = fields(detail(run, "titan.zero-packet.preflight-stability"))
    buffer_ok = (
        numbered(detail(run, "titan.zero-packet.buffer-preflight"), "size") == 0x4000 and
        preflight.get("all-zero") == "yes" and
        preflight_stability.get("pool") == "same" and
        numbered(detail(run, "titan.zero-packet.preflight-stability"), "backend") == 0
    )

    before = _pool_digest(run, "titan.zero-packet.pool-before")
    before_repeat = _pool_digest(run, "titan.zero-packet.pool-before-repeat")
    after = _pool_digest(run, "titan.zero-packet.pool-after")
    after_repeat = _pool_digest(run, "titan.zero-packet.pool-after-repeat")
    cleanup = fields(detail(run, "titan.zero-packet.cleanup-state"))
    pool_ok = bool(
        before is not None and before == before_repeat == after == after_repeat and
        cleanup.get("pool-post") == "stable" and
        cleanup.get("pool-restored") == "yes"
    )

    queue_before = fields(detail(run, "titan.zero-packet.queue-before"))
    queue_after = fields(detail(run, "titan.zero-packet.queue-after"))
    queue_after_repeat = fields(detail(run, "titan.zero-packet.queue-after-repeat"))
    queue_ok = bool(
        queue_before.get("backend") == "0x0" and
        queue_after == queue_after_repeat and
        queue_after.get("backend") == "0x0" and
        cleanup.get("queue-post") == "stable" and
        cleanup.get("backend") == "0x0/0x0"
    )

    command = numbered(detail(run, "titan.zero-packet.command-buffer"), "value")
    firmware = numbered(detail(run, "titan.zero-packet.firmware"), "value")
    buffer = numbered(detail(run, "titan.zero-packet.buffer"), "value")
    postflight = fields(detail(run, "titan.zero-packet.postflight"))
    identities_ok = bool(
        command and command == numbered(detail(run, "titan.zero-packet.command-buffer-final"), "value") and
        firmware and firmware == numbered(detail(run, "titan.zero-packet.firmware-final"), "value") and
        buffer and buffer == numbered(detail(run, "titan.zero-packet.buffer-final"), "value") and
        postflight.get("command") == postflight.get("firmware") ==
        postflight.get("buffer") == "same" and
        postflight.get("all-zero") == "yes"
    )

    zero_ok = bool(
        ordered and report.get("packet_route_identity_ok") and record_ok and call_ok and
        buffer_ok and pool_ok and queue_ok and identities_ok
    )
    report["zero_packet_observation_ok"] = zero_ok
    report["pool_digest"] = f"{before:#x}" if zero_ok else None
    report["selector25_attempts"] = 1 if zero_ok else None
    if report["verdict"] == "agx_packet_route_identity_observed":
        report["verdict"] = ("agx_zero_packet_cleanup_observed" if zero_ok else
                             "incomplete_or_blocked")
    report["limits"] = (
        "Exactly one selector-25 call with an all-zero owned 16K buffer is checked. "
        "No nonempty record, GPU command dispatch, MMIO, physical write, protected-memory "
        "modification, SPTM/TXM bypass, bootstrap, or Sileo launch is proved."
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
