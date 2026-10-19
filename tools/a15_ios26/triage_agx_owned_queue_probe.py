#!/usr/bin/env python3
"""Triage one exact-build owned AGX queue diagnostic run."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from triage_agx_iouat_object_probe import REQUIRED as OBJECT_REQUIRED
from triage_agx_metadata_probe import fields, load_events, numbered
from triage_agx_gart_state_probe import FORBIDDEN_PREFIXES
from triage_agx_shared_alias_probe import SHARED_REQUIRED


REVISION = "self-page-write-v1+agx-own-queue-v2+rtkit-mmio-disabled-v1"
OWN_REQUIRED = (
    ("titan.own-queue", "START"),
    ("titan.own-queue.device", "PASS"),
    ("titan.own-queue.device-vtable-identity", "PASS"),
    ("titan.own-queue.array", "PASS"),
    ("titan.own-queue.array-vtable-identity", "PASS"),
    ("titan.own-queue.array-count", "PASS"),
    ("titan.own-queue.input-size", "PASS"),
    ("titan.own-queue.create", "START"),
    ("titan.own-queue.create", "PASS"),
    ("titan.own-queue.array-slots", "PASS"),
    ("titan.own-queue.object", "PASS"),
    ("titan.own-queue.object-repeat", "PASS"),
    ("titan.own-queue.object-vtable-identity", "PASS"),
    ("titan.own-queue.table", "PASS"),
    ("titan.own-queue.device-backref", "PASS"),
    ("titan.own-queue.token", "PASS"),
    ("titan.own-queue.ready", "PASS"),
    ("titan.own-queue.resource", "PASS"),
    ("titan.own-queue.buffer-array", "PASS"),
    ("titan.own-queue.buffer-slots", "PASS"),
    ("titan.own-queue.buffer-repeat", "PASS"),
    ("titan.own-queue.identity", "PASS"),
    ("titan.own-queue", "PASS"),
    ("titan.own-queue.connection-close", "START"),
    ("titan.own-queue.connection-close", "PASS"),
)
INSERT_AFTER = OBJECT_REQUIRED.index(("titan.agx-iouat-object", "STOP")) + 1
REQUIRED = (
    OBJECT_REQUIRED[:INSERT_AFTER] + SHARED_REQUIRED[:-1] + OWN_REQUIRED +
    SHARED_REQUIRED[-1:] + OBJECT_REQUIRED[INSERT_AFTER:]
)
FORBIDDEN = FORBIDDEN_PREFIXES + (
    "titan.rtkit-parse", "titan.sptm", "titan.gfx", "titan.physwrite",
    "titan.physical-write", "titan.command-buffers", "titan.ipc-census",
)


def detail(run: list[dict], stage: str, status: str = "PASS") -> str:
    event = next((item for item in run if (item["stage"], item["status"]) ==
                  (stage, status)), None)
    return event["detail"] if event else ""


def triage(events: list[dict], run_id: str, *, revision: str = REVISION) -> dict:
    run = [event for event in events if event["run_id"] == run_id]
    if not run or run_id == "unknown":
        raise ValueError("requested run_id is absent or unattributable")
    sequence = [(event["stage"], event["status"]) for event in run]
    entry = fields(detail(run, "probe.entry", "START"))
    target_ok = entry.get("target") == "iPhone14,2" and entry.get("build") == "23A355"
    revision_ok = entry.get("revision") == revision
    position = 0
    missing = []
    for checkpoint in REQUIRED:
        try:
            position = sequence.index(checkpoint, position) + 1
        except ValueError:
            missing = [f"{stage}:{status}" for stage, status in REQUIRED
                       if (stage, status) not in sequence]
            if not missing:
                missing = ["checkpoint order invalid"]
            break
    forbidden = sorted({event["stage"] for event in run
                        if event["stage"].startswith(FORBIDDEN)})
    blocker = next((event for event in run if event["status"] in
                    {"FAIL", "BLOCKED", "REJECTED"} and
                    not event["stage"].startswith("hypervisor.") and
                    event["stage"] != "titan.run"), None)

    shared = detail(run, "titan.shared-alias.create")
    registry = detail(run, "titan.shared-alias.registry")
    buffer_id = numbered(shared, "id")
    buffer = numbered(detail(run, "titan.shared-alias.buffer"), "value")
    alias_ok = bool(
        numbered(shared, "kr") == 0 and
        numbered(shared, "out-size") == 0x10 and
        numbered(shared, "size") == 0x4000 and
        buffer_id and buffer_id == numbered(registry, "id") and
        buffer and buffer == numbered(detail(run, "titan.shared-alias.buffer-repeat"), "value") and
        numbered(detail(run, "titan.shared-alias.user-write"), "kernel-read") == 0 and
        fields(detail(run, "titan.shared-alias.user-write")).get("dual-alias-match") == "yes" and
        ("titan.shared-alias.restore", "PASS") in sequence and
        ("titan.shared-alias.redirect", "PASS") in sequence
    )
    created = detail(run, "titan.own-queue.create")
    queue_id = numbered(created, "id")
    count = numbered(detail(run, "titan.own-queue.array-count"), "value")
    queue = numbered(detail(run, "titan.own-queue.object"), "value")
    created_token = numbered(created, "token")
    queue_token = numbered(detail(run, "titan.own-queue.token"), "value")
    device = numbered(detail(run, "titan.own-queue.device"), "value")
    backref = numbered(detail(run, "titan.own-queue.device-backref"), "value")
    shared_table = numbered(detail(run, "titan.shared-alias.table"), "value")
    queue_table = numbered(detail(run, "titan.own-queue.table"), "value")
    identity = fields(detail(run, "titan.own-queue.identity"))
    queue_ok = bool(
        numbered(detail(run, "titan.own-queue.input-size"), "value") == 0x410 and
        numbered(created, "kr") == 0 and
        numbered(created, "output-size") == 0x10 and
        queue_id and count and queue_id < count and queue and
        queue == numbered(detail(run, "titan.own-queue.object-repeat"), "value") and
        numbered(detail(run, "titan.own-queue.ready"), "value") == 1 and
        created_token is not None and queue_token == created_token and
        numbered(detail(run, "titan.own-queue.buffer-repeat"), "value") == buffer and
        numbered(detail(run, "titan.own-queue.identity"), "queue") == queue and
        shared_table and queue_table == shared_table and
        device and backref == device and
        identity.get("table") == "same" and identity.get("device") == "same" and
        identity.get("token") == "same" and identity.get("buffer-stable") == "yes" and
        identity.get("ready") == "1"
    )
    complete = (target_ok and revision_ok and not missing and not forbidden and
                blocker is None and alias_ok and queue_ok)
    return {
        "run_id": run_id,
        "checkpoint_count": len(run),
        "target_ok": target_ok,
        "revision_ok": revision_ok,
        "alias_ok": alias_ok,
        "queue_identity_ok": queue_ok,
        "first_blocker": ({key: blocker[key] for key in ("stage", "status", "detail")}
                          if blocker else None),
        "missing_or_out_of_order": missing,
        "forbidden_stages": forbidden,
        "verdict": ("wrong_target_or_revision" if not target_ok or not revision_ok else
                    "unexpected_active_stage" if forbidden else
                    "owned_queue_and_buffer_observed" if complete else
                    "incomplete_or_blocked"),
        "limits": "Queue creation is stateful. No packet submission, parser consumption, physical write, protected-memory modification, or SPTM/TXM bypass is proved.",
    }


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
