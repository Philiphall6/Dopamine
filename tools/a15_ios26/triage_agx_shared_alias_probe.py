#!/usr/bin/env python3
"""Triage one bounded own-client AGX shared-buffer alias probe."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from triage_agx_iouat_object_probe import REQUIRED as OBJECT_REQUIRED
from triage_agx_metadata_probe import fields, load_events, numbered
from triage_agx_gart_state_probe import FORBIDDEN_PREFIXES


REVISION = "self-page-write-v1+agx-shared-alias-v1+rtkit-mmio-disabled-v1"
SHARED_REQUIRED = (
    ("titan.shared-alias", "START"),
    ("titan.shared-alias.service", "PASS"),
    ("titan.shared-alias.open", "START"),
    ("titan.shared-alias.open", "PASS"),
    ("titan.shared-alias.port-bits", "PASS"),
    ("titan.shared-alias.wrapper", "PASS"),
    ("titan.shared-alias.wrapper-vtable-identity", "PASS"),
    ("titan.shared-alias.client", "PASS"),
    ("titan.shared-alias.client-identity", "PASS"),
    ("titan.shared-alias.create", "START"),
    ("titan.shared-alias.create", "PASS"),
    ("titan.shared-alias.user-map", "PASS"),
    ("titan.shared-alias.table", "PASS"),
    ("titan.shared-alias.array", "PASS"),
    ("titan.shared-alias.array-vtable-identity", "PASS"),
    ("titan.shared-alias.array-count", "PASS"),
    ("titan.shared-alias.array-slots", "PASS"),
    ("titan.shared-alias.buffer", "PASS"),
    ("titan.shared-alias.buffer-repeat", "PASS"),
    ("titan.shared-alias.buffer-vtable-identity", "PASS"),
    ("titan.shared-alias.descriptor", "PASS"),
    ("titan.shared-alias.backing", "PASS"),
    ("titan.shared-alias.descriptor-vtable-identity", "PASS"),
    ("titan.shared-alias.user-map-object", "PASS"),
    ("titan.shared-alias.map-vtable-identity", "PASS"),
    ("titan.shared-alias.map-address", "PASS"),
    ("titan.shared-alias.map-length", "PASS"),
    ("titan.shared-alias.registry", "PASS"),
    ("titan.shared-alias.alias-read", "START"),
    ("titan.shared-alias.alias-read", "PASS"),
    ("titan.shared-alias.user-write", "START"),
    ("titan.shared-alias.user-write", "PASS"),
    ("titan.shared-alias.restore", "PASS"),
    ("titan.shared-alias.redirect", "PASS"),
    ("titan.shared-alias", "PASS"),
)
INSERT_AFTER = OBJECT_REQUIRED.index(("titan.agx-iouat-object", "STOP")) + 1
REQUIRED = (OBJECT_REQUIRED[:INSERT_AFTER] + SHARED_REQUIRED +
            OBJECT_REQUIRED[INSERT_AFTER:])
FORBIDDEN = FORBIDDEN_PREFIXES + (
    "titan.rtkit-parse", "titan.sptm", "titan.gfx", "titan.physwrite",
    "titan.physical-write",
)


def detail(run: list[dict], stage: str, status: str = "PASS") -> str:
    event = next((item for item in run if (item["stage"], item["status"]) ==
                  (stage, status)), None)
    return event["detail"] if event else ""


def triage(events: list[dict], run_id: str) -> dict:
    run = [event for event in events if event["run_id"] == run_id]
    if not run or run_id == "unknown":
        raise ValueError("requested run_id is absent or unattributable")
    sequence = [(event["stage"], event["status"]) for event in run]
    entry = fields(detail(run, "probe.entry", "START"))
    target_ok = entry.get("target") == "iPhone14,2" and entry.get("build") == "23A355"
    revision_ok = entry.get("revision") == REVISION
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

    created = detail(run, "titan.shared-alias.create")
    registry = detail(run, "titan.shared-alias.registry")
    returned_address = numbered(created, "address")
    returned_id = numbered(created, "id")
    buffer = numbered(detail(run, "titan.shared-alias.buffer"), "value")
    descriptor = numbered(detail(run, "titan.shared-alias.descriptor"), "value")
    map_object = numbered(detail(run, "titan.shared-alias.user-map-object"), "value")
    identity_ok = bool(
        numbered(created, "kr") == 0 and
        numbered(created, "out-size") == 0x10 and
        numbered(created, "size") == 0x4000 and
        returned_address and returned_id and
        returned_id == numbered(registry, "id") and
        buffer == numbered(detail(run, "titan.shared-alias.buffer-repeat"), "value") ==
                  numbered(registry, "buffer") and
        descriptor == numbered(detail(run, "titan.shared-alias.backing"), "value") ==
                      numbered(registry, "descriptor") and
        map_object == numbered(registry, "map") and
        returned_address == numbered(detail(run, "titan.shared-alias.map-address"), "value") and
        (numbered(detail(run, "titan.shared-alias.map-length"), "value") or 0) >= 0x4000
    )
    write = detail(run, "titan.shared-alias.user-write")
    alias = detail(run, "titan.shared-alias.alias-read")
    byte_alias_ok = (
        numbered(alias, "bytes") == 0x20 and
        numbered(alias, "physical") is not None and
        numbered(alias, "kernel-alias") is not None and
        numbered(write, "kernel-read") == 0 and
        fields(write).get("dual-alias-match") == "yes"
    )
    restored = bool(detail(run, "titan.shared-alias.restore") or
                    ("titan.shared-alias.restore", "PASS") in sequence)
    redirected = ("titan.shared-alias.redirect", "PASS") in sequence
    complete = (target_ok and revision_ok and not missing and not forbidden and
                blocker is None and identity_ok and byte_alias_ok and
                restored and redirected)
    return {
        "run_id": run_id,
        "checkpoint_count": len(run),
        "target_ok": target_ok,
        "revision_ok": revision_ok,
        "buffer_identity_ok": identity_ok,
        "byte_alias_ok": byte_alias_ok,
        "restored": restored,
        "redirected": redirected,
        "first_blocker": ({key: blocker[key] for key in ("stage", "status", "detail")}
                          if blocker else None),
        "missing_or_out_of_order": missing,
        "forbidden_stages": forbidden,
        "verdict": ("wrong_target_or_revision" if not target_ok or not revision_ok else
                    "unexpected_active_stage" if forbidden else
                    "registered_user_dram_alias_observed" if complete else
                    "incomplete_or_blocked"),
        "limits": "This is a user write to an app-mapped buffer, observed through a kernel DRAM alias. Parser acceptance, physical writing, protected-memory modification, and SPTM/TXM remain unproved.",
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
