#!/usr/bin/env python3
"""Triage the bounded AGX service-to-GART read-only device probe."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from triage_agx_metadata_probe import fields, load_events, numbered


REVISION = "self-page-write-v1+agx-gart-state-v1+rtkit-mmio-disabled-v1"
GART_VTABLE = 0xFFFFFFF007B1C4D8
REQUIRED = (
    ("probe.entry", "START"),
    ("kernel.primitive", "PASS"),
    ("titan.target-gate", "PASS"),
    ("titan.kernel-patchfinder", "PASS"),
    ("titan.agx-map-metadata.identity", "PASS"),
    ("titan.agx-map-metadata.wrapper-vtable", "PASS"),
    ("titan.agx-map-metadata.instance-vtable", "PASS"),
    ("titan.agx-map-metadata", "PASS"),
    ("titan.agx-gart-state", "START"),
    ("titan.agx-gart-state.gart", "PASS"),
    ("titan.agx-gart-state.gart-repeat", "PASS"),
    ("titan.agx-gart-state.vtable", "PASS"),
    ("titan.agx-gart-state.vtable-repeat", "PASS"),
    ("titan.agx-gart-state.identity", "PASS"),
    ("titan.agx-gart-state.state", "PASS"),
    ("titan.agx-gart-state.state-repeat", "PASS"),
    ("titan.agx-gart-state.state-vtable", "PASS"),
    ("titan.agx-gart-state.state-vtable-repeat", "PASS"),
    ("titan.agx-gart-state", "PASS"),
    ("titan.agx-gart-state", "STOP"),
    ("titan.agx-map-metadata", "STOP"),
)
FORBIDDEN_PREFIXES = (
    "titan.iorvbar", "titan.rtkit-metadata", "titan.command-buffers",
    "titan.ipc-census", "titan.agx-uat-mode", "titan.self-gpu",
)


def triage(events: list[dict], run_id: str) -> dict:
    run = [event for event in events if event["run_id"] == run_id]
    if not run or run_id == "unknown":
        raise ValueError("requested run_id is absent or unattributable")
    sequence = [(event["stage"], event["status"]) for event in run]
    entry = next((event for event in run if (event["stage"], event["status"]) ==
                  ("probe.entry", "START")), None)
    entry_fields = fields(entry["detail"]) if entry else {}
    target_ok = (entry_fields.get("target") == "iPhone14,2" and
                 entry_fields.get("build") == "23A355")
    revision_ok = entry_fields.get("revision") == REVISION
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
                        if event["stage"].startswith(FORBIDDEN_PREFIXES)})
    blocker = next((event for event in run if event["status"] in
                    {"FAIL", "BLOCKED", "REJECTED"} and
                    not event["stage"].startswith("hypervisor.") and
                    event["stage"] != "titan.run"), None)
    identity = next((event for event in run if (event["stage"], event["status"]) ==
                     ("titan.agx-gart-state.identity", "PASS")), None)
    summary = next((event for event in run if (event["stage"], event["status"]) ==
                    ("titan.agx-gart-state", "PASS")), None)
    identity_ok = (identity is not None and
                   numbered(identity["detail"], "expected") == GART_VTABLE and
                   identity["detail"].split("vtable=", 1)[-1].split()[0] ==
                   f"0x{GART_VTABLE:x}/0x{GART_VTABLE:x}")
    summary_fields = summary["detail"].split(";", 1)[0] if summary else ""
    values = {key: numbered(summary_fields, key) if summary else None
              for key in ("service", "gart", "state", "state-vtable-unslid")}
    pointers_ok = all(value is not None and value != 0 for value in values.values())
    complete = (target_ok and revision_ok and not missing and not forbidden and
                blocker is None and identity_ok and pointers_ok)
    return {
        "run_id": run_id,
        "checkpoint_count": len(run),
        "target_ok": target_ok,
        "revision_ok": revision_ok,
        "gart_identity_ok": identity_ok,
        "first_blocker": ({key: blocker[key] for key in ("stage", "status", "detail")}
                          if blocker else None),
        "missing_or_out_of_order": missing,
        "forbidden_stages": forbidden,
        "observed_pointers": values if complete else None,
        "verdict": ("wrong_target_or_revision" if not target_ok or not revision_ok else
                    "unexpected_active_stage" if forbidden else
                    "gart_state_pointer_chain_observed" if complete else
                    "incomplete_or_blocked"),
        "limits": "Pointer and vtable reads only. State type and factory field remain unconfirmed; no map call, GPU command, MMIO, IPC transfer, physical write, protected-memory change, or SPTM/TXM call is proved.",
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
