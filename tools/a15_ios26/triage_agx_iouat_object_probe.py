#!/usr/bin/env python3
"""Triage the bounded AGXUATMux factory-object read-only device probe."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from triage_agx_metadata_probe import fields, load_events, numbered
from triage_agx_gart_state_probe import FORBIDDEN_PREFIXES, GART_VTABLE, REQUIRED as GART_REQUIRED


REVISION = "self-page-write-v1+agx-iouat-object-v1+rtkit-mmio-disabled-v1"
MUX_VTABLE = 0xFFFFFFF007B22AE0
FACTORY_VTABLE = 0xFFFFFFF007AED3A0
IOUAT_REQUIRED = (
    ("titan.agx-iouat-object", "START"),
    ("titan.agx-iouat-object.mode", "PASS"),
    ("titan.agx-iouat-object.initialized", "PASS"),
    ("titan.agx-iouat-object.mode-repeat", "PASS"),
    ("titan.agx-iouat-object.initialized-repeat", "PASS"),
    ("titan.agx-iouat-object.mode-gate", "PASS"),
    ("titan.agx-iouat-object.pointer", "PASS"),
    ("titan.agx-iouat-object.pointer-repeat", "PASS"),
    ("titan.agx-iouat-object.vtable", "PASS"),
    ("titan.agx-iouat-object.vtable-repeat", "PASS"),
    ("titan.agx-iouat-object.identity", "PASS"),
    ("titan.agx-iouat-object", "PASS"),
    ("titan.agx-iouat-object", "STOP"),
)
INSERT_AFTER = GART_REQUIRED.index(("titan.agx-gart-state", "PASS")) + 1
REQUIRED = (
    GART_REQUIRED[:INSERT_AFTER - 1]
    + (("titan.agx-gart-state.mux-identity", "PASS"),)
    + GART_REQUIRED[INSERT_AFTER - 1:INSERT_AFTER]
    + IOUAT_REQUIRED
    + GART_REQUIRED[INSERT_AFTER:]
    + (("probe.cleanup", "PASS"),)
)


def _identity_matches(run: list[dict], stage: str, expected: int) -> bool:
    event = next((item for item in run if (item["stage"], item["status"]) ==
                  (stage, "PASS")), None)
    return bool(event and numbered(event["detail"], "expected") == expected and
                event["detail"].split("vtable=", 1)[-1].split()[0] ==
                f"0x{expected:x}/0x{expected:x}")


def _detail(run: list[dict], stage: str, status: str = "PASS") -> str:
    item = next((event for event in run if (event["stage"], event["status"]) ==
                 (stage, status)), None)
    return item["detail"] if item else ""


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
    identities_ok = all((
        _identity_matches(run, "titan.agx-gart-state.identity", GART_VTABLE),
        _identity_matches(run, "titan.agx-gart-state.mux-identity", MUX_VTABLE),
        _identity_matches(run, "titan.agx-iouat-object.identity", FACTORY_VTABLE),
    ))
    mode_gate = _detail(run, "titan.agx-iouat-object.mode-gate")
    mode_ok = (
        numbered(_detail(run, "titan.agx-iouat-object.mode"), "value") == 1 and
        numbered(_detail(run, "titan.agx-iouat-object.mode-repeat"), "value") == 1 and
        numbered(_detail(run, "titan.agx-iouat-object.initialized"), "value") == 1 and
        numbered(_detail(run, "titan.agx-iouat-object.initialized-repeat"), "value") == 1 and
        "mode=1/1 initialized=1/1 expected=1/1" in mode_gate
    )
    gart = next((event for event in run if (event["stage"], event["status"]) ==
                 ("titan.agx-gart-state", "PASS")), None)
    iouat = next((event for event in run if (event["stage"], event["status"]) ==
                  ("titan.agx-iouat-object", "PASS")), None)
    gart_detail = gart["detail"].split(";", 1)[0] if gart else ""
    pointers = {
        "service": numbered(gart_detail, "service") if gart else None,
        "gart": numbered(gart_detail, "gart") if gart else None,
        "mux": numbered(gart_detail, "state") if gart else None,
        "factory_object": numbered(iouat["detail"], "object") if iouat else None,
    }
    pointer_links_ok = bool(
        iouat and
        numbered(_detail(run, "titan.agx-gart-state.identity"), "gart") == pointers["gart"] and
        numbered(_detail(run, "titan.agx-gart-state.mux-identity"), "state") == pointers["mux"] and
        numbered(_detail(run, "titan.agx-iouat-object.identity"), "object") == pointers["factory_object"] and
        numbered(iouat["detail"], "mux") == pointers["mux"]
    )
    repeat_reads_ok = all(
        expected is not None and numbered(_detail(run, stage), "value") == expected
        for stage, expected in (
            ("titan.agx-gart-state.gart", pointers["gart"]),
            ("titan.agx-gart-state.gart-repeat", pointers["gart"]),
            ("titan.agx-gart-state.state", pointers["mux"]),
            ("titan.agx-gart-state.state-repeat", pointers["mux"]),
            ("titan.agx-iouat-object.pointer", pointers["factory_object"]),
            ("titan.agx-iouat-object.pointer-repeat", pointers["factory_object"]),
        )
    )
    complete = (target_ok and revision_ok and not missing and not forbidden and
                blocker is None and identities_ok and mode_ok and all(pointers.values()) and
                pointer_links_ok and repeat_reads_ok and
                numbered(gart_detail, "state-vtable-unslid") == MUX_VTABLE and
                numbered(iouat["detail"], "factory-vtable-unslid") == FACTORY_VTABLE)
    return {
        "run_id": run_id,
        "checkpoint_count": len(run),
        "target_ok": target_ok,
        "revision_ok": revision_ok,
        "identities_ok": identities_ok,
        "mode_ok": mode_ok,
        "pointer_links_ok": pointer_links_ok,
        "repeat_reads_ok": repeat_reads_ok,
        "first_blocker": ({key: blocker[key] for key in ("stage", "status", "detail")}
                          if blocker else None),
        "missing_or_out_of_order": missing,
        "forbidden_stages": forbidden,
        "observed_pointers": pointers if complete else None,
        "verdict": ("wrong_target_or_revision" if not target_ok or not revision_ok else
                    "unexpected_active_stage" if forbidden else
                    "iouat_factory_object_observed" if complete else
                    "incomplete_or_blocked"),
        "limits": "Pointer and exact-vtable reads only. No mapping, GPU command, MMIO, IPC transfer, physical write, protected-memory change, or SPTM/TXM call is proved.",
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
