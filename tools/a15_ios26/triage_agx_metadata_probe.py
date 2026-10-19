#!/usr/bin/env python3
"""Triage one exact-target AGX metadata run from Dopamine's persistent JSONL."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SCHEMA = "dopamine.a15-ios26.active-probe.v1"
REVISION = "agx-service-census-v1+agx-map-metadata-v1+rtkit-mmio-disabled-v1"
MODE_REVISION = "self-page-write-v1+agx-uat-mode-v1+rtkit-mmio-disabled-v1"
REVISIONS = {
    REVISION,
    "self-page-write-v1+agx-map-metadata-v1+rtkit-mmio-disabled-v1",
    MODE_REVISION,
}
FIELD_STAGES = (
    "service-map-address",
    "config-mode",
    "config-gpu-index",
    "config-fender-index",
    "config-flags",
    "config-gpu-physical",
    "config-fender-physical",
    "config-gpu-map",
    "config-fender-map",
)
UNEXPECTED_PREFIXES = (
    "titan.self-gpu",
    "titan.iorvbar",
    "titan.rtkit-metadata",
    "titan.command-buffers",
    "titan.ipc-census",
)


def load_events(raw: bytes) -> list[dict]:
    events = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid JSONL at line {line_number}: {error.msg}") from error
        if not isinstance(event, dict) or event.get("schema") != SCHEMA or any(
            not isinstance(event.get(key), str) or not event[key]
            for key in ("run_id", "stage", "status")
        ) or not isinstance(event.get("detail"), str):
            raise ValueError(f"invalid checkpoint schema at line {line_number}")
        events.append(event)
    if not events:
        raise ValueError("JSONL contains no checkpoints")
    return events


def fields(detail: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in detail.split() if "=" in token)


def numbered(detail: str, key: str) -> int | None:
    try:
        return int(fields(detail)[key], 0)
    except (KeyError, ValueError):
        return None


def triage(events: list[dict], run_id: str) -> dict:
    run = [event for event in events if event["run_id"] == run_id]
    if not run or run_id == "unknown":
        raise ValueError("requested run_id is absent or unattributable")

    entry = next((event for event in run if event["stage"] == "probe.entry" and
                  event["status"] == "START"), None)
    entry_fields = fields(entry["detail"]) if entry else {}
    target_ok = (entry_fields.get("target") == "iPhone14,2" and
                 entry_fields.get("build") == "23A355")
    revision_ok = entry_fields.get("revision") in REVISIONS
    mode_revision = entry_fields.get("revision") == MODE_REVISION

    required = [
        ("probe.entry", "START"),
        ("agx.registry", "SUMMARY"),
        ("agx.registry", "STOP"),
        ("xpf.gather", "PASS"),
        ("kernel.primitive", "PASS"),
        ("titan.target-gate", "PASS"),
        ("titan.kernel-patchfinder", "PASS"),
        ("titan.agx-map-metadata", "START"),
        ("titan.agx-map-metadata.identity", "PASS"),
        ("titan.agx-map-metadata.wrapper-vtable", "PASS"),
        ("titan.agx-map-metadata.instance-vtable", "PASS"),
    ]
    for suffix in FIELD_STAGES:
        required.append((f"titan.agx-map-metadata.{suffix}", "PASS"))
    for suffix in FIELD_STAGES:
        required.append((f"titan.agx-map-metadata.{suffix}-repeat", "PASS"))
    required += [
        ("titan.agx-map-metadata.stability", "PASS"),
        ("titan.agx-map-metadata", "PASS"),
    ]
    if mode_revision:
        required += [
            ("titan.agx-uat-mode", "START"),
            ("titan.agx-uat-mode.source", "PASS"),
            ("titan.agx-uat-mode.global", "PASS"),
            ("titan.agx-uat-mode.initialized", "PASS"),
            ("titan.agx-uat-mode.source-repeat", "PASS"),
            ("titan.agx-uat-mode.global-repeat", "PASS"),
            ("titan.agx-uat-mode.initialized-repeat", "PASS"),
            ("titan.agx-uat-mode.stability", "PASS"),
            ("titan.agx-uat-mode", "PASS"),
            ("titan.agx-uat-mode", "STOP"),
        ]
    required.append(("titan.agx-map-metadata", "STOP"))
    missing = []
    position = 0
    for stage, status in required:
        while position < len(run) and (run[position]["stage"], run[position]["status"]) != (stage, status):
            position += 1
        if position == len(run):
            missing.append(f"{stage}:{status}")
            break
        position += 1
    if missing:
        present = {(event["stage"], event["status"]) for event in run}
        missing = [f"{stage}:{status}" for stage, status in required if (stage, status) not in present]
        if not missing:
            missing = ["checkpoint order invalid"]

    forbidden = sorted({event["stage"] for event in run
                        if revision_ok and event["stage"].startswith(UNEXPECTED_PREFIXES)})
    blocker = next((event for event in run if event["status"] in {"FAIL", "BLOCKED", "REJECTED"}
                    and not event["stage"].startswith("hypervisor.")
                    and event["stage"] != "titan.run"), None)
    if blocker is None and ("titan.agx-map-metadata", "STOP") not in {
        (event["stage"], event["status"]) for event in run
    }:
        blocker = next((event for event in run if event["stage"] == "titan.run" and
                        event["status"] == "FAIL"), None)
    registry = next((event for event in run if event["stage"] == "agx.registry" and
                     event["status"] == "SUMMARY"), None)
    registry_fields = fields(registry["detail"]) if registry else {}
    registry_ok = (registry_fields.get("complete") == "yes" and
                   registry_fields.get("iterator-valid") == "yes" and
                   numbered(registry["detail"], "base") is not None and
                   numbered(registry["detail"], "base") > 0 and
                   numbered(registry["detail"], "class-failures") == 0) if registry else False

    summary = next((event for event in run if event["stage"] == "titan.agx-map-metadata" and
                    event["status"] == "PASS"), None)
    detail = summary["detail"] if summary else ""
    service_id = numbered(detail, "registry-id")
    provider_confirmed = any(
        event["stage"] == "agx.registry-match" and event["status"] == "INFO" and
        fields(event["detail"]).get("class") == "AGXAcceleratorG14P" and
        fields(event["detail"]).get("parent-name") == "sgx" and
        service_id is not None and numbered(event["detail"], "id") == service_id
        for event in run
    )
    values = {key: numbered(detail, key) for key in (
        "service+0x310", "mode", "gpu-index", "fender-index", "flags",
        "gpu-physical", "fender-physical", "gpu-map", "fender-map",
    )}
    wrapper = next((event for event in run if event["stage"] == "titan.agx-map-metadata.wrapper-vtable" and
                    event["status"] == "PASS"), None)
    instance = next((event for event in run if event["stage"] == "titan.agx-map-metadata.instance-vtable" and
                     event["status"] == "PASS"), None)
    identity_ok = (wrapper is not None and instance is not None and
                   numbered(wrapper["detail"], "unslid") == 0xFFFFFFF007ABCB18 and
                   numbered(instance["detail"], "unslid") == 0xFFFFFFF007B1E0D0)
    mode_reads = {
        suffix: next((event for event in run if event["stage"] == f"titan.agx-uat-mode.{suffix}"
                      and event["status"] == "PASS"), None)
        for suffix in ("source", "global", "initialized", "source-repeat",
                       "global-repeat", "initialized-repeat")
    }
    mode_values = {suffix: numbered(event["detail"], "value") if event else None
                   for suffix, event in mode_reads.items()}
    mode_summary = next((event for event in run if event["stage"] == "titan.agx-uat-mode"
                         and event["status"] == "PASS"), None)
    mode = mode_values["global"]
    dispatch_bit_stable = (mode_revision and mode in (0, 1) and
                           mode == mode_values["global-repeat"] and
                           mode_values["initialized"] == 1 and
                           mode_values["initialized-repeat"] == 1)
    mode_ok = (not mode_revision or
               (mode is not None and mode in (0, 1) and
                mode_values["initialized"] == 1 and
                mode_values["initialized-repeat"] == 1 and
                mode_values["source"] is not None and
                mode_values["source"] == mode_values["source-repeat"] and
                mode == mode_values["global-repeat"] and
                mode == (mode_values["source"] & 1) and
                mode_summary is not None and
                fields(mode_summary["detail"]).get("route") ==
                ("IOUAT" if mode else "AGXUAT") and
                numbered(mode_summary["detail"], "global") == mode and
                numbered(mode_summary["detail"], "initialized") == 1 and
                numbered(mode_summary["detail"], "source-bit") == mode))
    complete = (target_ok and revision_ok and not missing and not forbidden and
                not blocker and registry_ok and identity_ok and mode_ok and
                service_id is not None and
                all(value is not None for value in values.values()))
    static_match = (complete and values["mode"] == 2 and values["gpu-index"] == 0 and
                    values["fender-index"] == 1 and values["flags"] is not None and
                    (values["flags"] & 1) != 0 and values["gpu-physical"] == 0x204000000 and
                    values["fender-physical"] == 0x204D00000)
    map_nonzero = (complete and values["service+0x310"] not in (None, 0) and
                   values["gpu-map"] not in (None, 0))

    return {
        "run_id": run_id,
        "checkpoint_count": len(run),
        "target_ok": target_ok,
        "revision_ok": revision_ok,
        "registry_ok": registry_ok,
        "identity_ok": identity_ok,
        "mode_link_ok": mode_ok if mode_revision else None,
        "observed_dispatch_bit": ({"global": mode,
                                   "conditional_route": "IOUAT" if mode else "AGXUAT",
                                   "initialized": 1,
                                   "source_byte": mode_values["source"],
                                   "instance_link_proven": bool(mode_ok)}
                                  if target_ok and revision_ok and identity_ok and
                                  dispatch_bit_stable else None),
        "uat_dispatch": ({"route": "IOUAT" if mode else "AGXUAT", "global": mode,
                          "source_byte": mode_values["source"]}
                         if complete and mode_revision else None),
        "provider_confirmed": provider_confirmed,
        "first_blocker": ({key: blocker[key] for key in ("stage", "status", "detail")}
                          if blocker else None),
        "missing_or_out_of_order": missing,
        "forbidden_stages": forbidden,
        "verdict": ("wrong_target_or_revision" if not target_ok or not revision_ok else
                    "unexpected_active_stage" if forbidden else
                    "incomplete_or_blocked" if not complete else
                    "iouat_dispatch_bit_selected" if mode_revision and mode == 1 else
                    "agxuat_dispatch_bit_selected" if mode_revision and mode == 0 else
                    "metadata_matches_static_candidate" if static_match and map_nonzero and provider_confirmed else
                    "metadata_complete_unconfirmed_map_or_provider"),
        "map_metadata": values if complete else None,
        "limits": ("The dispatch bit selects a static map branch, not proof of an IOUAT request, SPTM call, physical write, or protected-memory change. The separate self-page write proves a kernel-virtual alias write only. GFX MMIO remains disabled."
                   if mode_revision else
                   "These metadata checkpoints alone cannot prove MMIO access, a controlled kernel write, a physical write, protected-memory modification, or selection of the IOUAT dispatch branch; ProbeConfig mode is not the AGX dispatch bit."),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path)
    parser.add_argument("--run-id", help="Select a run; default is the last run in file order")
    args = parser.parse_args()
    raw = args.jsonl.read_bytes()
    events = load_events(raw)
    run_id = args.run_id or events[-1]["run_id"]
    report = triage(events, run_id)
    report["source_sha256"] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
