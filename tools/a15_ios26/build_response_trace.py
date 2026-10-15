#!/usr/bin/env python3
"""Build a provenance-aware diagnostic trace from existing analysis reports.

The trace never represents offline or read-only evidence as a live SPTM/TXM
response. Runtime-only stages remain blocked or not reached until an upstream
report can provide direct evidence for them.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return value


def has_items(value: Any) -> bool:
    return isinstance(value, (list, dict)) and bool(value)


def make_stage(
    stage_id: str,
    status: str,
    provenance: str,
    evidence: str,
) -> dict[str, str]:
    return {
        "id": stage_id,
        "status": status,
        "provenance": provenance,
        "evidence": evidence,
    }


def build_trace(
    titan: dict[str, Any],
    sptm_txm: dict[str, Any],
    device_diagnostic: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if titan.get("diagnostic_only") is not True:
        raise ValueError("Titan report is not marked diagnostic-only")
    if device_diagnostic is not None:
        if device_diagnostic.get("diagnostic_only") is not True:
            raise ValueError("Device report is not marked diagnostic-only")
        if device_diagnostic.get("asserts_live_sptm_txm_response") is not False:
            raise ValueError("Device report does not explicitly reject a live SPTM/TXM claim")

    live = titan.get("live_layout", {})
    kernel = titan.get("kernel", {})
    gfx = titan.get("gfx", {})
    txm = sptm_txm.get("txm", {})
    sptm = sptm_txm.get("sptm", {})
    sptm_kernel = sptm_txm.get("kernel", {})
    device_events = {
        event.get("checkpoint"): event
        for event in (device_diagnostic or {}).get("events", [])
        if isinstance(event, dict) and isinstance(event.get("checkpoint"), str)
    }
    eligible_counts = (device_diagnostic or {}).get("selector_counts", {}).get("eligible", {})
    kernel_metadata_count = eligible_counts.get("Kernel")
    ppl_metadata_count = eligible_counts.get("PPL")

    identity_ok = all(
        live.get(key) == expected
        for key, expected in {
            "device": "iPhone14,2",
            "soc": "A15",
            "ios": "26.0.1",
            "build": "23A355",
        }.items()
    )
    txm_static_ok = (
        isinstance(txm.get("imagebase"), int)
        and bool(txm.get("device_tree_trust_cache_range"))
        and has_items(txm.get("trustcache_root_candidates"))
        and has_items(txm.get("developer_mode_storage_candidates"))
    )
    sptm_static_ok = (
        isinstance(sptm.get("imagebase"), int)
        and has_items(sptm.get("papt_compressed_tables"))
        and bool(sptm_kernel.get("sptm_args"))
    )

    stages = [
        make_stage(
            "target.identity",
            "OBSERVED" if identity_ok else "INCOMPLETE",
            "bounded-live-manifest",
            "iPhone14,2 / A15 / iOS 26.0.1 / 23A355",
        ),
        make_stage(
            "titan.kernel_patchfinder",
            "STATIC_PASS" if kernel.get("adapted_status") == "PASS" else "INCOMPLETE",
            "offline-kernelcache",
            "adapted iOS 26 relationships",
        ),
        make_stage(
            "titan.gfx_patchfinder",
            "STATIC_PASS" if gfx.get("adapted_status") == "PASS" else "INCOMPLETE",
            "offline-gfx-firmware",
            "adapted GFX relationships",
        ),
        make_stage(
            "rtbuddy.layout",
            "OBSERVED" if live.get("layout_status") == "PASS" else "INCOMPLETE",
            "bounded-read-only-capture",
            "object chain and segment descriptor roles",
        ),
        make_stage(
            "iorvbar.mapping",
            "OBSERVED" if live.get("iorvbar_status") == "VALIDATED" else "INCOMPLETE",
            "bounded-read-only-capture",
            "existing IOMemoryMap metadata; address not dereferenced",
        ),
        make_stage(
            "txm.static_relationships",
            "STATIC_PASS" if txm_static_ok else "INCOMPLETE",
            "offline-txm-image",
            "trust-cache and developer-mode relationships",
        ),
        make_stage(
            "sptm.static_relationships",
            "STATIC_PASS" if sptm_static_ok else "INCOMPLETE",
            "offline-sptm-and-kernel-images",
            "PAPT and SPTM argument relationships",
        ),
        make_stage(
            "device.app_owned_vm",
            "OBSERVED"
            if device_events.get("runtime.app_owned_vm", {}).get("status") == "PASS"
            else "INCOMPLETE",
            "bounded-device-diagnostic",
            "app-owned allocation and deallocation only; no write",
        ),
        make_stage(
            "device.standard_iosurface",
            "OBSERVED"
            if device_events.get("runtime.standard_iosurface", {}).get("status") == "PASS"
            else "INCOMPLETE",
            "bounded-device-diagnostic",
            "ordinary private IOSurface lifecycle only",
        ),
        make_stage(
            "selector.kernel_metadata",
            "INCOMPLETE"
            if kernel_metadata_count is None
            else ("METADATA_ELIGIBLE" if kernel_metadata_count > 0 else "MISSING"),
            "packaged-framework-metadata",
            f"eligible={kernel_metadata_count}; runtime primitive not inferred",
        ),
        make_stage(
            "selector.ppl_metadata",
            "INCOMPLETE"
            if ppl_metadata_count is None
            else ("METADATA_ELIGIBLE" if ppl_metadata_count > 0 else "MISSING"),
            "packaged-framework-metadata",
            f"eligible={ppl_metadata_count}; metadata only",
        ),
        make_stage(
            "kernel.runtime_read_write",
            "MISSING",
            "chain-contract",
            "no target-compatible runtime primitive established",
        ),
        make_stage(
            "titan.command_buffers",
            "BLOCKED",
            "application-guard",
            "iOS 26 diagnostic guard returns before setup",
        ),
        make_stage(
            "titan.physical_write",
            "NOT_REACHED",
            "chain-contract",
            "physwritebuf was not published",
        ),
        make_stage(
            "sptm_txm.runtime_response",
            "NOT_REACHED",
            "chain-contract",
            "no live protected-component request was issued",
        ),
    ]

    first_metadata_blocker = (
        "selector.kernel_metadata"
        if kernel_metadata_count == 0
        else ("selector.ppl_metadata" if ppl_metadata_count == 0 else None)
    )
    first_runtime_blocker = (
        None
        if device_events.get("kernel.runtime_read_write", {}).get("status") == "PASS"
        else "kernel.runtime_read_write"
    )

    return {
        "schema": "dopamine.a15-ios26.response-trace.v2",
        "diagnostic_only": True,
        "asserts_live_sptm_txm_response": False,
        "first_metadata_blocker": first_metadata_blocker,
        "first_runtime_blocker": first_runtime_blocker,
        "protected_component_boundary": "NOT_REACHED",
        "target": {
            "device": live.get("device"),
            "soc": live.get("soc"),
            "ios": live.get("ios"),
            "build": live.get("build"),
        },
        "static_bases": {
            "txm": f"0x{txm['imagebase']:x}" if isinstance(txm.get("imagebase"), int) else None,
            "sptm": f"0x{sptm['imagebase']:x}" if isinstance(sptm.get("imagebase"), int) else None,
        },
        "txm_interface_model": {
            "provenance": "arXiv:2510.09272 sections 8.3-8.4 and cited XNU headers",
            "transport": [
                "txm_kernel_call",
                "txm_enter",
                "SPTM dispatch",
                "TXM dispatch table",
                "TXM handler",
            ],
            "request_fields": [
                "selector",
                "failure_code_silent",
                "failure_fatal",
                "failure_silent",
                "skip_logs",
                "num_input_args",
                "num_output_args",
            ],
            "response_fields": ["txm_ret", "num_return_words", "return_words"],
            "request_generated": False,
            "request_transmitted": False,
            "handler_dispatched": False,
            "response_received": False,
            "runtime_values": None,
            "runtime_values_status": "NOT_REACHED",
        },
        "source_end_to_end_status": titan.get("end_to_end_status"),
        "stages": stages,
    }


def render_markdown(trace: dict[str, Any]) -> str:
    target = trace["target"]
    lines = [
        "# A15 / iOS 26 Diagnostic Response Trace",
        "",
        (
            f"Target: `{target.get('device')}` / `{target.get('soc')}` / "
            f"iOS `{target.get('ios')}` (`{target.get('build')}`)"
        ),
        "",
        "This trace does not assert that a live SPTM/TXM request was issued.",
        "",
        (
            f"First metadata blocker: `{trace.get('first_metadata_blocker')}`. "
            f"First runtime blocker: `{trace.get('first_runtime_blocker')}`. "
            f"Protected-component boundary: `{trace.get('protected_component_boundary')}`."
        ),
        "",
        "## Published TXM call contract",
        "",
        "Transport: `txm_kernel_call -> txm_enter -> SPTM dispatch -> TXM dispatch table -> TXM handler`.",
        "The response fields are `txm_ret`, `num_return_words`, and `return_words`; runtime values are `NOT_REACHED`.",
        "",
        "| Stage | Status | Provenance | Evidence |",
        "|---|---|---|---|",
    ]
    for stage in trace["stages"]:
        lines.append(
            f"| `{stage['id']}` | **{stage['status']}** | "
            f"`{stage['provenance']}` | {stage['evidence']} |"
        )
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--titan-report", type=Path, required=True)
    parser.add_argument("--sptm-txm-report", type=Path, required=True)
    parser.add_argument("--device-diagnostic", type=Path)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    device_diagnostic = load_json(args.device_diagnostic) if args.device_diagnostic else None
    trace = build_trace(
        load_json(args.titan_report),
        load_json(args.sptm_txm_report),
        device_diagnostic,
    )
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(trace, indent=2) + "\n", encoding="utf-8")
    args.markdown_output.write_text(render_markdown(trace), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
