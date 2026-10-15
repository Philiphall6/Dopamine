#!/usr/bin/env python3
"""Compare AGX translation and saved-state controls across GFX firmwares.

The comparison is static and diagnostic-only. It does not execute firmware,
submit GPU commands, or infer exploitability from the presence of a symbol.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib

from analyze_titan import analyze_gfx, hex_value


def parse_image(value: str) -> tuple[str, pathlib.Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("use LABEL=PATH")
    label, raw_path = value.split("=", 1)
    if not label or not raw_path:
        raise argparse.ArgumentTypeError("use a non-empty LABEL=PATH")
    path = pathlib.Path(raw_path).resolve()
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"GFX image not found: {path}")
    return label, path


def build_report(images: list[tuple[str, pathlib.Path]]) -> dict:
    records = []
    for label, path in images:
        result = analyze_gfx(path)
        for firmware_slice in result["slices"]:
            controls = firmware_slice["security_controls"]
            dispatch = firmware_slice["mmu_dispatch_contract"]
            classifications = collections.Counter(
                chain["classification"] for chain in controls["pacga_chains"]
            )
            records.append(
                {
                    "label": label,
                    "path": str(path),
                    "slice": firmware_slice["name"],
                    "legacy_titan_status": firmware_slice["status"],
                    "adapted_static_status": firmware_slice["adapted_status"],
                    "ttbr0_writes": [
                        item
                        for item in controls["ttbr_writes"]
                        if item["register"] == "ttbr0_el1"
                    ],
                    "ttbr1_writes": [
                        item
                        for item in controls["ttbr_writes"]
                        if item["register"] == "ttbr1_el1"
                    ],
                    "pacga_chains": controls["pacga_chains"],
                    "pacga_classifications": dict(sorted(classifications.items())),
                    "eret_sites": controls["eret_sites"],
                    "security_symbols": firmware_slice["security_symbol_candidates"],
                    "mmu_dispatch_contract": dispatch,
                }
            )
    return {
        "schema_version": 1,
        "scope": "offline-static-gfx-security-controls",
        "limitations": (
            "Counts and local classifications do not establish reachability, an "
            "oracle, a mutable translation root, or a bypass."
        ),
        "records": records,
    }


def render_markdown(report: dict) -> str:
    lines = [
        "# Symmetric GFX security-control comparison",
        "",
        report["limitations"],
        "",
        "| Build label | Slice | Legacy Titan | Adapted static | TTBR0 writes | "
        "TTBR1 writes | PACGA chains | ERET | UPPL route | Auth boundary |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for record in report["records"]:
        lines.append(
            f"| `{record['label']}` | `{record['slice']}` | "
            f"**{record['legacy_titan_status']}** | "
            f"**{record['adapted_static_status']}** | "
            f"{len(record['ttbr0_writes'])} | {len(record['ttbr1_writes'])} | "
            f"{len(record['pacga_chains'])} | {len(record['eret_sites'])} | "
            f"{'yes' if record['mmu_dispatch_contract']['uppl']['status'] == 'PASS' else 'no'} | "
            f"`{record['mmu_dispatch_contract']['mapping']['authorization_boundary']}` |"
        )

    for record in report["records"]:
        lines.extend(
            [
                "",
                f"## `{record['label']}` / `{record['slice']}`",
                "",
                f"Source: `{record['path']}`",
                "",
                "### Translation roots",
                "",
                "| Register | Address | Source register |",
                "|---|---:|---|",
            ]
        )
        writes = record["ttbr0_writes"] + record["ttbr1_writes"]
        for write in sorted(writes, key=lambda item: item["address"]):
            lines.append(
                f"| `{write['register']}` | `{hex_value(write['address'])}` | "
                f"`{write['source_register']}` |"
            )
        if not writes:
            lines.append("| none observed | - | - |")

        lines.extend(
            [
                "",
                "### Authenticated saved state",
                "",
                "| PACGA chain | Length | Local classification |",
                "|---|---:|---|",
            ]
        )
        for chain in record["pacga_chains"]:
            lines.append(
                f"| `{hex_value(chain['start'])}`..`{hex_value(chain['end'])}` | "
                f"{chain['length']} | `{chain['classification']}` |"
            )
        if not record["pacga_chains"]:
            lines.append("| none observed | 0 | - |")

        symbols = ", ".join(
            f"`{name}`={hex_value(address)}"
            for name, address in record["security_symbols"].items()
        ) or "none observed"
        lines.extend(["", f"Named signing/MMU candidates: {symbols}."])

        dispatch = record["mmu_dispatch_contract"]
        lines.extend(
            [
                "",
                "### GXF/UPPL mapping boundary",
                "",
                "| Property | Static observation |",
                "|---|---|",
            ]
        )
        routes = dispatch["entry"].get("routes", [])
        route_text = ", ".join(
            (
                f"priority {route['priority']}: bit {route['bit']} -> "
                f"`{route['target_symbol'] or hex_value(route['target'])}`"
                if route["bit"] is not None
                else (
                    "direct -> `"
                    f"{route['target_symbol'] or hex_value(route['target'])}`"
                )
            )
            for route in routes
        ) or "not resolved"
        lines.append(f"| GXF entry routes | {route_text} |")
        uppl = dispatch["uppl"]
        if uppl["status"] == "PASS":
            lines.append(
                "| UPPL packet | `u32 index @ +0x0`, four `u64` arguments at "
                "`+0x8..+0x20`, authenticated `BRAAZ` |"
            )
            lines.append(
                f"| UPPL table | `{uppl['table_status']}`; packaged count="
                f"`{hex_value(uppl['static_handler_count'])}`, pointer="
                f"`{hex_value(uppl['static_handler_table'])}` |"
            )
            errors = uppl.get("error_returns", {})
            lines.append(
                "| UPPL rejects | index out of bounds="
                f"`{hex_value(errors.get('index_out_of_bounds'))}`; null handler="
                f"`{hex_value(errors.get('null_handler'))}` |"
            )
        else:
            lines.append("| UPPL packet | not present |")
            lines.append("| UPPL table | not present |")
            lines.append("| UPPL rejects | not present |")
        mapping = dispatch["mapping"]
        lines.append(
            f"| Direct GXF range guard | "
            f"{'observed' if mapping['direct_gxf']['separate_ingress_guard_observed'] else 'not classified'} |"
        )
        lines.append(
            f"| Authorization boundary | `{mapping['authorization_boundary']}` |"
        )
        classes = ", ".join(
            f"`{hex_value(value)}`" for value in mapping["attribute_classes"]
        )
        lines.append(f"| Encoded attribute classes | {classes} |")
        context_guard = mapping["context_switch_guard"]
        lines.append(
            "| Context switch guard | "
            + (
                "state byte `+0x638`; authorization bit `x2[0]`"
                if context_guard["observed"]
                else "not observed"
            )
            + " |"
        )
        lines.append(f"| Interpretation | {mapping['interpretation']} |")

    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            "A newly present signing routine is not an oracle unless its signed values, "
            "modifier, key domain, output, and accepted destination are controllable. "
            "Likewise, an MMU mapping routine is not a bypass unless its caller and "
            "authorization boundary are independently established.",
            "The UPPL handler table is runtime-populated in 23A355. A zeroed "
            "packaged table prevents static assignment of an index to `map`, "
            "`unmap`, or `update_mapping`; this is recorded as an unresolved "
            "runtime authorization boundary, not filled in by inference.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image",
        action="append",
        required=True,
        type=parse_image,
        metavar="LABEL=PATH",
        help="GFX payload and its build label; repeat for every build",
    )
    parser.add_argument("--json-output", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    report = build_report(args.image)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(report, indent=2) + "\n")
    markdown = render_markdown(report)
    args.output.write_text(markdown)
    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
