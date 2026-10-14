#!/usr/bin/env python3
"""Check that the A15/iOS 26.0.1 integration stays diagnostic-only."""

from __future__ import annotations

import json
import pathlib
import plistlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGET_VERSION = (26, 0, 1)


def version_tuple(value: str) -> tuple[int, int, int]:
    parts = [int(part) for part in value.split(".")]
    return tuple((parts + [0, 0, 0])[:3])


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def main() -> int:
    info_path = ROOT / "Application/Dopamine/Exploits/Titan/Info.plist"
    with info_path.open("rb") as stream:
        info = plistlib.load(stream)

    for flavor_name, flavor in info["DPExploitFlavors"].items():
        if "A15" not in flavor.get("DPSupportedDevices", []):
            continue
        for supported_range in flavor.get("DPSupportedRanges", []):
            start = version_tuple(supported_range["Start"])
            end = version_tuple(supported_range["End"])
            require(
                not (start <= TARGET_VERSION <= end),
                f"Titan flavor {flavor_name!r} enables A15/iOS 26.0.1",
            )

    environment = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text()
    project = (ROOT / "Application/Dopamine.xcodeproj/project.pbxproj").read_text()
    settings = (ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m").read_text()
    titan = (ROOT / "Application/Dopamine/Exploits/Titan/exploit/titan.m").read_text()
    kernel_patchfinder = (
        ROOT / "Application/Dopamine/Exploits/Titan/exploit/kernel_patchfinder.c"
    ).read_text()
    gfx_patchfinder = (
        ROOT / "Application/Dopamine/Exploits/Titan/exploit/gfx_patchfinder.c"
    ).read_text()
    titan_analyzer = (ROOT / "tools/a15_ios26/analyze_titan.py").read_text()
    response_trace = (ROOT / "tools/a15_ios26/build_response_trace.py").read_text()
    live_layout = json.loads(
        (ROOT / "tools/a15_ios26/live-layout-iphone14_2-23A355.json").read_text()
    )
    report = (ROOT / "docs/A15_IOS_26_0_1_RESEARCH.md").read_text()

    for marker in (
        "CPUFAMILY_ARM_BLIZZARD_AVALANCHE",
        'strcmp(deviceInfo.machine, "iPhone14,2") == 0',
        'isEqualToString:@"26.0.1"',
    ):
        require(marker in environment, f"missing exact target marker: {marker}")

    unsupported_guard = re.compile(
        r"- \(BOOL\)isSupported\s*\{.*?"
        r"isA15IOS2601ResearchTarget.*?return NO;",
        re.DOTALL,
    )
    require(unsupported_guard.search(environment) is not None, "missing unsupported guard")
    titan_deployment_targets = re.findall(
        r'INFOPLIST_FILE = "\$\(SRCROOT\)/Dopamine/Exploits/Titan/Info\.plist";'
        r".{0,500}?IPHONEOS_DEPLOYMENT_TARGET = ([0-9.]+);",
        project,
        re.DOTALL,
    )
    require(
        titan_deployment_targets == ["16.1", "16.1"],
        "Titan framework deployment targets do not match its supported range",
    )
    require("Research_Stage_OSDictionary" in settings, "missing OSDictionary status")
    require("Research_Stage_IORVBAR" in settings, "missing in-app research status")
    require(
        "MAPPING_VALIDATED_TITAN_EXECUTION_BLOCKED" in report,
        "report does not record the current diagnostic blocker",
    )
    for marker in ("0xfffffff007aaaf58", "dictionary=+0x20", "16-byte"):
        require(marker in report, f"report is missing OSDictionary evidence: {marker}")
    require("fAddress=+0x28" in report, "report is missing the validated map offset")
    segment_ranges = live_layout["io_registry"]["segment_properties"]["segment_ranges"]
    require(
        segment_ranges.get("field_roles")
        == {
            "field_00": "physical",
            "field_08": "virtual",
            "field_10": "remap",
            "field_18_low32": "length",
            "field_18_high32": "flags",
        },
        "live-layout manifest is missing resolved RTBuddy segment semantics",
    )
    require(
        "offline or VM scan cannot recover `gfx_data_pa` or `gfx_ttbr_pa`" in report,
        "report does not distinguish static RTKit markers from live state",
    )

    for localization in ("en", "fr"):
        strings = (ROOT / f"Application/Dopamine/{localization}.lproj/Localizable.strings").read_text()
        for key in ("Research_Target_Header", "Research_Stage_OSDictionary", "Research_Stage_IORVBAR"):
            require(strings.count(f'"{key}" =') == 1, f"{localization} localization is missing {key}")

    titan_run = titan.find("int titan_run")
    guard = titan.find("if (!gTitanContext.iorvbar_mapping_validated)", titan_run)
    queue_setup = titan.find("titan_setup_command_buffers()", titan_run)
    require(guard >= 0, "Titan iOS 26 guard is missing")
    require(queue_setup >= 0 and guard < queue_setup, "Titan guard no longer precedes command-buffer setup")
    require(
        "fAddress == 0 || fAddress > 0x100" in kernel_patchfinder,
        "legacy IOMemoryMap offset candidates are no longer range-checked",
    )
    require(
        "failed to find unique iOS 26 IOMemoryMap address accessor"
        in kernel_patchfinder,
        "target-specific IOMemoryMap address accessor fallback is missing",
    )
    require(
        "kpf_fileset_entry_patchfind_text_unique" in kernel_patchfinder,
        "iOS 26 AGX anchors are no longer required to be unique",
    )
    require(
        "AGX fence layout disagrees with processKernelCommand" in kernel_patchfinder,
        "iOS 26 AGX cross-method layout validation is missing",
    )
    require(
        "gfx_patchfind_unique(ios26_insns, ios26_masks, 11)" in gfx_patchfinder,
        "iOS 26 GFX hibernation ABI anchor is not unique or complete",
    )
    require(
        "analyze_static_rtkit_marker" in titan_analyzer
        and "EXECUTABLE_IMAGE_OCCURRENCES_ONLY" in titan_analyzer
        and '"runtime_values_available": False' in titan_analyzer,
        "offline analyzer no longer scopes static RTKit markers away from live state",
    )
    require(
        '"asserts_live_sptm_txm_response": False' in response_trace
        and '"runtime_values": None' in response_trace
        and '"runtime_values_status": "NOT_REACHED"' in response_trace,
        "response trace can no longer distinguish its model from a live SPTM/TXM response",
    )
    require(
        "txm_kernel_call" in response_trace
        and "txm_enter" in response_trace
        and "txm_ret" in response_trace
        and "num_return_words" in response_trace,
        "response trace is missing the published TXM call contract",
    )

    print(
        "OK: A15/iOS 26.0.1 remains diagnostic-only; "
        "IORVBAR mapping validated and Titan execution blocked"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
