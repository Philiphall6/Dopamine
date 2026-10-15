#!/usr/bin/env python3
"""Check the exact-target A15/iOS 26.0.1 active Titan probe integration."""

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
        exact_includes = [
            entry
            for entry in flavor.get("DPSupportInclude", [])
            if entry.get("Devices") == ["iPhone14,2"]
            and "23A355" in entry.get("Builds", [])
        ]
        require(
            len(exact_includes) == 1,
            f"Titan flavor {flavor_name!r} is missing the exact iPhone14,2/23A355 include",
        )
        require(
            all(
                "23A355" not in entry.get("Builds", [])
                or entry.get("Devices") == ["iPhone14,2"]
                for entry in flavor.get("DPSupportInclude", [])
            ),
            "build 23A355 is enabled outside the exact iPhone14,2 rule",
        )

    environment = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text()
    project = (ROOT / "Application/Dopamine.xcodeproj/project.pbxproj").read_text()
    settings = (ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m").read_text()
    main_view = (ROOT / "Application/Dopamine/UI/DOMainViewController.m").read_text()
    jailbreaker = (ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m").read_text()
    titan = (ROOT / "Application/Dopamine/Exploits/Titan/exploit/titan.m").read_text()
    clearsword_krw = (
        ROOT / "Application/Dopamine/Exploits/ClearSword/exploit/krw.c"
    ).read_text()
    kernel_patchfinder = (
        ROOT / "Application/Dopamine/Exploits/Titan/exploit/kernel_patchfinder.c"
    ).read_text()
    gfx_patchfinder = (
        ROOT / "Application/Dopamine/Exploits/Titan/exploit/gfx_patchfinder.c"
    ).read_text()
    titan_analyzer = (ROOT / "tools/a15_ios26/analyze_titan.py").read_text()
    response_trace = (ROOT / "tools/a15_ios26/build_response_trace.py").read_text()
    macho_preflight = (ROOT / "tools/a15_ios26/analyze_macho_preflight.py").read_text()
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
    require("Research_Button_Run" in main_view, "missing research diagnostic button")
    require(
        "[self startA15ActiveTitanProbe]" in main_view,
        "exact research target does not route to the active Titan probe",
    )
    active_start = jailbreaker.find("- (void)runA15IOS2601ActiveTitanProbeWithError")
    active_end = jailbreaker.find("- (NSError *)buildPhysRWPrimitive", active_start)
    require(active_start >= 0 and active_end > active_start, "missing bounded active probe")
    active_body = jailbreaker[active_start:active_end]
    for marker in (
        "isA15IOS2601ResearchTarget",
        "A15_ACTIVE_PROBE_RUN_ID",
        'A15ActiveProbeCheckpoint(@"kernel.run"',
        'A15ActiveProbeCheckpoint(@"kernel.primitive"',
        'A15ActiveProbeCheckpoint(@"titan.run"',
        'A15ActiveProbeCheckpoint(@"titan.physwrite.publish"',
        "Documents/a15-ios26-active-probe.jsonl",
        "gPrimitives.physwritebuf",
    ):
        require(marker in active_body or marker in jailbreaker, f"active probe is missing marker: {marker}")
    for forbidden in (
        "buildPhysRWPrimitive",
        "elevatePrivileges",
        "prepareBootstrap",
        "loadBasebinTrustcache",
        "ensureJailbreakRootExists",
    ):
        require(forbidden not in active_body, f"active probe crosses bounded stop into {forbidden}")
    for marker in (
        "gPrimitives.krwMinSafeReadSize",
        "fieldEnd > readSize ? fieldEnd - readSize : 0",
        "kreadbuf(object + readOffset, readBuffer, readSize)",
        "UNSIGN_PTR(*(uint64_t *)&readBuffer[offset - readOffset])",
    ):
        require(marker in titan, f"Titan tail-aligned kernel read is missing marker: {marker}")
    diagnostic_start = main_view.find("- (void)startResearchDiagnostics")
    diagnostic_end = main_view.find("- (void)viewWillAppear", diagnostic_start)
    require(
        diagnostic_start >= 0 and diagnostic_end > diagnostic_start,
        "missing bounded research diagnostic implementation",
    )
    diagnostic_body = main_view[diagnostic_start:diagnostic_end]
    for forbidden in (
        "DOJailbreaker",
        "startJailbreak",
        "titan_run",
        "titan_setup_command_buffers",
        "gfx_write",
        "kwrite",
        "physwritebuf(",
        "gPrimitives.physwritebuf",
        "dlopen(",
        "exploit_init",
        "IOServiceOpen",
        "IOConnectCall",
        "accessibleKernelPath",
        "IOSurfacePrefetchPages(",
        "IOSurfaceGetBaseAddress(",
        "IOSurfaceCreateMachPort(",
        "kIOSurfaceMemoryRegion",
        "mach_make_memory_entry_64(",
        "mach_vm_map(",
        "vm_write(",
        "socket(",
        "pe_init(",
        "pe_v1(",
        "pread(",
        "pwrite(",
    ):
        require(
            forbidden not in diagnostic_body,
            f"research diagnostic unexpectedly references {forbidden}",
        )
    for marker in (
        '@"schema": @"dopamine.a15-ios26.device-diagnostic.v6"',
        '@"binary_preflight": binaryPreflight',
        '@"runtime_preflight": runtimePreflight',
        '@"standard_iosurface_preflight": standardIOSurfacePreflight',
        '@"scope": @"mach_task_self/app-owned-page-only"',
        '@"scope": @"standard-private-iosurface-only"',
        '@"lock_read_only": @YES',
        '@"lock_avoid_sync": @YES',
        'record(@"runtime.app_owned_vm"',
        'record(@"runtime.standard_iosurface"',
        'vm_allocate(mach_task_self()',
        'vm_deallocate(mach_task_self()',
        '@"memory_written": @NO',
        '@"base_address_accessed": @NO',
        '@"mach_port_created": @NO',
        '@"prefetch_called": @NO',
        '@"memory_region_requested": @NO',
        '@"iokit_called": @NO',
        '@"exploit_matrix": exploitMatrix',
        '@"jailbreak_dry_run": jailbreakDryRun',
        '@"mode": @"selection-and-precondition-trace-only"',
        '@"actual_entrypoint_called": @NO',
        '@"gather_system_information_called": @NO',
        '@"xpf_started": @NO',
        '@"image_download_attempted": @NO',
        '@"exploit_framework_loaded": @NO',
        '@"exploit_entrypoint_called": @NO',
        '@"kernel_primitive_created": @NO',
        '@"physrw_created": @NO',
        '@"privileges_modified": @NO',
        '@"bootstrap_modified": @NO',
        '@"protected_request_issued": @NO',
        '@"first_proven_blocker": firstProvenBlocker',
        '@"earliest_unexecuted_stage": @"gather_system_information"',
        'recordDryRun(@"gather_system_information"',
        'recordDryRun(@"kernel_selection"',
        'recordDryRun(@"ppl_selection"',
        'recordDryRun(@"exploit_load", @"NOT_EXECUTED"',
        'recordDryRun(@"exploit_run", @"NOT_EXECUTED"',
        'recordDryRun(@"privilege_elevation", @"NOT_REACHED"',
        'recordDryRun(@"protected_component", @"NOT_REACHED"',
        'record(@"selector.kernel"',
        'record(@"selector.pac"',
        'record(@"selector.ppl"',
        'record(@"selector.overall"',
        '@"METADATA_ELIGIBLE"',
        '@"metadata-candidate-only-no-verified-runtime-primitive"',
        'record(@"titan.command_buffers", @"BLOCKED"',
        'record(@"titan.physical_write", @"NOT_REACHED"',
        'record(@"sptm_txm.runtime_response", @"NOT_REACHED"',
        'Documents/a15-ios26-diagnostic-v6.json',
        '@"asserts_live_sptm_txm_response": @NO',
    ):
        require(marker in diagnostic_body, f"research diagnostic is missing safety marker: {marker}")
    require(
        diagnostic_body.count("IOSurfaceCreate(") == 1,
        "research diagnostic must create exactly one standard IOSurface",
    )
    require(
        diagnostic_body.count("IOSurfaceLock(") == 1
        and diagnostic_body.count("IOSurfaceUnlock(") == 1,
        "research diagnostic must use exactly one bounded IOSurface lock/unlock pair",
    )
    require(
        "kIOSurfaceLockReadOnly | kIOSurfaceLockAvoidSync" in diagnostic_body,
        "standard IOSurface lock is not explicitly read-only and synchronization-avoiding",
    )
    require(
        "CFRelease(standardSurface)" in diagnostic_body,
        "standard IOSurface is not released",
    )
    require(
        "ACTIVE_TITAN_PROBE_DESCRIPTOR_RANGE_FIX_BUILT" in report,
        "report does not record the descriptor-range correction state",
    )
    for marker in ("iokit.IOMachPort", "clearsword_kreadbuf", "[+0x08,+0x28)"):
        require(marker in report, f"report is missing active-device panic evidence: {marker}")
    for marker in ("kalloc.type.var2.16", "elements+0x8", "clearsword_kreadbuf_exact"):
        require(marker in report, f"report is missing second active-device panic evidence: {marker}")
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
        for key in (
            "Research_Target_Header",
            "Research_Stage_OSDictionary",
            "Research_Stage_IORVBAR",
            "Research_Button_Run",
        ):
            require(strings.count(f'"{key}" =') == 1, f"{localization} localization is missing {key}")

    titan_run = titan.find("int titan_run")
    guard = titan.find("if (!gTitanContext.iorvbar_mapping_validated)", titan_run)
    queue_setup = titan.find("titan_setup_command_buffers()", titan_run)
    require(guard >= 0, "Titan iOS 26 guard is missing")
    require(queue_setup >= 0 and guard < queue_setup, "Titan guard no longer precedes command-buffer setup")
    for marker in (
        "titan_resolve_ios26_iorvbar_mapping",
        'strcmp(machine, "iPhone14,2") == 0',
        'strcmp(build, "23A355") == 0',
        "kIOS2601AppleARMIODeviceVtable",
        "kIOS2601IOGeneralMemoryDescriptorVtable",
        "kIOS2601IOMemoryMapVtable",
        "kIOS2601GFXIORVBARPhysicalAddress = 0x206050000ULL",
        "kIOS2601GFXIORVBARLength = 0x8ULL",
        "titan_read_exact_scalar",
        "descriptorRanges = titan_read_valid_pointer(descriptor, 0x60",
        "descriptorRangesCount != 1",
        "descriptorPhysical != kIOS2601GFXIORVBARPhysicalAddress",
        "descriptorLength != kIOS2601GFXIORVBARLength",
        "descriptorRangeLength != kIOS2601GFXIORVBARLength",
        "fMemory != descriptor",
        "fOffset != 0",
        "fLength != kIOS2601GFXIORVBARLength",
        'titan_checkpoint(@"titan.iorvbar.descriptor-range"',
        'titan_checkpoint(@"titan.rop-wait-thread"',
        'titan_checkpoint(@"titan.rop-trigger"',
        "int triggerResult = gfx_write32",
        'dlsym(RTLD_DEFAULT,\n                                                               "clearsword_kreadbuf_exact")',
        "exact-kreadbuf-unavailable",
    ):
        require(marker in titan, f"active Titan adaptation is missing marker: {marker}")
    for marker in (
        "int clearsword_kreadbuf_exact",
        "socklen_t read_data_length = (socklen_t)size",
        "read_data_length < size",
    ):
        require(marker in clearsword_krw, f"ClearSword exact-read path is missing marker: {marker}")
    for marker in (
        "!titan_gadget(tpidrro_el0)",
        "!titan_gadget(write)",
        "!titan_gadget(rop_invoke)",
        "!titan_gadget(cache_flush)",
        "!titan_gadget(spin)",
        "!titan_address(power_thread)",
        "!titan_address(target_job)",
        "!titan_address(arm_hb_context)",
    ):
        require(marker in gfx_patchfinder, f"GFX ROP validation is missing marker: {marker}")
    require(
        'A15ActiveProbeCheckpoint(@"probe.cleanup"' in active_body,
        "active probe does not record exploit cleanup",
    )
    require(
        "0xffffffec9be40000" not in titan,
        "per-boot IORVBAR kernel mapping was hard-coded into Titan",
    )
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
        '"schema": "dopamine.a15-ios26.response-trace.v2"' in response_trace
        and '"asserts_live_sptm_txm_response": False' in response_trace
        and '"runtime_values": None' in response_trace
        and '"runtime_values_status": "NOT_REACHED"' in response_trace
        and '"first_metadata_blocker": first_metadata_blocker' in response_trace
        and '"first_runtime_blocker": first_runtime_blocker' in response_trace
        and '"protected_component_boundary": "NOT_REACHED"' in response_trace,
        "response trace can no longer distinguish its model from a live SPTM/TXM response",
    )
    for marker in (
        '"request_generated": False',
        '"request_transmitted": False',
        '"handler_dispatched": False',
        '"response_received": False',
    ):
        require(marker in response_trace, f"response trace is missing boundary marker: {marker}")
    require(
        "txm_kernel_call" in response_trace
        and "txm_enter" in response_trace
        and "txm_ret" in response_trace
        and "num_return_words" in response_trace,
        "response trace is missing the published TXM call contract",
    )
    for marker in (
        '"dopamine.a15-ios26.macho-preflight.v1"',
        "path.read_bytes()",
        '"execution": "NOT_PERFORMED"',
        "LC_SYMTAB",
        "LC_DYSYMTAB",
        "LC_CODE_SIGNATURE",
    ):
        require(marker in macho_preflight, f"Mach-O preflight is missing marker: {marker}")
    for forbidden in ("ctypes", "subprocess", "os.system", "Popen(", "CDLL(", "exec(", "eval("):
        require(forbidden not in macho_preflight, f"Mach-O preflight can execute target code via {forbidden}")

    print(
        "OK: exact iPhone14,2/23A355 active Titan probe enabled; "
        "persistent checkpoints present; privilege and bootstrap stages remain blocked"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
