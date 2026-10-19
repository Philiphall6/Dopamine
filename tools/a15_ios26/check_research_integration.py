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
    with (ROOT / "Application/Dopamine/Info.plist").open("rb") as stream:
        app_info = plistlib.load(stream)
    require(app_info.get("A15ProbeRevision") ==
            "self-page-write-v1+agx-firmware-read-v2+rtkit-mmio-disabled-v1",
            "app Info.plist does not identify the MMIO-disabled revision")
    require(app_info.get("A15ProbeSafetyMode") == "no-gfx-mmio",
            "app Info.plist does not expose the MMIO safety mode")
    titan = (ROOT / "Application/Dopamine/Exploits/Titan/exploit/titan.m").read_text()
    ipc_port = (
        ROOT / "Application/Dopamine/Exploits/Titan/exploit/ipc_port.c"
    ).read_text()
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
    ipc_copy_audit = (ROOT / "docs/TITAN_IPC_COPY_DARWIN25_AUDIT.md").read_text()

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
    self_page_start = jailbreaker.find("static BOOL A15ProbeSelfPageKernelWrite")
    self_page_end = jailbreaker.find("typedef CFTypeRef (*A15SecTaskCreateFromSelfFn)", self_page_start)
    require(0 <= self_page_start < self_page_end < active_start,
            "self-page writer must be isolated before the active probe")
    self_page_body = jailbreaker[self_page_start:self_page_end]
    for marker in (
        "isA15IOS2601ResearchTarget",
        'isEqualToString:@"ClearSword"',
        'resolveSymbol:"clearsword_kreadbuf_exact"',
        'resolveSymbol:"clearsword_kwritebuf_exact"',
        "vm_allocate(mach_task_self()",
        "mlock(",
        "vtophys(ttep_self()",
        "phystokv(physical)",
        'A15ActiveProbeCheckpoint(@"kernel-write.self-page.attempt", @"START"',
        "exactWrite(kernelAlias, changed, sizeof(changed))",
        "memcmp(observed, changed, sizeof(changed))",
        "memcmp(userBytes, changed, sizeof(changed))",
        "exactWrite(kernelAlias, original, sizeof(original))",
        "exactRead(safeTarget, safeRead, sizeof(safeRead))",
        'A15ActiveProbeCheckpoint(@"kernel-write.self-page.redirect", @"PASS"',
        "temporary page retained until process exit",
        "vm_deallocate(mach_task_self()",
    ):
        require(marker in self_page_body, f"self-page writer missing guard: {marker}")
    require(
        active_body.find("A15ProbeSelfPageKernelWrite(kernelExploit, kernelBase)") <
        active_body.find('A15ActiveProbeCheckpoint(@"titan.load"'),
        "self-page write proof must precede Titan",
    )
    require(
        "size != EARLY_KRW_LENGTH" in clearsword_krw
        and "return errno != 0 ? errno : EIO;" in clearsword_krw
        and "setsockopt(g_ctx.rw_socket" in clearsword_krw,
        "strict ClearSword writer is missing size or syscall error checks",
    )
    for marker in (
        "isA15IOS2601ResearchTarget",
        "A15_ACTIVE_PROBE_RUN_ID",
        'A15ActiveProbeCheckpoint(@"kernel.run"',
        'A15ActiveProbeCheckpoint(@"kernel.primitive"',
        "A15ProbeSelfPageKernelWrite(kernelExploit, kernelBase)",
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
        "ACTIVE_TITAN_PROBE_IPC_PROFILE_V5_DEVICE_PASS" in report,
        "report does not record the IPC profile v5 device-pass state",
    )
    for marker in (
        "valid=0x7f",
        "0xffffffdf5e4e4600",
        "0xffffffdf5e4e4800",
        "0xffffffe431bdc000",
        "distinct devices, namespaces,",
    ):
        require(marker in report, f"report is missing IPC profile v5 device evidence: {marker}")
    for marker in (
        "xnu-10002.41.9",
        "xnu-12377.1.9",
        "ip_kobject + 0x10",
        "ip_pdrequest",
        "ip_nsrequest",
        "field-specific pointer authentication",
        "must keep the unconditional stop before",
    ):
        require(marker in ipc_copy_audit, f"Darwin 25 IPC copy audit is missing: {marker}")
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
        "kIOS2601RTKitBootstrapPageSize = 0x4000",
        "kIOS2601RTKitBootstrapMarker = 0x7777777777777700ULL",
        "kIOS2601RTKitMaximumSegmentSize = 0x40000000ULL",
        "titan_read_exact_scalar",
        "titan_read_exact_window",
        "titan_probe_rtkit_metadata_readonly",
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
        'titan_checkpoint(@"titan.rtkit-metadata", @"START"',
        '@"titan.rtkit-metadata.iorvbar"',
        'titan_checkpoint(@"titan.rtkit-metadata.alias"',
        'titan_checkpoint(@"titan.rtkit-metadata", @"PASS"',
        'titan_checkpoint(@"titan.rtkit-metadata", @"STOP"',
        "textSize >= sizeof(uint64_t)",
    ):
        require(marker in titan, f"active Titan adaptation is missing marker: {marker}")
    rtkit_probe_start = titan.find("static int titan_probe_rtkit_metadata_readonly(void)")
    rtkit_probe_end = titan.find("const char *cpu_family_to_soc_name", rtkit_probe_start)
    require(
        rtkit_probe_start >= 0 and rtkit_probe_end > rtkit_probe_start,
        "bounded RTKit metadata probe body is missing",
    )
    rtkit_probe_body = titan[rtkit_probe_start:rtkit_probe_end]
    mmio_stop = rtkit_probe_body.find('@"MMIO-disabled-v1')
    mmio_read = rtkit_probe_body.find('titan_read_exact_scalar(gTitanContext.iorvbar_kernel_address')
    require(0 <= mmio_stop < mmio_read, "RTKit MMIO stop must precede the register read")
    guard_index = rtkit_probe_body.find("if (gTitanContext.ios26_a15_active_probe)")
    require(0 <= guard_index < mmio_stop,
            "RTKit MMIO stop must be gated on the exact A15 target")
    stop_return = rtkit_probe_body.find("return -1;", mmio_stop)
    require(0 <= stop_return < mmio_read,
            "RTKit MMIO stop must return before the register read")
    for forbidden in (
        "kmap(",
        "kwrite",
        "physwrite",
        "gfx_write",
        "task_copy_ipc_entry",
        "IOConnectCall",
        "IOServiceOpen",
    ):
        require(forbidden not in rtkit_probe_body, f"read-only RTKit metadata probe contains {forbidden}")
    rtkit_probe_call = titan.find("titan_probe_rtkit_metadata_readonly()", titan_run)
    require(
        rtkit_probe_call >= 0 and rtkit_probe_call < queue_setup,
        "RTKit metadata probe no longer precedes command-buffer setup",
    )
    for marker in (
        "int clearsword_kreadbuf_exact",
        "socklen_t read_data_length = (socklen_t)size",
        "read_data_length < size",
    ):
        require(marker in clearsword_krw, f"ClearSword exact-read path is missing marker: {marker}")
    for marker in (
        "if (!gTitanContext.ios26_a15_active_probe)",
        "proc_find_by_name_legacy",
        'dlsym(RTLD_DEFAULT,\n                                                    "clearsword_kreadbuf_exact")',
        "TITAN_PROC_IMAGE_MAX_SIZE",
        "TITAN_PROC_NAME_CANDIDATE_MAX",
        "TITAN_PROC_TRAVERSAL_MAX",
        "proc_self()",
        "titan.proc-name-offset CANDIDATE",
        "titan.proc-by-name PASS",
        "koffsetof(proc, list_next)",
    ):
        require(marker in ipc_port, f"bounded proc-name discovery is missing marker: {marker}")
    require(
        "int offset = 0x579" not in ipc_port,
        "iOS 26 proc-name lookup still hard-codes the stale p_comm offset",
    )
    for marker in (
        "TITAN_IPC_CENSUS_ENTRY_MAX",
        "TITAN_IPC_CENSUS_LOG_MAX",
        "TITAN_IPC_CENSUS_MATCH_LOG_MAX",
        "TITAN_IPC_CENSUS_TYPE_LOG_MAX",
        "TITAN_IPC_OBJECT_TYPE_COUNT",
        "TITAN_IPC_OBJECT_STATE_COUNT",
        "TITAN_IOS26_IPC_SPACE_TABLE_OFFSET",
        "TITAN_IOS26_IPC_ENTRY_SIZE",
        "TITAN_IOS26_IPC_ENTRY_BITS_OFFSET",
        "TITAN_IOS26_IPC_ENTRY_RIGHT_MASK",
        "TITAN_IOS26_IPC_PORT_KOBJECT_OFFSET",
        "TITAN_IOS26_IOMACHPORT_OBJECT_OFFSET",
        "TITAN_IOS26_IO_STATE_IN_SPACE",
        "TITAN_IOS26_IO_STATE_IN_SPACE_IMMOVABLE",
        "TITAN_XNU12377_IOT_IOKIT_CONNECT",
        "struct titan_ipc_entry_snapshot",
        "offsetof(struct titan_ipc_entry_snapshot, bits)",
        "TITAN_IOS26_TASK_LAYOUT_START",
        "TITAN_IOS26_TASK_LAYOUT_END",
        "TITAN_IOS26_IPC_SPACE_LAYOUT_END",
        "ipc_space_table_exact",
        "ipc_table_resolve(normalized_table, &size)",
        "uint64_t normalized_table = UNSIGN_PTR(encoded_table)",
        "process_census_open_userclients",
        "titan_read_pointer_exact",
        "gTitanContext.iomachport_vtable",
        "wrapper_vtable != gTitanContext.iomachport_vtable",
        "entry_start.bits & TITAN_IOS26_IPC_ENTRY_RIGHT_MASK",
        "io_type = object_bits & 0xffU",
        "io_state = (object_bits >> 8) & 0x7U",
        "memcmp(&entry_start, &entry_confirm, sizeof(entry_start))",
        "memcmp(&entry_start, &entry_end, sizeof(entry_start))",
        "titan.ipc-census CANDIDATE",
        "titan.ipc-census MATCH",
        "match-logged=%zu match-truncated=%zu",
        "struct titan_userclient_profile",
        "titan_profile_userclient",
        "TITAN_PROFILE_COMPLETE",
        "titan.ipc-census PROFILE index=",
        "titan.ipc-census PROFILE-COMPARE",
        "profiles=%zu profile-complete=%zu",
        "titan.ipc-census DECODE revision=ipc-census-v5",
        "titan.ipc-census OBJECT-TYPE",
        "titan.ipc-census OBJECT-STATE",
        "titan.ipc-census SUMMARY",
        "allocation=0x%x entries=%u entry-size=0x%x tail=0x%x",
        "table-stable=%s pid-stable=%s",
        "titan.ipc-layout START",
        "titan.ipc-layout WORD",
        "titan.ipc-layout STOP read-only words-only; no IPC object followed",
    ):
        require(marker in ipc_port, f"bounded IPC census is missing marker: {marker}")
    require(
        "revision=self-page-write-v1+agx-firmware-read-v2+rtkit-mmio-disabled-v1" in jailbreaker,
        "active probe entry does not identify the MMIO-disabled build",
    )
    queue_probe_start = titan.find('titan_checkpoint(@"titan.self-gpu.queue-selector", @"START"')
    local_gate = titan.find("if (!baseline_consistent || candidate_count != 1 ||")
    selector_call = titan.find("IOConnectCallStructMethod(candidate_name,")
    legacy_end = titan.find("static bool titan_valid_kernel_pointer", selector_call)
    require(0 <= local_gate < queue_probe_start < selector_call < legacy_end,
            "local queue selector must follow the stable, unique local-right gate")
    require('candidate_count = titan_count_local_gpu_clients("after-metal-queue"' in titan and
            'metal_queue = [device newCommandQueue]' in titan,
            "Metal queue bootstrap must be measured before the local selector")
    require('queue_created = kr == KERN_SUCCESS && output_size == sizeof(output)' in titan and
            'titan_checkpoint(@"titan.self-gpu.queue-selector", queue_created' in titan,
            "local queue selector result must have a persistent checkpoint")
    metadata_start = titan.find("static int titan_probe_agx_map_metadata(void)")
    metadata_end = titan.find("static int titan_read_exact_window", metadata_start)
    require(metadata_start >= 0 and metadata_end > metadata_start,
            "bounded AGX map metadata probe is missing")
    metadata_body = titan[metadata_start:metadata_end]
    for marker in (
        'IOServiceMatching("AGXAccelerator")',
        'strcmp(className, "AGXAcceleratorG14P")',
        'kIOS2601IOMachPortVtable = 0xfffffff007abcb18ULL',
        'kIOS2601AGXG14PInstanceVtable = 0xfffffff007b1e0d0ULL',
        'kIOS2601AGXProbeConfig = 0xfffffff00ab5ea88ULL',
        'titan.agx-map-metadata.service-map-address',
        'titan.agx-map-metadata.config-flags',
        'titan.agx-map-metadata.config-gpu-physical',
        'titan.agx-map-metadata.config-fender-physical',
        'titan.agx-map-metadata.config-gpu-map',
        'titan.agx-map-metadata.config-fender-map',
        'titan.agx-map-metadata.stability',
        'if (!stable) goto cleanup;',
        'titan_checkpoint(@"titan.agx-map-metadata", @"STOP"',
    ):
        require(marker in titan, f"AGX metadata probe is missing marker: {marker}")
    for forbidden in (
        "IOServiceOpen(", "IOConnectCall", "task_copy_ipc_entry(",
        "kwrite", "kmap(", "titan_resolve_ios26_iorvbar_mapping(",
    ):
        require(forbidden not in metadata_body,
                f"AGX metadata probe contains forbidden call: {forbidden}")
    wrapper_gate = metadata_body.find("unslidWrapper != kIOS2601IOMachPortVtable")
    object_follow = metadata_body.find("titan_read_valid_pointer(wrapper, 0x20")
    require(0 <= wrapper_gate < object_follow,
            "AGX wrapper object is followed before its vtable gate")
    instance_gate = metadata_body.find("unslidInstance != kIOS2601AGXG14PInstanceVtable")
    map_field_read = metadata_body.find("titan_read_exact_scalar(object, 0x310")
    require(0 <= instance_gate < map_field_read,
            "AGX map field is read before instance identity validation")
    stability_gate = metadata_body.find("if (!stable) goto cleanup;")
    summary_pass = metadata_body.find('titan_checkpoint(@"titan.agx-map-metadata", @"PASS"')
    require(0 <= stability_gate < summary_pass,
            "AGX metadata summary must follow the repeat-read stability gate")
    iouat_start = titan.find("static int titan_probe_agx_iouat_object(uint64_t mux)")
    gart_start = titan.find("static int titan_probe_agx_gart_state(uint64_t service)")
    mode_start = titan.find("titan_probe_agx_uat_mode(uint64_t object)")
    require(0 <= iouat_start < gart_start < mode_start < metadata_start,
            "bounded AGX IOUAT and GART probes must precede metadata")
    iouat_body = titan[iouat_start:gart_start]
    gart_body = titan[gart_start:mode_start]
    mode_body = titan[mode_start:metadata_start]
    for marker in (
        "kIOS2601AGXGartG14Vtable = 0xfffffff007b1c4d8ULL",
        "kIOS2601AGXGartServiceOffset = 0xee80ULL",
        "kIOS2601AGXGartStateOffset = 0x2e8ULL",
        "kIOS2601AGXUATMuxVtable = 0xfffffff007b22ae0ULL",
        "kIOS2601IOUATFactoryVtable = 0xfffffff007aed3a0ULL",
        "kIOS2601AGXUATMuxIOUATOffset = 0x10ULL",
        'titan.agx-gart-state.gart-repeat',
        'titan.agx-gart-state.vtable-repeat',
        'titan.agx-gart-state.identity',
        'if (!gartType) return -1;',
        'titan.agx-gart-state.state-repeat',
        'titan.agx-gart-state.state-vtable-repeat',
        'titan.agx-gart-state.mux-identity',
        'titan.agx-iouat-object.pointer-repeat',
        'titan.agx-iouat-object.vtable-repeat',
        'titan.agx-iouat-object.identity',
        'titan_checkpoint(@"titan.agx-gart-state", @"STOP"',
    ):
        require(marker in titan, f"AGX GART state probe is missing marker: {marker}")
    for forbidden in ("IOServiceOpen(", "IOConnectCall", "task_copy_ipc_entry(",
                      "kwrite", "kmap(", "titan_resolve_ios26_iorvbar_mapping("):
        require(forbidden not in gart_body,
                f"AGX GART state probe contains forbidden call: {forbidden}")
    require(gart_body.find("if (!gartType) return -1;") <
            gart_body.find("titan_read_valid_pointer(gart, kIOS2601AGXGartStateOffset"),
            "AGX GART state is followed before the vtable identity gate")
    require(0 <= gart_body.find("if (!muxType) return -1;") <
            gart_body.find("titan_probe_agx_iouat_object(state)"),
            "AGXUATMux factory field is followed before its vtable identity gate")
    require(0 <= iouat_body.find("if (!iouat || iouat != iouatAgain)") <
            iouat_body.find("titan_read_exact_scalar(iouat, 0"),
            "IOUAT object vtable read must follow stable pointer gate")
    require(0 <= iouat_body.find("if (!iouatRoute) return -1;") <
            iouat_body.find("titan_read_valid_pointer(mux, kIOS2601AGXUATMuxIOUATOffset"),
            "IOUAT factory field must follow stable initialized mode=1 gate")
    for forbidden in ("IOServiceOpen(", "IOConnectCall", "task_copy_ipc_entry(",
                      "kwrite", "kmap(", "titan_resolve_ios26_iorvbar_mapping("):
        require(forbidden not in iouat_body,
                f"AGX IOUAT object probe contains forbidden call: {forbidden}")
    require(iouat_body.find("if (!factoryType) return -1;") <
            iouat_body.find("return titan_probe_shared_alias();"),
            "own-client probe must follow the exact IOUAT factory identity gate")
    shared_start = titan.find("static int titan_probe_shared_alias(void)\n{")
    owned_queue_start = titan.find("static int titan_probe_owned_agx_queue(")
    shared_end = titan.find("static int titan_resolve_ios26_iorvbar_mapping(void)",
                            shared_start)
    require(0 <= owned_queue_start < shared_start < shared_end,
            "bounded own-client alias probe is missing")
    owned_queue_body = titan[owned_queue_start:shared_start]
    for marker in (
        'kIOS2601AGXCommandQueueVtable = 0xfffffff007b17550ULL',
        'kIOS2601AGXArmFirmwareASCVtable = 0xfffffff007b18e58ULL',
        'titan.own-queue.device-vtable',
        'titan.own-queue.array-vtable',
        'titan.own-queue.input-size',
        'requiredInputSize != 0x410',
        'sizeof(input) != 0x410 || sizeof(output) != 0x10',
        'IOConnectCallStructMethod(connection, 6, &input,',
        'titan.own-queue.object-repeat',
        'titan.own-queue.object-vtable',
        'titan.own-queue.table',
        'titan.own-queue.device-backref',
        'titan.own-queue.ready',
        'titan.own-queue.buffer-repeat',
        'titan.own-queue.identity',
        'titan.own-queue.firmware-object-repeat',
        'titan.own-queue.firmware-vtable-repeat',
        'titan.own-queue.firmware-vtable',
        'titan.own-queue.firmware-read',
    ):
        require(marker in titan, f"owned queue probe is missing: {marker}")
    for forbidden in ("IOGPU_submit_command_buffers(", "gfx_reset(",
                      "task_copy_ipc_entry(", "kwrite", "kmap(",
                      "IOConnectCallMethod("):
        require(forbidden not in owned_queue_body,
                f"owned queue probe contains forbidden call: {forbidden}")
    require(owned_queue_body.count('IOConnectCall') == 1 and
            owned_queue_body.count('IOConnectCallStructMethod(') == 1 and
            owned_queue_body.count('IOConnectCallStructMethod(connection, 6, &input,') == 1 and
            owned_queue_body.find('titan.own-queue.device-vtable') <
            owned_queue_body.find('IOConnectCallStructMethod(connection, 6, &input,') <
            owned_queue_body.find('titan.own-queue.object-vtable'),
            "owned queue creation must occur once, after identity gates and before object reads")
    require(0 <= owned_queue_body.find('if (!sameClient) {') <
            owned_queue_body.find('titan.own-queue.firmware-object') <
            owned_queue_body.find('titan.own-queue.firmware-vtable-read') <
            owned_queue_body.find('titan.own-queue.firmware-vtable-repeat') <
            owned_queue_body.find('titan.own-queue.firmware-read", @"PASS"') <
            owned_queue_body.find('titan.own-queue", @"PASS"'),
            "firmware identity reads must follow same-client gate and precede bounded stop")
    shared_body = titan[shared_start:shared_end]
    require('registryID != 0' in shared_body and 'registryID == 0x100000330ULL' not in shared_body,
            "AGX service guard must not pin a registry ID across boots")
    for marker in (
        'IOServiceOpen(service, mach_task_self(), 1, &connection)',
        'if (!expectedClient) goto cleanup;',
        'IOConnectCallMethod(connection, 12, inputs, 2,',
        'uint64_t inputs[2] = { 0x4000, 0 };',
        'vm_region_64(mach_task_self()',
        'if (!writable) goto cleanup;',
        'titan.shared-alias.registry',
        'if (!buffer || buffer != bufferAgain ||',
        'if (!descriptor || descriptor != backing ||',
        'mappedAddress != output.address',
        'mlock((void *)(uintptr_t)output.address, 0x4000)',
        'titan_read_exact_window(alias, observed, sizeof(observed)',
        'memcpy(userBytes, changed, sizeof(changed));',
        'memcpy(userBytes, original, sizeof(original));',
        'titan.shared-alias.restore',
        'titan.shared-alias.redirect',
        'IOServiceClose(connection)',
    ):
        require(marker in shared_body, f"shared alias probe is missing: {marker}")
    for forbidden in ("IOGPU_submit_command_buffers(", "gfx_reset(",
                      "task_copy_ipc_entry(", "kwrite", "IOConnectCallMethod(connection, 25"):
        require(forbidden not in shared_body,
                f"shared alias probe contains forbidden call: {forbidden}")
    require(shared_body.find('if (!expectedClient) goto cleanup;') <
            shared_body.find('IOConnectCallMethod(connection, 12, inputs, 2,') <
            shared_body.find('if (!created) goto cleanup;') <
            shared_body.find('if (!writable) goto cleanup;') <
            shared_body.find('titan.shared-alias.registry') <
            shared_body.find('memcpy(userBytes, changed, sizeof(changed));'),
            "shared alias probe gates are missing or out of order")
    require(0 <= shared_body.find('titan.shared-alias.restore') <
            shared_body.find('titan.shared-alias.redirect') <
            shared_body.find('if (result == 0) result = titan_probe_owned_agx_queue(') <
            shared_body.find('IOServiceClose(connection)'),
            "owned queue call must follow alias restoration and precede client close")
    for marker in (
        "kIOS2601AGXUATMode = 0xfffffff00ab61150ULL",
        "kIOS2601AGXUATModeSourceOffset = 0xdb08ULL",
        "kIOS2601AGXUATModeInitializedOffset = 0x10ULL",
        "titan.agx-uat-mode.initialized-repeat",
        "titan.agx-uat-mode.source-repeat",
        "titan.agx-uat-mode.global-repeat",
        "initialized == 1 && mode <= 1 && mode == (source & 1)",
        "titan.agx-uat-mode.stability",
        'mode ? @"IOUAT" : @"AGXUAT"',
    ):
        require(marker in titan, f"AGX UAT mode probe is missing marker: {marker}")
    for forbidden in ("IOServiceOpen(", "IOConnectCall", "task_copy_ipc_entry(",
                      "kwrite", "kmap(", "titan_resolve_ios26_iorvbar_mapping("):
        require(forbidden not in mode_body,
                f"AGX UAT mode probe contains forbidden call: {forbidden}")
    require("result = titan_probe_agx_gart_state(object);" in metadata_body and
            metadata_body.find("unslidInstance != kIOS2601AGXG14PInstanceVtable") <
            metadata_body.find("result = titan_probe_agx_gart_state(object);"),
            "AGX GART pointer must follow validated service identity")
    active_branch = titan.find("if (gTitanContext.ios26_a15_active_probe) {", titan_run)
    active_branch_end = titan.find("if (gTitanContext.ios26_a15_active_probe &&", active_branch)
    require(active_branch >= 0 and active_branch_end > active_branch and
            "titan_probe_agx_map_metadata();" in titan[active_branch:active_branch_end] and
            "titan_probe_self_owned_gpu_client();" not in titan[active_branch:active_branch_end] and
            "return -1;" in titan[active_branch:active_branch_end],
            "A15 active branch must stop after the bounded metadata/client probe")
    for marker in (
        "static void A15RunHypervisorPreflight(void)",
        'dlsym(symbolScope, "hv_vm_create")',
        'dlsym(symbolScope, "hv_vm_map")',
        'dlsym(symbolScope, "hv_vcpu_create")',
        'dlsym(symbolScope, "hv_vcpu_run")',
        'A15ActiveProbeCheckpoint(@"hypervisor.path"',
        'IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/product")',
        'IORegistryEntryCreateCFProperty(product, CFSTR("has-virtualization")',
        'IORegistryCreateIterator(kIOMainPortDefault',
        'A15ActiveProbeCheckpoint(@"hypervisor.ioreg"',
        'A15ActiveProbeCheckpoint(@"hypervisor.dyld"',
        'CFSTR("com.apple.private.hypervisor")',
        'CFSTR("com.apple.private.hypervisor.vmapple")',
        'CFSTR("com.apple.security.hypervisor")',
        'A15ReadOnlySysctlValue("kern.hv_support")',
        'A15ReadOnlySysctlValue("kern.hv_vmm_present")',
        'A15ReadOnlySysctlValue("kern.hv_disable")',
        'A15ActiveProbeCheckpoint(@"hypervisor.preflight", @"STOP", @"read-only; no hv_* function or IOKit user-client open invoked")',
    ):
        require(marker in jailbreaker, f"Hypervisor preflight is missing marker: {marker}")
    preflight_start = jailbreaker.find("static void A15RunHypervisorPreflight(void)")
    preflight_end = jailbreaker.find("static void A15RunAGXServiceCensus(void)", preflight_start)
    require(
        preflight_start >= 0 and preflight_end > preflight_start,
        "bounded Hypervisor preflight body is missing",
    )
    preflight_body = jailbreaker[preflight_start:preflight_end]
    for forbidden in (
        "hvVmCreate(",
        "hvVmMap(",
        "hvVcpuCreate(",
        "hvVcpuRun(",
        "kwrite",
        "task_copy_ipc_entry",
        "IOConnectCall",
        "IOServiceOpen",
    ):
        require(forbidden not in preflight_body, f"read-only Hypervisor preflight contains {forbidden}")
    registry_start = preflight_end
    registry_end = jailbreaker.find("- (NSError *)gatherSystemInformation", registry_start)
    require(registry_start >= 0 and registry_end > registry_start,
            "AGX service census body is missing")
    registry_body = jailbreaker[registry_start:registry_end]
    for marker in (
        "IORegistryCreateIterator(kIOMainPortDefault",
        "IOObjectGetClass(entry, className)",
        "IOIteratorIsValid(iterator)",
        'strcmp(className, "AGXAcceleratorG14P_A0")',
        "IORegistryEntryGetParentEntry(entry, kIOServicePlane",
        'A15ActiveProbeCheckpoint(@"agx.registry-match"',
        'A15ActiveProbeCheckpoint(@"agx.registry", @"SUMMARY"',
        "iterator-valid=%@",
        'A15ActiveProbeCheckpoint(@"agx.registry", @"STOP"',
    ):
        require(marker in registry_body, f"AGX service census is missing marker: {marker}")
    for forbidden in ("IOServiceOpen(", "IOConnectCall", "kwrite", "kread", "mach_vm_write", "IOConnectMapMemory"):
        require(forbidden not in registry_body, f"read-only AGX service census contains {forbidden}")
    target_gate = active_body.find("isA15IOS2601ResearchTarget")
    registry_call = active_body.find("A15RunAGXServiceCensus();")
    preflight_call = active_body.find("A15RunHypervisorPreflight();")
    xpf_start = active_body.find('A15ActiveProbeCheckpoint(@"xpf.gather"')
    require(0 <= target_gate < registry_call < preflight_call < xpf_start,
            "AGX census must run after the exact-target gate and before kernel/SPTM gathering")
    require(
        active_body.find("A15RunHypervisorPreflight();")
        < active_body.find('A15ActiveProbeCheckpoint(@"xpf.gather"'),
        "Hypervisor preflight no longer runs before kernel/SPTM gathering",
    )
    require(
        "INFO: iOS 26 IOMemoryMap primary candidate" in kernel_patchfinder
        and "trying the accessor pattern" in kernel_patchfinder,
        "iOS 26 IOMemoryMap fallback is not identified as an expected retry",
    )
    layout_start = ipc_port.find("static void titan_log_layout_window")
    layout_end = ipc_port.find("static int create_new_send_once_port", layout_start)
    require(layout_start >= 0 and layout_end > layout_start, "IPC layout probe body is missing")
    layout_body = ipc_port[layout_start:layout_end]
    for forbidden in ("kwrite", "task_copy_ipc_entry", "mach_port_", "IOConnectCall"):
        require(forbidden not in layout_body, f"read-only IPC layout probe contains {forbidden}")
    require(
        "unsigned_value = raw ? UNSIGN_PTR(raw) : 0" in layout_body
        and "ipc_table_resolve(unsigned_value, &decoded_size)" in layout_body,
        "fallback IPC layout logger does not normalize signed SMR words",
    )
    census_start = ipc_port.find("static uint64_t process_census_open_userclients")
    census_end = ipc_port.find("uint64_t process_find_open_userclient", census_start)
    require(census_start >= 0 and census_end > census_start, "IPC census body is missing")
    census_body = ipc_port[census_start:census_end]
    for forbidden in ("kwrite", "task_copy_ipc_entry", "mach_port_", "IOConnectCall"):
        require(forbidden not in census_body, f"read-only IPC census contains {forbidden}")
    profile_start = ipc_port.find("static bool titan_profile_userclient")
    profile_end = ipc_port.find("static const char *titan_profile_compare", profile_start)
    require(profile_start >= 0 and profile_end > profile_start, "IPC profile body is missing")
    profile_body = ipc_port[profile_start:profile_end]
    for forbidden in ("kwrite", "task_copy_ipc_entry", "mach_port_", "IOConnectCall"):
        require(forbidden not in profile_body, f"read-only IPC profile contains {forbidden}")
    require(
        "ipc_table_size % ipc_entry_size != 0" not in census_body
        and "ipc_table_count = ipc_table_size / ipc_entry_size" in census_body
        and "ipc_table_tail = ipc_table_size % ipc_entry_size" in census_body,
        "IPC census does not preserve the bounded complete-entry plus allocation-tail contract",
    )
    require(
        "state_word & 0x80000000U" not in census_body
        and "old_type" not in census_body,
        "exact-target IPC census still uses the obsolete packed active/type word",
    )
    for marker in (
        "titan.iorvbar.wrapper-vtable-read",
        "titan.iorvbar.wrapper-vtable",
        "gTitanContext.iomachport_vtable = wrapperVtable",
        "titan.ipc-census STOP read-only; task_copy_ipc_entry not reached",
    ):
        require(marker in titan, f"Titan IPC census integration is missing marker: {marker}")
    setup_start = titan.find("int titan_setup_command_buffers")
    setup_end = titan.find("int titan_parse_RTKit_information", setup_start)
    setup_body = titan[setup_start:setup_end]
    active_stop = setup_body.find("if (gTitanContext.ios26_a15_active_probe)")
    ipc_copy = setup_body.find("if (task_copy_ipc_entry(")
    require(
        active_stop >= 0 and ipc_copy >= 0 and active_stop < ipc_copy,
        "exact-target IPC census no longer stops before task_copy_ipc_entry",
    )
    copy_start = ipc_port.find("int task_copy_ipc_entry(")
    copy_end = ipc_port.find("static uint64_t process_find_open_userclient_legacy", copy_start)
    require(copy_start >= 0 and copy_end > copy_start, "legacy IPC copy body is missing")
    copy_body = ipc_port[copy_start:copy_end]
    copy_guard = copy_body.find("gTitanContext.os_major_version >= 26 || xnu_major >= 12377")
    first_legacy_read = copy_body.find("kread32(ipc_entry + 8)")
    require(
        copy_guard >= 0 and first_legacy_read >= 0 and copy_guard < first_legacy_read,
        "Darwin 25 legacy IPC copy guard is missing or follows the first target read",
    )
    require(
        "refusing legacy IPC right copy on Darwin 25" in copy_body,
        "Darwin 25 legacy IPC copy guard lacks a diagnostic marker",
    )
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
