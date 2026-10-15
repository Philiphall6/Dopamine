# A15 / iOS 26.0.1 Research Status

This document tracks the diagnostic work toward understanding Dopamine's
Titan/SPTM chain on iPhone14,2. It is not a compatibility declaration. The
target remains unsupported and the application explicitly refuses to enter the
jailbreak path on this exact device and OS combination.

## Target

- Device: iPhone14,2
- SoC: A15
- OS: iOS 26.0.1
- Kernel: Darwin 25.0.0
- Research state: `MAPPING_VALIDATED_TITAN_EXECUTION_BLOCKED`
- Operating mode: bounded read-only observation and offline static analysis

## End-to-End Chain Status

| Stage | Status | Evidence or blocker |
|---|---|---|
| Device and firmware identity | **PASS** | iPhone14,2 / A15 / 23A355 / iOS 26.0.1 |
| Read-only acquisition path | **PASS** | Filza bridge plus USB forwarding; probe restored disabled after each bounded capture |
| Kernelcache, GFX, SPTM, and TXM extraction | **PASS** | Offline analyzers accept all four extracted images |
| RTBuddy object and segment layout | **PASS** | Live object chain, two descriptors, and physical/virtual/remap field roles resolved |
| Existing GFX IORVBAR mapping | **VALIDATED** | One existing 8-byte `IOMemoryMap`; address recorded but never dereferenced |
| iOS 26 Titan kernel/GFX anchors | **STATIC PASS** | Adapted unique anchors resolve; legacy patterns fail as expected |
| TXM and SPTM anchors | **STATIC PASS** | Inspected trust-cache, PAPT, frame-table, and argument relationships resolve |
| Kernel read/write exploit primitive | **MISSING** | No target-compatible primitive has been established |
| Titan unrestricted physical write | **BLOCKED** | No command queue, GPU trigger, MMIO access, or physical write was executed |
| SPTM/PAPT bypass contract | **MISSING** | Static addresses do not satisfy Dopamine's physical-write bypass contract |
| Bootstrap, trust-cache, and jailbreak services | **NOT REACHABLE** | Depend on the missing kernel and SPTM primitives |
| A15/iOS 26 support declaration | **BLOCKED** | App guard returns unsupported before exploit selection |

The first unresolved operational link is a valid kernel read/write primitive
for this exact target. Even if that existed, Titan's physical-write stage and
the SPTM/PAPT bypass would still require separate validation. Passing static
patchfinders does not bridge either gap.

## How the Published Titan Chain Works

Titan is not a direct TXM bypass. Dopamine first requires a compatible kernel
exploit to provide kernel read/write. It initializes kernel translation and
IOSurface helpers, then loads Titan as the selected PPL/SPTM-stage component.

The published Titan path has four architectural phases:

1. It uses the existing kernel read primitive to discover the kernel pmap,
   translation roots, IOGPU objects, RTBuddy state, and GFX firmware mappings.
2. It copies and statically analyzes the running GFX firmware to resolve the
   version-specific RTKit state and control-flow anchors needed by the published
   implementation.
3. It uses the validated GFX/RTKit path to create a controlled CPU mapping
   window. Titan exports this result to Dopamine only as an unrestricted
   physical-write callback (`physwritebuf`).
4. Dopamine consumes that callback to construct its normal physical read/write
   layer. TXM and SPTM offsets found by XPF are downstream inputs for protected
   trust-cache, developer-mode, translation, and page-protection operations;
   knowing their static addresses does not create the physical-write primitive.

For iPhone14,2 on iOS 26.0.1, phases 1 and 2 are only partially represented by
offline and bounded read-only evidence. The current research guard stops before
GPU command-buffer setup. No target-compatible kernel read/write exploit,
RTKit execution path, controlled mapping window, unrestricted physical write,
or SPTM bypass has been established. The static TXM base and passing XPF
relationships therefore improve the map of the chain but do not bypass TXM.

## Diagnostic Response Logging

Every future diagnostic observation should record a timestamp, stage identifier,
input class, return status, and last completed stage. A process exit or reboot
must be recorded as an interrupted stage rather than interpreted as a protocol
response.

On the current build, the iOS 26 guard returns before Titan command-buffer
setup. Consequently there is no live GPU, RTKit-execution, SPTM, or TXM response
to decode yet. The available response set is limited to target identification,
offline patchfinder results, bounded IORegistry/RTBuddy reads, IOMemoryMap
metadata, and the explicit Titan diagnostic refusal. Downstream response logging
only becomes meaningful after a target-compatible kernel read/write primitive
exists and each subsequent stage has been independently validated.

| Observable checkpoint | Current target result |
|---|---|
| Application support gate | `UNSUPPORTED_TARGET` before exploit selection |
| Kernel exploit result | `NO_TARGET_COMPATIBLE_PRIMITIVE` |
| Kernel patchfinder | `STATIC_PASS`; no runtime kernel context |
| Titan iOS 26 guard | `DIAGNOSTIC_REFUSAL` before command-buffer setup |
| RTBuddy/segment discovery | `READ_ONLY_PASS` from bounded capture |
| GFX firmware patchfinder | `STATIC_PASS` on the extracted image |
| GFX physical addresses and translation root | `NOT_RESOLVED_LIVE` |
| Controlled mapping window | `NOT_ATTEMPTED` |
| Titan `physwritebuf` publication | `NOT_REACHED` |
| Dopamine physical read/write construction | `NOT_REACHED` |
| SPTM/TXM protected operations | `NOT_REACHED` |

The published SPTM/TXM architecture confirms a structured call contract rather
than an arbitrary response channel. XNU wraps a TXM request in `txm_call_t`,
passes it through `txm_kernel_call` and `txm_enter`, and SPTM dispatches it to a
registered TXM handler. The request carries a selector and argument counts; the
response is represented by `txm_ret`, `num_return_words`, and `return_words`.
See [Modern iOS Security Features: A Deep Dive into SPTM, TXM, and
Exclaves](https://arxiv.org/pdf/2510.09272), sections 8.3-8.4.

This model gives future USB logs a precise schema, but does not expose a direct
userspace interface. On the current target, no `txm_kernel_call` is reached, so
all runtime response fields must remain absent and the trace must remain
`NOT_REACHED`.

## Reproducible Diagnostic Build

- Source branch: `codex/a15-ios26-diagnostic-20261014`
- Source commit: `718a49a8d93a57c89831776cdc1529e4d98df423`
- GitHub Actions run: `38690838360` (successful, 2026-10-15)
- Artifact: `Dopamine-A15-iOS26-diagnostic-v2-718a49a.ipa`
- Size: `55,444,034` bytes
- SHA-256: `330DA0766A891C3A1792FC78B1C40FD263B1C1CD3251EB2434D1ABE80AD2287F`
- Application version: `3.0.11` (`com.opa334.Dopamine`)

On the exact iPhone14,2 / iOS 26.0.1 research target, this build replaces the
disabled main action with `Lancer le diagnostic`. That bounded action records
target and packaged-Titan observations in the UI, USB-visible `[A15DIAG]` log
lines, and `Documents/a15-ios26-diagnostic.json`. It cannot instantiate the
jailbreaker, initialize Titan command buffers, perform a physical write, or
claim a live SPTM/TXM response.

### On-device bounded diagnostic

The diagnostic completed on the USB-connected iPhone14,2 running iOS 26.0.1
build `23A355` on 2026-10-14. The report was pulled from the app container as
`a15-ios26-diagnostic-device-20261014.json` and has SHA-256
`AC467CFD44E2DE6BC07EF28962E4CA4980FCB4F70086F78CA31BAEFA740D2E3C`.

The seven reported checkpoints match the expected bounded state:

- `target.identity`, `environment.sptm`, and `titan.framework_metadata` are
  `OBSERVED`.
- `kernel.runtime_read_write` is `MISSING` because no target-compatible
  primitive is available.
- `titan.command_buffers` is `BLOCKED` by diagnostic mode.
- `titan.physical_write` and `sptm_txm.runtime_response` are `NOT_REACHED`.
- `diagnostic_only` is true and `asserts_live_sptm_txm_response` is false.

### Phase 2 metadata preflight

The phase 2 bounded build advances the diagnosis without advancing execution. Its
`dopamine.a15-ios26.device-diagnostic.v2` report reproduces the packaged exploit
selection rules for every framework and flavor, recording version-range,
device-family, and build-override decisions. It also records arm64e, PAC/PPL
requirements, installation mode, and the presence of local kernelcache, SPTM,
and TXM artifacts in the app bundle or Documents directory.

Metadata eligibility is reported separately from runtime availability. In
particular, a kernel framework matching an iOS range remains only a candidate;
it does not establish a working A15 primitive. The overall chain stays blocked
unless every required stage has a matching candidate, and runtime kernel R/W
stays `MISSING` until independently observed.

This preflight only reads bundle metadata, environment properties, and file
existence. The guarded method is statically prohibited from referencing exploit
loading, `IOServiceOpen`, `IOConnectCall`, kernel read/write, command-buffer
setup, or physical-write functions. Titan execution and live SPTM/TXM requests
therefore remain blocked.

The phase 2 diagnostic completed on the USB-connected target on 2026-10-15.
Its 17 checkpoints and 11 framework/flavor entries were pulled as
`a15-ios26-diagnostic-v2-device-20261015.json`, with SHA-256
`0B51294D28BA37D09FFC0EBEFF529A5BDDD5F0ACC01EDCF1B95217F84FB5C1B0`.
The device result matches the offline model:

- Kernel metadata: 7 candidates, with ClearSword and DarkSword as the 2 range
  matches. These remain metadata candidates only; runtime kernel R/W is
  `MISSING`.
- PAC metadata: 1 candidate, 0 matches, and the stage is `NOT_REQUIRED` on this
  target.
- PPL metadata: 3 candidates and 0 matches. Titan and dmaFail miss the version
  range; momentarius misses the declared device family.
- The overall selector result is `BLOCKED` with `ppl-bypass-missing`.
- Local kernelcache, SPTM, and TXM artifacts are all `MISSING` from the app
  bundle and Documents directory.
- Titan command buffers stay `BLOCKED`; physical write and live SPTM/TXM
  response stay `NOT_REACHED`.

The packaged Titan framework still declares support only for iOS `16.1` through
`17.3.1`. Its Info.plist and Mach-O `LC_BUILD_VERSION` both now declare a
minimum deployment target of iOS `16.1`. Although its historical device-family list contains A15, the exact
iPhone14,2 / iOS 26.0.1 target remains excluded and the app-side research guard
returns unsupported before exploit selection or GPU command-buffer setup.

Offline/VM validation regenerated both static reports from the extracted
kernelcache, GFX, SPTM, and TXM images. The adapted iOS 26 kernel and GFX
relationships pass their static checks, as do the inspected SPTM/TXM
relationships. These tests validate parsers, anchors, packaging, and safety
guards only; a VM cannot reproduce the live A15 RTKit/AGX state, SPTM hardware,
GPU memory behavior, MMIO access, or a physical-write primitive.

## Proven Facts

- The `gfx-asc` IOService object is an `AppleARMIODevice`.
- One bounded live capture observed the service object at
  `0xffffffde1c1699a0`. This is a per-boot live address, not a reusable offset.
- The same capture observed its vtable at `0xfffffff044741c68` and resolved the
  unslid vtable to `0xfffffff007b55c68`.
- The provider class resolves to `AppleT811xIO`.
- The live AppleARMIODevice property table is an `OSDictionary`. Its unslid
  vtable is `0xfffffff007aaaf58`, and static analysis proves a class size of
  `0x28`.
- Virtual methods in this kernel prove the OSDictionary layout as
  `fOptions=+0x10`, `count=+0x14`, `capacity=+0x18`,
  `capacityIncrement=+0x1c`, and `dictionary=+0x20`.
- OSDictionary destruction multiplies `capacity` by 16, proving a 16-byte
  `dictEntry` for this kernel.
- A bounded live probe validated `count=20`, `capacity=24`, and the entry table
  pointer for the AppleARMIODevice property dictionary.
- Exact-length OSSymbol reads identified dictionary entry 13 as
  `segment-names`, entry 14 as `segment-ranges`, entry 17 as
  `IODeviceMemory`, and entry 18 as `IOReportLegend`.
- Both segment-property values are `OSData` objects. Their reconstructed
  unslid object-vtable pointer is `0xfffffff007aaad98`, and the target kernel
  registers the class with size `0x28`. Target-kernel methods prove
  `length=+0xc`, `capacity/external-sentinel=+0x10`,
  `capacityIncrement=+0x14`, `data=+0x18`, and
  `owner/deallocator=+0x20`.
- The live `segment-ranges` object has length `0x40` and the live
  `segment-names` object has length `0xe`. Both use the `0xffffffff` external
  buffer sentinel at `+0x10`.
- Static analysis of `RTBuddy` function `0xfffffff00a51214c` proves that it
  divides the `segment-ranges` length by `0x20` and consumes one 32-byte
  descriptor per iteration. The bounded 64-byte capture therefore contains
  exactly two descriptors:
  - descriptor 0: `+0x00=0x8007ac000`,
    `+0x08=0xffffff8000000000`, `+0x10=0x8007ac000`,
    `length=0x5c000`, raw flags `0x1`;
  - descriptor 1: `+0x00=0x802048000`,
    `+0x08=0xffffff800005c000`, `+0x10=0x802048000`,
    `length=0xd8000`, raw flags `0x0`.
- `RTBuddy` loads each raw descriptor as physical address at `+0x00`, virtual
  address at `+0x08`, remap address at `+0x10`, 32-bit length at `+0x18`, and
  32-bit flags at `+0x1c`. It deliberately reorders the three address arguments
  before calling factory `0xfffffff00a505df0`, which stores physical at object
  offset `+0x18`, remap at `+0x20`, virtual at `+0x28`, length at `+0x30`, and
  transformed flags at `+0x40`.
- Target-kernel method `0xfffffff00a506234` passes object fields `+0x18` and
  `+0x30` to the physical-memory-descriptor factory at
  `0xfffffff0086e9dfc`. Methods `0xfffffff00a506298` and
  `0xfffffff00a506308` perform range checks against remap base `+0x20`, while
  methods `0xfffffff00a5062d0` and `0xfffffff00a506334` perform the matching
  checks against virtual base `+0x28`.
- This field order also matches a
  [comparative T8030 DeviceTree dump](https://gist.github.com/bazad/1faef1a6fe396b820a43170b43e38be1)
  that labels the same 32-byte format as `phys`, `virt`, `remap`, `size`, and
  `flags`. That external sample is corroborating format evidence, not
  target-device evidence.
- The `IODeviceMemory` value is an `OSArray` with exactly two elements. Static
  kernel analysis identifies both elements as `IOGeneralMemoryDescriptor`
  objects.
- Descriptor 0 covers physical range `0x206400000..0x20646ffff`
  (`0x6c000` bytes). Descriptor 1 covers physical address `0x206050000` for
  `0x8` bytes, exactly matching the GFX IORVBAR from the DeviceTree.
- Both descriptors have a non-null existing `_mappings` set. Target-kernel
  constructor analysis proves that `OSSet::members` is at `+0x18` in a `0x20`
  byte object. A staged live traversal of descriptor 1 then resolved an
  `OSArray` with `count=1`, `capacity=2`, and one mapping-element pointer.
  The element is an `IOMemoryMap`: its live vtable resolves to the target
  kernel's unslid `IOMemoryMap` vtable at `0xfffffff007ab4820`, whose class
  registration proves an object size of `0x58`.
- Target-kernel accessors and the live object agree on `fMemory=+0x10`,
  `fOffset=+0x20`, `fAddress=+0x28`, and `fLength=+0x30`. The live map points
  back to descriptor 1, has zero offset, length `0x8`, and exposes the existing
  kernel virtual address `0xffffffec9be40000` for physical `0x206050000`.
- Existing static analyzers resolve the inspected SPTM/TXM anchor
  relationships and selected Titan kernel/GFX patchfinder relationships for
  the sample firmware.
- Each packaged GFX firmware slice contains one `0x7777777777777700` RTKit
  marker occurrence in `__TEXT` at `0xffffff8000000990`. The surrounding bytes
  belong to the executable image, not the live reset-vector structure, so an
  offline or VM scan cannot recover `gfx_data_pa` or `gfx_ttbr_pa` from it.
- The exact `gfx-asc` DeviceTree node contains only the `0x06400000/0x6c000`
  register range and the `0x06050000/0x8` IORVBAR range. Its RTBuddy nub adds
  firmware and power-management metadata, but neither node contains a reset
  vector, a GFX data physical address, or a GFX page-table base.
- The observations used for this work were bounded and read-only. No kernel
  write, GPU command queue, direct physical write, or MMIO access was used.

## Executed Bounded Probes

- Property metadata was read in blocks of four entries, restoring the disabled
  configuration and confirming HTTP `403` after every successful capture.
- String reads were limited to the exact length proven by each OSSymbol's
  packed length field.
- `segment-ranges` metadata was read first. Only after its `OSData` length was
  validated as `0x40` did a second probe read exactly eight 64-bit words, for
  a total of 64 bytes and two statically proven 32-byte descriptors.
- The `segment-names` key and `OSData` metadata were validated independently.
  A subsequent exact 14-byte payload read closed the connection before a
  capture file was produced. The disabled configuration was restored over USB
  and the payload read was not retried automatically.
- OSArray enumeration was limited to its proven count of two.
- IOGeneralMemoryDescriptor reads were limited to fields validated by Apple XNU
  source and the target kernel's virtual methods.
- An initial two-descriptor attempt to follow `_mappings` terminated Filza.
  The configuration was restored to disabled over USB. Its replacement used a
  single descriptor, static `OSSet` validation, and count-first collection
  reads; each stage succeeded and restored the disabled configuration with an
  HTTP `403` check. The stages must not be collapsed or exceed the proven
  collection count.

## Implemented but Unvalidated

- Offline tooling under `tools/a15_ios26` reproduces SPTM/TXM and Titan
  patchfinder assumptions without executing target code.
- The current working tree contains guarded iOS 26 parsing work for Titan,
  including nested AGX fence-layout decoding, IOMachPort object discovery, and
  the two-argument hibernation call shape.
- The iOS 26 AGX command and relaxed-fence anchors are unique in the inspected
  `AGXG14P` fileset. The in-app fallback now requires that uniqueness and
  cross-validates the independently decoded nested slot (`0x152a0`), map
  (`0x50`), and buffer (`0x498`) offsets before accepting the layout.
- Both GFX firmware slices contain exactly one strengthened iOS 26 hibernation
  anchor. Its instructions store `X0` in the per-CPU hibernation-context array,
  store `X1` in the adjacent FP-context array, and test `X1` before saving FP
  state; the guarded two-argument call shape now depends on that complete ABI
  sequence rather than the four-instruction prologue alone.
- The in-app legacy `IOMemoryMap::wireRange` finder now rejects zero or
  implausibly large field offsets, so the target's false `+0x260` match cannot
  silently enter Titan's offset table.
- Its iOS 26 fallback now requires one unique ten-instruction accessor anchor
  in the target kernel and derives `fAddress=+0x28` from the matched `LDR`;
  there is no unanchored hard-coded field offset.
- Titan refuses iOS 26 command-buffer setup and direct IORVBAR/MMIO mapping
  while the later Titan execution chain remains unvalidated.
- The unsupported target now exposes a separate `Run Diagnostics` action. It
  records target identity, SPTM presence, packaged Titan metadata, and explicit
  blocked/not-reached checkpoints to the UI, USB system log, and
  `Documents/a15-ios26-diagnostic.json`. It never instantiates `DOJailbreaker`
  or calls Titan, GFX, kernel-write, MMIO, or physical-write code.

These items are research scaffolding. They have not established an end-to-end
physical-write primitive and must not be interpreted as exploit support.

## Phase 3 Binary and App-Owned Memory Preflight

The next device diagnostic advances one bounded step beyond metadata selection:

- It reads the already packaged ClearSword and DarkSword executables as data.
- It validates their 64-bit ARM Mach-O headers and load-command bounds, then
  records `LC_BUILD_VERSION`, linked dylibs, file size, and three static marker
  strings. It does not load either framework or resolve an entry point.
- It reads `hw.pagesize`, `hw.cputype`, and `hw.cpusubtype` through `sysctlbyname`.
- It allocates and immediately deallocates one page in `mach_task_self`. The
  page is never written, shared, remapped, or exposed to an I/O service.
- It writes `Documents/a15-ios26-diagnostic-v3.json` with schema
  `dopamine.a15-ios26.device-diagnostic.v3`.

The phase remains diagnostic-only. It does not create an IOSurface, request a
PurpleGfxMem mapping, call either exploit, create sockets, issue GPU work, or
access SPTM/TXM. The integration checker explicitly rejects those calls from
the diagnostic body.

The reproducible phase 3 build completed successfully on 2026-10-15:

- Source commit: `1faefa50ff2f6507833806da1a217a449d28d4dc`
- GitHub Actions run: `38693388683` (successful in 11m 9s)
- Artifact: `Dopamine-A15-iOS26-diagnostic-v3-1faefa5.ipa`
- Size: `55,447,669` bytes
- SHA-256: `88A20F9CD764492BD3D8C6528A9AC01F3953B6C46E5D52F346F25DC925ABC790`

Post-build inspection confirms the v3 schema and output filename in the main
executable, the packaged ClearSword and DarkSword frameworks, and Titan's
unchanged declared support range of iOS `16.1` through `17.3.1`. Device
observations were collected from the USB-connected target on 2026-10-15. The
report was pulled as `a15-ios26-diagnostic-v3-device-20261015.json`, with
SHA-256 `B0368D9FFE288FB3C59F42D08E7C5E26A4BEC689D148BBD65222961A44BEC9EF`.

The bounded runtime and binary observations are:

- The target reports matching `vm_page_size` and `hw.pagesize` values of
  `16,384` bytes. Allocation and deallocation of one app-owned page both return
  success, and `memory_written` remains false.
- ClearSword is a valid ARM64 Mach-O of `93,920` bytes with valid load-command
  bounds, minimum iOS `15.0.0`, and SDK `26.5.0`.
- DarkSword is a valid ARM64 Mach-O of `112,464` bytes with valid load-command
  bounds, minimum iOS `15.0.0`, and SDK `26.5.0`.
- Both binaries link IOSurface and contain the three expected static marker
  strings, but neither framework was loaded or invoked by the diagnostic.
- The selector remains `BLOCKED` at `ppl-bypass-missing`: two kernel metadata
  candidates, no PPL candidate, no runtime kernel read/write primitive.
- Titan command buffers remain `BLOCKED`; physical write and SPTM/TXM runtime
  response remain `NOT_REACHED`.

## Phase 4 Static Symbol Inventory and Standard IOSurface Preflight

The phase 3 packaged frameworks were inspected offline with
`tools/a15_ios26/analyze_macho_preflight.py`. The tool parses the Mach-O symbol
metadata and code-signature bounds directly from bytes; it cannot load or
execute the target image.

The generated inventories are `clearsword-macho-preflight-v1.json` (SHA-256
`D10EB05832FA4ABEA3CAE078DEA823EF7F712086FEC6B7423156C478050CD7F2`) and
`darksword-macho-preflight-v1.json` (SHA-256
`9B3C8E07A46A3D85CF0D0B337414287F9E4B6E594EA013F94B80B3A843435C1F`).

- ClearSword contains 343 symbols, including 88 imports and 37 exports.
- DarkSword contains 437 symbols, including 91 imports and 78 exports.
- Both import three IOSurface functions, Mach VM functions, socket functions,
  and file read/write functions. DarkSword additionally imports four direct
  IOKit functions.
- Both export their exploit entry points and early kernel read/write helpers.
  This confirms that invoking either entry point would cross directly into the
  invasive chain; phase 4 therefore does not load either framework.

The phase 4 device diagnostic instead creates one ordinary private `16x16`
IOSurface with a four-byte element size, reads only its public dimensions and
allocation size, and immediately releases it. Static guards reject base-address
access, Mach-port creation, page prefetching, memory-region selection, IOKit,
socket, exploit, GPU, kernel-write, and SPTM/TXM calls from the diagnostic body.
The report schema is `dopamine.a15-ios26.device-diagnostic.v4`, written to
`Documents/a15-ios26-diagnostic-v4.json`.

The reproducible phase 4 build completed successfully on 2026-10-15:

- Source commit: `aac651dceed2864a9e9b8426e749d0a438e823a2`
- GitHub Actions run: `38697310661` (successful in 11m 27s)
- Artifact: `Dopamine-A15-iOS26-diagnostic-v4-aac651d.ipa`
- Size: `55,448,017` bytes
- SHA-256: `F0A09788B46FE6D0614D46ED31EE909DD97A9AF1E16A3BB190763FD36C0D0BD6`

Post-build inspection confirms the v4 schema, output filename, bounded
IOSurface checkpoint, and all five negative safety flags in the main
executable. Titan's declared iOS `16.1` through `17.3.1` range is unchanged.

The phase 4 diagnostic completed on the USB-connected target on 2026-10-15.
Its 21 checkpoints were pulled as
`a15-ios26-diagnostic-v4-device-20261015.json`, with SHA-256
`B24D91C86D3251446730207D6B97C8EF1DAB41CF00DB3AA6BA3DF3215523C3F5`.
The standard IOSurface result is `PASS`: width `16`, height `16`, bytes per row
`64`, allocation size `1,024`, and `released=true`. Base-address access,
Mach-port creation, prefetching, memory-region selection, and IOKit calls all
remain false. The app-owned 16 KiB VM allocation/deallocation also remains
`PASS` with no write. Selector, kernel, Titan, and SPTM/TXM states are unchanged:
`ppl-bypass-missing`, `MISSING`, `BLOCKED`, and `NOT_REACHED`, respectively.

## Phase 5 Read-Only IOSurface Lifecycle and Boundary Trace

Phase 5 extends the ordinary private `16x16` IOSurface checkpoint with exactly
one `IOSurfaceLock`/`IOSurfaceUnlock` pair using
`kIOSurfaceLockReadOnly | kIOSurfaceLockAvoidSync`. It records the return codes
and seed values, then releases the surface. It does not obtain the base address,
read or write the surface contents, create a Mach port, prefetch pages, request
a memory region, or call IOKit. The report schema is
`dopamine.a15-ios26.device-diagnostic.v5`, written to
`Documents/a15-ios26-diagnostic-v5.json`.

The response-trace builder now accepts an optional bounded device diagnostic.
Its v2 output separates `selector.ppl_metadata` as the first metadata blocker
from `kernel.runtime_read_write` as the first runtime blocker. Request
generation, transmission, handler dispatch, and response receipt are all
explicitly false, while `protected_component_boundary` remains `NOT_REACHED`.
This prevents a successful app-owned allocation or IOSurface lifecycle from
being misreported as a protected-component response.

Two public reverse-engineering notes were used only as architectural comparison:

- `https://proteas.github.io/ios/2023/06/09/some-quick-and-discrete-notes-on-sptm.html`
  identifies separate SPTM/TXM firmware images, the kernel `__DATA_SPTM`
  segment, and dispatch-related strings.
- `https://newosxbook.com/bonus/sptm2.html` describes an iOS 17.1.1 flow in
  which XNU enters SPTM with `GENTER`, TXM enters with `SVC #0`, and SPTM routes
  calls through subsystem dispatch tables.

Those observations are not target-version evidence. They do not establish that
the A15/iOS 26.0.1 request boundary, handler, or return path has been reached.
The structured comparison is recorded in
`docs/SPTM_IOS17_IOS26_STATIC_COMPARISON.md`.
It also records the post-iOS-17 Titan hardening sequence and the bounded role
of `qemu-sptm`/`darwin-vm` as an emulator-based comparison environment.

The reproducible phase 5 build completed successfully on 2026-10-15:

- Source commit: `38abc22d40f9c439750089d3473c2c03f0224e6d`
- GitHub Actions run: `38700381273` (successful in 13m 42s)
- Artifact: `Dopamine-A15-iOS26-diagnostic-v5-38abc22.ipa`
- Size: `55,449,632` bytes
- SHA-256: `7198C453407AA069973BADDBDAE501FEB1C5B235FB5E7E326E72B1743BAF68C8`

Post-build inspection confirms the v5 schema and output filename, the exact
read-only plus avoid-sync lock mode, the single lock/unlock lifecycle, and the
negative `memory_written` marker in the main executable. Titan's declared iOS
`16.1` through `17.3.1` range remains unchanged.

The phase 4-backed response trace v2 is recorded as JSON with SHA-256
`431954B2507F5F0E633D6B6A9607C523EB29B5869C90B2F36281C2317A71D235`
and Markdown with SHA-256
`DEC0B82C5E536B7F0F0CF6329A411C5B9F0878AE6ED181E38F369A28D8284E6E`.

The phase 5 diagnostic completed on the USB-connected target on 2026-10-15.
Its 21 checkpoints were pulled as
`a15-ios26-diagnostic-v5-device-20261015.json`, with SHA-256
`D2FAF47166C6AA8A190A5449B00512CBC8A0BC584FF985CF72457B3850D7B5DF`.
The standard IOSurface result is `PASS`: width `16`, height `16`, bytes per row
`64`, allocation size `1,024`, lock status `0`, unlock status `0`, both seed
values `0`, and `released=true`. The exact lock mode is read-only plus
avoid-sync. Base-address access, Mach-port creation, prefetching, memory-region
selection, IOKit calls, and memory writes all remain false.

Rebuilding response trace v2 from the phase 5 report produces the same JSON
and Markdown hashes listed above because the boundary states are unchanged:
the first metadata blocker remains `selector.ppl_metadata`, the first runtime
blocker remains `kernel.runtime_read_write`, and the protected-component
boundary remains `NOT_REACHED`.

## Phase 6 Jailbreak Selection Dry Run

Phase 6 adds an ordered dry-run trace of the application jailbreak path. It
uses `DOExploitManager` to record the exploit choices that the real path would
make from packaged metadata and user preferences, then records the first
proven missing requirement. This is more precise than treating every
metadata-eligible framework as selected.

The trace keeps `gatherSystemInformation` as the earliest unexecuted stage.
It reports whether the three static inputs are already present, but it does not
call that method because the normal path can download images and start XPF.
It then records kernel, PAC, and PPL selection before marking exploit load,
exploit execution, physRW construction, privilege elevation, bootstrap work,
and protected-component access as not executed or not reached.

The report schema is `dopamine.a15-ios26.device-diagnostic.v6`, written to
`Documents/a15-ios26-diagnostic-v6.json`. Its `jailbreak_dry_run` object keeps
explicit false flags for image download, XPF startup, framework loading,
exploit entry points, kernel primitives, physRW, privilege changes, bootstrap
changes, and protected requests. This test can identify the first proven
selection blocker without claiming that a jailbreak attempt occurred.

The reproducible phase 6 build completed successfully on 2026-10-15:

- Source commit: `5d084b4376ae127b301e54946c4a752300ad22e4`
- GitHub Actions run: `38704278559` (successful in 6m 37s)
- Artifact: `Dopamine-A15-iOS26-diagnostic-v6-5d084b4.ipa`
- Size: `55,451,968` bytes
- SHA-256: `B7247DEC04706CEBB66338E0AB8906FB25C5B4D7DC8FAEF1DC6D6FFD652731EB`

Post-build inspection confirms the v6 schema and filename, the dry-run mode,
the first-proven-blocker and earliest-unexecuted-stage fields, and the explicit
no-load/no-entrypoint/no-protected-request evidence in the main executable.
Titan's packaged support range remains iOS `16.1` through `17.3.1`; no target
support metadata was widened. The phase 6 on-device result is pending.

## Remaining Hypotheses

- The iOS 26 AGX layout changes represented in the guarded Titan code may be
  sufficient for later stages only after the IORVBAR mapping is independently
  proven.
- The remaining target-specific AGX relationships may replace legacy Titan
  patterns that no longer match this kernel and GFX firmware.
- The two live `segment-ranges` descriptors describe physical, virtual, and
  remap ranges for two RTKit firmware segments. The uncaptured 14-byte
  `segment-names` payload is strongly inferred as `__TEXT\0__DATA\0` from the
  exact length, descriptor count, and comparative DeviceTree format, but it is
  not recorded as a live-proven value.

None of these hypotheses is permission to invoke mapping methods, dereference
MMIO, create a GPU command queue, or perform a write.

## Blockers

### MAPPING_VALIDATED_TITAN_EXECUTION_BLOCKED

The existing GFX IORVBAR mapping is proven without dereferencing it. Titan is
still blocked because the legacy `IOMemoryMap::wireRange` signature resolves an
impossible `+0x260` field offset on this kernel and is rejected as a false
positive. The target-specific accessor proves `fAddress=+0x28`, but the later
AGX command, fence, and execution relationships are not yet an end-to-end
physical-write primitive.

Consequences:

- Do not dereference the physical register address.
- Do not invoke `mapDeviceMemoryWithIndex` or create a new mapping.
- Do not set up Titan GPU command queues on iOS 26.
- Do not enable Titan for A15 / iOS 26.0.1 in `Info.plist`.
- Do not perform kernel, GPU, page-table, or MMIO writes.

## Next Steps

1. Validate the target-specific `IOMemoryMap` accessor anchor against
   additional iOS 26 kernels before treating it as a family-wide finder.
2. Validate the resolved RTBuddy segment-field order against an additional
   iOS 26 kernel before treating it as a family-wide layout.
3. Validate each remaining iOS 26 AGX patchfinder result against the target
   kernel and GFX firmware without running a GPU command queue.
4. Keep all live probes count-bounded, read-only, and followed by restoration
   of the disabled configuration.
5. Review each later Titan stage in isolation before considering any on-device
   execution.
6. Change support metadata only after a separate end-to-end safety and
   correctness review.

## Application Policy

On iPhone14,2 with A15 and iOS 26.0.1, Dopamine presents this target as a
research target and returns unsupported before exploit selection. This policy
is checked by `tools/a15_ios26/check_research_integration.py`.
