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

## Reproducible Diagnostic Build

- Source branch: `codex/a15-ios26-diagnostic-20261014`
- Source commit: `9009fd0ced07415d1693d110bb98b9bbe9d4c0f0`
- GitHub Actions run: `38573660872` (successful, 2026-10-14)
- Artifact: `Dopamine-A15-iOS26-diagnostic-9009fd0.ipa`
- Size: `55,436,031` bytes
- SHA-256: `ED6CCD193359C687946CFB1166BFC875B865A1144AD2F6A7E23E30922F448EA4`
- Application version: `3.0.11` (`com.opa334.Dopamine`)

The packaged Titan framework still declares support only for iOS `16.1` through
`17.3.1`. Although its historical device-family list contains A15, the exact
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

These items are research scaffolding. They have not established an end-to-end
physical-write primitive and must not be interpreted as exploit support.

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
