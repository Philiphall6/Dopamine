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
- Exact-length OSSymbol reads identified dictionary entry 17 as
  `IODeviceMemory`; entry 14 is `segment-ranges` and entry 18 is
  `IOReportLegend`.
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
- The observations used for this work were bounded and read-only. No kernel
  write, GPU command queue, direct physical write, or MMIO access was used.

## Executed Bounded Probes

- Property metadata was read in blocks of four entries, restoring the disabled
  configuration and confirming HTTP `403` after every successful capture.
- String reads were limited to the exact length proven by each OSSymbol's
  packed length field.
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
2. Validate each remaining iOS 26 AGX patchfinder result against the target
   kernel and GFX firmware without running a GPU command queue.
3. Keep all live probes count-bounded, read-only, and followed by restoration
   of the disabled configuration.
4. Review each later Titan stage in isolation before considering any on-device
   execution.
5. Change support metadata only after a separate end-to-end safety and
   correctness review.

## Application Policy

On iPhone14,2 with A15 and iOS 26.0.1, Dopamine presents this target as a
research target and returns unsupported before exploit selection. This policy
is checked by `tools/a15_ios26/check_research_integration.py`.
