# Titan iOS 17 SPTM Bypass: Source-Level Reconstruction

## Scope

This note reconstructs the public Titan chain at the source-code level and
explains why it is described as a PPL/SPTM bypass. The primary sample is
`alfiecg24/Titan` at commit `bd962fd` (the repository's initial public
commit), cross-checked against littlelailo's Coruna/Rocket analysis and the
same-device iPhone14,2 firmware comparison already performed in this project.

The supported public window is iOS 16.1 through iOS 17.4 beta 3 on A14-A17.
The iPhone14,2/iOS 17.1.1 build 21B91 sample used by this project is therefore
inside Titan's published range. This is a source reconstruction, not a new
live execution of Titan on iOS 17.

## Mechanism in One Sentence

Titan does not forge an SPTM or TXM request or response. It obtains code
execution on the AGX coprocessor, makes AGX resume from hibernation with
attacker-supplied page tables, uses AGX to write one XNU page-table entry, and
turns that entry into a writable alias through which ordinary kernel R/W can
retarget a physical-memory window.

## Domain Transition

```text
userspace
   |
   | existing kernel R/W, permanent kalloc, bounded kmap
   v
XNU / IOGPU objects
   |
   | copied IOGPUDeviceUserClient + command buffers
   v
AGX firmware
   |
   | controlled 32-bit write -> power-thread saved-state pointer
   v
AGX ROP before hibernation
   |
   | fake TTBR1 + controlled resume SP -> core reset
   v
AGX ROP after hibernation
   |
   | AGX mapping exposes an XNU L3 page-table page
   | one 64-bit write creates a self-referencing AP PTE
   v
XNU writable page-table alias
   |
   | rewrite phys-window PTE, write data, restore PTE
   v
arbitrary physical write, including PPL/SPTM-protected pages
```

The security boundary is crossed indirectly. SPTM continues to enforce its
normal API and frame policy, but the final AP page-table mutation is performed
through a mapping created by AGX after the AGX microPPL boundary has already
been defeated.

## Prerequisites

Titan starts after a kernel exploit and expects more than a simple userspace
memory corruption:

| Primitive | Why Titan needs it |
|---|---|
| Kernel read/write | Walk XNU objects, inspect page tables, patch IOGPU fields, and prepare command buffers |
| Permanent `kalloc` | Keep fake L1/L2 tables and the self-reference table alive after the initial exploit state changes |
| Bounded `kmap` | Inspect AGX MMIO/firmware pages and obtain mappings that are still allowed before unrestricted physical write exists |
| Open IOGPU userclient | Submit the MDSID/fence command that supplies the first AGX-side write |

This distinction matters: the input primitive can read and write ordinary
kernel memory, but cannot directly remap every physical page protected by
PPL/SPTM. Titan manufactures the missing physical-write capability.

## Source Map

| Stage | Public implementation |
|---|---|
| Target and SoC setup | `src/titan.c:titan_init` |
| XNU/IOGPU patchfinder | `src/kernel_patchfinder.c:kpf_run` |
| Port reconstruction | `src/ipc_port.c:task_copy_ipc_entry` |
| Command queues and shared memory | `src/titan.c:titan_setup_command_buffers` |
| RTKit metadata | `src/titan.c:titan_parse_RTKit_information` |
| GFX image and physical roots | `src/titan.c:titan_copy_gfx_firmware`, `titan_resolve_gfx_physical_addresses` |
| GFX gadgets and contexts | `src/gfx_patchfinder.c:gfx_pf_run` |
| Initial AGX write | `src/gfx.c:gfx_write32` |
| Fake tables, hibernation ROP, and trigger | `src/titan.c:titan_run` |
| Stable physical write | `src/titan.c:titan_map_page`, `titan_physwritebuf` |

## Detailed Chain

### 1. Select the hardware model and protection regime

`titan_init` identifies A14-A17, selects the SoC-specific IORVBar physical
address, determines the RTKit stack-frame size, and marks A15 or newer running
post-iOS-16 kernels as SPTM systems. On A15, the public code uses IORVBar
`0x206050000` and an AGX text base of `0xffffff8000000000`.

This stage is configuration. It does not bypass SPTM and does not prove that
the later AGX assumptions still hold.

### 2. Recover a usable IOGPU connection

`titan_setup_command_buffers` finds `backboardd`, scans its IPC table for an
open `IOGPUDeviceUserClient`, and calls `task_copy_ipc_entry` to recreate a
usable Mach port in the current task. It then creates a command queue, a
notification queue, and two 16 KiB shared-memory objects.

The shared-memory handles are followed through the IOGPU namespace to their
kernel `IOMemoryMap` objects. Their kernel virtual addresses become Titan's
command buffers. This gives the process an authenticated path into the normal
IOGPU submission machinery without yet altering SPTM state.

### 3. Recover the running GFX firmware layout

Titan maps or reads IORVBar to recover the AGX reset vector. It scans the
reset-vector page for the RTKit metadata marker `0x7777777777777700`, from
which it obtains the GFX text size, data layout, and page-table information.

It then:

1. Copies the live GFX text image to userspace.
2. Resolves the GFX data-segment and translation-table physical addresses.
3. Maps those pages back through the available kernel mapping primitive.
4. Runs a GFX-specific patchfinder over the exact firmware image.

The GFX patchfinder locates the power thread, a writable job page, the
hibernation context, the full-register restore/`ERET` gadget, the 64-bit write
gadget, cache and TLB maintenance routines, the reset path, and the return-to-
RTKit state.

### 4. Obtain the first AGX-side arbitrary write

`gfx_write32` abuses the GFX MDSID/fence operation. During a normal drop-MDSID
command, GFX reads a counter, adds `0x100`, and writes it to a GPU virtual
address stored in `IOGPUMemoryMap`.

Titan temporarily changes three kernel-side fields:

1. `IOGPUMemoryMap->GPUVirtualAddress` becomes the desired AGX virtual address
   minus the current buffer offset.
2. The IOGPU fence value becomes the desired 32-bit value minus `0x100`.
3. The MDSID map and supported-count fields point at a controlled buffer.

Submitting the command makes GFX perform the final write. Titan then restores
the modified IOGPU fields. This primitive is required because the AGX power
thread's saved-state pointer is not directly writable through the pre-bypass
AP physical mapping path.

### 5. Prepare the fake translation hierarchy

`titan_run` allocates four 16 KiB regions:

| Allocation | Lifetime | Purpose |
|---|---|---|
| `fake_l1_table` | Permanent/global | Replacement AGX L1 table loaded into `TTBR1_EL1` |
| `fake_l2_table` | Permanent/global | Maps one selected AP L3 page-table page into AGX space |
| `self_ref_table` | Permanent/global | Becomes the AP-side writable alias for a page-table page |
| `phys_window` | Local | Virtual window whose PTE will later be retargeted to arbitrary physical pages |

The current GFX L1 entries are copied into `fake_l1_table` so normal AGX
mappings survive. One new L1 entry points to `fake_l2_table`; the first fake
L2 entry maps the AP L3 page-table page that contains `self_ref_table`'s own
PTE.

Titan also locates the distinct AP L3 page-table page containing the
`phys_window` PTE. It constructs `pte_to_store` by preserving the original
attributes of `self_ref_table`'s PTE while replacing its physical frame with
that `phys_window` L3-table page:

```text
pte_to_store = preserved_self_ref_attributes | phys_window_l3_table_pa
```

Once this value is installed, accesses through `self_ref_table` no longer
reach ordinary allocated data. They reach the page-table page containing the
`phys_window` PTE. That is the self-reference at the center of the bypass.

### 6. Build the two-phase AGX ROP chain

Each ROP frame is a complete saved register state. The invocation gadget
restores general, floating-point, exception, `X30`, and `ELR_EL1` state, then
executes `ERET`. `ELR_EL1` selects the operation and `X30` returns to the next
restore frame.

The pre-hibernation phase:

1. Restores the genuine power-thread saved-state pointer for normal recovery.
2. Calls the AGX hibernation routine.
3. Stores `fake_l1_table_pa` in the hibernation context's saved `TTBR1_EL1`.
4. Stores the original thread pointer and the post-wake ROP stack pointer.
5. Clears the L2 cache error status and flushes cache state.
6. Writes the ASC debug override used to reset the AGX core.
7. Spins until hibernation/reset occurs.

On affected iOS 17 firmware, resume restores `TTBR1_EL1` and the stack pointer
from this mutable context. AGX therefore wakes with the fake page tables and
continues at the post-hibernation ROP frames.

The post-hibernation phase performs one decisive 64-bit store:

```text
AGX store: self_ref_pte_gfx_addr <- pte_to_store
```

It then returns the power thread to ordinary RTKit execution. A userspace wait
thread observes the AP PTE change and publishes the alias only if the expected
value appears before the ten-second deadline.

### 7. Trigger the chain

The initial 32-bit AGX write targets bytes 1 through 4 of the power thread's
saved-state pointer:

```text
gfx_write32(power_thread.saved_state + 1, rop_chain_start >> 8)
```

The low byte is preserved because the chosen command writes four aligned
payload bytes starting at offset one. The next power-thread wake loads the
controlled state and begins the pre-hibernation ROP chain.

### 8. Turn one PTE write into unrestricted physical write

After the self-reference is installed, `titan_map_page` can reach the
`phys_window` PTE through ordinary kernel virtual R/W:

1. Save the original `phys_window` PTE.
2. Replace only its physical-frame field with the requested physical page.
3. Write through the unchanged `phys_window` virtual address.
4. Restore the original PTE.

`titan_physwritebuf` repeats this operation in 16 KiB page-sized chunks. The
published result is a physical-write callback, not a forged SPTM message.
Dopamine can then build its higher-level physical R/W and protected-memory
operations on top of that callback.

## Why This Defeats SPTM

SPTM normally owns page-table policy and prevents XNU from freely creating
writable aliases for protected physical memory. Titan separates the operation
into two domains:

1. AGX, running with attacker-controlled translation state after the microPPL
   failure, writes the one protected AP page-table entry that XNU cannot
   legitimately change.
2. XNU's existing virtual R/W follows the newly created alias and edits the
   `phys_window` PTE whenever a physical page must be accessed.

No SPTM selector is replayed, no TXM return structure is fabricated, and no
SPTM dispatcher branch is directly bypassed. The policy is defeated because
its protected metadata has been made writable through a coprocessor mapping.

This also explains a result from the symmetric 21B91/23A355 static analysis:
the SPTM request ABI, PAPT descriptors, and TXM trust-cache structures describe
the protected policy, but Titan's vulnerable control points live primarily in
AGX firmware and XNU's IOGPU/IPC integration. Searching only the SPTM image
cannot recover this chain.

## Patch Boundaries

| Boundary | Published change | Consequence |
|---|---|---|
| iOS 17.4 beta 4 | AGX no longer restores `TTBR0_EL1` from the mutable hibernation context and restores `TTBR1_EL1` from a hardcoded value | The fake translation root is not installed, so the microPPL bypass fails |
| iOS 18.1 beta 4 | AGX adds instruction PAC over critical saved-thread registers using `PACGA` | A forged saved state cannot directly drive the published `ERET` ROP chain |
| iOS 26 | Data PAC is added to `ipc_port->ip_nsrequest` | Titan's public IPC port reconstruction/stealing primitive no longer transfers unchanged |

These are independent barriers. Fixing the iOS 26 IPC-table decoder would
only reach the first command-buffer boundary. It would not restore the iOS 17
hibernation behavior or remove AGX instruction PAC.

### Symmetric GFX build differential

The Apple GFX payloads for iPhone14,2 were extracted directly from the IPSWs
for 17.3.1 (`21D61`), 17.4 beta 3 (`21E5200d`), 17.4 beta 4 (`21E5209b`),
18.0 (`22A3354`), 18.1 beta 4 (`22B5045g`), and 26.0.1 (`23A355`). Every
image was processed by the same instruction census.

| Build | TTBR0 writes | TTBR1 writes | PACGA chains | Resume behavior |
|---|---:|---:|---:|---|
| `21D61` | 5 | 4 | 0 | Restores hibernation `TTBR0`/`TTBR1` from `X29`/`X30` |
| `21E5200d` | 5 | 4 | 0 | Restores hibernation `TTBR0`/`TTBR1` from `X29`/`X30` |
| `21E5209b` | 4 | 3 | 0 | The mutable pair is gone; a helper-derived `X0` is written to `TTBR1` |
| `22A3354` | 4 | 3 | 0 | Fixed/helper-derived resume root; no decoded PACGA chain |
| `22B5045g` | 4 | 3 | 7 | Four signature-storage and three comparison-guard candidates |
| `23A355` | 4 | 3 | 7 | Fixed/helper-derived resume root plus authenticated saved-state paths |

Counts are identical in the two packaged firmware slices for each build. The
beta 3/beta 4 delta is direct: beta 3 executes `MSR TTBR0_EL1, X29` followed by
`MSR TTBR1_EL1, X30`; beta 4 removes both and instead calls a helper before
`MSR TTBR1_EL1, X0`. This confirms the published 17.4 beta 4 patch boundary on
the exact A15 device family. None of these iOS 17 payloads contains a decoded
PACGA chain. iOS 18.1 beta 3 (`22B5034e`) was not distributed for
`iPhone14,2`, so it cannot provide a same-device A15 baseline. The exact
same-device transition is instead 18.0 `22A3354` from September 16, 2024 to
18.1 beta 4 `22B5045g` from September 17: the census changes from zero to seven
PACGA chains per slice while the TTBR counts remain 4/3. The same four local
signature-storage and three comparison-guard candidates remain present in
23A355.

### Independent 23A355 confirmation

The two AGX hardening changes are visible in this project's exact iOS 26.0.1
GFX image, not merely inferred from Titan's README. The following are unslid
offline-analysis addresses and must not be treated as runtime addresses.

In the resume path at `0xffffff8000001478`, the firmware constructs a fixed
data address, calls a helper at `0xffffff80000015f0`, and then executes:

```text
0xffffff8000001484  BL   0xffffff80000015f0
0xffffff8000001488  MSR  TTBR1_EL1, X0
```

The helper transforms the eight bytes supplied from that firmware data slot.
The value written to `TTBR1_EL1` is therefore no longer loaded from the
attacker-editable hibernation-context field used by Titan on affected iOS 17
builds.

The full-register restore path still contains the recognizable `ERET` gadget,
but immediately before the restore it computes and verifies a chained
signature:

```text
0xffffff8000001f24  PACGA X1, X2, SP
0xffffff8000001f28  PACGA X1, X3, X1
0xffffff8000001f2c  PACGA X1, X30, X1
0xffffff8000001f30  PACGA X1, X16, X1
0xffffff8000001f34  PACGA X1, X17, X1
0xffffff8000001f38  LDR   X2, [SP,#0x340]
0xffffff8000001f3c  CMP   X1, X2
0xffffff8000001f40  B.NE  0xffffff8000001f40
0xffffff8000001f54  ERET
```

Consequently, the presence of the old restore gadget, write gadget,
hibernation context, and command-buffer structures on 23A355 is architectural
continuity, not evidence that Titan's original control-flow or TTBR1
substitution remains exploitable. The local static analyzer's adapted `PASS`
means that structural anchors were found; it does not override these two
hardening checks.

### 23A355 replacement-path candidates

The same exact firmware contains two families of routines that are relevant to
the missing replacement primitives. Their presence narrows the investigation,
but does not establish that either interface is attacker-reachable.

First, 23A355 contains both PACGA signature producers and consumers. The named
routine `__rtk_sign_initial_thread_state` at `0xffffff8000001668` prepares a
new thread context with a fixed firmware entry point, an EL-derived value, and
zeroed remaining signature inputs. It then reaches a helper at
`0xffffff8000001610` that chains five `PACGA` operations and stores the result
at context offset `0x340`. The observed initialization caller at
`0xffffff8000036acc` supplies a firmware-owned context and selects EL1 or EL2.
This is a legitimate signer, but it is not yet a signing oracle: the static
path constrains the program counter and other signed fields, and no interface
that signs arbitrary caller-controlled state has been established.

The exception and hibernation vectors contain additional producer/consumer
pairs. Signature-producing chains start at `0xffffff8000001c20`,
`0xffffff8000001e10`, and `0xffffff80000023dc`; guarded comparison chains start
at `0xffffff8000001d64`, `0xffffff8000001f24`, and
`0xffffff80000024d8`. This creates concrete targets for checking a possible
time-of-check/time-of-use gap or replay boundary. It does not by itself show
that a signed state can be changed after signing, transplanted to another
context, or replayed across reset.

Second, 23A355 exposes a separate MMU management surface:

- `__rtk_mmu_switch_region_base_by_contextID`
- `__rtk_mmu_map`
- `__rtk_mmu_unmap`
- `__rtk_mmu_update_mapping`
- `__rtk_mmu_switch_region_base`
- `__rtk_mmu_gxf_dispatcher_entry`
- `__rtk_uppl_client_dispatcher`

`__rtk_mmu_switch_region_base` at `0xffffff8000049170` accepts a region
selector, a translation-table base, and a TCR-size value. It writes the table
base to `TTBR0_EL1` or `TTBR1_EL1` and updates `TCR_EL1`. Its context-ID wrapper
resolves a registered table base before calling it. The UPPL dispatcher loads a
handler from a firmware table and transfers through authenticated `BRAAZ`.
These routines prove that legitimate mapping authority exists independently of
the fixed hibernation-resume root. The unresolved questions are whether the
host can reach the relevant dispatcher entries, how context IDs and physical
ranges are validated, and whether micro-PPL restricts the resulting mappings.
The direct caller of the UPPL dispatcher is the protected
`__rtk_mmu_gxf_dispatcher_entry`; the same image exposes boot-time patch fields
named `uat_gptbat_base`, `uat_gptbat_size`, `uat_ppl_shared_base`, and
`uat_ppl_shared_l2_phys`. This localizes the likely authorization boundary to
the GXF/UPPL request path and its PPL-shared ranges.

Public UAT implementations reinforce that boundary. AGX normally maps pages
backing validated GPU objects into one of multiple UAT contexts, with a shared
firmware region and an explicit AP/firmware handoff around table updates and
TLB invalidation. XNU's SPTM pmap data also records IOMMU ownership and mapping
state for physical pages. The useful research predicate is therefore narrower
than "can AGX write memory": it is whether the UPPL/UAT path can be made to
accept an AP/SPTM-owned page as a GPU-writable destination without an
authorized type transition. DART is a secondary path because it would still
require a controllable DMA endpoint and acceptance of the same protected page.

The offline analyzer now inventories every TTBR write, PACGA chain, ERET site,
and named signing/MMU candidate in each GFX slice. The companion symmetric
comparator applies the same census to every historical build so that changes
between 17.4 beta 3, 17.4 beta 4, and 23A355 are measured rather than inferred.

The symmetric dispatch pass now narrows this further. Through `22B5045g`, the
GXF vector enters `__rtk_mmu_gxf_dispatcher` directly. On `23A355`, bit 0 of
the entry selector retains that route and bit 1 selects
`__rtk_uppl_client_dispatcher`. The UPPL packet contains a 32-bit index and four
64-bit arguments, checks both bounds and a null handler, then transfers through
`BRAAZ`. Its packaged count and table pointer are both zero, proving that the
handler table is runtime-populated and preventing a static assignment of
indices to `map`, `unmap`, or `update_mapping`.

The direct GXF `map` route has a separate range guard before
`__rtk_mmu_map`; the mapping handler itself retains only the translation-region
lookup through `_mmu_get_tt_info` plus attribute decoding. This places the
unresolved authorization boundary at the UPPL table producer rather than at
the handler body. `23A355` also adds encoded attribute class `0x8000` (emitting
descriptor value `0x419`) and a context-switch check over state byte `+0x638`
and argument bit `x2[0]`. These are exact static deltas, not assigned policy
names or evidence of reachability. The durable checkpoint and next analysis
task are recorded in [A15 / iOS 26.0.1 Research Worklog](A15_IOS26_WORKLOG.md).

## Mapping to the Current iPhone14,2 / 23A355 Trace

| Published iOS 17 stage | Current 23A355 result |
|---|---|
| Kernel exploit and kernel primitive | Passed with ClearSword; live Mach-O header validated |
| Kernel/IOGPU patchfinder | Passed on the exact target |
| IORVBar object traversal | Passed; descriptor physical range matched `0x206050000/0x8` |
| `backboardd` lookup | Passed; pid and unique `proc` reproduced |
| IPC table normalization/census | Root cause identified; bounded read-only path still stops before entry copy |
| `task_copy_ipc_entry` | Deliberately not reached by the exact-target safety guard |
| IOGPU command submission | Not reached |
| Initial `gfx_write32` | Not reached |
| AGX ROP | Not reached; public chain is also blocked by instruction PAC |
| Mutable hibernation `TTBR1_EL1` | Public iOS 17 assumption is patched; no iOS 26 equivalent established |
| Self-referencing AP PTE | Not reached |
| Physical-write callback | Not reached |

The local iOS 26 work has resolved changed hibernation and floating-point
context locations and the newer two-argument hibernation call shape. Those are
layout findings only. They do not demonstrate that iOS 26 restores an
attacker-controlled `TTBR1_EL1`, accepts an unauthenticated saved state, or
permits the protected PTE write.

## Practical Conclusion

For iOS 17, the bypass is a three-primitive composition:

```text
MDSID write32 -> AGX saved-state ROP -> hibernation TTBR1 substitution
             -> AGX writes AP self-reference PTE -> XNU retargets phys window
```

For iOS 26, an offset-only adaptation cannot recreate the chain. A viable
successor would need, at minimum, independent answers for all three patched
boundaries: acquiring the IOGPU capability, obtaining authenticated AGX
control flow, and crossing microPPL without mutable hibernation translation
roots. The current project has evidence for object/layout discovery, not for
those three replacement primitives.

## References

- [Titan repository and technical README](https://github.com/alfiecg24/Titan)
- [Titan `titan.c`](https://github.com/alfiecg24/Titan/blob/main/src/titan.c)
- [Titan `gfx.c`](https://github.com/alfiecg24/Titan/blob/main/src/gfx.c)
- [Coruna/Rocket deep dive](https://littlelailo.github.io/writeups/coruna.html)
- [Asahi Linux AGX architecture notes](https://asahilinux.org/docs/hw/soc/agx/)
- [m1n1 UAT implementation](https://github.com/AsahiLinux/m1n1/blob/main/proxyclient/m1n1/hw/uat.py)
- [m1n1 AGX handoff implementation](https://github.com/AsahiLinux/m1n1/blob/main/proxyclient/m1n1/fw/agx/handoff.py)
- [XNU SPTM pmap/IOMMU metadata](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/arm64/sptm/pmap/pmap_data.h)
- [Modern iOS Security Features: SPTM, TXM, and Exclaves](https://arxiv.org/abs/2510.09272)
- [AppleDB metadata for 18.1 beta 3 build 22B5034e](https://api.appledb.dev/ios/iOS%3B22B5034e.json)
- [The Apple Wiki iOS 18 beta firmware history](https://theapplewiki.com/wiki/Beta_Firmware/iPhone/18.x)
- [Apple XNU saved-thread PAC implementation](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/arm64/machine_routines_asm.s)
- [Same-device iOS 17/iOS 26 static comparison](SPTM_IOS17_IOS26_STATIC_COMPARISON.md)
- [A15 iOS 17.1.1 symmetric baseline](A15_IOS17_1_1_SYMMETRIC_BASELINE.md)
