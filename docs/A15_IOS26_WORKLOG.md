# A15 / iOS 26.0.1 Research Worklog

This file is the durable handoff for the `iPhone14,2` / `23A355` research
branch. It records confirmed evidence, unresolved hypotheses, generated
artifacts, verification, and the next bounded task. Conversation history is
not treated as the source of truth.

## Scope and Safety Boundary

- Target: `iPhone14,2` (A15), iOS 26.0.1, build `23A355`.
- Current phase: offline GFX/SPTM/TXM comparison and bounded diagnostic code.
- Not enabled: unrestricted physical write, privilege elevation, trust-cache
  installation, bootstrap preparation, or a general jailbreak path.
- Runtime-derived addresses and credentials are not recorded here.

## 2026-10-16: AGX / SPTM Producer Boundary Correction

### Completed

- Added `analyze_agx_uppl_producer.py` for a symmetric, offline comparison of
  the exact `21B91` and `23A355` AGX/SPTM images plus the `23A355` GFX slices.
- Decoded every RTKit PatchBay descriptor by its four-byte tag, declared value
  width, and inline default.
- Classified direct references, writers, relocations, chained fixups, and the
  Mach-O symbol flags for `__rtk_uppl_client_dispatch`.
- Compared `AGXFirmwareKextG14RTBuddy::requestFirmwareBinary` and the SPTM
  microPPL handoff anchors on both builds.
- Reconstructed the shared handoff layout on both builds and linked the
  `23A355` GFX PatchBay PPL-shared base to its direct firmware consumer.
- Recovered the protected UAT map-continuation frame checks and per-type
  mapping-policy lookup on `23A355`.
- Recovered the exact `21B91` predecessor despite its older symbol/API shape,
  and compared its direct frame-type switch with the `23A355` table policy.

### Confirmed Findings

1. The microPPL handoff magic remains `0x4b1d000000000002` on both builds.
   The existence of the handoff is therefore not the iOS 26 novelty.
2. The iOS 17 AGX firmware-provider method copies the core configuration and
   returns success for its accepted role, while retaining an assertion path
   for unsupported input. The iOS 26 method is an unconditional
   `Unimplemented` stub with the added `AGFIFirmwareRole` argument.
3. PatchBay supplies `BtpG` (GPTBAT base), `StpG` (GPTBAT size), `BlpP`
   (PPL-shared base), and `S2xG` (PPL-shared L2 physical address). No PatchBay
   descriptor names or targets the UPPL dispatch object.
4. In both `23A355` GFX slices, `__rtk_uppl_client_dispatch` is a zeroed,
   16-byte weak definition (`n_desc=0x80`) in `__DATA,__gxf_data`. It has one
   direct reader, no direct writer, no section relocation, no image
   relocation, and no chained fixup.
5. The prior statement that this proved runtime population was too strong.
   The corrected status is **zero weak default; producer unresolved**. The
   exact A15 payload may leave the UPPL route inactive unless an external
   protected producer is demonstrated.
6. `23A355` SPTM explicitly parses dynamic `%s-data-base` and `%s-data-size`
   properties for `gfx`, checks page alignment, and carries the diagnostic
   anchor `uat_register_gfx_data_segment`. This is a real producer-side bridge
   for the protected GFX data segment, but it does not yet prove that SPTM
   replaces the two UPPL words.
7. The shared SPTM/GFX handoff layout is symmetrical: SPTM magic at `+0x0`,
   GFX peer magic at `+0x8`, status at `+0x18`, 65 records at `+0x20` with
   stride `0x18`, ownership/state byte at `+0x638`, and auxiliary word at
   `+0x640`. SPTM initializes the final fields to `1` and `0`; GFX writes the
   peer magic and clears `+0x638` during bootstrap.
8. Both `23A355` GFX slices directly consume PatchBay's PPL-shared base. This
   proves the shared handoff, but not an UPPL handler-table producer.
9. The iOS 26 SPTM initializer stores dynamic GFX segment records at driver
   state `+0xb8`, stride `0x10`, with physical base at `+0x0` and page count
   at `+0x8`. It registers them through the protected-frame helper using
   selector `1`; the shared handoff uses selector `2`. The helper's exact
   compatibility branches map existing protected region type `2` to selector
   `1` and type `0x16` to selector `2`.
10. `sptm_uat_map_continue` at `0xfffffff0270a1590` acquires page-table
    frames as type `0x17`. Its mapping path reaches
    `iommu_register_mapping` at `0xfffffff0270caa58`, which passes `0x42` as a
    wildcard selector, reads the actual frame type from metadata `+0x2`, and
    then consults the per-type record table at `0xfffffff02701d720`. Its
    `0x60`-byte records contain the allowed-domain bitmap at `+0x8` and the
    maximum mapping class at `+0x10`. Segment registration is therefore not
    equivalent to permission to map arbitrary protected pages.
11. The reverse chain now reaches the UAT request producer. Endpoint 4 at
    `0xfffffff0270a1d58` acquires the segment-descriptor frame as type `0xb`
    and calls map continuation at `0xfffffff0270a1ef0`; endpoint 5 is the
    continuation function itself. Both belong to UAT dispatch ID `7`.
12. The chain reconnects structurally to GFX through the shared UAT/handoff
    state and the direct GXF dispatcher, but no static call edge yet proves
    that GXF command `0x10` invokes SPTM endpoint 4 or 5. The UPPL branch also
    remains separate and unresolved.
13. The type-`2` policy record has a zero allowed-domain bitmap and maximum
    mapping class `0`. Selector-1 `gfx-data` registration is therefore not a
    direct UAT leaf-mapping capability. The frame types with a nonzero domain
    bitmap or mapping class are `0`, `0xb`, `0xe`, `0xf`, `0x10`, `0x19`,
    `0x22`, `0x23`, `0x24`, `0x25`, and `0x3b`.
14. The immediate GFX firmware constructor for command `0x10` is the
    unsymbolized function at `0xffffff80000339f8`. It writes the command at
    `0xffffff8000033a08` and submits it through the GXF wrapper from
    `0xffffff8000033a28`. The envelope contains command `0x10` at `+0x0` and
    a payload pointer at `+0x8`; the payload stores original arguments `x1`,
    `x0`, `x2`, and `w3` at `+0x0`, `+0x8`, `+0x10`, and `+0x18`.
15. The firmware route reaches `__mmu_gxf_enter`, the direct GXF dispatcher,
    and `__rtk_mmu_map`, but no branch, endpoint ID, packet translation, or
    common protocol links it directly to SPTM UAT endpoints 4/5. The kernel
    `gfx-handoff-base` initializer at `0xfffffff008892a3c` builds the shared
    handoff but not the command packet; the local `RTBuddy64` fileset contains
    only two trampolines. The demonstrated relation is architectural, not a
    direct packet transfer.
16. Exact `21B91` uses `iommu_frame_acquire` at `0xfffffff0070882a8`, not
    `iommu_frame_acquire_type`. Its `sptm_uat_map_continue` at
    `0xfffffff00706fd5c` page-masks the leaf address with
    `0xfffffffff000` and calls `iommu_register_mapping` at
    `0xfffffff00706ff30` with legacy mode `0` or `1`.
17. The `21B91` registrar at `0xfffffff007088760` reads the actual frame type
    from metadata `+0x2` and has accepting branches only for
    `XNU_DEFAULT (0xb)` and `XNU_IO (0x19)`. This is a direct switch, not the
    authenticated per-domain/per-class table used by `23A355`.
18. The `21B91` request function at `0xfffffff0070703b4` saves the same five
    input registers as the iOS 26 producer and tail-calls map continuation at
    `0xfffffff007070484`. Its copy helper at `0xfffffff00706f68c` validates
    the segment-descriptor page as `XNU_DEFAULT (0xb)`. The structural
    producer role is therefore symmetric even though the protected policy
    generation changed.

### Route Consequence

The elevation research should no longer assume that handler indices can be
discovered by observing an inevitable UPPL registration. The direct GXF route
and the SPTM/GFX shared handoff are proven, but the handoff is not new. The
iOS 26-specific route now runs through dynamic GFX segment registration into
the protected-frame registry and then through independent frame-type, domain,
and mapping-type checks. The reverse pass now reaches UAT dispatch ID `7`, the
endpoint-4 request producer, the shared handoff, and the known GXF side. The
type-`2` `gfx-data` record is not directly mappable under that policy. GXF
command `0x10` and SPTM endpoints 4/5 are now classified as separate
interfaces over the same UAT/handoff architecture; a direct edge or common
packet format was not observed. The next offline targets are the kernel/RTKit
caller provenance of the unsymbolized GXF constructor and ownership/naming of
the frame types that actually permit mapping. The weak UPPL object remains a
separate unresolved branch.

### Verification

- `python -m unittest discover -s tools/a15_ios26 -p "test_*.py"`: 33 tests
  passed.
- `python -m py_compile tools/a15_ios26/analyze_agx_uppl_producer.py
  tools/a15_ios26/analyze_titan.py
  tools/a15_ios26/compare_gfx_security.py`: passed.
- Generated producer-boundary reports:
  `outputs/iphone-system/agx-uppl-producer/agx-uppl-producer.{json,md}`.
- Regenerated `titan-static-report.{json,md}` and the six-build
  `gfx-security-comparison.{json,md}` with the corrected producer status.

| Generated artifact | SHA-256 |
|---|---|
| `agx-uppl-producer/agx-uppl-producer.json` | `38B900761EFC0E62144932FB642B8DDB2CAF08858AB03D1547B375566A6E9D9B` |
| `agx-uppl-producer/agx-uppl-producer.md` | `C83E5136A2D0469B28B64EE252BF5F84D91AF20D4865E61C7F0FA08068BFEB0C` |
| `titan-static-report.json` | `2A8BBE2F8F5F05E15B7F79796067438F4D9E85DCBC4208036AC6DB43D8BE702C` |
| `titan-static-report.md` | `18D96EE3FF989A62F4B34D7510E4E4C74E22D5FB6EF80BC0E2BD112575D1BE48` |
| `gfx-differential/gfx-security-comparison.json` | `A353190DFFE0AE029B83BDC812F2C18FB052E6C4AEFA7D8747DB0791EE33F17E` |
| `gfx-differential/gfx-security-comparison.md` | `6EE23F7DFB6799DB3291568A05B822575B2726CC94AC021C174AA0E866F2A7CF` |

## 2026-10-16: GXF / UPPL Entry Analysis

### Completed

- Extended `analyze_titan.py` with a static GXF/UPPL/MMU contract analyzer.
- Extended `compare_gfx_security.py` with a symmetric dispatch and mapping
  comparison for every GFX firmware slice.
- Added unit coverage for immediate decoding and bounded range-guard
  classification.
- Regenerated `gfx-security-comparison.json` and
  `gfx-security-comparison.md` from the six exact A15 firmware payloads.
- Exact `23A355` GFX payload SHA-256:
  `3B245807D7A65241890E0D1D31566FED221082322DE784779824A2E11464A98B`.

### Confirmed Findings

1. Builds through `22B5045g` route the GXF entry directly to
   `__rtk_mmu_gxf_dispatcher`.
2. `23A355` adds a two-bit route at `__rtk_mmu_gxf_dispatcher_entry`:
   bit 0 selects `__rtk_mmu_gxf_dispatcher`; bit 1 selects
   `__rtk_uppl_client_dispatcher`. The bit-0 branch is tested first, so it wins
   if both bits are set.
3. The UPPL packet is at least `0x28` bytes: a 32-bit handler index at `+0x0`
   and four 64-bit arguments at `+0x8`, `+0x10`, `+0x18`, and `+0x20`.
   Dispatch checks the index, rejects a null handler, and transfers with
   authenticated `BRAAZ`. The observed rejection statuses are `0x80000003`
   for an out-of-bounds index and `0x8000000b` for a null handler.
4. The packaged `23A355` dispatch state contains a zero handler count and zero
   table pointer. The 16-byte `__rtk_uppl_client_dispatch` object is a weak
   data symbol; its only direct text reference in GFX is the dispatcher and no
   local writer or table signer was found. Runtime population is not proven;
   this payload cannot map an index to `map`, `unmap`, or `update_mapping`
   without inventing evidence.
5. The direct GXF `map` path includes a separate bounded range guard before
   entering `__rtk_mmu_map`. The mapping handlers themselves call
   `_mmu_get_tt_info` to validate translation-region bounds but do not contain
   that separate ingress guard.
6. `_mmu_get_tt_info`, `_mmu_get_page_table`, and the public mapping facades
   are structurally equivalent across `22A3354`, `22B5045g`, and `23A355` for
   the observed range checks.
7. `23A355` adds attribute class `0x8000`, translated to descriptor value
   `0x419`. Older compared builds expose classes `0`, `0x100`, `0x200`,
   `0x400`, `0x800`, `0x2000`, and `0x4000`.
8. `23A355` adds a context-switch guard in
   `__rtk_mmu_switch_region_base_by_contextID`: it reads state byte `+0x638`
   and conditionally requires bit 0 of argument `x2`.
9. The direct GXF commands remain `0x10` map, `0x11` update, and `0x12` unmap.
   Their observed handler contracts are map `(physical page, virtual page,
   page count, attributes)`, update `(virtual page, page count, attributes)`,
   and unmap `(virtual page, page count)`, with `0x4000`-byte pages.

## 2026-10-16: SPTM UAT Endpoint Expansion

### Completed

- Extended `analyze_sptm_txm.py` to decode null-terminated IOMMU endpoint
  tables with their authenticated chained handlers and referenced anchors.
- Regenerated symmetric v10 reports for exact `21B91` and `23A355` images.
- Added a unit test for the `0x10`-byte endpoint record and null terminator.

### Confirmed Findings

1. The UAT registration identity is unchanged: dispatch table ID `7`, domain
   permission mask `0x2` on both builds.
2. The UAT endpoint table grows from 7 handlers on `21B91` to 13 handlers on
   `23A355`.
3. `21B91` exposes anchored endpoints for init state, map table, prepare
   firmware unmap begin, unmap begin, set context ID, and get info. One entry
   has no exact `sptm_*` string anchor.
4. `23A355` exposes init and destroy state, map and unmap table, map continue,
   prepare firmware unmap begin and continue, unmap begin and continue, set
   and remove context ID, and get info. One entry at index 4 has no exact
   `sptm_*` string anchor; the reverse call-graph pass now identifies it as
   the request producer that calls index 5 / `sptm_uat_map_continue`.
5. The `23A355` UAT table is at `0xfffffff0270180d0`, uses `0x10`-byte
   records, contains 13 authenticated chained function pointers, and is
   followed by a null record.
6. SPTM's UAT code directly references validation for virtual ranges, context
   IDs, map options, physical addresses, table descriptors, and map segments.

### Symmetric Counts

| Driver | iOS 17.1.1 / 21B91 | iOS 26.0.1 / 23A355 |
|---|---:|---:|
| SART | 2 | 3 |
| NVMe | 3 | 9 |
| UAT | 7 | 13 |
| t8110dart table 3 | 9 | 17 |
| t8110dart table 4 | 1 | 4 |

### Interpretation Boundary

The new UPPL path is a useful static control-flow marker, but it is not a
demonstrated active route. The weak zero default has no observed local writer,
relocation, fixup, or PatchBay descriptor. The missing evidence is whether an
external protected producer replaces it at all on A15, which caller can select
bit 1, and what the `+0x638`, `x2[0]`, and attribute class `0x8000` guards mean.
Physical-page type checking is no longer wholly unknown: the `23A355` UAT
map-continuation path requires type `0x17` for page-table frames. Mapping
registration passes wildcard selector `0x42`, then reads the actual frame type
and applies its domain bitmap and maximum mapping-class policy.

The SPTM UAT endpoint table is a separate registered dispatch table. Its
expansion is strong evidence of a richer protected mapping lifecycle, but no
static reference yet proves that it populates GFX's zeroed
`__rtk_uppl_client_dispatch` state. Endpoint index 4 remains unnamed because
it has no direct `sptm_*` anchor, but its role as the request producer is now
established by its direct call to endpoint 5 rather than inferred from table
order.

## 2026-10-16: GXF Producer and Handoff Queue Provenance

### Completed

- Extended `analyze_agx_uppl_producer.py` to recover the direct GXF map
  constructor, its serialized caller, first-order producer functions, exact
  pointer references, and the handoff queue consumer contract.
- Correlated restricted frame-policy bitmaps with the named IOMMU descriptor
  IDs recovered from the same SPTM image.
- Regenerated the v5 AGX/UPPL producer report for both packaged GFX slices.

### Confirmed Findings

1. In slice `a000`, direct GXF map command `0x10` is constructed at
   `0xffffff80000339f8`, submitted through `0xffffff80000338a0`, and enters
   GXF through `__mmu_gxf_enter` at `0xffffff80000009c0`.
2. The constructor has one direct caller, the serialized wrapper at
   `0xffffff8000035334`. That wrapper is called twice by
   `__rtk_arm_start_bootstrap_area` at `0xffffff80000344f8` and
   `0xffffff800003450c`, immediately before the firmware installs its
   `TTBR0_EL1`, `TCR_EL1`, and `SCTLR_EL1` configuration. A second caller at
   `0xffffff800003d44c` belongs to an internal memory-map path.
3. The same structural route is independently present in slice `b000` with
   shifted addresses. Neither slice contains an exact data pointer to the
   constructor or a direct named RTKit message/endpoint ingress in this call
   chain. This is a local firmware mapping API, not evidence of a translated
   SPTM endpoint-4/5 packet.
4. The shared handoff is an explicit 65-entry flush queue. Context IDs are
   bounded to `0..0x40`; records start at `+0x20`, use stride `0x18`, and hold
   state at `+0x0` plus two payload values at `+0x8/+0x10`.
5. `__rtk_mmu_uat_flush_request` consumes and acknowledges those records.
   `__rtk_mmu_uat_idle` sets owner byte `+0x638`; `__rtk_mmu_uat_wake`
   clears it. The owner byte is therefore lifecycle state, not a frame type or
   an SPTM authorization result.
6. `XNU_CPUTRACE_PA_BUFFER (0x22)` and `XNU_CPUTRACE_VA_BUFFER (0x23)` use
   domain bitmap `0x84`, permitting domains 2 and 7. Domain 7 is the named
   `uat` IOMMU descriptor. `TXM_SEP_SECURE_CHANNEL (0x3b)` uses bitmap
   `0x120`, permitting domain 5 (`SART`) and unresolved domain 8. These are
   CPU-trace and SEP integration policies, not AGX leaf candidates.
7. The same 65-record queue contract and `+0x638` idle/wake owner byte are
   confirmed in both slices of every available comparison GFX image from
   `21D61` through `22B5045g`. This is not an exact `21B91` GFX comparison,
   but it rules out the queue layout itself as the iOS 26-specific delta.

### Frame-Type Names and Retype Callbacks

The authenticated SPTM frame-type name table at `0xfffffff027019228` removes
the remaining ambiguity around the restricted policy rows:

1. `0x22` is `XNU_CPUTRACE_PA_BUFFER`. Its retype-in and retype-out callbacks
   are both no-op `BTI c; RET` stubs.
2. `0x23` is `XNU_CPUTRACE_VA_BUFFER`. Its retype-in callback conditionally
   clears the halfword at frame metadata `+0x4` when the old type is `0x11`;
   its retype-out callback is the function anchored by
   `xnu_generic_retype_out`.
3. `0x3b` is `TXM_SEP_SECURE_CHANNEL`. Its callbacks are no-op stubs.
4. The table also identifies `0x17` as `XNU_IOMMU`, `0x19` as `XNU_IO`, and
   `0x1a` as `XNU_PROTECTED_IO`.

### Consequence

The route no longer has an undefined gap between the GFX handoff and command
construction. More importantly, the apparent `0x22/0x23` AGX branch was a
false lead: domain 7 permission belongs to the CPU-trace/UAT integration, not
to unidentified GPU leaf frames. The direct producer is now identified as
`acquire_uat_segments_page`. It acquires the descriptor page as
`XNU_DEFAULT (0x0b)`, copies validated segment records, and forwards
`num_segments` plus `map_options` to `sptm_uat_map_continue`.

On `23A355`, the leaf path masks the physical address with
`0xfffffffff000` and derives a requested mapping class of `1` or `2`. The
domain-7 table permits
`XNU_IO (0x19)` for both classes but does not permit
`XNU_PROTECTED_IO (0x1a)`. This corrects the earlier open-ended
`XNU_IO`/`XNU_PROTECTED_IO` branch. Exact `21B91` instead uses a direct
`XNU_DEFAULT`/`XNU_IO` allow switch and legacy modes `0/1`; those values must
not be relabeled as iOS 26 classes `1/2`. A new IPA is not justified until
offline segment provenance identifies which permitted leaf type is actually
used by the legitimate AGX path.

### Exact Next Task

1. Trace the segment physical-address provenance from
   `acquire_uat_segments_page` into the leaf registration call.
2. Decode the `map_options` lookup completely and associate each legitimate
   AGX segment kind with mapping class `1` or `2`.
3. Trace the exact legacy mode `0/1` branch meaning on `21B91` and compare its
   reference-accounting side effects with the iOS 26 class table.
4. Acquire an exact `21B91` GFX image only if byte-exact queue comparison is
   still needed; the nearest iOS 17 images already match the queue contract.
5. Keep the zero weak UPPL table as a separate branch unless a direct writer,
   relocation, fixup, or protected producer is recovered.
6. Keep this phase offline; do not emit or send a live UPPL/SPTM mapping
   request.

### HackTricks Orientation Review

The HackTricks iOS exploitation index is useful as a broad checklist, but it
does not change the current route:

1. Its physical-UAF/IOSurface material concerns obtaining kernel read/write.
   The current chain has already crossed that stage with ClearSword, so it
   does not answer the remaining SPTM frame-policy question.
2. Its PPL stale-TLB example describes an older PPL-specific vulnerability.
   It is not evidence that the same invalidation or accounting flaw exists in
   the higher-privilege SPTM boundary on `23A355`.
3. Its BinDiff workflow supports versioned kernelcache comparison, but our
   symmetric method must also include `sptm`, `txm`, and GFX firmware. A
   kernel-only diff would miss the exact frame-name, retype-callback, and UAT
   policy evidence recovered here.
4. The page contains broad mitigation summaries and approximate timelines,
   not build-specific proof. Apple confirms the architectural boundary:
   SPTM and TXM protect user and kernel page tables even against kernel write,
   and replace PPL on A15 or later. Therefore HackTricks is retained as an
   orientation source, not as evidence of an A15/iOS 26 bypass.

### arXiv and Public-Source Cross-Check

The 2025 paper *Modern iOS Security Features -- A Deep Dive into SPTM, TXM,
and Exclaves* independently supports the descriptor-and-rule-set model used by
the analyzer. Its main static sample is an iPhone 16 on iOS 18.4, with dynamic
work on an SRD running iOS 18.5 and an M4 iPad on iPadOS 17.5.1. It is not an
A15/23A355 offset source.

Useful symmetric facts from the paper are:

1. SPTM is the sole authority for frame retyping and mapping policy.
2. `XNU_DEFAULT -> XNU_IOMMU` and `XNU_IOMMU -> XNU_DEFAULT` are explicit
   lifecycle transitions in its iOS 18.4 baseline.
3. The iOS 18.4 frame table leaves `0x22/0x23` reserved, while the recovered
   23A355 table names those slots as the two CPU-trace buffer types. This is a
   concrete version delta and a warning against carrying numeric types across
   releases without the authenticated name table.
4. The paper's normal CPU `sptm_map_page` rule set is not the proprietary UAT
   `iommu_register_mapping` policy recovered here. The two must remain
   separate in the report.

The Tin-Z starter pack is retained only as an introductory diagram. It uses
generic page-type names, models GXF as ordinary EL2, and says there is no
public iOS 17 SPTM bypass; that state claim conflicts with the published Titan
range. It contributes no build-specific UAT selector, frame type, or callback.

The `cloverfield11/ios26-hypervisor-research` repository documents a separate
Stage-2 virtualization route on A16/iOS 26.4.1. It currently contains a README
and two commits, not a reproducible artifact bundle. Its Stage-2 frame types
are useful as another example of SPTM-gated mapping policy, but the repository
explicitly reports no bypass and does not connect guest VM dispatch to the
23A355 UAT/GPU path.

The local A15/23A355 artifacts independently confirm that this Stage-2 route
is present on the current target too. `devicetree.raw` contains
`has-virtualization` at file offset `0x36bf8`, with a four-byte value
`01 00 00 00`. SPTM reads that property through the xref at
`0xfffffff0270c3a74` and stores the resulting flag at
`0xfffffff027085820`; the same image names frame types `0x1f` and `0x20` as
`XNU_STAGE2_ROOT_TABLE` and `XNU_STAGE2_PAGE_TABLE`. Neither type appears in
the recovered UAT leaf allow set, so this confirms a separate SPTM service,
not an alternate UAT permission or a bypass.

The separation is visible in code as well: the exact image anchors guest
root acquisition at `0xfffffff0270d9d68`, guest entry at
`0xfffffff0270d9efc`, guest exit at `0xfffffff0270da1b8`, guest dispatch at
`0xfffffff0270dadfc`, and guest VA-to-IPA translation at
`0xfffffff0270db164`. The UAT policy rows for Stage-2 types `0x1f/0x20` have
zero allowed-domain bitmap and zero maximum mapping class. A bug in this VM
surface would be a separate vulnerability hypothesis; static availability
and an entitlement gate alone do not produce a host Stage-1 write primitive.

The v8 producer report now recovers the Stage-2 gate and state machine rather
than relying on names alone. The flag at `0xfffffff027085820` has exactly three
static readers: `cpu_root_table_retype_in` (`0xfffffff0270c81a8`),
`genter_dispatch_entry` (`0xfffffff0270cc4e8`), and `sptm_surt_alloc`
(`0xfffffff0270d5558`). The low-level GENTER path branches at
`0xfffffff02708caac` into `genter_dispatch_entry`. Dispatch target `0x1b`
selects service `0xc` and transitions `STATE_XNU -> STATE_XNU_GUEST`; target
`0x1c` selects service `0xd` and transitions `STATE_XNU_GUEST ->
STATE_SPTM_CALLED_BY_XNU`. Both entries use the same state-transition handler
at `0xfffffff02708c23c`. This bounds the guest route without identifying an
UAT permission edge or a bypass.

The v9 report continues from those transitions into the SPTM endpoint registry
and typed-page lifecycle. The static registry slot at `0xfffffff0270856e8`
selects table `0` at `0xfffffff02701c910`; `sptm_dispatch` bounds it to 50
endpoints. The guest subset is `0x18` (`sptm_guest_va_to_ipa`), `0x19`
(`sptm_guest_stage1_tlb_op`), `0x1a` (inferred Stage-2 TLB operation from its
root acquisition and `sptm_broadcast_tlbi` call), `0x1b`
(`sptm_guest_dispatch`), and `0x1c` (`sptm_guest_exit`). `sptm_guest_enter`
has no endpoint slot and is called only internally.

The same extraction proves that a guest root is not a caller-supplied arbitrary
page. `acquire_stage2_root_pt` requires `0x4000` alignment, the tracked SPTM
physical range, a valid in-flight reference, and exact frame type `0x1f`.
Endpoint `1` is `sptm_retype`; its root callback validates the geometry,
requires the virtualization gate for attribute index `1`, checks the encoded
VMID with `(vmid & 0xff01) == 1`, and atomically rejects duplicate VMIDs. Root
retype-out requires zero mapping references, executes `TLBI VMALLS12E1IS`,
and clears the VMID bitmap. Type `0x20` accepts only page-table subtype values
below `4`, and retype-out requires both mapping and nested reference counts to
be zero. This closes the easy Stage-2-shortcut hypothesis without exercising
any protected service.

Integrated with the live chain, this result defines a later contract rather
than a replacement path. The current on-device frontier remains the bounded
`backboardd` IPC census after ClearSword, Titan patchfinding, and IORVBAR
resolution have passed. IPC entry copy, GFX command-buffer submission,
unrestricted physical write, and protected-memory mutation remain unreached.
If those stages are eventually satisfied, Stage-2 still requires the typed
`0x1f/0x20` frame lifecycle, unique VMID ownership, and guarded GENTER state
transitions. Nothing in the recovered table grants the missing UAT leaf
permission or turns guest translation into a host Stage-1 write primitive.

The active IPC branch now has a v3 source revision. Apple's adjacent
`xnu-12377.1.9` layout confirms that each table entry is `0x18` bytes with the
signed object pointer at `+0x0` and `ie_bits` at `+0x8`. It also confirms that
the port header uses byte-sized `io_type` plus a three-bit `io_state`, replacing
the legacy bit-31 active marker and low-ten-bit type consumed by Titan's old
scan. The exact-target census now snapshots the complete entry before and
after following it, requires capability rights and an in-space object state,
and keeps the `IOMachPort` plus user-client vtables as the final attribution
checks. This revision remains read-only and still stops before IPC right copy
or GFX submission. GitHub Actions run `38871258849` built source commit
`30579d2c1b3cb32b2697be95fea188e91ed3806a` successfully, and package
inspection confirmed the v3 markers plus the explicit pre-copy stop. The
resulting `Dopamine-A15-iOS26-ipc-census-v3-30579d2.ipa` has SHA-256
`74EBB99892BDD649957748B64A31B05E07E07025686F3B2B3C6A57D5491C122B`.

The exact target ran this v3 build on 2026-10-16. The table decode was stable:
`0xc000` bytes, 2,048 complete entries, 1,649 entries with rights, zero
unstable snapshots, and stable final table/PID checks. The modern header split
produced 547 state-1 and 1,102 state-2 objects. Type `36` contained 85
`IOMachPort` wrappers and exactly two objects with the expected IOGPU
user-client vtable. The census stopped before IPC right copy and GFX
submission, and the device did not reboot. Because both exact matches occurred
after the 64-line generic-candidate cap, the follow-up v4 source adds a separate
bounded `MATCH` marker while preserving the same read-only execution boundary.
GitHub Actions run `38879780175` built source commit
`d55d66724ba09d82727f97d106de1ff740fcdeb3` successfully. Package inspection
confirmed `ipc-census-v4`, the exact `MATCH` records and counters, and the
explicit pre-copy stop. The resulting
`Dopamine-A15-iOS26-ipc-census-v4-d55d667.ipa` is 55,473,398 bytes with
SHA-256 `1F518E8F11F3815E896B51FDCA632C98F805304C435C59BF209D27F656BB36AB`.
The exact target ran v4 on 2026-10-16 without rebooting. It emitted exact
matches at IPC indices `537` and `1009`, with object addresses
`0xffffffdf5e176b30` and `0xffffffdf5e176ca0`. Both resolved to runtime vtable
`0xfffffff04b36fa10` (unslid `0xfffffff007b17a10`). The scan reported 2,048
entries, 1,669 rights, zero unstable snapshots, 85 type-36 IOKit connections,
two logged matches, no truncated match, and stable final table/PID checks. The
next bounded source revision profiles only the seven read-only downstream
fields needed to compare the two user clients; the pre-copy stop remains in
place.

Dataflow Forensics' less-indexed public `SPTM - The Last Bits` post independently
identifies UAT as dispatch table `7` on iOS 26 and explains that calls use the
`0x70000000#` family. Its earlier iOS 17 round-two post records UAT as subsystem
`7` with 13 services. This corroborates the analyzer's independent dispatch
attribution, but neither post publishes a Stage-2 or UAT bypass.

### Verification

- `python -m unittest discover -s tools/a15_ios26 -p "test_*.py"`: 49 tests
  passed.
- In-memory `compile()` check for `analyze_agx_uppl_producer.py`,
  `analyze_titan.py`, `analyze_sptm_txm.py`, and
  `check_research_integration.py`: passed.
- `python tools/a15_ios26/check_research_integration.py`: passed; the active
  diagnostic remains exact-target and privilege/bootstrap stages stay blocked.
- `git diff --check`: passed (line-ending warnings only).
- Generated report root:
  `outputs/iphone-system/gfx-differential/` outside the Git worktree.
- Symmetric SPTM/TXM v10 reports:
  `outputs/iphone-system/sptm-txm-static-report-v10.{json,md}` and
  `outputs/iphone-system/ios17_1_1-symmetric/sptm-txm-static-report-v10.{json,md}`.

| Generated artifact | SHA-256 |
|---|---|
| `gfx-differential/gfx-security-comparison.json` | `A353190DFFE0AE029B83BDC812F2C18FB052E6C4AEFA7D8747DB0791EE33F17E` |
| `gfx-differential/gfx-security-comparison.md` | `6EE23F7DFB6799DB3291568A05B822575B2726CC94AC021C174AA0E866F2A7CF` |
| `sptm-txm-static-report-v10.json` | `498757C670945373111A06727843CF73E785D985C924D165101400C09A90BBBE` |
| `sptm-txm-static-report-v10.md` | `80E58C6FFB4CAA83A8B427FA07F4A94B2304B2391F9BB5EF7DF42805458E4AEE` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v10.json` | `FF4B1B8AF5819404D8271DB340A253B619612C7BFD45C6365E65BD5EF2FBCC23` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v10.md` | `5D6DADB165E0B4B7AF39B77BCEBC05B41193F28478BF14673986BCCA793005D4` |
| `agx-uppl-producer/agx-uppl-producer.json` | `D1280C523ECFEEC08564AADD4AC8CCBD7B774A1E30F02BC5DE65A1C8DFFDCB6A` |
| `agx-uppl-producer/agx-uppl-producer.md` | `D0FEF4A3845B9D45FC01BEF825982F930E91785A87A295581B5B54CE49724BBA` |

