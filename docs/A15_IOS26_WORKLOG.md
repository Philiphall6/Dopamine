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

### Exact Next Task

1. Recover callers and ownership for GFX firmware function
   `0xffffff80000339f8`, then identify the kernel/RTKit message that reaches
   it without assuming it is an SPTM endpoint call.
2. Assign owners/roles to the policy-allowed frame types, especially the
   domain-limited types `0x22`, `0x23`, and `0x3b`, using direct producers.
3. Map every reader and writer of the 65 handoff records and the `+0x638`
   guard, then compare those paths symmetrically with `21B91`.
4. Keep the zero weak UPPL table as a separate branch unless a direct writer,
   relocation, fixup, or protected producer is recovered.
5. Keep this phase offline; do not emit or send a live UPPL/SPTM mapping
   request.

### Verification

- `python -m unittest discover -s tools/a15_ios26 -p "test_*.py"`: 33 tests
  passed.
- `python -m py_compile tools/a15_ios26/analyze_agx_uppl_producer.py
  tools/a15_ios26/analyze_titan.py
  tools/a15_ios26/compare_gfx_security.py
  tools/a15_ios26/test_analyze_agx_uppl_producer.py
  tools/a15_ios26/test_analyze_titan.py
  tools/a15_ios26/analyze_sptm_txm.py
  tools/a15_ios26/test_analyze_sptm_txm.py`: passed.
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

