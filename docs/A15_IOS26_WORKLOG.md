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
   local writer or table signer was found. The table is populated at runtime;
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
   `sptm_*` string anchor.
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

The new UPPL path is the best static point of entry for continued research,
but it is not a demonstrated bypass. Because the handler table is supplied at
runtime, the missing evidence is the table producer and its policy: which
handlers it publishes, which caller can select bit 1, and where physical-page
ownership or type is checked. The `+0x638` byte, `x2[0]`, and attribute class
`0x8000` are raw facts; their security meanings remain unassigned.

The SPTM UAT endpoint table is a separate registered dispatch table. Its
expansion is strong evidence of a richer protected mapping lifecycle, but no
static reference yet proves that it populates GFX's zeroed
`__rtk_uppl_client_dispatch` state. Endpoint index 4 is deliberately left
unnamed on both builds rather than inferred from neighboring handlers.

### Exact Next Task

1. Trace callers and argument construction for UAT table ID `7`, focusing on
   the 21B91-to-23A355 endpoint expansion and index 4 without naming it by
   order alone.
2. Locate the separate producer that fills GFX's two-word
   `__rtk_uppl_client_dispatch` state.
3. Prove or disprove a registration bridge between that GFX producer and SPTM
   UAT table ID `7` using direct references or authenticated relocation data.
4. Trace validation of context ID, physical range, frame type, map options,
   and the new GFX `0x8000` attribute class.
5. Keep this phase offline; do not emit or send a live UPPL mapping request.

### Verification

- `python -m unittest discover -s tools/a15_ios26 -p "test_*.py"`: 24 tests
  passed.
- `python -m py_compile tools/a15_ios26/analyze_titan.py
  tools/a15_ios26/compare_gfx_security.py
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
| `gfx-differential/gfx-security-comparison.json` | `D51B52273BAB23F32C87DB3017273F8C742BCD09469C0F4BF86CF6E812E56820` |
| `gfx-differential/gfx-security-comparison.md` | `7FE30CE92E25E912182623B196FC6DB66B729EC45E9B87AA7CBE55DFE57FE6B8` |
| `sptm-txm-static-report-v10.json` | `498757C670945373111A06727843CF73E785D985C924D165101400C09A90BBBE` |
| `sptm-txm-static-report-v10.md` | `80E58C6FFB4CAA83A8B427FA07F4A94B2304B2391F9BB5EF7DF42805458E4AEE` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v10.json` | `FF4B1B8AF5819404D8271DB340A253B619612C7BFD45C6365E65BD5EF2FBCC23` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v10.md` | `5D6DADB165E0B4B7AF39B77BCEBC05B41193F28478BF14673986BCCA793005D4` |

