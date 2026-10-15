# SPTM/TXM Static Comparison: iOS 17.1.1 and iOS 26.0.1

## Scope

This is a static, provenance-aware, same-device comparison. Both sides use
iPhone14,2/A15 images analyzed by the same unmodified offline analyzer. The
iOS 17.1.1 build 21B91 triplet was extracted directly from the Apple-hosted
IPSW with HTTP range requests; the iOS 26.0.1 build 23A355 triplet is the
previously extracted local sample. The comparison does not invoke SPTM, TXM, a
GPU command queue, or any protected-memory operation.

## Samples

| Property | iOS 17.1.1 local sample | iOS 26.0.1 local sample |
|---|---|---|
| Evidence type | Local static binary analysis | Local static binary analysis |
| Target | iPhone14,2 / A15 / t8110 | iPhone14,2 / A15 / t8110 |
| Build | 21B91 | 23A355 |
| Kernel SHA-256 | `34279BEABB02A3E7012E5430D6A3DA2775ACD5794426BB751717CC60165D453A` | Recorded in the local 23A355 extraction manifest |
| SPTM image | `sptm.t8110.release.bin`, 721,064 bytes | `sptm.bin`, 1,048,608 bytes |
| TXM image | `txm.iphoneos.release.bin`, 360,608 bytes | `txm.bin`, 458,784 bytes |
| SPTM SHA-256 | `775CECC5CBF6DCD1B4B62DEC709FD20DBE8660BCFA5AB0BC67613D9FFFDBD7AA` | `ED7781D2D82FE4818B85DD18C6B07DC172440EEECC2F7B33FC1E048313583F7C` |
| TXM SHA-256 | `D5C308F637C0FDB62C6776DCCF60C3AA9152F057ADD4D63049C01D08C953C87B` | `04CBCCBB1D986B2492C6430DA259C12579B58DE74795208202988739CB68A55E` |

Both extracted image pairs use the same unslid analysis bases, not reusable
runtime addresses: SPTM `0xfffffff027004000` and TXM
`0xfffffff017004000`.

The published NewOSXBook and Proteas notes remain architectural context only.
The binary comparison no longer depends on their hardware labels: its 21B91
provenance is the Apple IPSW `BuildManifest.plist`, which identifies `d63ap`,
`ApChipID 0x8110`, and the exact kernel, SPTM, and TXM archive entries.

## Architectural Comparison

| Area | iOS 17.1.1 observation | iOS 26.0.1 observation | Assessment |
|---|---|---|---|
| Component split | Separate SPTM and TXM images extracted | Separate SPTM and TXM images extracted | Confirmed continuity |
| XNU entry | 7 kernel `GENTER` instructions: four `#0`, then one each of `#1` through `#3` | 9 kernel `GENTER` instructions: five `#0`, then one each of `#1` through `#4` | Entry family confirmed; 23A355 adds one immediate and two occurrences |
| TXM entry | One `SVC #0` thunk | Two adjacent `SVC #0` thunks | Entry instruction confirmed on both builds |
| Dispatch | Nearby `x16` setup includes the same dynamic high-halfword wrappers and a boot descriptor ending in `0xf` | The corresponding `x16` setup patterns remain visible; the immediate stubs add `BTI` and `GENTER #4` | Selector construction is observable; endpoint/table identity remains unresolved |
| Page ownership | PAPT range management resolves; frame types use immediate bit masks | PAPT range management resolves; frame types use a global descriptor table with `0x60`-byte records | Confirmed continuity with a changed representation |
| Kernel integration | `sptm_get_page_table_refcnt`, `libsptm_init`, PAPT globals, and `SPTMArgs` resolve; descriptor-table fields are absent | `libsptm_init`, `sptm_args`, page-table refcount helper, and descriptor-table relationships resolve | Same roles, different frame-type policy model |
| TXM role | Trust-cache root and developer-mode storage resolve through direct `ADR` chains | Trust-cache root, developer-mode storage, and license relationships resolve | Strong static continuity |
| Runtime request | No request generated or transmitted by this project | No request generated or transmitted by this project | `NOT_REACHED` |
| Runtime response | No handler dispatch or response received | No handler dispatch or response received | `NOT_REACHED` |

## iOS 26-Specific Static Evidence

The iOS 26 SPTM image contains referenced relationships for
`papt_ranges_update`, compressed PAPT range count and storage,
`bootstrap_register_papt_range`, `bootstrap_retype_papt_range`,
`papt_update_mapping`, `sptm_update_papt`, and physical-range boundaries.
The associated strings enforce range overlap, frame type, mapping permissions,
and retype-state invariants. This is evidence that PAPT remains a central
protection mechanism, not evidence of a bypass.

The iOS 26 TXM image resolves the device-tree trust-cache range and one
candidate each for the trust-cache root and developer-mode storage. The kernel
image resolves the SPTM argument structure, `libsptm_init`, and the page-table
reference-count helper used by the current Dopamine static analysis.

## Symmetric Entry-Sequence Result

The v3 analyzer recognizes Apple's `GENTER` instruction from its raw opcode
family because the local Capstone build emits it as four data bytes. The
matching rule is `opcode & 0xffffffe0 == 0x00201420`; the low five bits are
reported as the immediate. `GEXIT` (`0x00201400`) does not match this rule.

On 21B91, TXM has one `SVC #0` at `0xfffffff01705405c`. A nearby four-`movk`
sequence writes every 16-bit lane of `x16` and branches to that thunk. On
23A355, TXM has adjacent thunks at `0xfffffff017064004` and
`0xfffffff017064010`; the same four-`movk` sequence branches to the first.
This confirms the entry mechanism but does not establish why the second thunk
exists.

The kernel-side census is:

| Build | `GENTER #0` | `#1` | `#2` | `#3` | `#4` | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 21B91 | 4 | 1 | 1 | 1 | 0 | 7 |
| 23A355 | 5 | 1 | 1 | 1 | 1 | 9 |

Both builds contain structurally matching `GENTER #0` wrappers that load
arguments through `x0`-`x7` and prepare `x16` with dynamic low bits plus a
high halfword of `2` or `3`. Both also contain a boot path that writes all four
`x16` lanes, ending with low value `0xf`, before `GENTER #0`. The iOS 26
immediate stubs add `BTI` landing pads and extend the visible immediate set to
`#4`. These are instruction-level similarities and differences only. The
analysis does not name an endpoint, map an SPTM dispatch table, issue a call,
or observe a return value.

## TXM Tail-Branch Descriptor Symmetry

The v4 analyzer walks backward at most twelve instructions from each direct
tail branch to a TXM `SVC #0` thunk. It reports an `x16` value only when the
walk defines all 64 bits through immediate `mov`/`movk` writes. Both builds
resolve the same seven raw descriptors:

| Raw `x16` descriptor | 21B91 direct tail branch | 23A355 direct tail branch |
| --- | --- | --- |
| `0x0000000100000001` | yes | yes |
| `0x0000000100000002` | yes | yes |
| `0x0000000100000003` | yes | yes |
| `0x0000000100000004` | yes | yes |
| `0x000000fd00000000` | yes | yes |
| `0x000000fe00000000` | yes | yes |
| `0x000000ff00000000` | yes | yes |

The sole 21B91 `SVC #0` thunk and the first 23A355 thunk each receive seven
direct tail branches with complete constants. The second 23A355 thunk has no
direct branch cross-reference in the decoded executable sections. That does
not prove it is unreachable: an indirect reference or a runtime-computed
target remains possible. No semantic endpoint names are assigned to these raw
values.

## SPTM Return and Validation Delta

The v5 report adds a raw SPTM transfer census and direct cross-references for a
small set of dispatch diagnostic strings:

| Static item | 21B91 | 23A355 |
| --- | ---: | ---: |
| SPTM `GENTER #0` | 1 | 1 |
| SPTM `GEXIT #0` | 4 | 7 |
| `dispatch_table_lookup` references | 2 | 2 |
| `dispatch_state_machine` references | 3 | 7 |
| `genter_dispatch_entry` references | 1 | 2 |
| `sptm_dispatch` references | 2 | 2 |
| `endpoint_id` references | 3 | 3 |
| `validate_sptm_dispatch_table_id` references | 0 | 2 |
| `validate_dispatch_endpoint_id` references | 0 | 1 |

The extra 23A355 `GEXIT` sites and named validator references are bounded
control-flow comparison candidates. A missing diagnostic string on 21B91 does
not prove the equivalent validation logic is absent, and an added string does
not identify a bypass branch.

## Symmetric Dispatch Guard Comparison

The v6 report recovers candidate functions, direct callers, direct branch
ingress, and bounded comparison/conditional-branch guards for the same anchor
set on both images. The added 23A355 validator names identify inlined checks;
they are not separately called functions. Their structural 21B91 counterparts
are present without those names.

| Role | 21B91 | 23A355 | Static delta |
| --- | --- | --- | --- |
| Main table registration | `0xfffffff00708891c`, 4 direct calls | `0xfffffff0270cb73c`, 5 direct calls | Same role; 23A355 also carries the named table-ID assertion |
| Direct table registration | `0xfffffff0070892b4`, 3 direct calls | `0xfffffff0270cc1ac`, 2 direct calls | Both require table ID `0..15`; 23A355 forwards into the main registrar |
| State machine / lookup | `0xfffffff007088ea8` | `0xfffffff0270cbb94` | State bound grows from `<17` to `<23`; event bound grows from `<12` to `<15` |
| SPTM dispatch | `0xfffffff0070894fc` | `0xfffffff0270cc2b0` | Endpoint representation and entry width change |
| GENTER dispatch entry | effective branch entry `0xfffffff0070893a4`; diagnostic candidate `0xfffffff0070893c4` | `0xfffffff0270cc43c` | 23A355 adds explicit endpoint-derived events `12`, `13`, and `14` |

The table-ID policy is continuous: both builds reject IDs above `15`, require
an unused slot, and check dispatch state before registration. The endpoint
policy is not byte-for-byte continuous:

- 21B91 rejects a low endpoint byte with any of bits `5..7` set, giving an
  effective `0..31` range; it also bounds the extracted table ID to `0..7`,
  indexes 8-byte endpoint entries, and rejects a null entry.
- 23A355 rejects when `(x0 & 0xfe) >= 0x32`, indexes 16-byte endpoint entries,
  and rejects a null table or null entry. Its registration path separately
  enforces the `0..15` table-ID bound.
- The state-machine action transfer remains authenticated on both builds. The
  newer image has larger state/event spaces and more direct ingress branches.

This closes the v5 ambiguity: the named iOS 26 checks are strengthened or
restructured counterparts of checks already present on iOS 17, not a newly
isolated residual bypass branch. Static evidence still cannot establish a
selector ABI, accepted protected request, or exploitable control-flow path.

## Authenticated Callback Path

The v7 report follows code-pointer materialization through registration and
the final indirect handler transfer:

| Static stage | 21B91 | 23A355 |
| --- | --- | --- |
| `sptm_dispatch` pointer references | 2 | 3 |
| Registration signing | `PACIZA x16` | `PACIZA x16` |
| Common registrations | IDs `0`, `1`, `2`; values `2`, `4`, `8` | IDs `0`, `1`, `2`; values `2`, `4`, `8` |
| Additional registration | Direct canonical-pointer table store | Conditional ID `0xa`, value `0x10`, plus a wrapper registration |
| Registrar storage | `XPACI`, then `{pointer, value}` store | `XPACI`, then `{pointer, value}` store |
| State-machine transfer | `BRAA` | `BRAA` |
| Endpoint handler transfer | Tail trampoline, then `BLRAAZ` | Tail trampoline, then `BLRAAZ` |

On 21B91, the principal materialization is at `0xfffffff0070731b4` and
registers through `0xfffffff0070892b4`; the endpoint tail branch at
`0xfffffff007089608` reaches trampoline `0xfffffff0070603d8`, whose final
transfer is `BLRAAZ x11`. On 23A355, the corresponding principal
materialization is at `0xfffffff0270a6ba4` and registers through
`0xfffffff0270cb73c`; the endpoint tail branch at `0xfffffff0270cc32c`
reaches `0xfffffff02708c3c4`, ending in `BLRAAZ x11`.

The authenticated-callback architecture is therefore continuous. The newer
image expands registration topology, but this comparison finds no downgrade
to an unauthenticated endpoint transfer and no missing PAC branch that could
be carried forward as a bypass.

## Result

The high-level division of responsibility is continuous from iOS 17.1.1 to
iOS 26.0.1: SPTM owns protected translation and frame-type policy, while TXM
owns code-signing and trust decisions. The normalized v2 analyzer reports
`PASS` for TXM, the SPTM image, and kernel integration on both builds.

The former incomplete 21B91 results had bounded static explanations. Direct
`ADR` chains now resolve the trust-cache root and developer-mode storage. Its
refcount helper is represented as `immediate_bitmask`, with masks
`0x00060100` and `0x00180200`; the 23A355 helper is represented as
`descriptor_table`, with `0x60`-byte records and a policy byte at offset `1`.
This normalization preserves the architectural difference instead of
inventing an iOS 17 descriptor table.

| Normalized artifact | SHA-256 |
| --- | --- |
| `ios17_1_1-symmetric/sptm-txm-static-report-v2.json` | `8EF8EBFF58B338F797178210FA9A0DA4E7EBA95A64598949F4F912DB199B5E34` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v2.md` | `86C04F1A9E3A3D2D50FBBFE034717D5F55F1EEFC48C93B6435ED69B0AEE82C9D` |
| `sptm-txm-static-report-v2.json` | `5E1BB0D9C7B8ED42288639F78B9AD1031E0B03C418F2E277B205D3876676BDE8` |
| `sptm-txm-static-report-v2.md` | `D800F9D162CB57493B0CA4544726F57588E537AF6EE02480C280871427652141` |

The v3 artifacts add only the symmetric entry-sequence census and bounded
instruction windows. Their hashes are:

| v3 artifact | SHA-256 |
| --- | --- |
| `ios17_1_1-symmetric/sptm-txm-static-report-v3.json` | `87658C6F24C2F8EE19A689DB90CCF52233A646B89D69D6F6CE0FCC372D2256B4` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v3.md` | `12E0077BCA191F920EA1A9DD704F9FED876140F29BE5C379307ACE011F65452D` |
| `sptm-txm-static-report-v3.json` | `8AE272D5F03990721D29180724BB59B4264056A445EDB0BCFBE4C9DDE7DAE5DA` |
| `sptm-txm-static-report-v3.md` | `F65226F1F2F3A715F3ED74280D914F39FD564201FB9B00DE6CDC152468D90FC6` |

The v4 artifacts add bounded direct-tail-branch provenance and complete raw
`x16` descriptor reconstruction:

| v4 artifact | SHA-256 |
| --- | --- |
| `ios17_1_1-symmetric/sptm-txm-static-report-v4.json` | `7A27B4FA55331664129D5AFCBA49FDBE98C639D6B4E2CA48927A849F5274A2D5` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v4.md` | `023C589FA9C1F59D8B8B8B2504946E212B10C8AEDBCB66EB937A0F7462027944` |
| `sptm-txm-static-report-v4.json` | `99329CFB9419C273C6F541325CF1DEC0BE69955CE93E3232B621B3823237C770` |
| `sptm-txm-static-report-v4.md` | `D798C5EF67CC22FA19F0140F9F93A3D85DDB0E07391EC8514FDB4A66E62B3993` |

The v5 artifacts add the SPTM transfer and dispatch-anchor census:

| v5 artifact | SHA-256 |
| --- | --- |
| `ios17_1_1-symmetric/sptm-txm-static-report-v5.json` | `D17DB9D0C299DECC4B465B1C063E498302983C71CA51EB2622C3F11CE415A202` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v5.md` | `382D5EF0054EBCF4015F55564B75023ADC0B57CF2BBFE7133C9575623CEDB94A` |
| `sptm-txm-static-report-v5.json` | `8BB5C33B082DB4CDAECE6F4730A92A2136B0403BF97DB17AF27F5959340ABBA1` |
| `sptm-txm-static-report-v5.md` | `B74446AD9B4C18C3EB36BC98FB5B0B5BEA0D250F729AD8716159D8ECCEEAD5A5` |

The v6 artifacts add bounded dispatch function, ingress, caller, and guard
metadata:

| v6 artifact | SHA-256 |
| --- | --- |
| `ios17_1_1-symmetric/sptm-txm-static-report-v6.json` | `78BE444A6C684E4A8511079563EDCAC51A45179876CB9A9B1ACFF303DD49F812` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v6.md` | `728EF3C926A43704CF0C9F0110590A161EADB5348673B38B829A85846D4F60B0` |
| `sptm-txm-static-report-v6.json` | `175D130EB675592E8CC6EAD719E56A0166D32F52297232E2F0C7E03C30F4283B` |
| `sptm-txm-static-report-v6.md` | `43F5B9CB13BE7C7431B69EDF82E9603A5B5F48F0E399A8AD45F1A83ED19FF27A` |

The v7 artifacts add code-pointer provenance and authenticated indirect
transfer paths:

| v7 artifact | SHA-256 |
| --- | --- |
| `ios17_1_1-symmetric/sptm-txm-static-report-v7.json` | `743AE7B9CA5BE3DF03613D33D4C296C68E7BED4188DBFF9946702559907388C7` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v7.md` | `47EF90A8A4AA2B64D51613A2F4B9B2C42C68B319C179B3E68476C1435521B103` |
| `sptm-txm-static-report-v7.json` | `A45A99602CADEFE4E121E4DC14362E5EAC9B467388886A8C86BC342595FFC76E` |
| `sptm-txm-static-report-v7.md` | `A7FF36B66B90D5E5FBFFEA8E38EDC3051914DD601CEF794A1B669711BA40E910` |

The current chain still stops before protected execution. The first metadata
blocker is `selector.ppl_metadata`; the first runtime blocker is
`kernel.runtime_read_write`. Request generation, transmission, handler
dispatch, and response receipt are all false. Therefore this comparison cannot
identify an SPTM rejection code or claim a live SPTM/TXM behavior change.

## Titan Gap Between iOS 17 and iOS 26

The current upstream Titan README narrows the original bypass window to iOS
16.1 through iOS 17.4 beta 3 and records three independent hardening changes:

- iOS 17.4 beta 4 stopped restoring the exploitable AGX hibernation register
  state used by the microPPL stage.
- iOS 18.1 beta 4 added instruction authentication to the AGX thread state.
- iOS 26 added data PAC to `ipc_port->ip_nsrequest`, closing the documented
  IPC port-stealing prerequisite.

These changes sit before a protected SPTM/TXM response could be observed. They
support the current trace ordering: missing runtime kernel access and Titan
execution are upstream blockers, not evidence of an SPTM rejection.

## Emulator Comparison Path

`jprx/qemu-sptm` and its parent `jprx/darwin-vm` provide a useful controlled
path for future iOS 17/iOS 26 comparison. The projects can load custom kernel,
SPTM, TXM, DeviceTree, trust-cache, and ramdisk images, and expose a debugger
from the first SPTM instruction. The published matrix includes A15/t8110 and
iOS 26.6 configurations, though the exact iPhone14,2/iOS 26.0.1 sample is not
listed as tested.

Emulator results must remain separate from device claims. The emulator
disables PAC, treats some lockdown registers as no-ops, and is single-core.
It can validate image loading, boot choreography, static selector mapping, and
control-flow hypotheses, but it cannot prove a physical-device bypass or the
real hardware enforcement response. Preparing the firmware and ramdisk also
requires macOS tooling according to the project's setup instructions. The
published DeviceTree fixup also removes the SGX node and avoids the related
IOMMU initialization, so this path cannot validate the AGX/Titan chain.

## Symmetric Baseline Obtained

The exact iPhone14,2/iOS 17.1.1 triplet `kernelcache + sptm.t8110 + txm` is now
stored under `outputs/iphone-system/ios17_1_1-symmetric`. Its extraction
provenance, BuildManifest identities, hashes, reproducible Windows commands,
and full analyzer result are recorded in
`docs/A15_IOS17_1_1_SYMMETRIC_BASELINE.md`.

The bounded `ADR` resolution, tagged frame-type policy normalization,
entry-instruction census, direct TXM tail-branch provenance, SPTM transfer and
dispatch-anchor census, bounded dispatch guard graph, and authenticated
callback provenance are now implemented. Raw through `-v7` reports remain
separate. The v7 graph confirms continuous PAC-protected callback dispatch and
finds no residual bypass branch. Static similarity still cannot establish
selector, ABI, endpoint, bypass, or runtime-response identity.

## Sources

- https://newosxbook.com/bonus/sptm2.html
- https://proteas.github.io/ios/2023/06/09/some-quick-and-discrete-notes-on-sptm.html
- https://github.com/alfiecg24/Titan
- https://github.com/alfiecg24/libgrabkernel2
- https://github.com/alfiecg24/XPF
- https://github.com/opa334/ChOma
- https://github.com/jprx/qemu-sptm
- https://github.com/jprx/darwin-vm
- https://github.com/Vector35/binaryninja-api/issues/5933
- https://gist.github.com/asdfugil/101ae32734938cf2c186ff330fba1e97
- `docs/A15_IOS17_1_1_SYMMETRIC_BASELINE.md`
- `outputs/iphone-system/ios17_1_1-symmetric/sptm-txm-static-report.json`
- `outputs/iphone-system/ios17_1_1-symmetric/sptm-txm-static-report-v2.json`
- `outputs/iphone-system/sptm-txm-static-report.json`
- `outputs/iphone-system/sptm-txm-static-report-v2.json`
- `outputs/iphone-system/response-trace-v2.json`
