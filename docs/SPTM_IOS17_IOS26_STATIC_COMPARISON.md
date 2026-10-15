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
| XNU entry | XNU enters SPTM with `GENTER #0` | Exact entry sequence not yet independently matched | Open static check |
| TXM entry | TXM enters SPTM with `SVC #0` | Exact entry sequence not yet independently matched | Open static check |
| Dispatch | SPTM routes subsystem IDs through dispatch tables; TXM is subsystem 1 | Dispatch-related behavior is consistent with the retained component split, but the iOS 26 dispatch table has not been mapped by the current analyzer | Do not assume selector identity |
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

The bounded `ADR` resolution and tagged frame-type policy normalization are now
implemented. Raw reports remain separate from the `-v2` reports. The next
justified static step is to compare the SPTM/TXM entry and dispatch sequences
with the same instruction-level rules on both builds. Static similarity still
cannot establish selector, ABI, or runtime-response identity.

## Sources

- https://newosxbook.com/bonus/sptm2.html
- https://proteas.github.io/ios/2023/06/09/some-quick-and-discrete-notes-on-sptm.html
- https://github.com/alfiecg24/Titan
- https://github.com/alfiecg24/libgrabkernel2
- https://github.com/alfiecg24/XPF
- https://github.com/opa334/ChOma
- https://github.com/jprx/qemu-sptm
- https://github.com/jprx/darwin-vm
- https://gist.github.com/asdfugil/101ae32734938cf2c186ff330fba1e97
- `docs/A15_IOS17_1_1_SYMMETRIC_BASELINE.md`
- `outputs/iphone-system/ios17_1_1-symmetric/sptm-txm-static-report.json`
- `outputs/iphone-system/ios17_1_1-symmetric/sptm-txm-static-report-v2.json`
- `outputs/iphone-system/sptm-txm-static-report.json`
- `outputs/iphone-system/sptm-txm-static-report-v2.json`
- `outputs/iphone-system/response-trace-v2.json`
