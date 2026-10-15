# SPTM/TXM Static Comparison: iOS 17.1.1 and iOS 26.0.1

## Scope

This is a static, provenance-aware comparison. The iOS 17 side is based on
public reverse-engineering notes for iOS 17.1.1 on an iPhone 15 Pro-class
target. The iOS 26 side is based on locally extracted iPhone14,2/A15 iOS 26.0.1
build 23A355 images and the repository's offline analyzers. It is not a direct
same-device binary diff and does not invoke SPTM, TXM, a GPU command queue, or
any protected-memory operation.

## Samples

| Property | iOS 17.1.1 reference | iOS 26.0.1 local sample |
|---|---|---|
| Evidence type | Published static reverse engineering | Local static binary analysis |
| Target | t8122 / iPhone 15 Pro-class | iPhone14,2 / A15 |
| Build | 21B91 | 23A355 |
| SPTM image | Separate Mach-O image | `sptm.bin`, 1,048,608 bytes |
| TXM image | Separate Mach-O image | `txm.bin`, 458,784 bytes |
| SPTM SHA-256 | Not provided by the reference | `ED7781D2D82FE4818B85DD18C6B07DC172440EEECC2F7B33FC1E048313583F7C` |
| TXM SHA-256 | Not provided by the reference | `04CBCCBB1D986B2492C6430DA259C12579B58DE74795208202988739CB68A55E` |

The local image bases are unslid analysis values, not reusable runtime
addresses: SPTM `0xfffffff027004000` and TXM `0xfffffff017004000`.

## Architectural Comparison

| Area | iOS 17.1.1 reference | iOS 26.0.1 observation | Assessment |
|---|---|---|---|
| Component split | SPTM and TXM are standalone firmware images | Separate SPTM and TXM images extracted | Confirmed continuity |
| XNU entry | XNU enters SPTM with `GENTER #0` | Exact entry sequence not yet independently matched | Open static check |
| TXM entry | TXM enters SPTM with `SVC #0` | Exact entry sequence not yet independently matched | Open static check |
| Dispatch | SPTM routes subsystem IDs through dispatch tables; TXM is subsystem 1 | Dispatch-related behavior is consistent with the retained component split, but the iOS 26 dispatch table has not been mapped by the current analyzer | Do not assume selector identity |
| Page ownership | SPTM assigns frame types and controls page-table transitions | PAPT range registration, lookup, compression, retyping, permission updates, and frame-type checks resolve in the iOS 26 SPTM image | Strong static continuity |
| Kernel integration | XNU contains SPTM call stubs and protected page-table integration | `libsptm_init`, `sptm_args`, page-table refcount helper, and ten dependent references resolve | Strong static continuity |
| TXM role | TXM handles code-signing, entitlements, trust decisions, and IMG4 services | Device-tree trust-cache range, trust-cache root, developer-mode storage, and `research.com.apple.license-to-operate` relationships resolve | Strong static continuity |
| Runtime request | Published article reconstructs control flow offline | No request generated or transmitted by this project | `NOT_REACHED` |
| Runtime response | No result from this target | No handler dispatch or response received | `NOT_REACHED` |

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

The high-level division of responsibility appears continuous from iOS 17.1.1
to iOS 26.0.1: SPTM owns protected translation and frame-type policy, while TXM
owns code-signing and trust decisions. The most detailed local iOS 26 evidence
is in PAPT range management and validation, but a quantitative function-level
delta requires an iOS 17 binary sample analyzed by the same tool.

The current chain still stops before protected execution. The first metadata
blocker is `selector.ppl_metadata`; the first runtime blocker is
`kernel.runtime_read_write`. Request generation, transmission, handler
dispatch, and response receipt are all false. Therefore this comparison cannot
identify an SPTM rejection code or claim a live SPTM/TXM behavior change.

## Sources

- https://newosxbook.com/bonus/sptm2.html
- https://proteas.github.io/ios/2023/06/09/some-quick-and-discrete-notes-on-sptm.html
- `outputs/iphone-system/sptm-txm-static-report.json`
- `outputs/iphone-system/response-trace-v2.json`
