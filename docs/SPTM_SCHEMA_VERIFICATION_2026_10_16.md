# SPTM Schema Verification: 2026-10-16

## Scope

This verification checks the current static model against independently
regenerated reports for the exact iPhone14,2/A15 artifacts. It does not invoke
SPTM, TXM, Hypervisor.framework, a GPU command queue, IPC right transfer, or a
protected-memory write.

Targets:

| Release | Build | Device | Evidence |
|---|---|---|---|
| iOS 17.1.1 | 21B91 | iPhone14,2 / A15 | Symmetric kernel, SPTM, and TXM extraction |
| iOS 26.0.1 | 23A355 | iPhone14,2 / A15 | Local kernel, SPTM, TXM, and GFX extraction |

## Reproduction Result

The current analyzers were rerun from the source tree against both artifact
sets. The fresh reports are under
`outputs/iphone-system/schema-verify-2026-10-16/`, outside this Git worktree.

| Check | Result |
|---|---|
| Fresh iOS 17 report versus v10 | Structurally identical after normalizing the three input path strings |
| Fresh iOS 26 report versus v10 | Structurally identical after normalizing the three input path strings |
| Fresh AGX/UAT report versus the prior producer report | Byte-for-byte identical |

The input path strings are the only differences in the two SPTM/TXM JSON
reports. No address, policy row, endpoint, frame type, callback, or conclusion
changed.

| Reference report | SHA-256 |
|---|---|
| iOS 17 SPTM/TXM v10 JSON | `FF4B1B8AF5819404D8271DB340A253B619612C7BFD45C6365E65BD5EF2FBCC23` |
| iOS 26 SPTM/TXM v10 JSON | `498757C670945373111A06727843CF73E785D985C924D165101400C09A90BBBE` |
| AGX/UAT producer JSON | `D1280C523ECFEEC08564AADD4AC8CCBD7B774A1E30F02BC5DE65A1C8DFFDCB6A` |

## Confirmed Schema

| Contract | iOS 17.1.1 | iOS 26.0.1 | Verdict |
|---|---|---|---|
| UAT dispatch table | ID `7` | ID `7` | Stable subsystem identity |
| Frame-type policy | Immediate bitmasks | `0x60`-byte descriptor table | Policy representation changed |
| Frame-type source | Metadata byte `+0x2` | Metadata byte `+0x2` | Stable source field |
| Policy selector | Embedded mask tests | Descriptor policy byte `+0x1` | Authenticated table replaces the legacy switch |
| UAT page-table type | Typed UAT page table | `XNU_IOMMU` type `0x17` | Explicitly enforced on 23A355 |
| Leaf eligibility | `XNU_DEFAULT` / `XNU_IO` legacy switch | Per-type domain and class policy | iOS 17 values cannot be copied numerically |
| iOS 26 mapping classes | Not present in this form | Class `1` or `2` | Supplied by the protected segment producer |
| Stage-2 root/page types | No equivalent route recovered in 21B91 | `0x1f` / `0x20` | Separate virtualization lifecycle |
| Stage-2 direct UAT permission | Not applicable | Domain bitmap `0`, maximum class `0` | Not an AGX/UAT mapping route |

The iOS 26 segment producer remains `acquire_uat_segments_page`. It validates
the descriptor page as `XNU_DEFAULT` and passes segment count and map options
to UAT map continuation. For UAT domain `7`, `XNU_IO` is eligible up to the
recovered mapping class, while `XNU_PROTECTED_IO` is not. No report identifies
a direct GFX command ingress that supplies the missing protected producer
state.

## Hypervisor Repository Assessment

The public `cloverfield11/ios26-hypervisor-research` repository is useful
corroboration, but it does not advance the current Titan injection chain.

It statically documents an A16/iOS 26.4.1 Stage-2 virtualization surface,
including `/product/has-virtualization`, VMIDs, Stage-2 page tables, and the
private Hypervisor entitlement. It contains a README and two commits rather
than a runnable exploit or artifact bundle, and it explicitly presents no
SPTM bypass.

Our exact A15/23A355 images independently confirm more of the same surface:

- `/product/has-virtualization` is enabled.
- SPTM contains the guest dispatch and typed Stage-2 lifecycle.
- A guest root must already be a tracked, aligned frame of type `0x1f`.
- Root retyping claims a unique VMID and rejects duplicates.
- Stage-2 page type `0x20` has its own subtype and reference-count rules.
- `sptm_guest_enter` is internal rather than a general exported endpoint.
- Frame types `0x1f` and `0x20` have no direct UAT-domain permission.

Therefore the repository confirms a parallel SPTM service. It does not supply
the missing IPC-right transfer, AGX command-buffer submission, UAT leaf
authorization, TXM code-signing transition, or host Stage-1 write primitive.
Possession of the private entitlement would only reach the normal Hypervisor
API; it would not remove SPTM's frame-type and VMID state machine.

The only unresolved way this surface could change the route would be a
separate implementation vulnerability in the Stage-2 handlers. Neither the
public repository nor the local static reports establish such a bug. That
hypothesis must remain separate from the verified Titan/AGX chain.

## Public Cross-Check

The arXiv paper `2510.09272` supports the general model: SPTM is the authority
for frame retyping and protected mapping policy. The Emergent Mind page is a
secondary summary of that same paper and adds no A15/23A355 bypass or new
interface evidence.

Sources:

- https://github.com/cloverfield11/ios26-hypervisor-research
- https://arxiv.org/abs/2510.09272
- https://www.emergentmind.com/papers/2510.09272

## Chain Consequence

The verified frontier remains unchanged:

1. ClearSword kernel read/write: reached on device.
2. Titan patchfinding and IORVBAR resolution: reached on device.
3. Read-only `backboardd` IPC census and exact IOGPU client attribution:
   reached on device.
4. IPC right transfer: deliberately blocked on Darwin 25.
5. GFX command-buffer submission: unreached.
6. UAT-backed physical write, SPTM/TXM mutation, injection, and bootstrap:
   unreached.

The Hypervisor branch is retained as a negative, well-bounded research branch;
it is not merged into the active elevation route.
