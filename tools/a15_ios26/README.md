# A15 iOS 26 SPTM/TXM analysis

`analyze_sptm_txm.py` checks the static assumptions made by
`BaseBin/XPF/src/sptm_txm.c` against extracted firmware images. It is intended
to distinguish a patchfinder compatibility problem from a missing SPTM bypass.

The offline analyzer does not patch a firmware image or execute an exploit.
The app also contains a separate, exact-target active Titan probe for
`iPhone14,2` on build `23A355`; that route is not exercised by this analyzer.

`analyze_titan.py` separately reproduces the masked instruction searches in
Titan's kernel and GFX patchfinders. It understands the `rkosftab` container
used by extracted GFX firmware and checks every embedded firmware slice. Its
GFX report also inventories all static `MSR TTBR0_EL1`/`MSR TTBR1_EL1`,
`PACGA`, and `ERET` sites. PACGA-chain labels are bounded local heuristics;
they do not establish a signing oracle or a bypass.

The same GFX pass reconstructs the GXF entry routes, the static UPPL packet
layout, authenticated dispatch form, packaged table state, mapping-handler
calls, range-guard candidates, accepted attribute classes, and context-switch
guard. A zero default with no established producer is reported as unresolved
rather than being assigned speculative handler indices.

`analyze_agx_uppl_producer.py` compares the exact iOS 17 and iOS 26 AGX/SPTM
handoff paths with the iOS 26 GFX image. It decodes PatchBay records, checks
Mach-O symbol and relocation metadata for the UPPL state, and distinguishes a
weak zero default from a demonstrated producer. It also reconstructs the
shared SPTM/GFX handoff, dynamic GFX segment registration, and the downstream
UAT frame-type/domain/mapping-policy checks. The v7 report additionally traces
the local GXF command-`0x10` constructor back to RTKit bootstrap and internal
memory-map producers, decodes the 65-entry handoff flush queue, and correlates
restricted policy bitmaps with named IOMMU domains. It also recovers the SPTM
frame-type name table and classifies each policy row's authenticated retype-in
and retype-out callbacks. The direct protected producer is identified as
`acquire_uat_segments_page`; the report records its input bindings, the UAT
leaf page mask, requested mapping classes `1/2`, and per-class frame-type
candidates for named UAT domain 7. It also recognizes the exact iOS 17
predecessor's untyped acquisition API, tail-call producer, direct
`XNU_DEFAULT`/`XNU_IO` allow switch, and legacy registration modes without
mislabeling those modes as iOS 26 mapping classes. It performs no live
protected-component request.

`analyze_vtable_fields.py` decodes authenticated chained vtable entries in an
offline kernelcache and reports accesses to selected object-field offsets.
`disassemble_fileset.py` resolves unslid virtual addresses across every fileset
and prints bounded ARM64 disassembly for manual validation of method boundaries.

## Dependencies

```sh
python -m pip install lief capstone
```

## Usage

```sh
python tools/a15_ios26/analyze_sptm_txm.py \
  --kernel kernelcache.bin \
  --sptm sptm.bin \
  --txm txm.bin \
  --output sptm-txm-static-report.md \
  --json-output sptm-txm-static-report.json

python tools/a15_ios26/analyze_titan.py \
  --kernel kernelcache.bin \
  --gfx gfx.bin \
  --live-layout tools/a15_ios26/live-layout-iphone14_2-23A355.json \
  --output titan-static-report.md \
  --json-output titan-static-report.json

python tools/a15_ios26/compare_gfx_security.py \
  --image 21D61=gfx-21D61.bin \
  --image 21E5200d=gfx-21E5200d.bin \
  --image 21E5209b=gfx-21E5209b.bin \
  --image 22A3354=gfx-22A3354.bin \
  --image 22B5045g=gfx-22B5045g.bin \
  --image 23A355=gfx-23A355.bin \
  --output gfx-security-comparison.md \
  --json-output gfx-security-comparison.json

python tools/a15_ios26/analyze_agx_uppl_producer.py \
  --ios17-kernel kernelcache-21B91.bin \
  --ios17-sptm sptm-21B91.bin \
  --ios26-kernel kernelcache-23A355.bin \
  --ios26-sptm sptm-23A355.bin \
  --ios26-gfx gfx-23A355.bin \
  --output agx-uppl-producer.md \
  --json-output agx-uppl-producer.json

python tools/a15_ios26/build_response_trace.py \
  --titan-report titan-static-report.json \
  --sptm-txm-report sptm-txm-static-report.json \
  --device-diagnostic a15-ios26-diagnostic-v6.json \
  --json-output response-trace.json \
  --markdown-output response-trace.md
```

`build_response_trace.py` combines the existing reports and an optional device
diagnostic into an ordered, provenance-aware v2 trace. It separates the first
metadata blocker from the first runtime blocker and deliberately labels the
protected-component boundary and runtime SPTM/TXM responses as `NOT_REACHED`
until direct evidence exists. Offline or read-only observations are never
promoted to hardware responses.

The kernel image may be an Apple fileset kernelcache. The analyzer selects the
`com.apple.kernel` fileset automatically.

## Confirmed sample

The current validation sample is an iPhone14,2 (A15) running iOS 26.0.1 build
23A355. On that sample, the existing XPF relationships resolve the following:

- TXM device-tree trust-cache lookup and trust-cache root
- TXM developer-mode storage
- SPTM compressed PAPT range count and table
- kernel-side SPTM argument pointer and page-table refcount helper
- `vm_first_phys`, `vm_last_phys`, frame table, and frame-type parameters
- frame-type policy representation as either `immediate_bitmask` or
  `descriptor_table`
- `libsptm_init` and its PAPT range globals
- TXM `SVC #0` entry thunks and kernel `GENTER` occurrences
- nearby `x16` selector-register writes, reported without assigning endpoint
  semantics
- complete raw `x16` constants reconstructed from bounded TXM tail-branch
  wrappers
- SPTM `GENTER`/`GEXIT` transfer counts and directly referenced dispatch
  diagnostic anchors
- dispatch anchor function candidates, direct caller/branch ingress, and
  bounded comparison/conditional-branch guards
- dispatch code-pointer materializations, nearby PAC and registration calls,
  and authenticated transfers in direct or one-hop tail paths
- bounded `x0`/`x2` registration-argument reconstruction, preserving dynamic
  source registers instead of assigning unsupported immediate values
- symmetric IOMMU descriptor decoding across direct and chained-registry
  layouts, including final table IDs and domain permission masks
- null-terminated IOMMU endpoint-table decoding with `0x10`-byte records,
  authenticated chained handlers, and directly referenced function anchors

These results show patchfinder compatibility for the inspected paths. They do
not provide the unrestricted physical-write primitive required by Dopamine's
SPTM bypass contract, and therefore do not make A15/iOS 26 jailbreak-compatible
by themselves. All reported addresses are unslid and specific to the analyzed
firmware build.

Capstone currently decodes the Apple `GENTER` opcode as data. The analyzer
therefore recognizes the bounded opcode family `0x00201420` with mask
`0xffffffe0` and records the low five-bit immediate explicitly. This is a
static instruction census only. It does not invoke an entry thunk, infer a
dispatch-table identity, or validate a runtime request or response.

The TXM wrapper reconstruction requires a complete 64-bit definition before a
direct tail branch to the `SVC #0` thunk. Partial or dynamic `x16` setup remains
unresolved. The resulting values are raw descriptors, not service names or
authorization claims.

SPTM transfer and dispatch results are also static. Diagnostic string
cross-references can identify code clusters and validation deltas, but the
analyzer does not equate a string name with a resolved handler or reachable
runtime branch.

Registration arguments are reported as raw values. The symmetric report's
consumer analysis establishes that the stored `x2` value is a caller-domain
permission bitset; it remains distinct from the state machine's event index.

Endpoint-table anchors are static provenance, not a request recipe. An entry
without a directly referenced `sptm_*` anchor remains unnamed, and the SPTM
UAT table is not equated with GFX's separate zero-default UPPL handler table
without a direct producer-side reference.

The Titan report has the same limitation. A static PASS does not validate the
live RTKit state, command-buffer setup, GFX ROP trigger, or physical-write
primitive. Those stages require a deliberately bounded on-device probe.

The optional live-layout manifest records read-only object-layout evidence.
When a staged probe proves object linkage, it may also record per-boot live
addresses; those values are evidence for that capture and are never reusable
offsets. Even with a `VALIDATED` IORVBAR mapping, the analyzer keeps Titan
execution blocked until the later AGX and physical-write stages are validated.

## Active-probe integration policy

The app-side research status and its target gate are documented in
`docs/A15_IOS_26_0_1_RESEARCH.md`. Titan remains outside the general iOS 26
range and receives one build-and-device-specific metadata include. The probe
rediscovers the existing IORVBAR mapping on each run, writes fsync-backed JSONL
checkpoints, validates the descriptor's exact `0x206050000/0x8` range and all
required GFX ROP targets, and records thread creation, command submission, and
cleanup separately. It stops before Dopamine constructs physrw, changes
privileges, or installs a bootstrap. Validate these constraints with:

```sh
python tools/a15_ios26/check_research_integration.py
```
