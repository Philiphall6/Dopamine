# A15 / iOS 26.0.1 Research Status

This document tracks the staged work toward understanding Dopamine's Titan/SPTM
chain on iPhone14,2. It is not a jailbreak compatibility declaration. The full
jailbreak path remains unsupported; the exact target may enter a bounded active
Titan probe that stops before physrw construction, privilege changes, and the
bootstrap.

## Target

- Device: iPhone14,2
- SoC: A15
- OS: iOS 26.0.1
- Kernel: Darwin 25.0.0
- Research state: `ACTIVE_TITAN_PROBE_IPC_PROFILE_V5_DEVICE_PASS`
- Operating mode: exact-target staged execution with persistent checkpoints

The durable offline-analysis handoff is
`docs/A15_IOS26_WORKLOG.md`. The latest static pass resolves GFX's new UPPL
consumer separately from SPTM's registered UAT endpoint table, proves the
cross-version SPTM/GFX shared handoff, and isolates iOS 26's new dynamic GFX
segment registration plus the downstream protected frame-type policy.

## Latest Build Evidence

- Source commit: `79b75bb81b4fc3e8f5a112c8d3a1b924e0cfff67`
- GitHub Actions run: `38887531277` (`PASS`, 12m 6s)
- IPA: `Dopamine-A15-iOS26-ipc-profile-v5-guard-79b75bb.ipa`
- Size: `55,474,629` bytes
- SHA-256: `9A423151A27EBAFC2C3C4E4F0942886B95FC51928E592501F80EE01F60F8F752`
- Package check: `Payload/Dopamine.app/Dopamine`, app `Info.plist`, and
  `Frameworks/Titan.framework/Titan` and
  `Frameworks/ClearSword.framework/ClearSword` are present.

The packaged ClearSword binary contains `clearsword_kreadbuf_exact`. The
packaged Titan binary contains all nine exact-read map/descriptor checkpoints,
the bounded process-name discovery, the symmetric IPC-layout markers, and the
IPC profile v5 `DECODE`, `START`, `OBJECT-TYPE`, `OBJECT-STATE`, `CANDIDATE`,
`MATCH`, `PROFILE`, `PROFILE-COMPARE`, `SUMMARY`, and `STOP` markers. The probe
entry and decoder both identify revision `ipc-census-v5`. The binary records
`ie-bits`, `io-type`, `io-state`, stable-entry counters, dedicated exact-match
counters, and profile-completion counters, and no longer contains the old
exact-target `old-type` marker. It retains the explicit
`task_copy_ipc_entry not reached` stop marker. The packaged Titan framework
also contains the Darwin 25 refusal marker added at the start of the legacy
copy routine. Source inspection and the integration checker confirm that the
census remains read-only and requires stable complete entry snapshots before
and after following an object. The iOS 26 patchfinder still reports the
rejected primary `IOMemoryMap::fAddress` match as an expected accessor-pattern
retry, rather than as a false error.

This guard build was installed and run on the exact target on 2026-10-16 even
though it does not advance the active probe. It preserves the exact v5
read-only stop and adds a second defense that rejects iOS 26 or XNU 12377
before the first legacy target-port read or any write. The rerun decoded a
`0x10000`-byte backboardd IPC allocation containing 2,730 entries plus a
`0x10`-byte tail. It again found complete profiles at indices `537` and `1009`,
reported 1,940 rights, zero unstable snapshots, 86 type-36 connections, two
exact matches, and stable final table/PID checks. The probe stopped before
`task_copy_ipc_entry`; the guard itself was therefore not reached and no right
transfer or write occurred. The public Calif/Hexacon iOS 27 demonstration is
tracked separately in `docs/CALIF_HEXACON_IOS27_SIGNAL.md`; no public technical
detail currently connects it to Titan, backboardd IPC transfer, or this A15
route.

## First Active Device Result

The previous `16487f1` build was run on the exact target on 2026-10-15. It
reached Titan's iOS 26 IORVBAR object traversal and rebooted the device. The
panic was recovered over USB as `panic-full-2026-10-15-131411.000.ips`
(1,468,402 bytes), SHA-256
`F323AEB9E0C2D48CA0E7BD809CB34C22EA45071D299D46B474CCF47F8E6C8121`. Its incident is
`618738CD-2B6B-4577-84AC-DD659A822CE5`; the panicked task is Dopamine, pid 843.
The panic string is a zone-bound violation: a 32-byte read starting at offset
`0x20` overflowed a 40-byte object in the `iokit.IOMachPort` zone.

The panic's user stack was symbolicated against the exact binaries packaged in
the IPA. It resolves through `clearsword_kreadbuf`, libjailbreak's `kreadbuf`,
`kread64`, and `kread_ptr`, then `titan_read_valid_pointer`,
`titan_resolve_ios26_iorvbar_mapping`, and `titan_run`. The crash therefore
occurred while resolving the `IOMachPort::object` pointer at `+0x20`, before an
SPTM/TXM request and before Titan's GFX ROP trigger.

ClearSword advertises `krwMinSafeReadSize=0x20` and its early read primitive
always asks the kernel for that full size even when the caller requests an
eight-byte pointer. Reading directly at `object+0x20` consequently spans
`[+0x20,+0x40)`, outside the observed `0x28` allocation. The corrected probe
anchors each minimum-size read window at the end of the requested field. For
this pointer it reads `[+0x08,+0x28)` and extracts the final eight bytes. This
is still a read-only change; it does not add a kernel write, physical write,
protected request, privilege change, or bootstrap operation.

## Second Active Device Result

The corrected `e702adc` build reached the same IORVBAR traversal and rebooted at
the next small allocation. The panic was recovered over USB as
`panic-full-2026-10-15-134254.0002.ips` (1,872,627 bytes), SHA-256
`E2371579704270A15E729B047631837E6AA45C48F23BFF7F828E09B71CC64347`, incident
`3AB69B10-DB47-4453-B918-A44C1224BB00`. The panicked task is Dopamine, pid 908.
Its zone-bound check reports a 32-byte read from a 16-byte
`kalloc.type.var2.16` object.

Symbolication against the packaged binaries resolves the fault through
`clearsword_kreadbuf`, libjailbreak's `kreadbuf`,
`titan_read_valid_pointer + 0x33c`, and
`titan_resolve_ios26_iorvbar_mapping + 0x2d4`. Disassembly identifies the call
as the read of the second `IODeviceMemory` OSArray element at `elements+0x8`.
This is still before IORVBAR MMIO access, GFX ROP submission, and every SPTM/TXM
request.

The new build adds a separate exported ClearSword exact-read helper,
`clearsword_kreadbuf_exact`. It passes an eight-byte `optlen` to
`getsockopt(ICMP6_FILTER)` and refuses to fall back to
the 32-byte primitive when that helper is expected but unavailable. Apple's XNU
implementation bounds this copy with
[`MIN(sizeof(struct icmp6_filter), optlen)`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/icmp6.c#L2976-L2977),
allowing the pointer to be read without crossing the 16-byte allocation. The
change remains read-only.

## Third Active Device Result

The exact-read `1673566` build was run on the exact target on 2026-10-15. It
completed ClearSword in about 580 ms, validated the live kernel Mach-O header,
entered Titan, completed the active kernel patchfinder, and traversed the full
`gfx-asc` object path through the second `IODeviceMemory` descriptor and its
existing `IOMemoryMap`. Every exact eight-byte read passed and the device did
not panic.

The run stopped cleanly at `titan.iorvbar.descriptor-range`. The log reported
`descriptor+0x18` as a kernel pointer, `descriptor+0x20` as `0x10000920`, and
`descriptor+0x30` as zero. Those values prove that the validation code was
reading the descriptor's `_mappings`, flags, and an unrelated field as if they
were its physical range. The earlier bounded Filza capture already established
the correct `IOGeneralMemoryDescriptor` layout: total length at `+0x50`, ranges
pointer at `+0x60`, range count at `+0x68`, and the single inline physical range
at the pointed-to `{+0x0,+0x8}` pair. The same `+0x50/+0x60` accessors exist in
libjailbreak's XNU-derived descriptor helpers.

The `c703565` source revision reads those fields through
`clearsword_kreadbuf_exact`, requires one range, and independently validates
both descriptor and range lengths as eight bytes. It also exact-reads the four
`IOMemoryMap` linkage/address fields. The device result below confirms those
checks and still stops before GFX command submission, physical-write
publication, privileges, or bootstrap.

## Fourth Active Device Result

The descriptor-range `c703565` build was run on the exact target on 2026-10-15.
ClearSword again established the kernel primitive, and Titan passed the complete
IORVBAR object traversal. The live `IOMemoryMap` linked back to the expected
descriptor and reported `fOffset=0`, `fAddress=0xffffffecfef84000`, and
`fLength=0x8`. The descriptor reported total length `0x8`, one range at
`0xffffffe08f893af8`, and the exact physical pair `0x206050000/0x8`. Titan then
recorded `titan.iorvbar.resolve PASS` without a panic or reboot.

The new first failure is `titan.command-buffers`: the legacy
`proc_find_by_name` could not find `backboardd`. An independent USB process list
confirmed that `backboardd` was alive as pid 72, so this is a lookup-layout
failure rather than a missing process. The function still used the historical
hard-coded process-name offset `0x579`, which is not validated for the observed
XNU 25 `proc` size of `0x748`.

The next bounded revision leaves the legacy path unchanged outside this exact
probe. On iPhone14,2/23A355 it exact-reads the current Dopamine `proc`, discovers
every NUL-terminated occurrence of its own executable name, and treats those
offsets only as candidates. It then traverses at most 4096 processes, requires
all target-name matches to resolve to one `proc`, exact-reads its pid, and fails
closed on invalid pointers, read errors, ambiguity, or exhausted bounds. No
kernel write, IPC entry copy, command submission, physical write, privilege
change, or bootstrap operation is added by this discovery step.

## Fifth Active Device Result

The process-name `a720b8a` build was run on the exact target on 2026-10-15.
ClearSword established the same live kernel primitive, and Titan again passed
the kernel patchfinder and complete IORVBAR validation. The process-name scan
found two self-name candidates at `0x56c` and `0x57d`; only `0x57d` resolved
uniquely to `backboardd`, at proc `0xffffffe08fa67b40`, pid 72, after 330
processes. Its decoded IPC table was `0xffffffec50f4c000` with 2730 entries.
The run completed without a panic or reboot.

The first failure is now the legacy open-userclient scan. It did not find the
expected live object vtable `0xfffffff04bbbba10` (patchfinder base
`0xfffffff04bbbba00` plus the historical `0x10` vtable-header adjustment).
That scan assumes the first 32 bits of every port retain the older active bit
and low-ten-bit `IKOT_IOKIT_CONNECT == 29` encoding. Current XNU instead
routes `ip_type(port)` through the IPC object representation, while IOKit still
stores the port kobject as an `IOMachPort` wrapper whose signed `object` field
contains the userclient. See Apple's current
[`ipc_port.h`](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_port.h)
and
[`IOUserClient.cpp`](https://github.com/apple-oss-distributions/xnu/blob/main/iokit/Kernel/IOUserClient.cpp#L2399-L2454).

The next exact-target revision therefore records a read-only census instead of
trusting the legacy type gate. It captures the already validated live
`IOMachPort` vtable from the `gfx-asc` service path, scans at most 4096 stable
IPC entries, validates the observed `0x48/0x18/0x50/0x20` layout contract, and
follows `IOMachPort.object` only when the intermediate object has that exact
vtable. All table, port, wrapper, object, and vtable fields use four- or
eight-byte `clearsword_kreadbuf_exact` reads. Candidate and legacy-type logging
are each capped at 64 records; the full counters, type histogram, table
stability, and pid stability remain in a deterministic summary. The
historical active bit is retained as a safety gate before following a port's
`kobject`, but type 29 is measured rather than required. The
exact-target path returns before `task_copy_ipc_entry` even if a matching
vtable is seen.
It performs no kernel write, right transfer, command submission, MMIO access,
physical write, privilege change, or bootstrap operation.

## Sixth Active Device Result

The IPC-census `8beefad` build was run on the exact target on 2026-10-15 at
16:55. ClearSword again established and validated the kernel primitive. Titan
passed the target gate, kernel patchfinder, and complete IORVBAR traversal. It
also captured the live signed `IOMachPort` wrapper vtable and normalized it to
`0xfffffff04bb60b18`.

The bounded process lookup again resolved `backboardd` uniquely at proc
`0xffffffe08fa67b40`, pid 72, this time after 349 traversed processes. The
derived task address is `proc + 0x748`. The exact-read IPC census then stopped
before scanning any entry because the current `task.itk_space` / `ipc_space`
path produced no decodable table at the asserted `ipc_space + 0x48` layout:
`table=0x0`, `size=0x0`, `entry-size=0x18`. The explicit read-only stop ran and
`task_copy_ipc_entry` was not reached. The device did not panic or reboot.

This moves the blocker earlier than the legacy port-type test. The next source
revision records the exact raw table word before decode, compares target and
self `task.itk_space`, and logs fixed eight-byte windows at `task +
[0x2f0,0x330]` and `ipc_space + [0x00,0x80]`. It does not follow any IPC object
from those words. The output distinguishes a stale `task.itk_space` offset from
a moved `ipc_space` table field or changed SMR encoding.

## Seventh Active Device Result

The IPC-layout `b66873e` build was run on the exact target on 2026-10-15 at
17:17. ClearSword, Titan's target gate, patchfinder, IORVBAR traversal, and the
bounded `backboardd` lookup all passed. The process resolved uniquely at proc
`0xffffffe08fa67b40`, pid 72, after 397 traversed processes. The device did not
panic or reboot.

The symmetric exact-read windows prove the asserted layouts instead of merely
suggesting them. Both target and self tasks contain their respective canonical
`itk_space` pointer at `task + 0x310`. Both IPC spaces contain their respective
signed task backpointer at `ipc_space + 0x50`, immediately after the encoded
table word at `+0x48`. The target raw table word is
`0x96f958ac50f4c004`; removing its pointer signature first and then applying
Titan's existing SMR allocation decoder reconstructs
`0xffffffec50f4c000`, allocation size `0x10000`, and 2730 complete `0x18`-byte
entries with a `0x10`-byte allocation tail. This exactly reproduces the table
address and count seen by the older non-exact path.

The failure is therefore not a moved `task` or `ipc_space` field and does not
require a new XNU layout guess. `ipc_space_table_exact` passed the raw signed
word directly to `ipc_table_resolve`, while the historical path first called
`UNSIGN_PTR`. The corrected source restores that normalization and retains the
bounded read-only census. The exact-target stop before `task_copy_ipc_entry`
remains unconditional.

## IPC Census v3 Build

The next source revision addresses the entry format without widening the
active boundary. Apple's `xnu-12377.1.9` source, immediately adjacent to the
target's `xnu-12377.2.9~1`, defines a `0x18`-byte `ipc_entry` with the signed
object pointer at `+0x0` and `ie_bits` at `+0x8`. Its `ipc_object` header no
longer uses Titan's historical bit-31 active marker and low-ten-bit legacy
type. Instead, `io_type` occupies the first byte and `io_state` the following
three-bit field; active in-space objects use states `1` or `2`.

`ipc-census-v3` therefore reads each complete `0x18`-byte entry, requires a
nonzero capability-right mask from `ie_bits`, strips the object-pointer
signature, and records the modern `io_type/io_state` distribution. It requires
two identical snapshots before following the object and a third identical
snapshot after the wrapper/object reads. Candidate attribution still requires
the already observed `IOMachPort` wrapper vtable and the expected user-client
vtable. The probe remains read-only and returns before `task_copy_ipc_entry`,
GFX submission, MMIO, physical write, privilege changes, and bootstrap. The v3
implementation compiled successfully, passed package-marker inspection, and
was subsequently run on the device as recorded below.

Primary layout references:

- https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/osfmk/ipc/ipc_entry.h
- https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/osfmk/ipc/ipc_object.h
- https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/osfmk/ipc/ipc_types.h

## IPC Census v3 Device Result

The v3 IPA was run on the exact target on 2026-10-16. It decoded the signed
`backboardd` table as a stable `0xc000`-byte allocation containing 2,048
complete `0x18`-byte entries. All 1,649 nonzero entries carried capability
rights, resolved to valid port objects, and retained identical complete-entry
snapshots. The final table pointer and process ID were also unchanged.

The modern object header split is confirmed on-device: 547 objects used
in-space state `1`, 1,102 used in-space-immovable state `2`, and no other state
survived the census gate. Type `36` contained 85 objects; all 85 reached the
observed `IOMachPort` wrapper and exactly two reached Titan's expected IOGPU
user-client vtable. Across the full census there were 358 stable wrapper/object
candidates and no unstable entry.

The v3 generic-candidate log was intentionally capped at 64 lines, so the two
exact matches were counted but their indices were not emitted. The v4 source
adds a separate bounded `MATCH` record for exact vtable matches and leaves the
read-only stop before `task_copy_ipc_entry` unchanged. No IPC right was copied,
no GFX command was submitted, and the device did not reboot during this run.

## IPC Census v4 Build

The v4 IPA preserves the device-validated v3 traversal and gives exact matches
their own 16-line cap, independent of the 64-line generic-candidate cap. Each
`MATCH` record includes the table index, entry and object header bits, port,
wrapper, object, runtime vtable, and unslid vtable. The summary separately
reports `match-logged` and `match-truncated`. Package inspection confirms these
markers and the explicit pre-copy stop in the built Titan binary.

The exact target ran v4 on 2026-10-16 without rebooting. It identified the two
expected IOGPU user-client objects at IPC indices `537` and `1009`. Their
objects were `0xffffffdf5e176b30` and `0xffffffdf5e176ca0`; both used runtime
vtable `0xfffffff04b36fa10` (unslid `0xfffffff007b17a10`). The complete scan
reported 2,048 entries, 1,669 rights, zero unstable snapshots, 85 type-36
IOKit connections, two exact matches, `match-logged=2`, and
`match-truncated=0`. The table and PID remained stable, and execution again
stopped before IPC right copy.

## IPC Profile v5 Device Result

The v5 build follows only the two exact v4 matches. For each one it performs
seven exact, read-only field reads: the `IOGPUDevice` pointer and vtable,
nullable MDSID map, `IOGPU` pointer and vtable, namespace, and handle-table
pointer. A final `PROFILE-COMPARE` record reports whether the two clients share
those downstream objects. The integration checker separately scans this helper
for kernel writes, IPC-right copying, Mach operations, and IOKit method calls;
all remain absent. The unconditional stop before `task_copy_ipc_entry` is still
packaged.

The exact target ran v5 on 2026-10-16 without rebooting. Both exact user-client
matches produced complete profiles (`valid=0x7f`). Index `537` resolved through
device `0xffffffdf5e4e4600`, GPU `0xffffffe431bdc000`, namespace
`0xffffffe20f7794c0`, and handles `0xffffffe042a2a000`. Index `1009` resolved
through device `0xffffffdf5e4e4800`, the same GPU
`0xffffffe431bdc000`, namespace `0xffffffe20f77a4c0`, and handles
`0xffffffe042a18000`. Both devices used vtable `0xfffffff04b379c50`;
both reached GPU vtable `0xfffffff04b3760d0`; both nullable MDSID-map fields
were zero. `PROFILE-COMPARE` therefore reported distinct devices, namespaces,
and handle tables, but a shared GPU backend and GPU vtable. This preserves the
association between each IPC port and its own client namespace while proving
that both clients terminate at the same IOGPU object.

The final census remained stable across all 2,048 entries and reported two
complete profiles, no unstable entry, and stable table and PID checks. It
stopped at the explicit read-only boundary before IPC entry copy. The captured
USB log is `ipc-profile-v5-usb-2026-10-16.log`, SHA-256
`0C91FC6ABB960F3ABEBA005FD479E41A0F60A2BAD45A97431DA1AF7F9279FD3C`.

The follow-up offline audit is recorded in
`docs/TITAN_IPC_COPY_DARWIN25_AUDIT.md`. It finds a deterministic XNU 12377
contract break in the historical right-copy route: `ipc_object` grew from 8 to
16 bytes, old flag bits changed meaning, `ip_kobject + 0x10` now selects
`ip_pdrequest` instead of `ip_nsrequest`, and the destination pointer field is
authenticated with a different discriminator. The exact-target stop therefore
remains mandatory. A second guard now blocks the legacy copy function itself
for iOS 26 or XNU major 12377 and later, before its first target-port read.

## End-to-End Chain Status

| Stage | Status | Evidence or blocker |
|---|---|---|
| Device and firmware identity | **PASS** | iPhone14,2 / A15 / 23A355 / iOS 26.0.1 |
| Read-only acquisition path | **PASS** | Filza bridge plus USB forwarding; probe restored disabled after each bounded capture |
| Kernelcache, GFX, SPTM, and TXM extraction | **PASS** | Offline analyzers accept all four extracted images |
| RTBuddy object and segment layout | **PASS** | Live object chain, two descriptors, and physical/virtual/remap field roles resolved |
| Existing GFX IORVBAR mapping | **PASS** | Runtime vtables, linked map fields, descriptor count, and exact physical range `0x206050000/0x8` all passed on-device |
| iOS 26 Titan kernel/GFX anchors | **STATIC PASS** | Adapted unique anchors resolve; legacy patterns fail as expected |
| TXM and SPTM anchors | **STATIC PASS** | Inspected trust-cache, PAPT, frame-table, and argument relationships resolve |
| Kernel read/write exploit primitive | **PASS; EXACT-READ ADAPTER VALIDATED** | ClearSword validated the live kernel header and all small-zone eight-byte reads completed without panic |
| Titan unrestricted physical write | **NOT REACHED / IPC PROFILE V5 DEVICE PASS** | v5 completely profiled exact clients 537 and 1009: distinct device/namespace/handle objects share one IOGPU backend; IPC entry copy and GFX submission remain blocked |
| SPTM/PAPT and Stage-2 contract | **NO SHORTCUT / TYPED STAGE-2 CONTRACT MAPPED** | Table 0 and the `0x1f/0x20` lifecycle are statically resolved, but they add protected frame, VMID, and state-transition gates and do not satisfy Dopamine's physical-write bypass contract |
| Bootstrap, trust-cache, and jailbreak services | **NOT REACHED** | Depend on runtime confirmation of the selected kernel primitive and an A15 SPTM/TXM path |
| A15/iOS 26 support declaration | **EXACT PROBE ONLY** | Titan metadata includes only iPhone14,2 build 23A355; normal support remains false |

The two research routes now join without being conflated. The active Titan
route still stops at the bounded `backboardd` IPC census, before IPC entry
copy, GFX command-buffer submission, unrestricted physical write, or any
SPTM/TXM mutation. The offline Stage-2 route describes what a later guest
operation would additionally require: retyping tracked pages as root type
`0x1f` and page-table type `0x20`, claiming a unique VMID, and entering the
guest state machine through the guarded GENTER path. It neither replaces the
missing Titan stages nor authorizes an otherwise forbidden UAT leaf mapping.

ClearSword/DarkSword provide the kernel read/write candidate used through iOS
26.0.1, and the device-side selector chooses ClearSword for this exact target.
The active probe called that candidate, validated the resulting kernel read,
and entered Titan. The first two runs exposed ClearSword's minimum read window
at an IOMachPort tail field and a 16-byte OSArray backing allocation. The
exact-length ICMPv6 adapter passed both and reached a clean descriptor-layout
validation failure. These points remain earlier than every SPTM/TXM operation;
passing static patchfinders still does not bridge that gap.

## Exact-target active probe

The active path is restricted three times: Titan's metadata names only
`iPhone14,2` plus build `23A355`, `titan_init` repeats the machine/version/build
check, and the UI exposes the path only through
`isA15IOS2601ResearchTarget`. Titan dynamically locates `gfx-asc`, validates the
expected `AppleARMIODevice`, `IOGeneralMemoryDescriptor`, and `IOMemoryMap`
vtables, follows the proven IORegistry collection chain, and requires
the descriptor's exact `0x206050000/0x8` physical range, `fMemory` linkage,
zero `fOffset`, eight-byte `fLength`, and a valid kernel `fAddress` before
reading the IORVBAR. The IOKit service right remains alive through that full
validation.

Every stage appends one JSON object to
`Documents/a15-ios26-active-probe.jsonl` and calls `fsync`. Consequently, a
process termination or device restart leaves the last completed stage on disk.
Before the GFX trigger, every required ROP target must be nonzero. Thread
creation and command submission have separate PASS/FAIL checkpoints, and the
probe records exploit/IOSurface cleanup before returning.
The route intentionally returns after Titan publishes its physical-write
callback; it does not call Dopamine's physrw builder, privilege elevation,
trust-cache, or bootstrap code.

## How the Published Titan Chain Works

Titan is not a direct TXM bypass. Dopamine first requires a compatible kernel
exploit to provide kernel read/write. It initializes kernel translation and
IOSurface helpers, then loads Titan as the selected PPL/SPTM-stage component.

The published Titan path has four architectural phases:

1. It uses the existing kernel read primitive to discover the kernel pmap,
   translation roots, IOGPU objects, RTBuddy state, and GFX firmware mappings.
2. It copies and statically analyzes the running GFX firmware to resolve the
   version-specific RTKit state and control-flow anchors needed by the published
   implementation.
3. It uses the validated GFX/RTKit path to create a controlled CPU mapping
   window. Titan exports this result to Dopamine only as an unrestricted
   physical-write callback (`physwritebuf`).
4. Dopamine consumes that callback to construct its normal physical read/write
   layer. TXM and SPTM offsets found by XPF are downstream inputs for protected
   trust-cache, developer-mode, translation, and page-protection operations;
   knowing their static addresses does not create the physical-write primitive.

For iPhone14,2 on iOS 26.0.1, phases 1 and 2 now have an exact-target active
probe implementation. ClearSword was executed first, its kernel read was
checked against the live Mach-O header, and Titan entered its IORVBAR object
traversal. No successful controlled mapping window, unrestricted physical
write, or SPTM bypass has yet been observed on-device. The static TXM base and
passing XPF relationships therefore remain evidence, not a bypass claim.

The complete iOS 17 mechanism, including the MDSID write primitive, AGX
hibernation transition, self-referencing AP PTE, patch boundaries, and direct
mapping to the 23A355 trace, is reconstructed in
[Titan iOS 17 SPTM Bypass: Source-Level Reconstruction](TITAN_IOS17_SPTM_BYPASS_DEEP_DIVE.md).
The 23A355 follow-up now identifies legitimate saved-state signing routines
and a separate UPPL/MMU mapping surface in the exact GFX firmware. These are
replacement-path candidates, not bypasses: controllable signer inputs,
dispatcher reachability, context-ID authorization, and micro-PPL validation
remain unproven. `compare_gfx_security.py` applies an identical TTBR/PACGA/ERET
census to historical GFX payloads so the 17.4 and 18.1 hardening boundaries can
be measured symmetrically.

The latest offline pass reconstructs the new 23A355 GXF/UPPL split, its
indexed four-argument `BRAAZ` dispatch contract, and the zeroed packaged
dispatch state. A producer-side follow-up now shows that this object is a weak
zero definition with no local writer, relocation, chained fixup, or PatchBay
descriptor; runtime population must not be assumed. It also proves that the
PPL-shared PatchBay base feeds the same 65-record handoff layout used on iOS
17. The iOS 26-specific addition is dynamic `gfx-data-base`/`gfx-data-size`
registration into protected frame metadata. Downstream,
`sptm_uat_map_continue` requires page-table frame type `0x17`, while
`iommu_register_mapping` passes wildcard selector `0x42`, reads the actual
frame type, and consults that type's domain bitmap and maximum mapping class.
The reverse pass reaches endpoint 4 at `0xfffffff0270a1d58`, which acquires a
type-`0xb` segment-descriptor frame before calling map continuation, and then
reconnects structurally to the shared GFX handoff. Selector `1` is now mapped
to accepted existing protected region type `2`; registration validates this
classification rather than creating a type `0x42`. The next authorization
check shows that type `2` itself has a zero domain bitmap and maximum mapping
class `0`, so the registered `gfx-data` region is not a direct UAT leaf target.
The remaining questions at that stage were whether any direct GXF-to-SPTM edge
existed and which frame types actually permit mapping, not assumed UPPL table
publication. See
[A15 / iOS 26.0.1 Research Worklog](A15_IOS26_WORKLOG.md) for the durable
checkpoint and exact next task.

The reverse GXF pass subsequently identifies the immediate firmware packet
constructor at `0xffffff80000339f8`: it emits command `0x10`, submits through
the GXF wrapper, and reaches `__rtk_mmu_map`. No branch, ID-7 endpoint value,
packet translation, or shared packet format connects that route directly to
SPTM endpoints 4/5. They are therefore treated as separate interfaces in the
same UAT/handoff architecture. The unresolved edge is between the kernel AGX
message path and the unsymbolized firmware constructor, not between the GXF
packet and the SPTM endpoint table.

## Diagnostic Response Logging

Every future diagnostic observation should record a timestamp, stage identifier,
input class, return status, and last completed stage. A process exit or reboot
must be recorded as an interrupted stage rather than interpreted as a protocol
response.

The source records a durable checkpoint immediately before every active
boundary, including command-buffer setup, the IORVBAR read, firmware copying,
both patchfinders, target-job mapping, and the GFX ROP trigger. The latest
exact-read run passed the active kernel patchfinder, complete IORVBAR object
graph, and `backboardd` lookup, then stopped cleanly before IPC entry scanning
because the asserted XNU 25 `ipc_space` table layout did not decode. Later
stages remain `DEVICE_RESULT_PENDING`; they must not be inferred from static
captures.

| Observable checkpoint | Current target result |
|---|---|
| Application support gate | `EXACT_ACTIVE_PROBE`; full jailbreak support remains false |
| Kernel exploit result | `PASS`; ClearSword selected and live kernel Mach-O header validated |
| Kernel patchfinder | `ACTIVE_PASS` on the exact target |
| Titan iOS 26 guard | exact `iPhone14,2/23A355` gate plus runtime object validation |
| RTBuddy/segment discovery | `READ_ONLY_PASS` from bounded capture |
| GFX firmware patchfinder | `STATIC_PASS` on the extracted image |
| IORVBAR object traversal | `ACTIVE_PASS`; exact descriptor and map validation completed on-device |
| `backboardd` process lookup | `ACTIVE_PASS`; pid 72 and unique `proc` reproduced |
| Exact IPC-table decode | `ROOT_CAUSE_FOUND`; normalize the signed `+0x48` word before the existing SMR allocation decoder |
| Open IOGPU userclient lookup | `NOT_REACHED`; corrected bounded read-only census source ready |
| GFX physical addresses and translation root | `DEVICE_RESULT_PENDING`; not reached in first run |
| Controlled mapping window | `DEVICE_RESULT_PENDING` |
| Titan `physwritebuf` publication | `DEVICE_RESULT_PENDING` |
| Dopamine physical read/write construction | `NOT_REACHED` |
| SPTM/TXM protected operations | `NOT_REACHED` |

The published SPTM/TXM architecture confirms a structured call contract rather
than an arbitrary response channel. XNU wraps a TXM request in `txm_call_t`,
passes it through `txm_kernel_call` and `txm_enter`, and SPTM dispatches it to a
registered TXM handler. The request carries a selector and argument counts; the
response is represented by `txm_ret`, `num_return_words`, and `return_words`.
See [Modern iOS Security Features: A Deep Dive into SPTM, TXM, and
Exclaves](https://arxiv.org/pdf/2510.09272), sections 8.3-8.4.

This model gives future USB logs a precise schema, but does not expose a direct
userspace interface. On the current target, no `txm_kernel_call` is reached, so
all runtime response fields must remain absent and the trace must remain
`NOT_REACHED`.

## Reproducible Diagnostic Build

- Source branch: `codex/a15-ios26-diagnostic-20261014`
- Source commit: `718a49a8d93a57c89831776cdc1529e4d98df423`
- GitHub Actions run: `38690838360` (successful, 2026-10-15)
- Artifact: `Dopamine-A15-iOS26-diagnostic-v2-718a49a.ipa`
- Size: `55,444,034` bytes
- SHA-256: `330DA0766A891C3A1792FC78B1C40FD263B1C1CD3251EB2434D1ABE80AD2287F`
- Application version: `3.0.11` (`com.opa334.Dopamine`)

On the exact iPhone14,2 / iOS 26.0.1 research target, this build replaces the
disabled main action with `Lancer le diagnostic`. That bounded action records
target and packaged-Titan observations in the UI, USB-visible `[A15DIAG]` log
lines, and `Documents/a15-ios26-diagnostic.json`. It cannot instantiate the
jailbreaker, initialize Titan command buffers, perform a physical write, or
claim a live SPTM/TXM response.

### On-device bounded diagnostic

The diagnostic completed on the USB-connected iPhone14,2 running iOS 26.0.1
build `23A355` on 2026-10-14. The report was pulled from the app container as
`a15-ios26-diagnostic-device-20261014.json` and has SHA-256
`AC467CFD44E2DE6BC07EF28962E4CA4980FCB4F70086F78CA31BAEFA740D2E3C`.

The seven reported checkpoints match the expected bounded state:

- `target.identity`, `environment.sptm`, and `titan.framework_metadata` are
  `OBSERVED`.
- `kernel.runtime_read_write` is reported as `MISSING` because the bounded
  diagnostic never loads or executes the metadata-selected ClearSword
  candidate; this is lack of runtime evidence, not absence of exploit code.
- `titan.command_buffers` is `BLOCKED` by diagnostic mode.
- `titan.physical_write` and `sptm_txm.runtime_response` are `NOT_REACHED`.
- `diagnostic_only` is true and `asserts_live_sptm_txm_response` is false.

### Phase 2 metadata preflight

The phase 2 bounded build advances the diagnosis without advancing execution. Its
`dopamine.a15-ios26.device-diagnostic.v2` report reproduces the packaged exploit
selection rules for every framework and flavor, recording version-range,
device-family, and build-override decisions. It also records arm64e, PAC/PPL
requirements, installation mode, and the presence of local kernelcache, SPTM,
and TXM artifacts in the app bundle or Documents directory.

Metadata eligibility is reported separately from runtime availability. In
particular, a kernel framework matching an iOS range remains only a candidate;
it does not establish a working A15 primitive. The overall chain stays blocked
unless every required stage has a matching candidate, and runtime kernel R/W
stays `MISSING` until independently observed.

This preflight only reads bundle metadata, environment properties, and file
existence. The guarded method is statically prohibited from referencing exploit
loading, `IOServiceOpen`, `IOConnectCall`, kernel read/write, command-buffer
setup, or physical-write functions. Titan execution and live SPTM/TXM requests
therefore remain blocked.

The phase 2 diagnostic completed on the USB-connected target on 2026-10-15.
Its 17 checkpoints and 11 framework/flavor entries were pulled as
`a15-ios26-diagnostic-v2-device-20261015.json`, with SHA-256
`0B51294D28BA37D09FFC0EBEFF529A5BDDD5F0ACC01EDCF1B95217F84FB5C1B0`.
The device result matches the offline model:

- Kernel metadata: 7 candidates, with ClearSword and DarkSword as the 2 range
  matches. These remain metadata candidates only; runtime kernel R/W is
  `MISSING`.
- PAC metadata: 1 candidate, 0 matches, and the stage is `NOT_REQUIRED` on this
  target.
- PPL metadata: 3 candidates and 0 matches. Titan and dmaFail miss the version
  range; momentarius misses the declared device family.
- The overall selector result is `BLOCKED` with `ppl-bypass-missing`.
- Local kernelcache, SPTM, and TXM artifacts are all `MISSING` from the app
  bundle and Documents directory.
- Titan command buffers stay `BLOCKED`; physical write and live SPTM/TXM
  response stay `NOT_REACHED`.

That phase-2 artifact packaged Titan only for iOS `16.1` through `17.3.1` and
returned unsupported before exploit selection. The active-probe source retains
that general range and adds one explicit `iPhone14,2/23A355` inclusion; this
does not retroactively change the historical phase-2 result.

Offline/VM validation regenerated both static reports from the extracted
kernelcache, GFX, SPTM, and TXM images. The adapted iOS 26 kernel and GFX
relationships pass their static checks, as do the inspected SPTM/TXM
relationships. These tests validate parsers, anchors, packaging, and safety
guards only; a VM cannot reproduce the live A15 RTKit/AGX state, SPTM hardware,
GPU memory behavior, MMIO access, or a physical-write primitive.

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
- Exact-length OSSymbol reads identified dictionary entry 13 as
  `segment-names`, entry 14 as `segment-ranges`, entry 17 as
  `IODeviceMemory`, and entry 18 as `IOReportLegend`.
- Both segment-property values are `OSData` objects. Their reconstructed
  unslid object-vtable pointer is `0xfffffff007aaad98`, and the target kernel
  registers the class with size `0x28`. Target-kernel methods prove
  `length=+0xc`, `capacity/external-sentinel=+0x10`,
  `capacityIncrement=+0x14`, `data=+0x18`, and
  `owner/deallocator=+0x20`.
- The live `segment-ranges` object has length `0x40` and the live
  `segment-names` object has length `0xe`. Both use the `0xffffffff` external
  buffer sentinel at `+0x10`.
- Static analysis of `RTBuddy` function `0xfffffff00a51214c` proves that it
  divides the `segment-ranges` length by `0x20` and consumes one 32-byte
  descriptor per iteration. The bounded 64-byte capture therefore contains
  exactly two descriptors:
  - descriptor 0: `+0x00=0x8007ac000`,
    `+0x08=0xffffff8000000000`, `+0x10=0x8007ac000`,
    `length=0x5c000`, raw flags `0x1`;
  - descriptor 1: `+0x00=0x802048000`,
    `+0x08=0xffffff800005c000`, `+0x10=0x802048000`,
    `length=0xd8000`, raw flags `0x0`.
- `RTBuddy` loads each raw descriptor as physical address at `+0x00`, virtual
  address at `+0x08`, remap address at `+0x10`, 32-bit length at `+0x18`, and
  32-bit flags at `+0x1c`. It deliberately reorders the three address arguments
  before calling factory `0xfffffff00a505df0`, which stores physical at object
  offset `+0x18`, remap at `+0x20`, virtual at `+0x28`, length at `+0x30`, and
  transformed flags at `+0x40`.
- Target-kernel method `0xfffffff00a506234` passes object fields `+0x18` and
  `+0x30` to the physical-memory-descriptor factory at
  `0xfffffff0086e9dfc`. Methods `0xfffffff00a506298` and
  `0xfffffff00a506308` perform range checks against remap base `+0x20`, while
  methods `0xfffffff00a5062d0` and `0xfffffff00a506334` perform the matching
  checks against virtual base `+0x28`.
- This field order also matches a
  [comparative T8030 DeviceTree dump](https://gist.github.com/bazad/1faef1a6fe396b820a43170b43e38be1)
  that labels the same 32-byte format as `phys`, `virt`, `remap`, `size`, and
  `flags`. That external sample is corroborating format evidence, not
  target-device evidence.
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
- Each packaged GFX firmware slice contains one `0x7777777777777700` RTKit
  marker occurrence in `__TEXT` at `0xffffff8000000990`. The surrounding bytes
  belong to the executable image, not the live reset-vector structure, so an
  offline or VM scan cannot recover `gfx_data_pa` or `gfx_ttbr_pa` from it.
- The exact `gfx-asc` DeviceTree node contains only the `0x06400000/0x6c000`
  register range and the `0x06050000/0x8` IORVBAR range. Its RTBuddy nub adds
  firmware and power-management metadata, but neither node contains a reset
  vector, a GFX data physical address, or a GFX page-table base.
- The observations used for this work were bounded and read-only. No kernel
  write, GPU command queue, direct physical write, or MMIO access was used.

## Executed Bounded Probes

- Property metadata was read in blocks of four entries, restoring the disabled
  configuration and confirming HTTP `403` after every successful capture.
- String reads were limited to the exact length proven by each OSSymbol's
  packed length field.
- `segment-ranges` metadata was read first. Only after its `OSData` length was
  validated as `0x40` did a second probe read exactly eight 64-bit words, for
  a total of 64 bytes and two statically proven 32-byte descriptors.
- The `segment-names` key and `OSData` metadata were validated independently.
  A subsequent exact 14-byte payload read closed the connection before a
  capture file was produced. The disabled configuration was restored over USB
  and the payload read was not retried automatically.
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
- The unsupported target now exposes a separate `Run Diagnostics` action. It
  records target identity, SPTM presence, packaged Titan metadata, and explicit
  blocked/not-reached checkpoints to the UI, USB system log, and
  `Documents/a15-ios26-diagnostic.json`. It never instantiates `DOJailbreaker`
  or calls Titan, GFX, kernel-write, MMIO, or physical-write code.

These items are research scaffolding. They have not established an end-to-end
physical-write primitive and must not be interpreted as exploit support.

## Phase 3 Binary and App-Owned Memory Preflight

The next device diagnostic advances one bounded step beyond metadata selection:

- It reads the already packaged ClearSword and DarkSword executables as data.
- It validates their 64-bit ARM Mach-O headers and load-command bounds, then
  records `LC_BUILD_VERSION`, linked dylibs, file size, and three static marker
  strings. It does not load either framework or resolve an entry point.
- It reads `hw.pagesize`, `hw.cputype`, and `hw.cpusubtype` through `sysctlbyname`.
- It allocates and immediately deallocates one page in `mach_task_self`. The
  page is never written, shared, remapped, or exposed to an I/O service.
- It writes `Documents/a15-ios26-diagnostic-v3.json` with schema
  `dopamine.a15-ios26.device-diagnostic.v3`.

The phase remains diagnostic-only. It does not create an IOSurface, request a
PurpleGfxMem mapping, call either exploit, create sockets, issue GPU work, or
access SPTM/TXM. The integration checker explicitly rejects those calls from
the diagnostic body.

The reproducible phase 3 build completed successfully on 2026-10-15:

- Source commit: `1faefa50ff2f6507833806da1a217a449d28d4dc`
- GitHub Actions run: `38693388683` (successful in 11m 9s)
- Artifact: `Dopamine-A15-iOS26-diagnostic-v3-1faefa5.ipa`
- Size: `55,447,669` bytes
- SHA-256: `88A20F9CD764492BD3D8C6528A9AC01F3953B6C46E5D52F346F25DC925ABC790`

Post-build inspection confirms the v3 schema and output filename in the main
executable, the packaged ClearSword and DarkSword frameworks, and Titan's
unchanged declared support range of iOS `16.1` through `17.3.1`. Device
observations were collected from the USB-connected target on 2026-10-15. The
report was pulled as `a15-ios26-diagnostic-v3-device-20261015.json`, with
SHA-256 `B0368D9FFE288FB3C59F42D08E7C5E26A4BEC689D148BBD65222961A44BEC9EF`.

The bounded runtime and binary observations are:

- The target reports matching `vm_page_size` and `hw.pagesize` values of
  `16,384` bytes. Allocation and deallocation of one app-owned page both return
  success, and `memory_written` remains false.
- ClearSword is a valid ARM64 Mach-O of `93,920` bytes with valid load-command
  bounds, minimum iOS `15.0.0`, and SDK `26.5.0`.
- DarkSword is a valid ARM64 Mach-O of `112,464` bytes with valid load-command
  bounds, minimum iOS `15.0.0`, and SDK `26.5.0`.
- Both binaries link IOSurface and contain the three expected static marker
  strings, but neither framework was loaded or invoked by the diagnostic.
- The selector remains `BLOCKED` at `ppl-bypass-missing`: two kernel metadata
  candidates, no PPL candidate, no runtime kernel read/write primitive.
- Titan command buffers remain `BLOCKED`; physical write and SPTM/TXM runtime
  response remain `NOT_REACHED`.

## Phase 4 Static Symbol Inventory and Standard IOSurface Preflight

The phase 3 packaged frameworks were inspected offline with
`tools/a15_ios26/analyze_macho_preflight.py`. The tool parses the Mach-O symbol
metadata and code-signature bounds directly from bytes; it cannot load or
execute the target image.

The generated inventories are `clearsword-macho-preflight-v1.json` (SHA-256
`D10EB05832FA4ABEA3CAE078DEA823EF7F712086FEC6B7423156C478050CD7F2`) and
`darksword-macho-preflight-v1.json` (SHA-256
`9B3C8E07A46A3D85CF0D0B337414287F9E4B6E594EA013F94B80B3A843435C1F`).

- ClearSword contains 343 symbols, including 88 imports and 37 exports.
- DarkSword contains 437 symbols, including 91 imports and 78 exports.
- Both import three IOSurface functions, Mach VM functions, socket functions,
  and file read/write functions. DarkSword additionally imports four direct
  IOKit functions.
- Both export their exploit entry points and early kernel read/write helpers.
  This confirms that invoking either entry point would cross directly into the
  invasive chain; phase 4 therefore does not load either framework.

The phase 4 device diagnostic instead creates one ordinary private `16x16`
IOSurface with a four-byte element size, reads only its public dimensions and
allocation size, and immediately releases it. Static guards reject base-address
access, Mach-port creation, page prefetching, memory-region selection, IOKit,
socket, exploit, GPU, kernel-write, and SPTM/TXM calls from the diagnostic body.
The report schema is `dopamine.a15-ios26.device-diagnostic.v4`, written to
`Documents/a15-ios26-diagnostic-v4.json`.

The reproducible phase 4 build completed successfully on 2026-10-15:

- Source commit: `aac651dceed2864a9e9b8426e749d0a438e823a2`
- GitHub Actions run: `38697310661` (successful in 11m 27s)
- Artifact: `Dopamine-A15-iOS26-diagnostic-v4-aac651d.ipa`
- Size: `55,448,017` bytes
- SHA-256: `F0A09788B46FE6D0614D46ED31EE909DD97A9AF1E16A3BB190763FD36C0D0BD6`

Post-build inspection confirms the v4 schema, output filename, bounded
IOSurface checkpoint, and all five negative safety flags in the main
executable. Titan's declared iOS `16.1` through `17.3.1` range is unchanged.

The phase 4 diagnostic completed on the USB-connected target on 2026-10-15.
Its 21 checkpoints were pulled as
`a15-ios26-diagnostic-v4-device-20261015.json`, with SHA-256
`B24D91C86D3251446730207D6B97C8EF1DAB41CF00DB3AA6BA3DF3215523C3F5`.
The standard IOSurface result is `PASS`: width `16`, height `16`, bytes per row
`64`, allocation size `1,024`, and `released=true`. Base-address access,
Mach-port creation, prefetching, memory-region selection, and IOKit calls all
remain false. The app-owned 16 KiB VM allocation/deallocation also remains
`PASS` with no write. Selector, kernel, Titan, and SPTM/TXM states are unchanged:
`ppl-bypass-missing`, `MISSING`, `BLOCKED`, and `NOT_REACHED`, respectively.

## Phase 5 Read-Only IOSurface Lifecycle and Boundary Trace

Phase 5 extends the ordinary private `16x16` IOSurface checkpoint with exactly
one `IOSurfaceLock`/`IOSurfaceUnlock` pair using
`kIOSurfaceLockReadOnly | kIOSurfaceLockAvoidSync`. It records the return codes
and seed values, then releases the surface. It does not obtain the base address,
read or write the surface contents, create a Mach port, prefetch pages, request
a memory region, or call IOKit. The report schema is
`dopamine.a15-ios26.device-diagnostic.v5`, written to
`Documents/a15-ios26-diagnostic-v5.json`.

The response-trace builder now accepts an optional bounded device diagnostic.
Its v2 output separates `selector.ppl_metadata` as the first metadata blocker
from `kernel.runtime_read_write` as the first runtime blocker. Request
generation, transmission, handler dispatch, and response receipt are all
explicitly false, while `protected_component_boundary` remains `NOT_REACHED`.
This prevents a successful app-owned allocation or IOSurface lifecycle from
being misreported as a protected-component response.

Two public reverse-engineering notes were used only as architectural comparison:

- `https://proteas.github.io/ios/2023/06/09/some-quick-and-discrete-notes-on-sptm.html`
  identifies separate SPTM/TXM firmware images, the kernel `__DATA_SPTM`
  segment, and dispatch-related strings.
- `https://newosxbook.com/bonus/sptm2.html` describes an iOS 17.1.1 flow in
  which XNU enters SPTM with `GENTER`, TXM enters with `SVC #0`, and SPTM routes
  calls through subsystem dispatch tables.

Those observations are not target-version evidence. They do not establish that
the A15/iOS 26.0.1 request boundary, handler, or return path has been reached.
The structured comparison is recorded in
`docs/SPTM_IOS17_IOS26_STATIC_COMPARISON.md`.
It also records the post-iOS-17 Titan hardening sequence and the bounded role
of `qemu-sptm`/`darwin-vm` as an emulator-based comparison environment.

The reproducible phase 5 build completed successfully on 2026-10-15:

- Source commit: `38abc22d40f9c439750089d3473c2c03f0224e6d`
- GitHub Actions run: `38700381273` (successful in 13m 42s)
- Artifact: `Dopamine-A15-iOS26-diagnostic-v5-38abc22.ipa`
- Size: `55,449,632` bytes
- SHA-256: `7198C453407AA069973BADDBDAE501FEB1C5B235FB5E7E326E72B1743BAF68C8`

Post-build inspection confirms the v5 schema and output filename, the exact
read-only plus avoid-sync lock mode, the single lock/unlock lifecycle, and the
negative `memory_written` marker in the main executable. Titan's declared iOS
`16.1` through `17.3.1` range remains unchanged.

The phase 4-backed response trace v2 is recorded as JSON with SHA-256
`431954B2507F5F0E633D6B6A9607C523EB29B5869C90B2F36281C2317A71D235`
and Markdown with SHA-256
`DEC0B82C5E536B7F0F0CF6329A411C5B9F0878AE6ED181E38F369A28D8284E6E`.

The phase 5 diagnostic completed on the USB-connected target on 2026-10-15.
Its 21 checkpoints were pulled as
`a15-ios26-diagnostic-v5-device-20261015.json`, with SHA-256
`D2FAF47166C6AA8A190A5449B00512CBC8A0BC584FF985CF72457B3850D7B5DF`.
The standard IOSurface result is `PASS`: width `16`, height `16`, bytes per row
`64`, allocation size `1,024`, lock status `0`, unlock status `0`, both seed
values `0`, and `released=true`. The exact lock mode is read-only plus
avoid-sync. Base-address access, Mach-port creation, prefetching, memory-region
selection, IOKit calls, and memory writes all remain false.

Rebuilding response trace v2 from the phase 5 report produces the same JSON
and Markdown hashes listed above because the boundary states are unchanged:
the first metadata blocker remains `selector.ppl_metadata`, the first runtime
blocker remains `kernel.runtime_read_write`, and the protected-component
boundary remains `NOT_REACHED`.

The previously missing symmetric iOS 17 baseline is now available. The exact
iPhone14,2/A15 iOS 17.1.1 build 21B91 kernelcache, SPTM, and TXM were extracted
from the Apple-hosted IPSW with HTTP range requests and analyzed with the same
unmodified script as build 23A355. Provenance, hashes, commands, and results are
recorded in `docs/A15_IOS17_1_1_SYMMETRIC_BASELINE.md`; the consolidated delta
is in `docs/SPTM_IOS17_IOS26_STATIC_COMPARISON.md`.

The follow-up normalized analyzer keeps the original reports intact and writes
new `-v2` artifacts. It resolves the direct `ADR` chains in 21B91 TXM and tags
frame-type policy as `immediate_bitmask` on 21B91 or `descriptor_table` on
23A355. TXM, the SPTM image, and kernel integration now report static `PASS` on
both builds. This removes two analyzer limitations but does not change the live
chain: no protected request was generated or transmitted.

The v3 static reports add a symmetric entry-instruction census. Build 21B91
contains one TXM `SVC #0` and seven kernel `GENTER` instructions (`#0` through
`#3`); build 23A355 contains two TXM `SVC #0` thunks and nine kernel `GENTER`
instructions (`#0` through `#4`). Nearby `x16` setup is retained as evidence,
but no endpoint or dispatch-table identity is inferred. This remains offline
evidence: no privileged instruction was executed and the protected-component
boundary remains `NOT_REACHED`.

The v4 reports trace direct TXM tail branches and reconstruct `x16` only when
all 64 bits are defined by a bounded immediate-write sequence. Both builds
produce the same seven raw descriptor constants. The first 23A355 `SVC #0`
thunk has the same seven direct predecessors as 21B91; the added second thunk
has no direct branch cross-reference in decoded text. Indirect reachability is
not excluded, and the values are not promoted to endpoint or permission
identities.

The v5 offline census narrows the next static comparison. SPTM contains one
`GENTER #0` on both builds, while `GEXIT #0` grows from four sites on 21B91 to
seven on 23A355. The newer image also directly references
`validate_sptm_dispatch_table_id` and `validate_dispatch_endpoint_id`, and has
more references to `dispatch_state_machine` and `genter_dispatch_entry`.
These locations are suitable for a symmetric bounded call-graph comparison.
They are not a proven remaining bypass branch, and no device logging at the
protected boundary has been enabled.

The v6 symmetric guard graph resolves that comparison. The named 23A355
validators are inlined checks with structural 21B91 counterparts. Both builds
bound dispatch-table IDs to `0..15`, but the endpoint contract changes from an
effective `0..31` low-byte range with 8-byte entries on 21B91 to the masked
criterion `(x0 & 0xfe) < 0x32` with 16-byte entries on 23A355. State/event
bounds also grow from `17/12` to `23/15`, and the newer GENTER classifier adds
endpoint-derived events `12`, `13`, and `14`.

The report now records candidate functions, direct callers, direct branch
ingress, and bounded comparison/conditional-branch guards. This identifies a
policy migration, not an adaptable residual bypass branch. Runtime protected
request state remains `NOT_REACHED`, so no new IPA was built for this offline
analyzer-only phase.

The v7 offline callback trace then follows `sptm_dispatch` from pointer
materialization to endpoint invocation. Both 21B91 and 23A355 use `PACIZA` at
registration, `XPACI` before canonical table storage, `BRAA` for the dispatch
state-machine action, and a tail trampoline ending in `BLRAAZ` for the selected
endpoint handler. The common table registrations remain IDs `0`, `1`, and `2`
with values `2`, `4`, and `8`; 23A355 adds a conditional ID `0xa`/value `0x10`
registration and a wrapper path.

This removes an authentication-downgrade hypothesis: the iOS 26 path remains
PAC-protected at the same structural stages. The added registration topology
does not identify a reusable iOS 17 bypass branch, and the live protected
boundary remains `NOT_REACHED`.

The v8 offline report reconstructs the registration descriptors themselves.
Both builds register table IDs `0`, `1`, and `2` with `x2` values `0x2`,
`0x4`, and `0x8`; 23A355 adds table ID `0xa` with `0x10` and one dynamic
wrapper (`x0` from `x1`, `x2` from `x3`). The state-machine consumer shifts
the stored `x2` value by the current caller-domain index and tests bit zero.
Consequently these values are domain permission masks, not event IDs or
counts. The common masks permit domain bits `1`, `2`, and `3`; the new iOS 26
mask permits domain bit `4`. The 23A355 transition metadata labels those bits
`XNU`, `TXM`, `SK`, and `XNU_HIB`, respectively. The dynamic wrapper is the
separate IOMMU dispatch-table registration path; its later endpoint-table
store is not the permissions field.

The event matrix is separate: its event stride remains `0x20`, while its state
row grows from `0x180` on 21B91 to `0x1e0` on 23A355. The permission-table
descriptor remains `0x18` bytes on both builds. This narrows the contract
delta but does not change the live `NOT_REACHED` result, so no active SPTM/TXM
request or new IPA belongs to this static phase.

The v9 analysis closes the dynamic IOMMU-wrapper branch. SART, NVMe, uat, and
t8110dart produce the same table IDs and masks on both builds: `5/0x2`,
`6/0x2`, `7/0x2`, and `3/0x2 + 4/0x8`. iOS 17 carries the fields directly at
`+0x20/+0x28/+0x30`; iOS 26 introduces a `0x20`-byte registry, authenticated
descriptor pointers, wrapper `0xfffffff0270cc1ac`, and fields at
`+0x30/+0x38/+0x40`. The topology changed, but the observed permission contract
did not.

## Public Dopamine and Titan Fork Review

A read-only GitHub review was performed on 2026-10-15. It covered the newest
180 default branches in the public `opa334/Dopamine` fork network, targeted
code-search results containing Titan's IPC helper, relevant upstream pull
requests, and every public fork and non-default branch returned for
`alfiecg24/Titan` (22 forks at the time of review). A GitHub fork review cannot
prove that no unpublished work exists, but it separates implemented code from
version-label and UI claims.

No reviewed Dopamine fork contains a verified A15/23A355 adaptation of
Titan's IPC-port transfer or a replacement SPTM/TXM bypass. The original Titan
documentation explicitly says that its IPC port-stealing primitive was patched
in iOS 26 by adding data PAC to `ipc_port->ip_nsrequest`. The public Titan
forks contain no commits or divergent branches beyond the original repository.
This is consistent with upstream Titan metadata, which limits A14-A17 support
to iOS 16.1-17.3.1 rather than declaring A15/iOS 26 support.

The strongest concrete fork result is commit `5600ac412e` on the historical
`wip/darksword-integration` branches. It adds iOS 17.1-26.0 ClearSword/DarkSword
structure offsets for `inpcb`, `inpcbinfo`, `socket`, and
`kalloc_type_view`. Those exact iOS 26 values already appear in the current
upstream code and in the successful ClearSword portion of the 23A355 device
trace. The commit changes neither Titan nor SPTM/TXM, so it confirms the kernel
primitive setup but does not advance the protected-write stage.

`Anthony5473/dopamine-a18` is the only indexed non-upstream repository found
with materially different Titan IPC and patchfinder sources. Its changes target
A18/iOS 18.0-18.2. Its IPC change hard-codes `proc.p_comm = 0x56c` for
XNU 11215, whereas the bounded 23A355 probe found both `0x56c` and `0x57d` and
proved that only `0x57d` uniquely resolves `backboardd`. It does not implement
an iOS 26 `ip_nsrequest` PAC solution and is not transferable to the exact
target.

`tdd761914-arch/Dopamine` contains real exploit work: an A14/T8101
Momentarius port for iOS 17.4-18.7.1, an AGX-firmware scan through a trusted
kernel mapping, and a separate ClearSword IOSurface cleanup overread fix. It is
useful comparative material for A14, but it does not modify Titan, SPTM/TXM, or
the A15/iOS 26 IPC path.

The reviewed RootHide and repackaging variants either retain the exact upstream
`ipc_port.c` blob or add only logging, path, bootstrap, and UI changes. Other
apparent iOS 26 forks only widen `Info.plist` version ranges, change support
text, re-upload unchanged Titan files, or remove the exploit sources entirely
for a demo build. `OarCaw1126/Dynamite`, for example, declares Titan through
iOS 26.0.1 by changing one metadata line while providing no corresponding
Titan/SPTM/TXM implementation. None is evidence of a working A15/iOS 26 Titan
path.

Primary references:

- https://github.com/opa334/Dopamine
- https://github.com/opa334/Dopamine/blob/3.x/Application/Dopamine/Exploits/Titan/Info.plist
- https://github.com/alfiecg24/Titan
- https://github.com/masckmaster2007/Dopamine/commit/5600ac412e032b13be504cbf21ced9a52b92a7bb
- https://github.com/Anthony5473/dopamine-a18/commit/ab1f5d2aa82370e50100d8d443d59b6f48c11c88
- https://github.com/tdd761914-arch/Dopamine/commit/8031085a10cbc4651d25cf7c131e536b5be46065
- https://github.com/tdd761914-arch/Dopamine/commit/8ef885889351f866756687411b9a4db608e32178
- https://github.com/tdd761914-arch/Dopamine/commit/1a95dc986e552dcda5072d8e59100cf90a0f59e0
- https://github.com/OarCaw1126/Dynamite/commit/adce436d3ca1712c0b578bc611b9cbb12cf58a08
- https://github.com/P013onEr/RootHide/commit/6fa2ddf2021e4914cc9c7eec58cae7682b15fbbf
- https://github.com/opa334/Dopamine/pull/1038

## Broader Public GitHub Survey

A broader GitHub review on 2026-10-15 found public A15/23A355 material, but
no independently verified full jailbreak or SPTM/TXM bypass for
`iPhone14,2` on iOS 26.0.1.

`rooootdev/lara` and its derivatives contain the most relevant public
DarkSword work outside Dopamine. Lara advertises iOS 26.0-26.0.1 support and
contains A15-specific offset handling. Pull request 323 contributes an
XPF-derived `proc.p_name` value for an A15/T8110 23A355 kernelcache. This is
useful exact-build structure evidence, but Lara is a customization toolbox,
not a published Titan or SPTM bypass. Its issue tracker also documents that
RemoteCall remains unreliable on protected modern targets.

`kaffeindecaf/W0lfSword` has a substantial host-side A15/23A355 research set.
It verified the T8110 kernelcache, `task.itk_space=0x310`,
`proc.struct_size=0x748`, and SPTM presence. Its own testing record states that
the A15/iPhone14,7 device was used only for read-only USB, syslog, crash-report,
and offline kernelcache work; the full DarkSword run was initially not tested.
A later roadmap entry records that the staged A15/26.0.1 device run panicked.
This is valuable negative evidence and offset data, not a successful A15
chain.

`0xjohnnydev/cyanide` and FilzaJailedDS-derived projects expose DarkSword
kernel-read/write and RemoteCall-based customization over the affected iOS
window. They explicitly describe themselves as tweak runners or file-manager
escapes rather than traditional jailbreaks. Public compatibility tables cover
iOS 26.0-26.0.1, but they do not publish a validated A15 SPTM physical-write,
trust-cache, or bootstrap path.

`Indegosblade/pmap-tte-remove` documents a separate physical use-after-free
primitive. The repository reports 64/64 write-through on A17 Pro and A19, but
its limitations section explicitly says controlled reclaim is blocked by SPTM
quarantine on A14+ and that exploitation beyond the primitive requires an
unknown quarantine bypass. It therefore confirms a promising primitive class,
not an A15 jailbreak path.

`tosoonmulu123-ui/DSPloit` claims full A15/iOS 26.0.1 support in its README,
but the claim is not supported by its implementation or public CI evidence.
The latest default-branch revision, `905a4389c379`, fails its public build run
[`27388189528`](https://github.com/tosoonmulu123-ui/DSPloit/actions/runs/27388189528),
so no current release artifact is produced. `DeviceCompat.swift` marks iOS
26.0-26.0.1 supported from a version-range condition; it is not a device proof.
The fallback JPEG path says that the IOSurface-to-socket transition is still a
TODO and returns failure, while the SEPKeyStore path says full weaponization
still needs an information leak and gadget resolution. More importantly for
23A355, `amfi_bypass.m` labels its three fixed pmap/AMFI addresses as results
from an iOS 18.2 kernelcache, acknowledges PPL-blocked writes, and skips a
per-pmap write because it can respring devices. Its own context-transfer
document says device confirmation was only on an iPhone XR with iOS 18.2 and
lists AMFI, trust-cache, PAC, and PPL steps as blocked. DSPloit therefore
contains useful DarkSword-derived experiments, but no validated A15/23A355
SPTM/TXM bypass or complete jailbreak chain that can be transplanted here.

### CVE-2026-43748 ANE Direct-Path Assessment

The public `vschko/CaseStudies` write-up describes an out-of-bounds kernel
heap write in the Apple Neural Engine direct path. `ANE_ProgramSendRequest`
accepts as many as `0xff` IOSurfaces across its buffer lists, while
`ANEHWDevice::ANE_ProgramCheckandPrewireBuffers_gated` allocates storage for
only `0x80` 16-byte entries. The reported maximum overwrite is therefore
approximately `(0xff - 0x80) * 0x10 = 0x7f0` bytes in `data.kalloc.3072`.
The direct-path user client is reported as reachable from an application
sandbox without a dedicated entitlement.

Apple classifies CVE-2026-43748 as an Apple Neural Engine out-of-bounds write
whose public impact is unexpected system termination. Its iOS 26.6 advisory
lists iPhone 11 and later as affected devices and says the issue was fixed by
improved bounds checking. This makes the iPhone14,2 on 23A355 a likely affected
target, but the advisory does not establish identical exploitability or object
layout on this exact build.

The local exact-target kernelcache provides stronger structural evidence. The
23A355 `RELEASE_ARM64_T8110` image has SHA-256
`8867208C59BFA426611C36FCFE570FFC41CC75EE293472FE7197860D0C5223F1` and contains
`ANE_ProgramCheckandPrewireBuffers_gated`, `ANE_ProgramSendRequest`,
`H11ANEInDirectPathClient`, `H1xANELoadBalancerDirectPathClient`,
`kANEMaxBuffers`, and `programSendRequest`. Current evidence status is
`STRUCTURALLY_PRESENT / CONSTANTS_AND_CONTROL_FLOW_NOT_YET_VERIFIED`: the
relevant driver path is present, but the `0xff` versus `0x80` mismatch and the
late validation order still need exact-build disassembly confirmation.

This CVE does not fill the current Titan/SPTM gap. The public iOS proof of
concept repeatedly invokes CoreML until an MTE-related panic and does not claim
a stable kernel read/write primitive, protected physical write, accepted SPTM
request, trust-cache insertion, or TXM bypass. This project already has a
working ClearSword kernel primitive on the target, so CVE-2026-43748 is best
treated as an independent heap-corruption and reliability research path, not a
replacement for the missing SPTM transition. The panic-oriented proof of
concept must not be integrated into the diagnostic IPA. Static comparison with
the iOS 26.6 fix should precede any bounded device probe.

### Divine Seagull / Coruna Expansion Assessment

NetAskari's 2026-10-14 analysis of the captured `Divine Seagull V5` framework
does not disclose a working iOS 26 jailbreak chain. It describes three tracks:
the legacy `Godkiller V1` Coruna/DarkSword path, a `Liangri_26` wrapper, and a
parallel `Nextgen` primitive harvester. The article explicitly characterizes
most of the iOS 26 additions as incomplete research scaffolding rather than a
functioning deployment.

The only component assessed as a real renderer bug is a WebKit
CVE-2025-43529 use-after-free. The remaining advertised tiers include a WASM
BBQ-JIT attempt, a WebGPU placeholder, a WASM mutator, a PAC/JOP experiment,
an IOKit cold path, and a `splashboardd` XPC attempt. According to the captured
code review, these tiers either poll for another tier's primitive, fall back to
DarkSword, fuzz for crashes, or never reach a useful primitive. No public
source or reproducible artifact for the captured framework was found outside
the article.

Most importantly, the post-primitive `pe_main.js` and `kchain_escape.js` route
is reported as legacy code built for iOS 17 and earlier. The analyzed framework
therefore stops before a working iOS 26 sandbox/credential transition even
when its browser stage succeeds. Apple documents CVE-2025-43529 as a WebKit
use-after-free capable of arbitrary code execution and fixed with improved
memory management, but a renderer primitive does not imply kernel access or an
SPTM/TXM bypass.

For the current iPhone14,2/23A355 effort, this is useful negative evidence:
`Divine Seagull` neither improves the already working ClearSword kernel
primitive nor supplies Titan command-buffer acquisition, protected physical
write, an accepted SPTM request, trust-cache insertion, or TXM policy bypass.
Its C2 and data-harvesting portions are unrelated to the bounded diagnostic
goal and must not be imported. No new IPA is justified by this material.

Other useful repositories remain analysis infrastructure rather than an
on-device bypass: `Lessica/libgrabkernel2` can extract the A15 23A355
kernelcache efficiently; `cloverfield11/ios26-hypervisor-research` documents
SPTM virtualization statically; `jprx/qemu-sptm` and `Xplo8E/vphone-cli`
support emulation or virtualized firmware study. None supplies the missing
exact-target Titan/SPTM transition.

The practical conclusion is narrower than the number of GitHub claims:
public work supports A15 kernelcache analysis and DarkSword/ClearSword kernel
read/write experimentation, but the verified public chain still stops before
an A15/23A355 protected physical-write or equivalent SPTM/TXM bypass. The live
bounded trace in this project currently provides stronger exact-target Titan
progress evidence than the reviewed public repositories.

Primary references:

- https://github.com/rooootdev/lara
- https://github.com/rooootdev/lara/pull/323
- https://github.com/kaffeindecaf/W0lfSword
- https://github.com/kaffeindecaf/W0lfSword/blob/main/TESTING.md
- https://github.com/kaffeindecaf/W0lfSword/blob/main/ROADMAP.md
- https://github.com/0xjohnnydev/cyanide
- https://github.com/34306/FilzaJailedDS
- https://github.com/Indegosblade/pmap-tte-remove
- https://github.com/tosoonmulu123-ui/DSPloit
- https://github.com/tosoonmulu123-ui/DSPloit/blob/main/context_transfer.md
- https://github.com/vschko/CaseStudies/tree/main/CVE-2026-43748
- https://github.com/vschko/CaseStudies/blob/main/CVE-2026-43748/pocs/ios_poc/poc-ane/ViewController.m
- https://support.apple.com/en-us/128066
- https://netaskari.substack.com/p/divine-seagull-coruna-darksword-expansion
- https://support.apple.com/en-ae/125884
- https://github.com/Lessica/libgrabkernel2/blob/main/docs/aea-fast-path.md
- https://github.com/cloverfield11/ios26-hypervisor-research
- https://github.com/jprx/qemu-sptm
- https://github.com/Xplo8E/vphone-cli

## pois0nSword Parallel Comparison

`GenericCoding/pois0nSword` was reviewed at commit
`3caf88be7f46923db6ef62cc69cc7e6597c59928` without executing its JavaScript.
The repository targets iOS 26.1 build `23B85` and supplies offset profiles only
for `iPhone14,7` and `iPhone15,5`; it has no `iPhone14,2/23A355` profile.

Its implemented path is a WebContent/JSC chain: CVE-2025-43529 primitives,
DarkSword-style userland read/write, JSC/WebCore object traversal, a userland
PAC bypass, and an indirect native-call test. The repository does not provide
an ANGLE sandbox escape, kernel read/write, a Titan physical-write primitive,
or an SPTM/TXM bypass. Its offsets and internal JSC/WebCore/dyld layouts cannot
be transferred from `23B85` to `23A355`.

The reusable part is methodological: build-and-device keyed offset profiles,
staged primitive validation, bounded retries, and explicit logging between
chain stages. These patterns can improve diagnostics, but pois0nSword is not a
replacement for runtime confirmation of the selected ClearSword primitive or
the missing `selector.ppl_metadata` stage in the current Dopamine trace.

Primary references:

- https://github.com/GenericCoding/pois0nSword/tree/3caf88be7f46923db6ef62cc69cc7e6597c59928
- https://github.com/GenericCoding/pois0nSword/blob/3caf88be7f46923db6ef62cc69cc7e6597c59928/README.md
- https://github.com/GenericCoding/pois0nSword/blob/3caf88be7f46923db6ef62cc69cc7e6597c59928/do_chain.js
- https://github.com/GenericCoding/pois0nSword/tree/3caf88be7f46923db6ef62cc69cc7e6597c59928/offsets

## Phase 6 Jailbreak Selection Dry Run

Phase 6 adds an ordered dry-run trace of the application jailbreak path. It
uses `DOExploitManager` to record the exploit choices that the real path would
make from packaged metadata and user preferences, then records the first
proven missing requirement. This is more precise than treating every
metadata-eligible framework as selected.

The trace keeps `gatherSystemInformation` as the earliest unexecuted stage.
It reports whether the three static inputs are already present, but it does not
call that method because the normal path can download images and start XPF.
It then records kernel, PAC, and PPL selection before marking exploit load,
exploit execution, physRW construction, privilege elevation, bootstrap work,
and protected-component access as not executed or not reached.

The report schema is `dopamine.a15-ios26.device-diagnostic.v6`, written to
`Documents/a15-ios26-diagnostic-v6.json`. Its `jailbreak_dry_run` object keeps
explicit false flags for image download, XPF startup, framework loading,
exploit entry points, kernel primitives, physRW, privilege changes, bootstrap
changes, and protected requests. This test can identify the first proven
selection blocker without claiming that a jailbreak attempt occurred.

The reproducible phase 6 build completed successfully on 2026-10-15:

- Source commit: `5d084b4376ae127b301e54946c4a752300ad22e4`
- GitHub Actions run: `38704278559` (successful in 6m 37s)
- Artifact: `Dopamine-A15-iOS26-diagnostic-v6-5d084b4.ipa`
- Size: `55,451,968` bytes
- SHA-256: `B7247DEC04706CEBB66338E0AB8906FB25C5B4D7DC8FAEF1DC6D6FFD652731EB`

Post-build inspection confirms the v6 schema and filename, the dry-run mode,
the first-proven-blocker and earliest-unexecuted-stage fields, and the explicit
no-load/no-entrypoint/no-protected-request evidence in the main executable.
Titan's packaged support range remains iOS `16.1` through `17.3.1`; no target
support metadata was widened.

The phase 6 diagnostic completed on the USB-connected target on 2026-10-15.
The report was pulled as `a15-ios26-diagnostic-v6-device-20261015.json`, with
SHA-256
`B964E66048DDA2B7B2A741AABBF58A3F08C00054CA2B8A022452AFD2D07928C9`.
The real metadata selector chooses `ClearSword (default)` for the kernel,
requires no PAC bypass, and finds no selectable PPL/SPTM bypass. The first
proven blocker is therefore `selector.ppl_metadata`.

`gatherSystemInformation` remains the earliest unexecuted stage because the
three static inputs were not present in the app container and the diagnostic
does not trigger downloads or XPF. Framework loading, exploit entry points,
kernel primitives, physRW, privilege changes, bootstrap changes, and protected
requests are all recorded as false. Rebuilding response trace v2 produces the
same hashes as phases 4 and 5 because no protected boundary state changed.

## Remaining Hypotheses

- The iOS 26 AGX layout changes represented in the guarded Titan code may be
  sufficient for later stages only after the IORVBAR mapping is independently
  proven.
- The remaining target-specific AGX relationships may replace legacy Titan
  patterns that no longer match this kernel and GFX firmware.
- The two live `segment-ranges` descriptors describe physical, virtual, and
  remap ranges for two RTKit firmware segments. The uncaptured 14-byte
  `segment-names` payload is strongly inferred as `__TEXT\0__DATA\0` from the
  exact length, descriptor count, and comparative DeviceTree format, but it is
  not recorded as a live-proven value.

These hypotheses remain unproven. The exact-target active probe now tests them
under persistent stage logging; it does not broaden support to another device
or build.

## Blockers

### IOKIT_EXACT_READ_REQUIRED

The legacy `IOMemoryMap::wireRange` signature resolves an impossible `+0x260`
field offset and remains rejected. The active path instead rediscovers the
already existing eight-byte map and validates `fAddress=+0x28` plus the linked
object graph before using it. The first runtime attempt panicked earlier while
reading `IOMachPort::object`: ClearSword expanded the eight-byte request to its
minimum 32-byte kernel read and crossed the object's allocation boundary. A
tail-aligned window passed that object, then the second run proved that no
32-byte window can fit the 16-byte OSArray backing store. The third run used the
kernel's exact ICMPv6 copy length and passed every small-allocation read. It then
stopped cleanly because the active validation confused the descriptor's
`_mappings` and flags fields with its physical range. The corrected source now
uses the proven `+0x50/+0x60/+0x68` descriptor layout and exact-reads the single
range before allowing the probe to continue.

Consequences:

- Never reuse a per-boot kernel virtual address from a previous capture.
- Never create a replacement IORVBAR mapping; use only the validated existing map.
- Require the live descriptor itself to match physical range `0x206050000/0x8`.
- Reject every machine/build except iPhone14,2/23A355.
- Reject a missing GFX ROP target, wait-thread failure, or failed command
  submission before interpreting the timeout result.
- Treat the last durable checkpoint as the boundary reached, not as proof that
  the next operation completed.
- Do not continue into physrw construction, privilege changes, trust caches, or
  bootstrap installation from this probe route.

### PROC_NAME_OFFSET_DISCOVERY_REQUIRED

USB confirms that `backboardd` exists, while Titan's historical
`proc_find_by_name` cannot locate it on XNU 25. The failure occurs before the
user-client IPC entry is copied. The exact-target path must therefore derive a
candidate name offset from the current Dopamine process instead of assuming
`0x579`, then validate that the target name resolves unambiguously.

Consequences:

- Keep the historical fixed offsets only for existing non-probe targets.
- Read no more than the reported `proc` size and use the exact ClearSword read
  path in chunks of at most `0x20`.
- Cap both candidate offsets and allproc traversal, and fail closed on an
  invalid link or duplicate target process.
- Record the discovered offset, target `proc`, pid, and traversal count before
  attempting IPC-table inspection.
- Treat a successful process lookup only as permission to inspect the target's
  IPC table; it does not validate command queues, RTKit parsing, GFX ROP, or an
  SPTM/TXM path.

### IPC_TABLE_SMR_DECODE_CORRECTION_REQUIRED

The `b66873e` symmetric layout probe proves `task.itk_space=0x310`,
`ipc_space.table=0x48`, and the adjacent task backpointer at `+0x50`. It also
proves that the exact-read path omitted the `UNSIGN_PTR` normalization already
performed by the historical path before SMR allocation decoding.

Consequences:

- Normalize the encoded table word before applying `ipc_table_resolve`.
- Treat the allocation size as an upper byte bound and scan only complete
  `0x18`-byte entries; record but never read the remaining allocation tail.
- Keep the census capped at 4096 entries and all candidate/type logs capped at
  64 records.
- Keep the unconditional exact-target stop before `task_copy_ipc_entry`.

## Next Steps

1. Build and package the corrected exact-read IPC table decoder.
2. Run the bounded read-only census once and recover its `START`, `TYPE`,
   `CANDIDATE`, `SUMMARY`, and `STOP` records.
3. Compare the observed object/vtable census with the live IOMachPort wrapper
   vtable before selecting any later command-buffer experiment.
4. Keep the normal jailbreak, physrw, privilege, trust-cache, and bootstrap
   stages disabled until Titan's physical-write publication is independently
   reproduced.

## Application Policy

On iPhone14,2 with A15 and iOS 26.0.1, Dopamine presents this target as a
research target and routes it only to the bounded active Titan probe. General
support still returns false. This policy is checked by
`tools/a15_ios26/check_research_integration.py`.

## Offline GXF Producer Update

The direct GXF map route is no longer producer-unknown. For slice `a000`,
command constructor `0xffffff80000339f8` is called through serialized wrapper
`0xffffff8000035334`. Two calls originate in
`__rtk_arm_start_bootstrap_area` immediately before the firmware installs
`TTBR0_EL1`, `TCR_EL1`, and `SCTLR_EL1`; a third originates in an internal
memory-map path. Slice `b000` repeats the same structure. No exact pointer or
direct named message/endpoint ingress connects this local API to SPTM UAT
endpoint 4 or 5.

The shared handoff's 65 records are a firmware flush queue: context IDs
`0..0x40`, base `+0x20`, stride `0x18`, state `+0x0`, payload
`+0x8/+0x10`. Idle and wake independently set and clear owner byte `+0x638`.
This is lifecycle synchronization, not an SPTM policy decision.

The authenticated frame-type name table and policy callbacks remove the
remaining ambiguity around those rows. Type `0x22` is
`XNU_CPUTRACE_PA_BUFFER` and has no-op retype callbacks. Type `0x23` is
`XNU_CPUTRACE_VA_BUFFER`; its retype-in callback clears metadata `+0x4` when
the old type is `0x11`, and its retype-out callback is
`xnu_generic_retype_out`. Type `0x3b` is `TXM_SEP_SECURE_CHANNEL` and also has
no-op callbacks. Their domain permissions therefore describe CPU-trace/UAT
and SEP/SART integration, not unidentified AGX leaf types.

The remaining protected boundary is concentrated on the real mapping input.
The UAT page-table requirement remains `XNU_IOMMU (0x17)`, but the leaf
policy is now narrower than the earlier hypothesis. The direct producer at
`0xfffffff0270a1d58` is anchored as `acquire_uat_segments_page`; it validates
the page containing segment descriptors as `XNU_DEFAULT (0x0b)` and calls
`sptm_uat_map_continue` at `0xfffffff0270a1ef0`.

Inside map continuation, the leaf physical address is page-masked with
`0xfffffffff000`. A lookup derived from `map_options` selects mapping class
`1` or `2` before `iommu_register_mapping` at `0xfffffff0270a181c`. For named
UAT domain 7, `XNU_IO (0x19)` is permitted with maximum class 2, while
`XNU_PROTECTED_IO (0x1a)` has no permission in this table. The next offline
task is therefore segment provenance and exact map-option semantics, not a
binary choice between those two types.

The same analyzer now resolves the exact `21B91` predecessor rather than
reporting it absent. That image names the acquisition primitive
`iommu_frame_acquire` and uses `sptm_uat_map_continue` at
`0xfffffff00706fd5c`. Its leaf address is masked with the same
`0xfffffffff000` page mask, but `iommu_register_mapping` receives legacy mode
`0` or `1`. The registrar at `0xfffffff007088760` reads frame metadata `+0x2`
and directly accepts only `XNU_DEFAULT (0xb)` or `XNU_IO (0x19)`. There is no
authenticated per-domain/per-class descriptor table on this path. The
request function at `0xfffffff0070703b4` tail-calls map continuation and its
copy helper validates the descriptor page as `XNU_DEFAULT`, making the
producer structure comparable while keeping the policy semantics distinct.

## Public-Source Cross-Check

The public sources do not provide a shortcut around this boundary:

- arXiv 2510.09272 validates the frame-retype/rule-set model on a mostly A18
  iOS 18.4 baseline and records `XNU_DEFAULT <-> XNU_IOMMU` lifecycle
  transitions, but does not expose this proprietary UAT leaf policy.
- Tin-Z's starter pack is introductory and contains a stale claim that no
  public iOS 17 SPTM bypass exists. Its generic page types and EL2 diagram are
  not substitutes for the authenticated 23A355 frame table or GXF levels.
- The pasted `cloverfield11/ios26-hypervisor-research` note targets
  iPhone15,2/A16 on iOS 26.4.1 build 23E254. Its public repository currently
  contains a README and two commits rather than a reproducible artifact
  bundle. The Stage-2 guest path is a separate SPTM mapping interface; the
  note explicitly reports no bypass and supplies no connection to the
  A15/23A355 GPU UAT producer.

A fresh public-source check on 2026-10-16 found no released iOS 26/A15 chain,
SPTM bypass, TXM injection mechanism, or Darwin 25 replacement for Titan's
historical IPC-right transfer. The strongest new actionable route is an
official research environment rather than a consumer-device shortcut:

- Apple's Security Research Device program currently accepts applications
  through 2026-10-30. Apple documents shell access, arbitrary entitlements,
  kernel customization, and custom SPTM/TXM firmware on the specially fused
  research device. This permits controlled monitor experiments without first
  defeating the production-device protections.
- Apple's Private Cloud Compute Virtual Research Environment permits custom
  SPTM, TXM, and kernel-cache firmware. It can validate monitor request and
  policy hypotheses, but its PCC platform is not an iPhone14,2/A15 substitute
  and cannot establish portability to build 23A355.
- Neither official environment is evidence of a bypass on a standard iPhone.
  Results from either route must remain separated from the live A15 evidence.

The local `23A355` A15 extraction also contains `has-virtualization=1` in the
device tree, the SPTM guest-entry/exit strings, and named Stage-2 frame types
`0x1f/0x20`. SPTM reads the property at `0xfffffff0270c3a74` and stores the
gate at `0xfffffff027085820`. Those Stage-2 types are absent from the UAT leaf
allow set, confirming that the hypervisor note describes a parallel SPTM API,
not the missing link in the AGX/UAT chain.

Exact guest-surface anchors are `0xfffffff0270d9d68` (Stage-2 root
acquisition), `0xfffffff0270d9efc` (guest enter), `0xfffffff0270da1b8`
(guest exit), `0xfffffff0270dadfc` (guest dispatch), and
`0xfffffff0270db164` (guest VA-to-IPA). The UAT-policy rows for types
`0x1f/0x20` both have zero allowed-domain bitmap and zero maximum mapping
class. This is strong negative evidence for treating Hypervisor availability
as a UAT authorization shortcut, while leaving implementation bugs as a
separate, unproven research hypothesis.

The bounded v8 extraction also resolves the gate consumers and GENTER state
transitions. `has-virtualization` is stored as a boolean at
`0xfffffff027085820`; its three readers are `cpu_root_table_retype_in`,
`genter_dispatch_entry`, and `sptm_surt_alloc`. The low-level branch at
`0xfffffff02708caac` reaches the dispatcher. Target `0x1b` selects internal
service `0xc` for `STATE_XNU -> STATE_XNU_GUEST`, while target `0x1c` selects
service `0xd` for `STATE_XNU_GUEST -> STATE_SPTM_CALLED_BY_XNU`. Both use
handler `0xfffffff02708c23c`. These are private guest-context transitions;
they neither change the zero UAT policy rows for `0x1f/0x20` nor supply a
Stage-1 physical-write primitive.

The v9 endpoint/lifecycle pass identifies the next boundary. SPTM dispatch
table `0` begins at `0xfffffff02701c910`, is registered through
`0xfffffff0270856e8`, and is bounded to 50 entries. Its guest-facing subset is
`0x18` through `0x1c`; guest-enter itself is not exported. The `0x1a` handler
is identified conservatively as the Stage-2 TLB operation because it acquires
the typed guest root, validates a VA range, and calls `sptm_broadcast_tlbi`.

The root lifecycle is equally restrictive. `acquire_stage2_root_pt` accepts
only a `0x4000`-aligned, tracked frame of exact type `0x1f`. The ordinary
`sptm_retype` endpoint creates that type, claims a nonduplicate VMID in SPTM's
bitmap, and records the root metadata. Retype-out refuses a mapped root,
invalidates the Stage-2 TLB with `VMALLS12E1IS`, and then releases the VMID.
Stage-2 page-table type `0x20` stores a subtype below `4` and cannot be removed
while either mapping or nested references remain. This evidence changes the
research route from "call a guest service with any page" to "first satisfy a
protected frame-type and VMID state machine"; it still supplies no bypass.

Dataflow Forensics' public `SPTM - The Last Bits` post independently places UAT
at dispatch table `7` and describes the `0x70000000#` call family. Its iOS 17
round-two post also records UAT as subsystem `7` with 13 services. These are
useful corroborating labels, not evidence of a bypass.

## RTKit Metadata Path

The repeated live runs establish that command-buffer setup is blocked by the
missing safe Darwin 25 IPC-right transfer, not by the earlier IORVBAR walk.
They consistently resolve the same GFX register mapping and two complete
IOGPU user-client profiles, while stopping before `task_copy_ipc_entry`.

`rtkit-metadata-v1` therefore branches before command-buffer setup and follows
only the read dependency that is already available. It reads the reset vector
from the validated IORVBAR mapping, checks it against the physical-memory
range, obtains an existing kernel alias through `phystokv`, and reads one
bounded 16 KiB bootstrap page with the ClearSword exact-read primitive. A
unique bootstrap marker and the adjacent text/data metadata must pass size,
ordering, address, and stability checks.

This is a genuinely new accessible stage because it can identify the exact
RTKit bootstrap layout without stealing backboardd's port or creating GPU
command buffers. It remains a discovery probe: no `kmap`, firmware copy,
IPC-right transfer, IOKit call, or write is performed. A successful device run
would justify the next read-only step, correlating those metadata addresses
with the extracted RTKit image. It would not itself demonstrate injection,
protected-write access, or an SPTM/TXM bypass.

## pmap-tte-remove Cross-Check

The `Indegosblade/pmap-tte-remove` repository (main at
`78ccf6e580a92569e9d9685f9bd3f4ae7ebe5cfa`, reviewed 2026-10-16)
claims a 16-bit page-table reference-count overflow from 65,537 mappings of
one backing page. This claim is not established by its published PoC. The code
increments a local `created` counter for successful `mach_vm_map` calls and
prints `created % 65536` as the kernel refcount; it never reads the kernel's
page-table refcount. On a 16 KiB granule, one L3 table contains only 2,048
eight-byte PTE slots, so 65,537 distinct virtual mappings span multiple L3
tables. Mapping one physical backing page repeatedly does not make their
per-table counts a single counter.

The claimed write proof is also not independent. The PoC writes `0xBB` through
one retained mapping and reads the same mapping back. Its A17 log shows the
initial user sentinel `0x4141414141414141` followed by
`0x41414141414141bb` on later mappings; the latter is classified as a kernel
PTE even though it is exactly the user sentinel with its low byte changed.
This does not establish that a page-table page was freed or reclaimed.

Apple's XNU `xnu-12377.1.9` source instead obtains the page-table refcount
with `sptm_get_page_table_refcnt(tte_to_pa(*tte_p))` in
`pmap_remove_options_internal`. It checks that the count is zero before
deallocating that specific leaf table; `ptd_info->wiredcnt` is a separate
counter. These source-level facts directly challenge the repository's
refcount arithmetic. No pmap PoC was executed on the iPhone, and this branch
does not supply the missing Titan IPC transfer or a demonstrated SPTM bypass.

Sources reviewed:

- https://arxiv.org/abs/2510.09272
- https://tin-z.github.io/ios-exploit-starterpack/en/sptm-txm/
- https://github.com/cloverfield11/ios26-hypervisor-research
- https://df-f.com/blog/sptm4
- https://df-f.com/blog/ios-17round2
- https://security.apple.com/research-device
- https://security.apple.com/documentation/private-cloud-compute/virtualresearchenvironment
- https://github.com/Indegosblade/pmap-tte-remove/tree/78ccf6e580a92569e9d9685f9bd3f4ae7ebe5cfa
- https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/osfmk/arm64/sptm/pmap/pmap.c
