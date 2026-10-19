# A15 / 23A355: bounded AGX firmware identity diagnostic

Revision: `self-page-write-v1+agx-firmware-read-v2+rtkit-mmio-disabled-v1`.
Target: iPhone14,2, iOS 26.0.1, build 23A355 only.

The prior run proved an own AGX buffer and queue on the same client, but
never consumed a packet. Exact-image analysis of the queue packet route
found an intermediate command-buffer callback that loads the device's
firmware object. Its statically allocated ASC vtable has a callback slot
leading to `__cxa_pure_virtual`; the runtime object and vtable were not
observed. No conclusion about a live packet follows from that static slot.

The first firmware-read build stopped at `titan.shared-alias.service`: its
hard-coded registry ID `0x100000330` no longer matched the G14P service ID
`0x1000002f2` seen both in the fresh IORegistry census and the Titan metadata
stage. ClearSword, reversible self-page write, AGX metadata, GART, and IOUAT
identity passed. No owned AGX client was opened in that run, so it gave no
firmware identity result. The copied journal is
`outputs/device/a15-firmware-read-v1-20261019/after.jsonl` (SHA-256
`3494fef533a3c7b61233b2a235080df4149cea53b29a49cb14a419444122863f`).
The ID and kernel slide changed since the prior run; a registry ID is not a
cross-boot device identity.

This revision accepts the exact G14P service class with a nonzero registry ID,
while retaining the service-object vtable, client vtable, and same-client
queue gates. It repeats the bounded prior diagnostic and, only after the
same-client queue identity gate, reads `device+0x4a0` twice and the
pointed object's vtable twice through the existing exact kernel reader.
It reports whether the unslid vtable matches the static ASC base. A
different vtable is recorded, not followed or invoked. Either result
still ends the probe before packet submission. The owned AGX connection
is closed by the existing cleanup path.

Acceptance is limited to a stable pointer/vtable and a complete cleanup
journal. A missing value, mismatch between repeated reads, reboot, or
incomplete journal is a stop, not a reason to retry automatically. This
probe does not establish parser consumption, a physical write, protected
memory access, SPTM/TXM authority, or a jailbreak. GFX MMIO and legacy
IPC-right transfer remain disabled.

## v2 device result and exact-image interpretation

Run `A47F1FC8-896E-485F-A6F2-291B8E293106` completed without a reboot.
The two post-run USB copies of
`outputs/device/a15-firmware-read-v2-20261019/after.jsonl` match exactly
(SHA-256 `6fc2f3e53706ecee7909b5be42ba21451bc3388570b5fd6f95da5083987979f6`);
the earlier 480044-byte journal is its exact prefix. The triager found 211
checkpoints, the prior alias and same-client queue gates in order, no blocked
or forbidden stage, connection close, and `probe.cleanup PASS`.

The device's `+0x4a0` pointer was stable at `0xffffffe5ed494000` and its
PAC-stripped, unslid vtable pointer was `0xfffffff007b19ab8`, not the
statically allocated ASC base vtable `0xfffffff007b18e58`. In the exact
`23A355` kernelcache (SHA-256
`8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1`),
the AGX initializer beginning at `0xfffffff00884b540` first installs the
base vtable at `0xfffffff00884b580`, then installs the observed vtable at
`0xfffffff00884bde8`-`0xfffffff00884bdfc`. The observed vtable's `+0x210`
slot contains `0x801192500183dd6c`; its image-relative target is
`0xfffffff008841d6c` (`bti c; mov x0, x1; ret`). The base slot contains
`0x8011925001630720` and resolves to `0xfffffff008634720`, the previously
identified pure-virtual stub. Forty-five of the first 67 vtable slots differ.

This resolves the static-base ambiguity for the object at the time of the
read. It does not establish that this object or slot remains unchanged when
the command-buffer callback runs, that a packet reaches that callback, or
that any parser, physical write, protected-memory access, or SPTM/TXM
authority is available. No active packet test is authorized by this result.

The JSONL can be checked with
`python tools/a15_ios26/triage_agx_firmware_probe.py <journal.jsonl>`.
`firmware_identity_observed` means the identity reads and prior owned-queue
gates were recorded in order; it does not imply a firmware call or SPTM
access. Keep the original journal and its SHA-256 when comparing runs.

## Offline follow-up: callback and pre-parser boundary

The exact-image static audit was rerun against the SHA-256-pinned kernelcache
with `audit_agx_submit_boundary.py` (without its older, queue-only journal
argument). It confirms that the queue state write precedes the process call,
and that the backend call and its success gate precede the parser call on the
checked normal-return paths. Backend failure skips the parser. The candidate
AGX backend has a reachable pool-reservation path returning without a local
rollback; its complete effects and live object identity remain unbounded.

The command-buffer callback at `0xfffffff0087fd300` loads the firmware
object from the device's `+0x4a0` field. At its virtual call site it loads
an argument from a command-buffer array, calls vtable slot `+0x210`, then
stores the returned value in callback state. The v2-observed vtable resolves
that slot to `bti c; mov x0, x1; ret`, so the static target would return the
argument unchanged. This replaces the earlier *base-vtable* pure-virtual
concern for the object measured by v2. It does not prove which argument a
live submission would pass, whether the callback is reached, or whether its
other state writes are safe. The callback's runtime command-buffer object
was not observed.

Thus the next blocker is not firmware-object identity. It is a bounded,
reproducible account of the pre-parser queue/backend effects and the live
packet route. The read-only v2 probe supplies neither. A new IPA that submits
a packet merely to test reachability would cross this unbounded boundary;
it is not justified by these results. No physical write or SPTM/TXM access
has been demonstrated.

The journal-to-image link is reproducible with
`python tools/a15_ios26/audit_agx_firmware_v2.py <kernelcache.bin> <after.jsonl>`.
It checks the exact kernelcache hash, the bounded v2 journal verdict, the
constructor's final-vtable reference, the callback's slot load/call/store,
and the observed slot target's three instructions. It deliberately does not
infer a live packet or parser result from those static checks.
