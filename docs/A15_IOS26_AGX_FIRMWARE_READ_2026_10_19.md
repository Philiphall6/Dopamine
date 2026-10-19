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
IPC-right transfer remain disabled. No on-device result exists yet for v2.

The JSONL can be checked with
`python tools/a15_ios26/triage_agx_firmware_probe.py <journal.jsonl>`.
`firmware_identity_observed` means the identity reads and prior owned-queue
gates were recorded in order; it does not imply a firmware call or SPTM
access. Keep the original journal and its SHA-256 when comparing runs.
