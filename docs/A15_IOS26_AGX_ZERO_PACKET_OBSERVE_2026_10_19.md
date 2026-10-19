# A15 / 23A355: bounded AGX zero-packet observation

Revision: `self-page-write-v1+agx-zero-packet-observe-v1+rtkit-mmio-disabled-v1`.
Target: iPhone14,2, iOS 26.0.1, build 23A355 only.

The preceding device run validated the owned AGX queue, buffer, firmware
object, AGXBlockFence factory/allocator/prepare slots, command-buffer object,
and effective firmware callback. It made no selector-25 call. The final
`titan.run FAIL` in that run was the deliberate bounded return.

The exact retained kernelcache has SHA-256
`8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1`.
`audit_agx_submit_boundary.py` now pins the local release sites, virtual free
dispatch, AGXBlockFence pool restoration stores, the queue empty-record path,
and the queue `+0xa8` finalizer at `0xfffffff009f49d44`. The static audit
shows that an all-zero record skips command dispatch. It does not prove final
deallocation timing or complete runtime effects.

This revision therefore performs one observation only:

1. Require the same owned queue, firmware, command buffer, and registered
   16 KiB user mapping.
2. Require every byte of the user mapping to be zero.
3. Capture the firmware pool window at `firmware+0xbf0` twice and require
   identical 0x208-byte snapshots.
4. Require `queue+0x520` to contain no live backend object.
5. Call exact-image selector 25 once with four scalars
   `[queue_id, 0, 1, 56]` and a 56-byte zero structure whose first two
   32-bit fields contain the same owned buffer ID.
6. Capture the firmware pool and selected queue/command state twice after
   return. Require a restored pool, a null backend pointer, stable post-state,
   unchanged object identities, and a still-zero user buffer.
7. Close the owned AGX connection. There is no retry path.

Any failed precondition stops before selector 25. Any failed postcondition
records `BLOCKED`, closes the connection, and must not be retried
automatically. GFX/RTKit MMIO, nonempty packet records, direct kernel writes,
physical writes, protected-memory operations, privilege changes, bootstrap,
and Sileo remain disabled.

Triage one run with:

```powershell
py tools/a15_ios26/triage_agx_zero_packet_probe.py path\to\a15-ios26-active-probe.jsonl
```

Only `agx_zero_packet_cleanup_observed` means that the one empty-record call
returned and all measured cleanup invariants held. It is not a physical-write
primitive, SPTM/TXM bypass, jailbreak, or Sileo test.

## First device result

The `agx-zero-packet-observe-v1` run returned `0xe00002c2` without changing the
queue, firmware pool, registered buffer, or user mapping. Exact-image
disassembly identifies the pre-parser mismatch:

- the device constructor stores `0x30` at `device+0x268`;
- selector 25 compares that field with scalar input 3;
- v1 supplied `0x38`, so the method returned `kIOReturnBadArgument` before the
  batch routine at `0xfffffff009f49254`;
- no backend was allocated and no record was consumed.

The follow-up revision `self-page-write-v1+agx-zero-packet-abi-v2+rtkit-mmio-disabled-v1`
reads `device+0x268` twice, requires the stable exact value `0x30`, and supplies
one 0x30-byte record. It preserves the one-call limit and all v1 preflight,
postflight, cleanup, no-MMIO, and no-protected-write gates.
