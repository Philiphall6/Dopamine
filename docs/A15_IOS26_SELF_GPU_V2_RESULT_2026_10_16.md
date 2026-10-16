# A15 iOS 26.0.1 self-owned GPU client, v2 result

Target: iPhone14,2, iOS 26.0.1, build 23A355. USB identity was verified before
launch. The installed Dopamine SequenceNumber was 21208 (previously 21200).
The persistent run ID is `45B5A50E-D38D-4B14-BB23-A73D278DC85B` under
revision `self-gpu-client-v2+rtkit-mmio-disabled-v1`. USB House Arrest copied
`outputs/self-gpu-client-c7bca2b/device-probe-v2.jsonl`; its SHA-256 is
`2353E56A2983D614F2C46759027A5B0AF891322EBAED95B10B91E9A9257FB4F7`.
There are 37 persistent checkpoints for this run. The user supplied the
in-app console lines for the detailed IPC enumeration.

## Observation

- XPF, ClearSword kernel primitive, Titan target gate, kernel context and
  patchfinder all passed. The local IPC table passed the revised bound:
  allocation `0x98000`, 25941 complete `0x18`-byte entries and an 8-byte tail.
- Before Metal, 209 local Mach port names were listed. The census inspected
  39 send rights and found exactly one stable `IOGPUDeviceUserClient` match:
  name `0x5e43`, port `0xffffffe751668d60`, object
  `0xffffffe91692a570`, send-right type `0x10000`. No unstable entry was
  recorded, and the table remained stable.
- `MTLCreateSystemDefaultDevice` returned a device. Afterward the port-name
  count, inspected count, match count, name, port and object were unchanged.
  The Metal call therefore did not create a new matching connection in this
  observation. The v2 `queue=1` summary reused `after-device=1`; the branch
  that creates a Metal command queue was skipped. No queue was observed.
- This is a local send right of the expected user-client class. It is a
  concrete alternative to *obtaining* a right through Titan's foreign-process
  `task_copy_ipc_entry` step, but it does not yet establish that Titan's
  private selectors will accept it or that subsequent command submission
  works. No IPC copy, GFX submission, RTKit MMIO, arbitrary controlled write,
  physical write, or protected-memory modification occurred in this probe.

## Next falsifiable checkpoint

Revision `self-gpu-client-v3+rtkit-mmio-disabled-v1` requires a unique stable
local match with identical Mach name and kernel object before and after the
Metal device call. It then invokes only selector 7 (create command queue)
on that existing right, persisting the Mach return code, output size and
queue ID. A nonzero return code falsifies the immediate self-owned selector
bridge. A success demonstrates only that this selector is reachable on the
local right; it is not a controlled-write proof. The active path still stops
before command submission, IPC transfer, GFX MMIO or RTKit access.

The earlier GFX panic's MMIO read remains disabled pending provenance.
