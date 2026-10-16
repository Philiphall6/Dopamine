# A15 iOS 26.0.1 self-owned GPU client test, 2026-10-16

Target: iPhone14,2, iOS 26.0.1, build 23A355. USB identity was confirmed
through usbmux before the user launched Dopamine. The installed app's
SequenceNumber changed from 21184 to 21200. The run tagged
`self-gpu-client-v1+rtkit-mmio-disabled-v1` has ID
`26BE4B78-1AB1-43CF-B8BF-857159C02766`; the user supplied the in-app
console output and the persistent JSONL was retrieved over USB.

## Observed result

- XPF gather, ClearSword, kernel primitive, Titan load, target gate, kernel
  context, and Titan kernel patchfinder passed.
- `titan.self-gpu` stopped in the `before-metal` phase with
  `reason=table-contract size=0x98000 entry=0x18`.
- `0x98000 / 0x18` yields 25941 complete entries and an 8-byte tail. The
  diagnostic reused the 4096-entry cap intended for the bounded backboardd
  census, so it rejected Dopamine's larger IPC table before inspecting any
  local GPU port.
- The run reached neither Metal device creation nor command queue creation.
  The self-GPU phase did not copy IPC rights, submit GPU work, access RTKit
  MMIO, or perform a new controlled-write test. ClearSword did log its pointer
  corruption while acquiring KRW, but this output alone does not verify an
  arbitrary kernel write. No physical write or protected-memory modification
  is evidenced.
- Dopamine remained running after the stop. The classic USB syslog relay did
  not expose the `A15ACTIVE` console lines. House Arrest in Documents-only
  mode returned `InstallationLookupFailed`, but full-container mode retrieved
  `Documents/a15-ios26-active-probe.jsonl` over USB. The copy is at
  `outputs/self-gpu-client-0fc8dec/device-probe-v1.jsonl`; it contains 36
  checkpoints for this run. The detailed `table-contract` line is in the
  user-supplied console output, while the JSONL independently records the
  baseline enumeration failure and subsequent stop and cleanup.

## Correction and falsifiable next test

Revision `self-gpu-client-v2+rtkit-mmio-disabled-v1` uses a separate 32768-entry
limit for Dopamine's own IPC table and port-name list. The 4096-entry foreign
process census limit remains unchanged. The local probe now logs its table
size, complete entry count, tail, and port-name count before validating the
bound.

On the same model and build, a passing table check must log `titan.self-gpu
TABLE` with the measured counts, then reach `titan.self-gpu.device` or a
specific Metal failure checkpoint. A `MATCH` requires a stable Mach send
right, in-space IOKit connection, and the expected GPU user-client vtable.
No `MATCH` or write should be inferred from Metal device creation alone.

The GFX MMIO read associated with the earlier panic remains disabled while
its provenance is unresolved.
