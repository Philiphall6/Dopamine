# A15 / iOS 26.0.1 jailbreak-chain blockers

Exact target: iPhone14,2, build 23A355.

```text
[PASS] Exact target and kernel/SPTM/TXM artifacts
   |
[PASS] ClearSword kernel read/write primitive
   |
[PASS] Reversible kernel-alias write to one app-owned 16 KiB page
   |
[PASS] AGX G14P service, ProbeConfig, GART, AGXUATMux and IOUAT identity
   |
[PASS] Own AGX user mapping and matching kernel DRAM alias
   |
[PASS] Own same-client AGX command queue
   |
[PASS] Live firmware, AGXBlockFence backend and packet callback identities
   |
[NEXT IPA] One selector-25 all-zero record
   |          Required result: accepted call plus measured pool/backend cleanup
   |
[BLOCKED] Nonempty parser record and demonstrated owned-buffer consumption
   |
[BLOCKED] Controlled AGX/IOUAT mapping effect with independent physical readback
   |
[BLOCKED] Stable physical-write primitive
   |
[BLOCKED] Accepted SPTM/TXM operation with independent protected-state proof
   |
[BLOCKED] Jailbreak policy changes, trust cache, bootstrap and userspace setup
   |
[BLOCKED] Sileo launch and package-management validation
```

Parallel routes do not currently bridge the chain:

| Route | Current state |
|---|---|
| Hypervisor | Framework, entitlement and device-tree virtualization support absent. |
| GFX/RTKit MMIO | Disabled after unresolved SError provenance. |
| Legacy Titan IPC copy | Disabled; Darwin 25 PAC/SMR and port layout invalidate the old assumptions. |
| Selector 0 | Statically converges on the same stateful batch path; no parser-only shortcut. |
| pmap/UPPL alternatives | No independently measured protected or physical write. |

The chain currently reaches stable AGX route identity, not SPTM authority.
Even a successful zero-record observation would only clear the cleanup gate
for that empty record; it would not clear the nonempty parser, physical-write,
protected-memory, bootstrap, or Sileo gates.
