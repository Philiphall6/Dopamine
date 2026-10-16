# A15 iOS 26.0.1 self-owned GPU client, v3 result

Target: iPhone14,2, iOS 26.0.1, build 23A355. USB identity was confirmed
before launch. The installed Dopamine SequenceNumber was 21216 (previously
21208). The persistent run ID is `5832E726-1252-422A-85E9-463DD90031A0`
under revision `self-gpu-client-v3+rtkit-mmio-disabled-v1`. USB House Arrest
copied `outputs/self-gpu-client-0b78da0/device-probe-v3.jsonl`, SHA-256
`CF28A7A4A75AA4EECA54EDF0FA5CCF88E6E03720E5689E1309B1ED6936197CC6`.
The user supplied the in-app console lines for the detailed IPC enumeration.

XPF, ClearSword kernel primitive, Titan target gate, context and patchfinder
passed. Dopamine's local IPC table was stable at `0x98000` bytes, with 25941
complete `0x18`-byte entries. The baseline census listed 201 Mach names and
inspected 47 send rights but found **zero** matching GPU user clients. Metal
device creation succeeded; the second census remained at 201 names, 47
inspected and zero matches. No unstable entry was recorded.

Consequently, the unique-right gate blocked selector 7 before invocation.
There was no IPC copy, Metal queue creation, GFX submission, RTKit MMIO or
controlled-write test. No arbitrary kernel write, physical write or protected
memory modification is evidenced. The one local match in v2 was a real stable
right in that run but is not a guaranteed process-start condition.

Revision `self-gpu-client-v4+rtkit-mmio-disabled-v1` tests the next minimal
bootstrap: when both initial censuses find zero matches, create one Metal
command queue without a command buffer or submission, then repeat the stable
local-right census. Only a unique valid match can reach Titan's single queue
creation selector. If no match appears, this particular self-owned bridge is
blocked without invoking that selector. The earlier GFX MMIO read remains
disabled pending panic provenance.
