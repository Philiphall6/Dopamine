# A15 iOS 17.1.1 symmetric static baseline

## Scope

This baseline compares the same hardware family and the same static analysis
pipeline used for the local iOS 26.0.1 build:

- Product: `iPhone14,2` (iPhone 13 Pro)
- Device class: `d63ap`
- SoC: A15, `ApChipID 0x8110`
- Baseline firmware: iOS 17.1.1, build `21B91`
- Local comparison firmware: iOS 26.0.1, build `23A355`

The work is static only. No firmware was booted, restored, personalized, or
executed. No exploitation or SPTM/TXM bypass was attempted.

## Provenance

The exact Apple-hosted IPSW is:

`https://updates.cdn-apple.com/2023FallFCS/fullrestores/042-96762/FD5E1B54-D35B-4793-A0A0-D04583134FD1/iPhone14%2C2_17.1.1_21B91_Restore.ipsw`

An HTTP `HEAD` request to that Apple CDN object returned:

- Content length: `7,889,927,252` bytes
- Last modified: `2023-11-03 16:20:41 GMT`
- `Accept-Ranges: bytes`
- Apple/S3 SHA-1 metadata: `9582e0e4494f7d9a994b387a87e376375bc539bd`
- Apple/S3 SHA-256 metadata: `a3c2a30ca3b11f312515f77160c99767ef3d8e07e72eea8c087d53f466e32919`

The full-IPSW hashes above were read from the Apple CDN metadata and were not
recomputed locally because the complete 7.3 GiB archive was deliberately not
downloaded. `BuildManifest.plist`, also obtained directly from that archive,
confirms `ProductVersion 17.1.1`, `ProductBuildVersion 21B91`, and
`SupportedProductTypes = [iPhone14,2]`.

## BuildManifest identities

The manifest contains two `d63ap` identities. Both use `ApBoardID 0x0C`,
`ApChipID 0x8110`, and `ApSecurityDomain 0x01`:

| Identity | Variant | Restore behavior |
| --- | --- | --- |
| 0 | `Customer Erase Install (IPSW)` | `Erase` |
| 1 | `Customer Upgrade Install (IPSW)` | `Update` |

Both identities select the same archive paths:

| Logical component | BuildManifest key | Archive entry |
| --- | --- | --- |
| Kernel | `KernelCache` | `kernelcache.release.iphone14` |
| SPTM | `Ap,SecurePageTableMonitor` | `Firmware/sptm.t8110.release.im4p` |
| TXM | `Ap,TrustedExecutionMonitor` | `Firmware/txm.iphoneos.release.im4p` |

The corresponding restore keys point to the same files:
`RestoreKernelCache`, `Ap,RestoreSecurePageTableMonitor`, and
`Ap,RestoreTrustedExecutionMonitor`.

The manifest carries different signing digests for restore and normal boot.
These are Image4 personalization/signing values, not replacements for the local
SHA-256 file hashes below.

| BuildManifest key | Digest |
| --- | --- |
| `KernelCache` | `0960524C1795A8840FCDC9D05270AB6E0EA25679DF70C19095377073238744E4BF4566427CE428F639934F2ED2E27BB3` |
| `RestoreKernelCache` | `6714C36BFD65AB9CED5EB9650E38F7C84A3B87EBDC52598A0302F6737F4D39A1F8528968B32F113A59F50061C69BEF83` |
| `Ap,SecurePageTableMonitor` | `3A70826296F0E5CA2CF6028BAF8C736AC63A254024003A4DD9681EF2019B4FC552370DB655FB4C11F5F1CB0F15425716` |
| `Ap,RestoreSecurePageTableMonitor` | `999DF90B429BB26E5508E3853C322C02A1733678D924AD9EE3D3ABA1C4509BD27AA8C81ECC1E8F36B4E36C25C7026462` |
| `Ap,TrustedExecutionMonitor` | `93EABCB8AF28B477C4CCAE0CA7880BDC25EE8878BB46DB40E2BE036FB9B10EA55FA611BB7070FD2D9DEECF0381B4B4A6` |
| `Ap,RestoreTrustedExecutionMonitor` | `1E076795F222E7699D7BCF40795E552DEAAA6F0AA16C3FFDF5C142AEA9183F70D1B8724C8CFB359C9FDAD4B4CC16B4B5` |

## Targeted archive extraction

The Apple object supports HTTP range requests. The IPSW central directory was
read with `remotezip 0.12.6`, then only five entries were downloaded:

| Entry | Uncompressed bytes | ZIP bytes | CRC32 |
| --- | ---: | ---: | --- |
| `BuildManifest.plist` | 331,309 | 21,657 | `7b636224` |
| `Restore.plist` | 1,029 | 427 | `abda2af7` |
| `kernelcache.release.iphone14` | 17,060,722 | 17,050,448 | `04ea3eed` |
| `Firmware/sptm.t8110.release.im4p` | 98,342 | 97,918 | `539f696c` |
| `Firmware/txm.iphoneos.release.im4p` | 130,939 | 130,902 | `e09208cf` |

This avoids downloading the rest of the IPSW. The three IM4P payloads are
LZFSE-compressed and not encrypted; `PyIMG4 0.8.8` extracted them directly to
Mach-O files without a key.

### Reproducible Windows commands

```powershell
$workspace = (Get-Location).Path
$repo = Join-Path $workspace 'work\Dopamine-opa334'
$url = 'https://updates.cdn-apple.com/2023FallFCS/fullrestores/042-96762/FD5E1B54-D35B-4793-A0A0-D04583134FD1/iPhone14%2C2_17.1.1_21B91_Restore.ipsw'
$out = Join-Path $workspace 'outputs\iphone-system\ios17_1_1-symmetric'
$venv = Join-Path $workspace '.tools\ios17-static-baseline'
$python = Join-Path $venv 'Scripts\python.exe'
$pyimg4 = Join-Path $venv 'Scripts\pyimg4.exe'

New-Item -ItemType Directory -Force $out | Out-Null
python -m venv $venv
& $python -m pip install remotezip==0.12.6 pyimg4==0.8.8 lief==1.0.0 capstone==5.0.9
$env:SYMMETRIC_OUT = $out

@'
import os
from pathlib import Path
from remotezip import RemoteZip

url = 'https://updates.cdn-apple.com/2023FallFCS/fullrestores/042-96762/FD5E1B54-D35B-4793-A0A0-D04583134FD1/iPhone14%2C2_17.1.1_21B91_Restore.ipsw'
out = Path(os.environ['SYMMETRIC_OUT'])
entries = {
    'BuildManifest.plist': 'BuildManifest.plist',
    'Restore.plist': 'Restore.plist',
    'kernelcache.release.iphone14': 'kernelcache.release.iphone14.im4p',
    'Firmware/sptm.t8110.release.im4p': 'sptm.t8110.release.im4p',
    'Firmware/txm.iphoneos.release.im4p': 'txm.iphoneos.release.im4p',
}
with RemoteZip(url) as archive:
    for source, target in entries.items():
        (out / target).write_bytes(archive.read(source))
'@ | & $python -

& $pyimg4 im4p extract -i "$out\kernelcache.release.iphone14.im4p" -o "$out\kernelcache.release.iphone14.bin"
& $pyimg4 im4p extract -i "$out\sptm.t8110.release.im4p" -o "$out\sptm.t8110.release.bin"
& $pyimg4 im4p extract -i "$out\txm.iphoneos.release.im4p" -o "$out\txm.iphoneos.release.bin"
Get-FileHash -Algorithm SHA256 "$out\*"
```

Run the existing static analyzer unchanged:

```powershell
& $python "$repo\tools\a15_ios26\analyze_sptm_txm.py" `
  --kernel "$out\kernelcache.release.iphone14.bin" `
  --sptm "$out\sptm.t8110.release.bin" `
  --txm "$out\txm.iphoneos.release.bin" `
  --output "$out\sptm-txm-static-report.md" `
  --json-output "$out\sptm-txm-static-report.json"
```

## Local hashes

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `BuildManifest.plist` | 331,309 | `6078EB3D5EA8AFDAC62ED2501BA31760A3C36EB98D07DA7BBD44CB9290488E84` |
| `Restore.plist` | 1,029 | `A2B5FFFC3BA8E783E06F1CBF394B246AECFF68A0530320FEF39B557308C09C0D` |
| `kernelcache.release.iphone14.im4p` | 17,060,722 | `FF4086D293702DAFF45CAEC6CE1E89A19CC48BBBC5A2D3390077B44746D64BD8` |
| `kernelcache.release.iphone14.bin` | 55,541,760 | `34279BEABB02A3E7012E5430D6A3DA2775ACD5794426BB751717CC60165D453A` |
| `sptm.t8110.release.im4p` | 98,342 | `2272AC12B05913A7519EE4DE08887F623BB98E7175D0589C9367CC928075FB73` |
| `sptm.t8110.release.bin` | 721,064 | `775CECC5CBF6DCD1B4B62DEC709FD20DBE8660BCFA5AB0BC67613D9FFFDBD7AA` |
| `txm.iphoneos.release.im4p` | 130,939 | `DA662284A5D2CE301A20473CD9195437B01E2C1905A6A83962C02CDA9B8F3A77` |
| `txm.iphoneos.release.bin` | 360,608 | `D5C308F637C0FDB62C6776DCCF60C3AA9152F057ADD4D63049C01D08C953C87B` |
| `sptm-txm-static-report.json` | 35,475 | `5AF81D7B5355C356252D380D7E35AEC10DC92C1934CE1A20F6CAABEBB52398E8` |
| `sptm-txm-static-report.md` | 17,435 | `8695AA2750F348ECCF189805AF8CE22608E91534AE7D82C42258294B78143A7A` |
| `sptm-txm-static-report-v2.json` | 35,692 | `8EF8EBFF58B338F797178210FA9A0DA4E7EBA95A64598949F4F912DB199B5E34` |
| `sptm-txm-static-report-v2.md` | 17,625 | `86C04F1A9E3A3D2D50FBBFE034717D5F55F1EEFC48C93B6435ED69B0AEE82C9D` |

## Original same-analyzer baseline

The unmodified `tools/a15_ios26/analyze_sptm_txm.py` completed successfully on
the 21B91 triplet. This establishes tool-level reproducibility, but its report
title remains hard-coded to `iOS 26` and must not be read as source metadata.

| Check | 21B91 | 23A355 |
| --- | --- | --- |
| TXM XPF relationships | `INCOMPLETE` | `PASS` |
| SPTM-image XPF relationships | `PASS` | `PASS` |
| Kernel-side SPTM relationships | `INCOMPLETE` | `PASS` |

Important matches on 21B91:

- TXM `/chosen/memory-map` and license anchors resolve.
- `txm_deviceTreeTrustCacheRange` resolves.
- SPTM `papt_ranges_update` and both compressed PAPT globals resolve.
- The kernel `sptm_get_page_table_refcnt`, `libsptm_init`, PAPT globals, and
  `SPTMArgs` resolve.

The three incomplete fields have concrete explanations:

1. The generic data-reference resolver handles `ADRP` chains but not the
   direct `ADR` chains used by 21B91 TXM. Both the trust-cache root and
   developer-mode storage candidates are therefore found structurally but
   their final addresses remain unresolved.
2. The 21B91 refcount helper tests frame types through immediate bit masks
   after `ldrb [frame, #2]`. The 23A355 helper instead indexes a global
   frame-type descriptor table with 0x60-byte records and reads a policy byte
   at offset 1. Consequently, `libsptm_frame_type_params` and the descriptor
   size are legitimately absent from the current iOS 17 result.
3. The Markdown title and output schema are version-specific even though the
   underlying static routines are reusable.

These are analysis-model differences. They do not demonstrate a failed or
successful protected SPTM/TXM request, because no firmware component was run.

## Normalized analyzer v2 result

The original outputs above remain unchanged. A second pair of reports with the
`-v2` suffix records the bounded normalization implemented afterward:

- `MachOImage.resolve_data_reference` now handles direct `ADR` producers while
  retaining the bounded register-write walk.
- `frame_type_policy` is tagged as `immediate_bitmask` or `descriptor_table`.
- The report title is version-neutral.
- The original and normalized reports remain separate artifacts.

| Check | 21B91 v2 | 23A355 v2 |
| --- | --- | --- |
| TXM XPF relationships | `PASS` | `PASS` |
| SPTM-image XPF relationships | `PASS` | `PASS` |
| Kernel-side SPTM relationships | `PASS` | `PASS` |

On 21B91, the trust-cache root resolves to `0xfffffff0170104b8` and
developer-mode storage resolves to `0xfffffff017058a26`. Its frame-type policy
loads the type byte at offset `2`, bounds it to `20`, and tests masks
`0x00060100` and `0x00180200`. On 23A355, the policy remains a descriptor table
with `0x60`-byte records and a policy byte at offset `1`.

No exploit, selector fabrication, protected call, memory write, or support
metadata widening was used. `PASS` means that the requested static
relationships were resolved; it does not mean a protected request ran or that
SPTM/TXM accepted one.

## Symmetric analyzer v3 entry census

The v3 reports preserve all v2 checks and add the same instruction-level entry
census to both samples. On 21B91, TXM contains one `SVC #0`; the kernel
contains seven `GENTER` instructions with immediate counts `#0=4`, `#1=1`,
`#2=1`, and `#3=1`. On 23A355, TXM contains two `SVC #0` thunks; the kernel
contains nine `GENTER` instructions with `#0=5` and one each of `#1` through
`#4`.

The analyzer records nearby `x16` writes and bounded disassembly windows. It
does not assign endpoint names or treat the immediate as a dispatch-table
identity. No protected instruction was executed.

| v3 artifact | SHA-256 |
| --- | --- |
| `ios17_1_1-symmetric/sptm-txm-static-report-v3.json` | `87658C6F24C2F8EE19A689DB90CCF52233A646B89D69D6F6CE0FCC372D2256B4` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v3.md` | `12E0077BCA191F920EA1A9DD704F9FED876140F29BE5C379307ACE011F65452D` |
| `sptm-txm-static-report-v3.json` | `8AE272D5F03990721D29180724BB59B4264056A445EDB0BCFBE4C9DDE7DAE5DA` |
| `sptm-txm-static-report-v3.md` | `F65226F1F2F3A715F3ED74280D914F39FD564201FB9B00DE6CDC152468D90FC6` |

## Symmetric analyzer v4 TXM wrapper provenance

The v4 reports add bounded predecessor analysis for direct tail branches to
TXM `SVC #0`. Both builds resolve the same seven complete raw `x16` constants:
`0x0000000100000001`, `0x0000000100000002`,
`0x0000000100000003`, `0x0000000100000004`,
`0x000000fd00000000`, `0x000000fe00000000`, and
`0x000000ff00000000`. The first 23A355 thunk has the same seven direct
predecessors as 21B91; its second thunk has no direct branch cross-reference in
the decoded text.

The values remain uninterpreted descriptors. The analyzer does not claim that
the second thunk is unreachable, map an SPTM handler, or execute a request.

| v4 artifact | SHA-256 |
| --- | --- |
| `ios17_1_1-symmetric/sptm-txm-static-report-v4.json` | `7A27B4FA55331664129D5AFCBA49FDBE98C639D6B4E2CA48927A849F5274A2D5` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v4.md` | `023C589FA9C1F59D8B8B8B2504946E212B10C8AEDBCB66EB937A0F7462027944` |
| `sptm-txm-static-report-v4.json` | `99329CFB9419C273C6F541325CF1DEC0BE69955CE93E3232B621B3823237C770` |
| `sptm-txm-static-report-v4.md` | `D798C5EF67CC22FA19F0140F9F93A3D85DDB0E07391EC8514FDB4A66E62B3993` |

## Symmetric analyzer v5 SPTM transfer census

The v5 reports add SPTM-side `GENTER`/`GEXIT` counts and direct references to
dispatch diagnostic strings. Both builds contain one SPTM `GENTER #0`.
21B91 contains four `GEXIT #0` sites; 23A355 contains seven. The newer build
also has direct references to the additional names
`validate_sptm_dispatch_table_id` and `validate_dispatch_endpoint_id`.

These are candidates for a bounded function and caller comparison, not a
resolved bypass or runtime rejection. String absence does not prove logic
absence.

| v5 artifact | SHA-256 |
| --- | --- |
| `ios17_1_1-symmetric/sptm-txm-static-report-v5.json` | `D17DB9D0C299DECC4B465B1C063E498302983C71CA51EB2622C3F11CE415A202` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v5.md` | `382D5EF0054EBCF4015F55564B75023ADC0B57CF2BBFE7133C9575623CEDB94A` |
| `sptm-txm-static-report-v5.json` | `8BB5C33B082DB4CDAECE6F4730A92A2136B0403BF97DB17AF27F5959340ABBA1` |
| `sptm-txm-static-report-v5.md` | `B74446AD9B4C18C3EB36BC98FB5B0B5BEA0D250F729AD8716159D8ECCEEAD5A5` |

## Symmetric analyzer v6 dispatch guards

The v6 reports group dispatch diagnostic xrefs by candidate function and add
direct callers, branch ingress, and bounded control-flow guards. They confirm
that the table-ID and endpoint validators named by 23A355 have structural
counterparts in 21B91 even though the older image lacks the same strings.

Both builds bound registered table IDs to `0..15`. Endpoint policy differs:
21B91 admits an effective low-byte range of `0..31`, uses 8-byte entries, and
separately bounds the extracted table ID to `0..7`; 23A355 applies
`(x0 & 0xfe) < 0x32`, uses 16-byte entries, and rejects null tables and
entries. The state/event bounds grow from `17/12` to `23/15`.

These are contract deltas, not an identified bypass or runtime response.

| v6 artifact | SHA-256 |
| --- | --- |
| `ios17_1_1-symmetric/sptm-txm-static-report-v6.json` | `78BE444A6C684E4A8511079563EDCAC51A45179876CB9A9B1ACFF303DD49F812` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v6.md` | `728EF3C926A43704CF0C9F0110590A161EADB5348673B38B829A85846D4F60B0` |
| `sptm-txm-static-report-v6.json` | `175D130EB675592E8CC6EAD719E56A0166D32F52297232E2F0C7E03C30F4283B` |
| `sptm-txm-static-report-v6.md` | `43F5B9CB13BE7C7431B69EDF82E9603A5B5F48F0E399A8AD45F1A83ED19FF27A` |

## Symmetric analyzer v7 authenticated callbacks

The v7 reports follow each `sptm_dispatch` code-pointer materialization, nearby
PAC operation and registration call, then identify authenticated transfers in
the dispatch candidates and one-hop tail trampolines.

Both builds sign the callback with `PACIZA`, strip the code PAC with `XPACI`
before canonical storage, route the state-machine action with `BRAA`, and call
the selected endpoint handler through a tail trampoline ending in `BLRAAZ`.
The common registrations retain IDs `0`, `1`, and `2` with values `2`, `4`,
and `8`; 23A355 adds a conditional ID `0xa`/value `0x10` registration and a
wrapper path. This is expanded topology, not an authentication downgrade.

| v7 artifact | SHA-256 |
| --- | --- |
| `ios17_1_1-symmetric/sptm-txm-static-report-v7.json` | `743AE7B9CA5BE3DF03613D33D4C296C68E7BED4188DBFF9946702559907388C7` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v7.md` | `47EF90A8A4AA2B64D51613A2F4B9B2C42C68B319C179B3E68476C1435521B103` |
| `sptm-txm-static-report-v7.json` | `A45A99602CADEFE4E121E4DC14362E5EAC9B467388886A8C86BC342595FFC76E` |
| `sptm-txm-static-report-v7.md` | `A7FF36B66B90D5E5FBFFEA8E38EDC3051914DD601CEF794A1B669711BA40E910` |

## Symmetric analyzer v8 registration descriptors

The v8 reports reconstruct the immediate table ID in `w0` and associated
value in `x2` at each bounded registration call. The shared registrations are
`(0, 0x2)`, `(1, 0x4)`, and `(2, 0x8)`. 23A355 additionally registers
`(0xa, 0x10)` and has one wrapper whose arguments remain correctly recorded as
dynamic from `x1` and `x3`.

The registrar stores the callback and `x2` value in a 24-byte descriptor. The
state machine shifts the stored value by the current caller-domain index and
tests one bit before loading the callback. Therefore `x2` is a domain
permission mask, not an event ID or count. The event-entry stride remains
`0x20`; the state-row stride grows from `0x180` to `0x1e0` as the event space
grows from 12 to 15 entries. This remains a static topology result and does not
establish a live request or bypass.

On 23A355, transition metadata names bits `1..4` as `XNU`, `TXM`, `SK`, and
`XNU_HIB`. The dynamic wrapper is the IOMMU-table registration path; its
arguments remain caller-derived and its endpoint-table store is distinct from
the permission descriptor.

| v8 artifact | SHA-256 |
| --- | --- |
| `ios17_1_1-symmetric/sptm-txm-static-report-v8.json` | `7A5D7448799CE2777FBC6E6E05D9EA332AEBD5A195AF7680BF7A84C8419A719F` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v8.md` | `CFFA1DCEDD2C54EDECA2601D508C1C171A1F9E98B8C89565A64FC08652A06279` |
| `sptm-txm-static-report-v8.json` | `CB1465EFE7E855E43CACA55231A0F5F7C1A103F6EA1C6946253824704147882D` |
| `sptm-txm-static-report-v8.md` | `221C2E9D088182A5ED7EFBA23EF2FAB11F68DE7AE748B6B674BCFA0FA08297AE` |

## Symmetric analyzer v9 IOMMU topology

The v9 reports resolve the v8 dynamic wrapper to four IOMMU driver
descriptors. Both builds produce the same registrations: SART `5/0x2`, NVMe
`6/0x2`, uat `7/0x2`, and t8110dart `3/0x2` plus `4/0x8`.

The representation changes substantially. 21B91 passes descriptors directly,
with the table ID at `+0x20` and endpoint fields at `+0x28/+0x30`. 23A355 uses
a `0x20`-byte descriptor registry, an authenticated chained pointer, and a
separate wrapper; its fields move to `+0x30/+0x38/+0x40`. This is a layout and
ownership migration, not a change in the observed dispatch permission
contract.

| v9 artifact | SHA-256 |
| --- | --- |
| `ios17_1_1-symmetric/sptm-txm-static-report-v9.json` | `54D8968B498A2B4D11793D4D132315DB7910628EDE024D9F87E167D747D5D7A5` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v9.md` | `84E1B8D6E6B71AD8FB33F722703AFDEC2C3E7F9900D12D8A9CF1B725B855F6B6` |
| `sptm-txm-static-report-v9.json` | `64CD0866F24A691ACBD4ED872E38682BF41019D43433F29AB0E1E3BDF571E64C` |
| `sptm-txm-static-report-v9.md` | `B839CCB6C06CA198B7550C172CD7620D495E31D5476F1C96C716DFCCB84B0DC1` |

## Created artifacts

All extracted files and generated reports are under:

`outputs/iphone-system/ios17_1_1-symmetric`

The baseline document is:

`docs/A15_IOS17_1_1_SYMMETRIC_BASELINE.md`

## Sources

- Apple CDN IPSW object and its HTTP metadata:
  `https://updates.cdn-apple.com/2023FallFCS/fullrestores/042-96762/FD5E1B54-D35B-4793-A0A0-D04583134FD1/iPhone14%2C2_17.1.1_21B91_Restore.ipsw`
- IPSW index used only to locate the Apple-hosted object and cross-check the
  published whole-file hashes: `https://ipsw.me/download/iPhone14,2/21B91/`
- Python RemoteZip implementation: `https://github.com/gtsystem/python-remotezip`
- PyIMG4: `https://github.com/m1stadev/PyIMG4`
