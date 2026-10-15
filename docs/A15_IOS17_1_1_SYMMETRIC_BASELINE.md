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

## Same-analyzer result

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

## Minimal analyzer deltas

The current analyzer can be reused unchanged for a strict first pass. For a
normalized two-version comparison, the smallest justified changes are:

- Add `ADR` support to `MachOImage.resolve_data_reference` while preserving
  the existing register-write and bounded-backtracking checks.
- Represent frame-type policy as a tagged result with at least
  `immediate_bitmask` (21B91) and `descriptor_table` (23A355), instead of
  requiring the iOS 26 global table for every version.
- Parameterize report title, product, build, input hashes, and schema version.
- Keep raw findings and normalized findings separate so an improved heuristic
  cannot silently rewrite the original same-analyzer baseline.

No exploit, selector fabrication, protected call, memory write, or support
metadata widening is needed for these improvements.

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
