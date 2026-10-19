# A15 / 23A355: bounded AGX backend identity IPA

Revision: `self-page-write-v1+agx-backend-identity-v2+rtkit-mmio-disabled-v1`.
Target: iPhone14,2, iOS 26.0.1, build 23A355 only.

The firmware-read v2 journal established one owned AGX client, buffer, queue,
and stable firmware object. It did not submit a packet. Exact-image control-flow
analysis found that a selector-25 submission would modify queue state and
enter a potentially stateful backend before reaching the parser. This IPA
does **not** take that path.

After the existing same-client and firmware gates, the new stage reads the
live `AGXBlockFence` metaclass global twice and validates its dispatch-table
address directly. It then reads the device factory, metaclass allocation,
and instance preparation vtable slots twice each. It PAC-strips the code
pointers and compares their unslid targets with the exact 23A355 kernelcache.
Any missing, unstable, or unexpected value stops the probe. The owned AGX
connection is closed by the existing cleanup path.

These observations can confirm that the candidate backend class and its
three static dispatch targets are present in live memory. They cannot prove
that a submitted packet selects this class, that an instance is allocated,
or that backend effects are reversible. No backend method is called; selector
25, GPU packet submission, GFX MMIO, physical writes, legacy IPC-right
transfer, and SPTM/TXM operations remain disabled.

The journal can be assessed with
`python tools/a15_ios26/triage_agx_backend_identity_probe.py <after.jsonl>`.
`agx_backend_identity_observed` denotes only the ordered identity reads and
cleanup. A reboot, incomplete journal, or unexpected active stage is a stop,
not a reason for an automatic second attempt.

The v1 run on this device stopped at the metaclass check. The global held
`0xfffffff007b16de0` after removing the slide, exactly the expected dispatch
table address. V1 incorrectly dereferenced it and interpreted its first code
entry (`0xfffffff0087f637c` unslid) as another vtable pointer. V2 removes that
extra dereference; it does not relax any code-slot target comparison.

## v2 device result

Run `EF41B53F-9C86-4E76-AD05-05D27353A825` is preserved in
`outputs/device/a15-agx-backend-identity-v2-20261019/after.jsonl`
(SHA-256 `7522e14ffcf9cd7f887f018ab79960cbd3ac4da2d3555a2181fe264c0ed2f89d`).
The triager found 228 checkpoints in the selected run, all required
same-client, firmware, and backend identity gates in order, no first blocked
checkpoint, no forbidden stage, connection close, and `probe.cleanup PASS`.
Its verdict is `agx_backend_identity_observed`. The final `titan.run FAIL`
is the deliberate bounded stop after these reads, not a backend failure.

The live metaclass global held `0xfffffff007b16de0` after removing the
slide. The factory, allocation, and preparation slots resolved to
`0xfffffff0087e4280`, `0xfffffff0087f630c`, and `0xfffffff0087f5ca8`
respectively, matching the pinned image. The firmware object's observed
vtable remained `0xfffffff007b19ab8`, not the ASC base vtable; this is an
informational identity result, not a failed gate.

**Decision: no packet-submission IPA on this evidence.** The live reads
validate the candidate dispatch tables but do not show a factory call,
returned backend object, reversible preparation effects, packet consumption,
physical write, or SPTM/TXM access. The exact-image pre-parser analysis in
`A15_IOS26_BLOCKERS_AFTER_QUEUE_2026_10_19.md` still identifies stateful
effects and unresolved downstream callbacks. Further work belongs in the
offline effect audit before another device experiment is considered.
