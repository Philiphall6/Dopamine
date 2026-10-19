# A15 / 23A355: bounded AGX backend identity IPA

Revision: `self-page-write-v1+agx-backend-identity-v1+rtkit-mmio-disabled-v1`.
Target: iPhone14,2, iOS 26.0.1, build 23A355 only.

The firmware-read v2 journal established one owned AGX client, buffer, queue,
and stable firmware object. It did not submit a packet. Exact-image control-flow
analysis found that a selector-25 submission would modify queue state and
enter a potentially stateful backend before reaching the parser. This IPA
does **not** take that path.

After the existing same-client and firmware gates, the new stage reads the
live `AGXBlockFence` metaclass global twice and validates its vtable. It then
reads the device factory, metaclass allocation, and instance preparation
vtable slots twice each, PAC-strips the code pointers, and compares their
unslid targets with the exact 23A355 kernelcache. Any missing, unstable, or
unexpected value stops the probe. The owned AGX connection is closed by the
existing cleanup path.

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
