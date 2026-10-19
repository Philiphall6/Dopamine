# A15 / 23A355: bounded AGX packet-route identity probe

Revision: `self-page-write-v1+agx-packet-route-identity-v1+rtkit-mmio-disabled-v1`.
Target: iPhone14,2, iOS 26.0.1, build 23A355 only.

The backend-identity v2 device run observed the owned queue and buffer,
firmware object, and AGXBlockFence dispatch slots. It did not invoke a
backend method or submit a packet. The exact-image audit still finds
potentially stateful effects before the parser, so this revision does not
attempt a Sileo/bootstrap run or selector 25.

After the previous same-client, firmware, and backend gates, the new stage
reads `queue+0x670` twice. It validates the pointed AGXCommandBuffer vtable,
its `+0x18` device backreference, and its `+0x98` callback slot against the
exact 23A355 image. It also requires the previously observed concrete
firmware vtable, re-reads it, checks its `+0x210` callback slot, and rechecks
the queue and device pointers before returning. Every mismatch stops the
probe. The owned AGX connection is closed by the existing cleanup path.

The runtime identities, if observed, narrow the static packet route. They
do not establish that selector 25 selects these callbacks, that any buffer
byte is consumed, or that the backend's state changes are reversible.
No packet, backend method, GFX MMIO, physical write, or SPTM/TXM operation
is performed. The final `titan.run FAIL` remains the deliberate bounded
stop, not a claim that Sileo was attempted.

Triage a single run with
`python tools/a15_ios26/triage_agx_packet_route_identity_probe.py <after.jsonl>`.
Only `agx_packet_route_identity_observed`, a complete cleanup journal, and
no forbidden stages count as an identity observation. A reboot or partial
journal is a stop; do not automatically retry.

The packet-submission gate remains closed until the pre-parser backend and
queue effects are bounded independently. A runtime callback identity alone
does not clear that gate.
