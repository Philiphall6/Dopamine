# Calif / Hexacon iOS 27 Jailbreak Signal

This note records a same-day public signal for later comparison with the A15
iOS 26.0.1 research. It is not evidence that Calif's private chain uses Titan,
backboardd, the same IPC transfer mechanism, or the same SPTM/TXM boundary.

## Observed Claim

On 2026-10-16, a user-supplied screenshot of an X post by Billy Ellis
(`@bellis1000`) showed the text: "At #hexacon - Calif.io demos iOS 27.0.1
untethered jailbreak on iPhone 18 Pro." The attached conference image appears
to show a terminal beside a physical iPhone and a short stage video. The post
alone does not expose the reboot sequence, exploit stages, logs, or artifacts.

The Hexacon 2026 conference page independently confirms that Bruce Dang and
Thai Duong of Calif delivered the opening keynote on 2026-10-16. Its abstract
is about AI-assisted vulnerability research and does not describe the jailbreak
chain. Calif's public research index currently has no matching technical
write-up or downloadable exploit.

Huy Nguyen's public GitHub activity also shows no same-day iOS 27 release. His
most recent security repository, `p7-darksword-rce`, was pushed on 2026-10-11
and describes GhostWave/P7 DarkSword RCE support for iOS 18.4 through 26.3.
Its public tree contains browser/RCE and `sbx` stages, but no stated iOS 27
support, untether mechanism, or SPTM/TXM stage. It may be relevant to an entry
layer on iOS 26, not to the protected-memory blocker established here.

## What This Supports

- Calif demonstrated a private result on current hardware and firmware, if the
  post description and stage footage are accurate.
- The word `untethered`, if used precisely, implies persistence across a normal
  reboot without a host-assisted reactivation.
- Calif has relevant Apple-security expertise. Public profiles associate the
  company with Bruce Dang, Huy Nguyen (`Little_34306`), and `blacktop`.
- A private research demonstration is not a public jailbreak tool, a disclosed
  vulnerability chain, or evidence of portability to older devices.

## What Remains Unknown

- The initial entry point and whether the demo began from a stock boot.
- Whether persistence lives in the boot chain, a signed storage artifact, a
  restore/update path, or another mechanism.
- The kernel primitive, code-signing path, and privilege transition.
- Whether SPTM/TXM was bypassed, legitimately driven through a supported
  interface, or avoided by an earlier trust-domain compromise.
- Whether the result is specific to A20 Pro, iPhone 18 Pro, or build `24A446`.
- Whether the bugs are already reported, patched in a later beta, or intended
  for publication.
- Whether any part of the chain touches AGX, Titan, backboardd, or IPC-right
  transfer. No public evidence currently establishes such a link.

## Relevance To The A15 Route

The demonstration is strategically important because a complete chain on a
newer SPTM generation proves that modern mitigations are not an absolute end to
private jailbreak research. It does not repair Titan's Darwin 25 IPC contract.
The local XNU audit still shows that the historical no-senders handoff writes
the wrong field and cannot preserve the new authenticated `ip_nsrequest`
contract.

The current A15 plan therefore remains unchanged:

1. Keep the exact v5 device path read-only and stopped before IPC-right copy.
2. Keep the Darwin 25 guard in the legacy copy routine.
3. Continue offline XNU/SPTM/TXM analysis from verified contracts.
4. Re-evaluate only when Calif or Hexacon publishes slides, video, a write-up,
   a CVE, or a sufficiently detailed third-party reconstruction.

## Monitoring Questions

When better footage or material appears, extract only verifiable details:

- Does the video show a full power-off and stock Apple boot sequence?
- What device identifier, build number, and jailbreak-state indicator appear?
- Is a computer, cable, recovery mode, or server interaction involved?
- Do terminal messages name a kernel service, trust cache, SPTM/TXM, GPU, or
  boot component?
- Do the speakers describe the result as a one-off research chain, an AI-found
  chain, or a future public release?

## Public References Checked

- https://www.hexacon.fr/conference/speakers/
- https://calif.io/research
- https://github.com/34306
- https://github.com/34306/p7-darksword-rce
- https://ipsw.me/iPhone19%2C2/

