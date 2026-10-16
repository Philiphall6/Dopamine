# Titan IPC Right Copy Audit: XNU 10002 to XNU 12377

This note audits Dopamine Titan's historical `task_copy_ipc_entry` path against
Apple's published XNU sources. It is an offline structural comparison only. It
does not enable IPC-right transfer, kernel writes, Mach-port fabrication, GFX
submission, or the physical-write stage.

## Compared Inputs

- Titan implementation: `Application/Dopamine/Exploits/Titan/exploit/ipc_port.c`
- iOS 17 reference: Apple XNU tag `xnu-10002.41.9`
- iOS 26 reference: Apple XNU tag `xnu-12377.1.9`
- Runtime target: iPhone14,2, build 23A355
- Runtime evidence: IPC profile v5, two complete profiles, stable table and PID

The active A15 path still returns before `task_copy_ipc_entry`. Every result in
this note was obtained from source comparison or the existing read-only census.

## Result

`task_copy_ipc_entry` is not layout-compatible with XNU 12377. The first
deterministic blocker is before any GFX command-buffer operation: the historical
no-senders handoff writes the target port into a field that is no longer
`ip_nsrequest`. Two earlier bit manipulations also changed meaning and cannot be
carried forward.

This is a contract break, not a missing constant.

## Structural Comparison

| Contract used by Titan | XNU 10002.41.9 | XNU 12377.1.9 | Audit result |
|---|---|---|---|
| `ipc_object` prefix | 8 bytes: `io_bits`, `io_references` | 16 bytes: typed/state header, references, signed label pointer | **Broken**: the waitq and every following `ipc_port` field move by 8 bytes |
| Target read at `port + 0x8` | Beginning of the old waitq/port flags | Signed IPC-object label storage | **Unsafe**: the old `0x200000` test no longer observes the intended flag |
| Target bit `0x400` in `io_bits` | `IO_BITS_KOLABEL` | Part of the new `io_state` encoding | **Broken**: clearing it would mutate object state, not remove the old label flag |
| `ip_kobject + 0x10` | `ip_nsrequest` | `ip_pdrequest` | **Broken**: `MACH_NOTIFY_NO_SENDERS` reads the new `ip_nsrequest` union at `ip_kobject`, not `ip_pdrequest` |
| Stored port pointer | Old `ip_nsrequest` was an ordinary pointer field | `ip_nsrequest` is PAC-signed with its own storage discriminator | **Broken**: a pointer recovered from `ipc_entry.ie_object` is not reusable in another authenticated field |
| Entry generation/name | Eight-bit generation | Six generation bits plus two rollover bits; `IE_BITS_GEN()` still supplies the complete high byte | **Structurally compatible** if read from a stable entry and assembled with `MACH_PORT_MAKE()` |
| Entry size | 24 bytes | 24 bytes | **Compatible**, already confirmed on-device |
| IPC table pointer | SMR/PAC encoded | SMR/PAC encoded with the live XNU 12377 format | **Legacy path insufficient**; v5's exact decoder and stable snapshots are required |

## Historical Mechanism

The function name is misleading: its input is the target `ipc_port` object,
not the address of an `ipc_entry`. The legacy finder reads `ie_object` from the
foreign task's table and returns that port pointer. The copy routine then:

1. Manipulates two old-layout bits in the target port.
2. Looks for an existing local name for the same port object.
3. Allocates a local receive right when no name exists.
4. Writes the target port into a field derived as `ip_kobject + 0x10`.
5. Uses `MACH_NOTIFY_NO_SENDERS` to ask XNU to return the previous
   `ip_nsrequest` as a send-once right.
6. Rewrites local entry rights to turn that temporary result into the desired
   local name.

Step 4 selected `ip_nsrequest` in XNU 10002 because that field followed the
`ip_kobject` union by two pointer slots. XNU 12377 reorganized these unions:
`ip_kobject` and `ip_nsrequest` now share one slot, followed by the importance
union and then `ip_pdrequest`. The same `+0x10` write therefore feeds the wrong
notification mechanism. The current no-senders implementation reads
`port->ip_nsrequest`, so it cannot return the value written to `ip_pdrequest`.

## Darwin 25 Hazards

### New IPC-object header

XNU 12377 replaces the old active/kotype word with `io_type`, `io_state`, and
`io_filtered`, and adds a signed label pointer at offset `+0x8`. The v5 target
objects reported `io-bits=0x224`, meaning type 36 and in-space state 2. The
legacy `0x400` operation is therefore semantically invalid even though this
particular value does not currently contain that bit.

The earlier read at target `+0x8` now samples the low half of signed label
storage. If its incidental value contains `0x200000`, the legacy path would
write into authenticated label data. That operation is not bounded by the
observed object type or state and must remain unreachable.

### Pointer authentication

The foreign table stores a pointer authenticated for `ipc_entry.ie_object`.
XNU 12377 authenticates `ip_nsrequest` with a different, storage-dependent
discriminator. Stripping one pointer and writing the raw address into the other
field does not preserve the authentication contract. A field offset alone
cannot repair this.

### Concurrency and table lifetime

The legacy local-table scan copies an unlocked table and does not verify that
the encoded table pointer or selected entry remained stable. The v5 census
demonstrated the minimum safer read-only contract: decode the SMR allocation,
read complete 24-byte entries, confirm each entry before and after following
its object, then verify table and PID stability. That contract is diagnostic;
it does not make a mutation safe.

### Surviving arithmetic

Port names are still assembled as `MACH_PORT_MAKE(index, IE_BITS_GEN(bits))`.
Although XNU 12377 divides the high byte into six generation and two rollover
bits, `IE_BITS_GEN()` restores the complete byte. Titan's shift expression is
mathematically equivalent for a stable entry, but it should not be treated as
validation of the rest of the routine.

## Decision

The current exact-target route must keep the unconditional stop before
`task_copy_ipc_entry`. The function itself now has a second defensive gate: it
returns before reading or mutating any port when the runtime reports iOS 26 or
XNU major 12377 and later. This does not make the historical mechanism
compatible; it prevents an accidental call if a later control-flow change
bypasses the outer exact-target stop. No active v6 should call this function.
Before any later device-side work, an offline design would need to satisfy all
of these independent contracts:

- typed `ipc_object` state and label lifetime;
- field-specific pointer authentication;
- XNU 12377 no-senders policy and `ip_nsrequest` ownership;
- SMR-safe table lifetime and stable entry generation;
- balanced port and right reference accounting;
- cleanup that remains valid on every failing branch.

The v5 profiles solve target attribution only. They do not validate a right
transfer mechanism. The next safe step is continued offline XNU control-flow
analysis or another read-only probe designed from a specific unresolved field;
it is not execution of the historical copy routine.

## Guard Build Verification

Commit `79b75bb81b4fc3e8f5a112c8d3a1b924e0cfff67` adds the defensive runtime
gate described above. GitHub Actions run `38887531277` completed successfully.
The packaged `Titan.framework/Titan` contains both the existing
`task_copy_ipc_entry not reached` marker and the new Darwin 25 refusal string.
The resulting IPA is
`Dopamine-A15-iOS26-ipc-profile-v5-guard-79b75bb.ipa`, 55,474,629 bytes,
SHA-256 `9A423151A27EBAFC2C3C4E4F0942886B95FC51928E592501F80EE01F60F8F752`.
It was installed and run on the exact target on 2026-10-16. The existing v5
read-only census completed with stable table/PID checks and stopped before
`task_copy_ipc_entry`; the new refusal was therefore not reached. This confirms
that packaging the guard did not regress the bounded probe, but it is not a
runtime exercise of the rejected copy path.

