# A15 iOS 26: self-owned GPU client hypothesis

Target: iPhone14,2, iOS 26.0.1, build 23A355. This is an offline route
assessment, not an observed new device capability.

## Why this route is different

Titan currently locates an IOGPUDeviceUserClient in backboardd and tries to
copy its IPC right. The XNU 12377 audit shows that the historical copy path
cannot be repaired by changing offsets: its notification slot, PAC context,
typed IPC state, and reference accounting no longer match. The exact-target
probe correctly stops before that operation.

The rest of `titan_setup_command_buffers` does not consume backboardd-owned
queue or shared-memory IDs. Once it has a usable connection, it creates its
own command queue, notification queue, and two shared-memory objects, then
looks up those newly created objects through the selected GPU device's
namespace. Therefore the foreign-client handoff is not inherently required
by this part of Titan's design.

## Falsifiable hypothesis

An ordinary Metal initialization in Dopamine may cause the process to own a
live connection whose kernel object has the same IOGPUDeviceUserClient vtable
as the two backboardd objects. If so, the connection's existing local Mach
name could be identified and validated without copying an IPC entry or
rewriting a port. Metal's public API provides a default GPU device on iOS,
but it does not promise this particular private user-client class or expose
Titan's selector ABI. Both points require device evidence.

## Minimal bounded diagnostic

1. Gate on the exact model and build, record a persistent run ID and checkpoint.
2. Record the current process's matching user-client count before GPU setup.
3. Create a Metal device, retain it, and record the count again. If still zero,
   create a Metal command queue without submitting a command buffer and record
   a third count.
4. For each new vtable match in the current process, correlate its kernel port
   with a name returned by the kernel's own `mach_port_names` API. Check that
   the name has a live send right. Do not derive a name from foreign table bits,
   modify an IPC entry, invoke Titan selectors, or use `task_copy_ipc_entry`.
5. Release the Metal objects only after the final checkpoint. Keep RTKit MMIO
   disabled; do not call `IOGPU_submit_command_buffers`, `gfx_write32`, or any
   physical/protected-memory operation in this diagnostic.

Success at this stage requires a stable, newly local IOGPUDeviceUserClient
match and a corresponding live local send right. A Metal device without that
class, an absent local right, or unstable attribution falsifies the hypothesis
for this bootstrap. Even success would only remove the IPC handoff blocker.
It would not establish that private IOGPU selectors accept this client, that
GPU command submission is safe, or that kernel, physical, or protected-memory
writing works.

## Implemented diagnostic

The exact-target Titan path now stops after a bounded local-port enumeration,
Metal device creation, and an optional Metal command-queue creation. It records
the count and identity of matching local send rights before and after setup in
the persistent active-probe JSONL. It does not call private IOGPU selectors,
submit GPU commands, transfer IPC rights, or read RTKit MMIO. Creating Metal
objects does have normal system side effects; "read-only" here applies only to
the IPC inspection and the absence of exploit writes.

## Current evidence and next blocker

The existing device census has two complete matching objects in backboardd,
not in Dopamine. No self-owned Metal client has been observed on the exact
target. The first concrete blocker is therefore whether ordinary GPU setup
creates the same user-client type in the app's own IPC space. Only after that
is established would a separately bounded compatibility test of the relevant
IOGPU selectors be meaningful.
