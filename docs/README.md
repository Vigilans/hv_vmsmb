# hv_vmsmb Documentation

Research notes and technical documentation for the hv_vmsmb Linux kernel module — a VSMB (Virtual SMB) client over Hyper-V VMBus.

## Contents

- [VSMB Architecture](vsmb-architecture.md) — Dual-channel design, host/guest protocol stacks, SMB2 configuration
- [VMBus Pipe Protocol](vmbus-pipe-protocol.md) — Pipe-mode channel framing, version negotiation, notification framing, VMBusPipeIO internals, channel open sequence
- [VmbFs Boot Channel](vmbfs-boot-channel.md) — The secondary VmbFs BOOT_INSTANCE channel: protocol, message types, relation to the VSMB channel
