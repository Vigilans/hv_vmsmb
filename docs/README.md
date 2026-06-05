# hv_vmsmb Documentation

Research notes and technical documentation for the hv_vmsmb Linux kernel module — a VSMB (Virtual SMB) client over Hyper-V VMBus.

## Contents

- [Performance Evolution](performance.md) — Benchmarks and optimization history for bulk I/O, metadata-heavy workloads, compound operations, and discarded approaches
- [VSMB Architecture](vsmb-architecture.md) — Dual-channel design, host/guest protocol stacks, SMB2 configuration, DirectMap protocol, ring buffer sizing
- [VMBus Pipe Protocol](vmbus-pipe-protocol.md) — Pipe-mode channel framing, version negotiation, receive path, VMBusPipeIO internals, channel open sequence, packet size limits, VMBus packet types
- [VmbFs Boot Channel](vmbfs-boot-channel.md) — The secondary VmbFs BOOT_INSTANCE channel: protocol, message types, relation to the VSMB channel
- [Code Attribution](ATTRIBUTION.md) — Per-function upstream source attribution and protocol discovery log
