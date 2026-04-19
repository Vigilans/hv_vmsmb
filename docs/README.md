# hv_vmsmb Documentation

Research notes and technical documentation for the hv_vmsmb Linux kernel module — a VSMB (Virtual SMB) client over Hyper-V VMBus.

## Contents

- [Performance Evolution](performance.md) — Optimization journey from 435 MB/s to 3.8 GB/s: async I/O, ring tuning, zero-copy ring read, readahead, dead ends (DirectMap, readdirplus)
- [VSMB Architecture](vsmb-architecture.md) — Dual-channel design, host/guest protocol stacks, SMB2 configuration, DirectMap protocol, ring buffer sizing
- [VMBus Pipe Protocol](vmbus-pipe-protocol.md) — Pipe-mode channel framing, version negotiation, notification framing, VMBusPipeIO internals, channel open sequence, packet size limits, VMBus packet types
- [VmbFs Boot Channel](vmbfs-boot-channel.md) — The secondary VmbFs BOOT_INSTANCE channel: protocol, message types, relation to the VSMB channel
- [Code Attribution](ATTRIBUTION.md) — Per-function upstream source attribution and protocol discovery log
