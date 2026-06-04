# VmbFs Boot Channel

The VmbFs BOOT_INSTANCE channel is a secondary VMBus channel that provides simple binary file access, separate from the main VSMB (SMB2) channel.

## Channel Identity

| Property | Value |
|----------|-------|
| Instance GUID | `c63c9bdf-5fa5-4208-b03f-6b458b365592` |
| Interface Type | `c376c1c3-d276-48d2-90a9-c04748072c60` |
| Protocol | VmbFs binary protocol (NOT SMB2) |

There is also a VmbFs IMC_INSTANCE (`c4e5e7d1-d748-4afc-979d-683167910a55`) for Integration Management Configuration, but it is not present on NanaBox Linux VMs.

GUIDs sourced from openvmm `vm/devices/vmbus/vmbfs/src/protocol.rs`.

## Protocol

The VmbFs protocol is a simple request/response binary format, wrapped in PipeHeader framing (no VMBusPipeIO layer on the host side — direct pipe framing).

### Message Types

| Type | Direction | Name | Minimum Size | Response Type |
|------|-----------|------|-------------|---------------|
| 1 | Guest → Host | Version Request | 12 | 2 |
| 2 | Host → Guest | Version Response | 12 | — |
| 3 | Guest → Host | File Open Request | 8+ | 4 |
| 4 | Host → Guest | File Open Response | 24 | — |
| 5 | Guest → Host | File Read Request | 20+ | 6 |
| 6 | Host → Guest | File Read Response | 12 | — |
| 7 | Guest → Host | File Read RDMA | 32+ | 8 |
| 8 | Host → Guest | File Read RDMA Response | 16 | — |

### Version Exchange

**Version Request** (12 bytes):
```
type(u32 LE) = 1
reserved(u32 LE) = 0
version(u32 LE) = 0x00010000  (version 1.0)
```

**Version Response** (12 bytes):
```
type(u32 LE) = 2
reserved(u32 LE) = 0
status(u32 LE) = 0 (accepted) or 1 (rejected)
```

### File Operations

**GetFileInfo** — Open a path and get metadata:
```
Type 3 request: path as wide string (UTF-16LE)
Type 4 response: flags (0x1 = directory), file size, etc.
```

Example results:
- `GetFileInfo("\\")` → SUCCESS, flags=0x1 (directory)
- `GetFileInfo("\\IMC")` → NOT_FOUND (Linux VM has no IMC config)

## Comparison with VSMB Channel

| Aspect | VmbFs BOOT | VSMB |
|--------|-----------|------|
| Protocol | Custom binary (8 message types) | SMB2 (full command set) |
| Host transport | Direct pipe framing | VMBusPipeIO layer |
| Framing | PipeHeader only | PipeHeader + Direct TCP |
| Complexity | Simple request/response | Full SMB2 state machine |
| Purpose | Boot-time driver store / IMC access | General file sharing |

## openvmm Reference

openvmm's open-source VmbFs implementation uses direct pipe framing without VMBusPipeIO:

```rust
ChannelType::Device { pipe_packets: true }
MessagePipe::new(channel)  // PipeHeader framing
```

Source: `vm/devices/vmbus/vmbfs/src/protocol.rs`
