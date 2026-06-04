# VMBus Pipe Protocol

The VSMB channel uses VMBus pipe-mode (`chn_flags & VMBUS_CHANNEL_NAMED_PIPE_MODE`). This document covers the wire protocol on the VSMB channel.

## PipeHeader Framing

All messages on pipe-mode channels are wrapped in a `vmpipe_proto_header`:

```c
struct vmpipe_proto_header {
    u32 pkt_type;   // LE: 1=Data, 2=Partial, 3=SetupGpaDirect, 4=TeardownGpaDirect
    u32 data_size;  // LE: payload length in bytes
};
```

The payload follows immediately. For VSMB, the payload is a Direct TCP header + SMB2 PDU.

Defined in openvmm's `vmbus_ring/src/lib.rs`. Also used by Linux `hv_sock` (`net/vmw_vsock/hyperv_transport.c`).

## Direct TCP Framing

Inside the PipeHeader payload, SMB2 messages use Direct TCP framing (same as SMB2 over TCP port 445):

```c
struct smb2_direct_tcp_hdr {
    u8  type;       // 0x00=SMB2, 0x01=VSMB_VERSION
    u8  size_be[3]; // big-endian 24-bit payload size
};
```

## VSMB Version Negotiation

Before any SMB2 traffic, the guest and host exchange version information using Direct TCP framing with `type=1`:

```
Wire format (12 bytes):
  Direct TCP:  type=0x01, size_be=0x000008
  Payload:     version(u32 LE), capabilities(u32 LE)
```

**Request**: version=1, capabilities=1 (DirectMap)
**Response**: version=1 (accepted) or 0xFFFFFFFF (rejected), capabilities=host caps

The version exchange is always PipeHeader-wrapped (`pkt_type=1`).

## Normal Response Framing

When the host is fully initialized, responses use standard PipeHeader wrapping:

```
[PipeHeader: pkt_type=1, data_size=N] [DirectTCP: type=0, size=M] [SMB2 PDU]
              8 bytes                        4 bytes                 M bytes
```

## Receive Path

The driver treats `pkt_type=1` as the only data-bearing pipe message. Non-data pipe messages are ignored by the SMB2 receive path.

SMB2 responses are matched by the MessageId in the Direct TCP payload. The channel callback keeps a small scratch buffer for the first bytes of a response, parses the Direct TCP header and SMB2 MessageId once enough bytes arrive, then dispatches the remaining bytes into the matching in-flight request buffer.

A single VMBus ring entry may contain part of a response, one complete response, or multiple responses back-to-back. The driver reassembles the Direct TCP byte stream by tracking the current request's expected total length; when that response completes, any remaining bytes in the same ring entry are parsed as the next response.

If a response arrives for an unknown MessageId, the driver skips exactly the Direct TCP frame length for that response and resumes parsing subsequent frames.

## Boot-Time Readiness

At early boot, the host VSMB device may accept the VMBus channel and version exchange before the SMB2 layer is ready. The driver handles this by retrying SMB2 NEGOTIATE + SESSION_SETUP a few times after version negotiation. It also drains any pending ring entries after the version exchange before starting SMB2 traffic.

## VMBusPipeIO — Host-Side Transport Layer

The host uses VMBusPipeIO (in vmsmb.dll) to manage the VSMB channel. It implements a state machine and pipe connection lifecycle.

### State Machine

| State | Name | Description |
|-------|------|-------------|
| 0 | Torndown | Final cleanup |
| 1 | Disconnected | ConnectJob submitted, awaiting guest |
| 2 | Disconnecting | Disconnection in progress |
| 3 | Connected | **Active — reads ring buffer and forwards data** |
| 4-6 | Pausing* | Pause transition states |
| 7 | PausedAndDisconnected | **Initial state** |
| 8 | PausedAndConnected | Paused but connected |
| 9-10 | Terminating | Shutdown in progress |

Lifecycle:
```
7 (PausedAndDisconnected)
  → Resume
    → 1 (Disconnected) + issue ConnectJob
      → Guest opens channel (OPENCHANNEL)
        → 3 (Connected) → ReadJob starts
```

Only state 3 forwards data to the SMB2 engine. Messages received in other states are consumed by the pipe layer.

### ConnectPipe

The host waits for the guest to open the channel via an internal synchronous primitive:

```
DeviceIoControl(pipeHandle, IOCTL 0x3EC058, NULL, 0, NULL, 0)
```

This completes when the guest sends OPENCHANNEL (triggered by `vmbus_open()`). No special action is needed from the guest — a standard `vmbus_open()` suffices.

### Pipe Version Table

| Version | Header Size |
|---------|-------------|
| 1 | 0 bytes |
| 2 | 8 bytes |
| 3 | 0x10 bytes |
| 4 | 0x20 bytes |
| 5 | 0x28 bytes |

Version negotiation happens in the OfferChannel IOCTL input buffer, not on the ring buffer.

## Channel Open Sequence

### Connection Timeline

| Step | Message | Direction | Component |
|------|---------|-----------|-----------|
| 1 | OFFERCHANNEL (type 1) | Host → Guest | vmwp.exe via vmbusr.sys |
| 2 | OPENCHANNEL (type 5) | Guest → Host | Guest driver via vmbus_open() |
| 3 | OPENCHANNEL_RESULT | Host → Guest | vmbusr.sys |
| 4 | ConnectPipe completes | Host internal | vmbusr.sys pipe callback |

The guest only needs OPENCHANNEL (standard `vmbus_open()`). It does not create SynIC ports or send OFFERCHANNEL.

### Guest Channel Open (mrxsmb.sys / hv_vmsmb)

On Windows, mrxsmb.sys opens a type 7 file in the `\Device\VMBus\{IfType}-{Instance}-0000` namespace. On Linux, hv_vmsmb calls `vmbus_open()` directly. Both trigger the same OPENCHANNEL message to the host.

The `\Device\VMBus\` namespace on Windows has multiple file types:

| Path Format | Type | Purpose |
|-------------|------|---------|
| `{GUID}-{GUID}-N` | 7 | Direct channel access (mrxsmb uses this) |
| `pipe` | 5 | Pipe mode, host-side only |
| `offer` | 1 | Channel offer subscription |

When the host's vmbusr.sys receives OPENCHANNEL for a pipe-mode channel, it completes the pending ConnectPipe and transitions VMBusPipeIO to state 3 (Connected).

## Channel Lifecycle

### Close Behavior

Once `vmbus_close()` is called on the guest, the channel enters a terminal state and cannot be reopened without a VM restart. The host-side VMBusPipeIO does not handle reconnection.

This means module reload (`rmmod` + `insmod`) requires a VM restart. During development, changes are installed to `/lib/modules/` and tested on the next boot.

## References

- openvmm `vmbus_ring/src/lib.rs` — PipeHeader definition and pipe_packets handling
- openvmm `vm/devices/vmbus/vmbfs/src/protocol.rs` — VmbFs pipe framing (no VMBusPipeIO)
- Linux `net/vmw_vsock/hyperv_transport.c` — hv_sock PipeHeader usage
- MS-SMB2 §2.1 — Direct TCP transport

## Guest-to-Host Packet Size Limit

The host-side SMB2 engine (`vmusrv.dll`) validates incoming packets
against a hardcoded `Smb2MaxPacketSize = 0x11000` (69632 bytes). The
compared "received size" is the SMB2 PDU length measured from the SMB2
header (excludes PipeHeader and DirectTCP framing). Packets exceeding
this cause the host to silently not respond.

This is **not a VMBus protocol limit** — the VMBus transport layer
(`vmbkmclr.sys`) supports packets up to ~512KB.

Empirically, the maximum safe write data is `65419` bytes per SMB2 WRITE PDU:

```
0xFFFF - sizeof(smb2_direct_tcp_hdr) - sizeof(struct smb2_write_req)
= 65535 - 4 - 112
= 65419 bytes
```

The limiting value is the 16-bit VMBus pipe payload size field. The host silently drops packets at 65420 bytes and above.

## VMBus Packet Types

VMBus supports multiple packet types for different data transfer modes:

| Type | Name | Description |
|------|------|-------------|
| 6 | `VM_PKT_DATA_INBAND` | All data in ring buffer (our current mode) |
| 7 | `VM_PKT_DATA_USING_XFER_PAGES` | Ring carries descriptor; data in transfer pages |
| 8 | `VM_PKT_DATA_USING_GPADL` | Ring carries descriptor; data via GPADL |
| 9 | `VM_PKT_DATA_USING_GPA_DIRECT` | Ring carries descriptor; data at GPA ranges |

Windows' `mrxsmb.sys` uses type 9 (GPA-direct) for large SMB
sends/receives via `VmbPacketSendWithExternalMdl` /
`VmbPacketSendWithExternalPfns`. The ring buffer carries only a compact
descriptor (page range list + small inline fragment), while the bulk data
resides in locked guest pages that the host reads/writes directly.

This is why Windows can use 20KB (5-page) ring buffers while handling
68KB+ packets — the ring is a descriptor/notification channel, not a
data channel.

Our Linux driver currently uses type 6 (`VM_PKT_DATA_INBAND` via
`vmbus_sendpacket()`), which puts the entire payload in the ring and
is therefore ring-size-bound. Switching to `vmbus_sendpacket_mpb_desc()`
(Linux equivalent of GPA-direct) would decouple packet size from ring
size.
