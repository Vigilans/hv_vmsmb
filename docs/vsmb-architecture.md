# VSMB Architecture

VSMB (Virtual SMB) is Hyper-V's mechanism for sharing host folders into VMs via VMBus. It is used by Windows Containers, Windows Sandbox, and NanaBox.

## Dual-Channel Design

A VM with VSMB shares configured has **two** VMBus channels:

| Channel | Instance GUID | Class GUID | Protocol | Purpose |
|---------|---------------|------------|----------|---------|
| VSMB | `dcc079ae-60ba-4d07-847c-3493609c0870` | `4d12e519-17a0-4ae4-8eaa-5270fc6abdb7` | SMB2 over VMBus | File sharing |
| VmbFs BOOT | `c63c9bdf-5fa5-4208-b03f-6b458b365592` | `c376c1c3-d276-48d2-90a9-c04748072c60` | VmbFs binary protocol | Boot-time file access |

The VSMB channel carries standard SMB2 traffic for general file sharing. The VmbFs BOOT channel uses a simpler binary protocol for early boot file access (driver store, IMC) before the SMB2 stack is ready. See [VmbFs Boot Channel](vmbfs-boot-channel.md) for details.

Both channels appear in Linux's `/sys/bus/vmbus/devices/`, but the kernel logs `Unknown GUID` since no driver claims them by default.

## Host-Side Protocol Stack

On the host, `vmwp.exe` loads `vmsmb.dll` which manages both channels:

```
┌───────────────────────────────────────────────────────┐
│                 vmwp.exe (VM Worker)                  │
├───────────────────────────────────────────────────────┤
│  vmsmb.dll — VSMB Virtual Device                      │
│                                                       │
│  ┌─────────────────────┐  ┌────────────────────────┐  │
│  │    VSMB Channel      │  │  VmbFs BOOT Channel    │  │
│  │                      │  │                        │  │
│  │  SMB2 Engine         │  │  VmbFs binary protocol │  │
│  │  (vmusrv.dll)        │  │  handler               │  │
│  │       ↕              │  │       ↕                │  │
│  │  VMBusPipeIO         │  │  Direct pipe framing   │  │
│  │  (vmbuspiper.dll)    │  │                        │  │
│  └──────────┬───────────┘  └──────────┬─────────────┘  │
├─────────────┴─────────────────────────┴────────────────┤
│  vmbusr.sys — VMBus root driver                        │
│  Channel management, ring buffers, message passing     │
├────────────────────────────────────────────────────────┤
│  Hypervisor (WinHv)                                    │
└────────────────────────────────────────────────────────┘
```

The VSMB channel uses the VMBusPipeIO transport layer, which manages a state machine and pipe connection lifecycle (see [VMBus Pipe Protocol](vmbus-pipe-protocol.md)). The VmbFs BOOT channel bypasses VMBusPipeIO and uses direct pipe framing.

Source path (from PDB): `onecore\vm\dv\storage\vsmb\vdev\vsmb.cpp`

## Guest-Side Implementations

### Windows Guest (mrxsmb.sys)

The Windows VSMB client is built into the kernel SMB redirector (`mrxsmb.sys`). It opens the VMBus channel device directly:

1. `ZwOpenFile("\Device\VMBus\{IfType}-{Instance}-0000")` with `GENERIC_READ|GENERIC_WRITE`
   - Retries up to 5 times, 10 second interval
2. VSMB version exchange via `ZwWriteFile` / `ZwReadFile`
3. Async SMB2 operations via `IofCallDriver` + `IRP_MJ_WRITE`

mrxsmb.sys does not import any VMBus library — it opens a type 7 file in the `\Device\VMBus\` namespace, which triggers the standard channel OPENCHANNEL sequence internally.

### Linux Guest (hv_vmsmb — this project)

This kernel module registers as a VMBus driver for the VSMB class GUID:

1. VMBus probe → `vmbus_open()` on the pipe-mode channel
2. VSMB version negotiation
3. SMB2 NEGOTIATE + SESSION_SETUP (anonymous)
4. Registers `vsmb` filesystem type
5. On mount: TREE_CONNECT → `fill_super` → file operations via SMB2

### Container Guest (hcsshim / gcs-sidecar)

In Windows Containers, the GCS sidecar (`hcsshim/internal/gcs-sidecar/vsmb.go`) handles VSMB:

1. Opens VMBus channel as `io.ReadWriteCloser`
2. Wraps in `vmpipe.Conn` (PipeHeader framing)
3. Uses the `go-smb2` library for SMB2 protocol
4. Mounts shares and holds keepalive handles to prevent channel teardown

## SMB2 Configuration

VSMB uses a minimal subset of SMB2:

| Parameter | Value |
|-----------|-------|
| Dialect | 0x0210 (SMB 2.1) |
| Authentication | Anonymous (no auth token) |
| Signing | Disabled |
| Encryption | None |
| MaxReadSize | 1044480 (~1 MB) |
| MaxWriteSize | 1044480 (~1 MB) |
| MaxTransactSize | 1044480 (~1 MB) |

UNC path format for TREE_CONNECT: `\\vsmb\ShareName`

## Related Resources

- [hcsshim](https://github.com/microsoft/hcsshim) — `internal/gcs-sidecar/vsmb.go`, `internal/uvm/vsmb.go`
- [openvmm](https://github.com/microsoft/openvmm) — `vm/devices/vmbus/vmbfs/` (open-source VmbFs implementation)
- [libsmb2](https://github.com/sahlberg/libsmb2) — Lightweight C SMB2 client with clean transport/protocol separation
