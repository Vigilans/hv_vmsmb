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

## DirectMap (Zero-Copy File Mapping)

DirectMap is VSMB's mechanism for mapping host file pages directly into
guest physical memory, bypassing the VMBus ring buffer entirely.

### Capability Negotiation

During the VSMB version exchange, the guest advertises `capabilities=1`
(bit 0 = DirectMap support). The host stores this as a per-connection
capability flag.

### Mapping Protocol

DirectMap uses a private FSCTL `0x1403cc` (not the public
`FSCTL_QUERY_DIRECT_ACCESS_EXTENTS`):

**Request** (8 bytes):
```c
struct {
    uint32_t PageProtection;       // PAGE_READONLY(0x2), PAGE_EXECUTE(0x10),
                                   // or PAGE_EXECUTE_READ(0x20)
    uint32_t AllocationAttributes; // SEC_IMAGE(0x01000000) or SEC_COMMIT(0x08000000)
};
```

**Response** (0x28 bytes):
```c
struct {
    uint64_t OriginalImageBase;
    uint32_t ExtentCount;       // always 1
    uint32_t Reserved;
    uint64_t TotalPageCount;
    uint64_t PageIndex;
    uint64_t PageCount;
};
```

### Host-Side Mechanism

`vmusrv.dll` handles `0x1403cc` as follows:
1. `NtCreateSection` creates a section-backed mapping from the file
2. Section size is rounded up to 4KB pages
3. Quota is charged against the DirectMap budget
4. `PageIndex` + `PageCount` are returned to the guest

Budget is controlled by `vmwp.exe` via the HCS configuration key
`/configuration/settings/topology/direct_file_mapping_mb` (even MB,
max 65536 MB, default from `DirectFileMappingInMB` in the VM config).

### Lifecycle

- **Create**: On section creation (e.g., loading a DLL from VSMB share)
- **Use**: Guest accesses file data directly via mapped pages
- **Teardown refused**: File close / tree close / share removal are
  blocked while DirectMap is active
- **Destroy**: Explicit teardown
- **Save/Restore**: Validates `PageCount` and `OriginalImageBase` unchanged

### Coherence

There is **no explicit invalidation mechanism**. Coherence is provided by
NT section/cache-manager semantics — section pages and file cache pages
are the same physical pages. Host file modifications are automatically
visible through the mapping.

### Windows Guest Implementation

On Windows, `mrxsmb.sys` implements the guest side of this
section-synchronization path, choosing per request between mapping the
section pages directly (`MmMapLockedPagesSpecifyCache`) and copying them
(`RtlCopyMdlToBuffer`).

Windows guests use only 20KB (5-page) ring buffers per direction —
DirectMap handles data transfer, and the ring carries only SMB2 control
PDUs.

### Host-Side GPA Mapping (vid.sys)

`vmwp.exe` installs DirectMap pages into guest physical address space via
`vid.sys`, which uses two distinct GPA mapping paths:

| Path | API | EPT Memory Type | Use |
|------|-----|-----------------|-----|
| Normal RAM / hot-add | `WinHvAddPhysicalMemory` | WB (write-back) | Guest RAM |
| DirectMap / VA-backed | `WinHvMapGpaPagesSpecial` | UC/WT (uncached) | File sections |

VA-backed (file-section) mappings are dispatched to the "Special" mapper,
while ordinary guest RAM uses the normal mapper; this is what gives
DirectMap pages their UC/WT EPT memory type.

There is **no cache-type selector** in the recovered API surface — the
EPT memory type is implicitly determined by the mapper path.

### Linux Guest Status

Implemented and reverted. The full protocol works correctly:
FSCTL `0x1403cc` → `ioremap_cache(page_index << 12)` → `memcpy_fromio`
read path → `iounmap` cleanup. Data integrity verified (md5sum match).

However, the hypervisor assigns UC/WT EPT entries to DirectMap GPA pages
(via `WinHvMapGpaPagesSpecial`), making `ioremap_cache` ineffective —
the effective memory type is UC/WT regardless of guest page table
settings (Intel SDM Vol.3C Ch.28). Measured throughput:

| Method | Read Speed |
|--------|-----------|
| DirectMap + `ioremap` (UC) | ~15 MB/s |
| DirectMap + `ioremap_cache` (WB requested, UC effective) | ~35 MB/s |
| VMBus ring buffer (baseline) | 2,000+ MB/s |

The DirectMap read fast path is reverted. The VMBus ring path remains
the primary data transfer mechanism for Linux guests.

## VMBus Transport Details

### Ring Buffer Sizing

| Implementation | Send Ring | Recv Ring |
|---------------|-----------|-----------|
| Windows guest (mrxsmb.sys) | 20KB (5 pages) | 20KB (5 pages) |
| Linux guest (hv_vmsmb) | 1MB | 1MB |

Windows' small rings work because data is transferred via GPA-direct
packet types (type 9), not in-band. Our Linux driver uses
`VM_PKT_DATA_INBAND` (type 6), requiring larger rings.

### Direct Ring Buffer Read

The channel callback bypasses the kernel's `hv_pkt_iter_first` bounce
copy, reading packet data directly from the double-mapped ring buffer.
This eliminates one full-packet `memcpy` per VMBus entry (~512K for READ
responses), improving sequential I/O by ~15-19%.

Key implementation details:
- `VMBUS_PKT_TRAILER = 8`: each ring entry has an 8-byte trailer that
  must be accounted for when advancing `priv_read_index`
- `vmsmb_ring_avail()` uses `priv_read_index` (not host-visible
  `read_index`) with `virt_load_acquire` on `write_index`, matching
  the kernel's internal `hv_pkt_iter_avail()`
- `hv_pkt_iter_close()` is called after processing to update the
  host-visible read index and handle flow control signaling

Trade-off: bypasses TOCTOU protection (the bounce copy prevents a
malicious host from mutating packet metadata after validation). For VSMB
the host is our own hypervisor, so this is acceptable.

### Readahead Configuration

BDI readahead is set to 4 MB (`sb->s_bdi->ra_pages = 1024`) at mount
time. The kernel default of 128 KB is too small — each async subrequest
is 512K, and the transport can pipeline 4-8 of them concurrently.

Impact on cold sequential reads (real model files, NVMe backend):
- `ra_pages = 128KB`: ~538 MB/s
- `ra_pages = 4MB`: ~2,500 MB/s (+365%)

### Packet Types

Windows' VMBus client library (`vmbkmclr.sys`) supports external-data
packet types where the ring carries only a descriptor:

| Type | Usage | Ring Content |
|------|-------|-------------|
| `VM_PKT_DATA_INBAND` (6) | Our current mode | Full payload |
| `VM_PKT_DATA_USING_GPA_DIRECT` (9) | Windows mode | Descriptor + small inline fragment |

See [VMBus Pipe Protocol](vmbus-pipe-protocol.md) for details.

## Known Host-Side Limitations

### SET_INFO must be terminal in a compound chain

CIFS-style `CREATE+SET_INFO+CLOSE` is not usable against `vmusrv.dll`.
When SET_INFO is followed by another PDU, the host's compound-continuation
path corrupts the chain state after the provider callback succeeds, so
the host cannot advance to the following CLOSE and no complete response
is sent.

The safe compound shape is `CREATE+SET_INFO(final)`: SET_INFO is the
last PDU in the chain, and the client follows it with a standalone
`CLOSE` on the real FID returned by CREATE.

**Affected operations**:
- `SET_INFO(FILE_END_OF_FILE_INFORMATION)` for truncate/extend
- `SET_INFO(FILE_BASIC_INFORMATION)` for timestamp updates

**Unaffected**: `CREATE+CLOSE`, `CREATE+IOCTL+CLOSE` (readlink), and
standalone SET_INFO all work correctly.

**Current implementation**: metadata SET_INFO paths use a 2-PDU
`CREATE+SET_INFO(final)` compound plus standalone CLOSE. This reduces
the previous three-round-trip CREATE → SET_INFO → CLOSE sequence to two
round-trips while avoiding the broken continuation path.

### Guest-to-host packet size limit

`vmusrv.dll` enforces `Smb2MaxPacketSize = 0x11000` (69632 bytes) on
incoming SMB2 PDUs. This is a host-side implementation limit, not a
VMBus protocol constraint. See [VMBus Pipe Protocol](vmbus-pipe-protocol.md)
for details.

### No server-side copy (copychunk)

`vmusrv.dll` does not implement the SMB2 server-side copy FSCTLs, so copy
offload (`copy_file_range(2)` / `FICLONE`) is impossible — a same-share
copy cannot be performed host-locally and always streams the data
guest→host→guest.

The host's FSCTL whitelist (`Smb2IsSupportedFsctl`) rejects all three
copy-offload control codes; an SMB2 IOCTL for any of them returns
`STATUS_NOT_SUPPORTED` (0xC00000BB) at validation, before execution:

- `FSCTL_SRV_REQUEST_RESUME_KEY` (0x00140078)
- `FSCTL_SRV_COPYCHUNK` (0x001440F2)
- `FSCTL_SRV_COPYCHUNK_WRITE` (0x001480F2)

The client therefore does not implement `.copy_file_range`; the VFS falls
back to a normal read/write copy.

## Related Resources

- [hcsshim](https://github.com/microsoft/hcsshim) — `internal/gcs-sidecar/vsmb.go`, `internal/uvm/vsmb.go`
- [openvmm](https://github.com/microsoft/openvmm) — `vm/devices/vmbus/vmbfs/` (open-source VmbFs implementation)
- [libsmb2](https://github.com/sahlberg/libsmb2) — Lightweight C SMB2 client with clean transport/protocol separation
