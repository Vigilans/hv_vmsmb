# Performance Evolution

This document traces the optimization journey of hv_vmsmb from initial
working prototype to its current performance level. Each stage describes
the bottleneck identified, the change made, and the measured impact.

All benchmarks use [fio-cdm](https://github.com/chocolateboy/fio-cdm)
with a 1 GB test file unless noted otherwise. The host has 128 GB RAM
and an NVMe SSD (~2 GB/s sustained, ~4.7 GB/s burst); the guest has
16 GB RAM. All fio-cdm reads hit the host page cache (1 GB << 128 GB
host RAM) and measure VMBus throughput, not disk speed. Real-world cold
read benchmarks against large LLM model weights are in the final section.

## Summary

| Metric | Stage 1 | Stage 6 | Speedup |
|--------|---------|---------|---------|
| SEQ1M Q8T1 Read | 932 MB/s | 7,856 MB/s | **8.4x** |
| SEQ1M Q8T1 Write | 404 MB/s | 3,853 MB/s | **9.5x** |
| SEQ1M Q1T1 Read | 895 MB/s | 2,481 MB/s | **2.8x** |
| SEQ1M Q1T1 Write | 407 MB/s | 1,697 MB/s | **4.2x** |
| RND4K Q32T16 Read | 28 MB/s | 456 MB/s | **16x** |
| RND4K Q32T16 Write | 28 MB/s | 578 MB/s | **21x** |
| RND4K Q1T1 Read | 23 MB/s | ~27 MB/s | (latency-bound) |
| Cold SEQ Read (dd) | ~600 MB/s | 1.5-2.5 GB/s | **3-4x** |
| Hot SEQ Read (dd) | ~600 MB/s | 2.9-3.8 GB/s | **5-6x** |

fio-cdm rows use 1 GB test file with host page cache warm (synthetic
throughput ceiling). Cold/hot read rows use real model files (4.7-47 GB)
with `dd`: "cold" = both host and guest caches empty after VM restart;
"hot" = host page cache warm.

## Stage 1: Synchronous Baseline

First successful fio-cdm run. All I/O serialized through a
single `transport_mutex` — one request in flight at a time regardless
of thread count.

| Workload | Read | Write |
|----------|------|-------|
| SEQ1M Q8T1 | 932 MB/s | 404 MB/s |
| SEQ1M Q1T1 | 895 MB/s | 407 MB/s |
| RND4K Q32T16 | 28 MB/s (6,820 IOPS) | 28 MB/s (6,911 IOPS) |
| RND4K Q1T1 | 23 MB/s (5,719 IOPS) | 24 MB/s (5,800 IOPS) |

Q8 ≈ Q1 for sequential, Q32T16 ≈ Q1T1 for random — all serialized.

## Stage 2: Async I/O

The async transformation happened in two layers:
1. **Async transport** — per-request `vmsmb_request` structs with
   individual `completion`, MessageId matching in the channel callback,
   `send_mutex` replacing `transport_mutex` (only serializes sends,
   not waits). This allowed multiple requests in flight.
2. **Async netfs callbacks** — `issue_read`/`issue_write` submit and
   return immediately; completions call
   `netfs_read_subreq_terminated`/`netfs_write_subrequest_terminated`
   from a workqueue.

Also added a `prepare_write` hook (ported from CIFS `cifs_prepare_write`)
that sets `stream->sreq_max_len = VMSMB_MAX_WRITE_CHUNK` — without it,
netfs tries 1 MB subrequests with a 64K buffer, triggering
`usercopy_abort`.

The async transport introduced a regression on synchronous-path
sequential reads (932 → 812 MB/s) due to `wait_for_completion`
sleep/wake overhead on sub-10us round-trips. `VMSMB_SPIN_USEC`
adaptive spinning (10 us `completion_done()` busy-poll before sleeping)
recovered this to 900 MB/s.

**Results**:

| Workload | Stage 1 | Async Transport | + Async Netfs |
|----------|---------|-----------------|---------------|
| SEQ1M Q8T1 Read | 932 | — | 3,893 MB/s |
| SEQ1M Q8T1 Write | 404 | — | 1,211 MB/s |
| SEQ1M Q1T1 Read | 895 | — | 1,850 MB/s |
| SEQ1M Q1T1 Write | 407 | — | 963 MB/s |
| RND4K Q32T16 Read | 28 | 228 | 464 MB/s |
| RND4K Q32T16 Write | 28 | 230 | 581 MB/s |
| RND4K Q1T1 | ~23 | ~25 | ~25 MB/s |

## Stage 3: Write Chunk Size Discovery

How large can a single SMB2 WRITE PDU be?

Reverse engineering of `vmusrv.dll` revealed
`Smb2MaxPacketSize = 0x11000` (69632 bytes), but the actual limit is
lower. The VMBus pipe payload is encoded in 16 bits, capping at
0xFFFF bytes. The effective formula:

```
max_write_data = 0xFFFF - sizeof(smb2_direct_tcp_hdr) - sizeof(smb2_write_req)
               = 65535 - 4 - 112
               = 65419 bytes
```

65419 bytes works; 65420 fails silently (host drops the packet).

**Note**: This 64K limit is *not* a VMBus protocol constraint —
`vmbkmclr.sys` supports ~512K single packets. It's a limit of the
VMBus pipe framing layer that wraps SMB2 PDUs. READ responses
(host-to-guest) are not subject to this limit; our read chunk is 512K.

**Results**: Write chunk was already near-optimal before this analysis; the
main gain was understanding the exact limit.

## Stage 4: Ring Buffer and Read Chunk Tuning

With async I/O, multiple requests can be in flight — but
the 256K ring buffer fills after ~2 responses. READ responses are ~192K
each (the read chunk), so only one fits in the ring at a time. The
pipeline depth is limited by ring capacity.

**Changes**:
- `VMSMB_RING_SIZE`: 256K → **1 MB** per direction
- `VMSMB_MAX_READ_CHUNK`: 192K → **512K**
- `VMSMB_MAX_WRITE_CHUNK`: unchanged at 65419 (hardware limit)

**Why these values**: Windows guest (`mrxsmb.sys`) uses only 20K (5-page)
rings because it transfers data via GPA-direct packet types, using the
ring only for control PDUs. Our INBAND mode puts full payloads in the
ring, so we need ~50x more ring space. 1 MB allows ~2 concurrent 512K
READ responses to be queued, which is the sweet spot — larger rings
have diminishing returns and cost kernel memory.

**Results**:

| Workload | Stage 2 | Stage 4 | Change |
|----------|-------------|-------------------|--------|
| SEQ1M Q8T1 Read | 3,893 | 6,728 | **+73%** |
| SEQ1M Q8T1 Write | 1,211 | 3,288 | **+172%** |
| SEQ1M Q1T1 Read | 1,850 | 2,096 | +13% |
| SEQ1M Q1T1 Write | 963 | 1,514 | +57% |
| RND4K Q32T16 | 464/581 | 464/582 | flat |
| RND4K Q1T1 | ~25 | ~25 | flat |

## Stage 5: Direct Ring Buffer Read

The kernel's `hv_pkt_iter_first()` allocates a temporary
buffer and copies each packet's payload out of the ring buffer before
returning it to the caller. For a 512K READ response, this is a
full 512K memcpy per packet — pure overhead.

**Change**: Bypass `hv_pkt_iter_first` and read packet data directly
from the double-mapped ring buffer. The VMBus ring is mapped twice in
virtual memory (ring page N and ring page N+wraparound point to the
same physical page), so any contiguous read starting within the ring
always sees a contiguous virtual buffer, even across the wrap boundary.

Implementation details:
- `vmsmb_ring_avail()` reimplements the kernel-internal
  `hv_pkt_iter_avail()`, using `priv_read_index` with
  `virt_load_acquire` on `write_index`
- `VMBUS_PKT_TRAILER = 8` bytes after each ring entry must be
  accounted for when advancing the read index
- `hv_pkt_iter_close()` is called after processing to update the
  host-visible read index and handle flow control

**Trade-off**: This bypasses TOCTOU protection — the bounce copy
prevents a malicious host from mutating packet metadata after
validation. For VSMB the host is our own hypervisor, so this is
acceptable.

**Results**:

| Workload | Stage 4 | Stage 5 | Change |
|----------|---------|----------|--------|
| SEQ1M Q8T1 Read | 6,728 | 7,856 | **+17%** |
| SEQ1M Q8T1 Write | 3,288 | 3,853 | **+17%** |
| SEQ1M Q1T1 Read | 2,096 | 2,481 | +18% |
| SEQ1M Q1T1 Write | 1,514 | 1,697 | +12% |
| RND4K Q32T16 | 464/582 | 456/578 | flat |

## Stage 6: Readahead Tuning

The kernel default BDI readahead window is 128 KB. With
512K read chunks, the transport can pipeline 4-8 subrequests
concurrently, but only if the readahead window is large enough to
generate them.

**Change**: Set `sb->s_bdi->ra_pages = 1024` (4 MB) at mount time.

**Results** (sequential cold read, real model files, NVMe backend):

| Readahead | Cold Read Speed |
|-----------|----------------|
| 128 KB (default) | 538 MB/s |
| 4 MB | **2,500 MB/s (+365%)** |

The fio-cdm benchmarks above all use host-cached data and don't
show this effect.

**VM cold reads sometimes exceed host NVMe speed**: The host baseline
is a single `dd` (effectively QD=1). With a 4 MB readahead window,
the guest issues multiple concurrent 512K async subrequests, which
may result in higher effective NVMe queue depth on the host side —
though we haven't directly measured host-side QD to confirm this
explanation. Measured:

| Scenario | Speed |
|----------|-------|
| Host NVMe raw (dd, QD=1) | 1.2-2.2 GB/s |
| VM cold read (ra=4MB) | 1.5-2.5 GB/s |
| VM hot read (host cached) | 2.9-3.8 GB/s |

## Dead Ends

### DirectMap (FSCTL 0x1403cc)

DirectMap maps host file pages directly into guest physical address
space via the Hyper-V hypervisor. The full protocol was implemented
and verified (data integrity confirmed), but performance was 50x
worse than VMBus:

| Method | Read Speed |
|--------|-----------|
| DirectMap + `ioremap_cache` | ~35 MB/s |
| VMBus ring buffer | 2,000+ MB/s |

**Root cause**: Reverse engineering of `vid.sys` confirmed that
DirectMap GPA pages are mapped via `WinHvMapGpaPagesSpecial`, which
uses UC/WT EPT entries. Normal guest RAM uses `WinHvAddPhysicalMemory`
with WB EPT. There is no cache-type selector in the recovered API —
the EPT memory type is determined by the mapper path, not by guest
requests.

Intel SDM Vol.3C Ch.28: effective memory type = min(EPT type, guest PAT
type). When EPT=UC, the guest cannot override to WB regardless of
`ioremap_cache` or `set_memory_wb`.

Windows guests presumably achieve fast DirectMap through
`MmMapLockedPagesSpecifyCache` in the Windows memory manager, which
may obtain WB EPT mappings through a different `vid.sys` code path —
but we have not directly measured Windows DirectMap performance.

DirectMap read path is reverted; probe code retained for future use.

### Readdirplus (dcache priming during readdir)

CIFS primes the dcache during `readdir` to avoid per-file `lookup`
calls on subsequent `stat`. This makes sense when each lookup is a
network round-trip (1-10 ms). For VSMB over VMBus (~170 us RTT),
the priming cost exceeds the lookup cost:

| Operation | Cost |
|-----------|------|
| 5,084 lookups (stat after ls) | 0.86s |
| 5,084 `iget5_locked` + `d_alloc` + `d_splice_alias` | 1.5s |

**Net effect**: readdirplus made `ls -la` ~0.64s slower. Discarded.

### GPA-direct packet bypass (VMBus type 9)

VMBus supports `VM_PKT_DATA_USING_GPA_DIRECT` (type 9) packets where
the ring carries only a small descriptor and data is read directly from
guest physical memory. This would bypass the 64K pipe payload limit
that caps our write chunk size.

RE of `vmbuspiper.dll` and `vmbkmclr.sys` confirmed four independent
blocking points:
1. Pipe setup never calls `VmbChannelInitSetMaximumExternalData`
2. Pipe read handler only accepts descriptor types 1/2/3/4, not type 9
3. Pipe activation hard-fails into error state 7 on non-type-1 packets
4. `VmbChannelInitSuppressQueueManagement` bypasses the KMCL packet
   callback that would handle external data

`VmbChannelPacketGetExternalData` is imported but has no code callsite
in the pipe-mode path.

## Compound Operations

SMB2 compound requests batch multiple PDUs into a single VMBus
round-trip. Two types are implemented:

### CREATE+CLOSE (metadata probe)

Used by `lookup` and `getattr` (cache-miss path). Instead of
CREATE→extract info→CLOSE (2 round-trips), a single compound PDU
does both.

Measured on `ls -laR` of a directory with 5,084 entries:
- Wall time: **-30.6%**
- Transport round-trips: **-44%**

### CREATE+IOCTL+CLOSE (symlink readlink)

Used by `get_reparse` for reading symlink targets. Saves 2 of 3
round-trips.

### CREATE+SET_INFO+CLOSE — SET_INFO must be terminal

The CIFS-style 3-PDU `CREATE+SET_INFO+CLOSE` compound is not usable
against `vmusrv.dll`: the host's compound-continuation path corrupts the
chain state after a successful SET_INFO, so it cannot advance to the
following CLOSE and no response is sent.

The implemented form is `CREATE+SET_INFO(final)` plus a standalone
`CLOSE`. SET_INFO is the last PDU in the compound, which avoids the
broken continuation path. This changes `set_basic_info` / `set_eof`
from 3 round-trips to 2 round-trips.

Paths that need another operation after SET_INFO, such as hardlink and
rename setattr handling, still use separate requests.

Wall-time impact on `tar xf` is in the [Small-File / Metadata
Workload](#small-file--metadata-workload) section.

## Small-File / Metadata Workload

The fio-cdm stages above measure bulk I/O. Archive extraction stresses
a different path: many small creates, closes, stats, and timestamp
updates.

Benchmark: `tar xf linux-6.12.tar.xz` into a VSMB share. The archive
contains 86,605 regular files plus directories and symlinks, and
extracts to about 1.6 GB.

| Stage | Wall | Δ | Main change |
|---|---|---|---|
| Pre-atomic_open | 4m19s | baseline | O_CREAT path used separate lookup, create, and open requests |
| + atomic_open | 2m46s | -1m33s | O_CREAT path becomes one CREATE that instantiates the dentry |
| + generalized CREATE+CLOSE compound | not isolated | small | metadata probes and simple create/unlink paths drop one round-trip |
| Stable baseline rerun | **2m59s** | — | current atomic_open + CREATE+CLOSE baseline under host variance |
| + 2-PDU SET_INFO compound | **2m55-56s** | -3-4s | timestamp SET_INFO path drops from 3 round-trips to 2 |
| `tar -m` | **1m48s** | -1m11s | tar skips mtime restore, so the utimensat path is not executed |
| Local ext4 on btrfs | 2.7s | — | local-filesystem reference |

`atomic_open` is the dominant improvement. Before it, creating a file
walked through lookup/probe, create, and open as separate SMB2 request
sequences. The atomic path sends the final CREATE directly and lets VFS
populate the new dentry from that result.

The generalized `CREATE+CLOSE` helper reuses the same compound shape
for metadata probes and simple create/unlink-style paths. It is not
isolated in the table because it shipped together with adjacent VFS
work, but it is part of the stable baseline.

The SET_INFO compound targets the timestamp restore that `tar xf` runs
near the end of each file. The win is small because it removes one
round-trip, while most of the `tar xf` versus `tar -m` gap is host-side
metadata work in the SET_INFO path.

A future direction is deferred-close + FID-reuse for the utimensat
path: keep the just-closed write FID briefly and issue timestamp
SET_INFO on that FID instead of reopening by path. That removes the
CREATE and CLOSE around each timestamp update; the hard part is
invalidating the cached handle before sibling rename, unlink, or
SET_INFO operations conflict with it.

## Q1 Write Gap Analysis

The remaining performance gap is most visible in Q1 (single-threaded,
single-outstanding) sequential writes:

| Implementation | Q1 Write | Relative |
|----------------|----------|----------|
| Host native (1 MB/op) | 3,707 MB/s | 100% |
| hv_vmsmb (65K/op) | 1,697 MB/s | 46% |

Writing 1 MB requires ~16 VMBus round-trips (65K each), each taking
~41 us. The 16x latency overhead is the likely Q1 bottleneck. Q8
recovers most of this through pipeline overlap (3,853 MB/s = 104% of
host native).

## Real-World Benchmarks

Model file loading (LLM weight shards), measured with `dd`:

| Model | Size | Host NVMe Cold | VM Cold | VM Hot |
|-------|------|---------------|---------|--------|
| Qwen3-Coder-Next-AWQ | 4.7 GB/shard | 2.0-2.2 GB/s | 2.5 GB/s | 3.1-3.8 GB/s |
| GLM-4.5-Air-AWQ (58 GB total) | 4.7 GB/shard | 1.2-1.3 GB/s | 1.5-1.8 GB/s | 3.7-3.8 GB/s |
| Qwen3.5-122B-GGUF | 47 GB single shard | 1.6 GB/s | 2.5 GB/s | 2.2 GB/s |

"VM cold" means both host page cache and guest page cache are cold
(clean VM restart). "VM hot" means host page cache is warm.

VM cold reads sometimes exceed host NVMe raw speed, possibly due to
the guest readahead pipeline achieving higher effective NVMe queue
depth than a single-threaded host `dd`.

## Filesystem Correctness

[pjdfstest](https://github.com/pjd/pjdfstest) results: **8,787 / 8,789
pass**. The 2 failures are `utimensat` timestamp precision issues
(Windows FILETIME granularity vs POSIX nanosecond expectation).
