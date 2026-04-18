# Code Attribution

This document describes the upstream sources referenced during development
of `hv_vmsmb`. The module is licensed under GPL-2.0; all referenced
projects use GPL-2.0-compatible licenses.

## Upstream References

| Project | Files / API | License | What we use |
|---------|-------------|---------|-------------|
| **Linux CIFS client** (`fs/smb/client/`) | `smb2pdu.c`, `smb2maperror.c`, `smb2inode.c`, `cifsfs.c`, `inode.c`, `reparse.c`, `link.c` | LGPL-2.1 | Inode lifecycle patterns, NTSTATUS mapping, VFS integration, reparse/symlink parsing, hardlink |
| **Linux CIFS common headers** (`fs/smb/common/`) | `smb2pdu.h`, `smb2status.h`, `fscc.h`, `smbfsctl.h` | LGPL-2.1 | SMB2 struct definitions, FSCTL codes, reparse tags (copied, SPDX headers preserved) |
| **Linux CIFS client headers** (`fs/smb/client/`) | `smb1pdu.h` | LGPL-2.1 | CreateDisposition / CreateOptions host-endian constants (subset extracted) |
| **Linux hvsock** (`net/vmw_vsock/hyperv_transport.c`) | `hv_pkt_iter` recv loop | GPL-2.0-only | VMBus pipe-mode receive pattern |
| **Linux kernel** (`lib/unicode.c`) | `utf8s_to_utf16s`, `utf16s_to_utf8s` | GPL-2.0 | UTF-8 / UTF-16LE conversion (called directly) |
| **Linux netfs** (`fs/netfs/`) | `netfs_read_folio`, `netfs_writepages`, etc. | GPL-2.0 | Page cache read/write via standard netfs API |
| **storvsc / netvsc** (`drivers/scsi/`, `drivers/net/hyperv/`) | `max_pkt_size` pattern | GPL-2.0 | VMBus packet buffer sizing |

## Per-File Breakdown

### vmsmb_transport.c

| Code | Origin | Notes |
|------|--------|-------|
| `foreach_vmbus_pkt` recv loop | **Ported** from hvsock `hyperv_transport.c` | `hv_pkt_iter` API, `vmpipe_proto_header` parsing |
| `max_pkt_size` setup | **Ported** from storvsc/netvsc | Standard VMBus driver pattern |
| `vmbus_open` / `vmbus_close` | **Standard** VMBus API | |
| `vmsmb_channel_cb` (parse + dispatch) | **Modeled on** libsmb2 pdu/callback model | Implementation is VMBus tasklet-based, no code ported |
| `vmsmb_process_data` (stream reassembly) | **Modeled on** CIFS `cifs_demultiplex_thread` | DirectTCP frame splitting + SMB2 MessageId matching + per-request dispatch; reimplemented for VMBus pipe framing |
| `vmsmb_request` struct | **Modeled on** libsmb2 `smb2_pdu` / CIFS `mid_q_entry` | Fields designed for VMBus transport |
| `vmsmb_smb2_transact` | **Modeled on** CIFS `compound_send_recv` | Single-PDU case: build request, queue mid, send, wait, extract response; reimplemented for VMBus |
| Adaptive spinning (`VMSMB_SPIN_USEC`) | **Modeled on** NVMe `nvme_poll_cq()` | `completion_done()` busy-poll before `wait_for_completion`; no code ported |
| `vmsmb_send_recv_sync` | **VSMB-specific** | Synchronous path retained for version negotiation only |
| `vmsmb_negotiate_version` | **VSMB-specific** | VSMB version protocol is entirely reverse-engineered |
| EAGAIN retry + post-negotiate drain | **VSMB-specific** | Discovered empirically |

### vmsmb_smb2.c

| Code | Origin | Notes |
|------|--------|-------|
| `smb2pdu.h` / `smb2status.h` / `fscc.h` / `smbfsctl.h` | **Copied** from CIFS `fs/smb/common/` | Struct definitions, FSCTL codes, reparse tags; SPDX headers preserved |
| `smb1pdu.h` | **Ported** (subset) from CIFS `fs/smb/client/smb1pdu.h` | CreateDisposition + CreateOptions host-endian constants |
| `vmsmb_fill_hdr` | **Simplified** from CIFS `smb2_plain_req_init()` + `fill_small_buf()` | Skips signing, encryption, compound |
| `vmsmb_check_resp` | **Simplified** from CIFS `smb2_check_message()` | Skips StructureSize, command match, signing validation |
| `vmsmb_status_to_errno` | **Ported** from CIFS `smb2maperror.c` | ~40 NTSTATUS-to-errno entries |
| NEGOTIATE / SESSION_SETUP | **Simplified** from CIFS | Single dialect, no auth (VSMB-specific) |
| TREE_CONNECT | **VSMB-specific** | UNC path `\\vsmb\<ShareName>` discovered via reverse engineering |
| `vmsmb_path_to_utf16` | **Ported** from kernel `utf8s_to_utf16s()` | Corresponds to CIFS `cifs_strtoUTF16()`, without NLS/SFU/SFM |
| CREATE | **Simplified** from CIFS `SMB2_open()` | No create contexts, oplock, lease, compound |
| CLOSE | **Ported** from CIFS `SMB2_close_flags()` | Skips optional `POSTQUERY_ATTRIB` flag |
| READ / WRITE | **Simplified** from CIFS `smb2_async_readv()` / `smb2_async_writev()` | Synchronous, single credit charge |
| QUERY_DIR | **Simplified** from CIFS `SMB2_query_directory()` | No resumption, single info class |
| SET_INFO (rename) | **Simplified** from CIFS `smb2_rename_path()` | Three round-trips instead of compound |
| SET_INFO (hardlink) | **Ported** from CIFS `smb2_create_hardlink()` | Same access mask + wire format |
| `vmsmb_smb2_unlink` | **Ported** from CIFS `smb2_unlink()` | Same flags: `DELETE_ON_CLOSE \| OPEN_REPARSE_POINT` |
| IOCTL | **Simplified** from CIFS `SMB2_ioctl()` | Single synchronous round-trip, no compound/async/credit |
| `vmsmb_smb2_get_reparse` | **Ported** from CIFS `smb2_query_reparse_point()` | Same flags, separate CREATE+IOCTL+CLOSE |
| `vmsmb_smb2_create_symlink` | **Simplified** from CIFS `create_native_symlink()` | No symlinkroot, directory detection, or xattr contexts |
| `vmsmb_smb2_queryfs` | **Simplified** from CIFS `smb2_queryfs()` | QUERY_INFO InfoType=FILESYSTEM, FileInfoClass=FS_FULL_SIZE_INFORMATION on share root; CIFS uses compound CREATE+QUERY+CLOSE, we use three round-trips |
| `vmsmb_smb2_set_basic_info` | **Simplified** from CIFS `smb2_set_file_info_compound()` | SET_INFO InfoType=FILE, FileInfoClass=FILE_BASIC_INFORMATION; three round-trips (CREATE+SET_INFO+CLOSE) instead of CIFS compound |
| `vmsmb_smb2_set_eof` | **Simplified** from CIFS `smb2_set_file_size()` | SET_INFO InfoType=FILE, FileInfoClass=FILE_END_OF_FILE_INFORMATION; three round-trips (CREATE+SET_INFO+CLOSE) instead of CIFS compound |
| `vmsmb_smb2_flush` | **Ported** from CIFS `SMB2_flush()` | MS-SMB2 2.2.17, single round-trip |

### vmsmb_vfs.c

| Code | Origin | Notes |
|------|--------|-------|
| `vmsmb_init_once` | **Ported** from CIFS `cifs_init_once` | Slab constructor calling `inode_init_once()` |
| `vmsmb_alloc_inode` / `free_inode` | **Ported** from CIFS pattern | |
| `vmsmb_evict_inode` | **Ported** from CIFS `cifs_evict_inode` | `netfs_wait` + `truncate` + `clear` |
| `vmsmb_write_inode` | **Ported** from CIFS `cifs_write_inode` | = `netfs_unpin_writeback` |
| `netfs_inode_init` placement | **Ported** from CIFS `cifs_fattr_to_inode` | Called after inode attributes are filled |
| `vmsmb_aops` | **Standard** netfs API | `netfs_read_folio`, `netfs_readahead`, `netfs_writepages`, etc. |
| `vmsmb_file_ops` (read/write) | **Standard** netfs API | `netfs_file_read_iter`, `netfs_unbuffered_write_iter` |
| `.mmap = generic_file_mmap` | **Standard** VFS API | Page faults handled by netfs `read_folio` |
| `vmsmb_fsync` | **Ported** from CIFS `cifs_fsync` pattern | `file_write_and_wait_range` + SMB2 FLUSH via `vmsmb_smb2_flush()` |
| `super_setup_bdi` | **Ported** from CIFS | Required for netfs writeback |
| `fs_context` / mount options | **Standard** VFS `fs_context` API | `fs_parameter_spec` + `parse_param` |
| `vmsmb_fill_inode` | **Ported** from CIFS `cifs_fattr_to_inode` | SMB2 attrs to inode; simplified (no SFU/SFM, no reparse tags beyond symlink) |
| `vmsmb_refresh_inode` | **Ported** from CIFS `cifs_fattr_to_inode` update-path | Truncates pagecache on shrink, invalidates on mtime change |
| `vmsmb_build_path` | **Simplified** from CIFS `build_path_from_dentry` | Same dentry-walk logic, simpler (no UNC prefix) |
| `vmsmb_lookup` | **Ported** from CIFS `cifs_lookup` | Compound CREATE+CLOSE probe; reparse handling at lookup time |
| `vmsmb_create` / `vmsmb_mkdir` | **Ported** from CIFS `cifs_create` / `cifs_mkdir` | |
| `vmsmb_unlink` | **Ported** from CIFS `cifs_unlink` | Uses `vmsmb_smb2_unlink()`; same `DELETE_ON_CLOSE \| OPEN_REPARSE_POINT` flags |
| `vmsmb_rmdir` | **Ported** from CIFS `cifs_rmdir` | Uses `DELETE_ON_CLOSE`; CIFS uses `SET_INFO FileDispositionInfo` |
| `vmsmb_rename` | **Ported** from CIFS `cifs_rename2` | Calls `vmsmb_smb2_rename()`, supports `RENAME_NOREPLACE` |
| `vmsmb_link` | **Ported** from CIFS `cifs_hardlink()` | `d_drop()` + `inc_nlink()` under `i_lock` |
| `vmsmb_symlink` | **Simplified** from CIFS `cifs_symlink()` | Calls `vmsmb_smb2_create_symlink()`; host denies in practice |
| `vmsmb_get_link` | **Ported** from CIFS `cifs_get_link()` | Returns cached symlink target via `set_delayed_call` |
| `vmsmb_fill_inode` (reparse) | **Ported** from CIFS `cifs_reparse_point_to_fattr()` | `FILE_ATTRIBUTE_REPARSE_POINT` → `S_IFLNK` |
| `vmsmb_parse_reparse` | **Ported** from CIFS `smb2_parse_native_symlink()` | Same NT prefix stripping (`\??\`, `\DosDevices\`, `\GLOBAL??\`), `GLOBALROOT` chaining, `Global\` prefix, drive-letter translation under `symlinkroot`; skips NFS/WSL/AF_UNIX tags |
| `vmsmb_lookup` (reparse) | **Ported** from CIFS pattern | `OPEN_REPARSE_POINT` + cache symlink target at lookup time |
| `vmsmb_readdir` (reparse) | **Ported** from CIFS pattern | `FILE_ATTRIBUTE_REPARSE_POINT` → `DT_LNK` |
| `vmsmb_file_open` / `release` | **Ported** from CIFS `cifs_open` / `cifs_close` | Open flags to SMB2 disposition mapping |
| `vmsmb_readdir` | **Ported** from CIFS `cifs_readdir` | Parses `FILE_DIRECTORY_INFO` chain |
| `vmsmb_utf16_name_to_utf8` | **Ported** from kernel `utf16s_to_utf8s()` | Corresponds to CIFS `cifs_from_utf16()`, without NLS/SFU/SFM |
| `vmsmb_issue_read` / `issue_write` | **Ported** from CIFS `smb2_async_readv` / `smb2_async_writev` | Async submit + completion callback into netfs |
| `vmsmb_prepare_write` | **Ported** from CIFS `cifs_prepare_write` | Sets `sreq_max_len` for unbuffered write path |
| `vmsmb_statfs` | **Ported** from CIFS `cifs_statfs` | Calls `vmsmb_smb2_queryfs()` and converts FS_FULL_SIZE_INFORMATION to `kstatfs` |
| `vmsmb_getattr` | **Ported** from CIFS `cifs_getattr` | Re-issues CREATE+CLOSE when stale (actimeo expired); `generic_fillattr` |
| `vmsmb_setattr` | **Ported** from CIFS `cifs_setattr()` | Pushes atime/mtime/ctime via `vmsmb_smb2_set_basic_info()` and size via `vmsmb_smb2_set_eof()` + `truncate_setsize()`; uid/gid/mode stay local |

## Protocol Discovery

The following aspects of the VSMB protocol are not documented in any
public specification and were discovered through reverse engineering:

- **VSMB version exchange**: DirectTCP-style framing with `type=1`,
  payload of `{version: u32, capabilities: u32}`
- **UNC path format**: `\\vsmb\<ShareName>` for TREE_CONNECT
- **VMBus pipe-mode guest-to-host size limit**: Not a VMBus protocol
  limit — `vmusrv.dll` enforces `Smb2MaxPacketSize = 0x11000` (69632
  bytes, measured from the SMB2 header). Packets exceeding this are
  silently dropped. The VMBus transport itself supports ~512K packets.
- **Post-negotiate drain**: Host may send asynchronous notifications
  after version negotiation that must be drained before SMB2 begins
- **DirectMap protocol**: FSCTL `0x1403cc` triggers host-side
  `NtCreateSection` + page mapping; returns 0x28-byte extent descriptor
  `{OriginalImageBase, ExtentCount, TotalPageCount, PageIndex, PageCount}`.
  Request is 8 bytes: `{PageProtection, AllocationAttributes}` where
  PageProtection ∈ {PAGE_READONLY, PAGE_EXECUTE, PAGE_EXECUTE_READ}
  and AllocationAttributes ∈ {SEC_IMAGE, SEC_COMMIT}.
  No explicit invalidation — coherence via section/cache-manager semantics.
- **DirectMap budget**: `vmwp.exe` reads `direct_file_mapping_mb` from
  VM configuration (even MB, max 65536 MB)
- **Windows guest ring buffer**: mrxsmb.sys uses 5 pages (20KB) per
  direction — relies on DirectMap for data, ring only for control PDUs
- **VMBus external-data packets**: Windows guest uses type 9
  (`VM_PKT_DATA_USING_GPA_DIRECT`) for large sends/receives; ring
  carries only descriptors + small inline fragment. Our driver currently
  uses type 6 (`VM_PKT_DATA_INBAND`) which is ring-size-bound.

## License Compatibility

| Upstream | License | Compatible with GPL-2.0? |
|----------|---------|--------------------------|
| CIFS client (`fs/smb/client/`) | LGPL-2.1 | Yes |
| CIFS common headers (`fs/smb/common/`) | LGPL-2.1 | Yes |
| hvsock (`hyperv_transport.c`) | GPL-2.0-only | Yes |
| Kernel `lib/unicode.c` | GPL-2.0 | Yes |
| netfs (`fs/netfs/`) | GPL-2.0 | Yes |
| libsmb2 (design reference) | LGPL-2.1 | Yes |
