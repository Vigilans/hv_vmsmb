# Code Attribution

This document describes the upstream sources referenced during development
of `hv_vmsmb`. The module is licensed under GPL-2.0; all referenced
projects use GPL-2.0-compatible licenses.

## Upstream References

| Project | Files / API | License | What we use |
|---------|-------------|---------|-------------|
| **Linux CIFS client** (`fs/smb/client/`) | `smb2pdu.c`, `smb2maperror.c`, `smb2inode.c`, `cifsfs.c`, `inode.c` | LGPL-2.1 | Inode lifecycle patterns, NTSTATUS mapping, VFS integration |
| **Linux CIFS common headers** (`fs/smb/common/`) | `smb2pdu.h`, `smb2status.h`, `fscc.h` | LGPL-2.1 | SMB2 struct definitions (copied, SPDX headers preserved) |
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
| `vmsmb_recv_response` (stream framing) | **Original** | SMB2 stream header parsing, reverse-engineered from VSMB protocol |
| `vmsmb_send_recv` (sync model) | **Original** | hvsock is async; we use sync + mutex |
| `vmsmb_smb2_transact` | **Original** | Wraps PipeHdr + StreamHdr, exposes pure SMB2 interface to upper layer |
| `vmsmb_negotiate_version` | **Original** | VSMB version protocol is entirely reverse-engineered |
| EAGAIN retry + post-negotiate drain | **Original** | Discovered empirically |

### vmsmb_smb2.c

| Code | Origin | Notes |
|------|--------|-------|
| `smb2pdu.h` / `smb2status.h` / `fscc.h` | **Copied** from CIFS `fs/smb/common/` | Struct definitions only; SPDX headers preserved |
| `vmsmb_fill_hdr` | **Original** | Simplified from CIFS `smb2_plain_req_init()` + `fill_small_buf()` |
| `vmsmb_check_resp` | **Original** | Simplified from CIFS `smb2_check_message()` |
| `vmsmb_status_to_errno` | **Ported** from CIFS `smb2maperror.c` | ~40 NTSTATUS-to-errno entries |
| NEGOTIATE / SESSION_SETUP | **Original** | Intentionally simplified (single dialect, no auth) |
| TREE_CONNECT | **Original** | UNC path `\\vsmb\<ShareName>` discovered via reverse engineering |
| `vmsmb_path_to_utf16` | **Ported** from kernel `utf8s_to_utf16s()` | Corresponds to CIFS `cifs_strtoUTF16()`, without NLS/SFU/SFM |
| CREATE / CLOSE / READ / WRITE / QUERY_DIR | **Original** | Fills SMB2 structs per spec; no compound/oplock/async |
| SET_INFO (rename) | **Original** | Corresponds to CIFS `smb2_rename_path()`; simplified to CREATE+SET_INFO+CLOSE |

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
| `vmsmb_fsync` | **Ported** from CIFS `cifs_fsync` pattern | `file_write_and_wait_range` |
| `super_setup_bdi` | **Ported** from CIFS | Required for netfs writeback |
| `fs_context` / mount options | **Standard** VFS `fs_context` API | `fs_parameter_spec` + `parse_param` |
| `vmsmb_fill_inode` | **Original** | SMB2 attrs to inode; CIFS `cifs_fattr_to_inode` is much more complex |
| `vmsmb_build_path` | **Original** | CIFS has `build_path_from_dentry`, similar but simpler |
| `vmsmb_lookup` | **Original** | Uses CREATE to probe; CIFS uses compound ops |
| `vmsmb_create` / `vmsmb_mkdir` | **Original** | |
| `vmsmb_unlink` / `vmsmb_rmdir` | **Original** | Uses `DELETE_ON_CLOSE`; CIFS uses `SET_INFO FileDispositionInfo` |
| `vmsmb_rename` | **Original** | Calls `vmsmb_smb2_rename()`, supports `RENAME_NOREPLACE` |
| `vmsmb_file_open` / `release` | **Original** | Open flags to SMB2 disposition mapping |
| `vmsmb_readdir` | **Original** | Parses `FILE_DIRECTORY_INFO` chain |
| `vmsmb_utf16_name_to_utf8` | **Ported** from kernel `utf16s_to_utf8s()` | Corresponds to CIFS `cifs_from_utf16()`, without NLS/SFU/SFM |
| `vmsmb_issue_read` / `issue_write` | **Original** | netfs callbacks; CIFS versions are async |
| `vmsmb_statfs` | **Original** | Hardcoded values, no server query |
| `vmsmb_getattr` | **Original** | `generic_fillattr` only, no server revalidation |

## Summary

| Category | Approximate % | Description |
|----------|---------------|-------------|
| Ported from upstream | ~20% | Inode lifecycle (CIFS), recv loop (hvsock), netfs aops/fops, struct headers |
| Spec-conformant original | ~60% | SMB2 command construction, VFS ops, stream framing, mount logic |
| Reverse-engineered original | ~20% | VSMB version protocol, UNC path format, 64K pipe MTU, post-negotiate drain |

## Protocol Discovery

The following aspects of the VSMB protocol are not documented in any
public specification and were discovered through reverse engineering:

- **VSMB version exchange**: DirectTCP-style framing with `type=1`,
  payload of `{version: u32, capabilities: u32}`
- **UNC path format**: `\\vsmb\<ShareName>` for TREE_CONNECT
- **VMBus pipe-mode 64K guest-to-host MTU**: Packets exceeding 64K
  are silently dropped by the host
- **Post-negotiate drain**: Host may send asynchronous notifications
  after version negotiation that must be drained before SMB2 begins

## License Compatibility

| Upstream | License | Compatible with GPL-2.0? |
|----------|---------|--------------------------|
| CIFS client (`fs/smb/client/`) | LGPL-2.1 | Yes |
| CIFS common headers (`fs/smb/common/`) | LGPL-2.1 | Yes |
| hvsock (`hyperv_transport.c`) | GPL-2.0-only | Yes |
| Kernel `lib/unicode.c` | GPL-2.0 | Yes |
| netfs (`fs/netfs/`) | GPL-2.0 | Yes |
| libsmb2 (future async reference) | LGPL-2.1 | Yes |
