/* SPDX-License-Identifier: GPL-2.0 */
/*
 * vmsmb.h - Internal definitions for hv_vmsmb kernel module
 *
 * VSMB (Virtual SMB) client over Hyper-V VMBus for Linux guests.
 */
#ifndef _VMSMB_H
#define _VMSMB_H

#include <linux/hyperv.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/netfs.h>
#include "fscc.h"

/* VSMB class GUID: 4d12e519-17a0-4ae4-8eaa-5270fc6abdb7 */
#define HV_VSMB_GUID \
	GUID_INIT(0x4d12e519, 0x17a0, 0x4ae4, \
		  0x8e, 0xaa, 0x52, 0x70, 0xfc, 0x6a, 0xbd, 0xb7)

/* Default ring buffer size (bytes per direction) */
#define VMSMB_RING_SIZE		(1024 * 1024)

/* Max SMB2 response buffer */
#define VMSMB_MAX_RESPONSE	4096

/*
 * Max I/O response buffer (MaxReadSize + framing/header overhead).
 * Overhead: StreamHdr(4) + smb2_hdr(64) + smb2_read_rsp body(17) + padding = ~85.
 * Rounded to 256 for alignment safety.
 */
#define VMSMB_MAX_IO_RESPONSE	(1048576 + 256)

/*
 * Guest→host packet size limit.  The VMBus pipe payload (DirectTCP header +
 * SMB2 PDU) must fit in 16 bits, i.e. ≤ 0xFFFF.  At 0x10000 the size
 * overflows and the host silently drops the packet.  Binary-search testing
 * confirms max write data = 0xFFFF - sizeof(smb2_direct_tcp_hdr) -
 * sizeof(struct smb2_write_req) = 65535 - 4 - 112 = 65419.
 *
 * vmusrv.dll also has Smb2MaxPacketSize = 0x11000 at the SMB2 layer, but
 * the pipe-level 16-bit limit is hit first.
 *
 * READ responses travel host→guest and are not subject to this limit;
 * VMSMB_MAX_READ_CHUNK is our self-chosen chunk size, sized for good
 * pipelining within the 1MB ring buffer.
 */
#define VMSMB_PIPE_MAX_PAYLOAD	0xFFFF
#define VMSMB_SMB2_MAX_PACKET_SIZE	0x11000
#define VMSMB_WRITE_HDR_SIZE		0x70	/* sizeof(struct smb2_write_req) */
#define VMSMB_DIRECT_TCP_HDR_SIZE	4
#define VMSMB_MAX_WRITE_CHUNK	(VMSMB_PIPE_MAX_PAYLOAD - VMSMB_DIRECT_TCP_HDR_SIZE - VMSMB_WRITE_HDR_SIZE)
#define VMSMB_MAX_READ_CHUNK	(512 * 1024)

/* Timeout for synchronous send/recv (ms). CIFS uses 30s; local VMBus latency
 * is sub-millisecond, so 10s is generous even for host-side disk I/O. */
#define VMSMB_TIMEOUT_MS	10000

/* Max send retries on EAGAIN (ring buffer backpressure) */
#define VMSMB_SEND_MAX_RETRIES	100

/*
 * VMBus pipe header — required for pipe-mode channels.
 */
struct vmpipe_hdr {
	__le32 pkt_type;
	__le32 data_size;
} __packed;

#define VMPIPE_TYPE_DATA	1

/*
 * SMB2 stream framing header (4 bytes, big-endian).
 *
 * Same format as MS-SMB2 "Direct TCP Transport" (§2.1) and the
 * "rfc1002_marker" in the Linux CIFS client (fs/smb/client/transport.c),
 * but carried over VMBus pipes instead of TCP.
 *
 * VSMB extends the type field: 0 = SMB2 PDU, 1 = VSMB version exchange.
 */
struct smb2_stream_hdr {
	u8 type;
	u8 size_be[3];
} __packed;

#define SMB2_STREAM_TYPE_SMB2		0
#define SMB2_STREAM_TYPE_VERSION	1

static inline void smb2_stream_set_size(struct smb2_stream_hdr *h, u32 size)
{
	h->size_be[0] = (size >> 16) & 0xff;
	h->size_be[1] = (size >> 8) & 0xff;
	h->size_be[2] = size & 0xff;
}

static inline u32 smb2_stream_get_size(const struct smb2_stream_hdr *h)
{
	return ((u32)h->size_be[0] << 16) |
	       ((u32)h->size_be[1] << 8) |
	       (u32)h->size_be[2];
}

/*
 * VSMB version request/response payload.
 */
struct vsmb_version_payload {
	__le32 version;
	__le32 capabilities;
} __packed;

#define VSMB_VERSION_1		1
#define VSMB_CAP_DIRECTMAP	1

/*
 * VSMB private FSCTL for DirectMap (not public FSCTL_QUERY_DIRECT_ACCESS_EXTENTS).
 * Input: 8 bytes (PageProtection + AllocationAttributes).
 * Output: 0x28 bytes (extent descriptor with GPA page_index).
 */
#define VSMB_FSCTL_QUERY_DIRECT_ACCESS	0x001403cc

struct vsmb_directmap_req {
	__le32 page_protection;		/* PAGE_READONLY=0x02, PAGE_EXECUTE_READ=0x20 */
	__le32 alloc_attributes;	/* SEC_COMMIT=0x08000000, SEC_IMAGE=0x01000000 */
} __packed;

struct vsmb_directmap_reply {
	__le64 original_image_base;
	__le32 extent_count;		/* always 1 */
	__le32 reserved;
	__le64 total_page_count;
	__le64 page_index;		/* GPA base page number; phys addr = page_index << 12 */
	__le64 page_count;
} __packed;

/*
 * SMB2 file ID (128-bit opaque handle).
 */
struct vmsmb_fid {
	u64 persistent;
	u64 volatile_id;
};

/*
 * Basic file info extracted from SMB2 responses.
 */
struct vmsmb_file_info {
	u64 size;
	u64 alloc_size;
	u64 creation_time;	/* Windows FILETIME (100ns since 1601) */
	u64 last_access_time;
	u64 last_write_time;
	u64 change_time;
	u32 attributes;		/* FILE_ATTRIBUTE_* */
	u64 index_number;	/* NTFS file reference number (from QFid create context), 0 if unavailable */
};

/*
 * Per-request tracking for async transport.
 *
 * Analogous to libsmb2's struct smb2_pdu / CIFS's struct mid_q_entry.
 * Each in-flight SMB2 request gets one of these; the channel callback
 * matches responses by MessageId and completes the right request.
 *
 * Completion model:
 *   - Sync path: caller waits on `done`; channel_cb calls complete().
 *   - Async path: caller sets `async_cb`; channel_cb schedules `work`,
 *     which invokes async_cb() in process context (safe to sleep,
 *     copy_to_iter, terminate netfs subreq, etc.). The async_cb owns
 *     the request lifetime — it must kfree(req) and kvfree(response_buf).
 */
struct vmsmb_request {
	struct list_head list;		/* in sess->pending_requests */
	u64 message_id;			/* SMB2 MessageId for matching */

	/* Response buffer (caller-owned for sync, req-owned for async) */
	void *response_buf;
	u32 response_buf_size;
	u32 response_len;		/* actual bytes received */

	/* Stream framing state (used by channel_cb) */
	u32 expected_total;		/* from DirectTCP header, 0=unknown */
	u32 recv_offset;		/* bytes accumulated so far */

	int status;			/* 0 or -errno */
	struct completion done;		/* signaled when response complete (sync) */

	/* Async completion (optional) */
	void (*async_cb)(struct vmsmb_request *req);
	void *async_priv;		/* opaque for async_cb */
	struct work_struct work;	/* scheduled by channel_cb if async_cb set */
};

/*
 * Session state for one VSMB connection.
 */
struct vmsmb_session {
	struct hv_device *dev;
	struct vmbus_channel *channel;

	/* VSMB version negotiation result */
	u32 vsmb_version;
	u32 vsmb_caps;

	/* SMB2 session state */
	u64 session_id;
	atomic64_t message_id;
	u32 max_read_size;
	u32 max_write_size;
	u32 max_transact_size;

	/* Send serialization (ring buffer write is not concurrent-safe) */
	struct mutex send_mutex;

	/* Pending request tracking */
	spinlock_t pending_lock;
	struct list_head pending_requests;

	/* Stream reassembly state (channel_cb context, single-threaded) */
	struct vmsmb_request *current_recv;
	u8 scratch[64];		/* accumulate initial bytes of new response */
	u32 scratch_len;
	u32 skip_bytes;		/* bytes to skip for unmatched response */

	/* Synchronous send+recv for pre-SMB2 (version negotiation) */
	struct completion recv_done;
};

/*
 * Superblock private data.
 */
struct vmsmb_sb_info {
	struct vmsmb_session *sess;
	char *share_name;
	u32 tree_id;
	kuid_t uid;		/* owner uid for all inodes (mount-time) */
	kgid_t gid;		/* owner gid for all inodes (mount-time) */
	umode_t file_mode;	/* permission bits for files */
	umode_t dir_mode;	/* permission bits for directories */
	bool noperm;		/* skip VFS permission checks */
	char *symlinkroot;	/* mount option: translate Windows abs symlinks to {symlinkroot}/x/... */
	unsigned long actimeo;	/* metadata cache TTL in jiffies (mount option, default 1s) */
};

/*
 * Per-open-file private data.
 */
struct vmsmb_file_ctx {
	struct vmsmb_fid fid;
};

/*
 * Per-inode private data — wraps struct netfs_inode.
 * netfs_inode must be first so container_of works via netfs_inode().
 */
struct vmsmb_inode_info {
	struct netfs_inode netfs;	/* Must be first — contains struct inode */
	struct vmsmb_file_ctx *active_ctx; /* Open file context for writeback */
	char *symlink_target;		/* Cached readlink target, or NULL */
	u64 index_number;		/* NTFS file reference (dedup key); 0 if unavailable */
	unsigned long meta_expires;	/* jiffies after which metadata is stale */

	/* DirectMap state (per-inode, set on first open if caps allow) */
	void __iomem *dm_addr;		/* ioremap_cache'd kernel VA, or NULL */
	u64 dm_size;			/* mapped region size in bytes */
};

static inline struct vmsmb_inode_info *VMSMB_I(struct inode *inode)
{
	return container_of(inode, struct vmsmb_inode_info, netfs.inode);
}

/* Global session (one VSMB channel per VM) */
extern struct vmsmb_session *vmsmb_global_session;

/* Inode cache */
extern struct kmem_cache *vmsmb_inode_cachep;
void vmsmb_init_once(void *data);

/* netfs integration */
extern const struct netfs_request_ops vmsmb_netfs_ops;
extern const struct address_space_operations vmsmb_aops;

/* vmsmb_transport.c */
int vmsmb_open_channel(struct vmsmb_session *sess);
void vmsmb_close_channel(struct vmsmb_session *sess);
int vmsmb_negotiate_version(struct vmsmb_session *sess);
int vmsmb_smb2_transact(struct vmsmb_session *sess,
			const void *smb2_req, u32 req_len,
			void *smb2_resp, u32 resp_buf_size,
			u32 *resp_len);
int vmsmb_smb2_submit_async(struct vmsmb_session *sess,
			    const void *smb2_req, u32 req_len,
			    u32 resp_buf_size,
			    void (*async_cb)(struct vmsmb_request *),
			    void *async_priv,
			    struct vmsmb_request **req_out);

/* vmsmb_smb2.c */
int vmsmb_smb2_negotiate(struct vmsmb_session *sess);
int vmsmb_smb2_session_setup(struct vmsmb_session *sess);
int vmsmb_smb2_tree_connect(struct vmsmb_session *sess, const char *share_name,
			    u32 *tree_id_out);
int vmsmb_smb2_create(struct vmsmb_session *sess, u32 tree_id,
		      const char *path,
		      u32 desired_access, u32 disposition, u32 create_options,
		      struct vmsmb_fid *fid, struct vmsmb_file_info *info);
int vmsmb_smb2_close(struct vmsmb_session *sess, u32 tree_id,
		     struct vmsmb_fid *fid);
int vmsmb_smb2_create_close(struct vmsmb_session *sess, u32 tree_id,
			    const char *path,
			    u32 desired_access, u32 create_options,
			    struct vmsmb_file_info *info);
int vmsmb_smb2_create_ioctl_close(struct vmsmb_session *sess, u32 tree_id,
				  const char *path,
				  u32 desired_access, u32 create_options,
				  u32 share_access,
				  u32 ctl_code,
				  const void *in, u32 in_len,
				  void *out, u32 out_size, u32 *out_len);
int vmsmb_smb2_read(struct vmsmb_session *sess, u32 tree_id,
		    struct vmsmb_fid *fid,
		    u64 offset, u32 length, void *data, u32 *bytes_read);
int vmsmb_smb2_write(struct vmsmb_session *sess, u32 tree_id,
		     struct vmsmb_fid *fid,
		     u64 offset, const void *data, u32 length,
		     u32 *bytes_written);
int vmsmb_smb2_read_async(struct vmsmb_session *sess, u32 tree_id,
			  struct vmsmb_fid *fid,
			  u64 offset, u32 length,
			  void (*cb)(void *priv, int status,
				     const void *data, u32 len),
			  void *priv);
int vmsmb_smb2_write_async(struct vmsmb_session *sess, u32 tree_id,
			   struct vmsmb_fid *fid,
			   u64 offset, const void *data, u32 length,
			   void (*cb)(void *priv, int status, u32 bytes_written),
			   void *priv);
int vmsmb_smb2_query_dir(struct vmsmb_session *sess, u32 tree_id,
			 struct vmsmb_fid *fid,
			 const char *pattern, void *buf, u32 buf_size,
			 u32 *data_len);
int vmsmb_smb2_rename(struct vmsmb_session *sess, u32 tree_id,
		       const char *old_path, const char *new_path,
		       bool replace);
int vmsmb_smb2_unlink(struct vmsmb_session *sess, u32 tree_id,
		      const char *path);
int vmsmb_smb2_hardlink(struct vmsmb_session *sess, u32 tree_id,
			 const char *src_path, const char *link_path);
int vmsmb_smb2_ioctl(struct vmsmb_session *sess, u32 tree_id,
		      struct vmsmb_fid *fid,
		      u32 ctl_code, const void *in, u32 in_len,
		      void *out, u32 out_size, u32 *out_len);
int vmsmb_smb2_get_reparse(struct vmsmb_session *sess, u32 tree_id,
			    const char *path,
			    void *buf, u32 buf_size, u32 *data_len);
int vmsmb_smb2_create_symlink(struct vmsmb_session *sess, u32 tree_id,
			       const char *path, const char *target);
struct smb2_fs_full_size_info;
int vmsmb_smb2_queryfs(struct vmsmb_session *sess, u32 tree_id,
		       struct smb2_fs_full_size_info *out);
int vmsmb_smb2_set_basic_info(struct vmsmb_session *sess, u32 tree_id,
			      const char *path,
			      const FILE_BASIC_INFO *binfo);
int vmsmb_smb2_set_eof(struct vmsmb_session *sess, u32 tree_id,
		       const char *path, u64 eof);
int vmsmb_smb2_flush(struct vmsmb_session *sess, u32 tree_id,
		     struct vmsmb_fid *fid);
int vmsmb_smb2_query_direct_access(struct vmsmb_session *sess, u32 tree_id,
				   const char *path,
				   struct vsmb_directmap_reply *reply);

/* vmsmb_vfs.c */
extern struct file_system_type vmsmb_fs_type;
extern const struct inode_operations vmsmb_dir_inode_ops;
extern const struct inode_operations vmsmb_file_inode_ops;
extern const struct inode_operations vmsmb_symlink_inode_ops;
extern const struct file_operations vmsmb_file_ops;
extern const struct file_operations vmsmb_dir_ops;

/* Windows FILETIME → Linux timespec64 conversion */
static inline struct timespec64 vmsmb_time_to_ts(u64 filetime)
{
	struct timespec64 ts;

	/* Windows FILETIME: 100ns intervals since 1601-01-01 */
	/* Linux epoch: 1970-01-01 */
	/* Difference: 11644473600 seconds */
	if (filetime == 0) {
		ts.tv_sec = 0;
		ts.tv_nsec = 0;
	} else {
		filetime -= 116444736000000000ULL;
		ts.tv_sec = filetime / 10000000;
		ts.tv_nsec = (filetime % 10000000) * 100;
	}
	return ts;
}

#endif /* _VMSMB_H */
