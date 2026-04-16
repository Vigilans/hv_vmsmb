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
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/netfs.h>

/* VSMB class GUID: 4d12e519-17a0-4ae4-8eaa-5270fc6abdb7 */
#define HV_VSMB_GUID \
	GUID_INIT(0x4d12e519, 0x17a0, 0x4ae4, \
		  0x8e, 0xaa, 0x52, 0x70, 0xfc, 0x6a, 0xbd, 0xb7)

/* Default ring buffer size (bytes per direction) */
#define VMSMB_RING_SIZE		(256 * 1024)

/* Max SMB2 response buffer */
#define VMSMB_MAX_RESPONSE	4096

/* Max I/O response buffer (header overhead + MaxReadSize) */
#define VMSMB_MAX_IO_RESPONSE	(1048576 + 256)

/*
 * VMBus pipe-mode guest→host packets must fit within 64K.
 * Total VMBus payload = vmpipe_hdr(8) + DirectTCP(4) + SMB2 header + data.
 * READ requests are small so the limit only constrains WRITE data.
 * READ chunk controls how much data we ask the server to return per request;
 * the response travels host→guest and is not subject to this limit.
 */
#define VMSMB_MAX_WRITE_CHUNK	(65536 - 256)	/* 65280 — under 64K pipe MTU */
#define VMSMB_MAX_READ_CHUNK	(192 * 1024)	/* limited by ring buffer size */

/* Timeout for synchronous send/recv (ms) */
#define VMSMB_TIMEOUT_MS	10000

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
	u32 tree_id;
	u64 message_id;
	u32 max_read_size;
	u32 max_write_size;
	u32 max_transact_size;

	/* Transport serialization */
	struct mutex transport_mutex;

	/* Synchronous receive completion */
	struct completion recv_done;
	spinlock_t recv_lock;
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

/* vmsmb_smb2.c */
int vmsmb_smb2_negotiate(struct vmsmb_session *sess);
int vmsmb_smb2_session_setup(struct vmsmb_session *sess);
int vmsmb_smb2_tree_connect(struct vmsmb_session *sess, const char *share_name);
int vmsmb_smb2_create(struct vmsmb_session *sess, const char *path,
		      u32 desired_access, u32 disposition, u32 create_options,
		      struct vmsmb_fid *fid, struct vmsmb_file_info *info);
int vmsmb_smb2_close(struct vmsmb_session *sess, struct vmsmb_fid *fid);
int vmsmb_smb2_read(struct vmsmb_session *sess, struct vmsmb_fid *fid,
		    u64 offset, u32 length, void *data, u32 *bytes_read);
int vmsmb_smb2_write(struct vmsmb_session *sess, struct vmsmb_fid *fid,
		     u64 offset, const void *data, u32 length,
		     u32 *bytes_written);
int vmsmb_smb2_query_dir(struct vmsmb_session *sess, struct vmsmb_fid *fid,
			 const char *pattern, void *buf, u32 buf_size,
			 u32 *data_len);
int vmsmb_smb2_rename(struct vmsmb_session *sess,
		       const char *old_path, const char *new_path,
		       bool replace);
int vmsmb_smb2_unlink(struct vmsmb_session *sess, const char *path);
int vmsmb_smb2_hardlink(struct vmsmb_session *sess,
			 const char *src_path, const char *link_path);
int vmsmb_smb2_ioctl(struct vmsmb_session *sess, struct vmsmb_fid *fid,
		      u32 ctl_code, const void *in, u32 in_len,
		      void *out, u32 out_size, u32 *out_len);
int vmsmb_smb2_get_reparse(struct vmsmb_session *sess, const char *path,
			    void *buf, u32 buf_size, u32 *data_len);
int vmsmb_smb2_create_symlink(struct vmsmb_session *sess,
			       const char *path, const char *target);

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
