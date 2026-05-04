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
#include <linux/spinlock.h>
#include <linux/wait.h>
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
 * Initial SMB2 credit pool — minimum to send NEGOTIATE.
 *
 * Per MS-SMB2 §3.2.4.1.2, the client starts with one implicit credit so it
 * can send the initial NEGOTIATE; the server's NEGOTIATE response grants
 * the real pool via the CreditRequest field. Subsequent responses
 * replenish; sends decrement by CreditCharge.
 *
 * This supersedes the earlier VMSMB_MAX_ASYNC_INFLIGHT semaphore: credit
 * gating is the protocol-correct way to bound in-flight requests, since
 * the server's MID window — not the ring buffer or guest concurrency — is
 * what wedges the channel under burst.
 */
#define VMSMB_INITIAL_CREDITS	1

/*
 * MID table sizing.
 *
 * The MID table is sess->ct_mid_table[mid % ct_max_credits], an O(1)
 * response-demux index sized to bound the in-flight MID span.  It is a
 * separate ring from the server's Slots[] but anchored to the same wire
 * MIDs — the client's mid_table[mid % ct_max_credits] and the server's
 * Slots[mid % AllocatedWindows] map the same MID through different
 * modular indices.
 *
 * VMSMB_INITIAL_MAX_CREDITS: starting capacity.  Mirrors mrxsmb.sys's
 * 0x80; doubles via vmsmb_grow_mid_table when outstanding pressure
 * approaches max_credits.
 *
 * VMSMB_MAX_CREDITS: hard ceiling, matching server's VSmbMaxCredits
 * (vmusrv reads HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
 * Virtualization\Containers\VSmbMaxCredits, default 0x2000=8192).  The
 * server enforces EndMid - StartMid <= MaxWindowSize <= VSmbMaxCredits;
 * sending past this returns STATUS_INVALID_PARAMETER (0xc00000d0)
 * silently — recorded in ETW Event 403 but no response on the wire.
 * Once outstanding hits this cap, vmsmb_grow_mid_table refuses to grow
 * further and reserve_credits queues senders.
 *
 * Memory: 8192 slots × sizeof(void *) = 64 KB per session, kvzalloc'd.
 */
#define VMSMB_INITIAL_MAX_CREDITS	128
#define VMSMB_MAX_CREDITS		8192

/*
 * Initial adaptive target_window (mrxsmb's `target_window` init value).
 *
 * Mirrors `+0x90 target_window` initialization in
 * SmbCeAllocateCreditTransport @0x1c00156eb (init 2).  Floor for the
 * EWMA-driven shrink path; bucket 16-17 (>4.25s avg latency) divides by
 * 2 each response, so without a floor it would collapse to 0 and stall.
 *
 * 2 is enough to keep the channel breathing during catastrophic latency
 * (one CREATE+CLOSE compound = charge 2 fits exactly), so timed-out
 * sends still drain and senders eventually wake.
 */
#define VMSMB_INITIAL_TARGET_WINDOW	2

/*
 * Reserve-side wait timeout (ms).
 *
 * If the send admission gate (live_window / outstanding) keeps a sender
 * blocked beyond this, return -EBUSY.  Surfaces stalls as user-visible
 * errors instead of silent wedges.  Set to match VMSMB_TIMEOUT_MS so a
 * stuck reserve fails before its caller's transact timeout.
 */
#define VMSMB_SEND_TIMEOUT_MS	VMSMB_TIMEOUT_MS

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
	u64 message_id;			/* SMB2 MessageId, assigned by reserve_credits */
	u16 credit_charge;		/* CC at reserve time, freed back on release */
	struct vmsmb_session *sess;	/* back-pointer for async slot release */
	ktime_t send_tick;		/* set in reserve_credits; used by EWMA */

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
	u32 max_read_size;
	u32 max_write_size;
	u32 max_transact_size;

	/* Send serialization (ring buffer write is not concurrent-safe) */
	struct mutex send_mutex;

	/*
	 * Credit transport state — mrxsmb.sys-derived rate-agnostic gate.
	 *
	 * The send admission predicate is
	 *
	 *   bound = max(min(live_window, max_credits), outstanding)
	 *   effective_avail = bound - outstanding
	 *
	 * which throttles purely on outstanding (in-flight CC sum), not on
	 * accumulated CR.  When the server emits CR=0 (server-side flow
	 * control via vmusrv path #3 zero-grant) live_window stops growing,
	 * outstanding stays high, effective_avail collapses to 0, and senders
	 * queue on ct_send_wait.  In-flight responses still drain via
	 * release_mid, which re-opens the gate from below.  Net effect: any
	 * server zero-rate is tolerated without drifting next_mid past the
	 * server's actual EndMid.
	 *
	 * Models mrxsmb.sys SmbCe* credit transport
	 * (SmbCeReserveCreditsForBufferContexts, SmbCeApplyCreditGrantAndRelease,
	 * SmbCeDemuxResponseAndAccumulateCredits, SmbCeGrowCreditMidTable).
	 *
	 * ct_lock protects all ct_* fields except ct_pending_grant which is
	 * lockless atomic_add (drained via xchg under ct_lock).  Process
	 * context uses spin_lock_bh; channel_cb softirq context uses plain
	 * spin_lock — receivers do not race with each other because ring
	 * processing is single-threaded.
	 */
	spinlock_t  ct_lock;
	wait_queue_head_t ct_send_wait;
	u64    ct_oldest_mid;		/* lower bound of in-flight MID span */
	u64    ct_next_mid;		/* next MID to assign in reserve */
	u32    ct_outstanding;		/* sum of in-flight CreditCharge */
	u32    ct_live_window;		/* folded grant accumulator (verbatim CR sum) */
	atomic_t ct_pending_grant;	/* lockless receive-side accumulator */
	u32    ct_max_credits;		/* mid_table capacity, init 128, doubles to 8192 */
	struct vmsmb_request **ct_mid_table; /* size = ct_max_credits */

	/*
	 * EWMA latency feedback for adaptive target_window (mrxsmb-derived).
	 *
	 * On every release the response latency is folded into ct_avg_lat_us
	 * via mrxsmb's EWMA formula (SmbCeDemuxResponseAndAccumulateCredits
	 * @0x1c000217c..0x1c00021bc):
	 *
	 *   avg = (elapsed_us + max(outstanding, 8) * old_avg)
	 *         / (max(outstanding, 8) + credit_charge)
	 *
	 * The 18-entry bucket table at DAT_1c0072270 then maps avg latency
	 * into a multiplicative or additive op on ct_target_window:
	 *
	 *   bucket = clamp((2 * avg_us) / 500000, 0, 17)
	 *
	 * Buckets 0-7 grow target (x4..x5/4); 8-10 add (+4..+1); 11-12
	 * subtract (-1, -2); 13-17 shrink (x7/8..x1/2).  ct_target_window
	 * is clamped to [VMSMB_INITIAL_TARGET_WINDOW=2, ct_max_credits].
	 *
	 * The send admission gate uses target_window (not max_credits) as
	 * the upper bound that competes with outstanding:
	 *
	 *   bound = max(min(live_window, target_window), outstanding)
	 *
	 * When server enters sustained CR=0 flow control (vmusrv path #3
	 * zero-grant), per-request latency rises -> bucket index rises ->
	 * target_window shrinks -> outstanding cap shrinks -> in-flight
	 * count auto-throttles below ring saturation, avoiding Mode A
	 * over-send.
	 */
	u64    ct_avg_lat_us;		/* EWMA average response latency, microseconds */
	u32    ct_target_window;	/* adaptive target, init 2, clamped to max_credits */

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
void vmsmb_credit_reset(struct vmsmb_session *sess);
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
			 const char *pattern, u8 flags,
			 void *buf, u32 buf_size,
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
