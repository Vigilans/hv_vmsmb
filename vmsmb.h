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

/* VSMB class GUID: 4d12e519-17a0-4ae4-8eaa-5270fc6abdb7 */
#define HV_VSMB_GUID \
	GUID_INIT(0x4d12e519, 0x17a0, 0x4ae4, \
		  0x8e, 0xaa, 0x52, 0x70, 0xfc, 0x6a, 0xbd, 0xb7)

/* Default ring buffer size (bytes per direction) */
#define VMSMB_RING_SIZE		(128 * 1024)

/* Max SMB2 response buffer */
#define VMSMB_MAX_RESPONSE	4096

/* Max I/O response buffer (header overhead + MaxReadSize) */
#define VMSMB_MAX_IO_RESPONSE	(1048576 + 256)

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
 * SMB2 Direct TCP framing header (4 bytes, big-endian).
 */
struct smb2_direct_tcp_hdr {
	u8 type;
	u8 size_be[3];
} __packed;

#define SMB2_DIRECT_TYPE_SMB2		0
#define SMB2_DIRECT_TYPE_VERSION	1

static inline void smb2_direct_tcp_set_size(struct smb2_direct_tcp_hdr *h,
					    u32 size)
{
	h->size_be[0] = (size >> 16) & 0xff;
	h->size_be[1] = (size >> 8) & 0xff;
	h->size_be[2] = size & 0xff;
}

static inline u32 smb2_direct_tcp_get_size(const struct smb2_direct_tcp_hdr *h)
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

	/* Receive overflow buffer — leftover bytes from coalesced VMBus packets */
	u8 *overflow_buf;
	u32 overflow_len;
	u32 overflow_cap;

	/* Synchronous transport (protected by recv_lock) */
	struct completion recv_done;
	u8 *recv_buf;
	u32 recv_buf_size;
	u32 recv_len;
	spinlock_t recv_lock;
};

/* vmsmb_transport.c */
int vmsmb_open_channel(struct vmsmb_session *sess);
void vmsmb_close_channel(struct vmsmb_session *sess);
int vmsmb_send_recv(struct vmsmb_session *sess,
		    const void *send_buf, u32 send_len,
		    void *recv_buf, u32 recv_buf_size,
		    u32 *recv_len);
int vmsmb_negotiate_version(struct vmsmb_session *sess);

#endif /* _VMSMB_H */
