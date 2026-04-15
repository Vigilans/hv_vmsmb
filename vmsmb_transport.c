// SPDX-License-Identifier: GPL-2.0
/*
 * vmsmb_transport.c - VMBus ring buffer transport for VSMB
 *
 * Handles channel open/close and synchronous send/receive over VMBus.
 *
 * Framing: The VSMB host uses two response framing modes:
 *   1) PipeHdr(8) + DirectTCP(4) + SMB2 — standard after drain
 *   2) pkt_type=0 notification(9) + 7-byte-header + SMB2 — at boot
 *
 * Mode 2 may deliver the notification and response in the same or
 * separate VMBus packets. This file handles both transparently.
 */

#define pr_fmt(fmt) "hv_vmsmb: " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/hyperv.h>
#include "vmsmb.h"
#include "smb2pdu.h"

static void vmsmb_channel_cb(void *ctx)
{
	struct vmsmb_session *sess = ctx;

	complete(&sess->recv_done);
}

int vmsmb_open_channel(struct vmsmb_session *sess)
{
	struct vmbus_channel *ch = sess->dev->channel;
	int ret;

	if (ch->state != CHANNEL_OPEN_STATE) {
		pr_info("channel state=%d, forcing to CHANNEL_OPEN_STATE\n",
			ch->state);
		ch->state = CHANNEL_OPEN_STATE;
	}

	sess->channel = ch;
	mutex_init(&sess->transport_mutex);
	spin_lock_init(&sess->recv_lock);
	init_completion(&sess->recv_done);

	sess->overflow_cap = 65536;
	sess->overflow_buf = kmalloc(sess->overflow_cap, GFP_KERNEL);
	if (!sess->overflow_buf)
		return -ENOMEM;
	sess->overflow_len = 0;

	ret = vmbus_open(ch, VMSMB_RING_SIZE, VMSMB_RING_SIZE,
			 NULL, 0, vmsmb_channel_cb, sess);
	if (ret) {
		pr_err("vmbus_open failed: %d\n", ret);
		return ret;
	}

	pr_info("channel opened (ring=%d)\n", VMSMB_RING_SIZE);
	return 0;
}

void vmsmb_close_channel(struct vmsmb_session *sess)
{
	if (sess->channel) {
		vmbus_close(sess->channel);
		sess->channel = NULL;
		pr_info("channel closed\n");
	}
	kfree(sess->overflow_buf);
	sess->overflow_buf = NULL;
}

/*
 * Scan a buffer for the SMB2 ProtocolId magic (0xFE 'SMB').
 * Returns offset of the magic, or buf_len if not found.
 */
static u32 vmsmb_find_smb2_magic(const u8 *buf, u32 buf_len)
{
	u32 i;

	for (i = 0; i + 4 <= buf_len; i++) {
		u32 magic;

		memcpy(&magic, buf + i, 4);
		if (magic == SMB2_PROTO_NUMBER)
			return i;
	}
	return buf_len;
}

/*
 * Gather data from overflow + ring buffer into raw_buf.
 * Read until SMB2 magic is found or timeout.
 */
static int vmsmb_gather_raw(struct vmsmb_session *sess,
			     u8 **out_buf, u32 *out_len)
{
	u8 *buf;
	u32 len = 0, cap;
	int ret, i;

	cap = max(sess->overflow_len + 8192, (u32)16384);
	buf = kvmalloc(cap, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Start with overflow data */
	if (sess->overflow_len > 0) {
		memcpy(buf, sess->overflow_buf, sess->overflow_len);
		len = sess->overflow_len;
		sess->overflow_len = 0;
	}

	/* Read from ring until we find SMB2 magic */
	for (i = 0; i < 100; i++) {
		u32 chunk_len = 0;
		u64 req_id;

		if (vmsmb_find_smb2_magic(buf, len) < len)
			break;

		/* Grow buffer if needed */
		if (len + 4096 > cap) {
			u32 new_cap = cap * 2;
			u8 *new_buf = kvmalloc(new_cap, GFP_KERNEL);

			if (!new_buf) {
				kvfree(buf);
				return -ENOMEM;
			}
			memcpy(new_buf, buf, len);
			kvfree(buf);
			buf = new_buf;
			cap = new_cap;
		}

		ret = vmbus_recvpacket(sess->channel, buf + len,
				       cap - len, &chunk_len, &req_id);
		if (ret == -ENOBUFS) {
			u32 new_cap = cap * 2;
			u8 *new_buf = kvmalloc(new_cap, GFP_KERNEL);

			if (!new_buf) {
				kvfree(buf);
				return -ENOMEM;
			}
			memcpy(new_buf, buf, len);
			kvfree(buf);
			buf = new_buf;
			cap = new_cap;
			continue;
		}
		if (ret < 0) {
			kvfree(buf);
			return ret;
		}
		if (chunk_len == 0) {
			ret = wait_for_completion_timeout(
				&sess->recv_done,
				msecs_to_jiffies(VMSMB_TIMEOUT_MS));
			if (ret == 0) {
				pr_err("gather timeout waiting for SMB2\n");
				kvfree(buf);
				return -ETIMEDOUT;
			}
			reinit_completion(&sess->recv_done);
			continue;
		}
		len += chunk_len;
	}

	*out_buf = buf;
	*out_len = len;
	return 0;
}

/*
 * Handle a pkt_type=0 notification response: gather overflow+ring data,
 * find the first SMB2 response, and synthesize PipeHdr+DirectTCP framing.
 *
 * Any data after the first SMB2 response is discarded — it's unsolicited
 * host data that we don't need (we send our own requests).
 */
static int vmsmb_handle_notification(struct vmsmb_session *sess,
				     void *recv_buf, u32 recv_buf_size,
				     u32 *recv_len)
{
	u8 *raw;
	u32 raw_len, smb2_off;
	u32 smb2_size, synth_hdr;
	int ret;

	ret = vmsmb_gather_raw(sess, &raw, &raw_len);
	if (ret)
		return ret;

	/* Find first SMB2 magic */
	smb2_off = vmsmb_find_smb2_magic(raw, raw_len);
	if (smb2_off + sizeof(struct smb2_hdr) > raw_len) {
		pr_err("SMB2 magic not found (%u bytes gathered)\n", raw_len);
		kvfree(raw);
		return -EPROTO;
	}

	/* Take everything from SMB2 magic to end as the response.
	 * Discard any excess (unsolicited host data).
	 */
	smb2_size = raw_len - smb2_off;

	/* Discard leftover overflow — it's unsolicited data */
	sess->overflow_len = 0;

	/* Build synthetic: PipeHdr(8) + DirectTCP(4) + SMB2 */
	synth_hdr = sizeof(struct vmpipe_hdr) + sizeof(struct smb2_direct_tcp_hdr);
	if (synth_hdr + smb2_size > recv_buf_size) {
		pr_err("synth response too large: %u > %u\n",
		       synth_hdr + smb2_size, recv_buf_size);
		kvfree(raw);
		return -EPROTO;
	}

	{
		struct vmpipe_hdr *ph = recv_buf;
		struct smb2_direct_tcp_hdr *tcp =
			recv_buf + sizeof(struct vmpipe_hdr);

		ph->pkt_type = cpu_to_le32(VMPIPE_TYPE_DATA);
		ph->data_size = cpu_to_le32(
			sizeof(struct smb2_direct_tcp_hdr) + smb2_size);
		tcp->type = SMB2_DIRECT_TYPE_SMB2;
		smb2_direct_tcp_set_size(tcp, smb2_size);
		memcpy(recv_buf + synth_hdr, raw + smb2_off, smb2_size);
	}

	kvfree(raw);
	*recv_len = synth_hdr + smb2_size;
	return 0;
}

int vmsmb_send_recv(struct vmsmb_session *sess,
		    const void *send_buf, u32 send_len,
		    void *recv_buf, u32 recv_buf_size,
		    u32 *recv_len)
{
	struct {
		struct vmpipe_hdr pipe;
		u8 data[];
	} __packed *pkt;
	u32 pkt_len;
	u32 offset = 0;
	u32 expected_total = 0;
	int ret;

	pkt_len = sizeof(struct vmpipe_hdr) + send_len;
	pkt = kmalloc(pkt_len, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;

	pkt->pipe.pkt_type = cpu_to_le32(VMPIPE_TYPE_DATA);
	pkt->pipe.data_size = cpu_to_le32(send_len);
	memcpy(pkt->data, send_buf, send_len);

	reinit_completion(&sess->recv_done);

	/* Send with EAGAIN retry — ring buffer may be full during large I/O */
	{
		int send_retries;

		for (send_retries = 0; send_retries < 100; send_retries++) {
			ret = vmbus_sendpacket(sess->channel, pkt, pkt_len,
					       sess->message_id,
					       VM_PKT_DATA_INBAND, 0);
			if (ret != -EAGAIN)
				break;
			usleep_range(100, 500);
		}
	}
	kfree(pkt);

	if (ret) {
		pr_err("vmbus_sendpacket failed: %d\n", ret);
		return ret;
	}

	/* Read response packets until we have the full message */

	/* Start with any leftover data from the previous response */
	if (sess->overflow_len > 0) {
		u32 copy = min(sess->overflow_len, recv_buf_size);

		memcpy(recv_buf, sess->overflow_buf, copy);
		offset = copy;
		if (copy < sess->overflow_len) {
			memmove(sess->overflow_buf,
				sess->overflow_buf + copy,
				sess->overflow_len - copy);
			sess->overflow_len -= copy;
		} else {
			sess->overflow_len = 0;
		}
	}

	while (1) {
		u32 chunk_len = 0;
		u64 request_id;
		u32 space;

		/* Parse PipeHeader as soon as we have enough data */
		if (expected_total == 0 && offset >= sizeof(struct vmpipe_hdr)) {
			const struct vmpipe_hdr *ph = recv_buf;
			u32 ptype = le32_to_cpu(ph->pkt_type);
			u32 dsize = le32_to_cpu(ph->data_size);

			if (ptype != VMPIPE_TYPE_DATA ||
			    dsize > 16 * 1024 * 1024) {
				/*
				 * Non-DATA type or unreasonably large size.
				 * Save recv_buf data back to overflow so
				 * the notification handler can find it.
				 */
				if (offset > 0 && offset <= sess->overflow_cap) {
					memcpy(sess->overflow_buf, recv_buf,
					       offset);
					sess->overflow_len = offset;
				}
				return vmsmb_handle_notification(sess,
					recv_buf, recv_buf_size, recv_len);
			}

			expected_total = sizeof(struct vmpipe_hdr) + dsize;
		}

		if (expected_total > 0 && offset >= expected_total)
			break;

		space = recv_buf_size - offset;

		ret = vmbus_recvpacket(sess->channel,
				       recv_buf + offset, space,
				       &chunk_len, &request_id);

		if (ret == -ENOBUFS) {
			if (expected_total > 0 && offset >= expected_total)
				break;
			pr_err("vmbus_recvpacket ENOBUFS (offset=%u expected=%u space=%u)\n",
			       offset, expected_total, space);
			return -ENOBUFS;
		}
		if (ret < 0) {
			pr_err("vmbus_recvpacket failed: %d\n", ret);
			return ret;
		}

		if (chunk_len == 0) {
			ret = wait_for_completion_timeout(
				&sess->recv_done,
				msecs_to_jiffies(VMSMB_TIMEOUT_MS));
			if (ret == 0) {
				pr_err("recv timeout (offset=%u expected=%u)\n",
				       offset, expected_total);
				return -ETIMEDOUT;
			}
			reinit_completion(&sess->recv_done);
			continue;
		}

		offset += chunk_len;
	}

	/* Save any overflow data for the next response */
	if (expected_total > 0 && offset > expected_total) {
		u32 excess = offset - expected_total;

		if (excess <= sess->overflow_cap) {
			memcpy(sess->overflow_buf,
			       recv_buf + expected_total, excess);
			sess->overflow_len = excess;
		}
		offset = expected_total;
	}

	/*
	 * Check PipeHeader pkt_type. Non-DATA messages (pkt_type != 1)
	 * use alternate framing. Hand off to the notification handler
	 * which gathers data, finds SMB2 magic, and synthesizes a
	 * standard PipeHdr+DirectTCP response.
	 */
	if (offset >= sizeof(struct vmpipe_hdr)) {
		const struct vmpipe_hdr *ph = recv_buf;
		u32 ptype = le32_to_cpu(ph->pkt_type);

		if (ptype != VMPIPE_TYPE_DATA)
			return vmsmb_handle_notification(sess, recv_buf,
							 recv_buf_size,
							 recv_len);
	}

	*recv_len = offset;
	return 0;
}

/*
 * VSMB version negotiation (pre-SMB2).
 */
int vmsmb_negotiate_version(struct vmsmb_session *sess)
{
	struct {
		struct smb2_direct_tcp_hdr tcp;
		struct vsmb_version_payload ver;
	} __packed req;
	u8 resp_buf[64];
	u32 resp_len;
	const struct vmpipe_hdr *pipe_resp;
	const struct smb2_direct_tcp_hdr *tcp_resp;
	const struct vsmb_version_payload *ver_resp;
	int ret;

	req.tcp.type = SMB2_DIRECT_TYPE_VERSION;
	smb2_direct_tcp_set_size(&req.tcp, sizeof(req.ver));
	req.ver.version = cpu_to_le32(VSMB_VERSION_1);
	req.ver.capabilities = cpu_to_le32(VSMB_CAP_DIRECTMAP);

	ret = vmsmb_send_recv(sess, &req, sizeof(req),
			      resp_buf, sizeof(resp_buf), &resp_len);
	if (ret)
		return ret;

	if (resp_len < sizeof(struct vmpipe_hdr) +
		       sizeof(struct smb2_direct_tcp_hdr) +
		       sizeof(struct vsmb_version_payload)) {
		pr_err("version response too short: %u\n", resp_len);
		return -EPROTO;
	}

	pipe_resp = (const struct vmpipe_hdr *)resp_buf;
	tcp_resp = (const struct smb2_direct_tcp_hdr *)
		   (resp_buf + sizeof(struct vmpipe_hdr));
	ver_resp = (const struct vsmb_version_payload *)
		   (resp_buf + sizeof(struct vmpipe_hdr) +
		    sizeof(struct smb2_direct_tcp_hdr));

	if (tcp_resp->type != SMB2_DIRECT_TYPE_VERSION) {
		pr_err("unexpected response type: %u\n", tcp_resp->type);
		return -EPROTO;
	}

	sess->vsmb_version = le32_to_cpu(ver_resp->version);
	sess->vsmb_caps = le32_to_cpu(ver_resp->capabilities);

	if (sess->vsmb_version == 0xFFFFFFFF) {
		pr_err("version rejected by host\n");
		return -EPROTO;
	}

	pr_info("VSMB version %u accepted (caps=0x%x)\n",
		sess->vsmb_version, sess->vsmb_caps);

	/*
	 * After version negotiation, the host may send asynchronous
	 * notifications and pre-emptive data. Wait briefly then drain
	 * all pending data before the SMB2 handshake.
	 */
	{
		u8 *drain;
		u32 drain_len;
		u64 drain_req;
		int drain_total = 0;

		wait_for_completion_timeout(&sess->recv_done,
					    msecs_to_jiffies(500));
		reinit_completion(&sess->recv_done);

		sess->overflow_len = 0;
		drain = kmalloc(4096, GFP_KERNEL);
		if (drain) {
			while (vmbus_recvpacket(sess->channel, drain, 4096,
						&drain_len, &drain_req) == 0 &&
			       drain_len > 0) {
				drain_total += drain_len;
			}
			kfree(drain);
		}
		if (drain_total > 0)
			pr_info("drained %d bytes of pending data\n",
				drain_total);
	}

	return 0;
}
