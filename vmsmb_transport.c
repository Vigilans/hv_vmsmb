// SPDX-License-Identifier: GPL-2.0
/*
 * vmsmb_transport.c - VMBus ring buffer transport for VSMB
 *
 * Handles channel open/close and synchronous send/receive over VMBus.
 *
 * Receive path follows the hvsock (hyperv_transport.c) pattern: iterate
 * ring buffer entries with hv_pkt_iter, parse the vmpipe_proto_header
 * in each entry, skip notifications (pkt_type=0), accumulate data
 * payloads (pkt_type=1). No overflow buffer, no magic scanning —
 * each VMBus ring entry is one self-contained pipe message.
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
}

/*
 * Receive one response by iterating VMBus ring buffer entries.
 *
 * Each ring entry contains one vmpipe_proto_header (8 bytes) followed
 * by data_size bytes of payload. Like hvsock, we use hv_pkt_iter to
 * walk entries without copying alignment padding.
 *
 * pkt_type=0 entries are notifications (skip).
 * pkt_type=1 entries carry response data (DirectTCP + SMB2).
 *
 * Data payloads are accumulated into recv_buf starting at offset
 * sizeof(vmpipe_hdr) to leave room for a synthetic PipeHdr that
 * callers expect.
 */
static int vmsmb_recv_response(struct vmsmb_session *sess,
			       void *recv_buf, u32 recv_buf_size,
			       u32 *recv_len)
{
	struct vmbus_channel *ch = sess->channel;
	/* Reserve space for synthetic PipeHdr at recv_buf[0..7] */
	const u32 hdr_reserve = sizeof(struct vmpipe_hdr);
	u32 offset = hdr_reserve;
	u32 expected_total = 0; /* 0 = unknown, set once DirectTCP parsed */
	unsigned long deadline = jiffies +
		msecs_to_jiffies(VMSMB_TIMEOUT_MS);

	while (1) {
		struct vmpacket_descriptor *desc;
		bool got_data = false;

		foreach_vmbus_pkt(desc, ch) {
			const struct vmpipe_hdr *ph;
			u32 pkt_payload_len, ptype, dsize, copy;
			const u8 *data;

			pkt_payload_len = hv_pkt_datalen(desc);
			if (pkt_payload_len < sizeof(struct vmpipe_hdr))
				continue;

			ph = (const struct vmpipe_hdr *)
				((const u8 *)desc + (desc->offset8 << 3));
			ptype = le32_to_cpu(ph->pkt_type);
			dsize = le32_to_cpu(ph->data_size);

			if (ptype == 0) {
				/* Notification — skip */
				continue;
			}

			if (ptype != VMPIPE_TYPE_DATA || dsize == 0)
				continue;

			/* Validate data_size against actual packet payload */
			if (sizeof(struct vmpipe_hdr) + dsize > pkt_payload_len)
				dsize = pkt_payload_len -
					sizeof(struct vmpipe_hdr);

			data = (const u8 *)ph + sizeof(struct vmpipe_hdr);
			copy = min(dsize, recv_buf_size - offset);
			if (copy > 0) {
				memcpy(recv_buf + offset, data, copy);
				offset += copy;
			}
			got_data = true;

			if (expected_total == 0 &&
			    offset - hdr_reserve >=
					sizeof(struct smb2_direct_tcp_hdr)) {
				const struct smb2_direct_tcp_hdr *tcp =
					recv_buf + hdr_reserve;
				u32 body_size =
					smb2_direct_tcp_get_size(tcp);

				expected_total = hdr_reserve +
					sizeof(struct smb2_direct_tcp_hdr) +
					body_size;
			}
		}

		/* Check if response is complete */
		if (expected_total > 0 && offset >= expected_total)
			break;

		if (got_data)
			continue;

		/* No data — wait briefly, then recheck.
		 * Short waits avoid completion races: if the
		 * callback fired before we entered wait, we just
		 * spin again after the short timeout.
		 */
		if (time_after(jiffies, deadline)) {
			pr_err("recv timeout (offset=%u expected=%u)\n",
			       offset - hdr_reserve, expected_total);
			return -ETIMEDOUT;
		}

		wait_for_completion_timeout(&sess->recv_done,
					    msecs_to_jiffies(50));
		reinit_completion(&sess->recv_done);
	}

	/* Write synthetic PipeHdr at the front */
	{
		struct vmpipe_hdr *ph = recv_buf;
		u32 data_len = offset - hdr_reserve;

		ph->pkt_type = cpu_to_le32(VMPIPE_TYPE_DATA);
		ph->data_size = cpu_to_le32(data_len);
	}

	*recv_len = offset;
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

	return vmsmb_recv_response(sess, recv_buf, recv_buf_size, recv_len);
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
	 * notifications. Wait briefly then drain all pending entries.
	 */
	{
		struct vmpacket_descriptor *desc;
		int drain_count = 0;

		wait_for_completion_timeout(&sess->recv_done,
					    msecs_to_jiffies(500));
		reinit_completion(&sess->recv_done);

		foreach_vmbus_pkt(desc, sess->channel)
			drain_count++;

		if (drain_count > 0)
			pr_info("drained %d pending ring entries\n",
				drain_count);
	}

	return 0;
}
