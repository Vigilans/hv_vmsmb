// SPDX-License-Identifier: GPL-2.0
/*
 * vmsmb_transport.c - VMBus ring buffer transport for VSMB
 *
 * Handles channel open/close and asynchronous send/receive over VMBus.
 *
 * Receive path: the VMBus channel callback iterates ring buffer entries
 * with hv_pkt_iter, parses vmpipe_proto_header + DirectTCP stream header,
 * matches responses to pending requests by SMB2 MessageId, and completes
 * them. Multiple requests can be in-flight simultaneously.
 *
 * Send path: vmbus_sendpacket is serialized by send_mutex (ring buffer
 * write is not concurrent-safe), but the mutex is only held during the
 * send — not during the response wait.
 *
 * Version negotiation (pre-SMB2) uses a separate synchronous path since
 * there is no concurrency at that point.
 */

#define pr_fmt(fmt) "hv_vmsmb: " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/hyperv.h>
#include "vmsmb.h"
#include "smb2pdu.h"

/*
 * Adaptive spinning window (microseconds).
 *
 * Before sleeping on wait_for_completion, busy-poll for this long.
 * Sequential I/O responses arrive within a few microseconds — spinning
 * avoids the schedule/wake context switch overhead (~7μs per I/O).
 * Reference: NVMe nvme_poll_cq() uses similar adaptive polling.
 */
#define VMSMB_SPIN_USEC		10

/*
 * Find a pending request by SMB2 MessageId.
 * Must be called with sess->pending_lock held.
 *
 * Analogous to CIFS __smb2_find_mid() (fs/smb/client/smb2transport.c).
 */
static struct vmsmb_request *
vmsmb_find_request(struct vmsmb_session *sess, u64 message_id)
{
	struct vmsmb_request *req;

	list_for_each_entry(req, &sess->pending_requests, list) {
		if (req->message_id == message_id)
			return req;
	}
	return NULL;
}

/*
 * Process one vmpipe DATA payload chunk in the channel callback.
 *
 * The VSMB byte stream is: [StreamHdr(4)] [SMB2 PDU(N)] per response.
 * Multiple responses arrive sequentially (no interleaving).
 *
 * sess->current_recv tracks the request currently being received.
 * When NULL, we're at the start of a new response and need to parse
 * StreamHdr + SMB2 header to extract MessageId for dispatch.
 */
static void vmsmb_process_data(struct vmsmb_session *sess,
				const u8 *data, u32 len)
{
	while (len > 0) {
		struct vmsmb_request *req = sess->current_recv;

		if (!req) {
			/*
			 * Starting a new response. We need at least
			 * StreamHdr(4) + SMB2 header up to MessageId.
			 * MessageId is at offset 24 in struct smb2_hdr,
			 * so we need 4 + 24 + 8 = 36 bytes minimum.
			 *
			 * Use the session's scratch buffer to accumulate
			 * initial bytes until we can parse MessageId.
			 */
			const u32 min_hdr = sizeof(struct smb2_stream_hdr) +
					     offsetof(struct smb2_hdr, MessageId) +
					     sizeof(u64);
			u32 have = sess->scratch_len;
			u32 need = min_hdr - have;
			u32 copy = min(need, len);
			const struct smb2_stream_hdr *sh;
			const struct smb2_hdr *smb2h;
			u64 mid;
			u32 body_size;

			memcpy(sess->scratch + have, data, copy);
			sess->scratch_len += copy;
			data += copy;
			len -= copy;

			if (sess->scratch_len < min_hdr)
				return; /* need more data */

			/* Parse StreamHdr */
			sh = (const struct smb2_stream_hdr *)sess->scratch;
			body_size = smb2_stream_get_size(sh);

			/* Parse MessageId from SMB2 header */
			smb2h = (const struct smb2_hdr *)
				(sess->scratch + sizeof(struct smb2_stream_hdr));
			mid = le64_to_cpu(smb2h->MessageId);

			/* Find matching pending request (softirq context — no _bh) */
			spin_lock(&sess->pending_lock);
			req = vmsmb_find_request(sess, mid);
			if (req)
				list_del_init(&req->list);
			spin_unlock(&sess->pending_lock);

			if (!req) {
				pr_warn("recv: no pending request for MessageId=%llu\n",
					mid);
				/*
				 * Skip this response. We know the total size
				 * from DirectTCP, so skip remaining bytes.
				 */
				sess->skip_bytes = sizeof(struct smb2_stream_hdr) +
						   body_size - sess->scratch_len;
				sess->scratch_len = 0;
				goto skip;
			}

			/* Set up framing state */
			req->expected_total = sizeof(struct smb2_stream_hdr) +
					       body_size;
			req->recv_offset = 0;

			/* Copy scratch bytes into request's response buffer */
			{
				u32 tocopy = min(sess->scratch_len,
						 req->response_buf_size);
				memcpy(req->response_buf, sess->scratch, tocopy);
				req->recv_offset = tocopy;
			}
			sess->scratch_len = 0;
			sess->current_recv = req;

			/* Check if already complete (small response) */
			if (req->recv_offset >= req->expected_total) {
				req->response_len = req->recv_offset;
				req->status = 0;
				complete(&req->done);
				sess->current_recv = NULL;
			}
			continue;
		}

		/* Continuing accumulation into current request */
		{
			u32 space = req->response_buf_size - req->recv_offset;
			u32 remaining = req->expected_total - req->recv_offset;
			u32 copy = min3(len, space, remaining);

			if (copy > 0) {
				memcpy(req->response_buf + req->recv_offset,
				       data, copy);
				req->recv_offset += copy;
			}
			data += min(len, remaining);
			len -= min(len, remaining);

			if (req->recv_offset >= req->expected_total) {
				req->response_len = req->recv_offset;
				req->status = 0;
				complete(&req->done);
				sess->current_recv = NULL;
			}
		}
		continue;
skip:
		/* Skip bytes of an unmatched response */
		{
			u32 skip = min(len, sess->skip_bytes);
			data += skip;
			len -= skip;
			sess->skip_bytes -= skip;
		}
	}
}

/*
 * VMBus channel callback — parse and dispatch responses.
 *
 * Iterates ring buffer entries using hv_pkt_iter (hvsock pattern),
 * extracts vmpipe DATA payloads, and feeds them into the stream
 * reassembly state machine.
 *
 * Dispatch model inspired by libsmb2's smb2_service_fd() readable
 * path (parse header → match by MessageId → invoke completion).
 * CIFS uses a dedicated demultiplex_thread for the same purpose.
 *
 * Also signals recv_done for the synchronous version negotiation path.
 */
static void vmsmb_channel_cb(void *ctx)
{
	struct vmsmb_session *sess = ctx;

	/*
	 * If async requests are in flight, iterate ring buffer and
	 * dispatch responses. Otherwise, leave packets in the ring
	 * buffer for the synchronous receive path (version negotiation).
	 */
	if (!list_empty(&sess->pending_requests) || sess->current_recv) {
		struct vmpacket_descriptor *desc;

		foreach_vmbus_pkt(desc, sess->channel) {
			const struct vmpipe_hdr *ph;
			u32 pkt_payload_len, ptype, dsize;
			const u8 *data;

			pkt_payload_len = hv_pkt_datalen(desc);
			if (pkt_payload_len < sizeof(struct vmpipe_hdr))
				continue;

			ph = (const struct vmpipe_hdr *)
				((const u8 *)desc + (desc->offset8 << 3));
			ptype = le32_to_cpu(ph->pkt_type);
			dsize = le32_to_cpu(ph->data_size);

			if (ptype == 0)
				continue;

			if (ptype != VMPIPE_TYPE_DATA || dsize == 0)
				continue;

			if (sizeof(struct vmpipe_hdr) + dsize > pkt_payload_len)
				dsize = pkt_payload_len -
					sizeof(struct vmpipe_hdr);

			data = (const u8 *)ph + sizeof(struct vmpipe_hdr);
			vmsmb_process_data(sess, data, dsize);
		}
	}

	/* Signal synchronous waiters (version negotiation, drain) */
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
	mutex_init(&sess->send_mutex);
	spin_lock_init(&sess->pending_lock);
	INIT_LIST_HEAD(&sess->pending_requests);
	sess->current_recv = NULL;
	sess->scratch_len = 0;
	sess->skip_bytes = 0;
	init_completion(&sess->recv_done);

	/*
	 * Set max_pkt_size before vmbus_open so hv_ringbuffer_init
	 * allocates a pkt_buffer large enough for I/O responses.
	 * Default is VMBUS_DEFAULT_MAX_PKT_SIZE (4096) which truncates
	 * READ responses larger than ~4K in hv_pkt_iter_first.
	 */
	ch->max_pkt_size = VMSMB_MAX_IO_RESPONSE +
			   sizeof(struct vmpipe_hdr) +
			   sizeof(struct vmpacket_descriptor);

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
 * Synchronous send + receive for pre-SMB2 paths (version negotiation).
 *
 * Only used when no async requests are pending. Uses the sess->recv_done
 * completion signaled by the channel callback.
 */
static int vmsmb_send_recv_sync(struct vmsmb_session *sess,
				const void *send_buf, u32 send_len,
				void *recv_buf, u32 recv_buf_size,
				u32 *recv_len)
{
	struct {
		struct vmpipe_hdr pipe;
		u8 data[];
	} __packed *pkt;
	u32 pkt_len;
	u32 offset, expected_total;
	unsigned long deadline;
	int ret;

	pkt_len = sizeof(struct vmpipe_hdr) + send_len;
	pkt = kmalloc(pkt_len, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;

	pkt->pipe.pkt_type = cpu_to_le32(VMPIPE_TYPE_DATA);
	pkt->pipe.data_size = cpu_to_le32(send_len);
	memcpy(pkt->data, send_buf, send_len);

	reinit_completion(&sess->recv_done);

	/* Send with EAGAIN retry */
	{
		int send_retries;

		for (send_retries = 0; send_retries < 100; send_retries++) {
			ret = vmbus_sendpacket(sess->channel, pkt, pkt_len,
					       0, VM_PKT_DATA_INBAND, 0);
			if (ret != -EAGAIN)
				break;
			usleep_range(100, 500);
		}
	}
	kfree(pkt);

	if (ret) {
		pr_err("vmbus_sendpacket failed: %d (pkt_len=%u)\n",
		       ret, pkt_len);
		return ret;
	}

	/*
	 * Synchronous receive — same logic as the old vmsmb_recv_response
	 * but with PipeHdr prefix for backward compatibility with callers.
	 */
	offset = sizeof(struct vmpipe_hdr);
	expected_total = 0;
	deadline = jiffies + msecs_to_jiffies(VMSMB_TIMEOUT_MS);

	while (1) {
		struct vmpacket_descriptor *desc;
		bool got_data = false;

		foreach_vmbus_pkt(desc, sess->channel) {
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

			if (ptype == 0)
				continue;
			if (ptype != VMPIPE_TYPE_DATA || dsize == 0)
				continue;

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
			    offset - sizeof(struct vmpipe_hdr) >=
					sizeof(struct smb2_stream_hdr)) {
				const struct smb2_stream_hdr *sh =
					recv_buf + sizeof(struct vmpipe_hdr);
				u32 body_size = smb2_stream_get_size(sh);

				expected_total = sizeof(struct vmpipe_hdr) +
					sizeof(struct smb2_stream_hdr) +
					body_size;
			}
		}

		if (expected_total > 0 && offset >= expected_total)
			break;

		if (got_data)
			continue;

		if (time_after(jiffies, deadline)) {
			pr_err("recv timeout (offset=%u expected=%u)\n",
			       offset - (u32)sizeof(struct vmpipe_hdr),
			       expected_total);
			return -ETIMEDOUT;
		}

		wait_for_completion_timeout(&sess->recv_done,
					    msecs_to_jiffies(50));
		reinit_completion(&sess->recv_done);
	}

	/* Write synthetic PipeHdr */
	{
		struct vmpipe_hdr *ph = recv_buf;
		u32 data_len = offset - sizeof(struct vmpipe_hdr);

		ph->pkt_type = cpu_to_le32(VMPIPE_TYPE_DATA);
		ph->data_size = cpu_to_le32(data_len);
	}

	*recv_len = offset;
	return 0;
}

/*
 * SMB2-level transact: send a pure SMB2 PDU, receive a pure SMB2 response.
 *
 * Handles all transport framing (PipeHdr + StreamHdr) internally so the
 * SMB2 layer has no knowledge of VMBus pipe mode or stream framing.
 *
 * Multiple transacts can be in-flight concurrently. Each allocates a
 * per-request vmsmb_request on the stack, registers it in the pending
 * list, sends via vmbus_sendpacket (serialized by send_mutex), then
 * waits on its own completion.
 *
 * @smb2_req / @req_len:       SMB2 request PDU (no framing headers)
 * @smb2_resp / @resp_buf_size: caller-allocated buffer for SMB2 response
 * @resp_len:                  actual SMB2 response length on success
 */
int vmsmb_smb2_transact(struct vmsmb_session *sess,
			const void *smb2_req, u32 req_len,
			void *smb2_resp, u32 resp_buf_size,
			u32 *resp_len)
{
	const u32 stream_hdr_size = sizeof(struct smb2_stream_hdr);
	struct vmsmb_request req;
	struct smb2_stream_hdr *sh;
	struct vmpipe_hdr *pipe;
	u8 *send_buf;
	u32 send_pkt_len;
	void *recv_buf;
	u32 recv_buf_size;
	const struct smb2_hdr *smb2h;
	u32 smb2_size;
	unsigned long remaining;
	int ret;

	/* Extract MessageId from SMB2 header */
	if (req_len < sizeof(struct smb2_hdr))
		return -EINVAL;
	smb2h = (const struct smb2_hdr *)smb2_req;

	/* Initialize per-request state */
	INIT_LIST_HEAD(&req.list);
	req.message_id = le64_to_cpu(smb2h->MessageId);
	init_completion(&req.done);
	req.status = -EINPROGRESS;
	req.recv_offset = 0;
	req.expected_total = 0;

	/*
	 * Allocate response buffer with room for StreamHdr.
	 * channel_cb writes StreamHdr + SMB2 data here directly.
	 */
	recv_buf_size = stream_hdr_size + resp_buf_size;
	recv_buf = kvmalloc(recv_buf_size, GFP_KERNEL);
	if (!recv_buf)
		return -ENOMEM;

	req.response_buf = recv_buf;
	req.response_buf_size = recv_buf_size;
	req.response_len = 0;

	/* Build send packet: PipeHdr + StreamHdr + SMB2 PDU */
	send_pkt_len = sizeof(struct vmpipe_hdr) + stream_hdr_size + req_len;
	send_buf = kmalloc(send_pkt_len, GFP_KERNEL);
	if (!send_buf) {
		kvfree(recv_buf);
		return -ENOMEM;
	}

	pipe = (struct vmpipe_hdr *)send_buf;
	pipe->pkt_type = cpu_to_le32(VMPIPE_TYPE_DATA);
	pipe->data_size = cpu_to_le32(stream_hdr_size + req_len);

	sh = (struct smb2_stream_hdr *)(send_buf + sizeof(struct vmpipe_hdr));
	sh->type = SMB2_STREAM_TYPE_SMB2;
	smb2_stream_set_size(sh, req_len);

	memcpy(send_buf + sizeof(struct vmpipe_hdr) + stream_hdr_size,
	       smb2_req, req_len);

	/* Register in pending list before sending (bh: lock shared with tasklet) */
	spin_lock_bh(&sess->pending_lock);
	list_add_tail(&req.list, &sess->pending_requests);
	spin_unlock_bh(&sess->pending_lock);

	/* Send with EAGAIN retry (ring buffer may be full) */
	mutex_lock(&sess->send_mutex);
	{
		int send_retries;

		for (send_retries = 0; send_retries < 100; send_retries++) {
			ret = vmbus_sendpacket(sess->channel, send_buf,
					       send_pkt_len, 0,
					       VM_PKT_DATA_INBAND, 0);
			if (ret != -EAGAIN)
				break;
			usleep_range(100, 500);
		}
	}
	mutex_unlock(&sess->send_mutex);
	kfree(send_buf);

	if (ret) {
		pr_err("vmbus_sendpacket failed: %d\n", ret);
		spin_lock_bh(&sess->pending_lock);
		list_del_init(&req.list);
		spin_unlock_bh(&sess->pending_lock);
		kvfree(recv_buf);
		return ret;
	}

	/*
	 * Adaptive spinning: busy-poll briefly before sleeping.
	 * For fast responses (sequential I/O), the channel callback
	 * completes the request within microseconds.  Spinning avoids
	 * the schedule/wake context switch overhead (~7μs per I/O).
	 */
	{
		ktime_t spin_end = ktime_add_us(ktime_get(), VMSMB_SPIN_USEC);

		while (!completion_done(&req.done)) {
			if (ktime_after(ktime_get(), spin_end))
				break;
			cpu_relax();
		}
	}

	/* Wait for channel_cb to complete this request (immediate if spun) */
	remaining = wait_for_completion_timeout(&req.done,
				msecs_to_jiffies(VMSMB_TIMEOUT_MS));
	if (!remaining) {
		/*
		 * Timeout. Remove from pending list if still there.
		 * The channel_cb might have completed us in a race.
		 */
		spin_lock_bh(&sess->pending_lock);
		if (!list_empty(&req.list))
			list_del_init(&req.list);
		spin_unlock_bh(&sess->pending_lock);

		if (req.status == -EINPROGRESS) {
			pr_err("transact timeout (mid=%llu)\n",
			       req.message_id);
			kvfree(recv_buf);
			return -ETIMEDOUT;
		}
		/* Completed in the race — fall through */
	}

	if (req.status) {
		kvfree(recv_buf);
		return req.status;
	}

	/* Validate StreamHdr */
	if (req.response_len < stream_hdr_size) {
		pr_err("smb2_transact: response too short: %u\n",
		       req.response_len);
		kvfree(recv_buf);
		return -EPROTO;
	}

	sh = (struct smb2_stream_hdr *)recv_buf;
	if (sh->type != SMB2_STREAM_TYPE_SMB2) {
		pr_err("smb2_transact: unexpected stream type: %u\n",
		       sh->type);
		kvfree(recv_buf);
		return -EPROTO;
	}

	/* Copy SMB2 portion to caller's buffer */
	smb2_size = req.response_len - stream_hdr_size;
	if (smb2_size > resp_buf_size)
		smb2_size = resp_buf_size;

	memcpy(smb2_resp, (u8 *)recv_buf + stream_hdr_size, smb2_size);
	*resp_len = smb2_size;

	kvfree(recv_buf);
	return 0;
}

/*
 * VSMB version negotiation (pre-SMB2).
 *
 * Uses the synchronous send_recv_sync path since there is no
 * concurrency at this point (probe is single-threaded).
 */
int vmsmb_negotiate_version(struct vmsmb_session *sess)
{
	struct {
		struct smb2_stream_hdr stream;
		struct vsmb_version_payload ver;
	} __packed req;
	u8 resp_buf[64];
	u32 resp_len;
	const struct vmpipe_hdr *pipe_resp;
	const struct smb2_stream_hdr *stream_resp;
	const struct vsmb_version_payload *ver_resp;
	int ret;

	req.stream.type = SMB2_STREAM_TYPE_VERSION;
	smb2_stream_set_size(&req.stream, sizeof(req.ver));
	req.ver.version = cpu_to_le32(VSMB_VERSION_1);
	req.ver.capabilities = cpu_to_le32(VSMB_CAP_DIRECTMAP);

	ret = vmsmb_send_recv_sync(sess, &req, sizeof(req),
				   resp_buf, sizeof(resp_buf), &resp_len);
	if (ret)
		return ret;

	if (resp_len < sizeof(struct vmpipe_hdr) +
		       sizeof(struct smb2_stream_hdr) +
		       sizeof(struct vsmb_version_payload)) {
		pr_err("version response too short: %u\n", resp_len);
		return -EPROTO;
	}

	pipe_resp = (const struct vmpipe_hdr *)resp_buf;
	stream_resp = (const struct smb2_stream_hdr *)
		      (resp_buf + sizeof(struct vmpipe_hdr));
	ver_resp = (const struct vsmb_version_payload *)
		   (resp_buf + sizeof(struct vmpipe_hdr) +
		    sizeof(struct smb2_stream_hdr));

	if (stream_resp->type != SMB2_STREAM_TYPE_VERSION) {
		pr_err("unexpected response type: %u\n", stream_resp->type);
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
