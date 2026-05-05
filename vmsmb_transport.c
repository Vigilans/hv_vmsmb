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
 * Workqueue handler: runs the per-request async callback in process
 * context. channel_cb schedules this when a response arrives for a
 * request whose async_cb is set.
 *
 * CIFS runs async mid callbacks directly from cifs_demultiplex_thread
 * (fs/smb/client/connect.c), which is already process context. Our
 * channel_cb is a softirq callback, so we bounce through a workqueue
 * before invoking async_cb — async_cb is then free to sleep (copy_to_iter,
 * netfs_read_subreq_terminated, etc.).
 */
static void vmsmb_async_work(struct work_struct *work)
{
	struct vmsmb_request *req = container_of(work, struct vmsmb_request, work);

	req->async_cb(req);
	/* async_cb owns req from here — it must kfree. */
}

/*
 * SMB2 credit accounting — walks the (possibly compound) PDU chain in @buf
 * and sums CreditCharge (request side) or CreditRequest (response side).
 *
 * SMB 2.1 dialect always uses CreditCharge=1 per PDU, so the walk reduces
 * to "PDU count" for charges; we read the field anyway for correctness if
 * a future caller bumps it (e.g. SMB3.x large MTU credit charging).
 *
 * Bound by @len so a malformed chain or truncated response cannot run off
 * the end of the buffer.
 *
 * Models CIFS smb2_check_message() credit accounting
 * (fs/smb/client/smb2misc.c).
 */
static u16 vmsmb_walk_pdu_charges(const void *buf, u32 len)
{
	u32 off = 0;
	u16 total = 0;

	while (off + sizeof(struct smb2_hdr) <= len) {
		const struct smb2_hdr *h = (const struct smb2_hdr *)((const u8 *)buf + off);
		u16 c = le16_to_cpu(h->CreditCharge);
		u32 next = le32_to_cpu(h->NextCommand);

		total += c ? c : 1;	/* MS-SMB2: 0 ≡ 1 for SMB 2.0.2/2.1 */
		if (!next || next < sizeof(struct smb2_hdr))
			break;
		if (off + next > len)
			break;
		off += next;
	}
	return total;
}

static u16 vmsmb_walk_pdu_grants(const void *buf, u32 len)
{
	u32 off = 0;
	u16 total = 0;

	while (off + sizeof(struct smb2_hdr) <= len) {
		const struct smb2_hdr *h = (const struct smb2_hdr *)((const u8 *)buf + off);
		u32 next = le32_to_cpu(h->NextCommand);

		total += le16_to_cpu(h->CreditRequest);
		if (!next || next < sizeof(struct smb2_hdr))
			break;
		if (off + next > len)
			break;
		off += next;
	}
	return total;
}

/*
 * mrxsmb-derived rate-agnostic credit transport.
 *
 * Send admission gate (`vmsmb_reserve_credits`):
 *
 *   bound = max(min(live_window, max_credits), outstanding)
 *   effective_avail = bound - outstanding
 *
 * Throttles purely on outstanding (in-flight CC sum), not on accumulated
 * CR.  Server CR=0 (vmusrv path #3 zero-grant flow control) stops
 * live_window from growing; effective_avail naturally collapses to 0;
 * senders queue on ct_send_wait.  Drains via vmsmb_release_mid which
 * decrements outstanding when the oldest in-flight MID completes.  Net:
 * any server zero-rate is tolerated without drifting next_mid past the
 * server's actual EndMid.
 *
 * Models mrxsmb.sys SmbCe* family
 * (SmbCeReserveCreditsForBufferContexts/SmbCeApplyCreditGrantAndRelease/
 * SmbCeDemuxResponseAndAccumulateCredits/SmbCeGrowCreditMidTable).
 */

/*
 * Reset credit transport state for fresh handshake.
 *
 * Used by NEGOTIATE retry loop in vmsmb_main.c — replaces the previous
 * `atomic64_set(&sess->message_id, 0)` plus implicit pool semantics.
 * Mid_table allocation and ct_max_credits are preserved across reset
 * (only the per-handshake counters are zeroed).
 */
void vmsmb_credit_reset(struct vmsmb_session *sess)
{
	spin_lock_bh(&sess->ct_lock);
	sess->ct_oldest_mid  = 0;
	sess->ct_next_mid    = 0;
	sess->ct_outstanding = 0;
	sess->ct_live_window = VMSMB_INITIAL_CREDITS;
	atomic_set(&sess->ct_pending_grant, 0);
	sess->ct_avg_lat_us  = 0;
	sess->ct_target_window = VMSMB_INITIAL_TARGET_WINDOW;
	if (sess->ct_mid_table)
		memset(sess->ct_mid_table, 0,
		       sess->ct_max_credits * sizeof(*sess->ct_mid_table));
	spin_unlock_bh(&sess->ct_lock);
	wake_up(&sess->ct_send_wait);
}

/*
 * Drain ct_pending_grant atomically into ct_live_window, clamp to
 * [outstanding, max_credits], spill any overflow back to pending_grant.
 * Caller must hold ct_lock.
 *
 * Mirrors mrxsmb.sys SmbCeFoldPendingCreditsIntoWindow @0x1c00260d0.
 */
static void vmsmb_fold_pending_locked(struct vmsmb_session *sess)
{
	u32 pending = atomic_xchg(&sess->ct_pending_grant, 0);

	if (pending == 0)
		return;

	sess->ct_live_window += pending;
	if (sess->ct_live_window < sess->ct_outstanding)
		sess->ct_live_window = sess->ct_outstanding;
	if (sess->ct_live_window > sess->ct_max_credits) {
		u32 overflow = sess->ct_live_window - sess->ct_max_credits;

		sess->ct_live_window = sess->ct_max_credits;
		atomic_add(overflow, &sess->ct_pending_grant);
	}
}

/*
 * Effective-avail predicate.  Caller must hold ct_lock.
 */
/*
 * mrxsmb 18-bucket EWMA target_window adaptation table
 * (DAT_1c0072270 in mrxsmb.sys Win11 26100).
 *
 * Each entry is {op, a, b}:
 *   op=0  -> target = (target * a) / b      (multiplicative)
 *   op=1  -> target = target + a - b        (additive, b is subtracted)
 *
 * Bucket index is computed in vmsmb_ewma_update_locked from the EWMA
 * average response latency (microseconds):
 *
 *   bucket = clamp((2 * avg_us) / 500000, 0, 17)
 *
 * 250000us per bucket step; bucket 0 covers [0..250ms], bucket 17 is
 * the >4.25s saturation slot.  See mrxsmb.md (re-analyst memory) for
 * the recovered table from disasm of
 * SmbCeDemuxResponseAndAccumulateCredits @0x1c00022a0..0x1c00032c7.
 *
 * Net effect:
 *   buckets 0-7 grow target_window aggressively (x4..x5/4)
 *   buckets 8-10 add small constants (+4, +2, +1)
 *   buckets 11-12 subtract (-1, -2)
 *   buckets 13-17 shrink multiplicatively (x7/8..x1/2)
 *
 * After op, target_window is clamped to
 * [VMSMB_INITIAL_TARGET_WINDOW, ct_max_credits].
 */
static const struct {
	u8 op;
	u8 a;
	u8 b;
} vmsmb_target_buckets[18] = {
	{ 0, 4, 1 },	/*  0: x4   */
	{ 0, 4, 1 },	/*  1: x4   */
	{ 0, 3, 1 },	/*  2: x3   */
	{ 0, 2, 1 },	/*  3: x2   */
	{ 0, 2, 1 },	/*  4: x2   */
	{ 0, 7, 4 },	/*  5: x7/4 */
	{ 0, 3, 2 },	/*  6: x3/2 */
	{ 0, 5, 4 },	/*  7: x5/4 */
	{ 1, 4, 0 },	/*  8: +4   */
	{ 1, 2, 0 },	/*  9: +2   */
	{ 1, 1, 0 },	/* 10: +1   */
	{ 1, 0, 1 },	/* 11: -1   */
	{ 1, 0, 2 },	/* 12: -2   */
	{ 0, 7, 8 },	/* 13: x7/8 */
	{ 0, 7, 8 },	/* 14: x7/8 */
	{ 0, 3, 4 },	/* 15: x3/4 */
	{ 0, 1, 2 },	/* 16: x1/2 */
	{ 0, 1, 2 },	/* 17: x1/2 */
};

/*
 * Update EWMA average latency, derive bucket, apply target_window op.
 * Caller must hold ct_lock; @elapsed_us is the just-completed request's
 * response latency in microseconds, @charge is its credit_charge.
 *
 * EWMA formula (mrxsmb SmbCeDemuxResponseAndAccumulateCredits
 *   @0x1c000217c..0x1c00021bc):
 *
 *     avg_new = (elapsed_us + max(outstanding, 8) * avg_old)
 *               / (max(outstanding, 8) + charge)
 *
 * max(outstanding, 8) dampens EWMA changes at low queue depth to avoid
 * single-sample spikes dominating the moving average.
 */
static void vmsmb_ewma_update_locked(struct vmsmb_session *sess,
				     u64 elapsed_us, u16 charge)
{
	u64 weight = max_t(u32, sess->ct_outstanding, 8U);
	u64 numer = elapsed_us + weight * sess->ct_avg_lat_us;
	u64 denom = weight + (u64)charge;
	u32 bucket;
	u32 target;

	if (denom)
		sess->ct_avg_lat_us = numer / denom;

	/* bucket = (2 * avg_us) / 500000, clamped to [0, 17] */
	bucket = (u32)((2 * sess->ct_avg_lat_us) / 500000ULL);
	if (bucket > 17)
		bucket = 17;

	target = sess->ct_target_window;
	if (vmsmb_target_buckets[bucket].op == 0) {
		/* multiplicative: target = (target * a) / b */
		u8 a = vmsmb_target_buckets[bucket].a;
		u8 b = vmsmb_target_buckets[bucket].b;

		if (b)
			target = (u32)(((u64)target * a) / b);
	} else {
		/* additive: target = target + a - b */
		u8 a = vmsmb_target_buckets[bucket].a;
		u8 b = vmsmb_target_buckets[bucket].b;

		if (target + a >= b)
			target = target + a - b;
		else
			target = 0;
	}

	if (target < VMSMB_INITIAL_TARGET_WINDOW)
		target = VMSMB_INITIAL_TARGET_WINDOW;
	if (target > sess->ct_max_credits)
		target = sess->ct_max_credits;

	sess->ct_target_window = target;
}

/*
 * Effective-avail predicate.  Caller must hold ct_lock.
 *
 * bound = max(min(live_window, target_window), outstanding)
 *
 * target_window is the EWMA-adapted upper bound (init 2, grows to
 * max_credits under low latency, shrinks toward 2 under high latency).
 * It dominates over max_credits in the gate, so when the server enters
 * sustained CR=0 flow control and per-request latency rises, the
 * outstanding cap auto-shrinks below ring saturation.
 */
static bool vmsmb_can_reserve_locked(struct vmsmb_session *sess, u16 charge)
{
	u32 bound;

	bound = min(sess->ct_live_window, sess->ct_target_window);
	if (bound < sess->ct_outstanding)
		bound = sess->ct_outstanding;
	if (bound < (u32)charge)
		return false;
	return (bound - sess->ct_outstanding) >= (u32)charge;
}

/*
 * Auto-double mid_table capacity, capped at VMSMB_MAX_CREDITS=8192
 * (server's VSmbMaxCredits ceiling).  Returns -ENOBUFS if already at
 * cap.  Allocates outside ct_lock (GFP_KERNEL OK in process context),
 * then takes ct_lock to rehash + swap.
 *
 * Models mrxsmb.sys SmbCeGrowCreditMidTable @0x1c0048e88.
 */
static int vmsmb_grow_mid_table(struct vmsmb_session *sess)
{
	struct vmsmb_request **new_table;
	struct vmsmb_request **old_table;
	u32 old_max, new_max, i;

	spin_lock_bh(&sess->ct_lock);
	old_max = sess->ct_max_credits;
	spin_unlock_bh(&sess->ct_lock);

	if (old_max >= VMSMB_MAX_CREDITS)
		return -ENOBUFS;

	new_max = old_max * 2;
	if (new_max > VMSMB_MAX_CREDITS)
		new_max = VMSMB_MAX_CREDITS;

	new_table = kvzalloc(new_max * sizeof(*new_table), GFP_KERNEL);
	if (!new_table)
		return -ENOMEM;

	spin_lock_bh(&sess->ct_lock);
	if (sess->ct_max_credits != old_max) {
		/* Lost a race; another grower won.  Drop our allocation. */
		spin_unlock_bh(&sess->ct_lock);
		kvfree(new_table);
		return 0;
	}
	for (i = 0; i < old_max; i++) {
		struct vmsmb_request *r = sess->ct_mid_table[i];

		if (r)
			new_table[r->message_id % new_max] = r;
	}
	old_table = sess->ct_mid_table;
	sess->ct_mid_table = new_table;
	sess->ct_max_credits = new_max;
	spin_unlock_bh(&sess->ct_lock);

	kvfree(old_table);
	pr_info("mid_table grown to %u\n", new_max);
	return 0;
}

/*
 * Reserve credit + assign MID for a (possibly compound) request chain.
 *
 * Walks @buf in-place, writes MessageId into each PDU header, places the
 * request pointer into mid_table[mid % max_credits], advances ct_next_mid
 * by per-PDU CC, increments ct_outstanding by total chain charge.  All
 * three updates happen under ct_lock so MID/outstanding/mid_table are
 * always consistent.
 *
 * If the gate denies (effective_avail < total_charge), the call queues
 * on ct_send_wait until a release_mid wakes us, the timeout fires
 * (returns -EBUSY), or a signal arrives (-EINTR).
 *
 * On success @req->message_id holds the FIRST PDU's MID (used by the
 * demux path to look up @req via mid_table[hdr.MessageId % max_credits]).
 * @req->credit_charge is the TOTAL chain charge (used by release_mid).
 *
 * Models mrxsmb.sys SmbCeReserveCreditsForBufferContexts @0x1c000ba60.
 */
static int vmsmb_reserve_credits(struct vmsmb_session *sess,
				 void *buf, u32 len,
				 struct vmsmb_request *req)
{
	DEFINE_WAIT(wait);
	u16 total_charge = 0;
	u32 off, first_mid_set = 0;
	int ret = 0;

	/* Pre-walk to compute charge so we know what to gate on. */
	total_charge = vmsmb_walk_pdu_charges(buf, len);
	if (total_charge == 0)
		total_charge = 1;

retry:
	/* Grow mid_table proactively if pressure approaches capacity. */
	{
		bool need_grow = false;

		spin_lock_bh(&sess->ct_lock);
		if (sess->ct_max_credits <
		    sess->ct_outstanding + 8 + total_charge)
			need_grow = (sess->ct_max_credits < VMSMB_MAX_CREDITS);
		spin_unlock_bh(&sess->ct_lock);

		if (need_grow) {
			ret = vmsmb_grow_mid_table(sess);
			if (ret == -ENOMEM)
				return ret;
			/* -ENOBUFS at cap is OK — fall through to wait if
			 * the gate denies; outstanding will drain via
			 * release_mid. */
		}
	}

	spin_lock_bh(&sess->ct_lock);
	vmsmb_fold_pending_locked(sess);

	if (!vmsmb_can_reserve_locked(sess, total_charge)) {
		long remaining;

		prepare_to_wait(&sess->ct_send_wait, &wait,
				TASK_INTERRUPTIBLE);
		spin_unlock_bh(&sess->ct_lock);

		if (signal_pending(current)) {
			finish_wait(&sess->ct_send_wait, &wait);
			return -EINTR;
		}
		remaining = schedule_timeout(
			msecs_to_jiffies(VMSMB_SEND_TIMEOUT_MS));
		finish_wait(&sess->ct_send_wait, &wait);

		if (remaining == 0) {
			pr_warn("reserve timeout: charge=%u outstanding=%u live=%u\n",
				total_charge,
				sess->ct_outstanding,
				sess->ct_live_window);
			return -EBUSY;
		}
		goto retry;
	}

	/*
	 * Walk the chain: per-PDU patch in MID, register in mid_table,
	 * advance ct_next_mid by CC.  All inside ct_lock — atomic with
	 * outstanding update below.
	 */
	off = 0;
	while (off + sizeof(struct smb2_hdr) <= len) {
		struct smb2_hdr *h = (struct smb2_hdr *)((u8 *)buf + off);
		u16 cc = le16_to_cpu(h->CreditCharge);
		u32 next = le32_to_cpu(h->NextCommand);

		if (!cc)
			cc = 1;

		h->MessageId = cpu_to_le64(sess->ct_next_mid);
		sess->ct_mid_table[sess->ct_next_mid %
				   sess->ct_max_credits] = req;
		if (!first_mid_set) {
			req->message_id = sess->ct_next_mid;
			first_mid_set = 1;
		}
		sess->ct_next_mid += cc;

		if (!next || next < sizeof(struct smb2_hdr))
			break;
		if (off + next > len)
			break;
		off += next;
	}

	req->credit_charge = total_charge;
	req->send_tick = ktime_get();
	sess->ct_outstanding += total_charge;
	spin_unlock_bh(&sess->ct_lock);
	return 0;
}

/*
 * Lockless receive-side grant accumulation.  Called from channel_cb
 * (softirq).  The fold into live_window + waiter wake happens later in
 * the next reserve / release_mid path; here we just bump pending_grant
 * and kick the waitqueue.
 *
 * Models mrxsmb.sys SmbCeDemuxResponseAndAccumulateCredits @0x1c000203c
 * (without the EWMA latency feedback — deferred to v2).
 */
static void vmsmb_accumulate_grant(struct vmsmb_session *sess, u16 grant)
{
	if (grant == 0)
		return;
	atomic_add(grant, &sess->ct_pending_grant);
	wake_up(&sess->ct_send_wait);
}

/*
 * Release a completed request: clear ALL mid_table slots written at
 * reserve time (one per PDU; chain wrote charge slots covering MIDs
 * [first..first+charge-1]), then if our first MID is at oldest_mid,
 * sweep oldest forward over consecutive NULLs and decrement outstanding.
 *
 * NOTE: clearing ALL slots (not just the first) is critical — for
 * compound chains (CC=1 per PDU but charge=N for an N-PDU chain) the
 * non-first slots also point at @req.  Leaving them with a stale
 * pointer to a stack-allocated request struct causes use-after-free
 * during the next vmsmb_grow_mid_table rehash (vmsmb_submit panic at
 * `mov rax, [rdi]` reading req->message_id from freed stack).
 *
 * Same shape as vmsmb_unreserve, kept as a separate function because
 * release_mid additionally advances oldest_mid + drains pending_grant.
 *
 * Models mrxsmb.sys SmbCeApplyCreditGrantAndRelease @0x1c000bf10.
 */
static void vmsmb_release_mid(struct vmsmb_session *sess,
			      struct vmsmb_request *req)
{
	u64 mid;
	u32 i, freed;

	spin_lock(&sess->ct_lock);

	/* Clear all slots this chain claimed at reserve time. */
	for (i = 0; i < req->credit_charge; i++) {
		mid = req->message_id + i;
		if (sess->ct_mid_table[mid % sess->ct_max_credits] == req)
			sess->ct_mid_table[mid % sess->ct_max_credits] = NULL;
	}

	if (req->message_id == sess->ct_oldest_mid) {
		mid = req->message_id + req->credit_charge;
		freed = req->credit_charge;
		while (mid < sess->ct_next_mid &&
		       sess->ct_mid_table[mid % sess->ct_max_credits] == NULL) {
			mid++;
			freed++;
		}
		sess->ct_oldest_mid = mid;
		if (sess->ct_outstanding >= freed)
			sess->ct_outstanding -= freed;
		else
			sess->ct_outstanding = 0;
	}

	/*
	 * EWMA latency feedback -> target_window adaptation.
	 *
	 * mrxsmb runs this on every demux response, before the credit
	 * release.  Computing it here (post-clear, pre-fold) keeps the
	 * formula's `outstanding` matching the post-release value used in
	 * the original (mrxsmb subtracts before EWMA at +0x1c000217c).
	 */
	{
		s64 elapsed_ns = ktime_to_ns(ktime_sub(ktime_get(),
						       req->send_tick));
		u64 elapsed_us = elapsed_ns > 0 ? (u64)elapsed_ns / 1000 : 0;

		vmsmb_ewma_update_locked(sess, elapsed_us, req->credit_charge);
	}

	vmsmb_fold_pending_locked(sess);
	spin_unlock(&sess->ct_lock);

	wake_up(&sess->ct_send_wait);
}

/*
 * Rollback for local send-failure (vmbus_sendpacket -EAGAIN exhausted /
 * post-reserve OOM) and sync-transact timeout.  Atomically claims
 * ownership of @req via the same -EINPROGRESS → sentinel transition
 * that channel_cb uses, then clears all chain slots and decrements
 * outstanding.  If channel_cb already claimed the request (status was
 * something other than -EINPROGRESS at lock entry), we exit without
 * touching anything — channel_cb's complete_req path will run
 * release_mid normally.
 *
 * Returns true if we successfully unreserved (caller may treat the
 * request as failed); false if a response was concurrently received
 * (caller should fall through and consume the response).
 */
static bool vmsmb_unreserve(struct vmsmb_session *sess,
			    struct vmsmb_request *req)
{
	u64 mid;
	u32 i;
	bool claimed;

	spin_lock_bh(&sess->ct_lock);

	claimed = (req->status == -EINPROGRESS);
	if (!claimed) {
		spin_unlock_bh(&sess->ct_lock);
		return false;
	}
	req->status = -ETIMEDOUT;	/* mark unreserve-side claim */

	/* Clear all slots this chain wrote (one per PDU; v1 CC=1). */
	for (i = 0; i < req->credit_charge; i++) {
		mid = req->message_id + i;
		if (sess->ct_mid_table[mid % sess->ct_max_credits] == req)
			sess->ct_mid_table[mid % sess->ct_max_credits] = NULL;
	}

	if (sess->ct_outstanding >= req->credit_charge)
		sess->ct_outstanding -= req->credit_charge;
	else
		sess->ct_outstanding = 0;

	/* Advance oldest_mid past now-empty leading slots. */
	while (sess->ct_oldest_mid < sess->ct_next_mid &&
	       sess->ct_mid_table[sess->ct_oldest_mid %
				  sess->ct_max_credits] == NULL)
		sess->ct_oldest_mid++;

	spin_unlock_bh(&sess->ct_lock);
	wake_up(&sess->ct_send_wait);
	return true;
}

/*
 * Called from channel_cb (softirq) when a response for @req is complete.
 * Routes to either the sync completion (wakes wait_for_completion_timeout)
 * or the async workqueue (runs async_cb in process context).
 *
 * Before signaling, walks the response PDU chain and adds the granted
 * credits back to the session pool, waking any blocked senders.  This is
 * the protocol-correct mirror of vmsmb_acquire_credits() on send.
 *
 * Simplified from CIFS handle_mid() dispatch (fs/smb/client/connect.c):
 * CIFS invokes a uniform mid->callback(mid) — sync mids register
 * cifs_wake_up_task, async mids register the business callback. We collapse
 * that to a boolean (async_cb set / unset) since the sync path here always
 * wakes via struct completion.
 */
static inline void vmsmb_complete_req(struct vmsmb_request *req)
{
	const u32 stream_hdr_size = sizeof(struct smb2_stream_hdr);

	req->response_len = req->recv_offset;
	req->status = 0;

	if (req->response_len > stream_hdr_size) {
		const void *smb2 = (const u8 *)req->response_buf + stream_hdr_size;
		u32 smb2_len = req->response_len - stream_hdr_size;

		vmsmb_accumulate_grant(req->sess,
				       vmsmb_walk_pdu_grants(smb2, smb2_len));
	}

	/* Release mid_table slot + sweep oldest_mid forward + decrement
	 * outstanding.  Must run before completing the waiter so a sender
	 * woken by ct_send_wait sees the updated state. */
	vmsmb_release_mid(req->sess, req);

	if (req->async_cb) {
		INIT_WORK(&req->work, vmsmb_async_work);
		schedule_work(&req->work);
	} else {
		complete(&req->done);
	}
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
 *
 * Demux: mid_table[mid % max_credits] is O(1).  CIFS uses a hashed list
 * walk (cifs_demultiplex_thread → __smb2_find_mid); we collapse to a
 * direct array index because we control MID allocation density.
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

			/* Find matching pending request via mid_table O(1).
			 * Softirq context — plain spin_lock pairs with
			 * spin_lock_bh on sender side.
			 *
			 * Atomic claim transition: only proceed if status was
			 * -EINPROGRESS, and flip it to -EOWNERDEAD (sentinel)
			 * under ct_lock so that a concurrent timeout in the
			 * sender path sees the claim taken and exits without
			 * touching @req.  Without this, transact timeout's
			 * unreserve would clear the slot + decrement
			 * outstanding while channel_cb still holds @req,
			 * dereferencing freed stack memory after the sender
			 * returns -ETIMEDOUT (use-after-free, panic in
			 * subsequent grow_mid_table rehash). */
			spin_lock(&sess->ct_lock);
			if (sess->ct_max_credits)
				req = sess->ct_mid_table[mid %
							 sess->ct_max_credits];
			else
				req = NULL;
			if (req && (req->message_id != mid ||
				    req->status != -EINPROGRESS))
				req = NULL;	/* stale slot or already claimed */
			if (req)
				req->status = -EOWNERDEAD;	/* claim sentinel */
			spin_unlock(&sess->ct_lock);

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
				vmsmb_complete_req(req);
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
				vmsmb_complete_req(req);
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
 * Each VMBus ring entry has an 8-byte trailer after the packet data.
 * __hv_pkt_iter_next accounts for this when advancing the read index.
 * The trailer is reserved space (typically contains a u64 = 0) that
 * must be skipped.  Defined in drivers/hv/ring_buffer.c (not exported).
 */
#define VMBUS_PKT_TRAILER	8

/*
 * Bytes available in the inbound ring from priv_read_index onward.
 * Equivalent to hv_pkt_iter_avail() (static in ring_buffer.c).
 * Uses virt_load_acquire on write_index to match the host's
 * store_release ordering.
 */
static inline u32 vmsmb_ring_avail(const struct hv_ring_buffer_info *rbi)
{
	u32 pri = rbi->priv_read_index;
	u32 wi = virt_load_acquire(&rbi->ring_buffer->write_index);

	return wi >= pri ? (wi - pri) : (rbi->ring_datasize - pri + wi);
}

/*
 * VMBus channel callback — parse and dispatch responses.
 *
 * Reads directly from the double-mapped ring buffer, bypassing the
 * hv_pkt_iter bounce copy (channel->pkt_buffer).  The ring is vmap'd
 * twice so virtual addresses are contiguous even at the physical wrap
 * point — no special handling needed.
 *
 * This saves one full-packet memcpy per VMBus entry.  For 512K READ
 * responses at 8K ops/s that's ~4 GB/s of memcpy eliminated.
 *
 * Trade-off: we bypass the TOCTOU protection that hv_pkt_iter_first
 * provides (the bounce snapshot prevents a malicious host from mutating
 * packet metadata after we validate it).  For VSMB the host is our own
 * hypervisor, so this is acceptable.
 *
 * Kernel API compatibility:
 *   - hv_ring_buffer_info.{priv_read_index, ring_datasize, ring_buffer},
 *     hv_get_ring_buffer(), hv_pkt_iter_close(), struct vmpacket_descriptor
 *     are all in <linux/hyperv.h> (stable since hv_pkt_iter introduction,
 *     kernel 4.14+). These are also used by the foreach_vmbus_pkt path,
 *     so no additional struct-layout risk vs the standard API.
 *   - VMBUS_PKT_TRAILER (8) is defined in drivers/hv/ring_buffer.c, not
 *     exported. Value unchanged since introduction. If it changes, our
 *     priv_read_index advance will silently misalign.
 *   - Ring double-mapping (vmap of 2N-1 pages) is an implementation
 *     detail of hv_ringbuffer_init, not an API guarantee. Added in
 *     commit 95096f2 (2020). If removed, reads spanning the ring wrap
 *     point would return garbage.
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
	if (READ_ONCE(sess->ct_outstanding) || sess->current_recv) {
		struct hv_ring_buffer_info *rbi = &sess->channel->inbound;
		u8 *ring = hv_get_ring_buffer(rbi);
		bool processed_any = false;

		while (vmsmb_ring_avail(rbi) >=
		       sizeof(struct vmpacket_descriptor) + VMBUS_PKT_TRAILER) {
			const struct vmpacket_descriptor *desc;
			const struct vmpipe_hdr *ph;
			u32 pkt_len, pkt_payload_len, ptype, dsize;
			const u8 *data;

			desc = (const struct vmpacket_descriptor *)
				(ring + rbi->priv_read_index);
			pkt_len = READ_ONCE(desc->len8) << 3;

			if (pkt_len < sizeof(*desc) ||
			    pkt_len + VMBUS_PKT_TRAILER > vmsmb_ring_avail(rbi))
				break;

			pkt_payload_len = pkt_len - (READ_ONCE(desc->offset8) << 3);
			if (pkt_payload_len < sizeof(struct vmpipe_hdr))
				goto advance;

			ph = (const struct vmpipe_hdr *)
				((const u8 *)desc + (desc->offset8 << 3));
			ptype = le32_to_cpu(ph->pkt_type);
			dsize = le32_to_cpu(ph->data_size);

			if (ptype == 0)
				goto advance;

			if (ptype != VMPIPE_TYPE_DATA || dsize == 0)
				goto advance;

			if (sizeof(struct vmpipe_hdr) + dsize > pkt_payload_len)
				dsize = pkt_payload_len -
					sizeof(struct vmpipe_hdr);

			data = (const u8 *)ph + sizeof(struct vmpipe_hdr);
			vmsmb_process_data(sess, data, dsize);

advance:
			rbi->priv_read_index += pkt_len + VMBUS_PKT_TRAILER;
			if (rbi->priv_read_index >= rbi->ring_datasize)
				rbi->priv_read_index -= rbi->ring_datasize;
			processed_any = true;
		}

		if (processed_any)
			hv_pkt_iter_close(sess->channel);
	}

	/* Signal synchronous waiters (version negotiation, drain) */
	complete(&sess->recv_done);

	/*
	 * Outbound drain wake.  Same callback fires for both inbound packet
	 * arrival and outbound-ring drain (host signals when out_full_flag
	 * was set and freed bytes >= pending_send_sz).  Mirrors hvsock's
	 * hvs_channel_cb at net/vmw_vsock/hyperv_transport.c:247-260.
	 *
	 * wake_up_all is safe in tasklet context (uses the wait_queue's
	 * IRQ-safe spinlock).  Senders blocked in vmsmb_submit's drain
	 * wait re-take send_mutex and retry vmbus_sendpacket; thundering
	 * herd is bounded by mutex contention + wait_queue FIFO.
	 */
	if (sess->channel &&
	    hv_get_bytes_to_write(&sess->channel->outbound) > 0)
		wake_up_all(&sess->send_drain_wait);
}

/*
 * Open the VMBus channel and prime session state.
 *
 * Analogous to hvsock hvs_open_connection() (net/vmw_vsock/hyperv_transport.c):
 * sets channel->max_pkt_size before vmbus_open so hv_ringbuffer_init allocates
 * a pkt_buffer that fits the largest expected response, then calls vmbus_open
 * with our channel callback. The force-reset of ch->state exists because
 * vmbus_close leaves the channel in a non-OPEN state that blocks reopening —
 * module reload path only (see docs/vmbus-pipe-protocol.md).
 */
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
	init_waitqueue_head(&sess->send_drain_wait);

	spin_lock_init(&sess->ct_lock);
	init_waitqueue_head(&sess->ct_send_wait);
	sess->ct_oldest_mid  = 0;
	sess->ct_next_mid    = 0;
	sess->ct_outstanding = 0;
	sess->ct_live_window = VMSMB_INITIAL_CREDITS;
	atomic_set(&sess->ct_pending_grant, 0);
	sess->ct_avg_lat_us  = 0;
	sess->ct_target_window = VMSMB_INITIAL_TARGET_WINDOW;
	sess->ct_max_credits = VMSMB_INITIAL_MAX_CREDITS;
	sess->ct_mid_table = kvzalloc(
		sess->ct_max_credits * sizeof(*sess->ct_mid_table),
		GFP_KERNEL);
	if (!sess->ct_mid_table) {
		pr_err("mid_table alloc failed (size=%u)\n",
		       sess->ct_max_credits);
		return -ENOMEM;
	}

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

	/*
	 * Arm the outbound-ring drain watermark.  Once set, the host signals
	 * us via the same channel interrupt whenever out_full_flag was true
	 * and free bytes >= VMSMB_DRAIN_WATERMARK.  vmsmb_channel_cb wakes
	 * send_drain_wait on every interrupt where outbound has space —
	 * the watermark just makes the host actually fire the interrupt
	 * after EAGAIN backpressure (otherwise drain progress is silent).
	 *
	 * virt_mb() ensures the host sees the watermark before any
	 * subsequent send (mirrors hvs_set_channel_pending_send_size at
	 * net/vmw_vsock/hyperv_transport.c:177-182).
	 */
	set_channel_pending_send_size(ch, VMSMB_DRAIN_WATERMARK);
	virt_mb();

	pr_info("channel opened (ring=%d, drain_wm=%lu)\n",
		VMSMB_RING_SIZE, (unsigned long)VMSMB_DRAIN_WATERMARK);
	return 0;
}

void vmsmb_close_channel(struct vmsmb_session *sess)
{
	if (sess->channel) {
		/*
		 * Wake any senders blocked on the drain wait so they can
		 * observe the channel teardown and exit (their next
		 * vmbus_sendpacket will see -ENODEV / similar).
		 */
		wake_up_all(&sess->send_drain_wait);
		wake_up_all(&sess->ct_send_wait);

		vmbus_close(sess->channel);
		sess->channel = NULL;
		pr_info("channel closed\n");
	}
	if (sess->ct_mid_table) {
		kvfree(sess->ct_mid_table);
		sess->ct_mid_table = NULL;
		sess->ct_max_credits = 0;
	}
}

/*
 * Synchronous send + receive for pre-SMB2 paths (version negotiation).
 *
 * VSMB-specific: the pre-SMB2 version exchange has no MessageId to dispatch
 * on, so we cannot reuse the mid-matching path used for SMB2 traffic. This
 * one-shot helper exists only until we transition into SMB2 framing; after
 * that point all traffic goes through vmsmb_submit() / vmsmb_smb2_transact().
 * No direct upstream analog — CIFS has no pre-SMB2 framing stage.
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

	/*
	 * Pre-SMB2 single-shot send.  Same drain-wait pattern as vmsmb_submit
	 * (no MID involved here, so no Mode A risk, but we use the same
	 * machinery for consistency and to avoid the legacy 100x usleep
	 * busy-retry).
	 */
	for (;;) {
		ret = vmbus_sendpacket(sess->channel, pkt, pkt_len,
				       0, VM_PKT_DATA_INBAND, 0);
		if (ret != -EAGAIN)
			break;
		set_channel_pending_send_size(sess->channel,
					      VMSMB_DRAIN_WATERMARK);
		virt_mb();
		ret = wait_event_interruptible_timeout(
			sess->send_drain_wait,
			hv_get_bytes_to_write(&sess->channel->outbound) >=
				pkt_len,
			msecs_to_jiffies(VMSMB_DRAIN_WAIT_MS));
		if (ret == -ERESTARTSYS)
			break;
		ret = -EAGAIN; /* loop and try again */
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
 * Send an SMB2 PDU (or compound chain) over VMBus.
 *
 * Builds the on-wire frame [VMpipeHdr][StreamHdr][SMB2 PDU(s)] in
 * @send_buf, then calls vmsmb_reserve_credits to atomically allocate
 * MID(s) + register @req in mid_table + bump outstanding under ct_lock,
 * patching MIDs into the SMB2 chain in-place.  Then transmits via
 * vmbus_sendpacket (serialized by send_mutex).
 *
 * Backpressure model — admission gate B2 (post-MID, on send_drain_wait):
 *
 *   try send -> EAGAIN -> sleep on send_drain_wait -> wake on host drain
 *               signal -> retry -> ...
 *
 * Replaces the legacy 100x usleep retry that, on exhaustion, called
 * vmsmb_unreserve to release the MID locally — that abandonment was the
 * Mode A wedge trigger (server's MID window stays pinned at the abandoned
 * MID, client.next_mid drifts to StartMid + MaxWindows, server begins
 * c00000d0 cascade).  Now we keep waiting until the host drains the ring;
 * the MID is never released without a wire commit.
 *
 * Sleep is interruptible (caller may signal-out) and bounded by
 * VMSMB_DRAIN_WAIT_MS per cycle.  Fatal vmbus_sendpacket failures
 * (non-EAGAIN errors, channel rescind) still call vmsmb_unreserve —
 * that path is treated as channel-fatal at the upper layers.
 *
 * Analogous to hvsock's check-then-send + drain-callback wake
 * (net/vmw_vsock/hyperv_transport.c hvs_channel_cb).
 *
 * Lifetime: @req must remain valid until the completion fires.  For sync
 * callers it's on the stack; async callers allocate it and hand
 * ownership to async_cb.
 */
static int vmsmb_submit(struct vmsmb_session *sess,
			const void *smb2_req, u32 req_len,
			struct vmsmb_request *req)
{
	const u32 stream_hdr_size = sizeof(struct smb2_stream_hdr);
	struct smb2_stream_hdr *sh;
	struct vmpipe_hdr *pipe;
	void *chain;
	u8 *send_buf;
	u32 send_pkt_len;
	int ret;

	if (req_len < sizeof(struct smb2_hdr))
		return -EINVAL;
	req->sess = sess;

	send_pkt_len = sizeof(struct vmpipe_hdr) + stream_hdr_size + req_len;
	send_buf = kvmalloc(send_pkt_len, GFP_KERNEL);
	if (!send_buf)
		return -ENOMEM;

	pipe = (struct vmpipe_hdr *)send_buf;
	pipe->pkt_type = cpu_to_le32(VMPIPE_TYPE_DATA);
	pipe->data_size = cpu_to_le32(stream_hdr_size + req_len);

	sh = (struct smb2_stream_hdr *)(send_buf + sizeof(struct vmpipe_hdr));
	sh->type = SMB2_STREAM_TYPE_SMB2;
	smb2_stream_set_size(sh, req_len);

	chain = send_buf + sizeof(struct vmpipe_hdr) + stream_hdr_size;
	memcpy(chain, smb2_req, req_len);

	/*
	 * Reserve credits + assign MIDs into the chain (in-place).  Returns
	 * -EBUSY on credit-side timeout, -EINTR on signal, 0 on success.
	 * Server's MID window dictates how many requests it will accept;
	 * the outstanding-based gate mirrors that without trusting
	 * cumulative grants.
	 */
	ret = vmsmb_reserve_credits(sess, chain, req_len, req);
	if (ret) {
		kvfree(send_buf);
		return ret;
	}

	/*
	 * Send loop with event-driven drain wake (no usleep busy-retry).
	 *
	 * vmbus_sendpacket may return -EAGAIN if the outbound ring is full.
	 * In that case the host has set out_full_flag (we armed the
	 * pending_send_size watermark in vmsmb_open_channel), so when the
	 * host drains the ring it will signal our channel callback, which
	 * wakes send_drain_wait.
	 *
	 * We use TASK_INTERRUPTIBLE so SIGKILL etc can break the wait, but
	 * once we're committed (MID assigned) we MUST eventually get the PDU
	 * onto the wire — abandoning leaks server-side MID-window state.
	 * On signal we still attempt one final non-blocking send, and if
	 * even that fails we fall through to the hard-error unreserve path
	 * (rare; same liability as today's hard-error path).
	 */
	for (;;) {
		mutex_lock(&sess->send_mutex);
		ret = vmbus_sendpacket(sess->channel, send_buf, send_pkt_len,
				       0, VM_PKT_DATA_INBAND, 0);
		mutex_unlock(&sess->send_mutex);
		if (ret != -EAGAIN)
			break;

		/*
		 * Ring saturated.  Re-arm the watermark defensively (host
		 * may have cleared out_full_flag spuriously) and sleep until
		 * the host signals drain progress, the wait times out, or
		 * a signal arrives.  Each wake re-checks the gate by
		 * looping back to vmbus_sendpacket.
		 */
		set_channel_pending_send_size(sess->channel,
					      VMSMB_DRAIN_WATERMARK);
		virt_mb();

		ret = wait_event_interruptible_timeout(
			sess->send_drain_wait,
			hv_get_bytes_to_write(&sess->channel->outbound) >=
				send_pkt_len,
			msecs_to_jiffies(VMSMB_DRAIN_WAIT_MS));

		if (ret == -ERESTARTSYS) {
			/*
			 * Caller signaled.  Try one final non-blocking send
			 * to honor the MID-lifetime invariant; if it still
			 * fails we'll fall through to vmsmb_unreserve below.
			 */
			pr_warn_ratelimited("submit: drain wait interrupted by signal, last-ditch send\n");
			mutex_lock(&sess->send_mutex);
			ret = vmbus_sendpacket(sess->channel, send_buf,
					       send_pkt_len,
					       0, VM_PKT_DATA_INBAND, 0);
			mutex_unlock(&sess->send_mutex);
			break;
		}
		/*
		 * ret == 0 (timeout, no progress) -> retry; the ring may
		 * have drained between our last vmbus_sendpacket and now.
		 * ret > 0 (woken up + condition true) -> retry, should
		 * succeed.
		 */
	}

	kvfree(send_buf);

	if (ret) {
		pr_err("vmbus_sendpacket failed: %d\n", ret);
		vmsmb_unreserve(sess, req);
	}
	return ret;
}

/*
 * Async SMB2 submit — allocates request + response buffer, transmits, and
 * returns immediately. On completion, channel_cb schedules a workqueue
 * that calls async_cb(req) in process context. async_cb owns the request
 * and response buffers from that point and must kfree them.
 *
 * On failure (send error / OOM) nothing is scheduled and the caller sees
 * the error synchronously; @req_out is not populated.
 *
 * Model: CIFS cifs_call_async() (fs/smb/client/transport.c).
 */
int vmsmb_smb2_submit_async(struct vmsmb_session *sess,
			    const void *smb2_req, u32 req_len,
			    u32 resp_buf_size,
			    void (*async_cb)(struct vmsmb_request *),
			    void *async_priv,
			    struct vmsmb_request **req_out)
{
	const u32 stream_hdr_size = sizeof(struct smb2_stream_hdr);
	struct vmsmb_request *req;
	int ret;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->response_buf_size = stream_hdr_size + resp_buf_size;
	req->response_buf = kvmalloc(req->response_buf_size, GFP_KERNEL);
	if (!req->response_buf) {
		kfree(req);
		return -ENOMEM;
	}
	init_completion(&req->done);
	req->status = -EINPROGRESS;
	req->sess = sess;
	req->async_cb = async_cb;
	req->async_priv = async_priv;

	ret = vmsmb_submit(sess, smb2_req, req_len, req);
	if (ret) {
		kvfree(req->response_buf);
		kfree(req);
		return ret;
	}

	if (req_out)
		*req_out = req;
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
 * Analogous to CIFS compound_send_recv() (fs/smb/client/transport.c)
 * for the single-PDU case: build request, queue mid, send, wait on
 * per-request completion, extract response. We do not support multi-PDU
 * rqst arrays at this layer — the SMB2 layer builds compound PDUs into
 * one flat buffer before calling this.
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
	struct vmsmb_request req = {};
	struct smb2_stream_hdr *sh;
	void *recv_buf;
	u32 recv_buf_size;
	u32 smb2_size;
	unsigned long remaining;
	int ret;

	/*
	 * Allocate response buffer with room for StreamHdr.
	 * channel_cb writes StreamHdr + SMB2 data here directly.
	 */
	recv_buf_size = stream_hdr_size + resp_buf_size;
	recv_buf = kvmalloc(recv_buf_size, GFP_KERNEL);
	if (!recv_buf)
		return -ENOMEM;

	init_completion(&req.done);
	req.status = -EINPROGRESS;
	req.response_buf = recv_buf;
	req.response_buf_size = recv_buf_size;

	ret = vmsmb_submit(sess, smb2_req, req_len, &req);
	if (ret) {
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
		 * Timeout.  Race-safe via vmsmb_unreserve's atomic claim:
		 * if channel_cb already took ownership (status != -EINPROGRESS
		 * at lock entry), unreserve returns false and we fall through
		 * to wait again briefly for the in-flight completion.  If we
		 * win the claim, slots are cleared + outstanding decremented
		 * inside ct_lock.
		 *
		 * We do NOT refund grants — server may still respond later,
		 * and incoming CR will accrue via accumulate_grant + fold.
		 * Treating the channel as wedged (refund-on-timeout) was the
		 * 253898b mistake amplifying Mode C.
		 */
		if (vmsmb_unreserve(sess, &req)) {
			pr_err("transact timeout (mid=%llu)\n",
			       req.message_id);
			kvfree(recv_buf);
			return -ETIMEDOUT;
		}
		/* channel_cb claimed first; complete is imminent.  Wait
		 * briefly for it to land.  This is purely race recovery —
		 * status has been set to -EOWNERDEAD inside ct_lock, the
		 * channel_cb is past the lock and will finish soon. */
		wait_for_completion_timeout(&req.done,
					    msecs_to_jiffies(100));
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
 * VSMB-specific handshake with no CIFS/SMB2 analog — the protocol exchanges
 * {version, capabilities} over DirectTCP-style framing before any SMB2
 * traffic. Wire format and semantics reverse-engineered from vmwp.exe /
 * mrxsmb.sys; see docs/vmbus-pipe-protocol.md. Uses the synchronous
 * send_recv_sync path since there is no concurrency at this point (probe
 * is single-threaded).
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
