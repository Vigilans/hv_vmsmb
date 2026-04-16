// SPDX-License-Identifier: GPL-2.0
/*
 * vmsmb_smb2.c - SMB2 command construction for VSMB
 *
 * Uses struct definitions from smb2pdu.h (copied from kernel fs/smb/common/).
 */

#define pr_fmt(fmt) "hv_vmsmb: " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/nls.h>
#include "vmsmb.h"
#include "smb2pdu.h"
#include "smb2status.h"
#include "fscc.h"

/*
 * Fill a common SMB2 header.
 */
static void vmsmb_fill_hdr(struct smb2_hdr *hdr, u16 command,
			    struct vmsmb_session *sess)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->ProtocolId = SMB2_PROTO_NUMBER;
	hdr->StructureSize = cpu_to_le16(64);
	hdr->Command = cpu_to_le16(command);
	hdr->CreditCharge = cpu_to_le16(1);
	hdr->CreditRequest = cpu_to_le16(64); /* request plenty of credits */
	hdr->MessageId = cpu_to_le64(sess->message_id++);
	hdr->Id.SyncId.TreeId = cpu_to_le32(sess->tree_id);
	hdr->SessionId = cpu_to_le64(sess->session_id);
}

/*
 * Wrap an SMB2 PDU in Direct TCP framing and send/recv.
 */
static int vmsmb_smb2_send_recv(struct vmsmb_session *sess,
				void *pdu, u32 pdu_len,
				void *resp, u32 resp_size,
				u32 *resp_len)
{
	struct smb2_direct_tcp_hdr *tcp;
	u8 *buf;
	u32 buf_len;
	int ret;

	/* Direct TCP header (4 bytes) + SMB2 PDU */
	buf_len = sizeof(struct smb2_direct_tcp_hdr) + pdu_len;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	tcp = (struct smb2_direct_tcp_hdr *)buf;
	tcp->type = SMB2_DIRECT_TYPE_SMB2;
	smb2_direct_tcp_set_size(tcp, pdu_len);
	memcpy(buf + sizeof(*tcp), pdu, pdu_len);

	ret = vmsmb_send_recv(sess, buf, buf_len, resp, resp_size, resp_len);
	kfree(buf);
	return ret;
}

/*
 * Parse an SMB2 response from the raw recv buffer.
 * The recv buffer contains: PipeHeader(8) + DirectTCP(4) + SMB2 PDU
 * Returns pointer to the SMB2 header and sets *smb2_len.
 */
static const struct smb2_hdr *vmsmb_parse_response(const void *recv_buf,
						    u32 recv_len,
						    u32 *smb2_len)
{
	const struct smb2_direct_tcp_hdr *tcp;
	const struct smb2_hdr *hdr;
	u32 offset;

	offset = sizeof(struct vmpipe_hdr) + sizeof(struct smb2_direct_tcp_hdr);
	if (recv_len < offset + sizeof(struct smb2_hdr)) {
		pr_err("response too short: %u bytes [%*ph]\n",
		       recv_len, min_t(u32, recv_len, 32), recv_buf);
		return NULL;
	}

	tcp = recv_buf + sizeof(struct vmpipe_hdr);

	if (tcp->type != SMB2_DIRECT_TYPE_SMB2) {
		pr_err("unexpected direct tcp type: %u\n", tcp->type);
		return NULL;
	}

	hdr = recv_buf + offset;
	if (hdr->ProtocolId != SMB2_PROTO_NUMBER) {
		pr_err("bad SMB2 protocol id: 0x%08x (recv_len=%u, offset=%u, first32=[%*ph])\n",
		       le32_to_cpu(hdr->ProtocolId), recv_len, offset,
		       min_t(u32, recv_len, 32), recv_buf);
		return NULL;
	}

	*smb2_len = recv_len - offset;
	return hdr;
}

/*
 * Map SMB2/NTSTATUS error to errno.
 */
static int vmsmb_status_to_errno(u32 status)
{
	switch (status) {
	case 0:
		return 0;
	case 0xC0000034: /* STATUS_OBJECT_NAME_NOT_FOUND */
	case 0xC000003A: /* STATUS_OBJECT_PATH_NOT_FOUND */
		return -ENOENT;
	case 0xC0000022: /* STATUS_ACCESS_DENIED */
		return -EACCES;
	case 0xC00000BA: /* STATUS_FILE_IS_A_DIRECTORY */
		return -EISDIR;
	case 0xC00000D5: /* STATUS_NOT_A_DIRECTORY */
		return -ENOTDIR;
	case 0xC0000035: /* STATUS_OBJECT_NAME_COLLISION */
		return -EEXIST;
	case 0xC0000101: /* STATUS_DIRECTORY_NOT_EMPTY */
		return -ENOTEMPTY;
	case 0xC0000043: /* STATUS_SHARING_VIOLATION */
		return -EBUSY;
	case 0x80000006: /* STATUS_NO_MORE_FILES */
		return -ENODATA;
	default:
		return -EIO;
	}
}

/*
 * Check SMB2 response status.
 */
static int vmsmb_check_status(const struct smb2_hdr *hdr, const char *cmd_name)
{
	u32 status = le32_to_cpu(hdr->Status);

	if (status != 0) {
		int err = vmsmb_status_to_errno(status);

		if (err != -ENOENT && err != -ENODATA)
			pr_err("%s failed: NTSTATUS 0x%08x\n", cmd_name, status);
		return err;
	}
	return 0;
}

/*
 * SMB2 NEGOTIATE — single dialect 0x210 (SMB 2.1).
 */
int vmsmb_smb2_negotiate(struct vmsmb_session *sess)
{
	struct {
		struct smb2_negotiate_req req;
		__le16 dialect;
	} __packed pdu;
	u8 *resp_buf;
	u32 resp_len, smb2_len;
	const struct smb2_hdr *hdr;
	const struct smb2_negotiate_rsp *rsp;
	int ret;

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	memset(&pdu, 0, sizeof(pdu));
	vmsmb_fill_hdr(&pdu.req.hdr, SMB2_NEGOTIATE_HE, sess);
	pdu.req.StructureSize = cpu_to_le16(36);
	pdu.req.DialectCount = cpu_to_le16(1);
	pdu.req.SecurityMode = cpu_to_le16(0); /* no signing */
	pdu.req.Capabilities = cpu_to_le32(0);
	/* ClientGUID left as zeros — VSMB doesn't use it */
	pdu.dialect = cpu_to_le16(SMB21_PROT_ID);

	ret = vmsmb_smb2_send_recv(sess, &pdu, sizeof(pdu),
				   resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	if (ret)
		goto out;

	hdr = vmsmb_parse_response(resp_buf, resp_len, &smb2_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "NEGOTIATE");
	if (ret)
		goto out;

	if (smb2_len < sizeof(struct smb2_negotiate_rsp)) {
		pr_err("NEGOTIATE response too short: %u\n", smb2_len);
		ret = -EPROTO;
		goto out;
	}

	rsp = (const struct smb2_negotiate_rsp *)hdr;
	sess->max_transact_size = le32_to_cpu(rsp->MaxTransactSize);
	sess->max_read_size = le32_to_cpu(rsp->MaxReadSize);
	sess->max_write_size = le32_to_cpu(rsp->MaxWriteSize);

	pr_info("NEGOTIATE: dialect=0x%04x MaxRead=%u MaxWrite=%u MaxTransact=%u\n",
		le16_to_cpu(rsp->DialectRevision),
		sess->max_read_size, sess->max_write_size,
		sess->max_transact_size);

out:
	kfree(resp_buf);
	return ret;
}

/*
 * SMB2 SESSION_SETUP — anonymous/null session (no auth).
 */
int vmsmb_smb2_session_setup(struct vmsmb_session *sess)
{
	struct smb2_sess_setup_req pdu;
	u8 *resp_buf;
	u32 resp_len, smb2_len;
	const struct smb2_hdr *hdr;
	int ret;

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	memset(&pdu, 0, sizeof(pdu));
	vmsmb_fill_hdr(&pdu.hdr, SMB2_SESSION_SETUP_HE, sess);
	pdu.StructureSize = cpu_to_le16(25);
	pdu.SecurityMode = 0;
	pdu.Capabilities = cpu_to_le32(0);
	pdu.Channel = cpu_to_le32(0);
	/* SecurityBufferOffset/Length = 0: no auth token (anonymous) */
	pdu.SecurityBufferOffset = cpu_to_le16(sizeof(pdu));
	pdu.SecurityBufferLength = cpu_to_le16(0);

	ret = vmsmb_smb2_send_recv(sess, &pdu, sizeof(pdu),
				   resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	if (ret)
		goto out;

	hdr = vmsmb_parse_response(resp_buf, resp_len, &smb2_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	/*
	 * SESSION_SETUP may return STATUS_SUCCESS (0) for anonymous,
	 * or STATUS_MORE_PROCESSING_REQUIRED (0xC0000016) if auth is needed.
	 * For VSMB we expect success or null session.
	 */
	if (hdr->Status != 0 &&
	    hdr->Status != STATUS_MORE_PROCESSING_REQUIRED) {
		pr_err("SESSION_SETUP failed: NTSTATUS 0x%08x\n",
		       le32_to_cpu(hdr->Status));
		ret = -EIO;
		goto out;
	}

	sess->session_id = le64_to_cpu(hdr->SessionId);
	pr_info("SESSION_SETUP: SessionId=0x%llx\n", sess->session_id);

out:
	kfree(resp_buf);
	return ret;
}

/*
 * SMB2 TREE_CONNECT — connect to a named share.
 * @share_name: UTF-8 share name (e.g., "Shared")
 *
 * The path is sent as UTF-16LE. For VSMB, the server expects
 * the share name directly (not \\server\share format).
 */
int vmsmb_smb2_tree_connect(struct vmsmb_session *sess, const char *share_name)
{
	u8 *pdu_buf;
	struct smb2_tree_connect_req *req;
	u32 pdu_len;
	__le16 *path_utf16;
	int path_utf16_len, i;
	u8 *resp_buf;
	u32 resp_len, smb2_len;
	const struct smb2_hdr *hdr;
	const struct smb2_tree_connect_rsp *rsp;
	int ret;

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	/* Build UNC path: \\vsmb\ShareName */
	{
		char unc[256];

		snprintf(unc, sizeof(unc), "\\\\vsmb\\%s", share_name);
		path_utf16_len = strlen(unc) * 2;
		path_utf16 = kmalloc(path_utf16_len, GFP_KERNEL);
		if (!path_utf16) {
			kfree(resp_buf);
			return -ENOMEM;
		}
		for (i = 0; unc[i]; i++)
			path_utf16[i] = cpu_to_le16((u16)(u8)unc[i]);
	}

	/* Build PDU: fixed header + UTF-16 path */
	pdu_len = sizeof(struct smb2_tree_connect_req) + path_utf16_len;
	pdu_buf = kzalloc(pdu_len, GFP_KERNEL);
	if (!pdu_buf) {
		kfree(path_utf16);
		kfree(resp_buf);
		return -ENOMEM;
	}

	req = (struct smb2_tree_connect_req *)pdu_buf;
	vmsmb_fill_hdr(&req->hdr, SMB2_TREE_CONNECT_HE, sess);
	req->StructureSize = cpu_to_le16(9);
	req->Flags = 0;
	req->PathOffset = cpu_to_le16(sizeof(struct smb2_tree_connect_req));
	req->PathLength = cpu_to_le16(path_utf16_len);
	memcpy(pdu_buf + sizeof(struct smb2_tree_connect_req),
	       path_utf16, path_utf16_len);

	kfree(path_utf16);

	ret = vmsmb_smb2_send_recv(sess, pdu_buf, pdu_len,
				   resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kfree(pdu_buf);

	if (ret)
		goto out;

	hdr = vmsmb_parse_response(resp_buf, resp_len, &smb2_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "TREE_CONNECT");
	if (ret)
		goto out;

	if (smb2_len < sizeof(struct smb2_tree_connect_rsp)) {
		pr_err("TREE_CONNECT response too short\n");
		ret = -EPROTO;
		goto out;
	}

	rsp = (const struct smb2_tree_connect_rsp *)hdr;
	sess->tree_id = le32_to_cpu(hdr->Id.SyncId.TreeId);

	pr_info("TREE_CONNECT '%s': TreeId=%u ShareType=%u Capability=0x%x MaxAccess=0x%x\n",
		share_name, sess->tree_id, rsp->ShareType,
		le32_to_cpu(rsp->Capabilities), le32_to_cpu(rsp->MaximalAccess));

out:
	kfree(resp_buf);
	return ret;
}

/*
 * Helper: convert UTF-8 path to UTF-16LE with backslash separators.
 * Returns allocated buffer and sets *out_len (in bytes).
 * Caller must kfree the result.
 */
static __le16 *vmsmb_path_to_utf16(const char *path, int *out_len)
{
	__le16 *buf;
	int i, len = strlen(path);

	*out_len = 0;
	buf = kmalloc((len + 1) * 2, GFP_KERNEL);
	if (!buf)
		return NULL;

	for (i = 0; i < len; i++) {
		if (path[i] == '/')
			buf[i] = cpu_to_le16('\\');
		else
			buf[i] = cpu_to_le16((u16)(u8)path[i]);
	}
	*out_len = len * 2;
	return buf;
}

/*
 * SMB2 CREATE — open or create a file/directory.
 */
int vmsmb_smb2_create(struct vmsmb_session *sess, const char *path,
		      u32 desired_access, u32 disposition, u32 create_options,
		      struct vmsmb_fid *fid, struct vmsmb_file_info *info)
{
	u8 *pdu_buf, *resp_buf;
	struct smb2_create_req *req;
	const struct smb2_create_rsp *rsp;
	const struct smb2_hdr *hdr;
	__le16 *name_utf16;
	int name_len;
	u32 pdu_len, resp_len, smb2_len;
	int ret;
	const char *p;

	/* Guard: reject non-ASCII paths until UTF-8→UTF-16 is ported
	 * from CIFS cifs_strtoUTF16() in cifs_unicode.c.
	 */
	for (p = path; *p; p++) {
		if ((unsigned char)*p >= 0x80) {
			pr_warn("CREATE path contains non-ASCII; UTF-8→UTF-16 not implemented: '%s'\n",
				path);
			return -EOPNOTSUPP;
		}
	}

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	name_utf16 = vmsmb_path_to_utf16(path, &name_len);
	if (!name_utf16) {
		kfree(resp_buf);
		return -ENOMEM;
	}

	pdu_len = sizeof(struct smb2_create_req) + max_t(int, name_len, 1);
	pdu_buf = kzalloc(pdu_len, GFP_KERNEL);
	if (!pdu_buf) {
		kfree(name_utf16);
		kfree(resp_buf);
		return -ENOMEM;
	}

	req = (struct smb2_create_req *)pdu_buf;
	vmsmb_fill_hdr(&req->hdr, SMB2_CREATE_HE, sess);
	req->StructureSize = cpu_to_le16(57);
	req->ImpersonationLevel = cpu_to_le32(0x02); /* Impersonation */
	req->DesiredAccess = cpu_to_le32(desired_access);
	req->FileAttributes = cpu_to_le32(FILE_ATTRIBUTE_NORMAL);
	req->ShareAccess = cpu_to_le32(0x07); /* READ|WRITE|DELETE */
	req->CreateDisposition = cpu_to_le32(disposition);
	req->CreateOptions = cpu_to_le32(create_options);
	/*
	 * NameOffset must point past the header even when name is empty.
	 * Some servers reject NameOffset=0.
	 */
	req->NameOffset = cpu_to_le16(sizeof(struct smb2_create_req));
	req->NameLength = cpu_to_le16(name_len);
	if (name_len > 0)
		memcpy(pdu_buf + sizeof(struct smb2_create_req), name_utf16, name_len);

	kfree(name_utf16);

	pr_debug("CREATE: path='%s' access=0x%x disp=0x%x opts=0x%x namelen=%d pdulen=%u nameoff=%u\n",
		 path, desired_access, disposition, create_options, name_len, pdu_len,
		 (unsigned)sizeof(struct smb2_create_req));

	ret = vmsmb_smb2_send_recv(sess, pdu_buf, pdu_len,
				   resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kfree(pdu_buf);
	if (ret)
		goto out;

	hdr = vmsmb_parse_response(resp_buf, resp_len, &smb2_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "CREATE");
	if (ret)
		goto out;

	if (smb2_len < sizeof(struct smb2_create_rsp)) {
		ret = -EPROTO;
		goto out;
	}

	rsp = (const struct smb2_create_rsp *)hdr;

	if (fid) {
		fid->persistent = rsp->PersistentFileId;
		fid->volatile_id = rsp->VolatileFileId;
	}
	if (info) {
		info->size = le64_to_cpu(rsp->EndofFile);
		info->alloc_size = le64_to_cpu(rsp->AllocationSize);
		info->creation_time = le64_to_cpu(rsp->CreationTime);
		info->last_access_time = le64_to_cpu(rsp->LastAccessTime);
		info->last_write_time = le64_to_cpu(rsp->LastWriteTime);
		info->change_time = le64_to_cpu(rsp->ChangeTime);
		info->attributes = le32_to_cpu(rsp->FileAttributes);
	}

out:
	kfree(resp_buf);
	return ret;
}

/*
 * SMB2 CLOSE.
 */
int vmsmb_smb2_close(struct vmsmb_session *sess, struct vmsmb_fid *fid)
{
	struct smb2_close_req pdu;
	u8 *resp_buf;
	u32 resp_len, smb2_len;
	const struct smb2_hdr *hdr;
	int ret;

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	memset(&pdu, 0, sizeof(pdu));
	vmsmb_fill_hdr(&pdu.hdr, SMB2_CLOSE_HE, sess);
	pdu.StructureSize = cpu_to_le16(24);
	pdu.PersistentFileId = fid->persistent;
	pdu.VolatileFileId = fid->volatile_id;

	ret = vmsmb_smb2_send_recv(sess, &pdu, sizeof(pdu),
				   resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	if (ret)
		goto out;

	hdr = vmsmb_parse_response(resp_buf, resp_len, &smb2_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "CLOSE");

out:
	kfree(resp_buf);
	return ret;
}

/*
 * SMB2 READ — read data from an open file.
 */
int vmsmb_smb2_read(struct vmsmb_session *sess, struct vmsmb_fid *fid,
		    u64 offset, u32 length, void *data, u32 *bytes_read)
{
	struct smb2_read_req pdu;
	u8 *resp_buf;
	u32 resp_len, smb2_len, resp_buf_size;
	const struct smb2_hdr *hdr;
	const struct smb2_read_rsp *rsp;
	u32 data_offset, data_len;
	int ret;

	if (length > sess->max_read_size)
		length = sess->max_read_size;

	/* Response: PipeHdr(8) + DirectTCP(4) + SMB2_hdr(64) + ReadRsp + data
	 * Add 4KB padding for VMBus packet coalescing — the last VMBus
	 * packet may contain data from the next response.
	 */
	resp_buf_size = sizeof(struct vmpipe_hdr) +
			sizeof(struct smb2_direct_tcp_hdr) +
			sizeof(struct smb2_read_rsp) + length + 4096;
	resp_buf = kvmalloc(resp_buf_size, GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	memset(&pdu, 0, sizeof(pdu));
	vmsmb_fill_hdr(&pdu.hdr, SMB2_READ_HE, sess);
	pdu.StructureSize = cpu_to_le16(49);
	pdu.Length = cpu_to_le32(length);
	pdu.Offset = cpu_to_le64(offset);
	pdu.PersistentFileId = fid->persistent;
	pdu.VolatileFileId = fid->volatile_id;
	pdu.MinimumCount = cpu_to_le32(0);
	pdu.RemainingBytes = cpu_to_le32(0);

	ret = vmsmb_smb2_send_recv(sess, &pdu, sizeof(pdu),
				   resp_buf, resp_buf_size, &resp_len);
	if (ret)
		goto out;

	hdr = vmsmb_parse_response(resp_buf, resp_len, &smb2_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "READ");
	if (ret)
		goto out;

	rsp = (const struct smb2_read_rsp *)hdr;
	data_offset = le16_to_cpu(rsp->DataOffset);
	data_len = le32_to_cpu(rsp->DataLength);

	if (data_offset + data_len > smb2_len) {
		ret = -EPROTO;
		goto out;
	}

	if (data_len > length)
		data_len = length;

	memcpy(data, (const u8 *)hdr + data_offset, data_len);
	*bytes_read = data_len;

out:
	kvfree(resp_buf);
	return ret;
}

/*
 * SMB2 WRITE — write data to an open file.
 */
int vmsmb_smb2_write(struct vmsmb_session *sess, struct vmsmb_fid *fid,
		     u64 offset, const void *data, u32 length,
		     u32 *bytes_written)
{
	u8 *pdu_buf, *resp_buf;
	struct smb2_write_req *req;
	const struct smb2_write_rsp *rsp;
	const struct smb2_hdr *hdr;
	u32 pdu_len, resp_len, smb2_len;
	u32 data_offset;
	int ret;

	if (length > sess->max_write_size)
		length = sess->max_write_size;

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	/* Data follows immediately after the fixed header */
	data_offset = sizeof(struct smb2_write_req);
	pdu_len = data_offset + length;
	pdu_buf = kvmalloc(pdu_len, GFP_KERNEL);
	if (!pdu_buf) {
		kfree(resp_buf);
		return -ENOMEM;
	}

	memset(pdu_buf, 0, data_offset);
	req = (struct smb2_write_req *)pdu_buf;
	vmsmb_fill_hdr(&req->hdr, SMB2_WRITE_HE, sess);
	req->StructureSize = cpu_to_le16(49);
	req->DataOffset = cpu_to_le16(data_offset);
	req->Length = cpu_to_le32(length);
	req->Offset = cpu_to_le64(offset);
	req->PersistentFileId = fid->persistent;
	req->VolatileFileId = fid->volatile_id;
	req->RemainingBytes = cpu_to_le32(0);
	req->Flags = cpu_to_le32(0);

	memcpy(pdu_buf + data_offset, data, length);

	ret = vmsmb_smb2_send_recv(sess, pdu_buf, pdu_len,
				   resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kvfree(pdu_buf);
	if (ret)
		goto out;

	hdr = vmsmb_parse_response(resp_buf, resp_len, &smb2_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "WRITE");
	if (ret)
		goto out;

	rsp = (const struct smb2_write_rsp *)hdr;
	*bytes_written = le32_to_cpu(rsp->DataLength);

out:
	kfree(resp_buf);
	return ret;
}

/*
 * SMB2 QUERY_DIRECTORY — enumerate directory entries.
 * Returns the raw output buffer; caller parses FILE_DIRECTORY_INFO entries.
 */
int vmsmb_smb2_query_dir(struct vmsmb_session *sess, struct vmsmb_fid *fid,
			 const char *pattern, void *buf, u32 buf_size,
			 u32 *data_len)
{
	u8 *pdu_buf, *resp_buf;
	struct smb2_query_directory_req *req;
	const struct smb2_query_directory_rsp *rsp;
	const struct smb2_hdr *hdr;
	__le16 *pat_utf16;
	int pat_len;
	u32 pdu_len, resp_len, smb2_len, resp_buf_size;
	u32 out_offset, out_len;
	int ret;

	/*
	 * recv buffer must hold PipeHdr + DirectTCP + SMB2 headers +
	 * the output data (up to buf_size bytes).
	 */
	resp_buf_size = sizeof(struct vmpipe_hdr) +
			sizeof(struct smb2_direct_tcp_hdr) +
			sizeof(struct smb2_query_directory_rsp) + buf_size;
	resp_buf = kvmalloc(resp_buf_size, GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	pat_utf16 = vmsmb_path_to_utf16(pattern, &pat_len);
	if (!pat_utf16) {
		kvfree(resp_buf);
		return -ENOMEM;
	}

	pdu_len = sizeof(struct smb2_query_directory_req) + pat_len;
	pdu_buf = kzalloc(pdu_len, GFP_KERNEL);
	if (!pdu_buf) {
		kfree(pat_utf16);
		kvfree(resp_buf);
		return -ENOMEM;
	}

	req = (struct smb2_query_directory_req *)pdu_buf;
	vmsmb_fill_hdr(&req->hdr, SMB2_QUERY_DIRECTORY_HE, sess);
	req->StructureSize = cpu_to_le16(33);
	req->FileInformationClass = 1; /* FileDirectoryInformation */
	req->Flags = SMB2_RESTART_SCANS;
	req->FileIndex = 0;
	req->PersistentFileId = fid->persistent;
	req->VolatileFileId = fid->volatile_id;
	req->FileNameOffset = cpu_to_le16(sizeof(struct smb2_query_directory_req));
	req->FileNameLength = cpu_to_le16(pat_len);
	req->OutputBufferLength = cpu_to_le32(buf_size);
	memcpy(pdu_buf + sizeof(struct smb2_query_directory_req), pat_utf16, pat_len);

	kfree(pat_utf16);

	ret = vmsmb_smb2_send_recv(sess, pdu_buf, pdu_len,
				   resp_buf, resp_buf_size, &resp_len);
	kfree(pdu_buf);
	if (ret)
		goto out;

	hdr = vmsmb_parse_response(resp_buf, resp_len, &smb2_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "QUERY_DIRECTORY");
	if (ret)
		goto out;

	rsp = (const struct smb2_query_directory_rsp *)hdr;
	out_offset = le16_to_cpu(rsp->OutputBufferOffset);
	out_len = le32_to_cpu(rsp->OutputBufferLength);

	if (out_offset + out_len > smb2_len || out_len > buf_size) {
		ret = -EPROTO;
		goto out;
	}

	memcpy(buf, (const u8 *)hdr + out_offset, out_len);
	*data_len = out_len;

out:
	kvfree(resp_buf);
	return ret;
}
