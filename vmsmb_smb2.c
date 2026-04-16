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
 *
 * Simplified version of CIFS smb2_plain_req_init() + fill_small_buf()
 * (fs/smb/client/smb2pdu.c, smb2transport.c). We skip signing,
 * encryption, and compound request support.
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
 * Validate SMB2 response header.
 *
 * Simplified version of CIFS smb2_check_message()
 * (fs/smb/client/smb2misc.c). We only check protocol magic and
 * minimum length; CIFS additionally validates StructureSize,
 * command match, and signing.
 */
static const struct smb2_hdr *vmsmb_check_resp(const void *resp_buf,
					       u32 resp_len)
{
	const struct smb2_hdr *hdr = resp_buf;

	if (resp_len < sizeof(struct smb2_hdr)) {
		pr_err("response too short: %u bytes\n", resp_len);
		return NULL;
	}

	if (hdr->ProtocolId != SMB2_PROTO_NUMBER) {
		pr_err("bad SMB2 protocol id: 0x%08x\n",
		       le32_to_cpu(hdr->ProtocolId));
		return NULL;
	}

	return hdr;
}

/*
 * Map NTSTATUS to errno.
 *
 * Subset of the CIFS smb2_error_map_table (fs/smb/client/smb2maperror.c),
 * covering status codes relevant to file operations. The canonical
 * NTSTATUS→errno mapping is defined by comments in smb2status.h
 * (copied from fs/smb/common/).
 */
static int vmsmb_status_to_errno(__le32 status)
{
	switch (status) {
	case STATUS_SUCCESS:
		return 0;

	/* File/path lookup errors → ENOENT */
	case STATUS_NO_SUCH_FILE:
	case STATUS_OBJECT_NAME_NOT_FOUND:
	case STATUS_OBJECT_PATH_NOT_FOUND:
	case STATUS_OBJECT_NAME_INVALID:
	case STATUS_DELETE_PENDING:
	case STATUS_BAD_NETWORK_NAME:
	case STATUS_NOT_FOUND:
		return -ENOENT;

	/* Access control → EACCES / EPERM */
	case STATUS_ACCESS_DENIED:
	case STATUS_NETWORK_ACCESS_DENIED:
	case STATUS_ACCESS_VIOLATION:
	case STATUS_FILE_LOCK_CONFLICT:
	case STATUS_LOCK_NOT_GRANTED:
	case STATUS_CANNOT_DELETE:
	case STATUS_LOGON_FAILURE:
		return -EACCES;
	case STATUS_PRIVILEGE_NOT_HELD:
		return -EPERM;

	/* File type errors */
	case STATUS_FILE_IS_A_DIRECTORY:
		return -EISDIR;
	case STATUS_NOT_A_DIRECTORY:
	case STATUS_OBJECT_PATH_INVALID:
		return -ENOTDIR;

	/* Name collision → EEXIST */
	case STATUS_OBJECT_NAME_COLLISION:
		return -EEXIST;

	/* Directory not empty → ENOTEMPTY */
	case STATUS_DIRECTORY_NOT_EMPTY:
		return -ENOTEMPTY;

	/* Resource busy → EBUSY */
	case STATUS_SHARING_VIOLATION:
	case STATUS_DEVICE_BUSY:
	case STATUS_PIPE_BUSY:
		return -EBUSY;

	/* Cross-device → EXDEV (rename across volumes) */
	case STATUS_NOT_SAME_DEVICE:
		return -EXDEV;

	/* Disk/space errors → ENOSPC */
	case STATUS_DISK_FULL:
		return -ENOSPC;

	/* Read-only → EROFS */
	case STATUS_MEDIA_WRITE_PROTECTED:
		return -EROFS;

	/* Name too long → ENAMETOOLONG */
	case STATUS_NAME_TOO_LONG:
		return -ENAMETOOLONG;

	/* Too many links → EMLINK */
	case STATUS_TOO_MANY_LINKS:
		return -EMLINK;

	/* End of file / no more data */
	case STATUS_END_OF_FILE:
	case STATUS_NO_MORE_FILES:
	case STATUS_NO_EAS_ON_FILE:
	case STATUS_NOT_A_REPARSE_POINT:
		return -ENODATA;

	/* Not supported/implemented → EOPNOTSUPP */
	case STATUS_NOT_SUPPORTED:
	case STATUS_NOT_IMPLEMENTED:
	case STATUS_INVALID_DEVICE_REQUEST:
	case STATUS_EAS_NOT_SUPPORTED:
		return -EOPNOTSUPP;

	/* Invalid parameter → EINVAL */
	case STATUS_INVALID_PARAMETER:
		return -EINVAL;

	/* Invalid handle → EBADF */
	case STATUS_INVALID_HANDLE:
	case STATUS_FILE_CLOSED:
		return -EBADF;

	/* Timeout / retry → EAGAIN / ETIMEDOUT */
	case STATUS_TIMEOUT:
	case STATUS_IO_TIMEOUT:
		return -ETIMEDOUT;
	case STATUS_INSUFFICIENT_RESOURCES:
	case STATUS_RETRY:
	case STATUS_SERVER_UNAVAILABLE:
	case STATUS_FILE_NOT_AVAILABLE:
		return -EAGAIN;

	default:
		return -EIO;
	}
}

/*
 * Check SMB2 response status.
 */
static int vmsmb_check_status(const struct smb2_hdr *hdr, const char *cmd_name)
{
	if (hdr->Status != STATUS_SUCCESS) {
		int err = vmsmb_status_to_errno(hdr->Status);

		if (err != -ENOENT && err != -ENODATA)
			pr_err("%s failed: NTSTATUS 0x%08x\n", cmd_name,
			       le32_to_cpu(hdr->Status));
		return err;
	}
	return 0;
}

/*
 * SMB2 NEGOTIATE — single dialect 0x210 (SMB 2.1).
 *
 * Simplified: CIFS SMB2_negotiate() (fs/smb/client/smb2pdu.c)
 * negotiates multiple dialects, preauth integrity, and encryption.
 * VSMB only needs SMB 2.1 with no security features.
 */
int vmsmb_smb2_negotiate(struct vmsmb_session *sess)
{
	struct {
		struct smb2_negotiate_req req;
		__le16 dialect;
	} __packed pdu;
	u8 *resp_buf;
	u32 resp_len;
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

	ret = vmsmb_smb2_transact(sess, &pdu, sizeof(pdu),
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	if (ret)
		goto out;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "NEGOTIATE");
	if (ret)
		goto out;

	if (resp_len < sizeof(struct smb2_negotiate_rsp)) {
		pr_err("NEGOTIATE response too short: %u\n", resp_len);
		ret = -EPROTO;
		goto out;
	}

	rsp = (const struct smb2_negotiate_rsp *)resp_buf;
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
 *
 * Simplified: CIFS SMB2_sess_setup() (fs/smb/client/smb2pdu.c)
 * does multi-round SPNEGO/NTLMSSP authentication.
 * VSMB accepts anonymous sessions with no auth token.
 */
int vmsmb_smb2_session_setup(struct vmsmb_session *sess)
{
	struct smb2_sess_setup_req pdu;
	u8 *resp_buf;
	u32 resp_len;
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

	ret = vmsmb_smb2_transact(sess, &pdu, sizeof(pdu),
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	if (ret)
		goto out;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	/*
	 * SESSION_SETUP may return STATUS_SUCCESS (0) for anonymous,
	 * or STATUS_MORE_PROCESSING_REQUIRED (0xC0000016) if auth is needed.
	 * For VSMB we expect success or null session.
	 */
	if (hdr->Status != STATUS_SUCCESS &&
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
 * Convert UTF-8 path to UTF-16LE with backslash separators.
 * Returns allocated buffer and sets *out_len (in bytes).
 * Caller must kfree the result.
 *
 * Uses the kernel's utf8s_to_utf16s() (lib/unicode.c), the same
 * function underlying CIFS cifs_strtoUTF16() (cifs_unicode.c).
 */
static __le16 *vmsmb_path_to_utf16(const char *path, int *out_len)
{
	int len = strlen(path);
	__le16 *buf;
	int i, wlen;

	*out_len = 0;
	buf = kmalloc((len + 1) * sizeof(__le16), GFP_KERNEL);
	if (!buf)
		return NULL;

	wlen = utf8s_to_utf16s(path, len, UTF16_LITTLE_ENDIAN,
			       (wchar_t *)buf, len + 1);
	if (wlen < 0) {
		pr_err("utf8→utf16 conversion failed: %d\n", wlen);
		kfree(buf);
		return NULL;
	}

	/* SMB2 paths use backslash separators */
	for (i = 0; i < wlen; i++) {
		if (le16_to_cpu(buf[i]) == '/')
			buf[i] = cpu_to_le16('\\');
	}

	*out_len = wlen * sizeof(__le16);
	return buf;
}

/*
 * SMB2 TREE_CONNECT — connect to a named share.
 *
 * Simplified: CIFS SMB2_tcon() (fs/smb/client/smb2pdu.c) handles
 * DFS referrals, encryption per-share, and secure signing.
 * VSMB uses a fixed UNC format \\vsmb\<ShareName> discovered
 * via reverse engineering of vmwp.exe.
 */
int vmsmb_smb2_tree_connect(struct vmsmb_session *sess, const char *share_name)
{
	u8 *pdu_buf;
	struct smb2_tree_connect_req *req;
	u32 pdu_len;
	__le16 *path_utf16;
	int path_utf16_len;
	u8 *resp_buf;
	u32 resp_len;
	const struct smb2_hdr *hdr;
	const struct smb2_tree_connect_rsp *rsp;
	char unc[256];
	int ret;

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	/* Build UNC path: \\vsmb\ShareName */
	snprintf(unc, sizeof(unc), "\\\\vsmb\\%s", share_name);
	path_utf16 = vmsmb_path_to_utf16(unc, &path_utf16_len);
	if (!path_utf16) {
		kfree(resp_buf);
		return -ENOMEM;
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

	ret = vmsmb_smb2_transact(sess, pdu_buf, pdu_len,
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kfree(pdu_buf);

	if (ret)
		goto out;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "TREE_CONNECT");
	if (ret)
		goto out;

	if (resp_len < sizeof(struct smb2_tree_connect_rsp)) {
		pr_err("TREE_CONNECT response too short\n");
		ret = -EPROTO;
		goto out;
	}

	rsp = (const struct smb2_tree_connect_rsp *)resp_buf;
	sess->tree_id = le32_to_cpu(hdr->Id.SyncId.TreeId);

	pr_info("TREE_CONNECT '%s': TreeId=%u ShareType=%u Capability=0x%x MaxAccess=0x%x\n",
		share_name, sess->tree_id, rsp->ShareType,
		le32_to_cpu(rsp->Capabilities), le32_to_cpu(rsp->MaximalAccess));

out:
	kfree(resp_buf);
	return ret;
}

/*
 * SMB2 CREATE — open or create a file/directory.
 *
 * Simplified: CIFS SMB2_open() (fs/smb/client/smb2pdu.c) supports
 * create contexts (oplock, lease, durable handle, query-on-create).
 * We send a plain CREATE with no contexts.
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
	u32 pdu_len, resp_len;
	int ret;

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

	ret = vmsmb_smb2_transact(sess, pdu_buf, pdu_len,
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kfree(pdu_buf);
	if (ret)
		goto out;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "CREATE");
	if (ret)
		goto out;

	if (resp_len < sizeof(struct smb2_create_rsp)) {
		ret = -EPROTO;
		goto out;
	}

	rsp = (const struct smb2_create_rsp *)resp_buf;

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
 *
 * Matches CIFS SMB2_close_flags() (fs/smb/client/smb2pdu.c).
 * We skip the SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB optimization.
 */
int vmsmb_smb2_close(struct vmsmb_session *sess, struct vmsmb_fid *fid)
{
	struct smb2_close_req pdu;
	u8 *resp_buf;
	u32 resp_len;
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

	ret = vmsmb_smb2_transact(sess, &pdu, sizeof(pdu),
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	if (ret)
		goto out;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
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
 *
 * Simplified: CIFS smb2_async_readv() (fs/smb/client/smb2pdu.c)
 * uses async I/O with credit-based flow control. We do synchronous
 * reads with a single credit charge.
 */
int vmsmb_smb2_read(struct vmsmb_session *sess, struct vmsmb_fid *fid,
		    u64 offset, u32 length, void *data, u32 *bytes_read)
{
	struct smb2_read_req pdu;
	u8 *resp_buf;
	u32 resp_len, resp_buf_size;
	const struct smb2_hdr *hdr;
	const struct smb2_read_rsp *rsp;
	u32 data_offset, data_len;
	int ret;

	if (length > sess->max_read_size)
		length = sess->max_read_size;

	/* Response buffer: SMB2 READ response header + data */
	resp_buf_size = sizeof(struct smb2_read_rsp) + length + 4096;
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

	ret = vmsmb_smb2_transact(sess, &pdu, sizeof(pdu),
				  resp_buf, resp_buf_size, &resp_len);
	if (ret)
		goto out;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "READ");
	if (ret)
		goto out;

	rsp = (const struct smb2_read_rsp *)resp_buf;
	data_offset = le16_to_cpu(rsp->DataOffset);
	data_len = le32_to_cpu(rsp->DataLength);

	if (data_offset + data_len > resp_len) {
		ret = -EPROTO;
		goto out;
	}

	if (data_len > length)
		data_len = length;

	memcpy(data, (const u8 *)resp_buf + data_offset, data_len);
	*bytes_read = data_len;

out:
	kvfree(resp_buf);
	return ret;
}

/*
 * SMB2 WRITE — write data to an open file.
 *
 * Simplified: CIFS smb2_async_writev() (fs/smb/client/smb2pdu.c)
 * uses async I/O with credit-based flow control. We do synchronous
 * writes with a single credit charge.
 */
int vmsmb_smb2_write(struct vmsmb_session *sess, struct vmsmb_fid *fid,
		     u64 offset, const void *data, u32 length,
		     u32 *bytes_written)
{
	u8 *pdu_buf, *resp_buf;
	struct smb2_write_req *req;
	const struct smb2_write_rsp *rsp;
	const struct smb2_hdr *hdr;
	u32 pdu_len, resp_len;
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

	ret = vmsmb_smb2_transact(sess, pdu_buf, pdu_len,
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kvfree(pdu_buf);
	if (ret)
		goto out;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "WRITE");
	if (ret)
		goto out;

	rsp = (const struct smb2_write_rsp *)resp_buf;
	*bytes_written = le32_to_cpu(rsp->DataLength);

out:
	kfree(resp_buf);
	return ret;
}

/*
 * SMB2 QUERY_DIRECTORY — enumerate directory entries.
 * Returns the raw output buffer; caller parses FILE_DIRECTORY_INFO entries.
 *
 * Simplified: CIFS SMB2_query_directory() (fs/smb/client/smb2pdu.c)
 * supports resumption via FileIndex and multiple info classes.
 * We always restart scans and use FileDirectoryInformation only.
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
	u32 pdu_len, resp_len, resp_buf_size;
	u32 out_offset, out_len;
	int ret;

	/* SMB2 response: header + output data (up to buf_size bytes) */
	resp_buf_size = sizeof(struct smb2_query_directory_rsp) + buf_size;
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

	ret = vmsmb_smb2_transact(sess, pdu_buf, pdu_len,
				  resp_buf, resp_buf_size, &resp_len);
	kfree(pdu_buf);
	if (ret)
		goto out;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "QUERY_DIRECTORY");
	if (ret)
		goto out;

	rsp = (const struct smb2_query_directory_rsp *)resp_buf;
	out_offset = le16_to_cpu(rsp->OutputBufferOffset);
	out_len = le32_to_cpu(rsp->OutputBufferLength);

	if (out_offset + out_len > resp_len || out_len > buf_size) {
		ret = -EPROTO;
		goto out;
	}

	memcpy(buf, (const u8 *)resp_buf + out_offset, out_len);
	*data_len = out_len;

out:
	kvfree(resp_buf);
	return ret;
}

/*
 * SMB2 SET_INFO (FileRenameInformation) — rename a file or directory.
 *
 * Simplified: CIFS smb2_rename_path() (fs/smb/client/smb2inode.c)
 * uses compound requests (CREATE+SET_INFO+CLOSE in one round-trip)
 * and opens the source with a cached writable handle when available.
 * We do three separate requests: CREATE (with DELETE access) →
 * SET_INFO → CLOSE.
 *
 * @old_path: current path relative to share root
 * @new_path: target path relative to share root
 * @replace:  if true, replace existing target (RENAME_NOREPLACE inverts this)
 */
int vmsmb_smb2_rename(struct vmsmb_session *sess,
		       const char *old_path, const char *new_path,
		       bool replace)
{
	struct vmsmb_fid fid;
	u8 *pdu_buf, *resp_buf;
	struct smb2_set_info_req *req;
	struct smb2_file_rename_info *rename_info;
	const struct smb2_hdr *hdr;
	__le16 *new_name_utf16;
	int new_name_len;
	u32 rename_info_len, buf_len, pdu_len, resp_len;
	int ret;

	/* Step 1: Open source with DELETE access */
	ret = vmsmb_smb2_create(sess, old_path, 0x00010000 /* DELETE */,
				0x01 /* FILE_OPEN */, 0, &fid, NULL);
	if (ret)
		return ret;

	/* Convert new path to UTF-16LE */
	new_name_utf16 = vmsmb_path_to_utf16(new_path, &new_name_len);
	if (!new_name_utf16) {
		ret = -ENOMEM;
		goto close;
	}

	/* Build SET_INFO request */
	rename_info_len = sizeof(struct smb2_file_rename_info) + new_name_len;
	buf_len = sizeof(struct smb2_set_info_req) + rename_info_len;
	pdu_buf = kzalloc(buf_len, GFP_KERNEL);
	if (!pdu_buf) {
		kfree(new_name_utf16);
		ret = -ENOMEM;
		goto close;
	}

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf) {
		kfree(pdu_buf);
		kfree(new_name_utf16);
		ret = -ENOMEM;
		goto close;
	}

	req = (struct smb2_set_info_req *)pdu_buf;
	vmsmb_fill_hdr(&req->hdr, SMB2_SET_INFO_HE, sess);
	req->StructureSize = cpu_to_le16(33);
	req->InfoType = SMB2_O_INFO_FILE;
	req->FileInfoClass = FILE_RENAME_INFORMATION;
	req->BufferLength = cpu_to_le32(rename_info_len);
	req->BufferOffset = cpu_to_le16(sizeof(struct smb2_set_info_req));
	req->AdditionalInformation = 0;
	req->PersistentFileId = fid.persistent;
	req->VolatileFileId = fid.volatile_id;

	/* Fill rename info in the Buffer[] area */
	rename_info = (struct smb2_file_rename_info *)req->Buffer;
	rename_info->ReplaceIfExists = replace ? 1 : 0;
	memset(rename_info->Reserved, 0, sizeof(rename_info->Reserved));
	rename_info->RootDirectory = 0;
	rename_info->FileNameLength = cpu_to_le32(new_name_len);
	memcpy(rename_info->FileName, new_name_utf16, new_name_len);

	kfree(new_name_utf16);

	pdu_len = sizeof(struct smb2_set_info_req) + rename_info_len;

	/* Step 2: Send SET_INFO */
	ret = vmsmb_smb2_transact(sess, pdu_buf, pdu_len,
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kfree(pdu_buf);
	if (ret)
		goto free_resp;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr) {
		ret = -EPROTO;
		goto free_resp;
	}

	ret = vmsmb_check_status(hdr, "SET_INFO(rename)");

free_resp:
	kfree(resp_buf);
close:
	/* Step 3: Close handle */
	vmsmb_smb2_close(sess, &fid);
	return ret;
}

/*
 * SMB2 unlink — delete a file or reparse point.
 *
 * Port of CIFS smb2_unlink() (fs/smb/client/smb2inode.c:1108-1110):
 * DELETE_ON_CLOSE + OPEN_REPARSE_POINT ensures reparse points are
 * deleted rather than followed.
 */
int vmsmb_smb2_unlink(struct vmsmb_session *sess, const char *path)
{
	struct vmsmb_fid fid;
	int ret;

	ret = vmsmb_smb2_create(sess, path, 0x00010000 /* DELETE */,
				0x01 /* FILE_OPEN */,
				0x00201000 /* DELETE_ON_CLOSE | OPEN_REPARSE_POINT */,
				&fid, NULL);
	if (ret == 0)
		vmsmb_smb2_close(sess, &fid);
	return ret;
}

/*
 * SMB2 IOCTL — generic file system control.
 *
 * Simplified from CIFS SMB2_ioctl() (fs/smb/client/smb2pdu.c).
 * CIFS supports compound requests, async handling, and credit
 * management. We do a single synchronous round-trip.
 */
int vmsmb_smb2_ioctl(struct vmsmb_session *sess, struct vmsmb_fid *fid,
		      u32 ctl_code, const void *in, u32 in_len,
		      void *out, u32 out_size, u32 *out_len)
{
	struct smb2_ioctl_req *req;
	const struct smb2_ioctl_rsp *rsp;
	const struct smb2_hdr *hdr;
	u8 *pdu_buf, *resp_buf;
	u32 pdu_len, resp_len, rsp_out_off, rsp_out_len;
	int ret;

	pdu_len = sizeof(*req) + in_len;
	pdu_buf = kzalloc(pdu_len, GFP_KERNEL);
	if (!pdu_buf)
		return -ENOMEM;

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf) {
		kfree(pdu_buf);
		return -ENOMEM;
	}

	req = (struct smb2_ioctl_req *)pdu_buf;
	vmsmb_fill_hdr(&req->hdr, SMB2_IOCTL_HE, sess);
	req->StructureSize = cpu_to_le16(57);
	req->CtlCode = cpu_to_le32(ctl_code);
	req->PersistentFileId = fid->persistent;
	req->VolatileFileId = fid->volatile_id;
	req->InputOffset = cpu_to_le32(sizeof(*req));
	req->InputCount = cpu_to_le32(in_len);
	req->MaxInputResponse = 0;
	req->OutputOffset = 0;
	req->OutputCount = 0;
	req->MaxOutputResponse = cpu_to_le32(out_size);
	req->Flags = cpu_to_le32(0x00000001); /* SMB2_0_IOCTL_IS_FSCTL */
	req->Reserved2 = 0;

	if (in_len)
		memcpy(req->Buffer, in, in_len);

	ret = vmsmb_smb2_transact(sess, pdu_buf, pdu_len,
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kfree(pdu_buf);
	if (ret)
		goto free_resp;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr) {
		ret = -EPROTO;
		goto free_resp;
	}

	ret = vmsmb_check_status(hdr, "IOCTL");
	if (ret)
		goto free_resp;

	rsp = (const struct smb2_ioctl_rsp *)resp_buf;
	rsp_out_off = le32_to_cpu(rsp->OutputOffset);
	rsp_out_len = le32_to_cpu(rsp->OutputCount);

	if (rsp_out_off + rsp_out_len > resp_len) {
		ret = -EPROTO;
		goto free_resp;
	}

	if (rsp_out_len > out_size)
		rsp_out_len = out_size;

	if (out && rsp_out_len)
		memcpy(out, (const u8 *)resp_buf + rsp_out_off, rsp_out_len);
	if (out_len)
		*out_len = rsp_out_len;

free_resp:
	kfree(resp_buf);
	return ret;
}

/*
 * Read reparse point data for a path.
 *
 * Simplified from CIFS smb2_query_reparse_point()
 * (fs/smb/client/smb2ops.c). Opens with FILE_OPEN_REPARSE_POINT
 * so CREATE returns metadata about the reparse point itself
 * instead of following it.
 */
int vmsmb_smb2_get_reparse(struct vmsmb_session *sess, const char *path,
			    void *buf, u32 buf_size, u32 *data_len)
{
	struct vmsmb_fid fid;
	int ret;

	ret = vmsmb_smb2_create(sess, path, FILE_READ_ATTRIBUTES,
				0x01 /* FILE_OPEN */,
				0x00200000 /* FILE_OPEN_REPARSE_POINT */,
				&fid, NULL);
	if (ret)
		return ret;

	ret = vmsmb_smb2_ioctl(sess, &fid, FSCTL_GET_REPARSE_POINT,
			       NULL, 0, buf, buf_size, data_len);

	vmsmb_smb2_close(sess, &fid);
	return ret;
}

/*
 * Create a symlink via NTFS reparse point.
 *
 * Simplified from CIFS create_native_symlink() (fs/smb/client/reparse.c).
 * CIFS handles symlinkroot mapping, compound requests, and xattr
 * contexts. We do: CREATE → IOCTL(SET_REPARSE_POINT) → CLOSE.
 *
 * Note: VSMB host currently denies FSCTL_SET_REPARSE_POINT with
 * STATUS_ACCESS_DENIED (0xC0000022) for both Linux and Windows guests.
 */
int vmsmb_smb2_create_symlink(struct vmsmb_session *sess,
			       const char *path, const char *target)
{
	struct vmsmb_fid fid;
	struct reparse_symlink_data_buffer *sym;
	__le16 *target_utf16;
	int target_utf16_len;
	u32 sym_len;
	bool relative;
	int ret;
	char *nt_target;
	int i, tlen;

	/* Determine relative vs absolute */
	relative = (target[0] != '/');

	/* Build NT-style target path */
	tlen = strlen(target);
	if (!relative) {
		/* Absolute: prepend \??\ */
		nt_target = kmalloc(4 + tlen + 1, GFP_KERNEL);
		if (!nt_target)
			return -ENOMEM;
		memcpy(nt_target, "\\??\\", 4);
		memcpy(nt_target + 4, target + 1, tlen); /* skip leading / */
		tlen = 4 + tlen - 1;
		nt_target[tlen] = '\0';
	} else {
		nt_target = kmalloc(tlen + 1, GFP_KERNEL);
		if (!nt_target)
			return -ENOMEM;
		memcpy(nt_target, target, tlen + 1);
	}

	/* Convert / to \ */
	for (i = 0; i < tlen; i++)
		if (nt_target[i] == '/')
			nt_target[i] = '\\';

	/* UTF-8 → UTF-16LE */
	target_utf16 = kmalloc((tlen + 1) * sizeof(__le16), GFP_KERNEL);
	if (!target_utf16) {
		kfree(nt_target);
		return -ENOMEM;
	}

	target_utf16_len = utf8s_to_utf16s(nt_target, tlen, UTF16_LITTLE_ENDIAN,
					    (wchar_t *)target_utf16, tlen + 1);
	kfree(nt_target);
	if (target_utf16_len < 0) {
		kfree(target_utf16);
		return -EINVAL;
	}
	target_utf16_len *= sizeof(__le16);

	/* CREATE new file */
	ret = vmsmb_smb2_create(sess, path,
				0x40000000 | 0x00010000, /* GENERIC_WRITE | DELETE */
				0x02 /* FILE_CREATE */,
				0x00200000 /* FILE_OPEN_REPARSE_POINT */,
				&fid, NULL);
	if (ret) {
		kfree(target_utf16);
		return ret;
	}

	/*
	 * Build reparse_symlink_data_buffer.
	 * SubstituteName and PrintName are identical, placed sequentially
	 * in PathBuffer.
	 */
	sym_len = sizeof(*sym) + 2 * target_utf16_len;
	sym = kzalloc(sym_len, GFP_KERNEL);
	if (!sym) {
		kfree(target_utf16);
		ret = -ENOMEM;
		goto close;
	}

	sym->ReparseTag = cpu_to_le32(IO_REPARSE_TAG_SYMLINK);
	sym->ReparseDataLength = cpu_to_le16(12 + 2 * target_utf16_len);
	sym->SubstituteNameOffset = cpu_to_le16(0);
	sym->SubstituteNameLength = cpu_to_le16(target_utf16_len);
	sym->PrintNameOffset = cpu_to_le16(target_utf16_len);
	sym->PrintNameLength = cpu_to_le16(target_utf16_len);
	sym->Flags = cpu_to_le32(relative ? SYMLINK_FLAG_RELATIVE : 0);

	memcpy(sym->PathBuffer, target_utf16, target_utf16_len);
	memcpy(sym->PathBuffer + target_utf16_len, target_utf16, target_utf16_len);
	kfree(target_utf16);

	ret = vmsmb_smb2_ioctl(sess, &fid, FSCTL_SET_REPARSE_POINT,
			       sym, sym_len, NULL, 0, NULL);
	kfree(sym);

close:
	vmsmb_smb2_close(sess, &fid);

	/*
	 * Clean up empty file on IOCTL failure.
	 * Matches CIFS smb2_create_reparse_inode() → smb2_unlink()
	 * (fs/smb/client/smb2inode.c:1418-1423).
	 */
	if (ret)
		vmsmb_smb2_unlink(sess, path);

	return ret;
}
