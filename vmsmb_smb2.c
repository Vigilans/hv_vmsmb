// SPDX-License-Identifier: GPL-2.0
/*
 * vmsmb_smb2.c - SMB2 command construction for VSMB
 *
 * Uses struct definitions from smb2pdu.h (copied from kernel fs/smb/common/).
 *
 * Portions derived from the Linux kernel CIFS client (fs/smb/client/),
 * copyright held by its respective upstream authors. See docs/ATTRIBUTION.md
 * for per-function provenance.
 */

#define pr_fmt(fmt) "hv_vmsmb: " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/nls.h>
#include "vmsmb.h"
#include "smb2pdu.h"
#include "smb1pdu.h"
#include "smbfsctl.h"
#include "smb2status.h"
#include "fscc.h"

/*
 * Compound-request sentinel file id: the second (and later) PDU in a chain
 * carries this value, and the server substitutes the fid produced by the
 * prior operation in the chain.
 *
 * MS-SMB2 §3.2.4.1.4 (Sending Compounded Requests) specifies the value
 * ({0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}) but not a symbolic name. The
 * name `COMPOUND_FID` comes from CIFS (fs/smb/client/smb2pdu.h); kept
 * without an SMB2_ prefix to match upstream naming for easy grep. Lives in
 * this .c instead of smb2pdu.h because our smb2pdu.h is a verbatim copy of
 * fs/smb/common/smb2pdu.h and should stay upstream-clean.
 */
#define COMPOUND_FID		0xFFFFFFFFFFFFFFFFULL

/*
 * Fill a common SMB2 header.
 *
 * Simplified version of CIFS smb2_plain_req_init() + fill_small_buf()
 * (fs/smb/client/smb2pdu.c, smb2transport.c). We skip signing,
 * encryption, and compound request support.
 */
static void vmsmb_fill_hdr(struct smb2_hdr *hdr, u16 command,
			    struct vmsmb_session *sess, u32 tree_id)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->ProtocolId = SMB2_PROTO_NUMBER;
	hdr->StructureSize = cpu_to_le16(64);
	hdr->Command = cpu_to_le16(command);
	hdr->CreditCharge = cpu_to_le16(1);
	/*
	 * CreditRequest: CIFS uses 256 (SMB2_MAX_CREDITS_DEFAULT). 64 is
	 * sufficient for our max async concurrency (~8 in-flight via netfs).
	 * CreditCharge=1 is correct because all our PDUs are ≤64K after
	 * chunking (VMSMB_MAX_WRITE_CHUNK ≈ 65K, control PDUs ≤ 4K).
	 */
	hdr->CreditRequest = cpu_to_le16(64);
	/*
	 * MessageId is left zero here; vmsmb_reserve_credits walks the chain
	 * in transport context and assigns the actual MID under ct_lock,
	 * keeping MID allocation atomic with mid_range_size/mid_table updates
	 * (mrxsmb.sys-style).
	 */
	hdr->Id.SyncId.TreeId = cpu_to_le32(tree_id);
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
 *
 * Thin wrapper over vmsmb_status_to_errno() + pr_debug. Equivalent to the
 * status-handling branch of CIFS smb2_check_receive() (fs/smb/client/smb2ops.c),
 * minus signing / compounded response handling which we don't support.
 */
static int vmsmb_check_status(const struct smb2_hdr *hdr, const char *cmd_name)
{
	if (hdr->Status != STATUS_SUCCESS) {
		int err = vmsmb_status_to_errno(hdr->Status);

		/*
		 * ENOTDIR / EISDIR are how a CREATE constrained to one object
		 * type reports the other one, which the symlink type probe in
		 * vmsmb_detect_directory_target() asks for deliberately.
		 */
		if (err != -ENOENT && err != -ENODATA &&
		    err != -ENOTDIR && err != -EISDIR)
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
	vmsmb_fill_hdr(&pdu.req.hdr, SMB2_NEGOTIATE_HE, sess, 0);
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
	vmsmb_fill_hdr(&pdu.hdr, SMB2_SESSION_SETUP_HE, sess, 0);
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
int vmsmb_smb2_tree_connect(struct vmsmb_session *sess, const char *share_name,
			    u32 *tree_id_out)
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
	vmsmb_fill_hdr(&req->hdr, SMB2_TREE_CONNECT_HE, sess, 0);
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
	*tree_id_out = le32_to_cpu(hdr->Id.SyncId.TreeId);

	pr_info("TREE_CONNECT '%s': TreeId=%u ShareType=%u Capability=0x%x MaxAccess=0x%x\n",
		share_name, *tree_id_out, rsp->ShareType,
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
int vmsmb_smb2_create(struct vmsmb_session *sess, u32 tree_id,
		      const char *path,
		      u32 desired_access, u32 disposition, u32 create_options,
		      u8 *oplock,
		      struct vmsmb_fid *fid, struct vmsmb_file_info *info)
{
	u8 *pdu_buf, *resp_buf;
	struct smb2_create_req *req;
	const struct smb2_create_rsp *rsp;
	const struct smb2_hdr *hdr;
	__le16 *name_utf16;
	int name_len;
	u32 pdu_len, resp_len;
	u32 ctx_offset;		/* 8-byte aligned offset of QFid context */
	u32 name_end;
	struct create_context *qfid_ctx;
	int ret;

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	name_utf16 = vmsmb_path_to_utf16(path, &name_len);
	if (!name_utf16) {
		kfree(resp_buf);
		return -ENOMEM;
	}

	/*
	 * Layout: [fixed smb2_create_req][name][pad][QFid context].
	 * QFid context requests the NTFS file reference number on the
	 * CREATE response (MS-SMB2 2.2.13.2.9), avoiding a separate
	 * QUERY_INFO round-trip. Port of CIFS smb2_open pattern.
	 */
	name_end = sizeof(struct smb2_create_req) + max_t(int, name_len, 1);
	ctx_offset = ALIGN(name_end, 8);
	pdu_len = ctx_offset + 24;	/* QFid context = 16 hdr + 4 name + 4 pad */
	pdu_buf = kzalloc(pdu_len, GFP_KERNEL);
	if (!pdu_buf) {
		kfree(name_utf16);
		kfree(resp_buf);
		return -ENOMEM;
	}

	req = (struct smb2_create_req *)pdu_buf;
	vmsmb_fill_hdr(&req->hdr, SMB2_CREATE_HE, sess, tree_id);
	req->StructureSize = cpu_to_le16(57);
	req->ImpersonationLevel = cpu_to_le32(0x02); /* Impersonation */
	req->DesiredAccess = cpu_to_le32(desired_access);
	req->FileAttributes = cpu_to_le32(FILE_ATTRIBUTE_NORMAL);
	req->ShareAccess = FILE_SHARE_READ_LE | FILE_SHARE_WRITE_LE |
			   FILE_SHARE_DELETE_LE;
	req->CreateDisposition = cpu_to_le32(disposition);
	req->CreateOptions = cpu_to_le32(create_options);
	req->RequestedOplockLevel = oplock ? *oplock : SMB2_OPLOCK_LEVEL_NONE;
	/*
	 * NameOffset must point past the header even when name is empty.
	 * Some servers reject NameOffset=0.
	 */
	req->NameOffset = cpu_to_le16(sizeof(struct smb2_create_req));
	req->NameLength = cpu_to_le16(name_len);
	if (name_len > 0)
		memcpy(pdu_buf + sizeof(struct smb2_create_req), name_utf16, name_len);

	kfree(name_utf16);

	/* QFid request context — Name = "QFid", no data */
	qfid_ctx = (struct create_context *)(pdu_buf + ctx_offset);
	qfid_ctx->hdr.Next = 0;
	qfid_ctx->hdr.NameOffset = cpu_to_le16(16);
	qfid_ctx->hdr.NameLength = cpu_to_le16(4);
	qfid_ctx->hdr.DataOffset = 0;
	qfid_ctx->hdr.DataLength = 0;
	memcpy(qfid_ctx->Buffer, SMB2_CREATE_QUERY_ON_DISK_ID, 4);
	req->CreateContextsOffset = cpu_to_le32(ctx_offset);
	req->CreateContextsLength = cpu_to_le32(24);

	pr_debug("CREATE: path='%s' access=0x%x disp=0x%x opts=0x%x namelen=%d pdulen=%u\n",
		 path, desired_access, disposition, create_options, name_len, pdu_len);

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
	if (oplock) {
		*oplock = rsp->OplockLevel;
		pr_debug("CREATE: granted oplock=0x%x\n", rsp->OplockLevel);
	}
	if (info) {
		u32 rsp_ctx_off = le32_to_cpu(rsp->CreateContextsOffset);
		u32 rsp_ctx_len = le32_to_cpu(rsp->CreateContextsLength);

		info->size = le64_to_cpu(rsp->EndofFile);
		info->alloc_size = le64_to_cpu(rsp->AllocationSize);
		info->creation_time = le64_to_cpu(rsp->CreationTime);
		info->last_access_time = le64_to_cpu(rsp->LastAccessTime);
		info->last_write_time = le64_to_cpu(rsp->LastWriteTime);
		info->change_time = le64_to_cpu(rsp->ChangeTime);
		info->attributes = le32_to_cpu(rsp->FileAttributes);
		info->index_number = 0;
		info->symlink_target = NULL;

		/* Walk create contexts looking for QFid response */
		if (rsp_ctx_off && rsp_ctx_len &&
		    rsp_ctx_off + rsp_ctx_len <= resp_len) {
			const u8 *p = resp_buf + rsp_ctx_off;
			const u8 *end = p + rsp_ctx_len;

			while (p + sizeof(struct create_context_hdr) <= end) {
				const struct create_context *cc =
					(const struct create_context *)p;
				u32 next = le32_to_cpu(cc->hdr.Next);
				u16 n_off = le16_to_cpu(cc->hdr.NameOffset);
				u16 n_len = le16_to_cpu(cc->hdr.NameLength);
				u16 d_off = le16_to_cpu(cc->hdr.DataOffset);
				u32 d_len = le32_to_cpu(cc->hdr.DataLength);

				if (n_len == 4 &&
				    p + n_off + 4 <= end &&
				    memcmp(p + n_off, SMB2_CREATE_QUERY_ON_DISK_ID, 4) == 0 &&
				    d_len >= 8 &&
				    p + d_off + 8 <= end) {
					__le64 disk_id;

					memcpy(&disk_id, p + d_off, 8);
					info->index_number = le64_to_cpu(disk_id);
					break;
				}

				if (!next)
					break;
				if (next < sizeof(struct create_context_hdr))
					break;
				p += next;
			}
		}
	}

out:
	kfree(resp_buf);
	return ret;
}

/*
 * SMB2 CLOSE.
 *
 * Port of CIFS SMB2_close_flags() (fs/smb/client/smb2pdu.c).
 * We skip the SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB optimization.
 */
int vmsmb_smb2_close(struct vmsmb_session *sess, u32 tree_id,
		     struct vmsmb_fid *fid)
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
	vmsmb_fill_hdr(&pdu.hdr, SMB2_CLOSE_HE, sess, tree_id);
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
 * SMB2 CREATE+CLOSE compound — halves round-trips for metadata operations
 * (lookup, getattr probe; also mkdir / unlink / rmdir via DELETE_ON_CLOSE).
 *
 * Ported from CIFS smb2_compound_op() (fs/smb/client/smb2inode.c): two PDUs
 * chained via hdr1->NextCommand (8-byte aligned offset to PDU2); PDU2 sets
 * SMB2_FLAGS_RELATED_OPERATIONS and inherits the CREATE'd fid by passing
 * COMPOUND_FID. MS-SMB2 §3.2.4.1.4 "Sending Compounded Requests".
 *
 * Disposition is caller-controlled (FILE_OPEN for probe; FILE_CREATE for
 * mkdir; FILE_OPEN with CREATE_DELETE_ON_CLOSE for unlink).  CLOSE status
 * is surfaced when CREATE succeeded — unlink relies on CLOSE to commit
 * DELETE_ON_CLOSE, so a server-side delete-veto must propagate.
 */
int vmsmb_smb2_create_close(struct vmsmb_session *sess, u32 tree_id,
			    const char *path,
			    u32 desired_access, u32 disposition, u32 create_options,
			    struct vmsmb_file_info *info)
{
	u8 *pdu_buf, *resp_buf;
	struct smb2_create_req *creq;
	struct smb2_close_req *clreq;
	const struct smb2_create_rsp *crsp;
	const struct smb2_hdr *hdr1;
	const struct smb2_hdr *hdr2;
	__le16 *name_utf16;
	int name_len;
	u32 resp_len;
	u32 name_end, ctx_offset, create_pdu_len, close_pdu_off, total_len;
	u32 next_off;
	struct create_context *qfid_ctx;
	int ret;

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	name_utf16 = vmsmb_path_to_utf16(path, &name_len);
	if (!name_utf16) {
		kfree(resp_buf);
		return -ENOMEM;
	}

	name_end = sizeof(struct smb2_create_req) + max_t(int, name_len, 1);
	ctx_offset = ALIGN(name_end, 8);
	create_pdu_len = ctx_offset + 24;		/* QFid ctx = 24 bytes */
	close_pdu_off = ALIGN(create_pdu_len, 8);
	total_len = close_pdu_off + sizeof(struct smb2_close_req);

	pdu_buf = kzalloc(total_len, GFP_KERNEL);
	if (!pdu_buf) {
		kfree(name_utf16);
		kfree(resp_buf);
		return -ENOMEM;
	}

	/* PDU #1: CREATE with NextCommand = close_pdu_off */
	creq = (struct smb2_create_req *)pdu_buf;
	vmsmb_fill_hdr(&creq->hdr, SMB2_CREATE_HE, sess, tree_id);
	creq->hdr.NextCommand = cpu_to_le32(close_pdu_off);
	creq->StructureSize = cpu_to_le16(57);
	creq->ImpersonationLevel = cpu_to_le32(0x02);
	creq->DesiredAccess = cpu_to_le32(desired_access);
	creq->FileAttributes = cpu_to_le32(FILE_ATTRIBUTE_NORMAL);
	creq->ShareAccess = FILE_SHARE_READ_LE | FILE_SHARE_WRITE_LE |
			    FILE_SHARE_DELETE_LE;
	creq->CreateDisposition = cpu_to_le32(disposition);
	creq->CreateOptions = cpu_to_le32(create_options);
	creq->NameOffset = cpu_to_le16(sizeof(struct smb2_create_req));
	creq->NameLength = cpu_to_le16(name_len);
	if (name_len > 0)
		memcpy(pdu_buf + sizeof(struct smb2_create_req), name_utf16, name_len);
	kfree(name_utf16);

	qfid_ctx = (struct create_context *)(pdu_buf + ctx_offset);
	qfid_ctx->hdr.Next = 0;
	qfid_ctx->hdr.NameOffset = cpu_to_le16(16);
	qfid_ctx->hdr.NameLength = cpu_to_le16(4);
	qfid_ctx->hdr.DataOffset = 0;
	qfid_ctx->hdr.DataLength = 0;
	memcpy(qfid_ctx->Buffer, SMB2_CREATE_QUERY_ON_DISK_ID, 4);
	creq->CreateContextsOffset = cpu_to_le32(ctx_offset);
	creq->CreateContextsLength = cpu_to_le32(24);

	/* PDU #2: CLOSE, RELATED, using COMPOUND_FID */
	clreq = (struct smb2_close_req *)(pdu_buf + close_pdu_off);
	vmsmb_fill_hdr(&clreq->hdr, SMB2_CLOSE_HE, sess, tree_id);
	clreq->hdr.Flags |= SMB2_FLAGS_RELATED_OPERATIONS;
	clreq->StructureSize = cpu_to_le16(24);
	clreq->PersistentFileId = COMPOUND_FID;
	clreq->VolatileFileId = COMPOUND_FID;

	pr_debug("CREATE+CLOSE compound: path='%s' access=0x%x opts=0x%x total=%u\n",
		 path, desired_access, create_options, total_len);

	ret = vmsmb_smb2_transact(sess, pdu_buf, total_len,
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kfree(pdu_buf);
	if (ret)
		goto out;

	hdr1 = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr1) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr1, "CREATE");
	if (ret)
		goto out;

	if (resp_len < sizeof(struct smb2_create_rsp)) {
		ret = -EPROTO;
		goto out;
	}

	crsp = (const struct smb2_create_rsp *)resp_buf;

	if (info) {
		u32 rsp_ctx_off = le32_to_cpu(crsp->CreateContextsOffset);
		u32 rsp_ctx_len = le32_to_cpu(crsp->CreateContextsLength);

		info->size = le64_to_cpu(crsp->EndofFile);
		info->alloc_size = le64_to_cpu(crsp->AllocationSize);
		info->creation_time = le64_to_cpu(crsp->CreationTime);
		info->last_access_time = le64_to_cpu(crsp->LastAccessTime);
		info->last_write_time = le64_to_cpu(crsp->LastWriteTime);
		info->change_time = le64_to_cpu(crsp->ChangeTime);
		info->attributes = le32_to_cpu(crsp->FileAttributes);
		info->index_number = 0;
		info->symlink_target = NULL;

		if (rsp_ctx_off && rsp_ctx_len &&
		    rsp_ctx_off + rsp_ctx_len <= resp_len) {
			const u8 *p = resp_buf + rsp_ctx_off;
			const u8 *end = p + rsp_ctx_len;

			while (p + sizeof(struct create_context_hdr) <= end) {
				const struct create_context *cc =
					(const struct create_context *)p;
				u32 next = le32_to_cpu(cc->hdr.Next);
				u16 n_off = le16_to_cpu(cc->hdr.NameOffset);
				u16 n_len = le16_to_cpu(cc->hdr.NameLength);
				u16 d_off = le16_to_cpu(cc->hdr.DataOffset);
				u32 d_len = le32_to_cpu(cc->hdr.DataLength);

				if (n_len == 4 &&
				    p + n_off + 4 <= end &&
				    memcmp(p + n_off, SMB2_CREATE_QUERY_ON_DISK_ID, 4) == 0 &&
				    d_len >= 8 &&
				    p + d_off + 8 <= end) {
					__le64 disk_id;

					memcpy(&disk_id, p + d_off, 8);
					info->index_number = le64_to_cpu(disk_id);
					break;
				}

				if (!next)
					break;
				if (next < sizeof(struct create_context_hdr))
					break;
				p += next;
			}
		}
	}

	/* Validate CLOSE response.  When CREATE succeeded, surface the CLOSE
	 * status: unlink uses CREATE_DELETE_ON_CLOSE, so the actual delete
	 * commits at CLOSE and any error there must propagate.  Probe
	 * paths (lookup/getattr) only call us when they would otherwise have
	 * issued a separate CLOSE anyway, so seeing CLOSE errors there is
	 * still correct. */
	next_off = le32_to_cpu(hdr1->NextCommand);
	if (next_off == 0 || next_off >= resp_len ||
	    resp_len - next_off < sizeof(struct smb2_hdr)) {
		pr_debug("compound: missing/short CLOSE response (next=%u resp=%u)\n",
			 next_off, resp_len);
		goto out;
	}
	hdr2 = (const struct smb2_hdr *)(resp_buf + next_off);
	if (hdr2->ProtocolId != SMB2_PROTO_NUMBER) {
		pr_debug("compound: CLOSE response bad magic\n");
		goto out;
	}
	ret = vmsmb_check_status(hdr2, "CLOSE");

out:
	kfree(resp_buf);
	return ret;
}
/*
 * SMB2 CREATE+IOCTL+CLOSE compound — folds a 3-round-trip probe into one
 * VMBus transact. Used for FSCTL_GET_REPARSE_POINT (symlink readlink).
 *
 * Ported from CIFS smb2_compound_op() (fs/smb/client/smb2inode.c): three
 * PDUs chained via NextCommand; PDUs 2 and 3 set SMB2_FLAGS_RELATED_OPERATIONS
 * and inherit the CREATE'd fid via COMPOUND_FID.
 *
 * Simplified: fixed disposition=FILE_OPEN; no QFid context (callers here
 * don't need index_number); CLOSE failure non-fatal.
 */
int vmsmb_smb2_create_ioctl_close(struct vmsmb_session *sess, u32 tree_id,
				  const char *path,
				  u32 desired_access, u32 create_options,
				  u32 ctl_code,
				  const void *in, u32 in_len,
				  void *out, u32 out_size, u32 *out_len)
{
	u8 *pdu_buf, *resp_buf;
	struct smb2_create_req *creq;
	struct smb2_ioctl_req *ireq;
	struct smb2_close_req *clreq;
	const struct smb2_ioctl_rsp *irsp;
	const struct smb2_hdr *hdr1, *hdr2, *hdr3;
	__le16 *name_utf16;
	int name_len;
	u32 resp_len, resp_buf_size;
	u32 create_pdu_len, ioctl_pdu_off, ioctl_pdu_len, close_pdu_off, total_len;
	u32 pdu2_resp_off, pdu2_resp_remaining, rsp_out_off, rsp_out_len;
	u32 next1, next2;
	int ret;

	/*
	 * Size response buffer to actual need: compound response is
	 * CREATE_rsp(~88) + IOCTL_rsp(48 + out_size) + CLOSE_rsp(60) +
	 * compound alignment slack. 1 KB overhead is generous.
	 *
	 * kvmalloc so callers passing larger out_size (e.g. future bulk
	 * IOCTLs) don't hit order-N physical-contiguity failures under
	 * memory fragmentation — vmalloc fallback uses non-contiguous pages.
	 */
	resp_buf_size = out_size + 1024;
	resp_buf = kvmalloc(resp_buf_size, GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	name_utf16 = vmsmb_path_to_utf16(path, &name_len);
	if (!name_utf16) {
		kvfree(resp_buf);
		return -ENOMEM;
	}

	create_pdu_len = sizeof(struct smb2_create_req) + max_t(int, name_len, 1);
	ioctl_pdu_off = ALIGN(create_pdu_len, 8);
	ioctl_pdu_len = sizeof(struct smb2_ioctl_req) + in_len;
	close_pdu_off = ioctl_pdu_off + ALIGN(ioctl_pdu_len, 8);
	total_len = close_pdu_off + sizeof(struct smb2_close_req);

	pdu_buf = kzalloc(total_len, GFP_KERNEL);
	if (!pdu_buf) {
		kfree(name_utf16);
		kvfree(resp_buf);
		return -ENOMEM;
	}

	/* PDU #1: CREATE */
	creq = (struct smb2_create_req *)pdu_buf;
	vmsmb_fill_hdr(&creq->hdr, SMB2_CREATE_HE, sess, tree_id);
	creq->hdr.NextCommand = cpu_to_le32(ioctl_pdu_off);
	creq->StructureSize = cpu_to_le16(57);
	creq->ImpersonationLevel = cpu_to_le32(0x02);
	creq->DesiredAccess = cpu_to_le32(desired_access);
	creq->FileAttributes = cpu_to_le32(FILE_ATTRIBUTE_NORMAL);
	creq->ShareAccess = FILE_SHARE_READ_LE | FILE_SHARE_WRITE_LE |
			    FILE_SHARE_DELETE_LE;
	creq->CreateDisposition = cpu_to_le32(FILE_OPEN);
	creq->CreateOptions = cpu_to_le32(create_options);
	creq->NameOffset = cpu_to_le16(sizeof(struct smb2_create_req));
	creq->NameLength = cpu_to_le16(name_len);
	if (name_len > 0)
		memcpy(pdu_buf + sizeof(struct smb2_create_req), name_utf16, name_len);
	kfree(name_utf16);

	/* PDU #2: IOCTL, RELATED, COMPOUND_FID */
	ireq = (struct smb2_ioctl_req *)(pdu_buf + ioctl_pdu_off);
	vmsmb_fill_hdr(&ireq->hdr, SMB2_IOCTL_HE, sess, tree_id);
	ireq->hdr.NextCommand = cpu_to_le32(close_pdu_off - ioctl_pdu_off);
	ireq->hdr.Flags |= SMB2_FLAGS_RELATED_OPERATIONS;
	ireq->StructureSize = cpu_to_le16(57);
	ireq->CtlCode = cpu_to_le32(ctl_code);
	ireq->PersistentFileId = COMPOUND_FID;
	ireq->VolatileFileId = COMPOUND_FID;
	ireq->InputOffset = cpu_to_le32(sizeof(struct smb2_ioctl_req));
	ireq->InputCount = cpu_to_le32(in_len);
	ireq->MaxInputResponse = 0;
	ireq->OutputOffset = 0;
	ireq->OutputCount = 0;
	ireq->MaxOutputResponse = cpu_to_le32(out_size);
	ireq->Flags = cpu_to_le32(SMB2_0_IOCTL_IS_FSCTL);
	ireq->Reserved2 = 0;
	if (in_len)
		memcpy(ireq->Buffer, in, in_len);

	/* PDU #3: CLOSE, RELATED, COMPOUND_FID */
	clreq = (struct smb2_close_req *)(pdu_buf + close_pdu_off);
	vmsmb_fill_hdr(&clreq->hdr, SMB2_CLOSE_HE, sess, tree_id);
	clreq->hdr.Flags |= SMB2_FLAGS_RELATED_OPERATIONS;
	clreq->StructureSize = cpu_to_le16(24);
	clreq->PersistentFileId = COMPOUND_FID;
	clreq->VolatileFileId = COMPOUND_FID;

	pr_debug("CREATE+IOCTL+CLOSE compound: path='%s' ctl=0x%x total=%u\n",
		 path, ctl_code, total_len);

	ret = vmsmb_smb2_transact(sess, pdu_buf, total_len,
				  resp_buf, resp_buf_size, &resp_len);
	kfree(pdu_buf);
	if (ret)
		goto out;

	/* CREATE response */
	hdr1 = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr1) {
		ret = -EPROTO;
		goto out;
	}
	ret = vmsmb_check_status(hdr1, "CREATE");
	if (ret)
		goto out;

	/* IOCTL response at hdr1->NextCommand */
	next1 = le32_to_cpu(hdr1->NextCommand);
	if (!next1 || next1 >= resp_len ||
	    resp_len - next1 < sizeof(struct smb2_ioctl_rsp)) {
		pr_warn_ratelimited("hv_vmsmb: compound: missing IOCTL resp (next=%u resp=%u)\n",
				    next1, resp_len);
		ret = -EPROTO;
		goto out;
	}
	hdr2 = (const struct smb2_hdr *)(resp_buf + next1);
	if (hdr2->ProtocolId != SMB2_PROTO_NUMBER) {
		ret = -EPROTO;
		goto out;
	}
	ret = vmsmb_check_status(hdr2, "IOCTL");
	if (ret)
		goto out;

	irsp = (const struct smb2_ioctl_rsp *)(resp_buf + next1);
	pdu2_resp_off = next1;
	pdu2_resp_remaining = resp_len - next1;
	rsp_out_off = le32_to_cpu(irsp->OutputOffset);	/* from start of SMB2 hdr */
	rsp_out_len = le32_to_cpu(irsp->OutputCount);

	if (rsp_out_off > pdu2_resp_remaining ||
	    rsp_out_len > pdu2_resp_remaining - rsp_out_off) {
		ret = -EPROTO;
		goto out;
	}
	if (rsp_out_len > out_size)
		rsp_out_len = out_size;
	if (out && rsp_out_len)
		memcpy(out, resp_buf + pdu2_resp_off + rsp_out_off, rsp_out_len);
	if (out_len)
		*out_len = rsp_out_len;

	/* CLOSE response (non-fatal) */
	next2 = le32_to_cpu(hdr2->NextCommand);
	if (!next2 || pdu2_resp_off + next2 >= resp_len ||
	    resp_len - pdu2_resp_off - next2 < sizeof(struct smb2_hdr)) {
		pr_debug("compound: missing/short CLOSE response\n");
		goto out;
	}
	hdr3 = (const struct smb2_hdr *)(resp_buf + pdu2_resp_off + next2);
	if (hdr3->ProtocolId != SMB2_PROTO_NUMBER) {
		pr_debug("compound: CLOSE bad magic\n");
		goto out;
	}
	if (hdr3->Status != STATUS_SUCCESS)
		pr_debug("compound CLOSE NTSTATUS 0x%08x\n",
			 le32_to_cpu(hdr3->Status));

out:
	kvfree(resp_buf);
	return ret;
}

/*
 * SMB2 READ — read data from an open file.
 *
 * Simplified: CIFS smb2_async_readv() (fs/smb/client/smb2pdu.c)
 * uses async I/O with credit-based flow control. We do synchronous
 * reads with a single credit charge.
 */
int vmsmb_smb2_read(struct vmsmb_session *sess, u32 tree_id,
		    struct vmsmb_fid *fid,
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
	vmsmb_fill_hdr(&pdu.hdr, SMB2_READ_HE, sess, tree_id);
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
	data_offset = rsp->DataOffset;
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
int vmsmb_smb2_write(struct vmsmb_session *sess, u32 tree_id,
		     struct vmsmb_fid *fid,
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
	BUILD_BUG_ON(sizeof(struct smb2_write_req) != VMSMB_WRITE_HDR_SIZE);
	data_offset = sizeof(struct smb2_write_req);
	pdu_len = data_offset + length;
	pdu_buf = kvmalloc(pdu_len, GFP_KERNEL);
	if (!pdu_buf) {
		kfree(resp_buf);
		return -ENOMEM;
	}

	memset(pdu_buf, 0, data_offset);
	req = (struct smb2_write_req *)pdu_buf;
	vmsmb_fill_hdr(&req->hdr, SMB2_WRITE_HE, sess, tree_id);
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
	if (resp_len < sizeof(struct smb2_write_rsp)) {
		ret = -EPROTO;
		goto out;
	}

	rsp = (const struct smb2_write_rsp *)resp_buf;
	*bytes_written = le32_to_cpu(rsp->DataLength);

out:
	kfree(resp_buf);
	return ret;
}

/*
 * Async SMB2 READ.
 *
 * Port of CIFS smb2_async_readv() (fs/smb/client/smb2pdu.c): build READ PDU,
 * submit via the async transport (vmsmb_smb2_submit_async), and on
 * response invoke the caller's callback in workqueue context.
 *
 * The @data pointer handed to @cb aliases the response buffer and is only
 * valid for the duration of the call — caller must copy or consume
 * in-place (e.g. copy_to_iter into a netfs subrequest).
 *
 * On synchronous submit failure (OOM / EAGAIN exhausted) returns -errno
 * without invoking @cb. On response-time failures @cb is invoked with
 * non-zero status and @data/@len set to NULL/0.
 */
struct vmsmb_read_async_ctx {
	void (*cb)(void *priv, int status, const void *data, u32 len);
	void *priv;
	u32 max_length;
};

static void vmsmb_read_async_complete(struct vmsmb_request *req)
{
	struct vmsmb_read_async_ctx *rctx = req->async_priv;
	const u32 stream_hdr_size = sizeof(struct smb2_stream_hdr);
	const struct smb2_hdr *hdr;
	const struct smb2_read_rsp *rsp;
	const u8 *smb2_buf;
	u32 smb2_len;
	u32 data_offset, data_len;
	int ret;

	if (req->status) {
		rctx->cb(rctx->priv, req->status, NULL, 0);
		goto done;
	}

	if (req->response_len < stream_hdr_size) {
		rctx->cb(rctx->priv, -EPROTO, NULL, 0);
		goto done;
	}
	smb2_buf = (const u8 *)req->response_buf + stream_hdr_size;
	smb2_len = req->response_len - stream_hdr_size;

	hdr = vmsmb_check_resp(smb2_buf, smb2_len);
	if (!hdr) {
		rctx->cb(rctx->priv, -EPROTO, NULL, 0);
		goto done;
	}

	ret = vmsmb_check_status(hdr, "READ(async)");
	if (ret) {
		rctx->cb(rctx->priv, ret, NULL, 0);
		goto done;
	}

	rsp = (const struct smb2_read_rsp *)smb2_buf;
	data_offset = rsp->DataOffset;
	data_len = le32_to_cpu(rsp->DataLength);

	if ((u64)data_offset + data_len > smb2_len) {
		rctx->cb(rctx->priv, -EPROTO, NULL, 0);
		goto done;
	}
	if (data_len > rctx->max_length)
		data_len = rctx->max_length;

	rctx->cb(rctx->priv, 0, smb2_buf + data_offset, data_len);

done:
	kvfree(req->response_buf);
	kfree(req);
	kfree(rctx);
}

int vmsmb_smb2_read_async(struct vmsmb_session *sess, u32 tree_id,
			  struct vmsmb_fid *fid,
			  u64 offset, u32 length,
			  void (*cb)(void *priv, int status,
				     const void *data, u32 len),
			  void *priv)
{
	struct vmsmb_read_async_ctx *rctx;
	struct smb2_read_req pdu;
	u32 resp_buf_size;
	int ret;

	if (length > sess->max_read_size)
		length = sess->max_read_size;

	rctx = kmalloc(sizeof(*rctx), GFP_KERNEL);
	if (!rctx)
		return -ENOMEM;
	rctx->cb = cb;
	rctx->priv = priv;
	rctx->max_length = length;

	memset(&pdu, 0, sizeof(pdu));
	vmsmb_fill_hdr(&pdu.hdr, SMB2_READ_HE, sess, tree_id);
	pdu.StructureSize = cpu_to_le16(49);
	pdu.Length = cpu_to_le32(length);
	pdu.Offset = cpu_to_le64(offset);
	pdu.PersistentFileId = fid->persistent;
	pdu.VolatileFileId = fid->volatile_id;
	pdu.MinimumCount = cpu_to_le32(0);
	pdu.RemainingBytes = cpu_to_le32(0);

	resp_buf_size = sizeof(struct smb2_read_rsp) + length + 4096;
	ret = vmsmb_smb2_submit_async(sess, &pdu, sizeof(pdu), resp_buf_size,
				      vmsmb_read_async_complete, rctx, NULL);
	if (ret) {
		kfree(rctx);
		return ret;
	}
	return 0;
}

/*
 * Async SMB2 WRITE.
 *
 * Port of CIFS smb2_async_writev() (fs/smb/client/smb2pdu.c): build WRITE
 * PDU with data inlined after the fixed header, submit async, and on
 * response invoke the caller's callback with bytes_written.
 *
 * The caller's @data buffer is copied into the send PDU before submit, so
 * the caller may free/reuse it as soon as this function returns.
 */
struct vmsmb_write_async_ctx {
	void (*cb)(void *priv, int status, u32 bytes_written);
	void *priv;
};

static void vmsmb_write_async_complete(struct vmsmb_request *req)
{
	struct vmsmb_write_async_ctx *wctx = req->async_priv;
	const u32 stream_hdr_size = sizeof(struct smb2_stream_hdr);
	const struct smb2_hdr *hdr;
	const struct smb2_write_rsp *rsp;
	const u8 *smb2_buf;
	u32 smb2_len;
	int ret;

	if (req->status) {
		wctx->cb(wctx->priv, req->status, 0);
		goto done;
	}

	if (req->response_len < stream_hdr_size) {
		wctx->cb(wctx->priv, -EPROTO, 0);
		goto done;
	}
	smb2_buf = (const u8 *)req->response_buf + stream_hdr_size;
	smb2_len = req->response_len - stream_hdr_size;

	hdr = vmsmb_check_resp(smb2_buf, smb2_len);
	if (!hdr) {
		wctx->cb(wctx->priv, -EPROTO, 0);
		goto done;
	}

	ret = vmsmb_check_status(hdr, "WRITE(async)");
	if (ret) {
		wctx->cb(wctx->priv, ret, 0);
		goto done;
	}
	if (smb2_len < sizeof(struct smb2_write_rsp)) {
		wctx->cb(wctx->priv, -EPROTO, 0);
		goto done;
	}

	rsp = (const struct smb2_write_rsp *)smb2_buf;
	wctx->cb(wctx->priv, 0, le32_to_cpu(rsp->DataLength));

done:
	kvfree(req->response_buf);
	kfree(req);
	kfree(wctx);
}

int vmsmb_smb2_write_async(struct vmsmb_session *sess, u32 tree_id,
			   struct vmsmb_fid *fid,
			   u64 offset, const void *data, u32 length,
			   void (*cb)(void *priv, int status, u32 bytes_written),
			   void *priv)
{
	struct vmsmb_write_async_ctx *wctx;
	struct smb2_write_req *req;
	u8 *pdu_buf;
	u32 pdu_len, data_offset;
	int ret;

	if (length > sess->max_write_size)
		length = sess->max_write_size;

	wctx = kmalloc(sizeof(*wctx), GFP_KERNEL);
	if (!wctx)
		return -ENOMEM;
	wctx->cb = cb;
	wctx->priv = priv;

	data_offset = sizeof(struct smb2_write_req);
	pdu_len = data_offset + length;
	pdu_buf = kvmalloc(pdu_len, GFP_KERNEL);
	if (!pdu_buf) {
		kfree(wctx);
		return -ENOMEM;
	}

	memset(pdu_buf, 0, data_offset);
	req = (struct smb2_write_req *)pdu_buf;
	vmsmb_fill_hdr(&req->hdr, SMB2_WRITE_HE, sess, tree_id);
	req->StructureSize = cpu_to_le16(49);
	req->DataOffset = cpu_to_le16(data_offset);
	req->Length = cpu_to_le32(length);
	req->Offset = cpu_to_le64(offset);
	req->PersistentFileId = fid->persistent;
	req->VolatileFileId = fid->volatile_id;
	req->RemainingBytes = cpu_to_le32(0);
	req->Flags = cpu_to_le32(0);
	memcpy(pdu_buf + data_offset, data, length);

	ret = vmsmb_smb2_submit_async(sess, pdu_buf, pdu_len, VMSMB_MAX_RESPONSE,
				      vmsmb_write_async_complete, wctx, NULL);
	kvfree(pdu_buf);
	if (ret) {
		kfree(wctx);
		return ret;
	}
	return 0;
}

/*
 * SMB2 QUERY_DIRECTORY — enumerate directory entries.
 * Returns the raw output buffer; caller parses FILE_ID_FULL_DIR_INFO entries.
 *
 * Simplified: CIFS SMB2_query_directory() (fs/smb/client/smb2pdu.c)
 * supports resumption via FileIndex and falls back to info classes without
 * a file ID when mounted -o noserverino.  We always restart scans and always
 * ask for FileIdFullDirectoryInformation, whose UniqueId is the same NTFS
 * file reference number CREATE's QFid context reports as IndexNumber.
 */
int vmsmb_smb2_query_dir(struct vmsmb_session *sess, u32 tree_id,
			 struct vmsmb_fid *fid,
			 const char *pattern, u8 flags,
			 void *buf, u32 buf_size,
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
	vmsmb_fill_hdr(&req->hdr, SMB2_QUERY_DIRECTORY_HE, sess, tree_id);
	req->StructureSize = cpu_to_le16(33);
	req->FileInformationClass = FILEID_FULL_DIRECTORY_INFORMATION;
	req->Flags = flags;
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
 * SMB2 SET_INFO (FileLinkInformation) — create a hard link.
 *
 * Port of CIFS smb2_create_hardlink() (fs/smb/client/smb2inode.c:1254):
 * opens source with FILE_READ_ATTRIBUTES, sends SET_INFO with
 * FILE_LINK_INFORMATION (level 11). Same wire format as rename
 * (FILE_RENAME_INFORMATION, level 10) but ReplaceIfExists is always 0.
 */
int vmsmb_smb2_hardlink(struct vmsmb_session *sess, u32 tree_id,
			 const char *src_path, const char *link_path)
{
	struct vmsmb_fid fid;
	u8 *pdu_buf, *resp_buf;
	struct smb2_set_info_req *req;
	struct smb2_file_link_info *link_info;
	const struct smb2_hdr *hdr;
	__le16 *link_name_utf16;
	int link_name_len;
	u32 link_info_len, buf_len, pdu_len, resp_len;
	int ret;

	ret = vmsmb_smb2_create(sess, tree_id, src_path, FILE_READ_ATTRIBUTES,
				FILE_OPEN, 0, NULL, &fid, NULL);
	if (ret)
		return ret;

	link_name_utf16 = vmsmb_path_to_utf16(link_path, &link_name_len);
	if (!link_name_utf16) {
		ret = -ENOMEM;
		goto hclose;
	}

	link_info_len = sizeof(struct smb2_file_link_info) + link_name_len;
	buf_len = sizeof(struct smb2_set_info_req) + link_info_len;
	pdu_buf = kzalloc(buf_len, GFP_KERNEL);
	if (!pdu_buf) {
		kfree(link_name_utf16);
		ret = -ENOMEM;
		goto hclose;
	}

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf) {
		kfree(pdu_buf);
		kfree(link_name_utf16);
		ret = -ENOMEM;
		goto hclose;
	}

	req = (struct smb2_set_info_req *)pdu_buf;
	vmsmb_fill_hdr(&req->hdr, SMB2_SET_INFO_HE, sess, tree_id);
	req->StructureSize = cpu_to_le16(33);
	req->InfoType = SMB2_O_INFO_FILE;
	req->FileInfoClass = FILE_LINK_INFORMATION;
	req->BufferLength = cpu_to_le32(link_info_len);
	req->BufferOffset = cpu_to_le16(sizeof(struct smb2_set_info_req));
	req->AdditionalInformation = 0;
	req->PersistentFileId = fid.persistent;
	req->VolatileFileId = fid.volatile_id;

	link_info = (struct smb2_file_link_info *)req->Buffer;
	link_info->ReplaceIfExists = 0;
	memset(link_info->Reserved, 0, sizeof(link_info->Reserved));
	link_info->RootDirectory = 0;
	link_info->FileNameLength = cpu_to_le32(link_name_len);
	memcpy(link_info->FileName, link_name_utf16, link_name_len);

	kfree(link_name_utf16);

	pdu_len = sizeof(struct smb2_set_info_req) + link_info_len;

	ret = vmsmb_smb2_transact(sess, pdu_buf, pdu_len,
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kfree(pdu_buf);
	if (ret)
		goto hfree_resp;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr) {
		ret = -EPROTO;
		goto hfree_resp;
	}

	ret = vmsmb_check_status(hdr, "SET_INFO(hardlink)");

hfree_resp:
	kfree(resp_buf);
hclose:
	vmsmb_smb2_close(sess, tree_id, &fid);
	return ret;
}

/*
 * SMB2 unlink — delete a file or reparse point.
 *
 * Port of CIFS smb2_unlink() (fs/smb/client/smb2inode.c:1071): a
 * hand-rolled compound CREATE(FILE_OPEN, DELETE_ON_CLOSE)+CLOSE.  The
 * actual deletion commits at CLOSE; vmsmb_smb2_create_close surfaces
 * CLOSE status when CREATE succeeds, so a server-side delete-veto
 * propagates.  OPEN_REPARSE_POINT ensures reparse points are deleted
 * rather than followed.
 */
int vmsmb_smb2_unlink(struct vmsmb_session *sess, u32 tree_id,
		      const char *path)
{
	return vmsmb_smb2_create_close(sess, tree_id, path, DELETE,
				       FILE_OPEN,
				       CREATE_DELETE_ON_CLOSE | OPEN_REPARSE_POINT,
				       NULL);
}

/*
 * SMB2 IOCTL — generic file system control.
 *
 * Simplified from CIFS SMB2_ioctl() (fs/smb/client/smb2pdu.c).
 * CIFS supports compound requests, async handling, and credit
 * management. We do a single synchronous round-trip.
 */
int vmsmb_smb2_ioctl(struct vmsmb_session *sess, u32 tree_id,
		      struct vmsmb_fid *fid,
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
	vmsmb_fill_hdr(&req->hdr, SMB2_IOCTL_HE, sess, tree_id);
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
	req->Flags = cpu_to_le32(SMB2_0_IOCTL_IS_FSCTL);
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

	if (hdr->Status == STATUS_BUFFER_OVERFLOW) {
		/*
		 * Not a failure: the server filled the output buffer with as
		 * much as fit (e.g. QUERY_ALLOCATED_RANGES with more ranges
		 * than requested) and the partial data is valid. Mirror CIFS
		 * SMB2_ioctl(), which returns -E2BIG yet still hands back the
		 * output.
		 */
		ret = -E2BIG;
	} else {
		ret = vmsmb_check_status(hdr, "IOCTL");
		if (ret)
			goto free_resp;
	}

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
 * Port of CIFS smb2_query_reparse_point() (fs/smb/client/smb2ops.c). Issues
 * compound CREATE+IOCTL+CLOSE via vmsmb_smb2_create_ioctl_close(). Opens
 * with FILE_OPEN_REPARSE_POINT so CREATE returns metadata about the reparse
 * point itself instead of following it.
 */
int vmsmb_smb2_get_reparse(struct vmsmb_session *sess, u32 tree_id,
			    const char *path,
			    void *buf, u32 buf_size, u32 *data_len)
{
	return vmsmb_smb2_create_ioctl_close(sess, tree_id, path,
					     FILE_READ_ATTRIBUTES,
					     OPEN_REPARSE_POINT,
					     FSCTL_GET_REPARSE_POINT,
					     NULL, 0, buf, buf_size, data_len);
}

/*
 * Create a symlink via NTFS reparse point.
 *
 * Simplified from CIFS create_native_symlink() (fs/smb/client/reparse.c).
 * CIFS handles symlinkroot mapping, compound requests, and xattr
 * contexts. We do: CREATE → IOCTL(SET_REPARSE_POINT) → CLOSE.
 *
 * The directory/file selection follows CIFS smb2_create_reparse_inode()
 * (fs/smb/client/smb2inode.c): a symlink to a directory and one to a file
 * are distinct SMB objects that cannot be exchanged, and the distinction
 * is not carried in the reparse buffer — it is the object the tag is
 * stamped on.  CREATE_NOT_FILE therefore makes a directory reparse point
 * (Windows <SYMLINKD>, FILE_ATTRIBUTE_DIRECTORY set), CREATE_NOT_DIR a
 * file one (<SYMLINK>).
 *
 * Note: VSMB host currently denies FSCTL_SET_REPARSE_POINT with
 * STATUS_ACCESS_DENIED (0xC0000022) for both Linux and Windows guests.
 */
int vmsmb_smb2_create_symlink(struct vmsmb_session *sess, u32 tree_id,
			       const char *path, const char *target,
			       bool directory)
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

	/* CREATE new file or directory to carry the reparse point */
	ret = vmsmb_smb2_create(sess, tree_id, path,
				GENERIC_WRITE | DELETE,
				FILE_CREATE,
				(directory ? CREATE_NOT_FILE : CREATE_NOT_DIR) |
				OPEN_REPARSE_POINT,
				NULL, &fid, NULL);
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

	ret = vmsmb_smb2_ioctl(sess, tree_id, &fid, FSCTL_SET_REPARSE_POINT,
			       sym, sym_len, NULL, 0, NULL);
	kfree(sym);

close:
	vmsmb_smb2_close(sess, tree_id, &fid);

	/*
	 * Clean up empty file on IOCTL failure.
	 * Matches CIFS smb2_create_reparse_inode() → smb2_unlink()
	 * (fs/smb/client/smb2inode.c:1418-1423).
	 */
	if (ret)
		vmsmb_smb2_unlink(sess, tree_id, path);

	return ret;
}

/*
 * SMB2 QUERY_INFO on filesystem — fetch FS_FULL_SIZE_INFORMATION.
 *
 * Simplified from CIFS SMB311_posix_qfs_info / smb2_queryfs
 * (fs/smb/client/smb2pdu.c). CIFS uses compound CREATE+QUERY_INFO+CLOSE;
 * we issue three separate round-trips to keep things straightforward.
 */
int vmsmb_smb2_queryfs(struct vmsmb_session *sess, u32 tree_id,
		       struct smb2_fs_full_size_info *out)
{
	struct vmsmb_fid fid;
	struct vmsmb_file_info info;
	struct smb2_query_info_req *req;
	const struct smb2_query_info_rsp *rsp;
	const struct smb2_hdr *hdr;
	u8 *pdu_buf, *resp_buf;
	u32 resp_len, rsp_out_off, rsp_out_len;
	int ret;

	/* Open the share root with minimum access for FS info query */
	ret = vmsmb_smb2_create(sess, tree_id, "", FILE_READ_ATTRIBUTES,
				FILE_OPEN, 0, NULL, &fid, &info);
	if (ret)
		return ret;

	pdu_buf = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!pdu_buf) {
		ret = -ENOMEM;
		goto close;
	}

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf) {
		kfree(pdu_buf);
		ret = -ENOMEM;
		goto close;
	}

	req = (struct smb2_query_info_req *)pdu_buf;
	vmsmb_fill_hdr(&req->hdr, SMB2_QUERY_INFO_HE, sess, tree_id);
	req->StructureSize = cpu_to_le16(41);
	req->InfoType = SMB2_O_INFO_FILESYSTEM;
	req->FileInfoClass = FS_FULL_SIZE_INFORMATION;
	req->OutputBufferLength = cpu_to_le32(sizeof(*out));
	req->InputBufferOffset = 0;
	req->InputBufferLength = 0;
	req->AdditionalInformation = 0;
	req->Flags = 0;
	req->PersistentFileId = fid.persistent;
	req->VolatileFileId = fid.volatile_id;

	ret = vmsmb_smb2_transact(sess, pdu_buf, sizeof(*req),
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kfree(pdu_buf);
	if (ret)
		goto free_resp;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr) {
		ret = -EPROTO;
		goto free_resp;
	}

	ret = vmsmb_check_status(hdr, "QUERY_INFO(FS)");
	if (ret)
		goto free_resp;

	rsp = (const struct smb2_query_info_rsp *)resp_buf;
	rsp_out_off = le16_to_cpu(rsp->OutputBufferOffset);
	rsp_out_len = le32_to_cpu(rsp->OutputBufferLength);

	if (rsp_out_len < sizeof(*out) ||
	    rsp_out_off + rsp_out_len > resp_len) {
		ret = -EPROTO;
		goto free_resp;
	}

	memcpy(out, (const u8 *)resp_buf + rsp_out_off, sizeof(*out));

free_resp:
	kfree(resp_buf);
close:
	vmsmb_smb2_close(sess, tree_id, &fid);
	return ret;
}

/*
 * SMB2 CREATE + SET_INFO 2-PDU compound — vmusrv requires SET_INFO to be
 * the terminal PDU in a compound chain.  SrvContinueSetInfo aliases the
 * response descriptor onto the request descriptor and truncates the
 * shared size to 0x42, so any subsequent PDU in the chain never gets
 * continued (no wire response).  Caller must follow up with a separate
 * vmsmb_smb2_close() on the returned FID.
 *
 * Layout: [CREATE | pad | SET_INFO(final)], NextCommand on CREATE only,
 * SET_INFO uses SMB2_FLAGS_RELATED_OPERATIONS + COMPOUND_FID.
 *
 * Cleanup contract — out_fid is zeroed on entry, then:
 * - If CREATE fails: out_fid stays zero; caller must NOT close.
 * - If CREATE succeeds: out_fid is set immediately, before SET_INFO is
 *   inspected; caller must close regardless of whether SET_INFO parsing
 *   returned 0 or an error.
 *
 * @op: what to call the SET_INFO in a failure message
 */
static int vmsmb_smb2_create_setinfo(struct vmsmb_session *sess, u32 tree_id,
				     const char *path, u32 desired_access,
				     u32 create_options,
				     u8 info_type, u8 file_info_class,
				     const void *payload, u32 payload_len,
				     const char *op, struct vmsmb_fid *out_fid)
{
	u8 *pdu_buf, *resp_buf;
	struct smb2_create_req *creq;
	struct smb2_set_info_req *sreq;
	const struct smb2_create_rsp *crsp;
	const struct smb2_hdr *hdr1, *hdr2;
	__le16 *name_utf16;
	int name_len;
	u32 resp_len;
	u32 name_end, ctx_offset, create_pdu_len, set_pdu_off, total_len;
	u32 next1;
	struct create_context *qfid_ctx;
	int ret;

	memset(out_fid, 0, sizeof(*out_fid));

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	name_utf16 = vmsmb_path_to_utf16(path, &name_len);
	if (!name_utf16) {
		kfree(resp_buf);
		return -ENOMEM;
	}

	name_end = sizeof(struct smb2_create_req) + max_t(int, name_len, 1);
	ctx_offset = ALIGN(name_end, 8);
	create_pdu_len = ctx_offset + 24;		/* QFid ctx = 24 bytes */
	set_pdu_off = ALIGN(create_pdu_len, 8);
	total_len = set_pdu_off + sizeof(struct smb2_set_info_req) + payload_len;

	pdu_buf = kzalloc(total_len, GFP_KERNEL);
	if (!pdu_buf) {
		kfree(name_utf16);
		kfree(resp_buf);
		return -ENOMEM;
	}

	/* PDU #1: CREATE with NextCommand = set_pdu_off */
	creq = (struct smb2_create_req *)pdu_buf;
	vmsmb_fill_hdr(&creq->hdr, SMB2_CREATE_HE, sess, tree_id);
	creq->hdr.NextCommand = cpu_to_le32(set_pdu_off);
	creq->StructureSize = cpu_to_le16(57);
	creq->ImpersonationLevel = cpu_to_le32(0x02);
	creq->DesiredAccess = cpu_to_le32(desired_access);
	creq->FileAttributes = cpu_to_le32(FILE_ATTRIBUTE_NORMAL);
	creq->ShareAccess = FILE_SHARE_READ_LE | FILE_SHARE_WRITE_LE |
			    FILE_SHARE_DELETE_LE;
	creq->CreateDisposition = cpu_to_le32(FILE_OPEN);
	creq->CreateOptions = cpu_to_le32(create_options);
	creq->NameOffset = cpu_to_le16(sizeof(struct smb2_create_req));
	creq->NameLength = cpu_to_le16(name_len);
	if (name_len > 0)
		memcpy(pdu_buf + sizeof(struct smb2_create_req), name_utf16, name_len);
	kfree(name_utf16);

	qfid_ctx = (struct create_context *)(pdu_buf + ctx_offset);
	qfid_ctx->hdr.Next = 0;
	qfid_ctx->hdr.NameOffset = cpu_to_le16(16);
	qfid_ctx->hdr.NameLength = cpu_to_le16(4);
	qfid_ctx->hdr.DataOffset = 0;
	qfid_ctx->hdr.DataLength = 0;
	memcpy(qfid_ctx->Buffer, SMB2_CREATE_QUERY_ON_DISK_ID, 4);
	creq->CreateContextsOffset = cpu_to_le32(ctx_offset);
	creq->CreateContextsLength = cpu_to_le32(24);

	/* PDU #2: SET_INFO(final), RELATED, using COMPOUND_FID */
	sreq = (struct smb2_set_info_req *)(pdu_buf + set_pdu_off);
	vmsmb_fill_hdr(&sreq->hdr, SMB2_SET_INFO_HE, sess, tree_id);
	sreq->hdr.Flags |= SMB2_FLAGS_RELATED_OPERATIONS;
	sreq->StructureSize = cpu_to_le16(33);
	sreq->InfoType = info_type;
	sreq->FileInfoClass = file_info_class;
	sreq->BufferLength = cpu_to_le32(payload_len);
	sreq->BufferOffset = cpu_to_le16(sizeof(struct smb2_set_info_req));
	sreq->AdditionalInformation = 0;
	sreq->PersistentFileId = COMPOUND_FID;
	sreq->VolatileFileId = COMPOUND_FID;
	memcpy(sreq->Buffer, payload, payload_len);

	pr_debug("CREATE+SET_INFO compound: path='%s' class=%u total=%u\n",
		 path, file_info_class, total_len);

	ret = vmsmb_smb2_transact(sess, pdu_buf, total_len,
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kfree(pdu_buf);
	if (ret)
		goto out;

	/* CREATE response */
	hdr1 = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr1) {
		ret = -EPROTO;
		goto out;
	}
	ret = vmsmb_check_status(hdr1, "CREATE");
	if (ret)
		goto out;

	if (resp_len < sizeof(struct smb2_create_rsp)) {
		ret = -EPROTO;
		goto out;
	}

	/*
	 * Surface FID to caller as soon as CREATE is known to have succeeded,
	 * BEFORE inspecting SET_INFO.  SET_INFO parse failure must not leak
	 * the host-side handle.
	 */
	crsp = (const struct smb2_create_rsp *)resp_buf;
	out_fid->persistent = crsp->PersistentFileId;
	out_fid->volatile_id = crsp->VolatileFileId;

	/* SET_INFO response at hdr1->NextCommand */
	next1 = le32_to_cpu(hdr1->NextCommand);
	if (!next1 || next1 >= resp_len ||
	    resp_len - next1 < sizeof(struct smb2_hdr)) {
		pr_warn_ratelimited("hv_vmsmb: compound: missing SET_INFO resp (next=%u resp=%u)\n",
				    next1, resp_len);
		ret = -EPROTO;
		goto out;
	}
	hdr2 = (const struct smb2_hdr *)(resp_buf + next1);
	if (hdr2->ProtocolId != SMB2_PROTO_NUMBER) {
		ret = -EPROTO;
		goto out;
	}
	ret = vmsmb_check_status(hdr2, op);

out:
	kfree(resp_buf);
	return ret;
}

/*
 * SMB2 SET_INFO (FileRenameInformation) — rename a file or directory.
 *
 * Port of CIFS smb2_rename_path() (fs/smb/client/smb2inode.c), which folds
 * CREATE+SET_INFO+CLOSE into one round-trip and opens the source with a
 * cached writable handle when it has one.  The CLOSE is a request of its
 * own here for the reason vmsmb_smb2_create_setinfo() documents.
 *
 * The source is opened with DELETE access, which a rename needs, and with
 * OPEN_REPARSE_POINT so a symlink is renamed rather than followed; that
 * flag has no effect on other files.
 *
 * @old_path: current path relative to share root
 * @new_path: target path relative to share root
 * @replace:  if true, replace existing target (RENAME_NOREPLACE inverts this)
 */
int vmsmb_smb2_rename(struct vmsmb_session *sess, u32 tree_id,
		       const char *old_path, const char *new_path,
		       bool replace)
{
	struct smb2_file_rename_info *rename_info;
	struct vmsmb_fid fid;
	__le16 *new_name_utf16;
	int new_name_len;
	u32 rename_info_len;
	int ret;

	new_name_utf16 = vmsmb_path_to_utf16(new_path, &new_name_len);
	if (!new_name_utf16)
		return -ENOMEM;

	rename_info_len = sizeof(*rename_info) + new_name_len;
	rename_info = kzalloc(rename_info_len, GFP_KERNEL);
	if (!rename_info) {
		kfree(new_name_utf16);
		return -ENOMEM;
	}

	rename_info->ReplaceIfExists = replace ? 1 : 0;
	rename_info->FileNameLength = cpu_to_le32(new_name_len);
	memcpy(rename_info->FileName, new_name_utf16, new_name_len);
	kfree(new_name_utf16);

	ret = vmsmb_smb2_create_setinfo(sess, tree_id, old_path, DELETE,
					OPEN_REPARSE_POINT, SMB2_O_INFO_FILE,
					FILE_RENAME_INFORMATION, rename_info,
					rename_info_len, "SET_INFO(rename)",
					&fid);
	kfree(rename_info);

	if (fid.persistent || fid.volatile_id)
		vmsmb_smb2_close(sess, tree_id, &fid);
	return ret;
}

/*
 * SMB2 SET_INFO (FileBasicInformation) — push timestamps + file attributes.
 *
 * Ported from CIFS smb2_set_file_info_compound() / set_basic_info path
 * (fs/smb/client/smb2inode.c).  CIFS uses a 3-PDU CREATE+SET_INFO+CLOSE
 * compound; vmusrv requires SET_INFO to be the terminal PDU in a chain
 * (SrvContinueSetInfo truncates the shared compound descriptor to 0x42),
 * so we issue a 2-PDU CREATE+SET_INFO compound plus a standalone CLOSE
 * on the real FID — 2 RT instead of CIFS's 1 RT or the prior 3 RT.
 *
 * Per MS-FSCC 2.4.7: timestamp value 0 means "do not change", -1 means
 * "maintain current". FileAttributes = 0 also means "do not change".
 *
 * @path: path relative to share root (empty string for share root)
 * @binfo: 40-byte FILE_BASIC_INFORMATION payload (caller-filled)
 */
int vmsmb_smb2_set_basic_info(struct vmsmb_session *sess, u32 tree_id,
			      const char *path,
			      const FILE_BASIC_INFO *binfo)
{
	struct vmsmb_fid fid;
	int ret;

	ret = vmsmb_smb2_create_setinfo(sess, tree_id, path,
					FILE_WRITE_ATTRIBUTES, 0,
					SMB2_O_INFO_FILE,
					FILE_BASIC_INFORMATION,
					binfo, sizeof(*binfo), "SET_INFO",
					&fid);
	if (fid.persistent || fid.volatile_id)
		vmsmb_smb2_close(sess, tree_id, &fid);
	return ret;
}
/*
 * SMB2 SET_INFO (FileEndOfFileInformation) — truncate/extend a file.
 *
 * Ported from CIFS smb2_set_file_size() (fs/smb/client/smb2ops.c).
 * Same 2-PDU + standalone CLOSE shape as vmsmb_smb2_set_basic_info()
 * because vmusrv requires SET_INFO to be the terminal PDU in a chain.
 *
 * Payload is an 8-byte LE __le64 EndOfFile value (MS-FSCC 2.4.13).
 */
int vmsmb_smb2_set_eof(struct vmsmb_session *sess, u32 tree_id,
		       const char *path, u64 eof)
{
	struct vmsmb_fid fid;
	__le64 eof_le = cpu_to_le64(eof);
	int ret;

	ret = vmsmb_smb2_create_setinfo(sess, tree_id, path,
					FILE_WRITE_DATA, 0,
					SMB2_O_INFO_FILE,
					FILE_END_OF_FILE_INFORMATION,
					&eof_le, sizeof(eof_le), "SET_INFO",
					&fid);
	if (fid.persistent || fid.volatile_id)
		vmsmb_smb2_close(sess, tree_id, &fid);
	return ret;
}

/*
 * SMB2 rmdir — delete a directory.
 *
 * Port of CIFS smb2_rmdir() (fs/smb/client/smb2inode.c): open the directory
 * with DELETE access and CREATE_NOT_FILE, then request the delete with
 * SET_INFO(FILE_DISPOSITION_INFORMATION) carrying a single byte of 1
 * (MS-FSCC 2.4.11).  Upstream sends this as one CREATE+SET_INFO+CLOSE chain;
 * SET_INFO has to terminate a chain here, so the CLOSE is standalone.
 *
 * This is deliberately not the CREATE_DELETE_ON_CLOSE shape that
 * vmsmb_smb2_unlink() uses, and upstream draws the same distinction.
 * DELETE_ON_CLOSE only marks the handle, leaving the server free to accept
 * the mark and drop the delete: vmusrv does exactly that for a non-empty
 * directory, answering STATUS_SUCCESS on both CREATE and CLOSE while keeping
 * the directory.  SET_INFO makes the server adjudicate before it replies, so
 * a non-empty directory comes back as STATUS_DIRECTORY_NOT_EMPTY.
 */
int vmsmb_smb2_rmdir(struct vmsmb_session *sess, u32 tree_id,
		     const char *path)
{
	struct vmsmb_fid fid;
	u8 delete_pending = 1;
	int ret;

	ret = vmsmb_smb2_create_setinfo(sess, tree_id, path,
					DELETE, CREATE_NOT_FILE,
					SMB2_O_INFO_FILE,
					FILE_DISPOSITION_INFORMATION,
					&delete_pending, sizeof(delete_pending),
					"SET_INFO", &fid);
	if (fid.persistent || fid.volatile_id)
		vmsmb_smb2_close(sess, tree_id, &fid);
	return ret;
}

/*
 * SMB2 FLUSH — force server-side flush of an open file.
 *
 * Port of CIFS SMB2_flush() (fs/smb/client/smb2pdu.c). MS-SMB2 2.2.17.
 * Single round-trip, no body beyond the 24-byte request.
 */
int vmsmb_smb2_flush(struct vmsmb_session *sess, u32 tree_id,
		     struct vmsmb_fid *fid)
{
	u8 *pdu_buf, *resp_buf;
	struct smb2_flush_req *req;
	const struct smb2_hdr *hdr;
	u32 resp_len;
	int ret;

	pdu_buf = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!pdu_buf)
		return -ENOMEM;

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf) {
		kfree(pdu_buf);
		return -ENOMEM;
	}

	req = (struct smb2_flush_req *)pdu_buf;
	vmsmb_fill_hdr(&req->hdr, SMB2_FLUSH_HE, sess, tree_id);
	req->StructureSize = cpu_to_le16(24);
	req->PersistentFileId = fid->persistent;
	req->VolatileFileId = fid->volatile_id;

	ret = vmsmb_smb2_transact(sess, pdu_buf, sizeof(*req),
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kfree(pdu_buf);
	if (ret)
		goto out;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "FLUSH");

out:
	kfree(resp_buf);
	return ret;
}

/*
 * SMB2 LOCK — acquire or release a single byte-range lock on an open file.
 *
 * Port of CIFS SMB2_lock()/smb2_lockv() (fs/smb/client/smb2pdu.c) for the
 * single-element case; MS-SMB2 2.2.26. @lock_flags is an SMB2_LOCKFLAG_*
 * combination (SHARED/EXCLUSIVE/UNLOCK, optionally | FAIL_IMMEDIATELY).
 *
 * @pid is stamped into the SMB2 header ProcessId for lock-owner attribution
 * (current->tgid, matching CIFS); on SMB2 the FileId is the primary owner key.
 *
 * Unlike CIFS — whose transport parks indefinitely on the async response —
 * our transact is synchronous with a fixed timeout (VMSMB_TIMEOUT_MS), so a
 * server-side blocking wait would spuriously time out and corrupt MID state.
 * Callers therefore always set FAIL_IMMEDIATELY and emulate F_SETLKW by
 * retrying (see vmsmb_setlk).
 *
 * Returns 0 on grant/release, -EAGAIN on lock conflict (so fcntl/flock report
 * EAGAIN rather than the generic EACCES vmsmb_check_status() would assign), or
 * a negative errno.
 */
int vmsmb_smb2_lock(struct vmsmb_session *sess, u32 tree_id,
		    struct vmsmb_fid *fid, u32 pid,
		    u64 offset, u64 length, u32 lock_flags)
{
	struct smb2_lock_req *req;
	const struct smb2_hdr *hdr;
	u8 *pdu_buf, *resp_buf;
	u32 resp_len;
	int ret;

	pdu_buf = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!pdu_buf)
		return -ENOMEM;

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf) {
		kfree(pdu_buf);
		return -ENOMEM;
	}

	req = (struct smb2_lock_req *)pdu_buf;
	vmsmb_fill_hdr(&req->hdr, SMB2_LOCK_HE, sess, tree_id);
	req->hdr.Id.SyncId.ProcessId = cpu_to_le32(pid);
	req->StructureSize = cpu_to_le16(48); /* includes one lock element */
	req->LockCount = cpu_to_le16(1);
	req->LockSequenceNumber = 0;
	req->PersistentFileId = fid->persistent;
	req->VolatileFileId = fid->volatile_id;
	req->lock.Offset = cpu_to_le64(offset);
	req->lock.Length = cpu_to_le64(length);
	req->lock.Flags = cpu_to_le32(lock_flags);
	req->lock.Reserved = 0;

	ret = vmsmb_smb2_transact(sess, pdu_buf, sizeof(*req),
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kfree(pdu_buf);
	if (ret)
		goto out;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}

	if (hdr->Status == STATUS_LOCK_NOT_GRANTED ||
	    hdr->Status == STATUS_FILE_LOCK_CONFLICT) {
		ret = -EAGAIN;
		goto out;
	}
	/*
	 * A coalesced VFS unlock can target a range that does not exactly
	 * match any single server lock (we keep no per-range list); report
	 * that as -ENOLCK so vmsmb_setlk() can treat it as benign. The
	 * residual server lock, if any, is released at CLOSE.
	 */
	if (hdr->Status == STATUS_RANGE_NOT_LOCKED) {
		ret = -ENOLCK;
		goto out;
	}

	ret = vmsmb_check_status(hdr, "LOCK");

out:
	kfree(resp_buf);
	return ret;
}

/*
 * SMB2 TREE_DISCONNECT — drop a tree connection at unmount.
 *
 * Port of CIFS SMB2_tdis() (fs/smb/client/smb2pdu.c). MS-SMB2 2.2.11/2.2.12:
 * a 4-byte request with a trivial response. Best-effort cleanup — the host
 * also releases every tree connect when the VMBus channel closes — so the
 * caller (unmount) ignores the result.
 */
int vmsmb_smb2_tree_disconnect(struct vmsmb_session *sess, u32 tree_id)
{
	struct smb2_tree_disconnect_req *req;
	const struct smb2_hdr *hdr;
	u8 *pdu_buf, *resp_buf;
	u32 resp_len;
	int ret;

	pdu_buf = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!pdu_buf)
		return -ENOMEM;

	resp_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
	if (!resp_buf) {
		kfree(pdu_buf);
		return -ENOMEM;
	}

	req = (struct smb2_tree_disconnect_req *)pdu_buf;
	vmsmb_fill_hdr(&req->hdr, SMB2_TREE_DISCONNECT_HE, sess, tree_id);
	req->StructureSize = cpu_to_le16(4);

	ret = vmsmb_smb2_transact(sess, pdu_buf, sizeof(*req),
				  resp_buf, VMSMB_MAX_RESPONSE, &resp_len);
	kfree(pdu_buf);
	if (ret)
		goto out;

	hdr = vmsmb_check_resp(resp_buf, resp_len);
	if (!hdr) {
		ret = -EPROTO;
		goto out;
	}
	ret = vmsmb_check_status(hdr, "TREE_DISCONNECT");

out:
	kfree(resp_buf);
	return ret;
}
