// SPDX-License-Identifier: GPL-2.0
/*
 * vmsmb_vfs.c - VFS integration for VSMB filesystem
 *
 * Implements mount/umount, inode operations, file operations,
 * and directory operations for the vsmb filesystem type.
 */

#define pr_fmt(fmt) "hv_vmsmb: " fmt

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/statfs.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/nls.h>
#include <linux/fs_parser.h>
#include "vmsmb.h"
#include "smb2pdu.h"
#include "smb1pdu.h"
#include "smbfsctl.h"
#include "fscc.h"

/* SMB2 access masks (combinations of standard constants from smb2pdu.h) */
#define VMSMB_READ_ACCESS	(FILE_READ_DATA | FILE_READ_ATTRIBUTES | \
				 GENERIC_READ)
#define VMSMB_WRITE_ACCESS	(FILE_WRITE_DATA | FILE_APPEND_DATA | \
				 FILE_WRITE_ATTRIBUTES | GENERIC_WRITE)
#define VMSMB_RW_ACCESS		(VMSMB_READ_ACCESS | VMSMB_WRITE_ACCESS)
#define VMSMB_DIR_ACCESS	(FILE_READ_DATA | FILE_READ_ATTRIBUTES | \
				 GENERIC_READ)

/* Inode number counter */
static atomic64_t vmsmb_ino_counter = ATOMIC64_INIT(2);

/* Forward declarations for symlink inode ops */
static const char *vmsmb_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done);
static int vmsmb_symlink(struct mnt_idmap *idmap, struct inode *dir,
			  struct dentry *dentry, const char *target);

/* Inode cache */
struct kmem_cache *vmsmb_inode_cachep;

/*
 * Slab constructor for vmsmb_inode_info objects.
 * inode_init_once() initializes VFS-internal list heads (i_io_list,
 * i_lru, i_hash, etc.) that are only set up once per slab object
 * lifetime — not on every alloc_inode call. Without this, those
 * list heads are {NULL, NULL} and any VFS operation that touches
 * them (mark_inode_dirty, iput) will NULL-deref.
 * Port of CIFS cifs_init_once → inode_init_once.
 */
void vmsmb_init_once(void *data)
{
	struct vmsmb_inode_info *vi = data;

	inode_init_once(&vi->netfs.inode);
}

static inline struct vmsmb_sb_info *VMSMB_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

/*
 * Fill an inode with SMB2 file attributes.
 */
static void vmsmb_fill_inode(struct inode *inode,
			     const struct vmsmb_file_info *info)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);

	if (info->attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		inode->i_mode = S_IFLNK | 0777;
		inode->i_op = &vmsmb_symlink_inode_ops;
		set_nlink(inode, 1);
	} else if (info->attributes & FILE_ATTRIBUTE_DIRECTORY) {
		inode->i_mode = S_IFDIR | sbi->dir_mode;
		inode->i_op = &vmsmb_dir_inode_ops;
		inode->i_fop = &vmsmb_dir_ops;
		set_nlink(inode, 2);
	} else {
		inode->i_mode = S_IFREG | sbi->file_mode;
		inode->i_op = &vmsmb_file_inode_ops;
		inode->i_fop = &vmsmb_file_ops;
		inode->i_mapping->a_ops = &vmsmb_aops;
		set_nlink(inode, 1);
	}

	inode->i_uid = sbi->uid;
	inode->i_gid = sbi->gid;

	i_size_write(inode, info->size);
	inode->i_blocks = (info->alloc_size + 511) / 512;
	inode_set_atime_to_ts(inode, vmsmb_time_to_ts(info->last_access_time));
	inode_set_mtime_to_ts(inode, vmsmb_time_to_ts(info->last_write_time));
	inode_set_ctime_to_ts(inode, vmsmb_time_to_ts(info->change_time));

	/*
	 * Initialize netfs context after VFS inode_init_always() has run
	 * and inode size is set. Port of CIFS pattern: cifs_fattr_to_inode()
	 * calls cifs_set_netfs_context() → netfs_inode_init() only after
	 * filling all inode attributes.
	 */
	netfs_inode_init(&VMSMB_I(inode)->netfs, &vmsmb_netfs_ops, false);
}

/*
 * Build the SMB2 path from a dentry.
 * Returns a kmalloc'd string like "" (root), "file.txt", "dir/file.txt".
 */
static char *vmsmb_build_path(struct dentry *dentry)
{
	char *buf, *path;
	int len;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	path = dentry_path_raw(dentry, buf, PATH_MAX);
	if (IS_ERR(path)) {
		kfree(buf);
		return ERR_CAST(path);
	}

	/* dentry_path_raw returns something like "/dir/file" — skip leading / */
	if (*path == '/')
		path++;

	/* Make a standalone copy */
	len = strlen(path);
	{
		char *result = kmalloc(len + 1, GFP_KERNEL);
		if (!result) {
			kfree(buf);
			return ERR_PTR(-ENOMEM);
		}
		memcpy(result, path, len + 1);
		kfree(buf);
		return result;
	}
}

/*
 * Parse reparse point buffer and return symlink target as UTF-8 string.
 *
 * Handles IO_REPARSE_TAG_SYMLINK and IO_REPARSE_TAG_MOUNT_POINT.
 * Simplified from CIFS parse_reparse_native_symlink() and
 * parse_reparse_point() (fs/smb/client/reparse.c).
 *
 * Path conversion: strip \??\ or \DosDevices\ prefix, convert \ to /.
 */
static char *vmsmb_parse_reparse(const void *buf, u32 buf_len)
{
	const struct reparse_data_buffer *hdr = buf;
	const u8 *name_start;
	u16 name_off, name_len;
	u32 tag;
	char *target, *p;
	int utf8_len;

	if (buf_len < sizeof(*hdr))
		return ERR_PTR(-EINVAL);

	tag = le32_to_cpu(hdr->ReparseTag);

	if (tag == IO_REPARSE_TAG_SYMLINK) {
		const struct reparse_symlink_data_buffer *sym = buf;

		if (buf_len < sizeof(*sym))
			return ERR_PTR(-EINVAL);

		name_off = le16_to_cpu(sym->SubstituteNameOffset);
		name_len = le16_to_cpu(sym->SubstituteNameLength);
		name_start = sym->PathBuffer + name_off;
	} else if (tag == IO_REPARSE_TAG_MOUNT_POINT) {
		const struct reparse_mount_point_data_buffer *mnt = buf;

		if (buf_len < sizeof(*mnt))
			return ERR_PTR(-EINVAL);

		name_off = le16_to_cpu(mnt->SubstituteNameOffset);
		name_len = le16_to_cpu(mnt->SubstituteNameLength);
		name_start = mnt->PathBuffer + name_off;
	} else {
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (!name_len)
		return ERR_PTR(-EINVAL);

	/* UTF-16LE → UTF-8 */
	target = kmalloc(name_len * 2 + 1, GFP_KERNEL);
	if (!target)
		return ERR_PTR(-ENOMEM);

	utf8_len = utf16s_to_utf8s((const wchar_t *)name_start,
				    name_len / sizeof(__le16),
				    UTF16_LITTLE_ENDIAN, target,
				    name_len * 2);
	if (utf8_len < 0) {
		kfree(target);
		return ERR_PTR(-EINVAL);
	}
	target[utf8_len] = '\0';

	/* Convert \ to / */
	for (p = target; *p; p++) {
		if (*p == '\\')
			*p = '/';
	}

	/* Strip NT path prefixes: \??\ or \DosDevices\ (now /??/ or /DosDevices/) */
	p = target;
	if (strncmp(p, "/??/", 4) == 0)
		p += 4;
	else if (strncmp(p, "/DosDevices/", 12) == 0)
		p += 12;

	if (p != target) {
		utf8_len = strlen(p);
		memmove(target, p, utf8_len + 1);
	}

	return target;
}

/* ---- Inode operations ---- */

static struct dentry *vmsmb_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(dir->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_fid fid;
	struct vmsmb_file_info info;
	struct inode *inode;
	char *path;
	int ret;

	path = vmsmb_build_path(dentry);
	if (IS_ERR(path))
		return ERR_CAST(path);


	ret = vmsmb_smb2_create(sess, sbi->tree_id, path, FILE_READ_ATTRIBUTES,
				FILE_OPEN,
				OPEN_REPARSE_POINT,
				&fid, &info);
	if (ret == 0)
		vmsmb_smb2_close(sess, sbi->tree_id, &fid);


	kfree(path);

	if (ret == -ENOENT)
		return d_splice_alias(NULL, dentry);
	if (ret)
		return ERR_PTR(ret);

	inode = new_inode(dir->i_sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->i_ino = atomic64_inc_return(&vmsmb_ino_counter);
	vmsmb_fill_inode(inode, &info);

	/* Resolve symlink target for reparse points (CIFS caches at lookup) */
	if (S_ISLNK(inode->i_mode)) {
		void *reparse_buf;
		u32 reparse_len;
		char *target;

		path = vmsmb_build_path(dentry);
		if (IS_ERR(path)) {
			iput(inode);
			return ERR_CAST(path);
		}

		reparse_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
		if (!reparse_buf) {
			kfree(path);
			iput(inode);
			return ERR_PTR(-ENOMEM);
		}

	
		ret = vmsmb_smb2_get_reparse(sess, sbi->tree_id, path, reparse_buf,
					      VMSMB_MAX_RESPONSE, &reparse_len);
	
		kfree(path);

		if (ret) {
			kfree(reparse_buf);
			iput(inode);
			return ERR_PTR(ret);
		}

		target = vmsmb_parse_reparse(reparse_buf, reparse_len);
		kfree(reparse_buf);

		if (IS_ERR(target)) {
			iput(inode);
			return ERR_CAST(target);
		}

		VMSMB_I(inode)->symlink_target = target;
	}

	d_add(dentry, inode);
	return NULL;
}

static int vmsmb_getattr(struct mnt_idmap *idmap,
			 const struct path *path,
			 struct kstat *stat, u32 request_mask,
			 unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);

	generic_fillattr(idmap, request_mask, inode, stat);
	return 0;
}

static int vmsmb_create(struct mnt_idmap *idmap, struct inode *dir,
			struct dentry *dentry, umode_t mode, bool excl)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(dir->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_fid fid;
	struct vmsmb_file_info info;
	struct inode *inode;
	char *path;
	int ret;

	path = vmsmb_build_path(dentry);
	if (IS_ERR(path))
		return PTR_ERR(path);


	ret = vmsmb_smb2_create(sess, sbi->tree_id, path, VMSMB_RW_ACCESS,
				excl ? FILE_CREATE : FILE_OPEN_IF,
				CREATE_NOT_DIR, &fid, &info);
	if (ret == 0)
		vmsmb_smb2_close(sess, sbi->tree_id, &fid);


	kfree(path);

	if (ret)
		return ret;

	inode = new_inode(dir->i_sb);
	if (!inode)
		return -ENOMEM;

	inode->i_ino = atomic64_inc_return(&vmsmb_ino_counter);
	vmsmb_fill_inode(inode, &info);

	d_instantiate(dentry, inode);
	return 0;
}

static struct dentry *vmsmb_mkdir(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, umode_t mode)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(dir->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_fid fid;
	struct vmsmb_file_info info;
	struct inode *inode;
	char *path;
	int ret;

	path = vmsmb_build_path(dentry);
	if (IS_ERR(path))
		return ERR_CAST(path);


	ret = vmsmb_smb2_create(sess, sbi->tree_id, path, VMSMB_DIR_ACCESS,
				FILE_CREATE, CREATE_NOT_FILE,
				&fid, &info);
	if (ret == 0)
		vmsmb_smb2_close(sess, sbi->tree_id, &fid);


	kfree(path);

	if (ret)
		return ERR_PTR(ret);

	inode = new_inode(dir->i_sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->i_ino = atomic64_inc_return(&vmsmb_ino_counter);
	vmsmb_fill_inode(inode, &info);
	inc_nlink(dir);

	d_instantiate(dentry, inode);
	return NULL;
}

static int vmsmb_unlink(struct inode *dir, struct dentry *dentry)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(dir->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	char *path;
	int ret;

	path = vmsmb_build_path(dentry);
	if (IS_ERR(path))
		return PTR_ERR(path);


	ret = vmsmb_smb2_unlink(sess, sbi->tree_id, path);


	kfree(path);

	if (ret == 0)
		drop_nlink(d_inode(dentry));
	return ret;
}

static int vmsmb_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(dir->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_fid fid;
	char *path;
	int ret;

	path = vmsmb_build_path(dentry);
	if (IS_ERR(path))
		return PTR_ERR(path);


	ret = vmsmb_smb2_create(sess, sbi->tree_id, path, 0x00010000 /* DELETE */,
				FILE_OPEN,
				CREATE_DELETE_ON_CLOSE |
				CREATE_NOT_FILE,
				&fid, NULL);
	if (ret == 0)
		vmsmb_smb2_close(sess, sbi->tree_id, &fid);


	kfree(path);

	if (ret == 0) {
		drop_nlink(d_inode(dentry));
		drop_nlink(dir);
	}
	return ret;
}

static int vmsmb_rename(struct mnt_idmap *idmap,
			struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry,
			unsigned int flags)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(old_dir->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	char *old_path, *new_path;
	bool replace;
	int ret;

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	old_path = vmsmb_build_path(old_dentry);
	if (IS_ERR(old_path))
		return PTR_ERR(old_path);

	new_path = vmsmb_build_path(new_dentry);
	if (IS_ERR(new_path)) {
		kfree(old_path);
		return PTR_ERR(new_path);
	}

	replace = !(flags & RENAME_NOREPLACE);


	ret = vmsmb_smb2_rename(sess, sbi->tree_id, old_path, new_path, replace);


	kfree(old_path);
	kfree(new_path);
	return ret;
}

/*
 * Create a hard link.
 *
 * Port of CIFS cifs_hardlink() (fs/smb/client/link.c:441):
 * d_drop() forces server re-lookup for the new dentry,
 * inc_nlink() updates the source inode link count locally.
 */
static int vmsmb_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(dir->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	char *old_path, *new_path;
	int ret;

	old_path = vmsmb_build_path(old_dentry);
	if (IS_ERR(old_path))
		return PTR_ERR(old_path);

	new_path = vmsmb_build_path(new_dentry);
	if (IS_ERR(new_path)) {
		kfree(old_path);
		return PTR_ERR(new_path);
	}


	ret = vmsmb_smb2_hardlink(sess, sbi->tree_id, old_path, new_path);


	if ((ret == -EIO) || (ret == -EINVAL))
		ret = -EOPNOTSUPP;

	/* Force lookup from server for new dentry (CIFS cifs_hardlink pattern) */
	d_drop(new_dentry);

	if (ret == 0) {
		struct inode *inode = d_inode(old_dentry);

		spin_lock(&inode->i_lock);
		inc_nlink(inode);
		spin_unlock(&inode->i_lock);
	}

	kfree(old_path);
	kfree(new_path);
	return ret;
}

/*
 * Read cached symlink target.
 *
 * Port of CIFS cifs_get_link() (fs/smb/client/cifsfs.c): the target
 * is resolved and cached at lookup time, so get_link just returns
 * the cached copy.
 */
static const char *vmsmb_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	char *target;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	target = VMSMB_I(inode)->symlink_target;
	if (!target)
		return ERR_PTR(-EOPNOTSUPP);

	set_delayed_call(done, (void (*)(void *))kfree, kstrdup(target, GFP_KERNEL));
	return VMSMB_I(inode)->symlink_target;
}

/*
 * Create a symlink.
 *
 * Note: VSMB host currently denies FSCTL_SET_REPARSE_POINT with
 * STATUS_ACCESS_DENIED (0xC0000022), so this will fail in practice.
 */
static int vmsmb_symlink(struct mnt_idmap *idmap, struct inode *dir,
			  struct dentry *dentry, const char *target)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(dir->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_fid fid;
	struct vmsmb_file_info info;
	struct inode *inode;
	char *path;
	int ret;

	path = vmsmb_build_path(dentry);
	if (IS_ERR(path))
		return PTR_ERR(path);


	ret = vmsmb_smb2_create_symlink(sess, sbi->tree_id, path, target);


	if (ret) {
		kfree(path);
		return ret;
	}

	/* Re-stat to get inode attributes */

	ret = vmsmb_smb2_create(sess, sbi->tree_id, path, FILE_READ_ATTRIBUTES,
				FILE_OPEN,
				OPEN_REPARSE_POINT,
				&fid, &info);
	if (ret == 0)
		vmsmb_smb2_close(sess, sbi->tree_id, &fid);


	kfree(path);

	if (ret)
		return ret;

	inode = new_inode(dir->i_sb);
	if (!inode)
		return -ENOMEM;

	inode->i_ino = atomic64_inc_return(&vmsmb_ino_counter);
	vmsmb_fill_inode(inode, &info);
	VMSMB_I(inode)->symlink_target = kstrdup(target, GFP_KERNEL);

	d_instantiate(dentry, inode);
	return 0;
}

const struct inode_operations vmsmb_symlink_inode_ops = {
	.get_link	= vmsmb_get_link,
	.getattr	= vmsmb_getattr,
};

const struct inode_operations vmsmb_dir_inode_ops = {
	.lookup		= vmsmb_lookup,
	.getattr	= vmsmb_getattr,
	.create		= vmsmb_create,
	.mkdir		= vmsmb_mkdir,
	.unlink		= vmsmb_unlink,
	.rmdir		= vmsmb_rmdir,
	.rename		= vmsmb_rename,
	.symlink	= vmsmb_symlink,
	.link		= vmsmb_link,
};

const struct inode_operations vmsmb_file_inode_ops = {
	.getattr	= vmsmb_getattr,
};

/* ---- Address space operations (netfs) ---- */

const struct address_space_operations vmsmb_aops = {
	.read_folio	= netfs_read_folio,
	.readahead	= netfs_readahead,
	.dirty_folio	= netfs_dirty_folio,
	.writepages	= netfs_writepages,
	.release_folio	= netfs_release_folio,
	.invalidate_folio = netfs_invalidate_folio,
	.direct_IO	= noop_direct_IO,
};

/* ---- netfs request operations ---- */

/*
 * Get dentry path from an inode (for handle-less readahead/writeback).
 * Returns a kmalloc'd path or ERR_PTR. Caller must kfree.
 */
static char *vmsmb_inode_path(struct inode *inode)
{
	struct dentry *dentry;
	char *path;

	dentry = d_find_alias(inode);
	if (!dentry)
		return ERR_PTR(-ENOENT);

	path = vmsmb_build_path(dentry);
	dput(dentry);
	return path;
}

static int vmsmb_init_request(struct netfs_io_request *rreq, struct file *file)
{
	if (file)
		rreq->netfs_priv = file->private_data; /* vmsmb_file_ctx */
	return 0;
}

static void vmsmb_issue_read(struct netfs_io_subrequest *subreq)
{
	struct netfs_io_request *rreq = subreq->rreq;
	struct inode *inode = rreq->inode;
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_file_ctx *ctx = rreq->netfs_priv;
	struct vmsmb_fid temp_fid;
	struct vmsmb_fid *fid;
	bool temp_open = false;
	void *buf;
	size_t remain = subreq->len;
	loff_t pos = subreq->start;
	size_t total = 0;
	int ret = 0;

	/* Get file handle — use cached or open temporary */
	if (ctx) {
		fid = &ctx->fid;
	} else {
		char *path = vmsmb_inode_path(inode);

		if (IS_ERR(path)) {
			subreq->error = PTR_ERR(path);
			goto out;
		}
	
		ret = vmsmb_smb2_create(sess, sbi->tree_id, path, VMSMB_READ_ACCESS,
					FILE_OPEN, CREATE_NOT_DIR,
					&temp_fid, NULL);
	
		kfree(path);
		if (ret) {
			subreq->error = ret;
			goto out;
		}
		fid = &temp_fid;
		temp_open = true;
	}

	buf = kvmalloc(min_t(size_t, remain, VMSMB_MAX_READ_CHUNK), GFP_KERNEL);
	if (!buf) {
		subreq->error = -ENOMEM;
		goto close;
	}

	while (remain > 0) {
		u32 chunk = min_t(size_t, remain, VMSMB_MAX_READ_CHUNK);
		u32 bytes_read = 0;

	
		ret = vmsmb_smb2_read(sess, sbi->tree_id, fid, pos, chunk, buf, &bytes_read);
	

		if (ret)
			break;
		if (bytes_read == 0)
			break;

		if (copy_to_iter(buf, bytes_read, &subreq->io_iter) != bytes_read) {
			ret = -EFAULT;
			break;
		}

		pos += bytes_read;
		total += bytes_read;
		remain -= bytes_read;

		if (bytes_read < chunk)
			break;
	}

	kvfree(buf);

	if (ret)
		subreq->error = ret;
	subreq->transferred = total;

close:
	if (temp_open) {
	
		vmsmb_smb2_close(sess, sbi->tree_id, &temp_fid);
	
	}
out:
	netfs_read_subreq_terminated(subreq);
}

static void vmsmb_begin_writeback(struct netfs_io_request *wreq)
{
	struct inode *inode = wreq->inode;
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_inode_info *vi = VMSMB_I(inode);

	/* Pass the active file handle to the write path */
	if (vi->active_ctx)
		wreq->netfs_priv = vi->active_ctx;

	wreq->io_streams[0].avail = true;
	wreq->io_streams[0].sreq_max_len = VMSMB_MAX_WRITE_CHUNK;
}

static void vmsmb_issue_write(struct netfs_io_subrequest *subreq)
{
	struct netfs_io_request *wreq = subreq->rreq;
	struct inode *inode = wreq->inode;
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_file_ctx *ctx = wreq->netfs_priv;
	struct vmsmb_fid temp_fid;
	struct vmsmb_fid *fid;
	bool temp_open = false;
	void *buf;
	size_t remain = subreq->len;
	loff_t pos = subreq->start;
	size_t total = 0;
	int ret = 0;

	pr_debug("issue_write: pos=%lld len=%zu\n", pos, remain);

	/* Get file handle — use cached or open temporary */
	if (ctx) {
		fid = &ctx->fid;
	} else {
		char *path = vmsmb_inode_path(inode);

		if (IS_ERR(path)) {
			ret = PTR_ERR(path);
			goto fail;
		}
	
		ret = vmsmb_smb2_create(sess, sbi->tree_id, path, VMSMB_WRITE_ACCESS,
					FILE_OPEN, CREATE_NOT_DIR,
					&temp_fid, NULL);
	
		kfree(path);
		if (ret)
			goto fail;
		fid = &temp_fid;
		temp_open = true;
	}

	buf = kvmalloc(min_t(size_t, remain, VMSMB_MAX_WRITE_CHUNK), GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto close;
	}

	while (remain > 0) {
		u32 chunk = min_t(size_t, remain, VMSMB_MAX_WRITE_CHUNK);
		u32 bytes_written = 0;
		size_t copied;

		copied = copy_from_iter(buf, chunk, &subreq->io_iter);
		if (copied == 0) {
			ret = -EFAULT;
			break;
		}

	
		ret = vmsmb_smb2_write(sess, sbi->tree_id, fid, pos, buf, copied,
				       &bytes_written);
	

		if (ret)
			break;

		pos += bytes_written;
		total += bytes_written;
		remain -= bytes_written;

		if (bytes_written < copied)
			break;
	}

	kvfree(buf);

close:
	if (temp_open) {
	
		vmsmb_smb2_close(sess, sbi->tree_id, &temp_fid);
	
	}
fail:
	netfs_write_subrequest_terminated(subreq,
					  ret ? ret : (ssize_t)total);
}

const struct netfs_request_ops vmsmb_netfs_ops = {
	.init_request	= vmsmb_init_request,
	.issue_read	= vmsmb_issue_read,
	.begin_writeback = vmsmb_begin_writeback,
	.issue_write	= vmsmb_issue_write,
};

/* ---- File operations ---- */

static int vmsmb_file_open(struct inode *inode, struct file *file)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_file_ctx *ctx;
	struct vmsmb_file_info info;
	char *path;
	u32 access = 0;
	u32 disposition;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	path = vmsmb_build_path(file->f_path.dentry);
	if (IS_ERR(path)) {
		kfree(ctx);
		return PTR_ERR(path);
	}

	if (file->f_mode & FMODE_READ)
		access |= VMSMB_READ_ACCESS;
	if (file->f_mode & FMODE_WRITE)
		access |= VMSMB_WRITE_ACCESS;

	if (file->f_flags & O_CREAT) {
		if (file->f_flags & O_EXCL)
			disposition = FILE_CREATE;
		else if (file->f_flags & O_TRUNC)
			disposition = FILE_OVERWRITE_IF;
		else
			disposition = FILE_OPEN_IF;
	} else if (file->f_flags & O_TRUNC) {
		disposition = FILE_OVERWRITE_IF;
	} else {
		disposition = FILE_OPEN;
	}


	ret = vmsmb_smb2_create(sess, sbi->tree_id, path, access, disposition,
				CREATE_NOT_DIR,
				&ctx->fid, &info);


	kfree(path);

	if (ret) {
		kfree(ctx);
		return ret;
	}

	/* Update inode size from server */
	i_size_write(inode, info.size);

	file->private_data = ctx;
	VMSMB_I(inode)->active_ctx = ctx;
	return 0;
}

static int vmsmb_file_release(struct inode *inode, struct file *file)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_file_ctx *ctx = file->private_data;

	if (ctx) {
		if (VMSMB_I(inode)->active_ctx == ctx)
			VMSMB_I(inode)->active_ctx = NULL;

	
		vmsmb_smb2_close(sess, sbi->tree_id, &ctx->fid);
	
		kfree(ctx);
	}
	return 0;
}

static loff_t vmsmb_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);

	return generic_file_llseek_size(file, offset, whence,
					MAX_LFS_FILESIZE,
					i_size_read(inode));
}

/*
 * Flush dirty pages to server.
 * VSMB writes are synchronous, so once netfs writeback completes
 * the data is on the host.  Modelled after cifs_fsync.
 */
static int vmsmb_fsync(struct file *file, loff_t start, loff_t end,
		       int datasync)
{
	int ret;

	ret = file_write_and_wait_range(file, start, end);
	if (ret)
		pr_debug("fsync: write_and_wait error %d\n", ret);
	return ret;
}

const struct file_operations vmsmb_file_ops = {
	.open		= vmsmb_file_open,
	.release	= vmsmb_file_release,
	.read_iter	= netfs_file_read_iter,
	.write_iter	= netfs_unbuffered_write_iter,
	.llseek		= vmsmb_file_llseek,
	.fsync		= vmsmb_fsync,
	.mmap		= generic_file_mmap,
};

/* ---- Directory operations ---- */

/*
 * Convert a UTF-16LE filename to UTF-8.
 *
 * Uses the kernel's utf16s_to_utf8s() (lib/unicode.c), the same
 * function underlying CIFS cifs_from_utf16() (cifs_unicode.c).
 * We skip CIFS's NLS codepage and SFU/SFM character mapping since
 * VSMB doesn't need them.
 */
static int vmsmb_utf16_name_to_utf8(char *dst, size_t dst_size,
				    const char *src, size_t src_len)
{
	const __le16 *name = (const __le16 *)src;
	int wlen = src_len / sizeof(__le16);
	int ret;

	ret = utf16s_to_utf8s((const wchar_t *)name, wlen,
			      UTF16_LITTLE_ENDIAN, dst, dst_size - 1);
	if (ret < 0)
		return ret;
	dst[ret] = '\0';
	return ret;
}

static int vmsmb_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_fid fid;
	char *path;
	void *buf;
	u32 buf_size = 4096;
	u32 data_len;
	int ret;

	if (!dir_emit_dots(file, ctx))
		return 0;

	/* Only scan once — if we've already emitted entries, done */
	if (ctx->pos > 2)
		return 0;

	path = vmsmb_build_path(file->f_path.dentry);
	if (IS_ERR(path))
		return PTR_ERR(path);

	buf = kmalloc(buf_size, GFP_KERNEL);
	if (!buf) {
		kfree(path);
		return -ENOMEM;
	}

	/* Open directory */

	ret = vmsmb_smb2_create(sess, sbi->tree_id, path, VMSMB_DIR_ACCESS,
				FILE_OPEN, CREATE_NOT_FILE,
				&fid, NULL);
	if (ret) {
	
		pr_err("readdir: CREATE '%s' failed: %d\n", path, ret);
		kfree(path);
		kfree(buf);
		return ret;
	}

	/* Query directory entries */
	ret = vmsmb_smb2_query_dir(sess, sbi->tree_id, &fid, "*", buf, buf_size, &data_len);
	pr_debug("readdir: QUERY_DIRECTORY ret=%d data_len=%u\n",
		 ret, ret == 0 ? data_len : 0);

	if (ret == -ENODATA) {
		/* Empty directory */
		ret = 0;
		data_len = 0;
	}

	if (ret == 0 && data_len > 0) {
		/* Parse FILE_DIRECTORY_INFO chain */
		u32 offset = 0;

		while (offset < data_len) {
			const FILE_DIRECTORY_INFO *entry =
				(const FILE_DIRECTORY_INFO *)((u8 *)buf + offset);
			u32 name_len = le32_to_cpu(entry->FileNameLength);
			u32 attrs = le32_to_cpu(entry->ExtFileAttributes);
			unsigned char d_type;
			char name_utf8[256];
			int utf8_len;

			utf8_len = vmsmb_utf16_name_to_utf8(name_utf8,
						      sizeof(name_utf8),
						      entry->FileName,
						      name_len);

			pr_debug("readdir: entry off=%u nlen=%u attrs=0x%x name='%s'\n",
				offset, name_len, attrs, name_utf8);

			/* Skip . and .. (already emitted by dir_emit_dots) */
			if ((utf8_len == 1 && name_utf8[0] == '.') ||
			    (utf8_len == 2 && name_utf8[0] == '.' &&
			     name_utf8[1] == '.'))
				goto next_entry;

			d_type = (attrs & FILE_ATTRIBUTE_REPARSE_POINT) ?
				 DT_LNK :
				 (attrs & FILE_ATTRIBUTE_DIRECTORY) ?
				 DT_DIR : DT_REG;

			if (!dir_emit(ctx, name_utf8, utf8_len,
				      atomic64_inc_return(&vmsmb_ino_counter),
				      d_type))
				break;

			ctx->pos++;

next_entry:
			if (entry->NextEntryOffset == 0)
				break;
			offset += le32_to_cpu(entry->NextEntryOffset);
		}
	}

	/* Close directory */
	vmsmb_smb2_close(sess, sbi->tree_id, &fid);


	kfree(path);
	kfree(buf);
	return ret;
}

const struct file_operations vmsmb_dir_ops = {
	.iterate_shared	= vmsmb_readdir,
	.llseek		= generic_file_llseek,
};

/* ---- Superblock operations ---- */

static struct inode *vmsmb_alloc_inode(struct super_block *sb)
{
	struct vmsmb_inode_info *vi;

	vi = alloc_inode_sb(sb, vmsmb_inode_cachep, GFP_KERNEL);
	if (!vi)
		return NULL;

	vi->active_ctx = NULL;
	vi->symlink_target = NULL;
	return &vi->netfs.inode;
}

static void vmsmb_free_inode(struct inode *inode)
{
	kmem_cache_free(vmsmb_inode_cachep, VMSMB_I(inode));
}

static int vmsmb_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	buf->f_type = 0x564D5342; /* "VMSB" */
	buf->f_bsize = 4096;
	buf->f_namelen = 255;
	/* Report large capacity so tools don't refuse to operate */
	buf->f_blocks = 1024 * 1024 * 1024ULL / 4096; /* 1 TiB */
	buf->f_bfree = 1024 * 1024 * 1024ULL / 4096;
	buf->f_bavail = 1024 * 1024 * 1024ULL / 4096;
	return 0;
}

static void vmsmb_evict_inode(struct inode *inode)
{
	kfree(VMSMB_I(inode)->symlink_target);
	netfs_wait_for_outstanding_io(inode);
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
}

static int vmsmb_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	return netfs_unpin_writeback(inode, wbc);
}

static const struct super_operations vmsmb_super_ops = {
	.alloc_inode	= vmsmb_alloc_inode,
	.free_inode	= vmsmb_free_inode,
	.write_inode	= vmsmb_write_inode,
	.evict_inode	= vmsmb_evict_inode,
	.statfs		= vmsmb_statfs,
};

static int vmsmb_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct vmsmb_sb_info *sbi = sb->s_fs_info;
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_fid root_fid;
	struct vmsmb_file_info root_info;
	struct inode *root_inode;
	int ret;

	sb->s_magic = 0x564D5342;
	sb->s_blocksize = 4096;
	sb->s_blocksize_bits = 12;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_op = &vmsmb_super_ops;
	sb->s_time_gran = 100; /* 100ns Windows FILETIME granularity */

	/* Set up writeback-capable BDI so netfs writepages works */
	ret = super_setup_bdi(sb);
	if (ret)
		return ret;
	sb->s_flags |= SB_ACTIVE;

	/* Query root directory attributes — empty path = share root */

	ret = vmsmb_smb2_create(sess, sbi->tree_id, "", FILE_READ_ATTRIBUTES,
				FILE_OPEN, CREATE_NOT_FILE,
				&root_fid, &root_info);
	if (ret == 0)
		vmsmb_smb2_close(sess, sbi->tree_id, &root_fid);


	if (ret) {
		pr_err("failed to open share root: %d\n", ret);
		return ret;
	}

	root_inode = new_inode(sb);
	if (!root_inode)
		return -ENOMEM;

	root_inode->i_ino = 1;
	vmsmb_fill_inode(root_inode, &root_info);

	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root)
		return -ENOMEM;

	return 0;
}

/* ---- Mount option parsing (fs_context API) ---- */

enum vmsmb_param {
	Opt_uid,
	Opt_gid,
	Opt_file_mode,
	Opt_dir_mode,
	Opt_noperm,
};

static const struct fs_parameter_spec vmsmb_fs_parameters[] = {
	fsparam_u32("uid",		Opt_uid),
	fsparam_u32("gid",		Opt_gid),
	fsparam_u32oct("file_mode",	Opt_file_mode),
	fsparam_u32oct("dir_mode",	Opt_dir_mode),
	fsparam_flag("noperm",		Opt_noperm),
	{}
};

/*
 * Mount context — holds parsed options until get_tree applies them.
 * Modelled after CIFS smb3_fs_context (fs/smb/client/fs_context.c).
 */
struct vmsmb_fs_context {
	kuid_t uid;
	kgid_t gid;
	umode_t file_mode;
	umode_t dir_mode;
	bool uid_set;
	bool gid_set;
	bool file_mode_set;
	bool dir_mode_set;
	bool noperm;
};

static int vmsmb_parse_param(struct fs_context *fc,
			     struct fs_parameter *param)
{
	struct vmsmb_fs_context *ctx = fc->fs_private;
	struct fs_parse_result result;
	int opt;

	opt = fs_parse(fc, vmsmb_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_uid:
		ctx->uid = make_kuid(current_user_ns(), result.uint_32);
		if (!uid_valid(ctx->uid))
			return invalfc(fc, "invalid uid");
		ctx->uid_set = true;
		break;
	case Opt_gid:
		ctx->gid = make_kgid(current_user_ns(), result.uint_32);
		if (!gid_valid(ctx->gid))
			return invalfc(fc, "invalid gid");
		ctx->gid_set = true;
		break;
	case Opt_file_mode:
		ctx->file_mode = result.uint_32 & 0777;
		ctx->file_mode_set = true;
		break;
	case Opt_dir_mode:
		ctx->dir_mode = result.uint_32 & 0777;
		ctx->dir_mode_set = true;
		break;
	case Opt_noperm:
		ctx->noperm = true;
		break;
	}

	return 0;
}

static int vmsmb_get_tree(struct fs_context *fc)
{
	struct vmsmb_fs_context *ctx = fc->fs_private;
	struct vmsmb_sb_info *sbi;
	struct vmsmb_session *sess = vmsmb_global_session;
	const char *dev_name = fc->source;
	int ret;

	if (!sess) {
		pr_err("no VSMB channel available\n");
		return -ENODEV;
	}

	if (!dev_name || !*dev_name) {
		pr_err("share name required (mount -t vsmb ShareName mountpoint)\n");
		return -EINVAL;
	}

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sbi->sess = sess;

	/* Apply parsed mount options, with defaults */
	sbi->uid = ctx->uid_set ? ctx->uid : current_fsuid();
	sbi->gid = ctx->gid_set ? ctx->gid : current_fsgid();
	sbi->file_mode = ctx->file_mode_set ? ctx->file_mode :
					       (S_IRUGO | S_IXUGO | S_IWUSR);
	sbi->dir_mode = ctx->dir_mode_set ? ctx->dir_mode :
					     (S_IRUGO | S_IXUGO | S_IWUSR);
	sbi->noperm = ctx->noperm;

	/* noperm: open all permissions so VFS checks always pass */
	if (sbi->noperm) {
		sbi->file_mode = 0777;
		sbi->dir_mode = 0777;
	}

	sbi->share_name = kstrdup(dev_name, GFP_KERNEL);
	if (!sbi->share_name) {
		kfree(sbi);
		return -ENOMEM;
	}

	/* TREE_CONNECT to the requested share */

	ret = vmsmb_smb2_tree_connect(sess, dev_name, &sbi->tree_id);


	if (ret) {
		pr_err("TREE_CONNECT '%s' failed: %d\n", dev_name, ret);
		kfree(sbi->share_name);
		kfree(sbi);
		return ret;
	}

	fc->s_fs_info = sbi;

	return get_tree_nodev(fc, vmsmb_fill_super);
}

static void vmsmb_free_fc(struct fs_context *fc)
{
	kfree(fc->fs_private);
}

static const struct fs_context_operations vmsmb_context_ops = {
	.parse_param	= vmsmb_parse_param,
	.get_tree	= vmsmb_get_tree,
	.free		= vmsmb_free_fc,
};

static int vmsmb_init_fs_context(struct fs_context *fc)
{
	struct vmsmb_fs_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	fc->fs_private = ctx;
	fc->ops = &vmsmb_context_ops;
	return 0;
}

static void vmsmb_kill_sb(struct super_block *sb)
{
	struct vmsmb_sb_info *sbi = sb->s_fs_info;

	kill_anon_super(sb);

	if (sbi) {
		/* TODO: TREE_DISCONNECT */
		kfree(sbi->share_name);
		kfree(sbi);
	}
}

struct file_system_type vmsmb_fs_type = {
	.owner			= THIS_MODULE,
	.name			= "vsmb",
	.init_fs_context	= vmsmb_init_fs_context,
	.parameters		= vmsmb_fs_parameters,
	.kill_sb		= vmsmb_kill_sb,
};
