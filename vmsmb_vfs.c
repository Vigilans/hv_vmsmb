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
#include "vmsmb.h"
#include "smb2pdu.h"
#include "fscc.h"

/* SMB2 access masks */
#define VMSMB_READ_ACCESS	(FILE_READ_DATA | FILE_READ_ATTRIBUTES | \
				 GENERIC_READ)
#define VMSMB_WRITE_ACCESS	(FILE_WRITE_DATA | FILE_APPEND_DATA | \
				 FILE_WRITE_ATTRIBUTES | GENERIC_WRITE)
#define VMSMB_RW_ACCESS		(VMSMB_READ_ACCESS | VMSMB_WRITE_ACCESS)
#define VMSMB_DIR_ACCESS	(FILE_READ_DATA | FILE_READ_ATTRIBUTES | \
				 GENERIC_READ)

/* SMB2 create dispositions */
#define VMSMB_FILE_OPEN		0x01
#define VMSMB_FILE_CREATE	0x02
#define VMSMB_FILE_OPEN_IF	0x03
#define VMSMB_FILE_OVERWRITE_IF	0x05

/* SMB2 create options */
#define VMSMB_FILE_DIRECTORY	0x01
#define VMSMB_FILE_NON_DIRECTORY	0x40
#define VMSMB_FILE_DELETE_ON_CLOSE	0x1000

/* Inode number counter */
static atomic64_t vmsmb_ino_counter = ATOMIC64_INIT(2);

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
	if (info->attributes & FILE_ATTRIBUTE_DIRECTORY) {
		inode->i_mode = S_IFDIR | 0755;
		inode->i_op = &vmsmb_dir_inode_ops;
		inode->i_fop = &vmsmb_dir_ops;
		set_nlink(inode, 2);
	} else {
		inode->i_mode = S_IFREG | 0644;
		inode->i_op = &vmsmb_file_inode_ops;
		inode->i_fop = &vmsmb_file_ops;
		set_nlink(inode, 1);
	}

	i_size_write(inode, info->size);
	inode->i_blocks = (info->alloc_size + 511) / 512;
	inode_set_atime_to_ts(inode, vmsmb_time_to_ts(info->last_access_time));
	inode_set_mtime_to_ts(inode, vmsmb_time_to_ts(info->last_write_time));
	inode_set_ctime_to_ts(inode, vmsmb_time_to_ts(info->change_time));
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

	mutex_lock(&sess->transport_mutex);
	ret = vmsmb_smb2_create(sess, path, VMSMB_DIR_ACCESS,
				VMSMB_FILE_OPEN, 0, &fid, &info);
	if (ret == 0)
		vmsmb_smb2_close(sess, &fid);
	mutex_unlock(&sess->transport_mutex);

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

	mutex_lock(&sess->transport_mutex);
	ret = vmsmb_smb2_create(sess, path, VMSMB_RW_ACCESS,
				excl ? VMSMB_FILE_CREATE : VMSMB_FILE_OPEN_IF,
				VMSMB_FILE_NON_DIRECTORY, &fid, &info);
	if (ret == 0)
		vmsmb_smb2_close(sess, &fid);
	mutex_unlock(&sess->transport_mutex);

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

	mutex_lock(&sess->transport_mutex);
	ret = vmsmb_smb2_create(sess, path, VMSMB_DIR_ACCESS,
				VMSMB_FILE_CREATE, VMSMB_FILE_DIRECTORY,
				&fid, &info);
	if (ret == 0)
		vmsmb_smb2_close(sess, &fid);
	mutex_unlock(&sess->transport_mutex);

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
	struct vmsmb_fid fid;
	char *path;
	int ret;

	path = vmsmb_build_path(dentry);
	if (IS_ERR(path))
		return PTR_ERR(path);

	mutex_lock(&sess->transport_mutex);
	ret = vmsmb_smb2_create(sess, path, 0x00010000 /* DELETE */,
				VMSMB_FILE_OPEN,
				VMSMB_FILE_DELETE_ON_CLOSE |
				VMSMB_FILE_NON_DIRECTORY,
				&fid, NULL);
	if (ret == 0)
		vmsmb_smb2_close(sess, &fid);
	mutex_unlock(&sess->transport_mutex);

	kfree(path);

	if (ret == 0) {
		if (d_inode(dentry))
			drop_nlink(d_inode(dentry));
		d_delete(dentry);
	}
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

	mutex_lock(&sess->transport_mutex);
	ret = vmsmb_smb2_create(sess, path, 0x00010000 /* DELETE */,
				VMSMB_FILE_OPEN,
				VMSMB_FILE_DELETE_ON_CLOSE |
				VMSMB_FILE_DIRECTORY,
				&fid, NULL);
	if (ret == 0)
		vmsmb_smb2_close(sess, &fid);
	mutex_unlock(&sess->transport_mutex);

	kfree(path);

	if (ret == 0) {
		drop_nlink(d_inode(dentry));
		drop_nlink(dir);
		d_delete(dentry);
	}
	return ret;
}

const struct inode_operations vmsmb_dir_inode_ops = {
	.lookup		= vmsmb_lookup,
	.getattr	= vmsmb_getattr,
	.create		= vmsmb_create,
	.mkdir		= vmsmb_mkdir,
	.unlink		= vmsmb_unlink,
	.rmdir		= vmsmb_rmdir,
};

const struct inode_operations vmsmb_file_inode_ops = {
	.getattr	= vmsmb_getattr,
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
			disposition = VMSMB_FILE_CREATE;
		else if (file->f_flags & O_TRUNC)
			disposition = VMSMB_FILE_OVERWRITE_IF;
		else
			disposition = VMSMB_FILE_OPEN_IF;
	} else if (file->f_flags & O_TRUNC) {
		disposition = VMSMB_FILE_OVERWRITE_IF;
	} else {
		disposition = VMSMB_FILE_OPEN;
	}

	mutex_lock(&sess->transport_mutex);
	ret = vmsmb_smb2_create(sess, path, access, disposition,
				VMSMB_FILE_NON_DIRECTORY,
				&ctx->fid, &info);
	mutex_unlock(&sess->transport_mutex);

	kfree(path);

	if (ret) {
		kfree(ctx);
		return ret;
	}

	/* Update inode size from server */
	i_size_write(inode, info.size);

	file->private_data = ctx;
	return 0;
}

static int vmsmb_file_release(struct inode *inode, struct file *file)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_file_ctx *ctx = file->private_data;

	if (ctx) {
		mutex_lock(&sess->transport_mutex);
		vmsmb_smb2_close(sess, &ctx->fid);
		mutex_unlock(&sess->transport_mutex);
		kfree(ctx);
	}
	return 0;
}

static ssize_t vmsmb_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_file_ctx *ctx = file->private_data;
	loff_t pos = iocb->ki_pos;
	size_t count = iov_iter_count(to);
	ssize_t total = 0;
	void *buf;
	int ret;

	if (pos >= i_size_read(inode))
		return 0;

	if (pos + count > i_size_read(inode))
		count = i_size_read(inode) - pos;

	buf = kvmalloc(min_t(size_t, count, sess->max_read_size), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	while (count > 0) {
		u32 chunk = min_t(size_t, count, sess->max_read_size);
		u32 bytes_read = 0;

		mutex_lock(&sess->transport_mutex);
		ret = vmsmb_smb2_read(sess, &ctx->fid, pos, chunk,
				      buf, &bytes_read);
		mutex_unlock(&sess->transport_mutex);

		if (ret)
			break;
		if (bytes_read == 0)
			break;

		if (copy_to_iter(buf, bytes_read, to) != bytes_read) {
			ret = -EFAULT;
			break;
		}

		pos += bytes_read;
		total += bytes_read;
		count -= bytes_read;

		if (bytes_read < chunk)
			break;
	}

	kvfree(buf);
	iocb->ki_pos = pos;
	return total > 0 ? total : ret;
}

static ssize_t vmsmb_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_file_ctx *ctx = file->private_data;
	loff_t pos = iocb->ki_pos;
	size_t count = iov_iter_count(from);
	ssize_t total = 0;
	void *buf;
	int ret = 0;

	if (iocb->ki_flags & IOCB_APPEND)
		pos = i_size_read(inode);

	buf = kvmalloc(min_t(size_t, count, sess->max_write_size), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	while (count > 0) {
		u32 chunk = min_t(size_t, count, sess->max_write_size);
		u32 bytes_written = 0;
		size_t copied;

		copied = copy_from_iter(buf, chunk, from);
		if (copied == 0) {
			ret = -EFAULT;
			break;
		}

		mutex_lock(&sess->transport_mutex);
		ret = vmsmb_smb2_write(sess, &ctx->fid, pos, buf,
				       copied, &bytes_written);
		mutex_unlock(&sess->transport_mutex);

		if (ret)
			break;

		pos += bytes_written;
		total += bytes_written;
		count -= bytes_written;

		if (pos > i_size_read(inode))
			i_size_write(inode, pos);

		if (bytes_written < copied)
			break;
	}

	kvfree(buf);
	iocb->ki_pos = pos;
	return total > 0 ? total : ret;
}

static loff_t vmsmb_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);

	return generic_file_llseek_size(file, offset, whence,
					MAX_LFS_FILESIZE,
					i_size_read(inode));
}

const struct file_operations vmsmb_file_ops = {
	.open		= vmsmb_file_open,
	.release	= vmsmb_file_release,
	.read_iter	= vmsmb_file_read_iter,
	.write_iter	= vmsmb_file_write_iter,
	.llseek		= vmsmb_file_llseek,
};

/* ---- Directory operations ---- */

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
	mutex_lock(&sess->transport_mutex);
	ret = vmsmb_smb2_create(sess, path, VMSMB_DIR_ACCESS,
				VMSMB_FILE_OPEN, VMSMB_FILE_DIRECTORY,
				&fid, NULL);
	if (ret) {
		mutex_unlock(&sess->transport_mutex);
		pr_err("readdir: CREATE '%s' failed: %d\n", path, ret);
		kfree(path);
		kfree(buf);
		return ret;
	}

	/* Query directory entries */
	ret = vmsmb_smb2_query_dir(sess, &fid, "*", buf, buf_size, &data_len);
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
			int i, utf8_len;

			/* Convert UTF-16LE filename to UTF-8 (ASCII subset) */
			utf8_len = name_len / 2;
			if (utf8_len > (int)sizeof(name_utf8) - 1)
				utf8_len = sizeof(name_utf8) - 1;
			for (i = 0; i < utf8_len; i++) {
				__le16 c;
				memcpy(&c, entry->FileName + i * 2, 2);
				name_utf8[i] = (char)le16_to_cpu(c);
			}
			name_utf8[utf8_len] = '\0';

			pr_debug("readdir: entry off=%u nlen=%u attrs=0x%x name='%s'\n",
				offset, name_len, attrs, name_utf8);

			/* Skip . and .. (already emitted by dir_emit_dots) */
			if ((utf8_len == 1 && name_utf8[0] == '.') ||
			    (utf8_len == 2 && name_utf8[0] == '.' &&
			     name_utf8[1] == '.'))
				goto next_entry;

			d_type = (attrs & FILE_ATTRIBUTE_DIRECTORY) ?
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
	vmsmb_smb2_close(sess, &fid);
	mutex_unlock(&sess->transport_mutex);

	kfree(path);
	kfree(buf);
	return ret;
}

const struct file_operations vmsmb_dir_ops = {
	.iterate_shared	= vmsmb_readdir,
	.llseek		= generic_file_llseek,
};

/* ---- Superblock operations ---- */

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

static const struct super_operations vmsmb_super_ops = {
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

	/* Query root directory attributes — empty path = share root */
	mutex_lock(&sess->transport_mutex);
	ret = vmsmb_smb2_create(sess, "", FILE_READ_ATTRIBUTES,
				VMSMB_FILE_OPEN, VMSMB_FILE_DIRECTORY,
				&root_fid, &root_info);
	if (ret == 0)
		vmsmb_smb2_close(sess, &root_fid);
	mutex_unlock(&sess->transport_mutex);

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

static int vmsmb_get_tree(struct fs_context *fc)
{
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
	sbi->share_name = kstrdup(dev_name, GFP_KERNEL);
	if (!sbi->share_name) {
		kfree(sbi);
		return -ENOMEM;
	}

	/* TREE_CONNECT to the requested share */
	mutex_lock(&sess->transport_mutex);
	ret = vmsmb_smb2_tree_connect(sess, dev_name);
	mutex_unlock(&sess->transport_mutex);

	if (ret) {
		pr_err("TREE_CONNECT '%s' failed: %d\n", dev_name, ret);
		kfree(sbi->share_name);
		kfree(sbi);
		return ret;
	}

	sbi->tree_id = sess->tree_id;
	fc->s_fs_info = sbi;

	return get_tree_nodev(fc, vmsmb_fill_super);
}

static void vmsmb_free_fc(struct fs_context *fc)
{
	/* sbi is freed in kill_sb if mount succeeded */
}

static const struct fs_context_operations vmsmb_context_ops = {
	.get_tree	= vmsmb_get_tree,
	.free		= vmsmb_free_fc,
};

static int vmsmb_init_fs_context(struct fs_context *fc)
{
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
	.kill_sb		= vmsmb_kill_sb,
};
