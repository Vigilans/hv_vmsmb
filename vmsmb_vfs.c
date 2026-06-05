// SPDX-License-Identifier: GPL-2.0
/*
 * vmsmb_vfs.c - VFS integration for VSMB filesystem
 *
 * Implements mount/umount, inode operations, file operations,
 * and directory operations for the vsmb filesystem type.
 */

#define pr_fmt(fmt) "hv_vmsmb: " fmt

#include <linux/module.h>
#include <linux/version.h>
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
 * Force the next access to re-fetch this directory's metadata from the
 * server.  Used after operations that change the parent dir's mtime/
 * ctime (create/mkdir/unlink/rmdir/rename/symlink/link), so subsequent
 * stat / readdir / negative-dentry probes don't serve stale attrs from
 * the actimeo cache.
 *
 * Port of CIFS cifs_unlink / cifs_rmdir / cifs_mkdir / cifs_create
 * pattern of clearing cifsInode->time on the parent inode after a
 * mutation (fs/smb/client/inode.c).  CIFS uses time=0 (absolute);
 * we use jiffies-1 so vmsmb_d_revalidate's time_after(jiffies,
 * meta_expires) check is true even when the next access lands on the
 * same jiffy as the invalidate (HZ=1000 → 1 ms granularity, fast
 * mutations like mkdir/unlink can complete and be re-stat'd within
 * one jiffy and would otherwise still see cached attrs).
 */
static inline void vmsmb_invalidate_dir(struct inode *dir)
{
	if (dir)
		VMSMB_I(dir)->meta_expires = jiffies - 1;
}

/*
 * Fill an inode with SMB2 file attributes.
 *
 * Port of CIFS cifs_fattr_to_inode() (fs/smb/client/inode.c) initial-fill
 * path: set mode/ops by attribute bits, size, times, then attach the netfs
 * context (cifs_set_netfs_context() → netfs_inode_init() equivalent).
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

	VMSMB_I(inode)->meta_expires = jiffies + sbi->actimeo;
}

/*
 * Refresh mutable metadata on an existing inode from a new CREATE/QUERY
 * response. Called when iget5_locked finds an already-hashed inode —
 * type/ops/uid/gid are immutable, but size/times may have changed.
 *
 * Port of CIFS cifs_fattr_to_inode() update-path (fs/smb/client/inode.c).
 */
static void vmsmb_refresh_inode(struct inode *inode,
				const struct vmsmb_file_info *info)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_inode_info *vi = VMSMB_I(inode);
	loff_t old_size = i_size_read(inode);
	loff_t new_size = info->size;
	struct timespec64 old_mtime = inode_get_mtime(inode);
	struct timespec64 new_mtime = vmsmb_time_to_ts(info->last_write_time);

	if (old_size != new_size) {
		/* Truncate page cache beyond new EOF to avoid serving stale data */
		i_size_write(inode, new_size);
		if (new_size < old_size)
			truncate_pagecache(inode, new_size);
	}
	inode->i_blocks = (info->alloc_size + 511) / 512;
	inode_set_atime_to_ts(inode, vmsmb_time_to_ts(info->last_access_time));
	inode_set_mtime_to_ts(inode, new_mtime);
	inode_set_ctime_to_ts(inode, vmsmb_time_to_ts(info->change_time));

	/*
	 * If mtime advanced on the server, the file content has changed;
	 * invalidate cached pages to force re-read. Port of CIFS
	 * cifs_revalidate_mapping (fs/smb/client/inode.c).
	 */
	if (S_ISREG(inode->i_mode) &&
	    timespec64_compare(&new_mtime, &old_mtime) != 0) {
		invalidate_inode_pages2(inode->i_mapping);
	}

	vi->meta_expires = jiffies + sbi->actimeo;
}

struct vmsmb_iget_args {
	u64 index_number;
	const struct vmsmb_file_info *info;
};

static int vmsmb_iget_test(struct inode *inode, void *opaque)
{
	struct vmsmb_iget_args *args = opaque;
	struct vmsmb_inode_info *vi = VMSMB_I(inode);

	return vi->index_number != 0 && vi->index_number == args->index_number;
}

static int vmsmb_iget_set(struct inode *inode, void *opaque)
{
	struct vmsmb_iget_args *args = opaque;
	struct vmsmb_inode_info *vi = VMSMB_I(inode);

	vi->index_number = args->index_number;
	inode->i_ino = args->index_number ?
		args->index_number :
		atomic64_inc_return(&vmsmb_ino_counter);
	return 0;
}

/*
 * Look up or allocate an inode keyed on the NTFS file reference number
 * (index_number from the QFid create context). Two dentries pointing at
 * the same underlying file (hardlinks) get the same inode, so dentry
 * cache and i_nlink are accurate.
 *
 * If index_number is 0 (server didn't return QFid), fall back to an
 * anonymous inode with a fresh counter-allocated ino — no dedup, but
 * still correct single-dentry semantics.
 *
 * Port of CIFS cifs_iget() (fs/smb/client/inode.c) using iget5_locked.
 */
static struct inode *vmsmb_iget(struct super_block *sb,
				const struct vmsmb_file_info *info)
{
	struct vmsmb_iget_args args = {
		.index_number = info->index_number,
		.info = info,
	};
	struct inode *inode;

	if (!info->index_number) {
		inode = new_inode(sb);
		if (!inode)
			return ERR_PTR(-ENOMEM);
		inode->i_ino = atomic64_inc_return(&vmsmb_ino_counter);
		vmsmb_fill_inode(inode, info);
		return inode;
	}

	inode = iget5_locked(sb, (unsigned long)info->index_number,
			     vmsmb_iget_test, vmsmb_iget_set, &args);
	if (!inode)
		return ERR_PTR(-ENOMEM);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
	if (inode_state_read(inode) & I_NEW) {
#else
	if (inode->i_state & I_NEW) {
#endif
		vmsmb_fill_inode(inode, info);
		unlock_new_inode(inode);
	} else {
		vmsmb_refresh_inode(inode, info);
	}
	return inode;
}

/*
 * Build the SMB2 path from a dentry.
 * Returns a kmalloc'd string like "" (root), "file.txt", "dir/file.txt".
 *
 * Simplified from CIFS build_path_from_dentry() (fs/smb/client/dir.c):
 * CIFS handles DFS tree prefixes and backslash conversion here; VSMB uses
 * forward slashes on the wire (the server accepts both) so we only strip
 * the leading '/' from dentry_path_raw().
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
 * Simplified from CIFS smb2_parse_native_symlink() (fs/smb/client/reparse.c).
 *
 * When symlinkroot is set and the target is an absolute NT path with a
 * drive letter (e.g. \??\C:\foo), translate it to {symlinkroot}/c/foo.
 * Otherwise just strip NT prefix and convert \ to /.
 */
static char *vmsmb_parse_reparse(const void *buf, u32 buf_len,
				 const char *symlinkroot)
{
	const struct reparse_data_buffer *hdr = buf;
	const u8 *name_start;
	u16 name_off, name_len;
	u32 tag, valid_len, pathbuf_off;
	char *smb_target, *result, *abs_path, *p;
	bool relative = false;
	int utf8_len;

	if (buf_len < sizeof(*hdr))
		return ERR_PTR(-EINVAL);

	valid_len = sizeof(*hdr) + le16_to_cpu(hdr->ReparseDataLength);
	if (valid_len > buf_len)
		return ERR_PTR(-EINVAL);
	buf_len = valid_len;

	tag = le32_to_cpu(hdr->ReparseTag);

	if (tag == IO_REPARSE_TAG_SYMLINK) {
		const struct reparse_symlink_data_buffer *sym = buf;

		if (buf_len < sizeof(*sym))
			return ERR_PTR(-EINVAL);

		name_off = le16_to_cpu(sym->SubstituteNameOffset);
		name_len = le16_to_cpu(sym->SubstituteNameLength);
		pathbuf_off = offsetof(struct reparse_symlink_data_buffer, PathBuffer);
		relative = !!(le32_to_cpu(sym->Flags) & SYMLINK_FLAG_RELATIVE);
	} else if (tag == IO_REPARSE_TAG_MOUNT_POINT) {
		const struct reparse_mount_point_data_buffer *mnt = buf;

		if (buf_len < sizeof(*mnt))
			return ERR_PTR(-EINVAL);

		name_off = le16_to_cpu(mnt->SubstituteNameOffset);
		name_len = le16_to_cpu(mnt->SubstituteNameLength);
		pathbuf_off = offsetof(struct reparse_mount_point_data_buffer, PathBuffer);
	} else {
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (!name_len || (name_len & 1))
		return ERR_PTR(-EINVAL);
	if (pathbuf_off > buf_len || name_off > buf_len - pathbuf_off ||
	    name_len > buf_len - pathbuf_off - name_off)
		return ERR_PTR(-EINVAL);
	name_start = (const u8 *)buf + pathbuf_off + name_off;

	/* UTF-16LE → UTF-8 (keep backslashes for prefix matching) */
	smb_target = kmalloc(name_len * 2 + 1, GFP_KERNEL);
	if (!smb_target)
		return ERR_PTR(-ENOMEM);

	utf8_len = utf16s_to_utf8s((const wchar_t *)name_start,
				    name_len / sizeof(__le16),
				    UTF16_LITTLE_ENDIAN, smb_target,
				    name_len * 2);
	if (utf8_len < 0) {
		kfree(smb_target);
		return ERR_PTR(-EINVAL);
	}
	smb_target[utf8_len] = '\0';

	/*
	 * Absolute NT path with symlinkroot set: translate drive letter.
	 * Port of CIFS smb2_parse_native_symlink (fs/smb/client/reparse.c).
	 */
	if (symlinkroot && !relative) {
		abs_path = smb_target;
globalroot:
		if (strstarts(abs_path, "\\??\\"))
			abs_path += sizeof("\\??\\") - 1;
		else if (strstarts(abs_path, "\\DosDevices\\"))
			abs_path += sizeof("\\DosDevices\\") - 1;
		else if (strstarts(abs_path, "\\GLOBAL??\\"))
			abs_path += sizeof("\\GLOBAL??\\") - 1;
		else
			goto out_no_translate;

		if (abs_path[0] == '\\')
			abs_path++;

		while (strstarts(abs_path, "Global\\"))
			abs_path += sizeof("Global\\") - 1;

		if (strstarts(abs_path, "GLOBALROOT\\")) {
			abs_path += sizeof("GLOBALROOT") - 1;
			goto globalroot;
		}

		/* Only drive-letter paths: X:\... or X: */
		if (((abs_path[0] >= 'A' && abs_path[0] <= 'Z') ||
		     (abs_path[0] >= 'a' && abs_path[0] <= 'z')) &&
		    abs_path[1] == ':' &&
		    (abs_path[2] == '\\' || abs_path[2] == '\0')) {
			char drive_letter = abs_path[0];
			int symroot_len = strlen(symlinkroot);
			int abs_len;

			if (drive_letter >= 'A' && drive_letter <= 'Z')
				drive_letter += 'a' - 'A';
			/* Drop colon: "C:\foo" → "\c\foo" in-place */
			abs_path++;
			abs_path[0] = drive_letter;

			/* Convert remaining \ → / */
			for (p = abs_path; *p; p++)
				if (*p == '\\')
					*p = '/';

			if (symlinkroot[symroot_len - 1] == '/')
				symroot_len--;
			abs_len = strlen(abs_path) + 1;

			result = kmalloc(symroot_len + 1 + abs_len, GFP_KERNEL);
			if (!result) {
				kfree(smb_target);
				return ERR_PTR(-ENOMEM);
			}
			memcpy(result, symlinkroot, symroot_len);
			result[symroot_len] = '/';
			memcpy(result + symroot_len + 1, abs_path, abs_len);
			kfree(smb_target);
			return result;
		}
		/* Non-drive-letter absolute path: fall through to plain conversion */
	}

out_no_translate:
	/* Plain conversion: \ → / and strip NT prefix if present */
	for (p = smb_target; *p; p++)
		if (*p == '\\')
			*p = '/';

	p = smb_target;
	if (strncmp(p, "/??/", 4) == 0)
		p += 4;
	else if (strncmp(p, "/DosDevices/", 12) == 0)
		p += 12;

	if (p != smb_target) {
		utf8_len = strlen(p);
		memmove(smb_target, p, utf8_len + 1);
	}

	return smb_target;
}

/* ---- Dentry operations ---- */

/*
 * Revalidate a dentry by checking whether its inode's metadata TTL has
 * expired. Returning 0 invalidates the dentry and forces VFS to re-invoke
 * lookup, which goes through iget5_locked → vmsmb_refresh_inode to pull
 * fresh size/mtime from the server.
 *
 * Port of CIFS cifs_d_revalidate() (fs/smb/client/dir.c) minus the
 * oplock / lease machinery we don't have.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
static int vmsmb_d_revalidate(struct inode *dir, const struct qstr *name,
			      struct dentry *dentry, unsigned int flags)
#else
static int vmsmb_d_revalidate(struct dentry *dentry, unsigned int flags)
#endif
{
	struct inode *inode;
	struct vmsmb_inode_info *vi;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	inode = d_inode(dentry);
	if (!inode) {
		/* Negative dentry: trust it only while parent's TTL is valid.
		 * Otherwise the host may have created the file and we'd never
		 * notice. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
		struct dentry *parent = dget_parent(dentry);
		struct inode *dir = d_inode(parent);
#endif
		int ret = 1;

		if (dir) {
			vi = VMSMB_I(dir);
			if (time_after(jiffies, vi->meta_expires))
				ret = 0;
		}
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
		dput(parent);
#endif
		return ret;
	}

	vi = VMSMB_I(inode);
	if (time_after(jiffies, vi->meta_expires)) {
		struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
		struct vmsmb_session *sess = sbi->sess;
		struct vmsmb_file_info info;
		char *path;
		int ret;

		path = vmsmb_build_path(dentry);
		if (IS_ERR(path))
			return 1;

		ret = vmsmb_smb2_create_close(sess, sbi->tree_id, path,
					      FILE_READ_ATTRIBUTES, FILE_OPEN,
					      OPEN_REPARSE_POINT, &info);
		kfree(path);

		if (ret == -ENOENT || ret == -ESTALE)
			return 0;
		if (ret == 0)
			vmsmb_refresh_inode(inode, &info);
	}

	return 1;
}

static const struct dentry_operations vmsmb_dentry_ops = {
	.d_revalidate	= vmsmb_d_revalidate,
};

/* ---- Inode operations ---- */

/*
 * Look up a dentry in a directory.
 *
 * Port of CIFS cifs_lookup() (fs/smb/client/dir.c): issues a compound
 * CREATE+CLOSE probe to test existence and fetch metadata; on ENOENT
 * returns a negative dentry (so VFS caches the miss under actimeo TTL).
 * Reparse points trigger a follow-up FSCTL_GET_REPARSE_POINT to resolve
 * and cache the symlink target.
 */
static struct dentry *vmsmb_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(dir->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_file_info info;
	struct inode *inode;
	char *path;
	int ret;

	path = vmsmb_build_path(dentry);
	if (IS_ERR(path))
		return ERR_CAST(path);

	ret = vmsmb_smb2_create_close(sess, sbi->tree_id, path,
				      FILE_READ_ATTRIBUTES, FILE_OPEN,
				      OPEN_REPARSE_POINT,
				      &info);
	kfree(path);

	if (ret == -ENOENT)
		return d_splice_alias(NULL, dentry);
	if (ret)
		return ERR_PTR(ret);

	inode = vmsmb_iget(dir->i_sb, &info);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

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

		target = vmsmb_parse_reparse(reparse_buf, reparse_len,
					     sbi->symlinkroot);
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

/*
 * Return file attributes for stat()-family syscalls.
 *
 * Port of CIFS cifs_getattr() (fs/smb/client/inode.c): if the inode's
 * metadata TTL expired, refresh from the server via CREATE+CLOSE probe
 * before calling generic_fillattr(). Otherwise the cached attrs suffice.
 */
static int vmsmb_getattr(struct mnt_idmap *idmap,
			 const struct path *path,
			 struct kstat *stat, u32 request_mask,
			 unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct vmsmb_inode_info *vi = VMSMB_I(inode);
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);

	/*
	 * Refresh metadata from the server if the TTL has expired.
	 * Port of CIFS cifs_getattr (fs/smb/client/inode.c) without
	 * the oplock-held fast path.
	 */
	if (time_after(jiffies, vi->meta_expires)) {
		struct vmsmb_file_info info;
		char *spath;
		int ret;

		spath = vmsmb_build_path(path->dentry);
		if (!IS_ERR(spath)) {
			ret = vmsmb_smb2_create_close(sbi->sess, sbi->tree_id, spath,
						      FILE_READ_ATTRIBUTES, FILE_OPEN,
						      OPEN_REPARSE_POINT, &info);
			if (ret == 0)
				vmsmb_refresh_inode(inode, &info);
			kfree(spath);
		}
	}

	generic_fillattr(idmap, request_mask, inode, stat);
	return 0;
}

/*
 * Create a regular file.
 *
 * Port of CIFS cifs_create() (fs/smb/client/dir.c): CREATE with
 * FILE_CREATE disposition, then CLOSE — we don't keep the handle open
 * since generic open() will reopen it through vmsmb_file_open.
 */
static int vmsmb_create(struct mnt_idmap *idmap, struct inode *dir,
			struct dentry *dentry, umode_t mode, bool excl)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(dir->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_file_info info;
	struct inode *inode;
	char *path;
	int ret;

	path = vmsmb_build_path(dentry);
	if (IS_ERR(path))
		return PTR_ERR(path);

	ret = vmsmb_smb2_create_close(sess, sbi->tree_id, path,
				      VMSMB_RW_ACCESS,
				      excl ? FILE_CREATE : FILE_OPEN_IF,
				      CREATE_NOT_DIR, &info);

	kfree(path);

	if (ret)
		return ret;

	inode = vmsmb_iget(dir->i_sb, &info);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	vmsmb_invalidate_dir(dir);
	d_instantiate(dentry, inode);
	return 0;
}

/*
 * Atomic open: fold lookup + create + open into a single SMB2 CREATE.
 *
 * Port of CIFS cifs_atomic_open() (fs/smb/client/dir.c).  Without this,
 * O_CREAT opens take 4 round-trips (lookup CREATE+CLOSE → vmsmb_create
 * CREATE+CLOSE → vmsmb_file_open CREATE).  With it, a single CREATE
 * suffices: the response carries the file_info needed to populate the
 * inode, and the returned fid is stashed in file->private_data for
 * subsequent read/write.
 *
 * Non-O_CREAT opens fall back to the lookup + .open path — matches CIFS
 * (dir.c:540-549), since the client can't tell from the dentry alone
 * whether the target is a regular file or a directory, and a CREATE
 * round-trip to discover that is wasteful.
 */
static int vmsmb_atomic_open(struct inode *dir, struct dentry *dentry,
			     struct file *file, unsigned int open_flag,
			     umode_t mode)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(dir->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_file_ctx *ctx;
	struct vmsmb_file_info info;
	struct inode *inode;
	struct dentry *alias;
	char *path;
	u32 access = 0;
	u32 disposition;
	int ret;

	if (!(open_flag & O_CREAT)) {
		if (!d_in_lookup(dentry))
			return -ENOENT;
		return finish_no_open(file, vmsmb_lookup(dir, dentry, 0));
	}

	/* CIFS __cifs_do_create() dir.c:311-323 */
	if (open_flag & O_EXCL)
		disposition = FILE_CREATE;
	else if (open_flag & O_TRUNC)
		disposition = FILE_OVERWRITE_IF;
	else
		disposition = FILE_OPEN_IF;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	path = vmsmb_build_path(dentry);
	if (IS_ERR(path)) {
		kfree(ctx);
		return PTR_ERR(path);
	}

	if (file->f_mode & FMODE_READ)
		access |= VMSMB_READ_ACCESS;
	if (file->f_mode & FMODE_WRITE)
		access |= VMSMB_WRITE_ACCESS;

	ret = vmsmb_smb2_create(sess, sbi->tree_id, path, access, disposition,
				CREATE_NOT_DIR, &ctx->fid, &info);
	kfree(path);
	if (ret) {
		kfree(ctx);
		return ret;
	}

	inode = vmsmb_iget(dir->i_sb, &info);
	if (IS_ERR(inode)) {
		vmsmb_smb2_close(sess, sbi->tree_id, &ctx->fid);
		kfree(ctx);
		return PTR_ERR(inode);
	}

	/* CIFS dir.c:582-588 */
	if (d_in_lookup(dentry)) {
		alias = d_splice_alias(inode, dentry);
		if (IS_ERR(alias)) {
			vmsmb_smb2_close(sess, sbi->tree_id, &ctx->fid);
			kfree(ctx);
			return PTR_ERR(alias);
		}
		if (alias)
			dentry = alias;
	} else {
		d_instantiate(dentry, inode);
	}

	refcount_set(&ctx->ref, 1);
	ctx->sess = sess;
	ctx->tree_id = sbi->tree_id;
	file->private_data = ctx;
	VMSMB_I(inode)->active_ctx = ctx;
	i_size_write(inode, info.size);

	/* CIFS dir.c:590-591 — only when we know the file was just created */
	if ((open_flag & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL))
		file->f_mode |= FMODE_CREATED;

	ret = finish_open(file, dentry, generic_file_open);
	if (ret) {
		vmsmb_smb2_close(sess, sbi->tree_id, &ctx->fid);
		VMSMB_I(inode)->active_ctx = NULL;
		file->private_data = NULL;
		kfree(ctx);
	}
	return ret;
}

/*
 * Create a directory.
 *
 * Port of CIFS cifs_mkdir() (fs/smb/client/inode.c): CREATE with
 * FILE_DIRECTORY_FILE + FILE_CREATE, then CLOSE.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
static struct dentry *vmsmb_mkdir(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, umode_t mode)
#else
static int vmsmb_mkdir(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, umode_t mode)
#endif
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(dir->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_file_info info;
	struct inode *inode;
	char *path;
	int ret;

	path = vmsmb_build_path(dentry);
	if (IS_ERR(path)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
		return ERR_CAST(path);
#else
		return PTR_ERR(path);
#endif
	}

	ret = vmsmb_smb2_create_close(sess, sbi->tree_id, path,
				      VMSMB_DIR_ACCESS, FILE_CREATE,
				      CREATE_NOT_FILE, &info);

	kfree(path);

	if (ret) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
		return ERR_PTR(ret);
#else
		return ret;
#endif
	}

	inode = vmsmb_iget(dir->i_sb, &info);
	if (IS_ERR(inode)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
		return ERR_CAST(inode);
#else
		return PTR_ERR(inode);
#endif
	}

	vmsmb_invalidate_dir(dir);
	d_instantiate(dentry, inode);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
	return NULL;
#else
	return 0;
#endif
}

/*
 * Remove a file.
 *
 * Port of CIFS cifs_unlink() (fs/smb/client/inode.c), delegates to
 * vmsmb_smb2_unlink() which issues CREATE(DELETE_ON_CLOSE)+CLOSE.
 */
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

	if (ret == 0) {
		drop_nlink(d_inode(dentry));
		vmsmb_invalidate_dir(dir);
	}
	return ret;
}

/*
 * Remove a directory.
 *
 * Port of CIFS cifs_rmdir() (fs/smb/client/inode.c): same DELETE_ON_CLOSE
 * path as unlink; server enforces "directory must be empty".
 *
 * On success clear_nlink() the removed directory's own inode (matches
 * CIFS cifs_rmdir which does the same — the inode is dead, nlink=0
 * marks it as such for any lingering references).  The parent's nlink
 * is intentionally NOT touched: CIFS does not maintain a precise dir
 * nlink client-side either, because vmsmb_fill_inode initialises every
 * directory inode with set_nlink(2) regardless of how many subdirs the
 * server already has.  An accurate inc/drop scheme is impossible with
 * an under-counted starting point, and underflow into nlink=0 trips an
 * inc_nlink() WARN on the next mkdir under that parent.
 */
static int vmsmb_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(dir->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	char *path;
	int ret;

	path = vmsmb_build_path(dentry);
	if (IS_ERR(path))
		return PTR_ERR(path);

	ret = vmsmb_smb2_create_close(sess, sbi->tree_id, path, DELETE,
				      FILE_OPEN,
				      CREATE_DELETE_ON_CLOSE | CREATE_NOT_FILE,
				      NULL);

	kfree(path);

	if (ret == 0) {
		clear_nlink(d_inode(dentry));
		vmsmb_invalidate_dir(dir);
	}
	return ret;
}

/*
 * Rename/move a file or directory.
 *
 * Port of CIFS cifs_rename2() (fs/smb/client/inode.c): delegates to
 * vmsmb_smb2_rename() which issues CREATE(DELETE)+SET_INFO(rename)+CLOSE.
 * RENAME_NOREPLACE flag inverts the ReplaceIfExists field.
 */
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

	if (ret == 0) {
		vmsmb_invalidate_dir(old_dir);
		if (new_dir != old_dir)
			vmsmb_invalidate_dir(new_dir);
	}
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
		vmsmb_invalidate_dir(dir);
	}

	kfree(old_path);
	kfree(new_path);
	return ret;
}

/*
 * Read cached symlink target.
 *
 * Port of CIFS cifs_get_link() (fs/smb/client/cifsfs.c): the target
 * is resolved and cached at lookup time; get_link returns a duplicate
 * that VFS frees through delayed_call.
 */
static const char *vmsmb_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	char *target;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	if (!VMSMB_I(inode)->symlink_target)
		return ERR_PTR(-EOPNOTSUPP);

	target = kstrdup(VMSMB_I(inode)->symlink_target, GFP_KERNEL);
	if (!target)
		return ERR_PTR(-ENOMEM);

	set_delayed_call(done, kfree_link, target);
	return target;
}

/*
 * Create a symlink.
 *
 * Port of CIFS cifs_symlink() (fs/smb/client/cifsfs.c) reparse-point path:
 * create the file then IOCTL(SET_REPARSE_POINT) to install the symlink
 * target. See vmsmb_smb2_create_symlink() for the wire format.
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

	inode = vmsmb_iget(dir->i_sb, &info);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	VMSMB_I(inode)->symlink_target = kstrdup(target, GFP_KERNEL);

	vmsmb_invalidate_dir(dir);
	d_instantiate(dentry, inode);
	return 0;
}

const struct inode_operations vmsmb_symlink_inode_ops = {
	.get_link	= vmsmb_get_link,
	.getattr	= vmsmb_getattr,
};

/*
 * Convert a Linux timespec64 to a Windows FILETIME (100-ns intervals
 * since 1601-01-01). Inverse of vmsmb_time_to_ts().
 *
 * Equivalent to CIFS cifs_UnixTimeToNT() (fs/smb/client/netmisc.c).
 */
static inline u64 vmsmb_ts_to_filetime(struct timespec64 ts)
{
	return (u64)ts.tv_sec * 10000000ULL +
	       (u64)ts.tv_nsec / 100ULL +
	       116444736000000000ULL;
}

/*
 * Push atime/mtime/ctime changes to the server via SMB2 SET_INFO
 * (FileBasicInformation), and size changes via SET_INFO
 * (FileEndOfFileInformation). uid/gid/mode are kept local (matching CIFS
 * default without modefromsid).
 *
 * Port of CIFS cifs_setattr() path (fs/smb/client/inode.c).
 */
static int vmsmb_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			 struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	char *path = NULL;
	int ret;

	ret = setattr_prepare(idmap, dentry, attr);
	if (ret)
		return ret;

	if (attr->ia_valid & ATTR_SIZE) {
		loff_t newsize = attr->ia_size;

		path = vmsmb_build_path(dentry);
		if (IS_ERR(path))
			return PTR_ERR(path);

		ret = vmsmb_smb2_set_eof(sess, sbi->tree_id, path, newsize);
		kfree(path);
		if (ret)
			return ret;

		truncate_setsize(inode, newsize);
	}

	if (attr->ia_valid & (ATTR_ATIME | ATTR_MTIME | ATTR_CTIME)) {
		FILE_BASIC_INFO binfo = {};

		if (attr->ia_valid & ATTR_ATIME)
			binfo.LastAccessTime =
				cpu_to_le64(vmsmb_ts_to_filetime(attr->ia_atime));
		if (attr->ia_valid & ATTR_MTIME)
			binfo.LastWriteTime =
				cpu_to_le64(vmsmb_ts_to_filetime(attr->ia_mtime));
		if (attr->ia_valid & ATTR_CTIME)
			binfo.ChangeTime =
				cpu_to_le64(vmsmb_ts_to_filetime(attr->ia_ctime));

		path = vmsmb_build_path(dentry);
		if (IS_ERR(path))
			return PTR_ERR(path);

		ret = vmsmb_smb2_set_basic_info(sess, sbi->tree_id, path, &binfo);
		kfree(path);
		if (ret)
			return ret;
	}

	setattr_copy(idmap, inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations vmsmb_dir_inode_ops = {
	.lookup		= vmsmb_lookup,
	.getattr	= vmsmb_getattr,
	.setattr	= vmsmb_setattr,
	.create		= vmsmb_create,
	.atomic_open	= vmsmb_atomic_open,
	.mkdir		= vmsmb_mkdir,
	.unlink		= vmsmb_unlink,
	.rmdir		= vmsmb_rmdir,
	.rename		= vmsmb_rename,
	.symlink	= vmsmb_symlink,
	.link		= vmsmb_link,
};

const struct inode_operations vmsmb_file_inode_ops = {
	.getattr	= vmsmb_getattr,
	.setattr	= vmsmb_setattr,
};

/* ---- Address space operations (netfs) ---- */

const struct address_space_operations vmsmb_aops = {
	.read_folio	= netfs_read_folio,
	.readahead	= netfs_readahead,
	.dirty_folio	= netfs_dirty_folio,
	.writepages	= netfs_writepages,
	.release_folio	= netfs_release_folio,
	.invalidate_folio = netfs_invalidate_folio,
	.migrate_folio	= filemap_migrate_folio,
	.direct_IO	= noop_direct_IO,
};

/* ---- netfs request operations ---- */

/*
 * Get dentry path from an inode (for handle-less readahead/writeback).
 * Returns a kmalloc'd path or ERR_PTR. Caller must kfree.
 *
 * Analogous to CIFS build_path_from_dentry() called from the writeback
 * path (fs/smb/client/file.c) when the write is not tied to an open
 * file — wraps d_find_alias + vmsmb_build_path.
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

/*
 * Drop a reference on a file ctx.  When the last reference goes away,
 * send the deferred SMB2 CLOSE and free the ctx.
 *
 * Refs are held by:
 *   - file_open: the user-space-fd reference (released by file_release)
 *   - init_request: each in-flight netfs_io_request (released by free_request)
 *
 * Port of CIFS _cifsFileInfo_put (fs/smb/client/file.c): server->ops->close
 * fires only when the refcount drops to zero, so an in-flight async WRITE
 * always extends the ctx lifetime past the user's close().  Without this,
 * the SMB2 CLOSE PDU could race a pending WRITE PDU on the same fid,
 * letting the host IoManager's NtClose cleanup cancel the still-queued
 * WRITE IRP without producing a matching SMB2 response.
 */
static void vmsmb_file_ctx_put(struct vmsmb_file_ctx *ctx)
{
	if (refcount_dec_and_test(&ctx->ref)) {
		vmsmb_smb2_close(ctx->sess, ctx->tree_id, &ctx->fid);
		kfree(ctx);
	}
}

/*
 * netfs init_request hook — stash the open file context so issue_read /
 * issue_write can use the existing fid without reopening.
 *
 * Port of CIFS cifs_init_request() (fs/smb/client/file.c): CIFS stashes
 * a cifsFileInfo; we stash vmsmb_file_ctx via rreq->netfs_priv. Also
 * advertises the per-subrequest max chunk size so netfs splits large
 * reads into chunks we can each fulfil in one async SMB2 round-trip.
 */
static int vmsmb_init_request(struct netfs_io_request *rreq, struct file *file)
{
	if (file) {
		struct vmsmb_file_ctx *ctx = file->private_data;

		rreq->netfs_priv = ctx; /* vmsmb_file_ctx */
		if (ctx)
			refcount_inc(&ctx->ref);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	rreq->io_streams[0].sreq_max_len = VMSMB_MAX_READ_CHUNK;
#else
	rreq->io_streams[0].submit_max_len = VMSMB_MAX_READ_CHUNK;
#endif
	return 0;
}

/*
 * netfs free_request hook — drop the ref taken in init_request.
 *
 * Port of CIFS cifs_free_request() (fs/smb/client/file.c).  Last ref
 * drop sends the deferred SMB2 CLOSE and frees the ctx.
 */
static void vmsmb_free_request(struct netfs_io_request *rreq)
{
	struct vmsmb_file_ctx *ctx = rreq->netfs_priv;

	if (ctx)
		vmsmb_file_ctx_put(ctx);
}

/*
 * Async completion for issue_read — invoked from workqueue context by
 * vmsmb_read_async_complete. Safe to copy_to_iter() / sleep here.
 *
 * Port of CIFS smb2_readv_callback() → cifs_readahead_to_fscache finish path.
 *
 * Drops the per-READ-PDU ref taken in vmsmb_issue_read fast path (mirror of
 * the WRITE-PDU pattern; preserves the wire-level ctx liveness invariant).
 */
static void vmsmb_issue_read_complete(void *priv, int status,
				      const void *data, u32 len)
{
	struct netfs_io_subrequest *subreq = priv;
	struct vmsmb_file_ctx *ctx = subreq->rreq->netfs_priv;

	if (status) {
		subreq->error = status;
	} else if (len && copy_to_iter(data, len, &subreq->io_iter) != len) {
		subreq->error = -EFAULT;
	} else {
		subreq->transferred = len;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0) || \
    !defined(NETFS_ICTX_WRITETHROUGH) || defined(NETFS_RREQ_SHORT_TRANSFER)
	netfs_read_subreq_terminated(subreq);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	netfs_read_subreq_terminated(subreq, subreq->error, false);
#else
	subreq->transferred = 0;
	netfs_subreq_terminated(subreq,
				subreq->error ? (ssize_t)subreq->error : (ssize_t)len,
				false);
#endif

	if (ctx)
		vmsmb_file_ctx_put(ctx);
}

/*
 * netfs issue_read hook — fulfil one subrequest by issuing SMB2 READ.
 *
 * Port of CIFS cifs_issue_read() (fs/smb/client/file.c). Fast path uses
 * vmsmb_smb2_read_async: netfs has bounded subreq->len to sreq_max_len
 * (VMSMB_MAX_READ_CHUNK), so a single async READ covers it. When no fid
 * is available (readahead outside an open()), fall back to the synchronous
 * CREATE+READ+CLOSE path.
 */
static void vmsmb_issue_read(struct netfs_io_subrequest *subreq)
{
	struct netfs_io_request *rreq = subreq->rreq;
	struct inode *inode = rreq->inode;
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_file_ctx *ctx = rreq->netfs_priv;
	struct vmsmb_fid temp_fid;
	void *buf;
	u32 bytes_read = 0;
	char *path;
	int ret;

	pr_debug("issue_read: ctx=%p pos=%lld len=%zu\n",
		 ctx, (long long)subreq->start, subreq->len);

	/* Fast path: open fid + subreq fits in one chunk → async single-shot */
	if (ctx && subreq->len <= VMSMB_MAX_READ_CHUNK) {
		/* Per-READ-PDU ref: same rationale as WRITE path. */
		refcount_inc(&ctx->ref);
		ret = vmsmb_smb2_read_async(sess, sbi->tree_id, &ctx->fid,
					    subreq->start, subreq->len,
					    vmsmb_issue_read_complete, subreq);
		if (ret == 0)
			return;
		vmsmb_file_ctx_put(ctx);	/* rollback per-PDU ref */
		/* Submit failed — fall through to sync path for graceful error */
		subreq->error = ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0) || \
    !defined(NETFS_ICTX_WRITETHROUGH) || defined(NETFS_RREQ_SHORT_TRANSFER)
		netfs_read_subreq_terminated(subreq);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
		netfs_read_subreq_terminated(subreq, subreq->error, false);
#else
		netfs_subreq_terminated(subreq, (ssize_t)ret, false);
#endif
		return;
	}

	/* Slow path: no fid → transient CREATE+READ+CLOSE */
	path = vmsmb_inode_path(inode);
	if (IS_ERR(path)) {
		subreq->error = PTR_ERR(path);
		goto out;
	}
	ret = vmsmb_smb2_create(sess, sbi->tree_id, path, VMSMB_READ_ACCESS,
				FILE_OPEN, CREATE_NOT_DIR, &temp_fid, NULL);
	kfree(path);
	if (ret) {
		subreq->error = ret;
		goto out;
	}

	buf = kvmalloc(min_t(size_t, subreq->len, VMSMB_MAX_READ_CHUNK),
		       GFP_KERNEL);
	if (!buf) {
		subreq->error = -ENOMEM;
		goto close;
	}

	ret = vmsmb_smb2_read(sess, sbi->tree_id, &temp_fid,
			      subreq->start, subreq->len, buf, &bytes_read);
	if (ret) {
		subreq->error = ret;
	} else if (bytes_read &&
		   copy_to_iter(buf, bytes_read, &subreq->io_iter) != bytes_read) {
		subreq->error = -EFAULT;
	} else {
		subreq->transferred = bytes_read;
	}

	kvfree(buf);
close:
	vmsmb_smb2_close(sess, sbi->tree_id, &temp_fid);
out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0) || \
    !defined(NETFS_ICTX_WRITETHROUGH) || defined(NETFS_RREQ_SHORT_TRANSFER)
	netfs_read_subreq_terminated(subreq);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	netfs_read_subreq_terminated(subreq, subreq->error, false);
#else
	subreq->transferred = 0;
	netfs_subreq_terminated(subreq,
				subreq->error ? (ssize_t)subreq->error : (ssize_t)bytes_read,
				false);
#endif
}

/*
 * netfs begin_writeback hook — advertise the per-subrequest max chunk size.
 *
 * Port of CIFS cifs_begin_writeback() (fs/smb/client/file.c).
 *
 * NOTE: the buffered writeback path is unused in our config
 * (.write_iter = netfs_unbuffered_write_iter, no page cache → no dirty
 * pages → no writeback wreq).  We do NOT stash vi->active_ctx into
 * wreq->netfs_priv here because that would create a refcount imbalance:
 * init_request only takes a ref when file != NULL, but writeback wreqs
 * arrive with file == NULL, so free_request would drop a ref that was
 * never taken.  CIFS handles this via cifs_get_writable_file() under
 * cinode->open_file_lock — port that pattern before re-enabling buffered
 * mode here.  In the meantime, if writeback ever fires (it shouldn't),
 * vmsmb_issue_write will see ctx == NULL and fall to the CREATE+WRITE+CLOSE
 * slow path, which is correct (just slower).
 */
static void vmsmb_begin_writeback(struct netfs_io_request *wreq)
{
	wreq->io_streams[0].avail = true;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	wreq->io_streams[0].sreq_max_len = VMSMB_MAX_WRITE_CHUNK;
#else
	wreq->io_streams[0].submit_max_len = VMSMB_MAX_WRITE_CHUNK;
#endif
}

/*
 * Async completion for issue_write. Port of CIFS smb2_writev_callback().
 *
 * Drops the per-WRITE-PDU ref taken in vmsmb_issue_write fast path.  This
 * fires when the wire response for the WRITE arrives via vmsmb_complete_req
 * → async_cb chain, so the ref is released exactly once per acknowledged
 * PDU. Pending PDUs that never receive a response keep their ref
 * permanently. That keeps the ctx alive and blocks CLOSE PDU emission,
 * preserving the wire-level invariant: do not send CLOSE while WRITE
 * PDUs may still be acted on by the server.
 */
static void vmsmb_issue_write_complete(void *priv, int status,
				       u32 bytes_written)
{
	struct netfs_io_subrequest *subreq = priv;
	struct vmsmb_file_ctx *ctx = subreq->rreq->netfs_priv;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0) || \
    !defined(NETFS_ICTX_WRITETHROUGH) || defined(NETFS_RREQ_SHORT_TRANSFER)
	netfs_write_subrequest_terminated(subreq,
					  status ? status : (ssize_t)bytes_written);
#else
	netfs_write_subrequest_terminated(subreq,
					  status ? status : (ssize_t)bytes_written, true);
#endif

	if (ctx)
		vmsmb_file_ctx_put(ctx);
}

/*
 * netfs issue_write hook — fulfil one subrequest by issuing SMB2 WRITE.
 *
 * Port of CIFS cifs_issue_write() (fs/smb/client/file.c). Fast path uses
 * vmsmb_smb2_write_async: begin_writeback bounded sreq_max_len so one
 * async WRITE covers the subreq. Falls back to synchronous CREATE+WRITE+CLOSE
 * when no fid is available.
 */
static void vmsmb_issue_write(struct netfs_io_subrequest *subreq)
{
	struct netfs_io_request *wreq = subreq->rreq;
	struct inode *inode = wreq->inode;
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_file_ctx *ctx = wreq->netfs_priv;
	struct vmsmb_fid temp_fid;
	void *buf;
	size_t copied;
	u32 bytes_written = 0;
	char *path;
	int ret;

	pr_debug("issue_write: pos=%lld len=%zu\n", subreq->start, subreq->len);

	/* Fast path: open fid + subreq fits in one chunk → async single-shot */
	if (ctx && subreq->len <= VMSMB_MAX_WRITE_CHUNK) {
		pr_debug("issue_write: ASYNC ctx=%p pos=%lld len=%zu\n",
			 ctx, (long long)subreq->start, subreq->len);
		buf = kvmalloc(subreq->len, GFP_KERNEL);
		if (!buf) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0) || \
    !defined(NETFS_ICTX_WRITETHROUGH) || defined(NETFS_RREQ_SHORT_TRANSFER)
			netfs_write_subrequest_terminated(subreq, -ENOMEM);
#else
			netfs_write_subrequest_terminated(subreq, -ENOMEM, false);
#endif
			return;
		}
		copied = copy_from_iter(buf, subreq->len, &subreq->io_iter);
		if (copied == 0) {
			kvfree(buf);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0) || \
    !defined(NETFS_ICTX_WRITETHROUGH) || defined(NETFS_RREQ_SHORT_TRANSFER)
			netfs_write_subrequest_terminated(subreq, -EFAULT);
#else
			netfs_write_subrequest_terminated(subreq, -EFAULT, false);
#endif
			return;
		}
		/* Per-WRITE-PDU ref: held until response is dispatched in
		 * vmsmb_issue_write_complete.  Strict mirror of wire state —
		 * needed because wreq-level ref (init_request) is dropped by
		 * netfs cleanup which can outpace wire-ack on cancel paths. */
		refcount_inc(&ctx->ref);
		ret = vmsmb_smb2_write_async(sess, sbi->tree_id, &ctx->fid,
					     subreq->start, buf, copied,
					     vmsmb_issue_write_complete, subreq);
		kvfree(buf);
		if (ret == 0)
			return;
		vmsmb_file_ctx_put(ctx);	/* rollback per-PDU ref */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0) || \
    !defined(NETFS_ICTX_WRITETHROUGH) || defined(NETFS_RREQ_SHORT_TRANSFER)
		netfs_write_subrequest_terminated(subreq, ret);
#else
		netfs_write_subrequest_terminated(subreq, ret, false);
#endif
		return;
	}

	/* Slow path: no fid → transient CREATE+WRITE+CLOSE */
	path = vmsmb_inode_path(inode);
	if (IS_ERR(path)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0) || \
    !defined(NETFS_ICTX_WRITETHROUGH) || defined(NETFS_RREQ_SHORT_TRANSFER)
		netfs_write_subrequest_terminated(subreq, PTR_ERR(path));
#else
		netfs_write_subrequest_terminated(subreq, PTR_ERR(path), false);
#endif
		return;
	}
	ret = vmsmb_smb2_create(sess, sbi->tree_id, path, VMSMB_WRITE_ACCESS,
				FILE_OPEN, CREATE_NOT_DIR, &temp_fid, NULL);
	kfree(path);
	if (ret) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0) || \
    !defined(NETFS_ICTX_WRITETHROUGH) || defined(NETFS_RREQ_SHORT_TRANSFER)
		netfs_write_subrequest_terminated(subreq, ret);
#else
		netfs_write_subrequest_terminated(subreq, ret, false);
#endif
		return;
	}

	buf = kvmalloc(min_t(size_t, subreq->len, VMSMB_MAX_WRITE_CHUNK),
		       GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto close;
	}
	copied = copy_from_iter(buf, subreq->len, &subreq->io_iter);
	if (copied == 0) {
		ret = -EFAULT;
		kvfree(buf);
		goto close;
	}
	ret = vmsmb_smb2_write(sess, sbi->tree_id, &temp_fid, subreq->start,
			       buf, copied, &bytes_written);
	kvfree(buf);

close:
	vmsmb_smb2_close(sess, sbi->tree_id, &temp_fid);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0) || \
    !defined(NETFS_ICTX_WRITETHROUGH) || defined(NETFS_RREQ_SHORT_TRANSFER)
	netfs_write_subrequest_terminated(subreq,
					  ret ? ret : (ssize_t)bytes_written);
#else
	netfs_write_subrequest_terminated(subreq,
					  ret ? ret : (ssize_t)bytes_written, false);
#endif
}

/*
 * netfs prepare_write hook — bound each subrequest to our max write chunk
 * so netfs splits large unbuffered writes into chunks we can send in a
 * single VMBus packet. Port of CIFS cifs_prepare_write().
 */
static void vmsmb_prepare_write(struct netfs_io_subrequest *subreq)
{
	struct netfs_io_stream *stream =
		&subreq->rreq->io_streams[subreq->stream_nr];

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	stream->sreq_max_len = VMSMB_MAX_WRITE_CHUNK;
#else
	stream->submit_max_len = VMSMB_MAX_WRITE_CHUNK;
#endif
}

const struct netfs_request_ops vmsmb_netfs_ops = {
	.init_request	= vmsmb_init_request,
	.free_request	= vmsmb_free_request,
	.issue_read	= vmsmb_issue_read,
	.begin_writeback = vmsmb_begin_writeback,
	.prepare_write	= vmsmb_prepare_write,
	.issue_write	= vmsmb_issue_write,
};

/* ---- File operations ---- */

/*
 * Open a file — allocate a per-file context and send SMB2 CREATE.
 *
 * Port of CIFS cifs_open() (fs/smb/client/file.c): map VFS open flags
 * to DesiredAccess + disposition, CREATE, stash the returned fid in
 * file->private_data for read/write/close.
 */
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

	if (file->f_flags & O_TRUNC)
		disposition = FILE_OVERWRITE_IF;
	else
		disposition = FILE_OPEN;

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

	refcount_set(&ctx->ref, 1);
	ctx->sess = sess;
	ctx->tree_id = sbi->tree_id;

	file->private_data = ctx;
	VMSMB_I(inode)->active_ctx = ctx;
	return 0;
}

/*
 * Close a file — drop the user-space-fd reference on the per-file ctx.
 *
 * The actual SMB2 CLOSE PDU is sent by vmsmb_file_ctx_put() once the
 * last reference drops; pending netfs_io_request refs (taken in
 * init_request, dropped in free_request) extend the ctx lifetime past
 * this point.  This serializes CLOSE behind in-flight async WRITEs on
 * the same fid, preventing the host-side IoManager NtClose path from
 * cancelling queued WRITE IRPs before they produce SMB2 responses.
 *
 * Port of CIFS cifs_close() (fs/smb/client/file.c) which calls
 * _cifsFileInfo_put — the SMB2 CLOSE there fires only inside the
 * (--count == 0) branch.
 */
static int vmsmb_file_release(struct inode *inode, struct file *file)
{
	struct vmsmb_file_ctx *ctx = file->private_data;

	if (ctx) {
		if (VMSMB_I(inode)->active_ctx == ctx)
			VMSMB_I(inode)->active_ctx = NULL;

		vmsmb_file_ctx_put(ctx);
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
 * Flush dirty pages to server, then force host-side flush via SMB2 FLUSH.
 *
 * Port of CIFS cifs_fsync() (fs/smb/client/file.c): filemap_write_and_wait
 * to drain the page cache, then SMB2 FLUSH PDU to force the server to
 * persist.
 */
static int vmsmb_fsync(struct file *file, loff_t start, loff_t end,
		       int datasync)
{
	struct vmsmb_file_ctx *ctx = file->private_data;
	struct inode *inode = file_inode(file);
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	int ret;

	ret = file_write_and_wait_range(file, start, end);
	if (ret) {
		pr_debug("fsync: write_and_wait error %d\n", ret);
		return ret;
	}

	if (ctx)
		ret = vmsmb_smb2_flush(sbi->sess, sbi->tree_id, &ctx->fid);
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

/*
 * Enumerate a directory — SMB2 QUERY_DIRECTORY with FileDirectoryInformation.
 *
 * Port of CIFS cifs_readdir() (fs/smb/client/readdir.c): open the dir with
 * FILE_LIST_DIRECTORY, loop QUERY_DIRECTORY until STATUS_NO_MORE_FILES,
 * feed each FILE_DIRECTORY_INFO into dir_emit().
 *
 * Stateless: each VFS call re-opens the directory and re-scans from the
 * beginning, skipping entries until ctx->pos is reached.  This is simple
 * and correct for directories of any size; the cost is proportional to
 * directory size × number of getdents calls (typically 1-2 for most dirs).
 */
static int vmsmb_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_session *sess = sbi->sess;
	struct vmsmb_fid fid;
	char *path;
	void *buf;
	u32 buf_size = 65536;
	u32 data_len;
	u8 flags;
	bool first = true;
	loff_t pos = 0;
	int ret;

	if (!dir_emit_dots(file, ctx))
		return 0;

	path = vmsmb_build_path(file->f_path.dentry);
	if (IS_ERR(path))
		return PTR_ERR(path);

	buf = kvmalloc(buf_size, GFP_KERNEL);
	if (!buf) {
		kfree(path);
		return -ENOMEM;
	}

	ret = vmsmb_smb2_create(sess, sbi->tree_id, path, VMSMB_DIR_ACCESS,
				FILE_OPEN, CREATE_NOT_FILE,
				&fid, NULL);
	if (ret) {
		pr_debug("readdir: CREATE '%s' failed: %d\n", path, ret);
		kfree(path);
		kvfree(buf);
		return ret;
	}

	for (;;) {
		flags = first ? SMB2_RESTART_SCANS : 0;
		first = false;

		ret = vmsmb_smb2_query_dir(sess, sbi->tree_id, &fid, "*",
					   flags, buf, buf_size, &data_len);

		if (ret == -ENODATA) {
			ret = 0;
			break;
		}
		if (ret)
			break;
		if (data_len == 0)
			break;

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

			if ((utf8_len == 1 && name_utf8[0] == '.') ||
			    (utf8_len == 2 && name_utf8[0] == '.' &&
			     name_utf8[1] == '.'))
				goto next_entry;

			pos++;
			if (pos + 2 <= ctx->pos)
				goto next_entry;

			d_type = (attrs & FILE_ATTRIBUTE_REPARSE_POINT) ?
				 DT_LNK :
				 (attrs & FILE_ATTRIBUTE_DIRECTORY) ?
				 DT_DIR : DT_REG;

			if (!dir_emit(ctx, name_utf8, utf8_len,
				      atomic64_inc_return(&vmsmb_ino_counter),
				      d_type))
				goto out;

			ctx->pos++;

next_entry:
			if (entry->NextEntryOffset == 0)
				break;
			offset += le32_to_cpu(entry->NextEntryOffset);
		}
	}

out:
	vmsmb_smb2_close(sess, sbi->tree_id, &fid);

	kfree(path);
	kvfree(buf);
	return ret;
}

const struct file_operations vmsmb_dir_ops = {
	.iterate_shared	= vmsmb_readdir,
	.llseek		= generic_file_llseek,
};

/* ---- Superblock operations ---- */

/*
 * Allocate an inode via the vmsmb_inode_info slab cache.
 *
 * Port of CIFS cifs_alloc_inode() (fs/smb/client/cifsfs.c): slab-allocate
 * the wrapping struct, zero fields that are not re-initialized by
 * vmsmb_fill_inode.
 */
static struct inode *vmsmb_alloc_inode(struct super_block *sb)
{
	struct vmsmb_inode_info *vi;

	vi = alloc_inode_sb(sb, vmsmb_inode_cachep, GFP_KERNEL);
	if (!vi)
		return NULL;

	vi->active_ctx = NULL;
	vi->symlink_target = NULL;
	vi->index_number = 0;
	return &vi->netfs.inode;
}

static void vmsmb_free_inode(struct inode *inode)
{
	kmem_cache_free(vmsmb_inode_cachep, VMSMB_I(inode));
}

/*
 * statfs — fetch filesystem capacity via SMB2 QUERY_INFO
 * FS_FULL_SIZE_INFORMATION.
 *
 * Port of CIFS cifs_statfs() (fs/smb/client/cifsfs.c).
 */
static int vmsmb_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(dentry->d_sb);
	struct smb2_fs_full_size_info fs;
	u32 sectors_per_unit, bytes_per_sector;
	u64 unit_size;
	int ret;

	buf->f_type = 0x564D5342; /* "VMSB" */
	buf->f_namelen = 255;

	ret = vmsmb_smb2_queryfs(sbi->sess, sbi->tree_id, &fs);
	if (ret) {
		/* Server query failed — fall back to a non-zero but obviously
		 * fake report so userspace tools don't refuse to operate. */
		buf->f_bsize = 4096;
		buf->f_blocks = 1024 * 1024 * 1024ULL / 4096;
		buf->f_bfree = buf->f_blocks;
		buf->f_bavail = buf->f_blocks;
		return 0;
	}

	sectors_per_unit = le32_to_cpu(fs.SectorsPerAllocationUnit);
	bytes_per_sector = le32_to_cpu(fs.BytesPerSector);
	unit_size = (u64)sectors_per_unit * bytes_per_sector;
	if (!unit_size)
		unit_size = 4096;

	buf->f_bsize = unit_size;
	buf->f_blocks = le64_to_cpu(fs.TotalAllocationUnits);
	buf->f_bfree = le64_to_cpu(fs.ActualAvailableAllocationUnits);
	buf->f_bavail = le64_to_cpu(fs.CallerAvailableAllocationUnits);
	return 0;
}

/*
 * Evict an inode — drop cached symlink target, wait for outstanding netfs
 * I/O, truncate pages, clear the inode.
 *
 * Port of CIFS cifs_evict_inode() (fs/smb/client/cifsfs.c): the
 * netfs_wait_for_outstanding_io + truncate_inode_pages_final sequence is
 * standard for netfs-backed filesystems.
 */
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

/*
 * Populate the super_block at mount: TREE_CONNECT to the share, set
 * s_op / s_root / default BDI, install the root inode.
 *
 * Port of CIFS cifs_read_super() (fs/smb/client/cifsfs.c): super_setup_bdi
 * is required for netfs writeback (see vmsmb_begin_writeback).
 */
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
	set_default_d_op(sb, &vmsmb_dentry_ops);
#else
	sb->s_d_op = &vmsmb_dentry_ops;
#endif
	sb->s_time_gran = 100; /* 100ns Windows FILETIME granularity */

	/* Set up writeback-capable BDI so netfs writepages works */
	ret = super_setup_bdi(sb);
	if (ret)
		return ret;

	/*
	 * Default BDI readahead is 128 KB — far too small for VSMB where each
	 * async subrequest is 512K and the transport can pipeline 4-8 of them.
	 * 4 MB matches btrfs and gives ~5x cold read improvement (readahead
	 * pipeline fills the VMBus ring and overlaps NVMe latency).
	 * CIFS sets this via server->rsize in cifs_negotiate_rsize().
	 */
	sb->s_bdi->ra_pages = (4096 * 1024) / PAGE_SIZE;

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

	root_inode = vmsmb_iget(sb, &root_info);
	if (IS_ERR(root_inode))
		return PTR_ERR(root_inode);

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
	Opt_symlinkroot,
	Opt_actimeo,
};

static const struct fs_parameter_spec vmsmb_fs_parameters[] = {
	fsparam_u32("uid",		Opt_uid),
	fsparam_u32("gid",		Opt_gid),
	fsparam_u32oct("file_mode",	Opt_file_mode),
	fsparam_u32oct("dir_mode",	Opt_dir_mode),
	fsparam_flag("noperm",		Opt_noperm),
	fsparam_string("symlinkroot",	Opt_symlinkroot),
	fsparam_u32("actimeo",		Opt_actimeo),
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
	char *symlinkroot;
	unsigned int actimeo_secs;	/* 0 = use default */
};

/*
 * Parse a single mount option.
 *
 * Port of CIFS smb3_fs_context_parse_param() (fs/smb/client/fs_context.c):
 * fs_parse() dispatch on the Opt_* enum. Supports: uid, gid, file_mode,
 * dir_mode, noperm, symlinkroot, actimeo.
 */
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
	case Opt_symlinkroot:
		if (param->string[0] != '/')
			return invalfc(fc, "symlinkroot must be absolute path");
		kfree(ctx->symlinkroot);
		ctx->symlinkroot = param->string;
		param->string = NULL;
		break;
	case Opt_actimeo:
		ctx->actimeo_secs = result.uint_32;
		break;
	}

	return 0;
}

/*
 * fs_context get_tree: validate state, materialize sbi from the parsed
 * context, then hand off to get_tree_nodev + vmsmb_fill_super.
 *
 * Port of CIFS smb3_get_tree() (fs/smb/client/fs_context.c), minus the
 * DFS referral / per-share auth paths we don't support.
 */
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

	/* Default 1 second — matches CIFS actimeo default */
	sbi->actimeo = ctx->actimeo_secs ? (ctx->actimeo_secs * HZ) : HZ;

	/* noperm: open all permissions so VFS checks always pass */
	if (sbi->noperm) {
		sbi->file_mode = 0777;
		sbi->dir_mode = 0777;
	}

	/* Transfer symlinkroot ownership from ctx to sbi */
	sbi->symlinkroot = ctx->symlinkroot;
	ctx->symlinkroot = NULL;

	sbi->share_name = kstrdup(dev_name, GFP_KERNEL);
	if (!sbi->share_name) {
		kfree(sbi->symlinkroot);
		kfree(sbi);
		return -ENOMEM;
	}

	/* TREE_CONNECT to the requested share */

	ret = vmsmb_smb2_tree_connect(sess, dev_name, &sbi->tree_id);

	if (ret) {
		pr_err("TREE_CONNECT '%s' failed: %d\n", dev_name, ret);
		kfree(sbi->share_name);
		kfree(sbi->symlinkroot);
		kfree(sbi);
		return ret;
	}

	fc->s_fs_info = sbi;

	return get_tree_nodev(fc, vmsmb_fill_super);
}

static void vmsmb_free_fc(struct fs_context *fc)
{
	struct vmsmb_fs_context *ctx = fc->fs_private;

	if (ctx) {
		kfree(ctx->symlinkroot);
		kfree(ctx);
	}
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

/*
 * Release superblock resources on unmount — free sbi's strings + the
 * sbi struct. No TREE_DISCONNECT: the host cleans up all tree connects
 * when the VMBus channel closes.
 *
 * Port of CIFS cifs_kill_sb() (fs/smb/client/cifsfs.c) simplified: no
 * per-sb cifs_sb_tlink_tree / tcon teardown.
 */
static void vmsmb_kill_sb(struct super_block *sb)
{
	struct vmsmb_sb_info *sbi = sb->s_fs_info;

	kill_anon_super(sb);

	if (sbi) {
		/* Nice to have: TREE_DISCONNECT */
		kfree(sbi->share_name);
		kfree(sbi->symlinkroot);
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
