// SPDX-License-Identifier: GPL-2.0
/*
 * vmsmb_vfs.c - VFS integration for VSMB filesystem
 *
 * Implements mount/umount, inode operations, file operations,
 * and directory operations for the vsmb filesystem type.
 *
 * Portions derived from the Linux kernel CIFS client (fs/smb/client/) and
 * netfs (fs/netfs/), copyright held by their respective upstream authors.
 * See docs/ATTRIBUTION.md for per-function provenance.
 */

#define pr_fmt(fmt) "hv_vmsmb: " fmt

#include <linux/module.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/filelock.h>
#include <linux/fcntl.h>
#include <linux/falloc.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/pagemap.h>
#include <linux/statfs.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/nls.h>
#include <linux/fs_parser.h>
#include <linux/seq_file.h>
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
static int vmsmb_fix_symlink_target_type(char **target, bool directory);
static void vmsmb_file_ctx_put(struct vmsmb_file_ctx *ctx);
static void vmsmb_register_open_ctx(struct inode *inode,
					    struct vmsmb_file_ctx *ctx);
static void vmsmb_unregister_open_ctx(struct inode *inode,
					      struct vmsmb_file_ctx *ctx);
static int vmsmb_flush(struct file *file, fl_owner_t id);
static void vmsmb_oplock_break_work(struct work_struct *work);

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
 * Whether a size reported by the server may replace the one we publish.
 *
 * Port of CIFS is_size_safe_to_change() (fs/smb/client/file.c): while this
 * client holds the file open for write, the server's EndOfFile covers only the
 * bytes writeback has already pushed, so it trails what the page cache holds.
 * Growth is safe to adopt; a shrink is refused until the writers are gone, so
 * that truncate_pagecache() stays clear of folios still waiting to be sent.
 * A directory listing is refused outright once any writer is open, matching
 * upstream's from_readdir arm: NT reports a size in QUERY_DIRECTORY that lags
 * the file's real state, so it must never win over what a writer knows.
 * Upstream also exempts direct-I/O mounts, which does not apply here: there is
 * no cache= mount option.
 */
static bool vmsmb_size_safe_to_change(struct inode *inode, loff_t end_of_file,
				      bool from_readdir)
{
	struct vmsmb_inode_info *vi = VMSMB_I(inode);
	struct vmsmb_file_ctx *ctx;
	bool writable = false;

	spin_lock(&vi->open_ctx_lock);
	list_for_each_entry(ctx, &vi->open_ctxs, inode_node) {
		if (ctx->f_mode & FMODE_WRITE) {
			writable = true;
			break;
		}
	}
	spin_unlock(&vi->open_ctx_lock);

	if (!writable)
		return true;

	if (from_readdir)
		return false;

	return i_size_read(inode) < end_of_file;
}

/*
 * Move a resolved link target from @info into the inode.
 *
 * Port of the S_ISLNK block in CIFS cifs_fattr_to_inode()
 * (fs/smb/client/inode.c).  Upstream reaches both a new and an existing inode
 * through that one function, ours are separate, so the block is shared rather
 * than inlined.  The inode takes the string and @info is cleared, so the
 * caller's unconditional kfree() reclaims only what was not taken.  The i_lock
 * pairs with vmsmb_get_link(), which can read the pointer while a refresh
 * replaces it.
 */
static void vmsmb_take_symlink_target(struct inode *inode,
				      struct vmsmb_file_info *info)
{
	if (!S_ISLNK(inode->i_mode) || !info->symlink_target)
		return;

	spin_lock(&inode->i_lock);
	kfree(VMSMB_I(inode)->symlink_target);
	VMSMB_I(inode)->symlink_target = info->symlink_target;
	spin_unlock(&inode->i_lock);
	info->symlink_target = NULL;
}

/*
 * Fill an inode with SMB2 file attributes.
 *
 * Port of CIFS cifs_fattr_to_inode() (fs/smb/client/inode.c) initial-fill
 * path: set mode/ops by attribute bits, size, times, then attach the netfs
 * context (cifs_set_netfs_context() → netfs_inode_init() equivalent).  Size is
 * taken from @info as-is, so a link's @info must describe the link and not the
 * reparse point behind it; vmsmb_reparse_info_to_inode() makes it do so.
 */
static void vmsmb_fill_inode(struct inode *inode,
			     struct vmsmb_file_info *info)
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
	VMSMB_I(inode)->btime = vmsmb_time_to_ts(info->creation_time);
	VMSMB_I(inode)->attributes = info->attributes;
	vmsmb_take_symlink_target(inode, info);

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
				struct vmsmb_file_info *info,
				bool from_readdir)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_inode_info *vi = VMSMB_I(inode);
	loff_t old_size = i_size_read(inode);
	loff_t new_size = info->size;
	struct timespec64 old_mtime = inode_get_mtime(inode);
	struct timespec64 new_mtime = vmsmb_time_to_ts(info->last_write_time);

	if (vmsmb_size_safe_to_change(inode, new_size, from_readdir)) {
		if (old_size != new_size) {
			/* Truncate page cache beyond new EOF to avoid serving stale data */
			i_size_write(inode, new_size);
			if (new_size < old_size && S_ISREG(inode->i_mode))
				truncate_pagecache(inode, new_size);
		}
		inode->i_blocks = (info->alloc_size + 511) / 512;
	} else if (from_readdir && old_size != new_size) {
		/*
		 * A listing that disagrees with the size we publish lost the
		 * arbitration above, so nothing it carries is trustworthy.
		 * Expire the inode and return before the bottom of this
		 * function stamps meta_expires forward, which would otherwise
		 * mark the size we just refused to change as freshly checked.
		 * Port of the from_readdir arm CIFS added in e8a8d54c2d50
		 * (fs/smb/client/inode.c).
		 */
		vi->meta_expires = jiffies - 1;
		return;
	}
	inode_set_atime_to_ts(inode, vmsmb_time_to_ts(info->last_access_time));
	inode_set_mtime_to_ts(inode, new_mtime);
	inode_set_ctime_to_ts(inode, vmsmb_time_to_ts(info->change_time));
	vi->attributes = info->attributes;
	vmsmb_take_symlink_target(inode, info);

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
				struct vmsmb_file_info *info,
				bool from_readdir)
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
		vmsmb_refresh_inode(inode, info, from_readdir);
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
 * Handles IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT and
 * IO_REPARSE_TAG_LX_SYMLINK.  Simplified from CIFS
 * smb2_parse_native_symlink() and parse_reparse_wsl_symlink()
 * (fs/smb/client/reparse.c).
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

	/*
	 * A WSL link holds a bare POSIX path in UTF-8, so it needs none of the
	 * UTF-16 decode and NT-prefix translation the NT forms below do.
	 *
	 * Port of CIFS parse_reparse_wsl_symlink() (fs/smb/client/reparse.c),
	 * minus its UTF-8 -> UTF-16 -> UTF-8 round trip, which upstream only
	 * makes because its callee takes UTF-16.  Its two rejections are kept:
	 * MS-FSCC 2.1.2.7 only defines the Target layout for version 2, and an
	 * embedded NUL cannot be expressed as a Linux symlink target.
	 */
	if (tag == IO_REPARSE_TAG_LX_SYMLINK) {
		const struct reparse_wsl_symlink_data_buffer *wsl = buf;
		u32 target_len;

		if (buf_len < sizeof(*wsl))
			return ERR_PTR(-EINVAL);
		if (le32_to_cpu(wsl->Version) != 2)
			return ERR_PTR(-EOPNOTSUPP);

		target_len = buf_len - sizeof(*wsl);
		if (!target_len)
			return ERR_PTR(-EINVAL);
		if (strnlen(wsl->Target, target_len) != target_len)
			return ERR_PTR(-EINVAL);

		smb_target = kmemdup_nul(wsl->Target, target_len, GFP_KERNEL);
		if (!smb_target)
			return ERR_PTR(-ENOMEM);
		return smb_target;
	}

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

/*
 * Make @info describe a link rather than the reparse point behind it.
 *
 * Port of CIFS reparse_info_to_fattr() (fs/smb/client/inode.c): read the
 * reparse buffer, translate it, reconcile the string with the object type the
 * server reported, and hand both the target and its length to the struct an
 * inode is filled from.  A link's size is the length of its target, so it is
 * set here rather than left at the reparse point's EndOfFile, as upstream's
 * out_reparse block sets cf_eof.  Upstream appends its FSCTL to the compound
 * that queried the attributes; ours is a separate round trip, so callers only
 * reach here for a reparse point.
 *
 * A caller that already knows the target seeds @info->symlink_target and no
 * read back happens, as upstream skips its own read for reparse data it was
 * handed.  Either way the type comes from @info->attributes rather than the
 * reparse buffer, as at every upstream call site: the buffer does not record
 * it.  On failure @info->symlink_target is left NULL and the caller reports
 * the error.
 */
static int vmsmb_reparse_info_to_inode(struct vmsmb_sb_info *sbi,
				       const char *path,
				       struct vmsmb_file_info *info)
{
	int ret;

	if (!info->symlink_target) {
		void *reparse_buf;
		u32 reparse_len;
		char *target;

		reparse_buf = kmalloc(VMSMB_MAX_RESPONSE, GFP_KERNEL);
		if (!reparse_buf)
			return -ENOMEM;

		ret = vmsmb_smb2_get_reparse(sbi->sess, sbi->tree_id, path,
					     reparse_buf, VMSMB_MAX_RESPONSE,
					     &reparse_len);
		if (ret) {
			kfree(reparse_buf);
			return ret;
		}

		target = vmsmb_parse_reparse(reparse_buf, reparse_len,
					     sbi->symlinkroot);
		kfree(reparse_buf);
		if (IS_ERR(target))
			return PTR_ERR(target);

		info->symlink_target = target;
	}

	ret = vmsmb_fix_symlink_target_type(&info->symlink_target,
					    info->attributes &
					    FILE_ATTRIBUTE_DIRECTORY);
	if (ret) {
		kfree(info->symlink_target);
		info->symlink_target = NULL;
		return ret;
	}

	info->size = strnlen(info->symlink_target, PATH_MAX);
	return 0;
}

/*
 * Re-read an existing inode's metadata from the server.
 *
 * Port of CIFS cifs_revalidate_dentry_attr() (fs/smb/client/inode.c), which
 * re-reads a link's reparse point along with its attributes: a CREATE response
 * describes the reparse point, so only the target says anything about the link.
 *
 * Doing that on every refresh would cost a round trip per revalidation, so this
 * follows CIFS reparse_inode_match() (fs/smb/client/reparse.h) and keeps what
 * the inode has while the change time is unchanged -- the server stamps it when
 * reparse data changes.  Keeping it means carrying the size forward in @info,
 * as CIFS cifs_prime_dcache() (fs/smb/client/readdir.c) carries cf_eof forward
 * for the same reason.  Upstream also compares the reparse tag, which a CREATE
 * response does not carry; its comment there notes the tag check is what can be
 * skipped.
 */
static int vmsmb_revalidate_dentry_attr(struct inode *inode,
					struct dentry *dentry)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_file_info info;
	char *path;
	int ret;

	path = vmsmb_build_path(dentry);
	if (IS_ERR(path))
		return PTR_ERR(path);

	ret = vmsmb_smb2_create_close(sbi->sess, sbi->tree_id, path,
				      FILE_READ_ATTRIBUTES, FILE_OPEN,
				      OPEN_REPARSE_POINT, &info);
	if (ret == 0 && S_ISLNK(inode->i_mode)) {
		struct timespec64 old_ctime = inode_get_ctime(inode);
		struct timespec64 ctime = vmsmb_time_to_ts(info.change_time);

		if (timespec64_equal(&ctime, &old_ctime))
			info.size = i_size_read(inode);
		else
			ret = vmsmb_reparse_info_to_inode(sbi, path, &info);
	}
	kfree(path);

	if (ret == 0) {
		vmsmb_refresh_inode(inode, &info, false);
		kfree(info.symlink_target);
	}
	return ret;
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
		/*
		 * Negative dentry: expire it actimeo after its own lookup stamp
		 * (dentry->d_time), so a file the host created after we cached the
		 * miss becomes visible.  Must not key off the parent dir's
		 * meta_expires: the path walk revalidates the parent first and
		 * refreshes its meta_expires on every traversal, which would pin
		 * the cached miss forever.  Mirrors cifs_d_revalidate()'s
		 * cifs_get_time(dentry) + timeout check (fs/smb/client/dir.c).
		 */
		struct vmsmb_sb_info *sbi = VMSMB_SB(dentry->d_sb);

		if (time_after(jiffies, dentry->d_time + sbi->actimeo))
			return 0;
		return 1;
	}

	vi = VMSMB_I(inode);
	if (time_after(jiffies, vi->meta_expires)) {
		int ret = vmsmb_revalidate_dentry_attr(inode, dentry);

		if (ret == -ENOENT || ret == -ESTALE)
			return 0;
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
 * A reparse point's target is resolved before the inode is instantiated,
 * as in CIFS cifs_get_fattr() (fs/smb/client/inode.c), because the size to
 * publish for a link is the length of that target.
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
	if (ret == 0 && (info.attributes & FILE_ATTRIBUTE_REPARSE_POINT))
		ret = vmsmb_reparse_info_to_inode(sbi, path, &info);
	kfree(path);

	if (ret == -ENOENT) {
		/* Stamp the miss so vmsmb_d_revalidate can expire it after actimeo. */
		dentry->d_time = jiffies;
		return d_splice_alias(NULL, dentry);
	}
	if (ret)
		return ERR_PTR(ret);

	inode = vmsmb_iget(dir->i_sb, &info, false);
	kfree(info.symlink_target);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

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

	/*
	 * Refresh metadata from the server if the TTL has expired.
	 * Port of CIFS cifs_getattr (fs/smb/client/inode.c) without
	 * the oplock-held fast path.
	 */
	if (time_after(jiffies, vi->meta_expires))
		vmsmb_revalidate_dentry_attr(inode, path->dentry);

	generic_fillattr(idmap, request_mask, inode, stat);

	/* Birth time is immutable and stored per-inode; the server always
	 * provides it via the CREATE response (port of CIFS cifs_getattr
	 * filling STATX_BTIME from cifsInfo->createtime). */
	stat->btime = vi->btime;
	stat->result_mask |= STATX_BTIME;

	/*
	 * Surface the NTFS DOS attributes the server reports. Port of CIFS
	 * cifs_getattr (fs/smb/client/inode.c), which maps the same two bits.
	 */
	stat->attributes_mask |= STATX_ATTR_COMPRESSED | STATX_ATTR_ENCRYPTED;
	if (vi->attributes & FILE_ATTRIBUTE_COMPRESSED)
		stat->attributes |= STATX_ATTR_COMPRESSED;
	if (vi->attributes & FILE_ATTRIBUTE_ENCRYPTED)
		stat->attributes |= STATX_ATTR_ENCRYPTED;
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

	inode = vmsmb_iget(dir->i_sb, &info, false);
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
	u8 oplock = sbi->oplocks ? SMB2_OPLOCK_LEVEL_II : SMB2_OPLOCK_LEVEL_NONE;
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

	ret = vmsmb_smb2_create(sess, sbi->tree_id, path, access,
				disposition, CREATE_NOT_DIR,
				&oplock, &ctx->fid, &info);
	kfree(path);
	if (ret) {
		kfree(ctx);
		return ret;
	}

	inode = vmsmb_iget(dir->i_sb, &info, false);
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

	/*
	 * Take the server's size before this handle joins open_ctxs, so the
	 * guard weighs the other writers rather than this one.  O_TRUNC relies
	 * on it: we report the truncation as handled, so the VFS never calls
	 * handle_truncate() and this is the only place the new size lands.
	 */
	if (vmsmb_size_safe_to_change(inode, info.size, false))
		i_size_write(inode, info.size);

	refcount_set(&ctx->ref, 1);
	ctx->sess = sess;
	ctx->tree_id = sbi->tree_id;
	INIT_LIST_HEAD(&ctx->inode_node);
	ctx->f_mode = file->f_mode;
	ctx->oplock_level = oplock;
	ctx->inode = inode;
	ihold(inode);		/* pinned for the ctx lifetime (break work) */
	INIT_LIST_HEAD(&ctx->sess_node);
	INIT_WORK(&ctx->oplock_break, vmsmb_oplock_break_work);
	file->private_data = ctx;
	vmsmb_register_open_ctx(inode, ctx);

	/* CIFS dir.c:590-591 — only when we know the file was just created */
	if ((open_flag & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL))
		file->f_mode |= FMODE_CREATED;

	ret = finish_open(file, dentry, generic_file_open);
	if (ret) {
		vmsmb_unregister_open_ctx(inode, ctx);
		file->private_data = NULL;
		vmsmb_file_ctx_put(ctx);
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

	inode = vmsmb_iget(dir->i_sb, &info, false);
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
 * Drop one link, stopping at zero.
 *
 * Port of CIFS cifs_drop_nlink() (fs/smb/client/inode.c).  A link count is
 * only ever an estimate here: a CREATE response carries no link count, so an
 * inode rebuilt after eviction starts at 1 however many names the file has on
 * disk.  Removing a second name would then take the count below zero, which
 * drop_nlink() warns about, so the count saturates instead.
 */
static void vmsmb_drop_nlink(struct inode *inode)
{
	spin_lock(&inode->i_lock);
	if (inode->i_nlink > 0)
		drop_nlink(inode);
	spin_unlock(&inode->i_lock);
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
		vmsmb_drop_nlink(d_inode(dentry));
		vmsmb_invalidate_dir(dir);
	}
	return ret;
}

/*
 * Remove a directory.
 *
 * Port of CIFS cifs_rmdir() (fs/smb/client/inode.c): delegates to
 * vmsmb_smb2_rmdir(), which asks the server to delete the directory and
 * reports its refusal if the directory is not empty.
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

	ret = vmsmb_smb2_rmdir(sess, sbi->tree_id, path);

	kfree(path);

	if (ret == 0) {
		clear_nlink(d_inode(dentry));
		vmsmb_invalidate_dir(dir);
	}
	return ret;
}

/*
 * Prefix for the name a destination is given while it waits for its last
 * handle to close.
 *
 * Port of CIFS_SILLYNAME_PREFIX (fs/smb/client/cifsfs.h).
 */
#define VMSMB_SILLY_PREFIX	".__vsmb_silly_"

static atomic_t vmsmb_silly_counter = ATOMIC_INIT(0);

/*
 * Build a sibling of @path under a silly name.
 *
 * Port of CIFS cifs_silly_fullpath() (fs/smb/client/dir.c), which walks the
 * parent dentry and looks each candidate up until one is free; the paths
 * here are plain strings and the caller retries, so the counter is all that
 * is left of it.  It only has to keep apart the names that exist at one
 * time, and each is removed as soon as the file under it is closed.
 *
 * Paths here are share-relative with forward slashes and no leading one, so
 * everything before the last separator is the parent, and a name directly
 * under the share root has no separator at all.
 */
static char *vmsmb_silly_path(const char *path)
{
	const char *sep = strrchr(path, '/');
	unsigned int seq = atomic_inc_return(&vmsmb_silly_counter);

	if (sep)
		return kasprintf(GFP_KERNEL, "%.*s/" VMSMB_SILLY_PREFIX "%08x",
				 (int)(sep - path), path, seq);

	return kasprintf(GFP_KERNEL, VMSMB_SILLY_PREFIX "%08x", seq);
}

/*
 * Replace @new_path while something still holds it open, by moving the
 * destination out of the way first -- the manoeuvre upstream calls a silly
 * rename.
 *
 * NT refuses to let a rename replace an open file, but not to rename one, so
 * the destination is moved to a name of ours, the caller's rename reissued
 * against the freed name, and the moved-aside name marked for deletion.  The
 * server drops that name once its last handle closes; until then whoever
 * holds the file goes on reading the bytes it had, which is what POSIX
 * promises.  A holder that did not grant share-delete blocks the first
 * rename, and nothing has moved by then.
 *
 * Port of CIFS cifs_rename2()'s busy-destination path (fs/smb/client/
 * inode.c), which performs the same manoeuvre through
 * __cifs_unlink(sillyrename) -> smb2_rename_pending_delete()
 * (fs/smb/client/smb2inode.c); those are one function here because only the
 * rename site needs them.
 *
 * Upstream renames and marks for deletion inside one compound; vmusrv stops
 * continuing a chain at its first SET_INFO, so the two are separate requests
 * here and the deletion waits until the reissued rename has succeeded, which
 * is what keeps @new_path recoverable when it has not.
 *
 * @old_target: the inode losing its name, for the link count
 */
static int vmsmb_silly_rename(struct vmsmb_session *sess, u32 tree_id,
			      const char *old_path, const char *new_path,
			      struct inode *old_target)
{
	char *silly = NULL;
	int tries, ret = -EEXIST;

	/* A silly name is only ever taken by one left behind by a crash. */
	for (tries = 0; tries < 3 && ret == -EEXIST; tries++) {
		kfree(silly);
		silly = vmsmb_silly_path(new_path);
		if (!silly)
			return -ENOMEM;

		ret = vmsmb_smb2_rename(sess, tree_id, new_path, silly, false);
	}
	if (ret) {
		kfree(silly);
		return -EBUSY;
	}

	ret = vmsmb_smb2_rename(sess, tree_id, old_path, new_path, true);
	if (ret) {
		if (vmsmb_smb2_rename(sess, tree_id, silly, new_path, false))
			pr_warn_ratelimited("rename %s -> %s failed; the old destination is left as %s\n",
					    old_path, new_path, silly);
		kfree(silly);
		return ret;
	}

	vmsmb_drop_nlink(old_target);

	if (vmsmb_smb2_unlink(sess, tree_id, silly) == -EACCES) {
		FILE_BASIC_INFO binfo = {
			.Attributes = cpu_to_le32(FILE_ATTRIBUTE_NORMAL),
		};

		/*
		 * A read-only file cannot be marked for deletion.  Nothing
		 * reads these attributes again, so clearing all of them is
		 * enough to let the delete through.
		 */
		vmsmb_smb2_set_basic_info(sess, tree_id, silly, &binfo);
		if (vmsmb_smb2_unlink(sess, tree_id, silly))
			pr_warn_ratelimited("replaced %s but left %s behind\n",
					    new_path, silly);
	}

	kfree(silly);
	return 0;
}

/*
 * Rename/move a file or directory.
 *
 * Port of CIFS cifs_rename2() (fs/smb/client/inode.c): delegates to
 * vmsmb_smb2_rename() which issues CREATE(DELETE)+SET_INFO(rename)+CLOSE,
 * with RENAME_NOREPLACE inverting the ReplaceIfExists field, and carries
 * over its fallback for the destinations NT will not let a rename replace:
 * a directory object is removed first and one that is merely open is moved
 * aside, either of which makes replacing it non-atomic.
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

	/*
	 * Skipped for RENAME_NOREPLACE, where refusing an existing
	 * destination is the requested behaviour.  A directory symlink is
	 * S_IFLNK here (vmsmb_fill_inode tests FILE_ATTRIBUTE_REPARSE_POINT
	 * before FILE_ATTRIBUTE_DIRECTORY), so it takes the unlink path and
	 * only the link is removed.
	 *
	 * A plain file destination is refused only while it is still open, so
	 * it is moved aside rather than removed, which leaves its data intact
	 * for whoever still holds it.
	 */
	if (replace && (ret == -EACCES || ret == -EEXIST) &&
	    d_really_is_positive(new_dentry)) {
		if (d_is_dir(new_dentry) || d_is_symlink(new_dentry)) {
			int tmpret;

			if (d_is_dir(new_dentry))
				tmpret = vmsmb_smb2_rmdir(sess, sbi->tree_id,
							  new_path);
			else
				tmpret = vmsmb_smb2_unlink(sess, sbi->tree_id,
							   new_path);

			/*
			 * A non-empty directory destination surfaces as
			 * EEXIST or ENOTEMPTY, and is reported in place of
			 * the rename's own EACCES.
			 */
			if (tmpret == -EEXIST || tmpret == -ENOTEMPTY)
				ret = tmpret;
			else if (!tmpret)
				ret = vmsmb_smb2_rename(sess, sbi->tree_id,
							old_path, new_path,
							replace);
		} else {
			ret = vmsmb_silly_rename(sess, sbi->tree_id,
						 old_path, new_path,
						 d_inode(new_dentry));
		}
	}

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
 * Port of CIFS cifs_get_link() (fs/smb/client/cifsfs.c): the target is
 * resolved when the inode is filled; get_link returns a duplicate that VFS
 * frees through delayed_call.  As upstream, the buffer is allocated before
 * taking i_lock and the string copied under it, since a refresh can replace
 * the pointer.
 */
static const char *vmsmb_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	char *target;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	target = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!target)
		return ERR_PTR(-ENOMEM);

	spin_lock(&inode->i_lock);
	if (likely(VMSMB_I(inode)->symlink_target)) {
		strscpy(target, VMSMB_I(inode)->symlink_target, PATH_MAX);
	} else {
		kfree(target);
		target = ERR_PTR(-EOPNOTSUPP);
	}
	spin_unlock(&inode->i_lock);

	if (!IS_ERR(target))
		set_delayed_call(done, kfree_link, target);

	return target;
}

/*
 * Reconcile a symlink target string with the link's SMB object type.
 *
 * Port of CIFS smb2_fix_symlink_target_type() (fs/smb/client/smb2file.c):
 * the object type is user-visible, so a directory symlink reads back with
 * a trailing slash, which is also what lets the target round-trip through
 * vmsmb_detect_directory_target() if the link is recreated.  A file
 * symlink whose target carries a trailing slash is unresolvable on either
 * system and is reported as corrupt.  As upstream, the caller passes the
 * type the server reported, not the one it asked for.
 *
 * Takes ownership of *target and may reallocate it.
 */
static int vmsmb_fix_symlink_target_type(char **target, bool directory)
{
	char *buf;
	int len;

	len = strlen(*target);
	if (!len)
		return -EIO;

	if (directory && (*target)[len - 1] != '/') {
		buf = krealloc(*target, len + 2, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		buf[len] = '/';
		buf[len + 1] = '\0';
		*target = buf;
		len++;
	}

	if (!directory && (*target)[len - 1] == '/')
		return -EIO;

	return 0;
}

/*
 * Collapse "." and ".." in a share-relative path, in place.
 *
 * Returns false when the path walks above the share root, which is a name this
 * client cannot express to the server.
 *
 * The collapse is lexical, so an intermediate component that is itself a
 * symlink resolves differently here than the server would resolve it.  The
 * only caller is the type probe below, whose worst case is choosing the wrong
 * reparse type for the new link.
 */
static bool vmsmb_collapse_path(char *path)
{
	const char *in = path;
	char *out = path;

	while (*in) {
		const char *seg = in;
		size_t len;

		while (*in && *in != '/')
			in++;
		len = in - seg;
		while (*in == '/')
			in++;

		if (!len || (len == 1 && seg[0] == '.'))
			continue;

		if (len == 2 && seg[0] == '.' && seg[1] == '.') {
			if (out == path)
				return false;
			while (out != path && out[-1] != '/')
				out--;
			if (out != path)
				out--;
			continue;
		}

		if (out != path)
			*out++ = '/';
		memmove(out, seg, len);
		out += len;
	}

	*out = '\0';
	return true;
}

/*
 * Decide whether a symlink target names a directory.
 *
 * Port of CIFS detect_directory_symlink_target() (fs/smb/client/reparse.c):
 * the type has to be chosen when the link is created, but Linux symlink(2)
 * only supplies a target string.  Three stages, in cost order:
 *
 *   1. the target's last component is empty (trailing slash), "." or ".."
 *      → certainly a directory, no server round-trip;
 *   2. the target is absolute → undeterminable here, treat as file;
 *   3. otherwise resolve it against the link's parent, collapse the result,
 *      and probe the server with CREATE(CREATE_NOT_FILE); ENOTDIR settles it
 *      as a file, ENOENT leaves a dangling link as a file, and anything else
 *      falls back to a second CREATE(CREATE_NOT_DIR) probe whose EISDIR
 *      settles it as a directory.  A target that resolves outside the share
 *      is undeterminable, like an absolute one.
 *
 * An undeterminable target is not an error: it leaves *directory false,
 * matching upstream.
 */
static int vmsmb_detect_directory_target(struct vmsmb_sb_info *sbi,
					 const char *full_path,
					 const char *target, bool *directory)
{
	struct vmsmb_session *sess = sbi->sess;
	const char *basename;
	char *resolved_path, *path_sep;
	int full_path_len, target_len, basename_len;
	int ret;

	/*
	 * A target ending in a slash, "." or ".." can only name a directory.
	 */
	basename = kbasename(target);
	basename_len = strlen(basename);
	if (basename_len == 0 ||
	    (basename_len == 1 && basename[0] == '.') ||
	    (basename_len == 2 && basename[0] == '.' && basename[1] == '.')) {
		*directory = true;
		return 0;
	}

	/* Absolute targets leave the share, so the server cannot resolve them. */
	if (target[0] == '/')
		return 0;

	full_path_len = strlen(full_path);
	target_len = strlen(target);

	resolved_path = kzalloc(full_path_len + target_len + 1, GFP_KERNEL);
	if (!resolved_path)
		return -ENOMEM;

	/* Splice the relative target onto the link's parent directory. */
	memcpy(resolved_path, full_path, full_path_len + 1);
	path_sep = strrchr(resolved_path, '/');
	if (path_sep)
		path_sep++;
	else
		path_sep = resolved_path;
	memcpy(path_sep, target, target_len + 1);

	/*
	 * The server resolves a CREATE path literally, so the spliced-in "."
	 * and ".." have to be gone before it is sent.  A target that walks
	 * above the share root is as undeterminable here as an absolute one.
	 */
	if (!vmsmb_collapse_path(resolved_path)) {
		kfree(resolved_path);
		return 0;
	}

	/* Probe as a directory. */
	ret = vmsmb_smb2_create_close(sess, sbi->tree_id, resolved_path,
				      FILE_READ_ATTRIBUTES, FILE_OPEN,
				      CREATE_NOT_FILE | OPEN_REPARSE_POINT,
				      NULL);
	if (ret == 0) {
		*directory = true;
	} else if (ret == -ENOTDIR || ret == -ENOENT) {
		/*
		 * ENOTDIR: certainly a file.  ENOENT: dangling target, so
		 * nothing to inspect — leave it a file symlink.
		 */
	} else {
		/* Probe as a file: the open may have been denied instead. */
		ret = vmsmb_smb2_create_close(sess, sbi->tree_id, resolved_path,
					      FILE_READ_ATTRIBUTES, FILE_OPEN,
					      CREATE_NOT_DIR | OPEN_REPARSE_POINT,
					      NULL);
		if (ret == -EISDIR)
			*directory = true;
	}

	kfree(resolved_path);
	return 0;
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
	bool directory = false;
	int ret;

	path = vmsmb_build_path(dentry);
	if (IS_ERR(path))
		return PTR_ERR(path);

	ret = vmsmb_detect_directory_target(sbi, path, target, &directory);
	if (ret) {
		kfree(path);
		return ret;
	}

	ret = vmsmb_smb2_create_symlink(sess, sbi->tree_id, path, target,
					directory);

	if (ret) {
		kfree(path);
		return ret;
	}

	/* Re-stat to get inode attributes */

	ret = vmsmb_smb2_create(sess, sbi->tree_id, path, FILE_READ_ATTRIBUTES,
				FILE_OPEN,
				OPEN_REPARSE_POINT,
				NULL, &fid, &info);
	if (ret == 0)
		vmsmb_smb2_close(sess, sbi->tree_id, &fid);

	if (ret == 0) {
		/*
		 * Hand on the target we were asked to create, as CIFS
		 * create_native_symlink() (fs/smb/client/reparse.c) seeds it
		 * into the open info it passes to cifs_get_inode_info(): the
		 * string is already known, so reading the reparse point back
		 * would only confirm it.  Everything downstream of that --
		 * reconciling the string against the type the server reported,
		 * and sizing the link by it -- is then the same code lookup
		 * runs, and the two paths agree by construction.
		 */
		info.symlink_target = kstrdup(target, GFP_KERNEL);
		if (info.symlink_target)
			ret = vmsmb_reparse_info_to_inode(sbi, path, &info);
		else
			ret = -ENOMEM;
	}

	kfree(path);

	if (ret)
		return ret;

	inode = vmsmb_iget(dir->i_sb, &info, false);
	kfree(info.symlink_target);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

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

	/*
	 * Flush dirty data before changing timestamps or size.  Writes are
	 * async (netfs writeback) and the server bumps the file's modification
	 * time on every WRITE; without this, writeback that lands after the
	 * SET_INFO overwrites the timestamp we just set (e.g. tar restoring an
	 * archived mtime ends up with the extraction time).  Port of CIFS
	 * cifs_setattr_nounix() (fs/smb/client/inode.c).
	 */
	if (attr->ia_valid & (ATTR_MTIME | ATTR_SIZE | ATTR_CTIME))
		filemap_write_and_wait(inode->i_mapping);

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
 *   - init_request: file-backed in-flight netfs_io_requests
 *   - begin_writeback: handle-less writeback requests that found this ctx
 *   - issue_read / issue_write: each submitted async READ/WRITE PDU
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
		iput(ctx->inode);
		kfree(ctx);
	}
}

static void vmsmb_register_open_ctx(struct inode *inode,
					    struct vmsmb_file_ctx *ctx)
{
	struct vmsmb_inode_info *vi = VMSMB_I(inode);

	spin_lock(&vi->open_ctx_lock);
	list_add_tail(&ctx->inode_node, &vi->open_ctxs);
	spin_unlock(&vi->open_ctx_lock);

	/* Session-global list, walked by the break dispatch to map fid->ctx. */
	spin_lock_bh(&ctx->sess->open_ctx_list_lock);
	list_add_tail(&ctx->sess_node, &ctx->sess->open_ctx_list);
	spin_unlock_bh(&ctx->sess->open_ctx_list_lock);
}

static void vmsmb_unregister_open_ctx(struct inode *inode,
					      struct vmsmb_file_ctx *ctx)
{
	struct vmsmb_inode_info *vi = VMSMB_I(inode);

	spin_lock_bh(&ctx->sess->open_ctx_list_lock);
	if (!list_empty(&ctx->sess_node))
		list_del_init(&ctx->sess_node);
	spin_unlock_bh(&ctx->sess->open_ctx_list_lock);

	spin_lock(&vi->open_ctx_lock);
	if (!list_empty(&ctx->inode_node))
		list_del_init(&ctx->inode_node);
	spin_unlock(&vi->open_ctx_lock);
}

static int vmsmb_get_writable_ctx(struct inode *inode,
					  struct vmsmb_file_ctx **out)
{
	struct vmsmb_inode_info *vi = VMSMB_I(inode);
	struct vmsmb_file_ctx *ctx;

	*out = NULL;

	spin_lock(&vi->open_ctx_lock);
	list_for_each_entry(ctx, &vi->open_ctxs, inode_node) {
		if (!(ctx->f_mode & FMODE_WRITE))
			continue;
		refcount_inc(&ctx->ref);
		*out = ctx;
		spin_unlock(&vi->open_ctx_lock);
		return 0;
	}
	spin_unlock(&vi->open_ctx_lock);

	return -EBADF;
}

/*
 * Oplock-break work — flush dirty data, then drop cached pages and metadata so
 * subsequent access re-fetches from the server.  Queued by the receive path
 * with a ctx ref held; that ref is dropped here.
 *
 * Port of CIFS cifs_oplock_break() (fs/smb/client/file.c).  A LEVEL_II break to
 * NONE is a one-way notification and is not acknowledged.  In-flight writes are
 * drained first so the server sees our data: DIO via inode_dio_wait(), buffered
 * (page cache) via filemap_write_and_wait().
 */
static void vmsmb_oplock_break_work(struct work_struct *work)
{
	struct vmsmb_file_ctx *ctx =
		container_of(work, struct vmsmb_file_ctx, oplock_break);
	struct inode *inode = ctx->inode;

	pr_debug("oplock break: ino=%lu held=0x%x\n",
		 inode->i_ino, ctx->oplock_level);

	inode_dio_wait(inode);
	filemap_write_and_wait(inode->i_mapping);
	invalidate_inode_pages2(inode->i_mapping);
	VMSMB_I(inode)->meta_expires = jiffies - 1;

	ctx->oplock_level = SMB2_OPLOCK_LEVEL_NONE;
	vmsmb_file_ctx_put(ctx);
}

/*
 * Receive-path entry: a server OPLOCK_BREAK arrived for (persistent,volatile).
 * Find the open ctx, pin it, and queue the break work.  Runs in the
 * channel_cb softirq, so it must not sleep — the heavy lifting is in
 * vmsmb_oplock_break_work().  Ports CIFS smb2_is_valid_oplock_break() +
 * cifs_queue_oplock_break().
 */
void vmsmb_oplock_break_received(struct vmsmb_session *sess, u64 persistent,
				 u64 volatile_id)
{
	struct vmsmb_file_ctx *ctx;

	spin_lock(&sess->open_ctx_list_lock);
	list_for_each_entry(ctx, &sess->open_ctx_list, sess_node) {
		if (ctx->fid.persistent != persistent ||
		    ctx->fid.volatile_id != volatile_id)
			continue;

		refcount_inc(&ctx->ref);
		/*
		 * On already-queued, drop the ref we just took.  The pending
		 * work still holds its own ref, so this never reaches zero —
		 * refcount_dec (not vmsmb_file_ctx_put) keeps us off the
		 * sleeping CLOSE path while under the spinlock in softirq.
		 */
		if (!queue_work(system_unbound_wq, &ctx->oplock_break))
			refcount_dec(&ctx->ref);
		break;
	}
	spin_unlock(&sess->open_ctx_list_lock);
}

/*
 * netfs init_request hook — stash the open file context so issue_read /
 * issue_write can use the existing fid without reopening.
 *
 * Port of CIFS cifs_init_request() (fs/smb/client/file.c): file-backed
 * requests take a ctx ref here.  Handle-less NETFS_WRITEBACK requests leave
 * netfs_priv empty; begin_writeback takes a referenced writable ctx later.
 * Also advertises the per-subrequest max chunk size so netfs splits large
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
 * netfs free_request hook — drop the request-level ctx ref taken either in
 * init_request (file-backed I/O) or begin_writeback (handle-less writeback).
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

	if (status == -ENODATA) {
		/*
		 * Read at/past EOF (e.g. the read-modify-write probe of a folio
		 * beyond i_size, or a sparse region) returns STATUS_END_OF_FILE.
		 * That is not an error: flag EOF so netfs zero-fills the rest of
		 * the subrequest.  Port of CIFS smb2_readv_callback()
		 * (fs/smb/client/smb2pdu.c), which maps -ENODATA to HIT_EOF.
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
		__set_bit(NETFS_SREQ_HIT_EOF, &subreq->flags);
#else
		__set_bit(NETFS_SREQ_SHORT_IO, &subreq->flags);
#endif
	} else if (status) {
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
				FILE_OPEN, CREATE_NOT_DIR, NULL, &temp_fid, NULL);
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
	if (ret == -ENODATA) {
		/* Read past EOF / sparse hole — zero-fill (see issue_read_complete). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
		__set_bit(NETFS_SREQ_HIT_EOF, &subreq->flags);
#else
		__set_bit(NETFS_SREQ_SHORT_IO, &subreq->flags);
#endif
	} else if (ret) {
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
 * netfs begin_writeback hook — acquire a writable fid for buffered writeback
 * and advertise the per-subrequest max chunk size.
 *
 * Port of CIFS cifs_begin_writeback() (fs/smb/client/file.c): lookup a
 * writable open file under the inode open-file lock and stash a referenced
 * file context in wreq->netfs_priv.  If all writable fds have already closed,
 * keep the stream available; issue_write will fall back to CREATE+WRITE+CLOSE
 * by path, which is correct but slower.
 */
static void vmsmb_begin_writeback(struct netfs_io_request *wreq)
{
	struct vmsmb_file_ctx *ctx;

	if (!wreq->netfs_priv &&
	    vmsmb_get_writable_ctx(wreq->inode, &ctx) == 0)
		wreq->netfs_priv = ctx;

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
	size_t len;
	u32 bytes_written = 0;
	char *path;
	int ret;

	pr_debug("issue_write: pos=%lld len=%zu\n", subreq->start, subreq->len);

	/* Fast path: open fid + subreq fits in one chunk → async single-shot */
	if (ctx && subreq->len <= VMSMB_MAX_WRITE_CHUNK) {
		pr_debug("issue_write: ASYNC ctx=%p pos=%lld len=%zu\n",
			 ctx, (long long)subreq->start, subreq->len);
		len = min_t(size_t, subreq->len, VMSMB_MAX_WRITE_CHUNK);
		buf = kvmalloc(len, GFP_KERNEL);
		if (!buf) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0) || \
    !defined(NETFS_ICTX_WRITETHROUGH) || defined(NETFS_RREQ_SHORT_TRANSFER)
			netfs_write_subrequest_terminated(subreq, -ENOMEM);
#else
			netfs_write_subrequest_terminated(subreq, -ENOMEM, false);
#endif
			return;
		}
		copied = copy_from_iter(buf, len, &subreq->io_iter);
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
		 * needed because wreq-level refs (init_request / begin_writeback)
		 * are dropped by netfs cleanup which can outpace wire-ack on
		 * cancel paths. */
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
				FILE_OPEN, CREATE_NOT_DIR, NULL, &temp_fid, NULL);
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

	len = min_t(size_t, subreq->len, VMSMB_MAX_WRITE_CHUNK);
	buf = kvmalloc(len, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto close;
	}
	copied = copy_from_iter(buf, len, &subreq->io_iter);
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
	u8 oplock = sbi->oplocks ? SMB2_OPLOCK_LEVEL_II : SMB2_OPLOCK_LEVEL_NONE;
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

	ret = vmsmb_smb2_create(sess, sbi->tree_id, path, access,
				disposition, CREATE_NOT_DIR,
				&oplock, &ctx->fid, &info);

	kfree(path);

	if (ret) {
		kfree(ctx);
		return ret;
	}

	/*
	 * Take the server's size before this handle joins open_ctxs, so the
	 * guard weighs the other writers rather than this one.
	 */
	if (vmsmb_size_safe_to_change(inode, info.size, false))
		i_size_write(inode, info.size);

	refcount_set(&ctx->ref, 1);
	ctx->sess = sess;
	ctx->tree_id = sbi->tree_id;
	INIT_LIST_HEAD(&ctx->inode_node);
	ctx->f_mode = file->f_mode;
	ctx->oplock_level = oplock;
	ctx->inode = inode;
	ihold(inode);		/* pinned for the ctx lifetime (break work) */
	INIT_LIST_HEAD(&ctx->sess_node);
	INIT_WORK(&ctx->oplock_break, vmsmb_oplock_break_work);

	file->private_data = ctx;
	vmsmb_register_open_ctx(inode, ctx);
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

	file->private_data = NULL;
	if (ctx) {
		vmsmb_unregister_open_ctx(inode, ctx);
		vmsmb_file_ctx_put(ctx);
	}
	return 0;
}

/*
 * llseek — add SEEK_HOLE / SEEK_DATA for sparse files via
 * FSCTL_QUERY_ALLOCATED_RANGES.  Port of CIFS smb3_llseek()
 * (fs/smb/client/smb2ops.c); other whences use the generic size-based seek.
 *
 * Unlike CIFS we do not cache the sparse attribute, so we always issue the
 * query: for a non-sparse file the server returns a single range covering
 * [offset, EOF), which gives SEEK_DATA == offset and SEEK_HOLE == EOF.
 */
static loff_t vmsmb_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct vmsmb_file_ctx *ctx = file->private_data;
	struct file_allocated_range_buffer in_data, out_data = {};
	loff_t isize = i_size_read(inode);
	u32 out_len = 0;
	int ret;

	if (!ctx || (whence != SEEK_HOLE && whence != SEEK_DATA))
		return generic_file_llseek_size(file, offset, whence,
						MAX_LFS_FILESIZE, isize);

	if (offset < 0 || offset >= isize)
		return -ENXIO;

	/*
	 * Flush dirty data first: the server won't reflect recent writes in
	 * QUERY_ALLOCATED_RANGES until they are written out.  The page-cache
	 * writeback above pushes them to the server; the extra SMB2 FLUSH is
	 * only meaningful — and only permitted — on a writable handle (FLUSH on
	 * a read-only fid returns STATUS_ACCESS_DENIED).
	 */
	filemap_write_and_wait(inode->i_mapping);
	if (file->f_mode & FMODE_WRITE)
		vmsmb_smb2_flush(sbi->sess, sbi->tree_id, &ctx->fid);

	in_data.file_offset = cpu_to_le64(offset);
	in_data.length = cpu_to_le64(isize - offset);

	ret = vmsmb_smb2_ioctl(ctx->sess, sbi->tree_id, &ctx->fid,
			       FSCTL_QUERY_ALLOCATED_RANGES,
			       &in_data, sizeof(in_data),
			       &out_data, sizeof(out_data), &out_len);
	/* -E2BIG just means more ranges exist; the first one is all we need. */
	if (ret == -E2BIG)
		ret = 0;
	if (ret)
		return ret;

	if (out_len == 0) {
		/* No allocated range from @offset to EOF: the rest is a hole. */
		if (whence == SEEK_DATA)
			return -ENXIO;
		goto out;	/* SEEK_HOLE: @offset is in the trailing hole */
	}
	if (out_len < sizeof(out_data))
		return -EINVAL;

	if (whence == SEEK_DATA) {
		offset = le64_to_cpu(out_data.file_offset);
		goto out;
	}
	/* SEEK_HOLE */
	if (offset < le64_to_cpu(out_data.file_offset))
		goto out;	/* @offset lies in a hole before the first range */
	offset = le64_to_cpu(out_data.file_offset) +
		 le64_to_cpu(out_data.length);
out:
	return vfs_setpos(file, offset, inode->i_sb->s_maxbytes);
}

/*
 * Unbuffered/DIO write — VSMB-native pipeline.
 *
 * Replaces netfs_unbuffered_write_iter on the IOCB_DIRECT path.  netfs's
 * strict-sequence dispatch (commit 153a9961b551) serialises one async PDU at
 * a time, which on a sub-ms RTT transport like VMBus collapses throughput
 * vs the pre-patch parallel path.  We pipeline N WRITE PDUs back-to-back,
 * relying on vmsmb_submit's internal ring/credit/MID admission for natural
 * backpressure.
 *
 * Return value is the contiguous prefix of bytes acknowledged by the server
 * (FUSE async DIO accounting).  On mid-pipeline failure later chunks may
 * already have landed on the server past the returned prefix.
 */

struct vmsmb_dio_chunk {
	struct vmsmb_dio_state *state;
	loff_t  pos;
	u32     requested;
	u32     written;
	int     status;		/* -EINPROGRESS / 0 / <0 / -ECHILD */
};

struct vmsmb_dio_state {
	atomic_t                inflight;
	struct completion       all_done;	/* sync path only */
	struct vmsmb_dio_chunk *chunks;
	size_t                  nchunks;
	size_t                  submitted_bytes;
	/* async path (iocb != NULL): */
	struct kiocb           *iocb;
	struct inode           *inode;
	loff_t                  pos;
};

static void vmsmb_dio_finalize_async(struct vmsmb_dio_state *state)
{
	struct kiocb *iocb = state->iocb;
	struct inode *inode = state->inode;
	ssize_t transferred = 0;
	int first_err = 0;
	size_t i;

	for (i = 0; i < state->nchunks; i++) {
		struct vmsmb_dio_chunk *c = &state->chunks[i];

		if (c->status == -ECHILD)
			break;
		if (c->status != 0) {
			first_err = c->status;
			break;
		}
		transferred += c->written;
		if (c->written < c->requested)
			break;
	}

	if (transferred > 0) {
		iocb->ki_pos = state->pos + transferred;
		if (iocb->ki_pos > i_size_read(inode))
			i_size_write(inode, iocb->ki_pos);
	}

	inode_dio_end(inode);
	iocb->ki_complete(iocb, transferred ?: first_err);
	kvfree(state->chunks);
	kfree(state);
}

static void vmsmb_dio_chunk_complete(void *priv, int status, u32 bytes_written)
{
	struct vmsmb_dio_chunk *c = priv;
	struct vmsmb_dio_state *state = c->state;

	c->written = bytes_written;
	c->status  = status;

	if (!atomic_dec_and_test(&state->inflight))
		return;

	if (state->iocb)
		vmsmb_dio_finalize_async(state);
	else
		complete(&state->all_done);
}

/*
 * Submit loop shared by sync and async paths.  Copies data from @iter in
 * the caller's context (user pages still mapped), submits each chunk via
 * vmsmb_smb2_write_async, and returns the first hard error (0 if all chunks
 * were submitted).  Caller must have seeded state->inflight to 1.
 */
static int vmsmb_unbuffered_write(struct vmsmb_dio_state *state,
				  struct vmsmb_session *sess, u32 tree_id,
				  struct vmsmb_fid *fid, loff_t pos,
				  struct iov_iter *iter, size_t total)
{
	size_t submitted_bytes = 0, last_submitted = 0;
	int first_err = 0;
	size_t i;

	for (i = 0; i < state->nchunks; i++) {
		struct vmsmb_dio_chunk *c = &state->chunks[i];
		u32 n = (u32)min_t(size_t, total - submitted_bytes,
				   VMSMB_MAX_WRITE_CHUNK);
		void *buf;
		int ret;

		c->state     = state;
		c->pos       = pos + submitted_bytes;
		c->requested = n;
		c->written   = 0;
		c->status    = -EINPROGRESS;

		buf = kvmalloc(n, GFP_KERNEL);
		if (!buf) {
			c->status = -ENOMEM;
			first_err = -ENOMEM;
			break;
		}
		if (copy_from_iter(buf, n, iter) != n) {
			kvfree(buf);
			c->status = -EFAULT;
			first_err = -EFAULT;
			break;
		}

		atomic_inc(&state->inflight);
		ret = vmsmb_smb2_write_async(sess, tree_id, fid,
					     c->pos, buf, n,
					     vmsmb_dio_chunk_complete, c);
		kvfree(buf);
		if (ret) {
			atomic_dec(&state->inflight);
			c->status = ret;
			first_err = ret;
			break;
		}

		submitted_bytes += n;
		last_submitted   = i + 1;
	}

	for (i = last_submitted; i < state->nchunks; i++)
		if (state->chunks[i].status == -EINPROGRESS)
			state->chunks[i].status = -ECHILD;

	state->submitted_bytes = submitted_bytes;
	return first_err;
}

static ssize_t vmsmb_unbuffered_write_iter_locked(struct kiocb *iocb,
						  struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct vmsmb_file_ctx *ctx = file->private_data;
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	bool async = !is_sync_kiocb(iocb);
	size_t total = iov_iter_count(from);
	struct vmsmb_dio_state state_local, *state;
	ssize_t transferred = 0;
	int first_err;
	size_t i;

	if (!ctx)
		return -EBADF;
	if (!total)
		return 0;

	if (async) {
		state = kzalloc(sizeof(*state), GFP_KERNEL);
		if (!state)
			return -ENOMEM;
		state->iocb  = iocb;
		state->inode = inode;
		state->pos   = iocb->ki_pos;
	} else {
		memset(&state_local, 0, sizeof(state_local));
		state = &state_local;
		init_completion(&state->all_done);
	}

	state->nchunks = DIV_ROUND_UP(total, VMSMB_MAX_WRITE_CHUNK);
	state->chunks  = kvmalloc_array(state->nchunks,
					sizeof(state->chunks[0]), GFP_KERNEL);
	if (!state->chunks) {
		if (async)
			kfree(state);
		return -ENOMEM;
	}

	atomic_set(&state->inflight, 1);
	inode_dio_begin(inode);

	first_err = vmsmb_unbuffered_write(state, ctx->sess, sbi->tree_id,
					   &ctx->fid, iocb->ki_pos, from,
					   total);

	if (async) {
		if (state->submitted_bytes == 0) {
			inode_dio_end(inode);
			kvfree(state->chunks);
			kfree(state);
			return first_err ?: -EIO;
		}
		if (atomic_dec_and_test(&state->inflight))
			vmsmb_dio_finalize_async(state);
		return -EIOCBQUEUED;
	}

	/* Sync: wait for all chunks, compute contiguous prefix. */
	if (atomic_dec_and_test(&state->inflight))
		complete(&state->all_done);
	wait_for_completion(&state->all_done);

	for (i = 0; i < state->nchunks; i++) {
		struct vmsmb_dio_chunk *c = &state->chunks[i];

		if (c->status == -ECHILD)
			break;
		if (c->status != 0) {
			if (!first_err)
				first_err = c->status;
			break;
		}
		transferred += c->written;
		if (c->written < c->requested)
			break;
	}

	if (transferred < (ssize_t)state->submitted_bytes)
		iov_iter_revert(from, state->submitted_bytes - transferred);

	inode_dio_end(inode);

	if (transferred > 0) {
		iocb->ki_pos += transferred;
		if (iocb->ki_pos > i_size_read(inode))
			i_size_write(inode, iocb->ki_pos);
	}

	kvfree(state->chunks);
	return transferred ?: first_err;
}

/*
 * Top-level DIO entry — mirrors netfs_unbuffered_write_iter preflight 1:1
 * (the fscache_invalidate step is the only omission; we never set up an
 * fscache cookie so it would no-op).
 */
static ssize_t vmsmb_unbuffered_write_iter(struct kiocb *iocb,
					   struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 0, 11)
	struct netfs_inode *ictx = netfs_inode(inode);
#endif
	loff_t pos = iocb->ki_pos;
	loff_t end;
	size_t count = iov_iter_count(from);
	ssize_t ret;

	if (!count)
		return 0;

	ret = netfs_start_io_direct(inode);
	if (ret < 0)
		return ret;

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out;
	count = iov_iter_count(from);
	if (!count) {
		ret = 0;
		goto out;
	}
	ret = file_remove_privs(file);
	if (ret < 0)
		goto out;
	ret = file_update_time(file);
	if (ret < 0)
		goto out;

	pos = iocb->ki_pos;
	end = pos + count - 1;
	if (iocb->ki_flags & IOCB_NOWAIT) {
		ret = -EAGAIN;
		if (filemap_range_has_page(mapping, pos, end))
			if (filemap_invalidate_inode(inode, true, pos, end))
				goto out;
	} else {
		ret = filemap_write_and_wait_range(mapping, pos, end);
		if (ret < 0)
			goto out;
	}

	ret = filemap_invalidate_inode(inode, true, pos, end);
	if (ret < 0)
		goto out;
	end = iocb->ki_pos + iov_iter_count(from);
	/*
	 * netfs renamed zero_point -> _zero_point and added accessors (taking a
	 * struct inode *) in 7.1, backported to 7.0.x stable from 7.0.11.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 11)
	if (end > netfs_read_zero_point(inode))
		netfs_write_zero_point(inode, end);
#else
	if (end > ictx->zero_point)
		ictx->zero_point = end;
#endif

	ret = vmsmb_unbuffered_write_iter_locked(iocb, from);

out:
	netfs_end_io_direct(inode);
	return ret;
}

static ssize_t vmsmb_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	if (iocb->ki_flags & IOCB_DIRECT)
		return vmsmb_unbuffered_write_iter(iocb, from);
	return netfs_file_write_iter(iocb, from);
}

/*
 * Flush dirty pages on close while the file ctx is still registered, so
 * buffered writeback can use the open writable fid instead of reopening by
 * path after release.
 */
static int vmsmb_flush(struct file *file, fl_owner_t id)
{
	struct inode *inode = file_inode(file);
	int ret = 0;

	if (file->f_mode & FMODE_WRITE)
		ret = filemap_write_and_wait(inode->i_mapping);
	return ret;
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

/* ---- Byte-range (fcntl) and whole-file (flock) locking ---- */

/*
 * Push a lock/unlock to the server and mirror it into the VFS lock list.
 *
 * Port of CIFS cifs_setlk()/cifs_read_flock() (fs/smb/client/file.c) minus the
 * cifsLockInfo range-coalescing list: we rely on the VFS's own POSIX/flock list
 * (via locks_lock_file_wait) and on FID CLOSE to release any residual server
 * lock left behind by a coalesced unlock. SMB2 enforces conflicts per FileId,
 * so distinct opens — including across the host and other VMs — coordinate
 * correctly.
 *
 * Blocking requests (FL_SLEEP) are emulated by retrying the non-blocking server
 * lock, because the synchronous transport cannot park on a server-side wait
 * (see vmsmb_smb2_lock).
 */
static int vmsmb_setlk(struct file *file, struct file_lock *fl)
{
	struct vmsmb_file_ctx *ctx = file->private_data;
	struct vmsmb_sb_info *sbi = VMSMB_SB(file_inode(file)->i_sb);
	bool wait = fl->c.flc_flags & FL_SLEEP;
	u64 offset = fl->fl_start;
	u64 length = fl->fl_end - fl->fl_start + 1; /* cifs_flock_len() */
	u32 pid = current->tgid;
	u32 lock_flags;
	int ret;

	if (lock_is_unlock(fl)) {
		/*
		 * Server unlock is best-effort: a coalesced range may not match
		 * (-ENOLCK) and the server drops every lock at CLOSE anyway, so
		 * never let it block the local unlock. Mirrors CIFS treating
		 * unlock failures as non-fatal.
		 */
		vmsmb_smb2_lock(ctx->sess, sbi->tree_id, &ctx->fid, pid,
				offset, length, SMB2_LOCKFLAG_UNLOCK);
		return locks_lock_file_wait(file, fl);
	}

	lock_flags = lock_is_read(fl) ? SMB2_LOCKFLAG_SHARED
				      : SMB2_LOCKFLAG_EXCLUSIVE;
	lock_flags |= SMB2_LOCKFLAG_FAIL_IMMEDIATELY;

	for (;;) {
		ret = vmsmb_smb2_lock(ctx->sess, sbi->tree_id, &ctx->fid, pid,
				      offset, length, lock_flags);
		if (ret != -EAGAIN || !wait)
			break;
		if (msleep_interruptible(VMSMB_LOCK_RETRY_MS))
			return -ERESTARTSYS;
	}
	if (ret)
		return ret;

	/*
	 * Record the lock locally for POSIX/flock semantics and close-time
	 * cleanup. If that fails, roll back the server lock we just took so the
	 * two views stay consistent.
	 */
	ret = locks_lock_file_wait(file, fl);
	if (ret)
		vmsmb_smb2_lock(ctx->sess, sbi->tree_id, &ctx->fid, pid,
				offset, length, SMB2_LOCKFLAG_UNLOCK);
	return ret;
}

/*
 * F_GETLK — report conflicts known to the local VFS lock list.
 *
 * We deliberately do not probe the server (cifs_getlk-style test-lock): the
 * probe would run on our own FileId and false-positive on ranges this open
 * already holds. Cross-client *enforcement* still works via F_SETLK (the server
 * rejects conflicting locks); only cross-client F_GETLK *queries* are limited
 * to locally-visible conflicts.
 */
static int vmsmb_getlk(struct file *file, struct file_lock *fl)
{
	posix_test_lock(file, fl);
	return 0;
}

static int vmsmb_file_lock(struct file *file, int cmd, struct file_lock *fl)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(file_inode(file)->i_sb);

	if (IS_GETLK(cmd))
		return vmsmb_getlk(file, fl);
	/*
	 * Default: keep fcntl/OFD byte-range locks guest-local advisory.  SMB2
	 * byte-range locks are mandatory (a shared lock blocks even the owner's
	 * own overlapping write — breaks qemu-img et al.), so only send them to
	 * the server under "brl".  flock is a separate mechanism and is
	 * unaffected; "brl" governs byte-range locks only (mount.cifs nobrl).
	 */
	if (!sbi->brl)
		return locks_lock_file_wait(file, fl);
	return vmsmb_setlk(file, fl);
}

static int vmsmb_file_flock(struct file *file, int cmd, struct file_lock *fl)
{
	if (!(fl->c.flc_flags & FL_FLOCK))
		return -ENOLCK;
	/* flock() is whole-file and never F_GETLK; reuse the setlk backend. */
	return vmsmb_setlk(file, fl);
}

/* ---- fallocate ---- */

/*
 * fallocate — preallocate space, punch holes, or zero ranges.
 *
 * Port of CIFS smb3_fallocate()/smb3_punch_hole()/smb3_zero_range()
 * (fs/smb/client/smb2ops.c).  PUNCH_HOLE and ZERO_RANGE go through the
 * SET_SPARSE / SET_ZERO_DATA FSCTLs (both on vmusrv's whitelist); plain
 * preallocation (mode 0) just extends EOF, since NTFS files are non-sparse —
 * hence already fully allocated — by default.
 *
 * We have no oplock, so unlike CIFS we neither cache the sparse attribute nor
 * gate on cached read state: SET_SPARSE is issued unconditionally before a
 * punch and the server is authoritative for size.  COLLAPSE/INSERT_RANGE have
 * no SMB2 equivalent and are rejected.
 */
static long vmsmb_fallocate(struct file *file, int mode, loff_t offset,
			    loff_t len)
{
	struct vmsmb_file_ctx *ctx = file->private_data;
	struct inode *inode = file_inode(file);
	struct vmsmb_sb_info *sbi = VMSMB_SB(inode->i_sb);
	struct file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(offset),
		.BeyondFinalZero = cpu_to_le64(offset + len),
	};
	loff_t end = offset + len;
	int ret;

	if (mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE))
		return -EOPNOTSUPP;

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		u8 set_sparse = 1;

		/* Make the file sparse so the range is actually deallocated. */
		ret = vmsmb_smb2_ioctl(ctx->sess, sbi->tree_id, &ctx->fid,
				       FSCTL_SET_SPARSE, &set_sparse, 1,
				       NULL, 0, NULL);
		if (ret)
			return ret;

		filemap_invalidate_lock(inode->i_mapping);
		truncate_pagecache_range(inode, offset, end - 1);
		ret = vmsmb_smb2_ioctl(ctx->sess, sbi->tree_id, &ctx->fid,
				       FSCTL_SET_ZERO_DATA, &zd, sizeof(zd),
				       NULL, 0, NULL);
		filemap_invalidate_unlock(inode->i_mapping);
		return ret;
	}

	if (mode & FALLOC_FL_ZERO_RANGE) {
		filemap_invalidate_lock(inode->i_mapping);
		filemap_write_and_wait_range(inode->i_mapping, offset, end - 1);
		truncate_pagecache_range(inode, offset, end - 1);
		ret = vmsmb_smb2_ioctl(ctx->sess, sbi->tree_id, &ctx->fid,
				       FSCTL_SET_ZERO_DATA, &zd, sizeof(zd),
				       NULL, 0, NULL);
		filemap_invalidate_unlock(inode->i_mapping);
		if (ret)
			return ret;
		/* fall through for the optional EOF extend below */
	}

	/*
	 * Extend EOF when a non-KEEP_SIZE request runs past the current end.
	 * For KEEP_SIZE, or a mode-0 range within the file, there is nothing to
	 * do: NTFS files are non-sparse and thus already fully allocated.
	 * Mirrors vmsmb_setattr()'s ATTR_SIZE path.
	 */
	if (!(mode & FALLOC_FL_KEEP_SIZE) && end > i_size_read(inode)) {
		char *path = vmsmb_build_path(file_dentry(file));

		if (IS_ERR(path))
			return PTR_ERR(path);
		ret = vmsmb_smb2_set_eof(sbi->sess, sbi->tree_id, path, end);
		kfree(path);
		if (ret)
			return ret;
		truncate_setsize(inode, end);
	}

	return 0;
}

const struct file_operations vmsmb_file_ops = {
	.open		= vmsmb_file_open,
	.release	= vmsmb_file_release,
	.read_iter	= netfs_file_read_iter,
	.write_iter	= vmsmb_file_write_iter,
	.llseek		= vmsmb_file_llseek,
	.flush		= vmsmb_flush,
	.fsync		= vmsmb_fsync,
	.mmap		= generic_file_mmap,
	.splice_read	= filemap_splice_read,
	.splice_write	= iter_file_splice_write,
	.lock		= vmsmb_file_lock,
	.flock		= vmsmb_file_flock,
	.fallocate	= vmsmb_fallocate,
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
 * Instantiate a directory entry into the dentry cache while the listing that
 * produced it is still in hand, so a stat() that follows costs no round trip.
 *
 * Port of CIFS cifs_prime_dcache() (fs/smb/client/readdir.c).  Ours is the
 * shape upstream reaches when the entry needs no revalidation: a reparse point
 * is left alone, because a listing reports only its tag while the size we must
 * publish for a symlink is the length of its target, which only the separate
 * IOCTL in vmsmb_lookup() can supply.
 *
 * d_hash_and_lookup() is open-coded: it stopped being exported in 6.16
 * (06c567403ae5), and the replacement try_lookup_noperm() warns unless the
 * parent's i_rwsem is held, which readdir does not hold.  The hash must be
 * computed here because d_alloc_parallel() reads name->hash without deriving
 * it.  vmsmb_dentry_ops has no ->d_hash, so the DCACHE_OP_HASH dispatch
 * upstream performs between the two has nothing to do.
 */
static void vmsmb_prime_dcache(struct dentry *parent, struct qstr *name,
			       struct vmsmb_file_info *info)
{
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);
	struct super_block *sb = parent->d_sb;
	struct dentry *dentry, *alias;
	struct inode *inode;

	if (info->attributes & FILE_ATTRIBUTE_REPARSE_POINT)
		return;

	name->hash = full_name_hash(parent, name->name, name->len);
	dentry = d_lookup(parent, name);
	if (dentry) {
		inode = d_inode(dentry);
		/*
		 * Never touch a dentry something is mounted on: d_invalidate()
		 * below would detach the covering mount.  Nested vsmb shares
		 * are mounted inside their parent share exactly this way.
		 */
		if (inode && d_mountpoint(dentry)) {
			dput(dentry);
			return;
		}
		if (inode &&
		    VMSMB_I(inode)->index_number == info->index_number) {
			vmsmb_refresh_inode(inode, info, true);
			dput(dentry);
			return;
		}
		/*
		 * Negative, or the name now resolves to a different file.  Drop
		 * it and let the next lookup rebuild it; do not allocate a
		 * replacement here, since that lookup will go to the server
		 * anyway.
		 */
		d_invalidate(dentry);
		dput(dentry);
		return;
	}

	dentry = d_alloc_parallel(parent, name, &wq);
	if (IS_ERR(dentry))
		return;
	if (!d_in_lookup(dentry)) {
		/* A parallel lookup instantiated it first; leave it to them. */
		dput(dentry);
		return;
	}

	inode = vmsmb_iget(sb, info, true);
	if (IS_ERR(inode))
		inode = NULL;
	alias = d_splice_alias(inode, dentry);
	d_lookup_done(dentry);
	if (!IS_ERR_OR_NULL(alias))
		dput(alias);
	dput(dentry);
}

/*
 * Enumerate a directory — SMB2 QUERY_DIRECTORY with
 * FileIdFullDirectoryInformation.
 *
 * Port of CIFS cifs_readdir() (fs/smb/client/readdir.c): open the dir with
 * FILE_LIST_DIRECTORY, loop QUERY_DIRECTORY until STATUS_NO_MORE_FILES,
 * feed each FILE_ID_FULL_DIR_INFO into dir_emit().
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
				NULL, &fid, NULL);
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

		size_t offset = 0;

		while (offset + sizeof(FILE_ID_FULL_DIR_INFO) <= data_len) {
			const FILE_ID_FULL_DIR_INFO *entry =
				(const FILE_ID_FULL_DIR_INFO *)((u8 *)buf + offset);
			u32 name_len = le32_to_cpu(entry->FileNameLength);
			u32 attrs = le32_to_cpu(entry->ExtFileAttributes);
			u32 next = le32_to_cpu(entry->NextEntryOffset);
			unsigned char d_type;
			char name_utf8[256];
			int utf8_len;
			u64 ino;

			if (name_len > data_len - offset - sizeof(*entry))
				break;

			utf8_len = vmsmb_utf16_name_to_utf8(name_utf8,
						      sizeof(name_utf8),
						      entry->FileName,
						      name_len);
			if (utf8_len < 0)
				goto next_entry;

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

			ino = le64_to_cpu(entry->UniqueId);
			if (ino) {
				struct vmsmb_file_info info = {
					.size = le64_to_cpu(entry->EndOfFile),
					.alloc_size = le64_to_cpu(entry->AllocationSize),
					.creation_time = le64_to_cpu(entry->CreationTime),
					.last_access_time = le64_to_cpu(entry->LastAccessTime),
					.last_write_time = le64_to_cpu(entry->LastWriteTime),
					.change_time = le64_to_cpu(entry->ChangeTime),
					.attributes = attrs,
					.index_number = ino,
				};
				struct qstr qname = QSTR_INIT(name_utf8, utf8_len);

				vmsmb_prime_dcache(file_dentry(file), &qname,
						   &info);
			} else {
				/* No file ID: nothing to key an inode on. */
				ino = atomic64_inc_return(&vmsmb_ino_counter);
			}

			if (!dir_emit(ctx, name_utf8, utf8_len, ino, d_type))
				goto out;

			ctx->pos++;

next_entry:
			if (next == 0)
				break;
			offset += next;
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

	INIT_LIST_HEAD(&vi->open_ctxs);
	spin_lock_init(&vi->open_ctx_lock);
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

	/* Stable filesystem id: hash of the share name (so two mounts of the
	 * same share report the same fsid) plus the tree id. f_files/f_ffree
	 * stay 0 — NTFS has no fixed inode table to report, as in CIFS. */
	buf->f_fsid.val[0] = full_name_hash(NULL, sbi->share_name,
					    strlen(sbi->share_name));
	buf->f_fsid.val[1] = sbi->tree_id;

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

/*
 * Render the active mount options into /proc/mounts.
 *
 * Port of CIFS cifs_show_options() (fs/smb/client/cifsfs.c): uid/gid are
 * emitted through the mounting user namespace, modes in octal. Options are
 * always shown (not only when non-default) so the mount line round-trips.
 */
static int vmsmb_show_options(struct seq_file *s, struct dentry *root)
{
	struct vmsmb_sb_info *sbi = VMSMB_SB(root->d_sb);

	seq_printf(s, ",uid=%u",
		   from_kuid_munged(&init_user_ns, sbi->uid));
	seq_printf(s, ",gid=%u",
		   from_kgid_munged(&init_user_ns, sbi->gid));
	seq_printf(s, ",file_mode=0%o", sbi->file_mode);
	seq_printf(s, ",dir_mode=0%o", sbi->dir_mode);
	if (sbi->noperm)
		seq_puts(s, ",noperm");
	if (sbi->symlinkroot)
		seq_show_option(s, "symlinkroot", sbi->symlinkroot);
	seq_printf(s, ",actimeo=%lu", sbi->actimeo / HZ);
	seq_puts(s, sbi->oplocks ? ",oplock" : ",nooplock");
	seq_puts(s, sbi->brl ? ",brl" : ",nobrl");

	return 0;
}

static const struct super_operations vmsmb_super_ops = {
	.alloc_inode	= vmsmb_alloc_inode,
	.free_inode	= vmsmb_free_inode,
	.write_inode	= vmsmb_write_inode,
	.evict_inode	= vmsmb_evict_inode,
	.statfs		= vmsmb_statfs,
	.show_options	= vmsmb_show_options,
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
				NULL, &root_fid, &root_info);
	if (ret == 0)
		vmsmb_smb2_close(sess, sbi->tree_id, &root_fid);


	if (ret) {
		pr_err("failed to open share root: %d\n", ret);
		return ret;
	}

	root_inode = vmsmb_iget(sb, &root_info, false);
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
	Opt_oplock,
	Opt_brl,
};

static const struct fs_parameter_spec vmsmb_fs_parameters[] = {
	fsparam_u32("uid",		Opt_uid),
	fsparam_u32("gid",		Opt_gid),
	fsparam_u32oct("file_mode",	Opt_file_mode),
	fsparam_u32oct("dir_mode",	Opt_dir_mode),
	fsparam_flag("noperm",		Opt_noperm),
	fsparam_string("symlinkroot",	Opt_symlinkroot),
	fsparam_u32("actimeo",		Opt_actimeo),
	fsparam_flag_no("oplock",	Opt_oplock),
	fsparam_flag_no("brl",		Opt_brl),
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
	bool oplocks;
	bool oplocks_set;
	bool brl;
	bool brl_set;
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
	case Opt_oplock:
		ctx->oplocks = !result.negated;
		ctx->oplocks_set = true;
		break;
	case Opt_brl:
		ctx->brl = !result.negated;
		ctx->brl_set = true;
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

	sbi->oplocks = ctx->oplocks;
	sbi->brl = ctx->brl;

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

/*
 * Apply changed mount options to a live superblock on `mount -o remount`.
 * Only options explicitly given on the remount command are touched; the
 * rest keep their current values. uid/gid/mode changes affect inodes
 * instantiated after the remount (cached inodes keep their fill-time
 * identity), matching CIFS remount semantics. The VFS handles the
 * generic ro/rw flag separately.
 */
static int vmsmb_reconfigure(struct fs_context *fc)
{
	struct vmsmb_fs_context *ctx = fc->fs_private;
	struct vmsmb_sb_info *sbi = VMSMB_SB(fc->root->d_sb);

	if (ctx->uid_set)
		sbi->uid = ctx->uid;
	if (ctx->gid_set)
		sbi->gid = ctx->gid;
	if (ctx->file_mode_set)
		sbi->file_mode = ctx->file_mode;
	if (ctx->dir_mode_set)
		sbi->dir_mode = ctx->dir_mode;
	if (ctx->noperm) {
		sbi->noperm = true;
		sbi->file_mode = 0777;
		sbi->dir_mode = 0777;
	}
	if (ctx->actimeo_secs)
		sbi->actimeo = ctx->actimeo_secs * HZ;
	if (ctx->oplocks_set)
		sbi->oplocks = ctx->oplocks;
	if (ctx->brl_set)
		sbi->brl = ctx->brl;
	if (ctx->symlinkroot) {
		char *old = sbi->symlinkroot;

		sbi->symlinkroot = ctx->symlinkroot;
		ctx->symlinkroot = NULL;
		kfree(old);
	}

	return 0;
}

static const struct fs_context_operations vmsmb_context_ops = {
	.parse_param	= vmsmb_parse_param,
	.get_tree	= vmsmb_get_tree,
	.reconfigure	= vmsmb_reconfigure,
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
	ctx->oplocks = true;	/* LEVEL_II coherence on by default; nooplock disables */
	return 0;
}

/*
 * Release superblock resources on unmount — drop the tree connect, then
 * free sbi's strings + the sbi struct.
 *
 * Port of CIFS cifs_kill_sb() (fs/smb/client/cifsfs.c) simplified: no
 * per-sb cifs_sb_tlink_tree / tcon teardown.
 */
static void vmsmb_kill_sb(struct super_block *sb)
{
	struct vmsmb_sb_info *sbi = sb->s_fs_info;

	kill_anon_super(sb);

	if (sbi) {
		/*
		 * Best-effort TREE_DISCONNECT after kill_anon_super() has
		 * evicted all inodes (so no file ops remain on this tree).
		 * Ignore the result: the host releases the tree connect anyway
		 * when the VMBus channel closes, and a slow/failed teardown
		 * must not block unmount.
		 */
		if (sbi->sess && sbi->tree_id)
			vmsmb_smb2_tree_disconnect(sbi->sess, sbi->tree_id);
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
