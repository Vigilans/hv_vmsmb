// SPDX-License-Identifier: GPL-2.0
/*
 * vmsmb_main.c - VSMB kernel module entry point
 *
 * Registers as a VMBus driver for the VSMB channel GUID.
 * On probe: channel open → VSMB version → NEGOTIATE → SESSION_SETUP.
 * On mount: TREE_CONNECT → VFS superblock.
 */

#define pr_fmt(fmt) "hv_vmsmb: " fmt

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/hyperv.h>
#include "vmsmb.h"
#include "smb2pdu.h"

/* Global session (one VSMB channel per VM) */
struct vmsmb_session *vmsmb_global_session;

/* VMBus device table */
static const struct hv_vmbus_device_id vmsmb_id_table[] = {
	{ .guid = HV_VSMB_GUID },
	{ },
};
MODULE_DEVICE_TABLE(vmbus, vmsmb_id_table);

/*
 * VMBus probe — attach to the VSMB channel, bring up the session.
 *
 * Analogous to hvsock hvs_probe() (net/vmw_vsock/hyperv_transport.c) for
 * the channel-open half, and CIFS cifs_mount() (fs/smb/client/connect.c)
 * for the SMB2 NEGOTIATE+SESSION_SETUP retry loop. Pre-SMB2 version
 * handshake is VSMB-specific (see vmsmb_negotiate_version).
 */
static int vmsmb_probe(struct hv_device *dev,
		       const struct hv_vmbus_device_id *id)
{
	struct vmsmb_session *sess;
	int ret, retries;

	pr_info("probe: VSMB channel found\n");

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess)
		return -ENOMEM;

	sess->dev = dev;
	hv_set_drvdata(dev, sess);

	/* Step 1: Open VMBus channel */
	ret = vmsmb_open_channel(sess);
	if (ret)
		goto err_free;

	/* Step 2: VSMB version negotiation */
	ret = vmsmb_negotiate_version(sess);
	if (ret)
		goto err_close;

	/* Step 3+4: SMB2 NEGOTIATE + SESSION_SETUP with retry.
	 * At boot the host-side SMB2 layer may not be ready yet
	 * (version handshake succeeds but NEGOTIATE returns a
	 * truncated response). Retry a few times with delay.
	 */
	for (retries = 0; retries < 5; retries++) {
		if (retries > 0) {
			pr_info("probe: SMB2 handshake retry %d/5\n",
				retries + 1);
			msleep(500 * retries);
		}

		vmsmb_credit_reset(sess);
		ret = vmsmb_smb2_negotiate(sess);
		if (ret)
			continue;

		ret = vmsmb_smb2_session_setup(sess);
		if (ret == 0)
			break;
	}
	if (ret)
		goto err_close;

	pr_info("session ready: version=%u session=0x%llx MaxRead=%u\n",
		sess->vsmb_version, sess->session_id, sess->max_read_size);

	vmsmb_global_session = sess;
	return 0;

err_close:
	vmsmb_close_channel(sess);
err_free:
	kfree(sess);
	return ret;
}

/*
 * VMBus remove — tear down the session and clear the global pointer.
 *
 * Analogous to hvsock hvs_remove() (net/vmw_vsock/hyperv_transport.c).
 * Cannot reconnect after this runs: vmbus_close puts vmwp.exe's VsmbPipe
 * in terminal state (see docs/vmbus-pipe-protocol.md), so module reload
 * requires VM restart.
 */
static void vmsmb_remove(struct hv_device *dev)
{
	struct vmsmb_session *sess = hv_get_drvdata(dev);

	pr_info("removing\n");

	if (sess == vmsmb_global_session)
		vmsmb_global_session = NULL;

	if (sess) {
		vmsmb_close_channel(sess);
		kfree(sess);
	}
}

static struct hv_driver vmsmb_drv = {
	.name		= "hv_vmsmb",
	.id_table	= vmsmb_id_table,
	.probe		= vmsmb_probe,
	.remove		= vmsmb_remove,
};

static int __init vmsmb_init(void)
{
	int ret;

	pr_info("loading\n");

	vmsmb_inode_cachep = kmem_cache_create("vmsmb_inode_cache",
					       sizeof(struct vmsmb_inode_info),
					       0,
					       SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
					       vmsmb_init_once);
	if (!vmsmb_inode_cachep)
		return -ENOMEM;

	ret = vmbus_driver_register(&vmsmb_drv);
	if (ret) {
		pr_err("vmbus driver register failed: %d\n", ret);
		goto err_cache;
	}

	ret = register_filesystem(&vmsmb_fs_type);
	if (ret) {
		pr_err("register_filesystem failed: %d\n", ret);
		vmbus_driver_unregister(&vmsmb_drv);
		goto err_cache;
	}

	return 0;

err_cache:
	kmem_cache_destroy(vmsmb_inode_cachep);
	return ret;
}

static void __exit vmsmb_exit(void)
{
	unregister_filesystem(&vmsmb_fs_type);
	vmbus_driver_unregister(&vmsmb_drv);
	kmem_cache_destroy(vmsmb_inode_cachep);
	pr_info("unloaded\n");
}

module_init(vmsmb_init);
module_exit(vmsmb_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("VSMB (Virtual SMB) client over Hyper-V VMBus");
MODULE_AUTHOR("Vigilans");
