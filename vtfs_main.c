// vtfs_main.c — Module initialization and filesystem registration

#include "vtfs.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("akiLsuh");
MODULE_DESCRIPTION("VTFS: RAM tree + HTTP push/restore");

char *vtfs_token = "testtoken";
module_param(vtfs_token, charp, 0600);

ino_t next_ino = 101;

/* Filesystem type */
extern struct dentry *vtfs_mount(struct file_system_type *fs_type,
                                 int flags, const char *token, void *data);
extern void vtfs_kill_sb(struct super_block *sb);

static struct file_system_type vtfs_fs_type = {
  .name = "vtfs",
  .mount = vtfs_mount,
  .kill_sb = vtfs_kill_sb,
  .owner = THIS_MODULE,
};

static int __init vtfs_init(void)
{
  int ret = register_filesystem(&vtfs_fs_type);
  if (ret) {
    pr_err("[" MODULE_NAME "]: register_filesystem failed: %d\n", ret);
    return ret;
  }
  LOG("VTFS joined the kernel\n");
  return 0;
}

static void __exit vtfs_exit(void)
{
  int ret = unregister_filesystem(&vtfs_fs_type);
  if (ret)
    pr_err("[" MODULE_NAME "]: unregister_filesystem failed: %d\n", ret);
  LOG("VTFS left the kernel\n");
}

module_init(vtfs_init);
module_exit(vtfs_exit);