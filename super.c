// super.c — Superblock operations and mount handling

#include "vtfs.h"

struct dentry *vtfs_mount(struct file_system_type *fs_type, int flags,
                          const char *token, void *data)
{
  struct dentry *ret = mount_nodev(fs_type, flags, data, vtfs_fill_super);
  (void)token;

  if (IS_ERR(ret)) {
    pr_err("[" MODULE_NAME "]: Can't mount: %ld\n", PTR_ERR(ret));
    return ret;
  }
  pr_info("[" MODULE_NAME "]: Mounted successfully\n");
  return ret;
}

void vtfs_kill_sb(struct super_block *sb)
{
  struct vtfs_node *root = vtfs_root(sb);

  kill_litter_super(sb);

  if (root) {
    vtfs_free_subtree(root);
    sb->s_fs_info = NULL;
  }

  pr_info("[" MODULE_NAME "]: Unmount successfully\n");
}

const struct super_operations vtfs_super_ops = {
  .statfs = simple_statfs,
  .drop_inode = generic_delete_inode,
};