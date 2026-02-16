// file.c — File operations (open/read/write)

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "vtfs.h"

const struct file_operations vtfs_file_ops = {
  .open = vtfs_open,
  .llseek = generic_file_llseek,
};

int vtfs_open(struct inode *inode, struct file *filp)
{
  struct vtfs_node *n = vtfs_node_from_inode(inode->i_sb, inode->i_ino);

  if (!n || n->is_dir)
    return -EISDIR;

  filp->private_data = n;

  if (filp->f_flags & O_TRUNC) {
    if (n->file) {
      kfree(n->file->data);
      n->file->data = NULL;
      n->file->size = 0;
      n->file->cap = 0;
    }
    filp->f_pos = 0;
  }

  return 0;
}
