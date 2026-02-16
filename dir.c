// dir.c — Directory operations

#include <linux/fs.h>
#include <linux/slab.h>
#include "vtfs.h"

const struct file_operations vtfs_dir_ops = {
  .iterate_shared = vtfs_iterate,
};

int vtfs_iterate(struct file *filp, struct dir_context *ctx)
{
  struct dentry *dentry = filp->f_path.dentry;
  struct inode *inode = dentry->d_inode;
  struct vtfs_node *dir;
  loff_t pos;

  dir = vtfs_node_from_inode(inode->i_sb, inode->i_ino);
  if (!dir || !dir->is_dir)
    return 0;

  if (ctx->pos == 0) {
    if (!dir_emit(ctx, ".", 1, inode->i_ino, DT_DIR))
      return 0;
    ctx->pos++;
  }

  if (ctx->pos == 1) {
    ino_t pino = dir->parent ? dir->parent->ino : inode->i_ino;
    if (!dir_emit(ctx, "..", 2, pino, DT_DIR))
      return 0;
    ctx->pos++;
  }

  pos = ctx->pos - 2;
  {
    struct vtfs_node *c;
    loff_t idx = 0;

    list_for_each_entry(c, &dir->children, sibling) {
      if (idx++ < pos)
        continue;

      if (!dir_emit(ctx, c->name, strlen(c->name), c->ino,
                    c->is_dir ? DT_DIR : DT_REG))
        return 0;

      ctx->pos++;
    }
  }

  return 0;
}

struct dentry *vtfs_lookup(struct inode *parent_inode, struct dentry *child_dentry,
                           unsigned int flag)
{
  const char *name = child_dentry->d_name.name;
  struct vtfs_node *parent;
  struct vtfs_node *n;
  struct inode *inode;
  umode_t mode;

  (void)flag;

  parent = vtfs_node_from_inode(parent_inode->i_sb, parent_inode->i_ino);
  if (!parent || !parent->is_dir)
    return NULL;

  n = vtfs_find_child(parent, name);
  if (!n)
    return NULL;

  mode = n->is_dir ? (S_IFDIR | 0777) : (S_IFREG | 0777);

  inode = vtfs_iget(parent_inode->i_sb, parent_inode, mode, n->ino);
  if (inode)
    d_add(child_dentry, inode);

  return NULL;
}