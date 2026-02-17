// ops.c — Inode operations (create, mkdir, unlink, rmdir, link)

#include "vtfs.h"

const struct inode_operations vtfs_inode_ops = {
  .lookup = vtfs_lookup,
  .create = vtfs_create,
  .unlink = vtfs_unlink,
  .mkdir = vtfs_mkdir,
  .rmdir = vtfs_rmdir,
  .link = vtfs_link,
};

int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode,
                struct dentry *child_dentry, umode_t mode, bool excl)
{
  const char *name = child_dentry->d_name.name;
  struct vtfs_node *parent, *n;
  struct inode *inode;
  int pr;

  (void)idmap;
  (void)excl;

  parent = vtfs_node_from_inode(parent_inode->i_sb, parent_inode->i_ino);
  if (!parent || !parent->is_dir)
    return -ENOTDIR;

  if (strlen(name) == 0 || strlen(name) > VTFS_NAME_MAX)
    return -ENAMETOOLONG;

  if (vtfs_find_child(parent, name))
    return -EEXIST;

  n = vtfs_alloc_node(parent, name, false);
  if (!n)
    return -ENOMEM;

  pr = vtfs_push_create(parent->ino, name, n->ino);
  if (pr)
    LOG("push create failed: %d\n", pr);

  mode = S_IFREG | (mode & 0777);
  if ((mode & 0777) == 0)
    mode = S_IFREG | 0777;

  inode = vtfs_iget(parent_inode->i_sb, parent_inode, mode, n->ino);
  if (!inode) {
    list_del(&n->sibling);
    vtfs_free_node(n);
    return -ENOMEM;
  }

  d_add(child_dentry, inode);
  return 0;
}

int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode,
               struct dentry *child_dentry, umode_t mode)
{
  const char *name = child_dentry->d_name.name;
  struct vtfs_node *parent, *n;
  struct inode *inode;
  int pr;

  (void)idmap;

  parent = vtfs_node_from_inode(parent_inode->i_sb, parent_inode->i_ino);
  if (!parent || !parent->is_dir)
    return -ENOTDIR;

  if (strlen(name) == 0 || strlen(name) > VTFS_NAME_MAX)
    return -ENAMETOOLONG;

  if (vtfs_find_child(parent, name))
    return -EEXIST;

  n = vtfs_alloc_node(parent, name, true);
  if (!n)
    return -ENOMEM;

  pr = vtfs_push_mkdir(parent->ino, name, n->ino);
  if (pr)
    LOG("push mkdir failed: %d\n", pr);

  mode = S_IFDIR | (mode & 0777);
  if ((mode & 0777) == 0)
    mode = S_IFDIR | 0777;

  inode = vtfs_iget(parent_inode->i_sb, parent_inode, mode, n->ino);
  if (!inode) {
    list_del(&n->sibling);
    vtfs_free_node(n);
    return -ENOMEM;
  }

  d_add(child_dentry, inode);
  inc_nlink(parent_inode);
  return 0;
}

int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry)
{
  const char *name = child_dentry->d_name.name;
  struct vtfs_node *parent, *n;
  struct inode *inode = d_inode(child_dentry);
  int pr;

  parent = vtfs_node_from_inode(parent_inode->i_sb, parent_inode->i_ino);
  if (!parent || !parent->is_dir)
    return -ENOTDIR;

  n = vtfs_find_child(parent, name);
  if (!n)
    return -ENOENT;

  if (n->is_dir)
    return -EISDIR;

  pr = vtfs_push_unlink(parent->ino, name);
  if (pr)
    LOG("push unlink failed: %d\n", pr);

  list_del(&n->sibling);
  d_drop(child_dentry);

  if (inode) {
    drop_nlink(inode);
    if (inode->i_nlink == 0) {
      vtfs_free_node(n);
    }
  }

  return 0;
}

int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry)
{
  const char *name = child_dentry->d_name.name;
  struct vtfs_node *parent, *n;
  int pr;

  parent = vtfs_node_from_inode(parent_inode->i_sb, parent_inode->i_ino);
  if (!parent || !parent->is_dir)
    return -ENOTDIR;

  n = vtfs_find_child(parent, name);
  if (!n)
    return -ENOENT;

  if (!n->is_dir)
    return -ENOTDIR;

  if (!list_empty(&n->children))
    return -ENOTEMPTY;

  pr = vtfs_push_rmdir(parent->ino, name);
  if (pr)
    LOG("push rmdir failed: %d\n", pr);

  list_del(&n->sibling);
  d_drop(child_dentry);
  vtfs_free_node(n);

  drop_nlink(parent_inode);
  return 0;
}

int vtfs_link(struct dentry *old_dentry, struct inode *parent_dir,
              struct dentry *new_dentry)
{
  struct inode *inode = d_inode(old_dentry);
  struct vtfs_node *parent, *target, *newn;
  const char *name = new_dentry->d_name.name;
  int pr;

  if (!inode)
    return -ENOENT;
  if (S_ISDIR(inode->i_mode))
    return -EPERM;

  parent = vtfs_node_from_inode(parent_dir->i_sb, parent_dir->i_ino);
  if (!parent || !parent->is_dir)
    return -ENOTDIR;

  if (strlen(name) == 0 || strlen(name) > VTFS_NAME_MAX)
    return -ENAMETOOLONG;

  if (vtfs_find_child(parent, name))
    return -EEXIST;

  target = vtfs_node_from_inode(parent_dir->i_sb, inode->i_ino);
  if (!target || target->is_dir || !target->file)
    return -EINVAL;

  newn = kzalloc(sizeof(*newn), GFP_KERNEL);
  if (!newn)
    return -ENOMEM;

  newn->name = kstrdup(name, GFP_KERNEL);
  if (!newn->name) {
    kfree(newn);
    return -ENOMEM;
  }

  INIT_LIST_HEAD(&newn->sibling);
  INIT_LIST_HEAD(&newn->children);

  newn->parent = parent;
  newn->is_dir = false;
  newn->ino = target->ino;
  newn->file = target->file;
  atomic_inc(&newn->file->nlink);

  list_add_tail(&newn->sibling, &parent->children);

  pr = vtfs_push_link(parent->ino, name, target->ino);
  if (pr)
    LOG("push link failed: %d\n", pr);

  inc_nlink(inode);

  return 0;
}