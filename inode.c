// inode.c — Inode operations and management

#include "vtfs.h"

struct inode *vtfs_iget(struct super_block *sb, const struct inode *dir,
                        umode_t mode, ino_t ino)
{
  struct inode *inode = iget_locked(sb, ino);
  struct vtfs_node *n;

  if (!inode)
    return NULL;

  if (!(inode->i_state & I_NEW))
    return inode;

  inode_init_owner(&nop_mnt_idmap, inode, dir, mode);
  inode->i_ino = ino;

  if (S_ISDIR(mode)) {
    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = &vtfs_dir_ops;
    inc_nlink(inode);
  } else if (S_ISREG(mode)) {
    inode->i_fop = &vtfs_file_ops;
    
    n = vtfs_node_from_inode(sb, ino);
    if (n && n->file) {
      inode->i_blocks = (n->file->size + VTFS_BLOCK_SIZE - 1) >> VTFS_BLOCK_SHIFT;
    }
  }

  unlock_new_inode(inode);
  return inode;
}

int vtfs_fill_super(struct super_block *sb, void *data, int silent)
{
  struct inode *inode;
  struct vtfs_node *root;
  int restored = 0;

  (void)silent;

  sb->s_magic = VTFS_MAGIC;
  sb->s_op = &vtfs_super_ops;
  sb->s_blocksize = VTFS_BLOCK_SIZE;
  sb->s_blocksize_bits = VTFS_BLOCK_SHIFT;

  if (data && ((char *)data)[0] != '\0') {
    char *opt = (char *)data;
    if (!strncmp(opt, "token=", 6))
      vtfs_token = opt + 6;
  }

  root = kzalloc(sizeof(*root), GFP_KERNEL);
  if (!root)
    return -ENOMEM;

  INIT_LIST_HEAD(&root->sibling);
  INIT_LIST_HEAD(&root->children);
  root->parent = NULL;
  root->is_dir = true;
  root->ino = ROOT_DIR;
  root->name = kstrdup("/", GFP_KERNEL);
  if (!root->name) {
    kfree(root);
    return -ENOMEM;
  }

  sb->s_fs_info = root;

  inode = vtfs_iget(sb, NULL, S_IFDIR | 0777, ROOT_DIR);
  if (!inode)
    return -ENOMEM;

  sb->s_root = d_make_root(inode);
  if (!sb->s_root)
    return -ENOMEM;

  vtfs_restore_from_server(sb, &restored);
  LOG("restore: parsed nodes=%d\n", restored);
  pr_info("[" MODULE_NAME "]: vtfs_fill_super: ok (token=%s)\n", vtfs_token);
  return 0;
}