// store.c — RAM tree storage management

#include <linux/slab.h>
#include <linux/string.h>
#include "vtfs.h"

struct vtfs_node *vtfs_root(struct super_block *sb)
{
  return (struct vtfs_node *)sb->s_fs_info;
}

static struct vtfs_node *vtfs_dfs_find(struct vtfs_node *n, ino_t ino)
{
  struct vtfs_node *c, *r;

  if (!n)
    return NULL;
  if (n->ino == ino)
    return n;

  list_for_each_entry(c, &n->children, sibling) {
    r = vtfs_dfs_find(c, ino);
    if (r)
      return r;
  }
  return NULL;
}

struct vtfs_node *vtfs_node_from_inode(struct super_block *sb, ino_t ino)
{
  return vtfs_dfs_find(vtfs_root(sb), ino);
}

struct vtfs_node *vtfs_find_child(struct vtfs_node *dir, const char *name)
{
  struct vtfs_node *c;

  if (!dir || !dir->is_dir)
    return NULL;

  list_for_each_entry(c, &dir->children, sibling) {
    if (!strcmp(c->name, name))
      return c;
  }
  return NULL;
}

struct vtfs_file *vtfs_file_alloc(void)
{
  struct vtfs_file *f = kzalloc(sizeof(*f), GFP_KERNEL);
  if (!f)
    return NULL;
  atomic_set(&f->nlink, 1);
  return f;
}

void vtfs_file_put(struct vtfs_file *f)
{
  if (!f)
    return;
  if (atomic_dec_and_test(&f->nlink)) {
    kfree(f->data);
    kfree(f);
  }
}

struct vtfs_node *vtfs_alloc_node(struct vtfs_node *parent, const char *name, bool is_dir)
{
  struct vtfs_node *n;
  size_t len;

  if (!name)
    return NULL;

  len = strlen(name);
  if (len == 0 || len > VTFS_NAME_MAX)
    return NULL;

  n = kzalloc(sizeof(*n), GFP_KERNEL);
  if (!n)
    return NULL;

  n->name = kstrdup(name, GFP_KERNEL);
  if (!n->name) {
    kfree(n);
    return NULL;
  }

  INIT_LIST_HEAD(&n->sibling);
  INIT_LIST_HEAD(&n->children);

  n->parent = parent;
  n->is_dir = is_dir;
  n->ino = next_ino++;

  if (!is_dir) {
    n->file = vtfs_file_alloc();
    if (!n->file) {
      kfree(n->name);
      kfree(n);
      return NULL;
    }
  }

  if (parent)
    list_add_tail(&n->sibling, &parent->children);

  return n;
}

struct vtfs_node *vtfs_alloc_node_ino(struct vtfs_node *parent, const char *name,
                                      bool is_dir, ino_t ino)
{
  struct vtfs_node *n = vtfs_alloc_node(parent, name, is_dir);
  if (!n)
    return NULL;

  n->ino = ino;
  if (ino >= next_ino)
    next_ino = ino + 1;

  return n;
}

void vtfs_free_subtree(struct vtfs_node *n)
{
  struct vtfs_node *c, *tmp;

  if (!n)
    return;

  list_for_each_entry_safe(c, tmp, &n->children, sibling) {
    list_del(&c->sibling);
    vtfs_free_subtree(c);
  }

  if (!n->is_dir)
    vtfs_file_put(n->file);

  kfree(n->name);
  kfree(n);
}