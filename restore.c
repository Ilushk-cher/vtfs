// restore.c — Restore filesystem state from server on mount

#include "vtfs.h"

static int vtfs_parse_mode(const char *s, umode_t *out)
{
  unsigned long v;
  char *endp;

  if (!s || !out)
    return -EINVAL;

  if (s[0] == '0' && (s[1] == 'o' || s[1] == 'O'))
    s += 2;

  v = simple_strtoul(s, &endp, 8);
  if (endp == s)
    return -EINVAL;

  *out = (umode_t)(v & 0777);
  return 0;
}

int vtfs_load_file_from_server(struct vtfs_file *f, ino_t ino, size_t size)
{
  char ino_s[32], off_s[32], len_s[32];
  size_t off = 0;
  char *tmp;
  int64_t rc;

  if (!f)
    return -EINVAL;

  kfree(f->data);
  f->data = NULL;
  f->size = 0;
  f->cap = 0;

  if (size == 0)
    return 0;

  f->data = kmalloc(size, GFP_KERNEL);
  if (!f->data)
    return -ENOMEM;
  f->cap = size;

  tmp = kmalloc(VTFS_CHUNK, GFP_KERNEL);
  if (!tmp)
    return -ENOMEM;

  snprintf(ino_s, sizeof(ino_s), "%lu", (unsigned long)ino);

  while (off < size) {
    size_t want = size - off;
    if (want > VTFS_CHUNK)
      want = VTFS_CHUNK;

    snprintf(off_s, sizeof(off_s), "%zu", off);
    snprintf(len_s, sizeof(len_s), "%zu", want);

    rc = vtfs_http_call(vtfs_token, "read", tmp, want, 3,
                        "ino", ino_s, "off", off_s, "len", len_s);
    if (rc != 0) {
      kfree(tmp);
      return -EIO;
    }

    memcpy(f->data + off, tmp, want);
    off += want;
  }

  f->size = size;
  kfree(tmp);
  return 0;
}

int vtfs_restore_from_server(struct super_block *sb, int *out_restored)
{
  struct vtfs_node *root = vtfs_root(sb);
  char *dump;
  size_t dump_sz = 256 * 1024;
  int64_t rc;
  char *p, *line;
  int restored = 0;
  struct inode *inode;

  if (out_restored)
    *out_restored = 0;

  if (!root)
    return -EINVAL;

  dump = kzalloc(dump_sz, GFP_KERNEL);
  if (!dump)
    return -ENOMEM;

  rc = vtfs_http_call(vtfs_token, "dump", dump, dump_sz - 1, 0);
  if (rc != 0) {
    kfree(dump);
    return 0;
  }

  p = dump;

  while ((line = strsep(&p, "\n")) != NULL) {
    char *t, *ino_s, *pino_s, *name, *mode_s, *size_s, *target_s;
    ino_t ino, pino, target;
    struct vtfs_node *parent, *n, *target_node;
    umode_t mode;

    if (!line[0])
      continue;

    t = strsep(&line, "\t");
    ino_s = strsep(&line, "\t");
    pino_s = strsep(&line, "\t");
    name = strsep(&line, "\t");

    if (!t || !ino_s || !pino_s || !name)
      continue;

    ino = (ino_t)simple_strtoul(ino_s, NULL, 10);
    pino = (ino_t)simple_strtoul(pino_s, NULL, 10);

    if (ino == ROOT_DIR)
      continue;

    parent = vtfs_node_from_inode(sb, pino);
    if (!parent || !parent->is_dir)
      continue;

    if (vtfs_find_child(parent, name))
      continue;

    if (t[0] == 'D') {
      mode = 0777;
      mode_s = strsep(&line, "\t");
      if (mode_s)
        vtfs_parse_mode(mode_s, &mode);

      n = vtfs_alloc_node_ino(parent, name, true, ino);
      if (!n)
        continue;

      inode = vtfs_iget(sb, NULL, S_IFDIR | mode, n->ino);
      if (inode)
        iput(inode);

      restored++;
      continue;
    }

    if (t[0] == 'F') {
      mode = 0777;
      size_t sz = 0;

      mode_s = strsep(&line, "\t");
      size_s = strsep(&line, "\t");
      if (!mode_s || !size_s)
        continue;

      vtfs_parse_mode(mode_s, &mode);
      sz = (size_t)simple_strtoul(size_s, NULL, 10);

      target_node = vtfs_find_any_node(sb, ino);
      if (target_node) {
        LOG("restore: inode %lu already exists, creating hardlink\n", (unsigned long)ino);
        
        n = kzalloc(sizeof(*n), GFP_KERNEL);
        if (!n)
          continue;

        n->name = kstrdup(name, GFP_KERNEL);
        if (!n->name) {
          kfree(n);
          continue;
        }

        INIT_LIST_HEAD(&n->sibling);
        INIT_LIST_HEAD(&n->children);

        n->parent = parent;
        n->is_dir = false;
        n->ino = target_node->ino;
        n->file = target_node->file;
        
        atomic_inc(&n->file->nlink);
        
        inode = vtfs_iget(sb, NULL, S_IFREG | mode, n->ino);
        if (inode) {
          inc_nlink(inode);
          LOG("restore: inc_nlink for inode %lu, i_nlink=%d\n", 
              (unsigned long)inode->i_ino, inode->i_nlink);
        }

        list_add_tail(&n->sibling, &parent->children);
        restored++;
        continue;
      }

      n = vtfs_alloc_node_ino(parent, name, false, ino);
      if (!n)
        continue;

      if (vtfs_load_file_from_server(n->file, ino, sz) != 0) {
        vtfs_free_node(n);
        continue;
      }
      
      atomic_set(&n->file->nlink, 1);
      
      inode = vtfs_iget(sb, NULL, S_IFREG | mode, n->ino);
      if (inode) {
        set_nlink(inode, 1);
        i_size_write(inode, sz);
        inode->i_blocks = (sz + VTFS_BLOCK_SIZE - 1) >> VTFS_BLOCK_SHIFT;
        LOG("restore: set_nlink for inode %lu = 1\n", (unsigned long)n->ino);
      }
      
      restored++;
      LOG("restore: created file inode %lu\n", (unsigned long)ino);
      continue;
    }

    if (t[0] == 'L') {
      target_s = strsep(&line, "\t");
      if (!target_s)
        continue;

      target = (ino_t)simple_strtoul(target_s, NULL, 10);
      
      target_node = vtfs_find_any_node(sb, target);
      if (!target_node || target_node->is_dir || !target_node->file) {
        LOG("restore: link target %lu not found, skipping\n", (unsigned long)target);
        continue;
      }

      n = kzalloc(sizeof(*n), GFP_KERNEL);
      if (!n)
        continue;

      n->name = kstrdup(name, GFP_KERNEL);
      if (!n->name) {
        kfree(n);
        continue;
      }

      INIT_LIST_HEAD(&n->sibling);
      INIT_LIST_HEAD(&n->children);

      n->parent = parent;
      n->is_dir = false;
      n->ino = target;
      n->file = target_node->file;
      
      atomic_inc(&n->file->nlink);
      
      inode = vtfs_iget(sb, NULL, S_IFREG | 0777, target);
      if (inode) {
        inc_nlink(inode);
        LOG("restore: inc_nlink for inode %lu, i_nlink=%d\n", 
            (unsigned long)target, inode->i_nlink);
      }

      list_add_tail(&n->sibling, &parent->children);
      restored++;
      
      LOG("restore: added hardlink '%s' -> inode %lu (nlink=%d)\n", 
          name, (unsigned long)target, atomic_read(&n->file->nlink));
      continue;
    }
  }

  if (out_restored)
    *out_restored = restored;

  kfree(dump);
  return 0;
}