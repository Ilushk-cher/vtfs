// file.c — File operations (open/read/write)

#include "vtfs.h"

const struct file_operations vtfs_file_ops = {
  .open = vtfs_open,
  .read = vtfs_read,
  .write = vtfs_write,
  .llseek = generic_file_llseek,
};

int vtfs_open(struct inode *inode, struct file *filp)
{
  struct vtfs_node *n = vtfs_node_from_inode(inode->i_sb, inode->i_ino);

  if (!n || n->is_dir)
    return -EISDIR;

  if (!n->file || atomic_read(&n->file->nlink) == 0)
    return -ENOENT;

  filp->private_data = n;

  if (filp->f_flags & O_TRUNC) {
    if (n->file) {
      kfree(n->file->data);
      n->file->data = NULL;
      n->file->size = 0;
      n->file->cap = 0;
    }
    vtfs_push_truncate(n->ino, 0);
    filp->f_pos = 0;
    
    i_size_write(inode, 0);
    inode->i_blocks = 0;
  }

  return 0;
}

ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t len, loff_t *offset)
{
  struct vtfs_node *n = (struct vtfs_node *)filp->private_data;
  struct vtfs_file *f;
  size_t avail;

  if (!n || n->is_dir)
    return -EIO;

  f = n->file;
  if (!f)
    return -EIO;

  if (*offset < 0)
    return -EINVAL;

  if ((size_t)*offset >= f->size)
    return 0;

  avail = f->size - (size_t)*offset;
  if (len > avail)
    len = avail;

  if (len == 0)
    return 0;

  if (copy_to_user(buffer, f->data + *offset, len))
    return -EFAULT;

  *offset += len;
  return (ssize_t)len;
}

ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t len, loff_t *offset)
{
  struct vtfs_node *n = (struct vtfs_node *)filp->private_data;
  struct vtfs_file *f;
  size_t endpos, need;
  char *newbuf;
  size_t done = 0;
  char *tmp;
  char *encoded;

  if (!n || n->is_dir)
    return -EIO;

  f = n->file;
  if (!f)
    return -EIO;

  if (*offset < 0)
    return -EINVAL;

  if (len == 0)
    return 0;

  endpos = (size_t)*offset + len;
  need = endpos;

  if (need > f->cap) {
    size_t newcap = f->cap ? f->cap : 64;
    while (newcap < need) {
      if (newcap > (SIZE_MAX / 2))
        return -EFBIG;
      newcap *= 2;
    }
    newbuf = krealloc(f->data, newcap, GFP_KERNEL);
    if (!newbuf)
      return -ENOMEM;
    f->data = newbuf;
    f->cap = newcap;
  }

  tmp = kmalloc(min_t(size_t, len, VTFS_CHUNK), GFP_KERNEL);
  if (!tmp)
    return -ENOMEM;

  encoded = kmalloc(VTFS_CHUNK * 3 + 1, GFP_KERNEL);
  if (!encoded) {
    kfree(tmp);
    return -ENOMEM;
  }

  while (done < len) {
    size_t chunk = min_t(size_t, len - done, VTFS_CHUNK);
    int pr;

    if (copy_from_user(tmp, buffer + done, chunk)) {
      kfree(tmp);
      kfree(encoded);
      return -EFAULT;
    }

    memcpy(f->data + (size_t)*offset + done, tmp, chunk);

    encode(tmp, encoded);
    pr = vtfs_push_write(n->ino, (size_t)*offset + done, encoded, strlen(encoded));
    if (pr)
      LOG("push write failed: %d\n", pr);

    done += chunk;
  }

  kfree(tmp);
  kfree(encoded);

  if (endpos > f->size) {
    f->size = endpos;
    i_size_write(filp->f_inode, f->size);
  }

  *offset += len;

  filp->f_inode->i_blocks = (f->size + VTFS_BLOCK_SIZE - 1) >> VTFS_BLOCK_SHIFT;

  LOG("write: size=%zu, i_size=%lld, blocks=%llu\n", 
      f->size, (long long)filp->f_inode->i_size,
      (unsigned long long)filp->f_inode->i_blocks);

  return (ssize_t)len;
}