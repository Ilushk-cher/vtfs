#ifndef _VTFS_H
#define _VTFS_H

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/atomic.h>
#include <linux/list.h>

#define MODULE_NAME "vtfs"
#define ROOT_DIR 1000
#define VTFS_NAME_MAX 255
#define VTFS_CHUNK 4096
#define VTFS_MAGIC 0x56544653

#define LOG(fmt, ...) pr_info("[" MODULE_NAME "]: " fmt, ##__VA_ARGS__)

extern char *vtfs_token;

/* File structure */
struct vtfs_file {
  atomic_t nlink;
  char *data;
  size_t size;
  size_t cap;
};

/* Node structure */
struct vtfs_node {
  struct list_head sibling;
  struct list_head children;
  struct vtfs_node *parent;
  bool is_dir;
  ino_t ino;
  char *name;
  struct vtfs_file *file;
};

/* Global ino counter */
extern ino_t next_ino;

/* Node operations */
struct vtfs_node *vtfs_root(struct super_block *sb);
struct vtfs_node *vtfs_node_from_inode(struct super_block *sb, ino_t ino);
struct vtfs_node *vtfs_find_child(struct vtfs_node *dir, const char *name);
struct vtfs_node *vtfs_alloc_node(struct vtfs_node *parent, const char *name, bool is_dir);
struct vtfs_node *vtfs_alloc_node_ino(struct vtfs_node *parent, const char *name, bool is_dir, ino_t ino);
void vtfs_free_subtree(struct vtfs_node *n);

/* File operations */
struct vtfs_file *vtfs_file_alloc(void);
void vtfs_file_put(struct vtfs_file *f);

/* Inode operations */
struct inode *vtfs_iget(struct super_block *sb, const struct inode *dir, umode_t mode, ino_t ino);

/* Super operations */
struct dentry *vtfs_mount(struct file_system_type *fs_type, int flags, const char *token, void *data);
void vtfs_kill_sb(struct super_block *sb);
int vtfs_fill_super(struct super_block *sb, void *data, int silent);

/* HTTP push operations */
int vtfs_push_mkdir(ino_t pino, const char *name, ino_t ino);
int vtfs_push_create(ino_t pino, const char *name, ino_t ino);
int vtfs_push_unlink(ino_t pino, const char *name);
int vtfs_push_rmdir(ino_t pino, const char *name);
int vtfs_push_truncate(ino_t ino, size_t sz);
int vtfs_push_write(ino_t ino, size_t off, const char *buf, size_t len);

/* VFS operations declarations */
extern const struct file_operations vtfs_file_ops;
extern const struct inode_operations vtfs_inode_ops;
extern const struct file_operations vtfs_dir_ops;
extern const struct super_operations vtfs_super_ops;

/* VFS operations functions */
struct dentry *vtfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flag);
int vtfs_iterate(struct file *filp, struct dir_context *ctx);
int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode, bool excl);
int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode);
int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry);
int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry);
int vtfs_link(struct dentry *old_dentry, struct inode *parent_dir, struct dentry *new_dentry);
int vtfs_open(struct inode *inode, struct file *filp);
ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t len, loff_t *offset);
ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t len, loff_t *offset);

#endif /* _VTFS_H */