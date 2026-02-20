// remote.c — HTTP push operations

#include "vtfs.h"

static int vtfs_enc_name(const char *name, char *out, size_t out_sz)
{
  if (!name || !out || out_sz < (strlen(name) * 3 + 1))
    return -ENAMETOOLONG;

  encode(name, out);
  return 0;
}

int vtfs_push_mkdir(ino_t pino, const char *name, ino_t ino)
{
  char pino_s[32], ino_s[32];
  char name_enc[VTFS_NAME_MAX * 3 + 1];
  int64_t r;

  snprintf(pino_s, sizeof(pino_s), "%lu", (unsigned long)pino);
  snprintf(ino_s, sizeof(ino_s), "%lu", (unsigned long)ino);
  if (vtfs_enc_name(name, name_enc, sizeof(name_enc)) != 0)
    return -ENAMETOOLONG;

  r = vtfs_http_call(vtfs_token, "mkdir", NULL, 0, 3,
                     "parent", pino_s, "name", name_enc, "ino", ino_s);
  return (r == 0) ? 0 : -EIO;
}

int vtfs_push_create(ino_t pino, const char *name, ino_t ino)
{
  char pino_s[32], ino_s[32];
  char name_enc[VTFS_NAME_MAX * 3 + 1];
  int64_t r;

  snprintf(pino_s, sizeof(pino_s), "%lu", (unsigned long)pino);
  snprintf(ino_s, sizeof(ino_s), "%lu", (unsigned long)ino);
  if (vtfs_enc_name(name, name_enc, sizeof(name_enc)) != 0)
    return -ENAMETOOLONG;

  r = vtfs_http_call(vtfs_token, "create", NULL, 0, 3,
                     "parent", pino_s, "name", name_enc, "ino", ino_s);
  return (r == 0) ? 0 : -EIO;
}

int vtfs_push_link(ino_t pino, const char *name, ino_t target_ino)
{
  char pino_s[32], target_ino_s[32];
  char name_enc[VTFS_NAME_MAX * 3 + 1];
  int64_t r;

  snprintf(pino_s, sizeof(pino_s), "%lu", (unsigned long)pino);
  snprintf(target_ino_s, sizeof(target_ino_s), "%lu", (unsigned long)target_ino);
  if (vtfs_enc_name(name, name_enc, sizeof(name_enc)) != 0)
    return -ENAMETOOLONG;

  r = vtfs_http_call(vtfs_token, "link", NULL, 0, 3,
                     "parent", pino_s, "name", name_enc, "target", target_ino_s);
  return (r == 0) ? 0 : -EIO;
}

int vtfs_push_unlink(ino_t pino, const char *name)
{
  char pino_s[32];
  char name_enc[VTFS_NAME_MAX * 3 + 1];
  int64_t r;

  snprintf(pino_s, sizeof(pino_s), "%lu", (unsigned long)pino);
  if (vtfs_enc_name(name, name_enc, sizeof(name_enc)) != 0)
    return -ENAMETOOLONG;

  r = vtfs_http_call(vtfs_token, "unlink", NULL, 0, 2,
                     "parent", pino_s, "name", name_enc);
  return (r == 0) ? 0 : -EIO;
}

int vtfs_push_rmdir(ino_t pino, const char *name)
{
  char pino_s[32];
  char name_enc[VTFS_NAME_MAX * 3 + 1];
  int64_t r;

  snprintf(pino_s, sizeof(pino_s), "%lu", (unsigned long)pino);
  if (vtfs_enc_name(name, name_enc, sizeof(name_enc)) != 0)
    return -ENAMETOOLONG;

  r = vtfs_http_call(vtfs_token, "rmdir", NULL, 0, 2,
                     "parent", pino_s, "name", name_enc);
  return (r == 0) ? 0 : -EIO;
}

int vtfs_push_truncate(ino_t ino, size_t sz)
{
  char ino_s[32], sz_s[32];
  int64_t r;

  snprintf(ino_s, sizeof(ino_s), "%lu", (unsigned long)ino);
  snprintf(sz_s, sizeof(sz_s), "%zu", sz);

  r = vtfs_http_call(vtfs_token, "truncate", NULL, 0, 2,
                     "ino", ino_s, "size", sz_s);
  return (r == 0) ? 0 : -EIO;
}

int vtfs_push_write(ino_t ino, size_t off, const char *buf, size_t len)
{
  char ino_s[32], off_s[32];
  char *encoded;
  int64_t r;

  snprintf(ino_s, sizeof(ino_s), "%lu", (unsigned long)ino);
  snprintf(off_s, sizeof(off_s), "%zu", off);

  encoded = kmalloc(len * 3 + 1, GFP_KERNEL);
  if (!encoded)
    return -ENOMEM;

  encode(buf, encoded);

  r = vtfs_http_call(vtfs_token, "write", NULL, 0, 3,
                     "ino", ino_s, "off", off_s, "data", encoded);
  kfree(encoded);
  return (r == 0) ? 0 : -EIO;
}