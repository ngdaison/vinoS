#ifndef KOS_RAMFS_H
#define KOS_RAMFS_H

#include <stdbool.h>
#include <stdint.h>

#include <kos/vfs.h>

bool ramfs_initialize(void);
bool ramfs_write_file(const char *path, const uint8_t *data, uint64_t size);
bool ramfs_unlink_file(const char *path);
extern const struct vfs_backend ramfs_vfs_backend;

#endif
