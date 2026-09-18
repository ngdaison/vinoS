#ifndef KOS_INITRAMFS_H
#define KOS_INITRAMFS_H

#include <stdbool.h>
#include <stdint.h>

#include <kos/vfs.h>

bool initramfs_initialize(const void *archive, uint64_t archive_size);
bool initramfs_is_initialized(void);
extern const struct vfs_backend initramfs_vfs_backend;

#endif
