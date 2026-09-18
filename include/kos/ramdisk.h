#ifndef KOS_RAMDISK_H
#define KOS_RAMDISK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/block.h>

/* Initialize RAM disk subsystem */
bool ramdisk_init(void);

/* Create a dynamic RAM disk of specified size in bytes */
struct block_device *ramdisk_create(const char *name, uint64_t size_bytes, uint64_t block_size);

/* Destroy a dynamic RAM disk and free its backing memory */
bool ramdisk_destroy(struct block_device *dev);

#endif /* KOS_RAMDISK_H */
