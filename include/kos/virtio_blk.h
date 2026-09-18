#ifndef KOS_VIRTIO_BLK_H
#define KOS_VIRTIO_BLK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/block.h>

/* VirtIO Block Driver Initialization */
bool virtio_blk_initialize(void);
uint32_t virtio_blk_device_count(void);

#endif /* KOS_VIRTIO_BLK_H */
