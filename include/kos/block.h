#ifndef KOS_BLOCK_H
#define KOS_BLOCK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/compiler.h>
#include <kos/list.h>
#include <kos/spinlock.h>

#define BLOCK_NAME_MAX 32
#define BLOCK_MAX_DEVICES 64
#define BLOCK_DEFAULT_SECTOR_SIZE 512

enum block_device_state {
    BLOCK_DEVICE_OFFLINE = 0,
    BLOCK_DEVICE_ONLINE  = 1,
    BLOCK_DEVICE_ERROR   = 2,
};

enum block_device_type {
    BLOCK_TYPE_UNKNOWN = 0,
    BLOCK_TYPE_RAMDISK = 1,
    BLOCK_TYPE_AHCI    = 2,
    BLOCK_TYPE_VIRTIO  = 3,
    BLOCK_TYPE_PARTITION = 4,
    BLOCK_TYPE_NVME    = 5,
};

struct block_device;

struct block_device_ops {
    bool (*read_blocks)(struct block_device *dev, uint64_t lba, uint32_t count, void *buffer);
    bool (*write_blocks)(struct block_device *dev, uint64_t lba, uint32_t count, const void *buffer);
    bool (*flush)(struct block_device *dev);
    void (*destroy)(struct block_device *dev);
};

struct block_device {
    uint32_t id;
    char name[BLOCK_NAME_MAX];
    enum block_device_type type;
    enum block_device_state state;
    uint64_t block_size;
    uint64_t total_blocks;
    uint64_t capacity_bytes;

    const struct block_device_ops *ops;
    void *private_data;
    kos_spinlock_t lock;
    struct list_head list_node;

    /* Partition relationship (if type == BLOCK_TYPE_PARTITION) */
    struct block_device *parent;
    uint64_t start_lba;
    uint32_t partition_index;
    uint8_t partition_type_mbr;
    uint8_t partition_guid[16];
    bool has_guid;
};

/* Core Block Device Subsystem */
bool block_subsystem_init(void);

struct block_device *block_device_register(
    const char *name,
    enum block_device_type type,
    uint64_t block_size,
    uint64_t total_blocks,
    const struct block_device_ops *ops,
    void *private_data
);

struct block_device *block_partition_register(
    struct block_device *parent,
    uint32_t part_index,
    uint64_t start_lba,
    uint64_t block_count,
    uint8_t part_type_mbr,
    const uint8_t *guid
);

bool block_device_unregister(struct block_device *dev);

struct block_device *block_device_find_by_name(const char *name);
struct block_device *block_device_find_by_id(uint32_t id);
uint32_t block_device_count(void);
struct block_device *block_device_get_at(uint32_t index);

/* Standard I/O Wrappers with parameter validation and bounds checking */
bool block_read(struct block_device *dev, uint64_t lba, uint32_t count, void *buffer);
bool block_write(struct block_device *dev, uint64_t lba, uint32_t count, const void *buffer);
bool block_flush(struct block_device *dev);

/* Universal DMA Allocation Helpers for Block Drivers (AHCI, VirtIO, etc.) */
bool block_alloc_dma_pages(uint32_t count, void **out_virt, uint64_t *out_phys);
void block_free_dma_pages(void *virt, uint64_t phys, uint32_t count);

#endif /* KOS_BLOCK_H */
