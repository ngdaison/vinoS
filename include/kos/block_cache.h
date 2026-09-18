#ifndef KOS_BLOCK_CACHE_H
#define KOS_BLOCK_CACHE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/block.h>

#define BLOCK_CACHE_CAPACITY 512  /* 512 sectors = 256 KiB cache */
#define BLOCK_CACHE_HASH_SIZE 128

struct block_cache_stats {
    uint64_t hits;
    uint64_t misses;
    uint64_t reads;
    uint64_t writes;
    uint64_t flushes;
    uint64_t evictions;
};

/* Block Cache Interface */
bool block_cache_init(void);

bool block_cache_read(struct block_device *dev, uint64_t lba, uint32_t count, void *buffer);
bool block_cache_write(struct block_device *dev, uint64_t lba, uint32_t count, const void *buffer);
bool block_cache_flush_device(struct block_device *dev);
bool block_cache_sync(void);
void block_cache_invalidate_device(struct block_device *dev);

void block_cache_get_stats(struct block_cache_stats *stats_out);

#endif /* KOS_BLOCK_CACHE_H */
