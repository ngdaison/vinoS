#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/block.h>
#include <kos/block_cache.h>
#include <kos/heap.h>
#include <kos/list.h>
#include <kos/log.h>
#include <kos/memory.h>
#include <kos/spinlock.h>
#include <kos/timer.h>

struct cache_entry {
    struct block_device *dev;
    uint64_t lba;
    uint8_t data[BLOCK_DEFAULT_SECTOR_SIZE];
    bool valid;
    bool dirty;
    uint64_t last_access;
    struct list_head lru_node;
    struct list_head hash_node;
};

struct block_cache_state {
    struct cache_entry entries[BLOCK_CACHE_CAPACITY];
    struct list_head lru_list;
    struct list_head hash_table[BLOCK_CACHE_HASH_SIZE];
    struct block_cache_stats stats;
    kos_spinlock_t lock;
    bool initialized;
};

static struct block_cache_state g_cache;

static inline uint32_t cache_hash(uint32_t dev_id, uint64_t lba) {
    uint64_t key = ((uint64_t)dev_id << 48) ^ lba;
    key = (~key) + (key << 18);
    key = key ^ (key >> 31);
    key = key * 21;
    key = key ^ (key >> 11);
    key = key + (key << 6);
    key = key ^ (key >> 22);
    return (uint32_t)(key % BLOCK_CACHE_HASH_SIZE);
}

bool block_cache_init(void) {
    spinlock_init(&g_cache.lock);
    list_init(&g_cache.lru_list);

    for (uint32_t i = 0; i < BLOCK_CACHE_HASH_SIZE; i++) {
        list_init(&g_cache.hash_table[i]);
    }

    kmemset(&g_cache.stats, 0, sizeof(g_cache.stats));

    for (uint32_t i = 0; i < BLOCK_CACHE_CAPACITY; i++) {
        struct cache_entry *entry = &g_cache.entries[i];
        entry->dev = NULL;
        entry->lba = 0;
        entry->valid = false;
        entry->dirty = false;
        entry->last_access = 0;
        list_init(&entry->lru_node);
        list_init(&entry->hash_node);
        list_add_tail(&entry->lru_node, &g_cache.lru_list);
    }

    g_cache.initialized = true;
    log_info("[block-cache] Block Cache initialized (512 blocks, 256 KiB)");
    return true;
}

static struct cache_entry *cache_lookup_locked(struct block_device *dev, uint64_t lba) {
    uint32_t bucket = cache_hash(dev->id, lba);
    struct cache_entry *entry;
    list_for_each_entry(entry, &g_cache.hash_table[bucket], hash_node) {
        if (entry->valid && entry->dev == dev && entry->lba == lba) {
            return entry;
        }
    }
    return NULL;
}

static bool cache_flush_entry_locked(struct cache_entry *entry) {
    if (!entry->valid || !entry->dirty || entry->dev == NULL) {
        return true;
    }

    /* Direct raw block write to hardware */
    bool ok = block_write(entry->dev, entry->lba, 1, entry->data);
    if (ok) {
        entry->dirty = false;
        g_cache.stats.flushes++;
    } else {
        log_errorf("[block-cache] Failed to flush dirty LBA %llu on %s",
                   (unsigned long long)entry->lba, entry->dev->name);
    }
    return ok;
}

static struct cache_entry *cache_allocate_slot_locked(struct block_device *dev, uint64_t lba) {
    /* 1. Look for unallocated/invalid entry from tail of LRU */
    struct cache_entry *entry = NULL;
    struct cache_entry *victim = NULL;

    list_for_each_entry_reverse(victim, &g_cache.lru_list, lru_node) {
        if (!victim->valid) {
            entry = victim;
            break;
        }
    }

    /* 2. If all valid, evict LRU victim (oldest at tail) */
    if (entry == NULL) {
        entry = list_last_entry(&g_cache.lru_list, struct cache_entry, lru_node);
        if (entry != NULL) {
            if (entry->dirty) {
                cache_flush_entry_locked(entry);
            }
            list_del(&entry->hash_node);
            list_init(&entry->hash_node);
            entry->valid = false;
            g_cache.stats.evictions++;
        }
    }

    if (entry == NULL) {
        return NULL;
    }

    /* Associate with new block */
    entry->dev = dev;
    entry->lba = lba;
    entry->dirty = false;
    entry->valid = false;
    entry->last_access = timer_get_ticks();

    /* Insert into hash table */
    uint32_t bucket = cache_hash(dev->id, lba);
    list_add(&entry->hash_node, &g_cache.hash_table[bucket]);

    /* Move to MRU head */
    list_del(&entry->lru_node);
    list_add(&entry->lru_node, &g_cache.lru_list);

    return entry;
}

static void cache_touch_locked(struct cache_entry *entry) {
    entry->last_access = timer_get_ticks();
    list_del(&entry->lru_node);
    list_add(&entry->lru_node, &g_cache.lru_list);
}

bool block_cache_read(struct block_device *dev, uint64_t lba, uint32_t count, void *buffer) {
    if (!g_cache.initialized || dev == NULL || buffer == NULL || count == 0) {
        return false;
    }

    uint8_t *dst = (uint8_t *)buffer;
    uint64_t flags = spinlock_lock_irqsave(&g_cache.lock);

    for (uint32_t i = 0; i < count; i++) {
        uint64_t cur_lba = lba + i;
        g_cache.stats.reads++;

        struct cache_entry *entry = cache_lookup_locked(dev, cur_lba);
        if (entry != NULL) {
            g_cache.stats.hits++;
            kmemcpy(dst, entry->data, BLOCK_DEFAULT_SECTOR_SIZE);
            cache_touch_locked(entry);
        } else {
            g_cache.stats.misses++;
            entry = cache_allocate_slot_locked(dev, cur_lba);
            if (entry == NULL) {
                /* Cache alloc failure, fallback to raw read */
                if (!block_read(dev, cur_lba, 1, dst)) {
                    spinlock_unlock_irqrestore(&g_cache.lock, flags);
                    return false;
                }
                dst += BLOCK_DEFAULT_SECTOR_SIZE;
                continue;
            }

            /* Read miss block from disk */
            if (!block_read(dev, cur_lba, 1, entry->data)) {
                entry->valid = false;
                list_del(&entry->hash_node);
                list_init(&entry->hash_node);
                spinlock_unlock_irqrestore(&g_cache.lock, flags);
                return false;
            }

            entry->valid = true;
            entry->dirty = false;
            kmemcpy(dst, entry->data, BLOCK_DEFAULT_SECTOR_SIZE);
        }

        dst += BLOCK_DEFAULT_SECTOR_SIZE;
    }

    spinlock_unlock_irqrestore(&g_cache.lock, flags);
    return true;
}

bool block_cache_write(struct block_device *dev, uint64_t lba, uint32_t count, const void *buffer) {
    if (!g_cache.initialized || dev == NULL || buffer == NULL || count == 0) {
        return false;
    }

    const uint8_t *src = (const uint8_t *)buffer;
    uint64_t flags = spinlock_lock_irqsave(&g_cache.lock);

    for (uint32_t i = 0; i < count; i++) {
        uint64_t cur_lba = lba + i;
        g_cache.stats.writes++;

        struct cache_entry *entry = cache_lookup_locked(dev, cur_lba);
        if (entry == NULL) {
            entry = cache_allocate_slot_locked(dev, cur_lba);
            if (entry == NULL) {
                /* Cache full/error, direct write */
                if (!block_write(dev, cur_lba, 1, src)) {
                    spinlock_unlock_irqrestore(&g_cache.lock, flags);
                    return false;
                }
                src += BLOCK_DEFAULT_SECTOR_SIZE;
                continue;
            }
            entry->valid = true;
        }

        kmemcpy(entry->data, src, BLOCK_DEFAULT_SECTOR_SIZE);
        entry->dirty = true;
        cache_touch_locked(entry);

        src += BLOCK_DEFAULT_SECTOR_SIZE;
    }

    spinlock_unlock_irqrestore(&g_cache.lock, flags);
    return true;
}

bool block_cache_flush_device(struct block_device *dev) {
    if (!g_cache.initialized) return false;

    uint64_t flags = spinlock_lock_irqsave(&g_cache.lock);
    bool all_ok = true;

    for (uint32_t i = 0; i < BLOCK_CACHE_CAPACITY; i++) {
        struct cache_entry *entry = &g_cache.entries[i];
        if (entry->valid && entry->dirty && (dev == NULL || entry->dev == dev)) {
            if (!cache_flush_entry_locked(entry)) {
                all_ok = false;
            }
        }
    }

    spinlock_unlock_irqrestore(&g_cache.lock, flags);

    if (dev != NULL) {
        block_flush(dev);
    }
    return all_ok;
}

bool block_cache_sync(void) {
    return block_cache_flush_device(NULL);
}

void block_cache_invalidate_device(struct block_device *dev) {
    if (!g_cache.initialized || dev == NULL) return;

    uint64_t flags = spinlock_lock_irqsave(&g_cache.lock);

    for (uint32_t i = 0; i < BLOCK_CACHE_CAPACITY; i++) {
        struct cache_entry *entry = &g_cache.entries[i];
        if (entry->valid && entry->dev == dev) {
            if (entry->dirty) {
                cache_flush_entry_locked(entry);
            }
            list_del(&entry->hash_node);
            list_init(&entry->hash_node);
            entry->valid = false;
            entry->dirty = false;
            entry->dev = NULL;
        }
    }

    spinlock_unlock_irqrestore(&g_cache.lock, flags);
}

void block_cache_get_stats(struct block_cache_stats *stats_out) {
    if (stats_out == NULL) return;
    uint64_t flags = spinlock_lock_irqsave(&g_cache.lock);
    *stats_out = g_cache.stats;
    spinlock_unlock_irqrestore(&g_cache.lock, flags);
}
