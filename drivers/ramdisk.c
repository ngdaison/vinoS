#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/block.h>
#include <kos/heap.h>
#include <kos/log.h>
#include <kos/memory.h>
#include <kos/ramdisk.h>

struct ramdisk_data {
    uint8_t *buffer;
    uint64_t size_bytes;
    bool buffer_allocated;
};

bool ramdisk_init(void) {
    return true;
}

static bool ramdisk_read_blocks(struct block_device *dev, uint64_t lba, uint32_t count, void *buffer) {
    if (dev == NULL || dev->private_data == NULL || buffer == NULL) {
        return false;
    }
    struct ramdisk_data *data = (struct ramdisk_data *)dev->private_data;
    uint64_t offset = lba * dev->block_size;
    uint64_t byte_count = (uint64_t)count * dev->block_size;

    if (offset + byte_count > data->size_bytes) {
        log_errorf("[ramdisk] Read beyond buffer size (%llu + %llu > %llu)",
                   (unsigned long long)offset, (unsigned long long)byte_count,
                   (unsigned long long)data->size_bytes);
        return false;
    }

    kmemcpy(buffer, data->buffer + offset, byte_count);
    return true;
}

static bool ramdisk_write_blocks(struct block_device *dev, uint64_t lba, uint32_t count, const void *buffer) {
    if (dev == NULL || dev->private_data == NULL || buffer == NULL) {
        return false;
    }
    struct ramdisk_data *data = (struct ramdisk_data *)dev->private_data;
    uint64_t offset = lba * dev->block_size;
    uint64_t byte_count = (uint64_t)count * dev->block_size;

    if (offset + byte_count > data->size_bytes) {
        log_errorf("[ramdisk] Write beyond buffer size (%llu + %llu > %llu)",
                   (unsigned long long)offset, (unsigned long long)byte_count,
                   (unsigned long long)data->size_bytes);
        return false;
    }

    kmemcpy(data->buffer + offset, buffer, byte_count);
    return true;
}

static bool ramdisk_flush(struct block_device *dev) {
    (void)dev;
    return true;
}

static void ramdisk_dev_destroy(struct block_device *dev) {
    if (dev != NULL && dev->private_data != NULL) {
        struct ramdisk_data *data = (struct ramdisk_data *)dev->private_data;
        if (data->buffer_allocated && data->buffer != NULL) {
            kfree(data->buffer);
            data->buffer = NULL;
        }
        kfree(data);
        dev->private_data = NULL;
    }
}

static const struct block_device_ops ramdisk_ops = {
    .read_blocks = ramdisk_read_blocks,
    .write_blocks = ramdisk_write_blocks,
    .flush = ramdisk_flush,
    .destroy = ramdisk_dev_destroy,
};

struct block_device *ramdisk_create(const char *name, uint64_t size_bytes, uint64_t block_size) {
    if (name == NULL || size_bytes == 0) {
        return NULL;
    }
    if (block_size == 0) {
        block_size = BLOCK_DEFAULT_SECTOR_SIZE;
    }

    uint64_t total_blocks = size_bytes / block_size;
    if (total_blocks == 0) {
        return NULL;
    }
    uint64_t alloc_size = total_blocks * block_size;

    uint8_t *buffer = (uint8_t *)kmalloc(alloc_size);
    if (buffer == NULL) {
        log_errorf("[ramdisk] Failed to allocate %llu bytes for ramdisk buffer",
                   (unsigned long long)alloc_size);
        return NULL;
    }
    kmemset(buffer, 0, alloc_size);

    struct ramdisk_data *data = (struct ramdisk_data *)kmalloc(sizeof(struct ramdisk_data));
    if (data == NULL) {
        kfree(buffer);
        return NULL;
    }
    data->buffer = buffer;
    data->size_bytes = alloc_size;
    data->buffer_allocated = true;

    struct block_device *dev = block_device_register(
        name,
        BLOCK_TYPE_RAMDISK,
        block_size,
        total_blocks,
        &ramdisk_ops,
        data
    );

    if (dev == NULL) {
        kfree(buffer);
        kfree(data);
        return NULL;
    }

    log_infof("[ramdisk] Created %s with %llu KiB backing memory",
              name, (unsigned long long)(alloc_size / 1024));
    return dev;
}

bool ramdisk_destroy(struct block_device *dev) {
    if (dev == NULL || dev->type != BLOCK_TYPE_RAMDISK) {
        return false;
    }
    return block_device_unregister(dev);
}
