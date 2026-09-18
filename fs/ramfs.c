#include <stdbool.h>
#include <stdint.h>

#include <kos/ramfs.h>
#include <kos/sync.h>

enum {
    RAMFS_DYNAMIC_FILE_MAX = 8,
    RAMFS_DYNAMIC_PATH_MAX = 128,
    RAMFS_DYNAMIC_FILE_SIZE_MAX = 8192,
};

static const uint8_t readme[] =
    "KOS Data volume\n"
    "This is an independent in-memory D: volume.\n"
    "It proves the VFS volume namespace before a disk/FAT32 backend is added.\n";

static const struct vfs_file built_in_files[] = {
    { .path = "README.TXT", .data = readme, .size = sizeof(readme) - 1 },
};

struct ramfs_dynamic_file {
    bool used;
    char path[RAMFS_DYNAMIC_PATH_MAX];
    uint8_t data[RAMFS_DYNAMIC_FILE_SIZE_MAX];
    struct vfs_file view;
};

static struct ramfs_dynamic_file dynamic_files[RAMFS_DYNAMIC_FILE_MAX];
static bool initialized;
static struct kos_spinlock ramfs_lock = KOS_SPINLOCK_INITIALIZER;

static bool strings_equal(const char *left, const char *right) {
    while (*left != '\0' && *right != '\0') {
        if (*left != *right) {
            return false;
        }
        ++left;
        ++right;
    }
    return *left == *right;
}

static bool ramfs_read_file(const char *path, const uint8_t **data, uint64_t *size) {
    uint64_t flags = spinlock_lock_irqsave(&ramfs_lock);
    if (!initialized || path == 0 || data == 0 || size == 0) {
        spinlock_unlock_irqrestore(&ramfs_lock, flags);
        return false;
    }
    for (uint64_t index = 0; index < sizeof(built_in_files) / sizeof(built_in_files[0]); ++index) {
        if (strings_equal(path, built_in_files[index].path)) {
            *data = built_in_files[index].data;
            *size = built_in_files[index].size;
            spinlock_unlock_irqrestore(&ramfs_lock, flags);
            return true;
        }
    }
    for (uint64_t index = 0; index < RAMFS_DYNAMIC_FILE_MAX; ++index) {
        if (dynamic_files[index].used && strings_equal(path, dynamic_files[index].path)) {
            *data = dynamic_files[index].data;
            *size = dynamic_files[index].view.size;
            spinlock_unlock_irqrestore(&ramfs_lock, flags);
            return true;
        }
    }
    spinlock_unlock_irqrestore(&ramfs_lock, flags);
    return false;
}

static uint64_t ramfs_file_count(void) {
    uint64_t flags = spinlock_lock_irqsave(&ramfs_lock);
    if (!initialized) {
        spinlock_unlock_irqrestore(&ramfs_lock, flags);
        return 0;
    }
    uint64_t count = sizeof(built_in_files) / sizeof(built_in_files[0]);
    for (uint64_t index = 0; index < RAMFS_DYNAMIC_FILE_MAX; ++index) {
        if (dynamic_files[index].used) {
            ++count;
        }
    }
    spinlock_unlock_irqrestore(&ramfs_lock, flags);
    return count;
}

static const struct vfs_file *ramfs_file_at(uint64_t index) {
    uint64_t flags = spinlock_lock_irqsave(&ramfs_lock);
    if (!initialized) {
        spinlock_unlock_irqrestore(&ramfs_lock, flags);
        return 0;
    }
    const uint64_t built_in_count = sizeof(built_in_files) / sizeof(built_in_files[0]);
    if (index < built_in_count) {
        const struct vfs_file *file = &built_in_files[index];
        spinlock_unlock_irqrestore(&ramfs_lock, flags);
        return file;
    }
    index -= built_in_count;
    for (uint64_t slot = 0; slot < RAMFS_DYNAMIC_FILE_MAX; ++slot) {
        if (dynamic_files[slot].used) {
            if (index == 0) {
                const struct vfs_file *file = &dynamic_files[slot].view;
                spinlock_unlock_irqrestore(&ramfs_lock, flags);
                return file;
            }
            --index;
        }
    }
    spinlock_unlock_irqrestore(&ramfs_lock, flags);
    return 0;
}

bool ramfs_write_file(const char *path, const uint8_t *data, uint64_t size) {
    if (path == 0 || *path == '\0' || (data == 0 && size != 0)
        || size > RAMFS_DYNAMIC_FILE_SIZE_MAX) {
        return false;
    }
    uint64_t path_size = 0;
    while (path[path_size] != '\0') {
        if (path_size + 1 >= RAMFS_DYNAMIC_PATH_MAX) {
            return false;
        }
        ++path_size;
    }

    uint64_t flags = spinlock_lock_irqsave(&ramfs_lock);
    if (!initialized) {
        spinlock_unlock_irqrestore(&ramfs_lock, flags);
        return false;
    }

    struct ramfs_dynamic_file *file = 0;
    for (uint64_t index = 0; index < RAMFS_DYNAMIC_FILE_MAX; ++index) {
        if (dynamic_files[index].used && strings_equal(path, dynamic_files[index].path)) {
            file = &dynamic_files[index];
            break;
        }
        if (!dynamic_files[index].used && file == 0) {
            file = &dynamic_files[index];
        }
    }
    if (file == 0) {
        spinlock_unlock_irqrestore(&ramfs_lock, flags);
        return false;
    }
    for (uint64_t index = 0; index <= path_size; ++index) {
        file->path[index] = path[index];
    }
    for (uint64_t index = 0; index < size; ++index) {
        file->data[index] = data[index];
    }
    file->used = true;
    file->view = (struct vfs_file){ .path = file->path, .data = file->data, .size = size };
    spinlock_unlock_irqrestore(&ramfs_lock, flags);
    return true;
}

bool ramfs_unlink_file(const char *path) {
    if (path == 0 || *path == '\0') {
        return false;
    }
    uint64_t flags = spinlock_lock_irqsave(&ramfs_lock);
    if (!initialized) {
        spinlock_unlock_irqrestore(&ramfs_lock, flags);
        return false;
    }
    for (uint64_t index = 0; index < RAMFS_DYNAMIC_FILE_MAX; ++index) {
        if (dynamic_files[index].used && strings_equal(path, dynamic_files[index].path)) {
            dynamic_files[index].used = false;
            dynamic_files[index].path[0] = '\0';
            dynamic_files[index].view.size = 0;
            spinlock_unlock_irqrestore(&ramfs_lock, flags);
            return true;
        }
    }
    spinlock_unlock_irqrestore(&ramfs_lock, flags);
    return false;
}

const struct vfs_backend ramfs_vfs_backend = {
    .read_file = ramfs_read_file,
    .write_file = ramfs_write_file,
    .file_count = ramfs_file_count,
    .file_at = ramfs_file_at,
    .unlink_file = ramfs_unlink_file,
};

bool ramfs_initialize(void) {
    uint64_t flags = spinlock_lock_irqsave(&ramfs_lock);
    if (initialized) {
        spinlock_unlock_irqrestore(&ramfs_lock, flags);
        return false;
    }
    initialized = true;
    spinlock_unlock_irqrestore(&ramfs_lock, flags);
    return true;
}
