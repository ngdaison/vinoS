#include <stdbool.h>
#include <stdint.h>

#include <kos/sync.h>
#include <kos/vfs.h>

enum {
    VFS_MAX_VOLUMES = 8,
    VFS_MAX_PATH = 256,
};

struct vfs_volume {
    char letter;
    const char *label;
    const struct vfs_backend *backend;
};

static struct vfs_volume volumes[VFS_MAX_VOLUMES];
static uint64_t mounted_volume_count;
static struct kos_spinlock vfs_lock = KOS_SPINLOCK_INITIALIZER;

static bool backend_is_valid(const struct vfs_backend *backend) {
    return backend != 0 && backend->read_file != 0 && backend->file_count != 0 && backend->file_at != 0;
}

static char normalize_letter(char letter) {
    return letter >= 'a' && letter <= 'z' ? (char)(letter - ('a' - 'A')) : letter;
}

static bool letter_is_valid(char letter) {
    return letter >= 'A' && letter <= 'Z';
}

static struct vfs_volume *find_volume_locked(char letter) {
    letter = normalize_letter(letter);
    for (uint64_t index = 0; index < mounted_volume_count; ++index) {
        if (volumes[index].letter == letter) {
            return &volumes[index];
        }
    }
    return 0;
}

bool vfs_mount_volume(char letter, const char *label, const struct vfs_backend *backend) {
    letter = normalize_letter(letter);
    if (!letter_is_valid(letter) || label == 0 || *label == '\0' || !backend_is_valid(backend)) {
        return false;
    }
    uint64_t flags = spinlock_lock_irqsave(&vfs_lock);
    if (find_volume_locked(letter) != 0 || mounted_volume_count >= VFS_MAX_VOLUMES) {
        spinlock_unlock_irqrestore(&vfs_lock, flags);
        return false;
    }
    volumes[mounted_volume_count++] = (struct vfs_volume){
        .letter = letter,
        .label = label,
        .backend = backend,
    };
    spinlock_unlock_irqrestore(&vfs_lock, flags);
    return true;
}

bool vfs_unmount_volume(char letter) {
    uint64_t flags = spinlock_lock_irqsave(&vfs_lock);
    struct vfs_volume *volume = find_volume_locked(letter);
    if (volume == 0 || volume->letter == 'C') {
        spinlock_unlock_irqrestore(&vfs_lock, flags);
        return false;
    }
    uint64_t index = (uint64_t)(volume - volumes);
    for (; index + 1 < mounted_volume_count; ++index) {
        volumes[index] = volumes[index + 1];
    }
    --mounted_volume_count;
    volumes[mounted_volume_count] = (struct vfs_volume){0};
    spinlock_unlock_irqrestore(&vfs_lock, flags);
    return true;
}

bool vfs_mount_root(const struct vfs_backend *backend) {
    return vfs_mount_volume('C', "System", backend);
}

bool vfs_is_initialized(void) {
    uint64_t flags = spinlock_lock_irqsave(&vfs_lock);
    bool init = find_volume_locked('C') != 0;
    spinlock_unlock_irqrestore(&vfs_lock, flags);
    return init;
}

static bool path_is_safe(const char *path) {
    if (path == 0 || *path == '\0') {
        return false;
    }
    for (const char *character = path; *character != '\0'; ++character) {
        if (*character == ':' || (character[0] == '.' && character[1] == '.'
                && (character == path || character[-1] == '/' || character[-1] == '\\')
                && (character[2] == '\0' || character[2] == '/' || character[2] == '\\'))) {
            return false;
        }
    }
    return true;
}

static bool parse_path_locked(const char *path, const struct vfs_backend **backend, char relative_path[VFS_MAX_PATH]) {
    if (path == 0 || backend == 0 || relative_path == 0) {
        return false;
    }
    char letter = 'C';
    if (path[0] != '\0' && path[1] == ':') {
        letter = path[0];
        path += 2;
    }
    while (*path == '/' || *path == '\\') {
        ++path;
    }
    if (!path_is_safe(path)) {
        return false;
    }
    uint64_t length = 0;
    for (; path[length] != '\0'; ++length) {
        if (length + 1 >= VFS_MAX_PATH) {
            return false;
        }
        relative_path[length] = path[length] == '\\' ? '/' : path[length];
    }
    relative_path[length] = '\0';
    struct vfs_volume *vol = find_volume_locked(letter);
    if (vol == 0) {
        return false;
    }
    *backend = vol->backend;
    return true;
}

bool vfs_read_file(const char *path, const uint8_t **data, uint64_t *size) {
    const struct vfs_backend *backend = 0;
    char relative_path[VFS_MAX_PATH];
    uint64_t flags = spinlock_lock_irqsave(&vfs_lock);
    if (!parse_path_locked(path, &backend, relative_path) || backend == 0 || backend->read_file == 0) {
        spinlock_unlock_irqrestore(&vfs_lock, flags);
        return false;
    }
    spinlock_unlock_irqrestore(&vfs_lock, flags);
    return backend->read_file(relative_path, data, size);
}

bool vfs_write_file(const char *path, const uint8_t *data, uint64_t size) {
    if (data == 0 && size != 0) {
        return false;
    }
    const struct vfs_backend *backend = 0;
    char relative_path[VFS_MAX_PATH];
    uint64_t flags = spinlock_lock_irqsave(&vfs_lock);
    if (!parse_path_locked(path, &backend, relative_path) || backend == 0 || backend->write_file == 0) {
        spinlock_unlock_irqrestore(&vfs_lock, flags);
        return false;
    }
    spinlock_unlock_irqrestore(&vfs_lock, flags);
    return backend->write_file(relative_path, data, size);
}

bool vfs_unlink_file(const char *path) {
    const struct vfs_backend *backend = 0;
    char relative_path[VFS_MAX_PATH];
    uint64_t flags = spinlock_lock_irqsave(&vfs_lock);
    if (!parse_path_locked(path, &backend, relative_path) || backend == 0 || backend->unlink_file == 0) {
        spinlock_unlock_irqrestore(&vfs_lock, flags);
        return false;
    }
    spinlock_unlock_irqrestore(&vfs_lock, flags);
    return backend->unlink_file(relative_path);
}

uint64_t vfs_file_count(void) {
    return vfs_file_count_on_volume('C');
}

const struct vfs_file *vfs_file_at(uint64_t index) {
    return vfs_file_at_on_volume('C', index);
}

uint64_t vfs_volume_count(void) {
    uint64_t flags = spinlock_lock_irqsave(&vfs_lock);
    uint64_t count = mounted_volume_count;
    spinlock_unlock_irqrestore(&vfs_lock, flags);
    return count;
}

bool vfs_volume_info_at(uint64_t index, struct vfs_volume_info *info) {
    if (info == 0) {
        return false;
    }
    uint64_t flags = spinlock_lock_irqsave(&vfs_lock);
    if (index >= mounted_volume_count) {
        spinlock_unlock_irqrestore(&vfs_lock, flags);
        return false;
    }
    const struct vfs_volume *volume = &volumes[index];
    char letter = volume->letter;
    const char *label = volume->label;
    const struct vfs_backend *backend = volume->backend;
    spinlock_unlock_irqrestore(&vfs_lock, flags);

    *info = (struct vfs_volume_info){
        .letter = letter,
        .label = label,
        .file_count = backend->file_count(),
    };
    return true;
}

bool vfs_volume_is_mounted(char letter) {
    uint64_t flags = spinlock_lock_irqsave(&vfs_lock);
    bool mounted = find_volume_locked(letter) != 0;
    spinlock_unlock_irqrestore(&vfs_lock, flags);
    return mounted;
}

uint64_t vfs_file_count_on_volume(char letter) {
    uint64_t flags = spinlock_lock_irqsave(&vfs_lock);
    struct vfs_volume *volume = find_volume_locked(letter);
    if (volume == 0) {
        spinlock_unlock_irqrestore(&vfs_lock, flags);
        return 0;
    }
    const struct vfs_backend *backend = volume->backend;
    spinlock_unlock_irqrestore(&vfs_lock, flags);
    return backend->file_count();
}

const struct vfs_file *vfs_file_at_on_volume(char letter, uint64_t index) {
    uint64_t flags = spinlock_lock_irqsave(&vfs_lock);
    struct vfs_volume *volume = find_volume_locked(letter);
    if (volume == 0) {
        spinlock_unlock_irqrestore(&vfs_lock, flags);
        return 0;
    }
    const struct vfs_backend *backend = volume->backend;
    spinlock_unlock_irqrestore(&vfs_lock, flags);
    return backend->file_at(index);
}
