#ifndef KOS_VFS_H
#define KOS_VFS_H

#include <stdbool.h>
#include <stdint.h>

struct vfs_file {
    const char *path;
    const uint8_t *data;
    uint64_t size;
};

struct vfs_backend {
    bool (*read_file)(const char *path, const uint8_t **data, uint64_t *size);
    bool (*write_file)(const char *path, const uint8_t *data, uint64_t size);
    uint64_t (*file_count)(void);
    const struct vfs_file *(*file_at)(uint64_t index);
    bool (*unlink_file)(const char *path);
};

struct vfs_volume_info {
    char letter;
    const char *label;
    uint64_t file_count;
};

/* Volumes use one ASCII letter, for example C: or D:. */
bool vfs_mount_volume(char letter, const char *label, const struct vfs_backend *backend);
bool vfs_unmount_volume(char letter);
bool vfs_mount_root(const struct vfs_backend *backend);
bool vfs_is_initialized(void);
bool vfs_read_file(const char *path, const uint8_t **data, uint64_t *size);
bool vfs_write_file(const char *path, const uint8_t *data, uint64_t size);
bool vfs_unlink_file(const char *path);
uint64_t vfs_file_count(void);
const struct vfs_file *vfs_file_at(uint64_t index);
uint64_t vfs_volume_count(void);
bool vfs_volume_info_at(uint64_t index, struct vfs_volume_info *info);
bool vfs_volume_is_mounted(char letter);
uint64_t vfs_file_count_on_volume(char letter);
const struct vfs_file *vfs_file_at_on_volume(char letter, uint64_t index);

#endif
