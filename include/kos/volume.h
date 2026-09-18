#ifndef KOS_VOLUME_H
#define KOS_VOLUME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/block.h>

struct volume_entry {
    char letter;
    char label[32];
    char fs_type[16];
    struct block_device *bdev;
    void *fs_handle;
    bool is_mounted;
};

#define VOLUME_MAX_ENTRIES 16

/* Volume Manager Interface */
bool volume_manager_init(void);
bool volume_manager_scan_and_mount(void);
uint32_t volume_manager_get_count(void);
const struct volume_entry *volume_manager_get_at(uint32_t index);
const struct volume_entry *volume_manager_find_by_letter(char letter);
bool volume_manager_mount_device(struct block_device *dev, char requested_letter, const char *label);
bool volume_manager_unmount_letter(char letter);
bool volume_manager_sync_all(void);

#endif /* KOS_VOLUME_H */
