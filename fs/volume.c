#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/block.h>
#include <kos/block_cache.h>
#include <kos/fat32.h>
#include <kos/log.h>
#include <kos/memory.h>
#include <kos/spinlock.h>
#include <kos/vfs.h>
#include <kos/volume.h>

static struct volume_entry g_volumes[VOLUME_MAX_ENTRIES];
static uint32_t g_volume_count = 0;
static kos_spinlock_t g_volume_lock = KOS_SPINLOCK_INITIALIZER;

static char get_next_available_letter(void) {
    /* Drive letters 'C' is Initramfs/System, 'D' is Ramfs.
     * Block / FAT32 volumes get 'E', 'F', 'G', ... 'Z' */
    for (char l = 'E'; l <= 'Z'; l++) {
        if (!vfs_volume_is_mounted(l)) {
            return l;
        }
    }
    return 0;
}

bool volume_manager_init(void) {
    uint64_t flags = spinlock_lock_irqsave(&g_volume_lock);
    kmemset(g_volumes, 0, sizeof(g_volumes));
    g_volume_count = 0;
    spinlock_unlock_irqrestore(&g_volume_lock, flags);

    volume_manager_scan_and_mount();
    log_info("[volume] Volume Manager initialized");
    return true;
}

bool volume_manager_mount_device(struct block_device *dev, char requested_letter, const char *label) {
    if (dev == NULL) return false;

    uint64_t flags = spinlock_lock_irqsave(&g_volume_lock);

    if (g_volume_count >= VOLUME_MAX_ENTRIES) {
        spinlock_unlock_irqrestore(&g_volume_lock, flags);
        return false;
    }

    char target_letter = requested_letter;
    if (target_letter == 0 || vfs_volume_is_mounted(target_letter)) {
        target_letter = get_next_available_letter();
    }
    if (target_letter == 0) {
        spinlock_unlock_irqrestore(&g_volume_lock, flags);
        log_error("[volume] No available drive letters");
        return false;
    }

    /* Probe filesystem type */
    if (fat32_probe(dev)) {
        struct fat32_volume *fat_vol = fat32_mount(dev);
        if (fat_vol == NULL) {
            spinlock_unlock_irqrestore(&g_volume_lock, flags);
            return false;
        }

        const char *vol_label = (label != NULL && *label != '\0') ? label : "FAT32_VOL";
        const struct vfs_backend *backend = fat32_get_vfs_backend(fat_vol);

        if (!vfs_mount_volume(target_letter, vol_label, backend)) {
            fat32_unmount(fat_vol);
            spinlock_unlock_irqrestore(&g_volume_lock, flags);
            return false;
        }

        struct volume_entry *entry = &g_volumes[g_volume_count++];
        entry->letter = target_letter;
        kstrncpy(entry->label, vol_label, sizeof(entry->label) - 1);
        kstrncpy(entry->fs_type, "FAT32", sizeof(entry->fs_type) - 1);
        entry->bdev = dev;
        entry->fs_handle = fat_vol;
        entry->is_mounted = true;

        log_infof("[volume] Mounted %s on %c: (FAT32, label '%s')",
                  dev->name, target_letter, entry->label);

        spinlock_unlock_irqrestore(&g_volume_lock, flags);
        return true;
    }

    spinlock_unlock_irqrestore(&g_volume_lock, flags);
    return false;
}

bool volume_manager_scan_and_mount(void) {
    uint32_t count = block_device_count();
    bool mounted_any = false;

    for (uint32_t i = 0; i < count; i++) {
        struct block_device *dev = block_device_get_at(i);
        if (dev == NULL) continue;

        /* Check if this device is already mounted */
        bool already_mounted = false;
        for (uint32_t v = 0; v < g_volume_count; v++) {
            if (g_volumes[v].bdev == dev && g_volumes[v].is_mounted) {
                already_mounted = true;
                break;
            }
        }
        if (already_mounted) continue;

        /* Try mounting device or partition */
        char label[32];
        label[0] = 'D'; label[1] = 'I'; label[2] = 'S'; label[3] = 'K'; label[4] = '_';
        int p = 5;
        for (int c = 0; dev->name[c] != '\0' && p + 1 < 32; c++) {
            label[p++] = dev->name[c];
        }
        label[p] = '\0';

        if (volume_manager_mount_device(dev, 0, label)) {
            mounted_any = true;
        }
    }

    return mounted_any;
}

uint32_t volume_manager_get_count(void) {
    return g_volume_count;
}

const struct volume_entry *volume_manager_get_at(uint32_t index) {
    if (index >= g_volume_count) return NULL;
    return &g_volumes[index];
}

const struct volume_entry *volume_manager_find_by_letter(char letter) {
    for (uint32_t i = 0; i < g_volume_count; i++) {
        if (g_volumes[i].letter == letter && g_volumes[i].is_mounted) {
            return &g_volumes[i];
        }
    }
    return NULL;
}

bool volume_manager_unmount_letter(char letter) {
    uint64_t flags = spinlock_lock_irqsave(&g_volume_lock);

    for (uint32_t i = 0; i < g_volume_count; i++) {
        if (g_volumes[i].letter == letter && g_volumes[i].is_mounted) {
            if (kstrcmp(g_volumes[i].fs_type, "FAT32") == 0) {
                fat32_unmount((struct fat32_volume *)g_volumes[i].fs_handle);
            }
            vfs_unmount_volume(letter);
            g_volumes[i].is_mounted = false;
            spinlock_unlock_irqrestore(&g_volume_lock, flags);
            return true;
        }
    }

    spinlock_unlock_irqrestore(&g_volume_lock, flags);
    return false;
}

bool volume_manager_sync_all(void) {
    return block_cache_sync();
}
