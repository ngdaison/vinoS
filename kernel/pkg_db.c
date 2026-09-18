#include <kos/pkg_db.h>
#include <kos/memory.h>
#include <kos/timer.h>
#include <kos/log.h>

static struct pkg_database g_pkg_db;

bool pkg_db_init(void) {
    uint64_t flags = spinlock_lock_irqsave(&g_pkg_db.lock);
    if (g_pkg_db.initialized) {
        spinlock_unlock_irqrestore(&g_pkg_db.lock, flags);
        return true;
    }

    memset(&g_pkg_db, 0, sizeof(g_pkg_db));
    g_pkg_db.initialized = true;
    spinlock_unlock_irqrestore(&g_pkg_db.lock, flags);
    log_info("Package Database: Initialized application metadata registry.");
    return true;
}

struct pkg_record *pkg_db_find(const char *app_id) {
    if (app_id == NULL || !g_pkg_db.initialized) {
        return NULL;
    }

    uint64_t flags = spinlock_lock_irqsave(&g_pkg_db.lock);
    for (uint32_t i = 0; i < PKG_DB_MAX_PACKAGES; i++) {
        if (g_pkg_db.packages[i].state == PKG_STATE_INSTALLED &&
            strcmp(g_pkg_db.packages[i].app_id, app_id) == 0) {
            spinlock_unlock_irqrestore(&g_pkg_db.lock, flags);
            return &g_pkg_db.packages[i];
        }
    }
    spinlock_unlock_irqrestore(&g_pkg_db.lock, flags);
    return NULL;
}

struct pkg_record *pkg_db_find_by_index(uint32_t index) {
    if (index >= PKG_DB_MAX_PACKAGES || !g_pkg_db.initialized) {
        return NULL;
    }
    if (g_pkg_db.packages[index].state == PKG_STATE_INSTALLED) {
        return &g_pkg_db.packages[index];
    }
    return NULL;
}

uint32_t pkg_db_count(void) {
    if (!g_pkg_db.initialized) {
        return 0;
    }
    uint32_t count = 0;
    uint64_t flags = spinlock_lock_irqsave(&g_pkg_db.lock);
    for (uint32_t i = 0; i < PKG_DB_MAX_PACKAGES; i++) {
        if (g_pkg_db.packages[i].state == PKG_STATE_INSTALLED) {
            count++;
        }
    }
    spinlock_unlock_irqrestore(&g_pkg_db.lock, flags);
    return count;
}

bool pkg_db_register(const struct kpkg_manifest *manifest, const char *install_path,
                     const char *data_path, const struct kpkg_file_entry *files,
                     uint32_t file_count, struct pkg_record **out_record) {
    if (manifest == NULL || install_path == NULL || data_path == NULL || !g_pkg_db.initialized) {
        return false;
    }

    uint64_t flags = spinlock_lock_irqsave(&g_pkg_db.lock);

    /* Find existing entry or free slot */
    int slot = -1;
    for (uint32_t i = 0; i < PKG_DB_MAX_PACKAGES; i++) {
        if (g_pkg_db.packages[i].state == PKG_STATE_INSTALLED &&
            strcmp(g_pkg_db.packages[i].app_id, manifest->app_id) == 0) {
            slot = (int)i;
            break;
        }
        if (slot == -1 && g_pkg_db.packages[i].state == PKG_STATE_UNUSED) {
            slot = (int)i;
        }
    }

    if (slot == -1) {
        spinlock_unlock_irqrestore(&g_pkg_db.lock, flags);
        return false;
    }

    /* If updating existing slot, clear previous file records */
    if (g_pkg_db.packages[slot].state == PKG_STATE_INSTALLED) {
        for (uint32_t f = 0; f < g_pkg_db.packages[slot].file_count; f++) {
            uint32_t f_idx = g_pkg_db.packages[slot].file_indices[f];
            if (f_idx < PKG_DB_MAX_FILES_TOTAL) {
                g_pkg_db.files[f_idx].in_use = false;
            }
        }
    }

    struct pkg_record *rec = &g_pkg_db.packages[slot];
    memset(rec, 0, sizeof(*rec));
    rec->id = (uint32_t)slot + 1;
    rec->state = PKG_STATE_INSTALLED;
    strncpy(rec->app_id, manifest->app_id, sizeof(rec->app_id) - 1);
    strncpy(rec->name, manifest->name, sizeof(rec->name) - 1);
    strncpy(rec->version, manifest->version, sizeof(rec->version) - 1);
    rec->version_code = manifest->version_code;
    strncpy(rec->install_path, install_path, sizeof(rec->install_path) - 1);
    strncpy(rec->data_path, data_path, sizeof(rec->data_path) - 1);
    strncpy(rec->entry_point, manifest->entry_point, sizeof(rec->entry_point) - 1);
    rec->permissions = manifest->permissions;
    rec->install_timestamp = timer_uptime_seconds();
    rec->file_count = 0;

    /* Register files */
    if (files != NULL && file_count > 0) {
        for (uint32_t f = 0; f < file_count && rec->file_count < KPKG_MAX_FILES; f++) {
            /* Find free slot in global files table */
            for (uint32_t g = 0; g < PKG_DB_MAX_FILES_TOTAL; g++) {
                if (!g_pkg_db.files[g].in_use) {
                    g_pkg_db.files[g].in_use = true;
                    g_pkg_db.files[g].pkg_index = (uint32_t)slot;
                    g_pkg_db.files[g].size = files[f].size;
                    memcpy(g_pkg_db.files[g].sha256, files[f].sha256, 32);

                    /* Construct full path e.g. "C:/Apps/com.kos.editor/bin/editor.elf" */
                    snprintf(g_pkg_db.files[g].path, sizeof(g_pkg_db.files[g].path),
                             "%s/%s", install_path, files[f].path);

                    rec->file_indices[rec->file_count++] = g;
                    break;
                }
            }
        }
    }

    if (out_record != NULL) {
        *out_record = rec;
    }

    spinlock_unlock_irqrestore(&g_pkg_db.lock, flags);
    return true;
}

bool pkg_db_unregister(const char *app_id) {
    if (app_id == NULL || !g_pkg_db.initialized) {
        return false;
    }

    uint64_t flags = spinlock_lock_irqsave(&g_pkg_db.lock);
    for (uint32_t i = 0; i < PKG_DB_MAX_PACKAGES; i++) {
        if (g_pkg_db.packages[i].state == PKG_STATE_INSTALLED &&
            strcmp(g_pkg_db.packages[i].app_id, app_id) == 0) {

            /* Free owned file entries */
            for (uint32_t f = 0; f < g_pkg_db.packages[i].file_count; f++) {
                uint32_t f_idx = g_pkg_db.packages[i].file_indices[f];
                if (f_idx < PKG_DB_MAX_FILES_TOTAL) {
                    g_pkg_db.files[f_idx].in_use = false;
                }
            }

            g_pkg_db.packages[i].state = PKG_STATE_UNUSED;
            memset(&g_pkg_db.packages[i], 0, sizeof(g_pkg_db.packages[i]));

            spinlock_unlock_irqrestore(&g_pkg_db.lock, flags);
            return true;
        }
    }
    spinlock_unlock_irqrestore(&g_pkg_db.lock, flags);
    return false;
}

bool pkg_db_is_file_owned(const char *path, char *out_owner_app_id, size_t max_len) {
    if (path == NULL || !g_pkg_db.initialized) {
        return false;
    }

    uint64_t flags = spinlock_lock_irqsave(&g_pkg_db.lock);
    for (uint32_t i = 0; i < PKG_DB_MAX_FILES_TOTAL; i++) {
        if (g_pkg_db.files[i].in_use && strcmp(g_pkg_db.files[i].path, path) == 0) {
            uint32_t pkg_idx = g_pkg_db.files[i].pkg_index;
            if (pkg_idx < PKG_DB_MAX_PACKAGES &&
                g_pkg_db.packages[pkg_idx].state == PKG_STATE_INSTALLED) {
                if (out_owner_app_id != NULL && max_len > 0) {
                    strncpy(out_owner_app_id, g_pkg_db.packages[pkg_idx].app_id, max_len - 1);
                    out_owner_app_id[max_len - 1] = '\0';
                }
                spinlock_unlock_irqrestore(&g_pkg_db.lock, flags);
                return true;
            }
        }
    }
    spinlock_unlock_irqrestore(&g_pkg_db.lock, flags);
    return false;
}
