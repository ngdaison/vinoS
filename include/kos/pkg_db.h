#ifndef KOS_PKG_DB_H
#define KOS_PKG_DB_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/kpkg.h>
#include <kos/spinlock.h>

#define PKG_DB_MAX_PACKAGES 64
#define PKG_DB_MAX_FILES_TOTAL 1024

enum pkg_state {
    PKG_STATE_UNUSED = 0,
    PKG_STATE_INSTALLED = 1,
    PKG_STATE_STAGED = 2,
    PKG_STATE_BROKEN = 3,
};

struct pkg_file_record {
    char path[KPKG_MAX_PATH_LEN];     /* Relative to app dir or full VFS path */
    uint64_t size;
    uint8_t sha256[32];
    uint32_t pkg_index;
    bool in_use;
};

struct pkg_record {
    uint32_t id;
    enum pkg_state state;
    char app_id[KPKG_MAX_APPID_LEN];
    char name[KPKG_MAX_NAME_LEN];
    char version[KPKG_MAX_VER_LEN];
    uint32_t version_code;
    char install_path[KPKG_MAX_PATH_LEN];   /* e.g. "C:/Apps/com.kos.editor" */
    char data_path[KPKG_MAX_PATH_LEN];      /* e.g. "C:/Data/com.kos.editor" */
    char entry_point[KPKG_MAX_PATH_LEN];    /* e.g. "bin/editor.elf" */
    uint32_t permissions;
    uint64_t install_timestamp;
    uint32_t file_count;
    uint32_t file_indices[KPKG_MAX_FILES];  /* Indices into global file table */
};

struct pkg_database {
    struct pkg_record packages[PKG_DB_MAX_PACKAGES];
    struct pkg_file_record files[PKG_DB_MAX_FILES_TOTAL];
    uint32_t package_count;
    uint32_t file_count;
    kos_spinlock_t lock;
    bool initialized;
};

/* Package Database Lifecycle & Operations */
bool pkg_db_init(void);
struct pkg_record *pkg_db_find(const char *app_id);
struct pkg_record *pkg_db_find_by_index(uint32_t index);
uint32_t pkg_db_count(void);

bool pkg_db_register(const struct kpkg_manifest *manifest, const char *install_path,
                     const char *data_path, const struct kpkg_file_entry *files,
                     uint32_t file_count, struct pkg_record **out_record);

bool pkg_db_unregister(const char *app_id);

bool pkg_db_is_file_owned(const char *path, char *out_owner_app_id, size_t max_len);

#endif /* KOS_PKG_DB_H */
