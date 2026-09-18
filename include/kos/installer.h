#ifndef KOS_INSTALLER_H
#define KOS_INSTALLER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/kpkg.h>
#include <kos/pkg_db.h>

enum installer_status {
    INSTALLER_OK = 0,
    INSTALLER_ERR_INVALID_HEADER = -1,
    INSTALLER_ERR_INVALID_MANIFEST = -2,
    INSTALLER_ERR_PATH_TRAVERSAL = -3,
    INSTALLER_ERR_QUOTA_EXCEEDED = -4,
    INSTALLER_ERR_INTEGRITY_FAIL = -5,
    INSTALLER_ERR_AUTH_FAIL = -6,
    INSTALLER_ERR_STAGING_FAIL = -7,
    INSTALLER_ERR_COMMIT_FAIL = -8,
    INSTALLER_ERR_ROLLBACK_FAIL = -9,
    INSTALLER_ERR_NOT_FOUND = -10,
    INSTALLER_ERR_ALREADY_INSTALLED = -11,
    INSTALLER_ERR_VERSION_DOWNGRADE = -12,
    INSTALLER_ERR_IO = -13,
};

struct installer_options {
    bool verify_signature;
    const uint8_t *trusted_pubkey;
    uint32_t key_len;
    bool allow_downgrade;
    bool keep_data_on_uninstall;
};

/* Installer Lifecycle & Operations */
bool installer_subsystem_init(void);

/* Transactional Operations */
int installer_install(struct kpkg_reader reader, const struct installer_options *opts);
int installer_update(struct kpkg_reader reader, const struct installer_options *opts);
int installer_uninstall(const char *app_id, bool keep_data);
int installer_rollback(const char *app_id);
int installer_verify_file(const char *vfs_path, const struct installer_options *opts);

const char *installer_status_string(int status);

bool installer_self_test(void);

#endif /* KOS_INSTALLER_H */
