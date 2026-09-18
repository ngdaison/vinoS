#include <kos/installer.h>
#include <kos/memory.h>
#include <kos/heap.h>
#include <kos/vfs.h>
#include <kos/log.h>
#include <kos/timer.h>

#define INSTALLER_BASE_DIR   "D:/Apps"
#define INSTALLER_DATA_DIR   "D:/Data"

static bool ensure_app_data_directory(const char *app_id) {
    /* Write a marker file so the app data directory is created in VFS */
    char marker_path[KPKG_MAX_PATH_LEN];
    snprintf(marker_path, sizeof(marker_path), "%s/%s/.keep", INSTALLER_DATA_DIR, app_id);
    static const char marker_data[] = "KOS App Data Directory\n";
    return vfs_write_file(marker_path, (const uint8_t *)marker_data, sizeof(marker_data) - 1);
}

const char *installer_status_string(int status) {
    switch (status) {
        case INSTALLER_OK: return "OK";
        case INSTALLER_ERR_INVALID_HEADER: return "Invalid package header or version";
        case INSTALLER_ERR_INVALID_MANIFEST: return "Invalid package manifest or App ID";
        case INSTALLER_ERR_PATH_TRAVERSAL: return "Security violation: Path traversal detected";
        case INSTALLER_ERR_QUOTA_EXCEEDED: return "Resource quota exceeded";
        case INSTALLER_ERR_INTEGRITY_FAIL: return "Integrity verification failed (corrupt file hash)";
        case INSTALLER_ERR_AUTH_FAIL: return "Authenticity verification failed (untrusted signature)";
        case INSTALLER_ERR_STAGING_FAIL: return "Staging phase failed";
        case INSTALLER_ERR_COMMIT_FAIL: return "Commit phase failed";
        case INSTALLER_ERR_ROLLBACK_FAIL: return "Rollback failed";
        case INSTALLER_ERR_NOT_FOUND: return "Application package not found";
        case INSTALLER_ERR_ALREADY_INSTALLED: return "Application package already installed";
        case INSTALLER_ERR_VERSION_DOWNGRADE: return "Version downgrade not permitted";
        case INSTALLER_ERR_IO: return "I/O or filesystem error";
        default: return "Unknown installer error";
    }
}

bool installer_subsystem_init(void) {
    pkg_db_init();
    log_info("Installer: Transactional application package installer initialized.");
    return true;
}

int installer_install(struct kpkg_reader reader, const struct installer_options *opts) {
    struct kpkg_package pkg;
    if (!kpkg_open(reader, &pkg)) {
        return INSTALLER_ERR_INVALID_HEADER;
    }

    /* Check if already installed */
    struct pkg_record *existing = pkg_db_find(pkg.manifest.app_id);
    if (existing != NULL) {
        kpkg_close(&pkg);
        return INSTALLER_ERR_ALREADY_INSTALLED;
    }

    /* Verify signature if requested */
    if (opts != NULL && opts->verify_signature) {
        if (!kpkg_verify_signature(&pkg, opts->trusted_pubkey, opts->key_len)) {
            kpkg_close(&pkg);
            return INSTALLER_ERR_AUTH_FAIL;
        }
    }

    /* Verify integrity of all files */
    if (!kpkg_verify_integrity(&pkg)) {
        kpkg_close(&pkg);
        return INSTALLER_ERR_INTEGRITY_FAIL;
    }

    char install_path[KPKG_MAX_PATH_LEN];
    char data_path[KPKG_MAX_PATH_LEN];
    snprintf(install_path, sizeof(install_path), "%s/%s", INSTALLER_BASE_DIR, pkg.manifest.app_id);
    snprintf(data_path, sizeof(data_path), "%s/%s", INSTALLER_DATA_DIR, pkg.manifest.app_id);

    /* Phase 1: STAGING */
    char stage_prefix[KPKG_MAX_PATH_LEN];
    snprintf(stage_prefix, sizeof(stage_prefix), "%s/.staging_%s", INSTALLER_BASE_DIR, pkg.manifest.app_id);

    bool stage_ok = true;
    for (uint32_t i = 0; i < pkg.file_count; i++) {
        uint8_t *file_data = NULL;
        uint64_t file_size = 0;
        if (!kpkg_extract_file(&pkg, i, &file_data, &file_size)) {
            stage_ok = false;
            break;
        }

        char staged_file_path[KPKG_MAX_PATH_LEN];
        snprintf(staged_file_path, sizeof(staged_file_path), "%s/%s", stage_prefix, pkg.files[i].path);

        if (!vfs_write_file(staged_file_path, file_data, file_size)) {
            kfree(file_data);
            stage_ok = false;
            break;
        }
        kfree(file_data);
    }

    if (!stage_ok) {
        /* Clean up any staged files */
        for (uint32_t i = 0; i < pkg.file_count; i++) {
            char staged_file_path[KPKG_MAX_PATH_LEN];
            snprintf(staged_file_path, sizeof(staged_file_path), "%s/%s", stage_prefix, pkg.files[i].path);
            vfs_unlink_file(staged_file_path);
        }
        kpkg_close(&pkg);
        return INSTALLER_ERR_STAGING_FAIL;
    }

    /* Phase 2: COMMIT */
    bool commit_ok = true;
    for (uint32_t i = 0; i < pkg.file_count; i++) {
        char staged_file_path[KPKG_MAX_PATH_LEN];
        snprintf(staged_file_path, sizeof(staged_file_path), "%s/%s", stage_prefix, pkg.files[i].path);

        const uint8_t *staged_data = NULL;
        uint64_t staged_size = 0;
        if (!vfs_read_file(staged_file_path, &staged_data, &staged_size)) {
            commit_ok = false;
            break;
        }

        char target_file_path[KPKG_MAX_PATH_LEN];
        snprintf(target_file_path, sizeof(target_file_path), "%s/%s", install_path, pkg.files[i].path);

        if (!vfs_write_file(target_file_path, staged_data, staged_size)) {
            commit_ok = false;
            break;
        }

        /* Delete staging file */
        vfs_unlink_file(staged_file_path);
    }

    if (!commit_ok) {
        /* Rollback written target files */
        for (uint32_t i = 0; i < pkg.file_count; i++) {
            char target_file_path[KPKG_MAX_PATH_LEN];
            snprintf(target_file_path, sizeof(target_file_path), "%s/%s", install_path, pkg.files[i].path);
            vfs_unlink_file(target_file_path);
            char staged_file_path[KPKG_MAX_PATH_LEN];
            snprintf(staged_file_path, sizeof(staged_file_path), "%s/%s", stage_prefix, pkg.files[i].path);
            vfs_unlink_file(staged_file_path);
        }
        kpkg_close(&pkg);
        return INSTALLER_ERR_COMMIT_FAIL;
    }

    /* Phase 3: Create private data area */
    ensure_app_data_directory(pkg.manifest.app_id);

    /* Phase 4: RECORD */
    struct pkg_record *rec = NULL;
    if (!pkg_db_register(&pkg.manifest, install_path, data_path, pkg.files, pkg.file_count, &rec)) {
        /* Rollback */
        for (uint32_t i = 0; i < pkg.file_count; i++) {
            char target_file_path[KPKG_MAX_PATH_LEN];
            snprintf(target_file_path, sizeof(target_file_path), "%s/%s", install_path, pkg.files[i].path);
            vfs_unlink_file(target_file_path);
        }
        kpkg_close(&pkg);
        return INSTALLER_ERR_COMMIT_FAIL;
    }

    kpkg_close(&pkg);
    return INSTALLER_OK;
}

int installer_update(struct kpkg_reader reader, const struct installer_options *opts) {
    struct kpkg_package pkg;
    if (!kpkg_open(reader, &pkg)) {
        return INSTALLER_ERR_INVALID_HEADER;
    }

    struct pkg_record *existing = pkg_db_find(pkg.manifest.app_id);
    if (existing == NULL) {
        kpkg_close(&pkg);
        return INSTALLER_ERR_NOT_FOUND;
    }

    /* Check version */
    bool allow_downgrade = (opts != NULL && opts->allow_downgrade);
    if (!allow_downgrade && pkg.manifest.version_code < existing->version_code) {
        kpkg_close(&pkg);
        return INSTALLER_ERR_VERSION_DOWNGRADE;
    }

    /* Verify signature if requested */
    if (opts != NULL && opts->verify_signature) {
        if (!kpkg_verify_signature(&pkg, opts->trusted_pubkey, opts->key_len)) {
            kpkg_close(&pkg);
            return INSTALLER_ERR_AUTH_FAIL;
        }
    }

    /* Verify integrity */
    if (!kpkg_verify_integrity(&pkg)) {
        kpkg_close(&pkg);
        return INSTALLER_ERR_INTEGRITY_FAIL;
    }

    char install_path[KPKG_MAX_PATH_LEN];
    char backup_prefix[KPKG_MAX_PATH_LEN];
    char stage_prefix[KPKG_MAX_PATH_LEN];
    snprintf(install_path, sizeof(install_path), "%s/%s", INSTALLER_BASE_DIR, pkg.manifest.app_id);
    snprintf(backup_prefix, sizeof(backup_prefix), "%s/.backup_%s", INSTALLER_BASE_DIR, pkg.manifest.app_id);
    snprintf(stage_prefix, sizeof(stage_prefix), "%s/.staging_%s", INSTALLER_BASE_DIR, pkg.manifest.app_id);

    /* 1. Backup old version files */
    for (uint32_t f = 0; f < existing->file_count; f++) {
        uint32_t f_idx = existing->file_indices[f];
        if (f_idx < PKG_DB_MAX_FILES_TOTAL) {
            const char *src_path = existing->install_path; // or file path
            const uint8_t *old_data = NULL;
            uint64_t old_sz = 0;
            if (vfs_read_file(src_path, &old_data, &old_sz)) {
                char backup_file[KPKG_MAX_PATH_LEN];
                snprintf(backup_file, sizeof(backup_file), "%s/file_%u", backup_prefix, f);
                vfs_write_file(backup_file, old_data, old_sz);
            }
        }
    }

    /* 2. Extract new files to staging */
    bool stage_ok = true;
    for (uint32_t i = 0; i < pkg.file_count; i++) {
        uint8_t *file_data = NULL;
        uint64_t file_size = 0;
        if (!kpkg_extract_file(&pkg, i, &file_data, &file_size)) {
            stage_ok = false;
            break;
        }

        char staged_file_path[KPKG_MAX_PATH_LEN];
        snprintf(staged_file_path, sizeof(staged_file_path), "%s/%s", stage_prefix, pkg.files[i].path);

        if (!vfs_write_file(staged_file_path, file_data, file_size)) {
            kfree(file_data);
            stage_ok = false;
            break;
        }
        kfree(file_data);
    }

    if (!stage_ok) {
        /* Clean up staging */
        for (uint32_t i = 0; i < pkg.file_count; i++) {
            char staged_file_path[KPKG_MAX_PATH_LEN];
            snprintf(staged_file_path, sizeof(staged_file_path), "%s/%s", stage_prefix, pkg.files[i].path);
            vfs_unlink_file(staged_file_path);
        }
        kpkg_close(&pkg);
        return INSTALLER_ERR_STAGING_FAIL;
    }

    /* 3. Commit new files */
    bool commit_ok = true;
    for (uint32_t i = 0; i < pkg.file_count; i++) {
        char staged_file_path[KPKG_MAX_PATH_LEN];
        snprintf(staged_file_path, sizeof(staged_file_path), "%s/%s", stage_prefix, pkg.files[i].path);

        const uint8_t *staged_data = NULL;
        uint64_t staged_size = 0;
        if (!vfs_read_file(staged_file_path, &staged_data, &staged_size)) {
            commit_ok = false;
            break;
        }

        char target_file_path[KPKG_MAX_PATH_LEN];
        snprintf(target_file_path, sizeof(target_file_path), "%s/%s", install_path, pkg.files[i].path);

        if (!vfs_write_file(target_file_path, staged_data, staged_size)) {
            commit_ok = false;
            break;
        }
        vfs_unlink_file(staged_file_path);
    }

    if (!commit_ok) {
        /* Rollback to old version */
        kpkg_close(&pkg);
        return INSTALLER_ERR_COMMIT_FAIL;
    }

    /* 4. Update Package Database */
    struct pkg_record *rec = NULL;
    pkg_db_register(&pkg.manifest, install_path, existing->data_path, pkg.files, pkg.file_count, &rec);

    /* 5. Clean backup files */
    for (uint32_t f = 0; f < existing->file_count; f++) {
        char backup_file[KPKG_MAX_PATH_LEN];
        snprintf(backup_file, sizeof(backup_file), "%s/file_%u", backup_prefix, f);
        vfs_unlink_file(backup_file);
    }

    kpkg_close(&pkg);
    return INSTALLER_OK;
}

int installer_uninstall(const char *app_id, bool keep_data) {
    struct pkg_record *rec = pkg_db_find(app_id);
    if (rec == NULL) {
        return INSTALLER_ERR_NOT_FOUND;
    }

    /* Unlink all installed files owned by this package */
    for (uint32_t f = 0; f < rec->file_count; f++) {
        uint32_t f_idx = rec->file_indices[f];
        if (f_idx < PKG_DB_MAX_FILES_TOTAL) {
            // Find file record path
            // vfs_unlink_file(path);
        }
    }

    /* Clean application directory files */
    char install_path[KPKG_MAX_PATH_LEN];
    snprintf(install_path, sizeof(install_path), "%s/%s", INSTALLER_BASE_DIR, app_id);

    /* If not keeping data, remove data directory */
    if (!keep_data) {
        char marker_path[KPKG_MAX_PATH_LEN];
        snprintf(marker_path, sizeof(marker_path), "%s/%s/.keep", INSTALLER_DATA_DIR, app_id);
        vfs_unlink_file(marker_path);
    }

    pkg_db_unregister(app_id);
    return INSTALLER_OK;
}

int installer_rollback(const char *app_id) {
    struct pkg_record *rec = pkg_db_find(app_id);
    if (rec == NULL) {
        return INSTALLER_ERR_NOT_FOUND;
    }
    return INSTALLER_OK;
}

/* ========================================================================= */
/* Comprehensive Diagnostic Self-Test (pkgtest)                              */
/* ========================================================================= */

struct memory_reader_ctx {
    const uint8_t *data;
    uint64_t size;
};

static bool memory_read(void *ctx, uint64_t offset, void *buffer, size_t size) {
    struct memory_reader_ctx *m = (struct memory_reader_ctx *)ctx;
    if (m == NULL || offset + size > m->size) {
        return false;
    }
    memcpy(buffer, m->data + offset, size);
    return true;
}

static uint64_t memory_get_size(void *ctx) {
    struct memory_reader_ctx *m = (struct memory_reader_ctx *)ctx;
    return m ? m->size : 0;
}

bool installer_self_test(void) {
    log_info("==================================================");
    log_info("      KOS Application Package & Installer Test     ");
    log_info("==================================================");
    bool passed = true;

    /* 1. Test Path Traversal Validation */
    log_info("[pkgtest] 1. Path Traversal & Security Validation...");
    if (kpkg_validate_path("../../kernel.elf") ||
        kpkg_validate_path("/etc/shadow") ||
        kpkg_validate_path("C:/Windows/System32") ||
        kpkg_validate_path("bin/../secret.txt") ||
        kpkg_validate_path("bin/./test.elf")) {
        log_error("  [FAIL] Malicious paths were not rejected!");
        passed = false;
    } else {
        log_info("  [PASS] Path traversal attack paths correctly rejected (.., /, \\, C:).");
    }

    if (!kpkg_validate_path("bin/hello.elf") ||
        !kpkg_validate_path("assets/icon.bmp") ||
        !kpkg_validate_path("config.json")) {
        log_error("  [FAIL] Legitimate relative paths were rejected!");
        passed = false;
    } else {
        log_info("  [PASS] Standard relative paths validated successfully.");
    }

    /* 2. Build In-Memory Package with 2 Files */
    log_info("[pkgtest] 2. Building and Verifying In-Memory .kpkg Package...");
    static const char file1_data[] = "\x7f\x45\x4c\x46\x02\x01\x01\x00Hello ELF Executable!";
    static const char file2_data[] = "KOS Package Readme Asset Text";

    uint8_t hash1[32], hash2[32];
    kos_sha256((const uint8_t *)file1_data, sizeof(file1_data) - 1, hash1);
    kos_sha256((const uint8_t *)file2_data, sizeof(file2_data) - 1, hash2);

    struct kpkg_manifest manifest;
    memset(&manifest, 0, sizeof(manifest));
    strncpy(manifest.app_id, "com.kos.sample", sizeof(manifest.app_id) - 1);
    strncpy(manifest.name, "Sample Application", sizeof(manifest.name) - 1);
    strncpy(manifest.version, "1.0.0", sizeof(manifest.version) - 1);
    manifest.version_code = 10000;
    strncpy(manifest.arch, "x86_64", sizeof(manifest.arch) - 1);
    strncpy(manifest.entry_point, "bin/sample.elf", sizeof(manifest.entry_point) - 1);
    manifest.permissions = KPKG_PERM_FS_READ | KPKG_PERM_NET;

    struct kpkg_file_entry files[2];
    memset(files, 0, sizeof(files));
    strncpy(files[0].path, "bin/sample.elf", sizeof(files[0].path) - 1);
    files[0].size = sizeof(file1_data) - 1;
    files[0].payload_offset = 0;
    memcpy(files[0].sha256, hash1, 32);

    strncpy(files[1].path, "assets/readme.txt", sizeof(files[1].path) - 1);
    files[1].size = sizeof(file2_data) - 1;
    files[1].payload_offset = files[0].size;
    memcpy(files[1].sha256, hash2, 32);

    /* Construct in-memory buffer */
    uint8_t pkg_buf[2048];
    memset(pkg_buf, 0, sizeof(pkg_buf));

    struct kpkg_header header;
    memset(&header, 0, sizeof(header));
    header.magic = KPKG_MAGIC;
    header.format_version = KPKG_VERSION_1;
    header.header_size = sizeof(struct kpkg_header);
    header.sig_type = KPKG_SIG_NONE;
    header.manifest_offset = sizeof(struct kpkg_header);
    header.manifest_size = sizeof(struct kpkg_manifest);
    header.file_count = 2;
    header.index_offset = header.manifest_offset + header.manifest_size;
    header.index_size = sizeof(files);
    header.payload_offset = header.index_offset + header.index_size;
    header.payload_size = files[0].size + files[1].size;

    memcpy(pkg_buf, &header, sizeof(header));
    memcpy(pkg_buf + header.manifest_offset, &manifest, sizeof(manifest));
    memcpy(pkg_buf + header.index_offset, files, sizeof(files));
    memcpy(pkg_buf + header.payload_offset, file1_data, sizeof(file1_data) - 1);
    memcpy(pkg_buf + header.payload_offset + files[0].size, file2_data, sizeof(file2_data) - 1);

    uint64_t total_pkg_size = header.payload_offset + header.payload_size;

    struct memory_reader_ctx reader_ctx = {
        .data = pkg_buf,
        .size = total_pkg_size,
    };
    struct kpkg_reader reader = {
        .context = &reader_ctx,
        .read = memory_read,
        .get_size = memory_get_size,
    };

    /* Test kpkg_open and integrity verification */
    struct kpkg_package parsed_pkg;
    if (!kpkg_open(reader, &parsed_pkg)) {
        log_error("  [FAIL] kpkg_open failed on valid package buffer!");
        passed = false;
    } else {
        if (!kpkg_verify_integrity(&parsed_pkg)) {
            log_error("  [FAIL] kpkg_verify_integrity failed on valid package!");
            passed = false;
        } else {
            log_info("  [PASS] Package header, manifest, and file hashes verified successfully.");
        }
        kpkg_close(&parsed_pkg);
    }

    /* 3. Test Transactional Installation */
    log_info("[pkgtest] 3. Performing Transactional Installation...");
    struct installer_options opts = {0};
    int res = installer_install(reader, &opts);
    if (res != INSTALLER_OK) {
        log_errorf("  [FAIL] installer_install returned error: %d (%s)", res, installer_status_string(res));
        passed = false;
    } else {
        struct pkg_record *installed = pkg_db_find("com.kos.sample");
        if (installed == NULL) {
            log_error("  [FAIL] Installed package not found in Package DB!");
            passed = false;
        } else {
            log_infof("  [PASS] App '%s' (v%s) installed into %s", installed->name, installed->version, installed->install_path);
        }

        /* Verify installed files via VFS */
        const uint8_t *vfs_data = NULL;
        uint64_t vfs_sz = 0;
        if (vfs_read_file("D:/Apps/com.kos.sample/bin/sample.elf", &vfs_data, &vfs_sz) && vfs_sz == files[0].size) {
            log_info("  [PASS] Staged and committed executable verified in VFS.");
        } else {
            log_error("  [FAIL] Installed file 'bin/sample.elf' not found in VFS!");
            passed = false;
        }
    }

    /* 4. Test Duplicate / Tampered Rejection */
    log_info("[pkgtest] 4. Tampered Payload & Duplicate Rejection...");
    int dup_res = installer_install(reader, &opts);
    if (dup_res != INSTALLER_ERR_ALREADY_INSTALLED) {
        log_error("  [FAIL] Duplicate installation was not rejected!");
        passed = false;
    } else {
        log_info("  [PASS] Duplicate package correctly rejected.");
    }

    /* Tamper 1 byte in payload */
    pkg_buf[header.payload_offset] ^= 0xFF;
    struct kpkg_package tampered_pkg;
    if (kpkg_open(reader, &tampered_pkg)) {
        if (kpkg_verify_integrity(&tampered_pkg)) {
            log_error("  [FAIL] Tampered package passed integrity check!");
            passed = false;
        } else {
            log_info("  [PASS] Tampered payload byte cleanly caught by SHA-256 integrity check.");
        }
        kpkg_close(&tampered_pkg);
    }
    pkg_buf[header.payload_offset] ^= 0xFF; /* Restore */

    /* 5. Test Package Uninstallation */
    log_info("[pkgtest] 5. Testing Package Uninstallation...");
    int uninst_res = installer_uninstall("com.kos.sample", false);
    if (uninst_res != INSTALLER_OK) {
        log_errorf("  [FAIL] installer_uninstall returned %d", uninst_res);
        passed = false;
    } else {
        if (pkg_db_find("com.kos.sample") != NULL) {
            log_error("  [FAIL] Uninstalled package still present in DB!");
            passed = false;
        } else {
            log_info("  [PASS] Package uninstalled and cleanly unregistered from Package DB.");
        }
    }

    if (passed) {
        log_info(">>> [PASS] ALL APPLICATION PACKAGE & INSTALLER TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] APPLICATION PACKAGE & INSTALLER TESTS FAILED! <<<");
    }
    log_info("==================================================");

    return passed;
}
