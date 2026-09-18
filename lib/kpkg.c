#include <kos/kpkg.h>
#include <kos/memory.h>
#include <kos/heap.h>
#include <kos/log.h>

bool kpkg_validate_path(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return false;
    }

    size_t len = 0;
    while (path[len] != '\0') {
        if (len >= KPKG_MAX_PATH_LEN - 1) {
            return false;
        }
        len++;
    }

    /* Reject leading slash or backslash */
    if (path[0] == '/' || path[0] == '\\') {
        return false;
    }

    /* Reject drive letters (e.g. C: or D:) */
    if (len >= 2 && path[1] == ':') {
        return false;
    }

    /* Check each segment between slashes */
    const char *p = path;
    while (*p != '\0') {
        const char *seg_start = p;
        while (*p != '\0' && *p != '/' && *p != '\\') {
            unsigned char c = (unsigned char)*p;
            /* Illegal path characters */
            if (c < 32 || c == 127 || c == ':' || c == '*' || c == '?' ||
                c == '"' || c == '<' || c == '>' || c == '|') {
                return false;
            }
            p++;
        }

        size_t seg_len = (size_t)(p - seg_start);
        /* Reject empty segment (double slash), "." or ".." */
        if (seg_len == 0) {
            return false;
        }
        if (seg_len == 1 && seg_start[0] == '.') {
            return false;
        }
        if (seg_len == 2 && seg_start[0] == '.' && seg_start[1] == '.') {
            return false;
        }

        if (*p != '\0') {
            p++; /* Skip separator */
        }
    }

    return true;
}

bool kpkg_validate_app_id(const char *app_id) {
    if (app_id == NULL || app_id[0] == '\0') {
        return false;
    }

    size_t len = 0;
    bool has_char = false;
    while (app_id[len] != '\0') {
        if (len >= KPKG_MAX_APPID_LEN - 1) {
            return false;
        }
        char c = app_id[len];
        bool valid_c = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || (c == '.') || (c == '-') || (c == '_');
        if (!valid_c) {
            return false;
        }
        if (c != '.') {
            has_char = true;
        }
        len++;
    }

    /* Must have at least one non-dot character, cannot start or end with '.' */
    if (!has_char || app_id[0] == '.' || app_id[len - 1] == '.') {
        return false;
    }

    /* Check for consecutive dots ".." */
    for (size_t i = 0; i + 1 < len; i++) {
        if (app_id[i] == '.' && app_id[i + 1] == '.') {
            return false;
        }
    }

    return true;
}

bool kpkg_open(struct kpkg_reader reader, struct kpkg_package *pkg) {
    if (pkg == NULL || reader.read == NULL || reader.get_size == NULL) {
        return false;
    }

    memset(pkg, 0, sizeof(*pkg));
    pkg->reader = reader;

    uint64_t total_size = reader.get_size(reader.context);
    if (total_size < sizeof(struct kpkg_header)) {
        return false;
    }

    /* Read header */
    if (!reader.read(reader.context, 0, &pkg->header, sizeof(struct kpkg_header))) {
        return false;
    }

    /* Validate header fields */
    if (pkg->header.magic != KPKG_MAGIC ||
        pkg->header.format_version != KPKG_VERSION_1 ||
        pkg->header.header_size != sizeof(struct kpkg_header)) {
        return false;
    }

    if (pkg->header.file_count > KPKG_MAX_FILES ||
        pkg->header.manifest_size > sizeof(struct kpkg_manifest) ||
        pkg->header.payload_size > KPKG_MAX_TOTAL_SIZE) {
        return false;
    }

    /* Read manifest */
    if (pkg->header.manifest_size > 0) {
        if (pkg->header.manifest_offset + pkg->header.manifest_size > total_size) {
            return false;
        }
        if (!reader.read(reader.context, pkg->header.manifest_offset,
                         &pkg->manifest, pkg->header.manifest_size)) {
            return false;
        }
        if (!kpkg_validate_app_id(pkg->manifest.app_id)) {
            return false;
        }
    }

    /* Read file index */
    pkg->file_count = pkg->header.file_count;
    if (pkg->file_count > 0) {
        size_t index_bytes = (size_t)pkg->file_count * sizeof(struct kpkg_file_entry);
        if (pkg->header.index_offset + index_bytes > total_size) {
            return false;
        }

        pkg->files = (struct kpkg_file_entry *)kmalloc(index_bytes);
        if (pkg->files == NULL) {
            return false;
        }

        if (!reader.read(reader.context, pkg->header.index_offset, pkg->files, index_bytes)) {
            kfree(pkg->files);
            pkg->files = NULL;
            return false;
        }

        /* Validate each file entry in the index */
        uint64_t accumulated_payload = 0;
        for (uint32_t i = 0; i < pkg->file_count; i++) {
            struct kpkg_file_entry *f = &pkg->files[i];
            if (!kpkg_validate_path(f->path)) {
                kfree(pkg->files);
                pkg->files = NULL;
                return false;
            }
            if (f->size > KPKG_MAX_FILE_SIZE) {
                kfree(pkg->files);
                pkg->files = NULL;
                return false;
            }
            if (f->payload_offset + f->size > pkg->header.payload_size) {
                kfree(pkg->files);
                pkg->files = NULL;
                return false;
            }
            accumulated_payload += f->size;
        }

        if (accumulated_payload > KPKG_MAX_TOTAL_SIZE) {
            kfree(pkg->files);
            pkg->files = NULL;
            return false;
        }
    }

    return true;
}

void kpkg_close(struct kpkg_package *pkg) {
    if (pkg != NULL) {
        if (pkg->files != NULL) {
            kfree(pkg->files);
            pkg->files = NULL;
        }
        memset(pkg, 0, sizeof(*pkg));
    }
}

bool kpkg_verify_integrity(struct kpkg_package *pkg) {
    if (pkg == NULL || (pkg->files == NULL && pkg->file_count > 0)) {
        return false;
    }

    uint8_t *chunk = (uint8_t *)kmalloc(4096);
    if (chunk == NULL) {
        return false;
    }

    for (uint32_t i = 0; i < pkg->file_count; i++) {
        struct kpkg_file_entry *f = &pkg->files[i];
        struct kos_sha256_context sha;
        kos_sha256_initialize(&sha);

        uint64_t remaining = f->size;
        uint64_t cur_offset = pkg->header.payload_offset + f->payload_offset;

        while (remaining > 0) {
            size_t to_read = (remaining > 4096) ? 4096 : (size_t)remaining;
            if (!pkg->reader.read(pkg->reader.context, cur_offset, chunk, to_read)) {
                kfree(chunk);
                return false;
            }
            kos_sha256_update(&sha, chunk, to_read);
            cur_offset += to_read;
            remaining -= to_read;
        }

        uint8_t digest[32];
        kos_sha256_finalize(&sha, digest);

        if (memcmp(digest, f->sha256, 32) != 0) {
            kfree(chunk);
            return false;
        }
    }

    kfree(chunk);
    pkg->verified_integrity = true;
    return true;
}

bool kpkg_verify_signature(struct kpkg_package *pkg, const uint8_t *trusted_pubkey, uint32_t key_len) {
    if (pkg == NULL || trusted_pubkey == NULL || key_len == 0) {
        return false;
    }

    if (pkg->header.sig_type == KPKG_SIG_NONE || pkg->header.sig_size == 0) {
        return false;
    }

    struct kpkg_signature_block sig_block;
    if (pkg->header.sig_size < sizeof(sig_block)) {
        return false;
    }

    if (!pkg->reader.read(pkg->reader.context, pkg->header.sig_offset, &sig_block, sizeof(sig_block))) {
        return false;
    }

    if (sig_block.sig_type != pkg->header.sig_type ||
        sizeof(sig_block) + sig_block.key_len + sig_block.sig_len > pkg->header.sig_size) {
        return false;
    }

    uint8_t *sig_data = (uint8_t *)kmalloc(sig_block.sig_len);
    if (sig_data == NULL) {
        return false;
    }

    uint64_t sig_data_offset = pkg->header.sig_offset + sizeof(sig_block) + sig_block.key_len;
    if (!pkg->reader.read(pkg->reader.context, sig_data_offset, sig_data, sig_block.sig_len)) {
        kfree(sig_data);
        return false;
    }

    /* Compute SHA-256 over Header + Manifest + Index (everything before payload) */
    struct kos_sha256_context sha;
    kos_sha256_initialize(&sha);

    /* Hash header */
    kos_sha256_update(&sha, (const uint8_t *)&pkg->header, sizeof(pkg->header));

    /* Hash manifest */
    if (pkg->header.manifest_size > 0) {
        kos_sha256_update(&sha, (const uint8_t *)&pkg->manifest, pkg->header.manifest_size);
    }

    /* Hash index */
    if (pkg->file_count > 0 && pkg->files != NULL) {
        kos_sha256_update(&sha, (const uint8_t *)pkg->files,
                          (size_t)pkg->file_count * sizeof(struct kpkg_file_entry));
    }

    uint8_t digest[32];
    kos_sha256_finalize(&sha, digest);

    bool verified = false;
    if (sig_block.sig_type == KPKG_SIG_ECDSA_P256 && sig_block.sig_len == 64 && key_len >= 64) {
        /* ECDSA P-256 signature (r[32] || s[32]), PubKey (x[32] || y[32]) */
        const uint8_t *qx = trusted_pubkey;
        const uint8_t *qy = trusted_pubkey + 32;
        const uint8_t *r = sig_data;
        const uint8_t *s = sig_data + 32;
        verified = kos_ecdsa_p256_verify(qx, qy, digest, r, s);
    } else if (sig_block.sig_type == KPKG_SIG_RSA2048_PKCS1 && key_len >= 256) {
        static const uint8_t exp[3] = { 0x01, 0x00, 0x01 }; /* 65537 */
        verified = kos_rsa_pkcs1_verify_sha256(trusted_pubkey, key_len, exp, sizeof(exp),
                                               digest, sig_data, sig_block.sig_len);
    }

    kfree(sig_data);
    if (verified) {
        pkg->verified_authenticity = true;
    }
    return verified;
}

bool kpkg_extract_file(struct kpkg_package *pkg, uint32_t file_index, uint8_t **out_buffer, uint64_t *out_size) {
    if (pkg == NULL || file_index >= pkg->file_count || out_buffer == NULL || out_size == NULL) {
        return false;
    }

    struct kpkg_file_entry *f = &pkg->files[file_index];
    uint8_t *buf = (uint8_t *)kmalloc((size_t)f->size + 1);
    if (buf == NULL) {
        return false;
    }

    uint64_t cur_offset = pkg->header.payload_offset + f->payload_offset;
    if (!pkg->reader.read(pkg->reader.context, cur_offset, buf, (size_t)f->size)) {
        kfree(buf);
        return false;
    }
    buf[f->size] = '\0';

    /* Verify hash */
    uint8_t digest[32];
    kos_sha256(buf, f->size, digest);
    if (memcmp(digest, f->sha256, 32) != 0) {
        kfree(buf);
        return false;
    }

    *out_buffer = buf;
    *out_size = f->size;
    return true;
}
