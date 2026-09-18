#ifndef KOS_KPKG_H
#define KOS_KPKG_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/crypto.h>

/* Magic: 0x47504B4B = "KPKG" in little-endian */
#define KPKG_MAGIC               0x47504B4B
#define KPKG_VERSION_1           1

/* Signature types */
#define KPKG_SIG_NONE            0
#define KPKG_SIG_ECDSA_P256      1
#define KPKG_SIG_RSA2048_PKCS1   2

/* Permission capability flags */
#define KPKG_PERM_NONE           0x00000000U
#define KPKG_PERM_FS_READ        (1U << 0)
#define KPKG_PERM_FS_WRITE       (1U << 1)
#define KPKG_PERM_NET            (1U << 2)
#define KPKG_PERM_AUDIO          (1U << 3)
#define KPKG_PERM_DRIVER         (1U << 4)
#define KPKG_PERM_SYSINFO        (1U << 5)

/* Resource quotas & safety limits */
#define KPKG_MAX_FILES           128
#define KPKG_MAX_FILE_SIZE       (16ULL * 1024ULL * 1024ULL) /* 16 MB max single file */
#define KPKG_MAX_TOTAL_SIZE      (64ULL * 1024ULL * 1024ULL) /* 64 MB max uncompressed package */
#define KPKG_MAX_PATH_LEN        256
#define KPKG_MAX_APPID_LEN       64
#define KPKG_MAX_NAME_LEN        64
#define KPKG_MAX_VER_LEN         32
#define KPKG_MAX_ARCH_LEN        16
#define KPKG_MAX_DEPS            8

#pragma pack(push, 1)

/* 64-byte Header */
struct kpkg_header {
    uint32_t magic;             /* KPKG_MAGIC ("KPKG") */
    uint32_t format_version;    /* KPKG_VERSION_1 */
    uint32_t header_size;       /* sizeof(struct kpkg_header) = 64 */
    uint32_t sig_type;          /* KPKG_SIG_* */

    uint64_t manifest_offset;   /* Byte offset to manifest in file */
    uint32_t manifest_size;     /* Size of manifest blob in bytes */
    uint32_t file_count;        /* Number of files in the index */

    uint64_t index_offset;      /* Byte offset to file index table */
    uint32_t index_size;        /* Total size of index table */
    uint32_t reserved1;

    uint64_t payload_offset;    /* Byte offset to payload blob */
    uint64_t payload_size;      /* Total size of all payloads */

    uint64_t sig_offset;        /* Byte offset to signature block */
    uint32_t sig_size;          /* Size of signature block */
    uint32_t reserved2;
};

/* Manifest data structure */
struct kpkg_manifest {
    char app_id[KPKG_MAX_APPID_LEN];       /* e.g. "com.kos.editor" */
    char name[KPKG_MAX_NAME_LEN];          /* e.g. "KOS Editor" */
    char version[KPKG_MAX_VER_LEN];        /* e.g. "1.2.0" */
    uint32_t version_code;                 /* e.g. 10200 */
    char arch[KPKG_MAX_ARCH_LEN];          /* e.g. "x86_64" */
    char entry_point[KPKG_MAX_PATH_LEN];   /* Relative path e.g. "bin/editor.elf" */
    uint32_t permissions;                  /* KPKG_PERM_* bitmask */
    uint32_t min_os_version;               /* Minimum OS build */
    uint32_t dep_count;                    /* Number of dependencies */
    char dependencies[KPKG_MAX_DEPS][KPKG_MAX_APPID_LEN];
};

/* File entry in File Index Table */
struct kpkg_file_entry {
    char path[KPKG_MAX_PATH_LEN];          /* Clean relative path e.g. "bin/editor.elf" */
    uint64_t size;                         /* File size in bytes */
    uint64_t payload_offset;               /* Offset from start of payload section */
    uint32_t permissions;                  /* POSIX permissions or execution flags */
    uint8_t sha256[32];                    /* SHA-256 hash of file content */
};

/* Signature block */
struct kpkg_signature_block {
    uint32_t sig_type;                     /* KPKG_SIG_ECDSA_P256 or KPKG_SIG_RSA2048_PKCS1 */
    uint32_t key_len;                      /* Public key length */
    uint32_t sig_len;                      /* Signature length */
    uint32_t reserved;
    /* Followed by: public key data (key_len bytes) + signature data (sig_len bytes) */
};

#pragma pack(pop)

/* Reader abstraction interface for parsing packages from any source (memory, disk, socket) */
struct kpkg_reader {
    void *context;
    bool (*read)(void *context, uint64_t offset, void *buffer, size_t size);
    uint64_t (*get_size)(void *context);
};

/* In-memory package representation */
struct kpkg_package {
    struct kpkg_header header;
    struct kpkg_manifest manifest;
    struct kpkg_file_entry *files;
    uint32_t file_count;
    struct kpkg_reader reader;
    bool verified_integrity;
    bool verified_authenticity;
};

/* Validation & Parsing APIs */
bool kpkg_validate_path(const char *path);
bool kpkg_validate_app_id(const char *app_id);
bool kpkg_open(struct kpkg_reader reader, struct kpkg_package *pkg);
void kpkg_close(struct kpkg_package *pkg);

bool kpkg_verify_integrity(struct kpkg_package *pkg);
bool kpkg_verify_signature(struct kpkg_package *pkg, const uint8_t *trusted_pubkey, uint32_t key_len);

bool kpkg_extract_file(struct kpkg_package *pkg, uint32_t file_index, uint8_t **out_buffer, uint64_t *out_size);

#endif /* KOS_KPKG_H */
