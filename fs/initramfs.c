#include <stdbool.h>
#include <stdint.h>

#include <kos/initramfs.h>

enum {
    CPIO_NEWC_HEADER_SIZE = 110,
    INITRAMFS_MAX_FILES = 32,
    CPIO_FILE_TYPE_MASK = 0170000,
    CPIO_REGULAR_FILE = 0100000,
};

static struct vfs_file files[INITRAMFS_MAX_FILES];
static uint64_t file_count;
static bool initialized;

static bool strings_equal(const char *left, const char *right) {
    while (*left != '\0' && *right != '\0') {
        if (*left != *right) {
            return false;
        }
        ++left;
        ++right;
    }
    return *left == *right;
}

static bool path_is_safe(const char *path) {
    if (*path == '/' || *path == '\0') {
        return false;
    }
    for (const char *character = path; *character != '\0'; ++character) {
        if (character[0] == '.' && character[1] == '.'
            && (character == path || character[-1] == '/')
            && (character[2] == '\0' || character[2] == '/')) {
            return false;
        }
    }
    return true;
}

static bool parse_hex8(const uint8_t *text, uint32_t *value) {
    uint32_t result = 0;
    for (uint64_t index = 0; index < 8; ++index) {
        uint8_t character = text[index];
        uint32_t digit;
        if (character >= '0' && character <= '9') {
            digit = character - '0';
        }
        else if (character >= 'A' && character <= 'F') {
            digit = character - 'A' + 10;
        }
        else if (character >= 'a' && character <= 'f') {
            digit = character - 'a' + 10;
        }
        else {
            return false;
        }
        result = (result << 4) | digit;
    }
    *value = result;
    return true;
}

static bool range_is_valid(uint64_t offset, uint64_t length, uint64_t total_size) {
    return offset <= total_size && length <= total_size - offset;
}

static bool align4(uint64_t value, uint64_t *aligned_value) {
    if (value > UINT64_MAX - 3) {
        return false;
    }
    *aligned_value = (value + 3) & ~3ull;
    return true;
}

static bool initramfs_read_file(const char *path, const uint8_t **data, uint64_t *size) {
    if (!initialized || path == 0 || data == 0 || size == 0) {
        return false;
    }
    for (uint64_t index = 0; index < file_count; ++index) {
        if (strings_equal(path, files[index].path)) {
            *data = files[index].data;
            *size = files[index].size;
            return true;
        }
    }
    return false;
}

static uint64_t initramfs_file_count(void) { return file_count; }

static const struct vfs_file *initramfs_file_at(uint64_t index) {
    return index < file_count ? &files[index] : 0;
}

const struct vfs_backend initramfs_vfs_backend = {
    .read_file = initramfs_read_file,
    .file_count = initramfs_file_count,
    .file_at = initramfs_file_at,
};

bool initramfs_initialize(const void *archive, uint64_t archive_size) {
    const uint8_t *bytes = archive;
    uint64_t offset = 0;

    if (initialized || bytes == 0 || archive_size < CPIO_NEWC_HEADER_SIZE) {
        return false;
    }
    file_count = 0;
    while (range_is_valid(offset, CPIO_NEWC_HEADER_SIZE, archive_size)) {
        const uint8_t *header = bytes + offset;
        if (header[0] != '0' || header[1] != '7' || header[2] != '0'
            || header[3] != '7' || header[4] != '0' || header[5] != '1') {
            return false;
        }
        uint32_t file_size;
        uint32_t name_size;
        uint32_t mode;
        if (!parse_hex8(header + 54, &file_size) || !parse_hex8(header + 94, &name_size)
            || !parse_hex8(header + 14, &mode) || name_size == 0) {
            return false;
        }
        uint64_t name_offset = offset + CPIO_NEWC_HEADER_SIZE;
        if (!range_is_valid(name_offset, name_size, archive_size)
            || bytes[name_offset + name_size - 1] != '\0') {
            return false;
        }
        const char *path = (const char *)(bytes + name_offset);
        uint64_t data_offset;
        if (!align4(name_offset + name_size, &data_offset)
            || !range_is_valid(data_offset, file_size, archive_size)) {
            return false;
        }
        if (strings_equal(path, "TRAILER!!!")) {
            if (file_size != 0 || file_count == 0) {
                return false;
            }
            initialized = true;
            return true;
        }
        if ((mode & CPIO_FILE_TYPE_MASK) != CPIO_REGULAR_FILE || !path_is_safe(path)
            || file_count >= INITRAMFS_MAX_FILES) {
            return false;
        }
        for (uint64_t index = 0; index < file_count; ++index) {
            if (strings_equal(files[index].path, path)) {
                return false;
            }
        }
        files[file_count] = (struct vfs_file){
            .path = path,
            .data = bytes + data_offset,
            .size = file_size,
        };
        ++file_count;
        if (!align4(data_offset + file_size, &offset)) {
            return false;
        }
    }
    return false;
}

bool initramfs_is_initialized(void) { return initialized; }
