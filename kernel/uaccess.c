#include <kos/uaccess.h>
#include <kos/memory.h>
#include <uapi/kos/syscall_numbers.h>
#include <kos/vmm.h>

bool access_ok(const void *addr, size_t size) {
    uintptr_t uaddr = (uintptr_t)addr;

    if (size == 0) {
        return true;
    }

    /* Null pointer check for non-zero size */
    if (uaddr == 0) {
        return false;
    }

    /* Check for integer overflow */
    if (uaddr + size < uaddr) {
        return false;
    }

    /* Check upper bound for user space canonical range */
    if (uaddr + size - 1 > KOS_USER_SPACE_MAX) {
        return false;
    }

    return true;
}

int copy_from_user(void *dst, const void *src, size_t size) {
    if (size == 0) {
        return 0;
    }

    if (!dst || !access_ok(src, size)) {
        return -EFAULT;
    }

    stac();
    memcpy(dst, src, size);
    clac();

    return 0;
}

int copy_to_user(void *dst, const void *src, size_t size) {
    if (size == 0) {
        return 0;
    }

    if (!src || !access_ok(dst, size)) {
        return -EFAULT;
    }

    stac();
    memcpy(dst, src, size);
    clac();

    return 0;
}

long strncpy_from_user(char *dst, const char *src, size_t count) {
    if (count == 0) {
        return 0;
    }

    if (!dst || !access_ok(src, 1)) {
        return -EFAULT;
    }

    stac();
    size_t i = 0;
    for (i = 0; i < count; i++) {
        uintptr_t curr = (uintptr_t)(src + i);
        if (curr > KOS_USER_SPACE_MAX) {
            clac();
            return -EFAULT;
        }
        char c = src[i];
        dst[i] = c;
        if (c == '\0') {
            clac();
            return (long)(i + 1);
        }
    }
    clac();

    return (long)count;
}

long strlen_user(const char *src) {
    if (!access_ok(src, 1)) {
        return -EFAULT;
    }

    stac();
    size_t len = 0;
    const size_t max_len = 4096;

    while (len < max_len) {
        uintptr_t curr = (uintptr_t)(src + len);
        if (curr > KOS_USER_SPACE_MAX) {
            clac();
            return -EFAULT;
        }
        if (src[len] == '\0') {
            clac();
            return (long)len;
        }
        len++;
    }
    clac();

    return -EFAULT;
}
