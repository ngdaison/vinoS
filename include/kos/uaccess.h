#ifndef KOS_UACCESS_H
#define KOS_UACCESS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <uapi/kos/syscall_numbers.h>
#include <kos/security.h>

/* Maximum canonical user address: 0x00007FFFFFFFFFFF (47-bit / 48-bit canonical low half) */
#define KOS_USER_SPACE_MAX  0x00007FFFFFFFFFFFULL

static inline void stac(void) {
    if (security_has_smap()) {
        __asm__ volatile ("stac" ::: "cc");
    }
}

static inline void clac(void) {
    if (security_has_smap()) {
        __asm__ volatile ("clac" ::: "cc");
    }
}

/* Check if [addr, addr + size) is within valid user address range without integer overflow */
bool access_ok(const void *addr, size_t size);

/* Safe memory copy from user space to kernel space. Returns 0 on success, -EFAULT on failure */
int copy_from_user(void *dst, const void *src, size_t size);

/* Safe memory copy from kernel space to user space. Returns 0 on success, -EFAULT on failure */
int copy_to_user(void *dst, const void *src, size_t size);

/* Safe string copy from user space to kernel space. Returns bytes copied (including null) or -EFAULT */
long strncpy_from_user(char *dst, const char *src, size_t count);

/* Safe string length calculation in user space. Returns string length (excluding null) or -EFAULT */
long strlen_user(const char *src);

#endif /* KOS_UACCESS_H */
