#include <stdint.h>

/* Minimal freestanding C runtime routines required by compiler-generated code. */
void *memset(void *destination, int value, uint64_t size) {
    uint8_t *bytes = destination;
    for (uint64_t index = 0; index < size; ++index) {
        bytes[index] = (uint8_t)value;
    }
    return destination;
}

void *memcpy(void *destination, const void *source, uint64_t size) {
    uint8_t *target = destination;
    const uint8_t *input = source;
    for (uint64_t index = 0; index < size; ++index) {
        target[index] = input[index];
    }
    return destination;
}

void *memmove(void *destination, const void *source, uint64_t size) {
    uint8_t *target = destination;
    const uint8_t *input = source;
    if (target < input) {
        for (uint64_t index = 0; index < size; ++index) {
            target[index] = input[index];
        }
    }
    else if (target > input) {
        for (uint64_t index = size; index != 0; --index) {
            target[index - 1] = input[index - 1];
        }
    }
    return destination;
}

int memcmp(const void *left, const void *right, uint64_t size) {
    const uint8_t *first = left;
    const uint8_t *second = right;
    for (uint64_t index = 0; index < size; ++index) {
        if (first[index] != second[index]) {
            return first[index] < second[index] ? -1 : 1;
        }
    }
    return 0;
}

uint64_t kstrlen(const char *s) {
    if (s == 0) return 0;
    uint64_t len = 0;
    while (s[len] != '\0') {
        len++;
    }
    return len;
}

int kstrcmp(const char *s1, const char *s2) {
    if (s1 == s2) return 0;
    if (s1 == 0) return -1;
    if (s2 == 0) return 1;
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return (int)((uint8_t)*s1 - (uint8_t)*s2);
}

int kstrncmp(const char *s1, const char *s2, uint64_t n) {
    if (n == 0) return 0;
    while (n > 0 && *s1 && *s2 && (*s1 == *s2)) {
        s1++;
        s2++;
        n--;
    }
    if (n == 0) return 0;
    return (int)((uint8_t)*s1 - (uint8_t)*s2);
}

char *kstrncpy(char *dst, const char *src, uint64_t n) {
    if (dst == 0 || n == 0) return dst;
    uint64_t i = 0;
    if (src != 0) {
        for (; i < n && src[i] != '\0'; i++) {
            dst[i] = src[i];
        }
    }
    for (; i < n; i++) {
        dst[i] = '\0';
    }
    return dst;
}
