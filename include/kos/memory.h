#ifndef KOS_MEMORY_H
#define KOS_MEMORY_H

#include <stdint.h>
#include <stddef.h>

/* The base mapping/allocation granularity used by PMM, VMM, and kernel heap. */
#define KOS_PAGE_SIZE 4096ull

_Static_assert(KOS_PAGE_SIZE != 0 && (KOS_PAGE_SIZE & (KOS_PAGE_SIZE - 1)) == 0,
    "KOS page size must be a non-zero power of two");

void *memset(void *destination, int value, uint64_t size);
void *memcpy(void *destination, const void *source, uint64_t size);
void *memmove(void *destination, const void *source, uint64_t size);
int memcmp(const void *left, const void *right, uint64_t size);

static inline void *kmemset(void *dst, int val, uint64_t sz) { return memset(dst, val, sz); }
static inline void *kmemcpy(void *dst, const void *src, uint64_t sz) { return memcpy(dst, src, sz); }
static inline void *kmemmove(void *dst, const void *src, uint64_t sz) { return memmove(dst, src, sz); }
static inline int kmemcmp(const void *l, const void *r, uint64_t sz) { return memcmp(l, r, sz); }

uint64_t kstrlen(const char *s);
int kstrcmp(const char *s1, const char *s2);
int kstrncmp(const char *s1, const char *s2, uint64_t n);
char *kstrncpy(char *dst, const char *src, uint64_t n);

static inline uint64_t strlen(const char *s) { return kstrlen(s); }
static inline int strcmp(const char *s1, const char *s2) { return kstrcmp(s1, s2); }
static inline int strncmp(const char *s1, const char *s2, uint64_t n) { return kstrncmp(s1, s2, n); }
static inline char *strncpy(char *dst, const char *src, uint64_t n) { return kstrncpy(dst, src, n); }

#endif
