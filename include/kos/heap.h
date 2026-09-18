#ifndef KOS_HEAP_H
#define KOS_HEAP_H

#include <stdbool.h>
#include <stdint.h>

bool heap_initialize(void);
void *kmalloc(uint64_t size);
bool kfree(void *pointer);
void *kcalloc(uint64_t num, uint64_t size);
void *krealloc(void *pointer, uint64_t new_size);
uint64_t heap_active_allocation_count(void);
uint64_t heap_mapped_page_count(void);

#endif
