#ifndef KOS_PMM_H
#define KOS_PMM_H

#include <stdbool.h>
#include <stdint.h>

#include <limine.h>

bool pmm_initialize(const struct limine_memmap_response *memory_map);
uint64_t pmm_allocate_frame(void);
bool pmm_free_frame(uint64_t physical_address);
uint64_t pmm_alloc_page(void);
bool pmm_free_page(uint64_t physical_address);
uint64_t pmm_alloc_pages(uint64_t count);
bool pmm_free_pages(uint64_t physical_address, uint64_t count);
uint64_t pmm_total_memory_bytes(void);
uint64_t pmm_usable_memory_bytes(void);
uint64_t pmm_tracked_memory_bytes(void);
uint64_t pmm_kernel_memory_bytes(void);
uint64_t pmm_framebuffer_memory_bytes(void);
uint64_t pmm_bootloader_reclaimable_bytes(void);
uint64_t pmm_free_frame_count(void);
uint64_t pmm_allocated_frame_count(void);
uint64_t pmm_frame_size(void);

#endif
