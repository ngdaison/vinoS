#ifndef KOS_VMM_H
#define KOS_VMM_H

#include <stdbool.h>
#include <stdint.h>

enum {
    VMM_PAGE_WRITABLE = 1ull << 1,
    VMM_PAGE_USER = 1ull << 2,
    VMM_PAGE_NO_EXECUTE = 1ull << 63,
};

#define VMM_PAGE_USER (1ull << 2)

bool vmm_initialize(uint64_t hhdm_offset);
void *vmm_physical_to_virtual(uint64_t physical_address);
uint64_t vmm_virtual_to_physical(const void *virtual_address);
uint64_t vmm_create_address_space(void);
void vmm_destroy_address_space(uint64_t pml4_phys);
void vmm_clear_user_address_space(uint64_t pml4_phys);
bool vmm_map_page(uint64_t virtual_address, uint64_t physical_address, uint64_t flags);
bool vmm_map_page_in(uint64_t pml4_phys, uint64_t virtual_address, uint64_t physical_address, uint64_t flags);
uint64_t vmm_unmap_page(uint64_t virtual_address);
uint64_t vmm_unmap_page_in(uint64_t pml4_phys, uint64_t virtual_address);
bool vmm_set_page_permissions(uint64_t virtual_address, uint64_t permissions);
bool vmm_is_mapped(uint64_t virtual_address);
bool vmm_query_page(uint64_t virtual_address, uint64_t *physical_address, uint64_t *flags);
bool vmm_query_page_in(uint64_t pml4_phys, uint64_t virtual_address, uint64_t *physical_address, uint64_t *flags);
bool vmm_map_pages(uint64_t virtual_address, uint64_t physical_address, uint64_t page_count, uint64_t flags);
uint64_t vmm_unmap_pages(uint64_t virtual_address, uint64_t page_count);
void *vmm_map_mmio(uint64_t physical_address, uint64_t size_bytes);

#endif

