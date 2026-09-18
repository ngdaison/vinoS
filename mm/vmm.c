#include <stdbool.h>
#include <stdint.h>

#include <kos/cpu.h>
#include <kos/elf.h>
#include <kos/log.h>
#include <kos/memory.h>
#include <kos/pmm.h>
#include <kos/sync.h>
#include <kos/vmm.h>

enum {
    PAGE_SIZE = KOS_PAGE_SIZE,
    PAGE_PRESENT = 1ull << 0,
    PAGE_USER = 1ull << 2,
    PAGE_HUGE = 1ull << 7,
    PAGE_KOS_OWNED_TABLE = 1ull << 9,
    PAGE_KOS_OWNED_MAPPING = 1ull << 10,
    PAGE_ADDRESS_MASK = 0x000ffffffffff000ull,
    PAGE_2M_ADDRESS_MASK = 0x000fffffffe00000ull,
    PAGE_1G_ADDRESS_MASK = 0x000fffffc0000000ull,
};

struct virtual_memory_manager {
    uint64_t hhdm_offset;
    uint64_t *pml4;
    uint64_t kernel_pml4_phys;
    bool initialized;
};

static struct virtual_memory_manager vmm;
static struct kos_spinlock vmm_lock = KOS_SPINLOCK_INITIALIZER;

void *vmm_physical_to_virtual(uint64_t physical_address) {
    return (void *)(vmm.hhdm_offset + physical_address);
}

uint64_t vmm_virtual_to_physical(const void *virtual_address) {
    return (uint64_t)virtual_address - vmm.hhdm_offset;
}

static uint64_t *physical_to_virtual(uint64_t physical_address) {
    return (uint64_t *)(vmm.hhdm_offset + physical_address);
}

static uint64_t page_table_index(uint64_t virtual_address, uint64_t shift) {
    return (virtual_address >> shift) & 0x1ff;
}

static void clear_page_table(uint64_t *table) {
    for (uint64_t index = 0; index < 512; ++index) {
        table[index] = 0;
    }
}

static bool page_table_is_empty(const uint64_t *table) {
    for (uint64_t index = 0; index < 512; ++index) {
        if ((table[index] & PAGE_PRESENT) != 0) {
            return false;
        }
    }
    return true;
}

static bool release_owned_empty_table(uint64_t *entry) {
    uint64_t value = *entry;
    if ((value & (PAGE_PRESENT | PAGE_KOS_OWNED_TABLE))
            != (PAGE_PRESENT | PAGE_KOS_OWNED_TABLE)) {
        return false;
    }
    uint64_t *table = physical_to_virtual(value & PAGE_ADDRESS_MASK);
    if (!page_table_is_empty(table)) {
        return false;
    }
    *entry = 0;
    return pmm_free_frame(value & PAGE_ADDRESS_MASK);
}

static uint64_t public_page_flags(uint64_t flags) {
    return flags & ~(PAGE_KOS_OWNED_TABLE | PAGE_KOS_OWNED_MAPPING);
}

static uint64_t combine_effective_flags(uint64_t parent_flags, uint64_t entry) {
    uint64_t result = entry;
    if ((parent_flags & VMM_PAGE_WRITABLE) == 0) {
        result &= ~VMM_PAGE_WRITABLE;
    }
    if ((parent_flags & VMM_PAGE_USER) == 0) {
        result &= ~VMM_PAGE_USER;
    }
    if ((parent_flags & VMM_PAGE_NO_EXECUTE) != 0) {
        result |= VMM_PAGE_NO_EXECUTE;
    }
    return result;
}

static uint64_t *next_table(uint64_t *entry, bool *created, uint64_t virtual_address, uint64_t flags) {
    *created = false;
    bool is_user = (virtual_address < 0x0000800000000000ull) || ((flags & VMM_PAGE_USER) != 0);

    if ((*entry & PAGE_PRESENT) != 0) {
        if ((*entry & PAGE_HUGE) != 0) {
            return 0;
        }
        if (is_user) {
            *entry |= PAGE_USER;
        }
        return physical_to_virtual(*entry & PAGE_ADDRESS_MASK);
    }

    uint64_t frame = pmm_allocate_frame();
    if (frame == 0) {
        return 0;
    }
    uint64_t *table = physical_to_virtual(frame);
    clear_page_table(table);

    uint64_t entry_flags = frame | PAGE_PRESENT | VMM_PAGE_WRITABLE | PAGE_KOS_OWNED_TABLE;
    if (is_user) {
        entry_flags |= PAGE_USER;
    }
    *entry = entry_flags;
    *created = true;
    return table;
}

static bool vmm_self_test(void);

bool vmm_initialize(uint64_t hhdm_offset) {
    uint64_t cr3 = cpu_read_cr3() & PAGE_ADDRESS_MASK;
    if (hhdm_offset == 0 || hhdm_offset % PAGE_SIZE != 0 || cr3 == 0) {
        return false;
    }
    uint64_t flags = spinlock_lock_irqsave(&vmm_lock);
    vmm.hhdm_offset = hhdm_offset;
    vmm.pml4 = physical_to_virtual(cr3);
    vmm.kernel_pml4_phys = cr3;
    vmm.initialized = true;
    spinlock_unlock_irqrestore(&vmm_lock, flags);

    if (!vmm_self_test()) {
        return false;
    }

    return true;
}

uint64_t vmm_create_address_space(void) {
    uint64_t interrupt_flags = spinlock_lock_irqsave(&vmm_lock);
    if (!vmm.initialized || vmm.pml4 == 0) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return 0;
    }

    uint64_t pml4_frame = pmm_allocate_frame();
    if (pml4_frame == 0) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return 0;
    }

    uint64_t *new_pml4 = physical_to_virtual(pml4_frame);
    for (uint64_t index = 0; index < 256; ++index) {
        new_pml4[index] = 0;
    }
    for (uint64_t index = 256; index < 512; ++index) {
        new_pml4[index] = vmm.pml4[index];
    }

    spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
    return pml4_frame;
}

void vmm_clear_user_address_space(uint64_t pml4_phys) {
    if (pml4_phys == 0 || (pml4_phys % PAGE_SIZE) != 0) {
        return;
    }
    uint64_t interrupt_flags = spinlock_lock_irqsave(&vmm_lock);
    if (!vmm.initialized || pml4_phys == vmm.kernel_pml4_phys) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return;
    }

    uint64_t *pml4 = physical_to_virtual(pml4_phys);

    for (uint64_t pml4_idx = 0; pml4_idx < 256; ++pml4_idx) {
        uint64_t pml4e = pml4[pml4_idx];
        if ((pml4e & PAGE_PRESENT) == 0) {
            continue;
        }
        uint64_t pdpt_phys = pml4e & PAGE_ADDRESS_MASK;
        uint64_t *pdpt = physical_to_virtual(pdpt_phys);

        for (uint64_t pdpt_idx = 0; pdpt_idx < 512; ++pdpt_idx) {
            uint64_t pdpte = pdpt[pdpt_idx];
            if ((pdpte & PAGE_PRESENT) == 0) {
                continue;
            }
            if ((pdpte & PAGE_HUGE) != 0) {
                pmm_free_frame(pdpte & PAGE_ADDRESS_MASK);
                pdpt[pdpt_idx] = 0;
                continue;
            }
            uint64_t pd_phys = pdpte & PAGE_ADDRESS_MASK;
            uint64_t *pd = physical_to_virtual(pd_phys);

            for (uint64_t pd_idx = 0; pd_idx < 512; ++pd_idx) {
                uint64_t pde = pd[pd_idx];
                if ((pde & PAGE_PRESENT) == 0) {
                    continue;
                }
                if ((pde & PAGE_HUGE) != 0) {
                    pmm_free_frame(pde & PAGE_ADDRESS_MASK);
                    pd[pd_idx] = 0;
                    continue;
                }
                uint64_t pt_phys = pde & PAGE_ADDRESS_MASK;
                uint64_t *pt = physical_to_virtual(pt_phys);

                for (uint64_t pt_idx = 0; pt_idx < 512; ++pt_idx) {
                    uint64_t pte = pt[pt_idx];
                    if ((pte & PAGE_PRESENT) == 0) {
                        continue;
                    }
                    uint64_t leaf_phys = pte & PAGE_ADDRESS_MASK;
                    pmm_free_frame(leaf_phys);
                    pt[pt_idx] = 0;
                }

                pmm_free_frame(pt_phys);
                pd[pd_idx] = 0;
            }

            pmm_free_frame(pd_phys);
            pdpt[pdpt_idx] = 0;
        }

        pmm_free_frame(pdpt_phys);
        pml4[pml4_idx] = 0;
    }

    if ((cpu_read_cr3() & PAGE_ADDRESS_MASK) == pml4_phys) {
        cpu_write_cr3(vmm.kernel_pml4_phys);
    }

    spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
}

void vmm_destroy_address_space(uint64_t pml4_phys) {
    if (pml4_phys == 0 || (pml4_phys % PAGE_SIZE) != 0) {
        return;
    }
    uint64_t interrupt_flags = spinlock_lock_irqsave(&vmm_lock);
    if (!vmm.initialized || pml4_phys == vmm.kernel_pml4_phys) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return;
    }
    if ((cpu_read_cr3() & PAGE_ADDRESS_MASK) == pml4_phys) {
        cpu_write_cr3(vmm.kernel_pml4_phys);
    }
    spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);

    vmm_clear_user_address_space(pml4_phys);
    pmm_free_frame(pml4_phys);
}

bool vmm_map_page_in(uint64_t pml4_phys, uint64_t virtual_address, uint64_t physical_address, uint64_t flags) {
    if (virtual_address % PAGE_SIZE != 0 || physical_address % PAGE_SIZE != 0
        || pml4_phys == 0 || pml4_phys % PAGE_SIZE != 0
        || (flags & ~(VMM_PAGE_WRITABLE | VMM_PAGE_USER | VMM_PAGE_NO_EXECUTE)) != 0) {
        return false;
    }
    if ((flags & VMM_PAGE_USER) != 0 && virtual_address >= 0x0000800000000000ull) {
        return false;
    }
    if (virtual_address >= 0x0000800000000000ull && virtual_address < 0xffff800000000000ull) {
        return false;
    }

    uint64_t interrupt_flags = spinlock_lock_irqsave(&vmm_lock);
    if (!vmm.initialized) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return false;
    }

    uint64_t *target_pml4 = physical_to_virtual(pml4_phys);
    uint64_t *pml4_entry = &target_pml4[page_table_index(virtual_address, 39)];
    bool pml4_table_created;
    uint64_t *pdpt = next_table(pml4_entry, &pml4_table_created, virtual_address, flags);
    if (pdpt == 0) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return false;
    }
    uint64_t *pdpt_entry = &pdpt[page_table_index(virtual_address, 30)];
    bool pdpt_table_created;
    uint64_t *directory = next_table(pdpt_entry, &pdpt_table_created, virtual_address, flags);
    if (directory == 0) {
        goto rollback_pml4;
    }
    uint64_t *directory_entry = &directory[page_table_index(virtual_address, 21)];
    bool directory_table_created;
    uint64_t *table = next_table(directory_entry, &directory_table_created, virtual_address, flags);
    if (table == 0) {
        goto rollback_pdpt;
    }
    uint64_t *entry = &table[page_table_index(virtual_address, 12)];
    if ((*entry & PAGE_PRESENT) != 0) {
        goto rollback_directory;
    }

    *entry = (physical_address & PAGE_ADDRESS_MASK) | PAGE_PRESENT | PAGE_KOS_OWNED_MAPPING | flags;
    if ((cpu_read_cr3() & PAGE_ADDRESS_MASK) == pml4_phys) {
        cpu_invalidate_page(virtual_address);
    }
    spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
    return true;

rollback_directory:
    if (directory_table_created) {
        release_owned_empty_table(directory_entry);
    }
rollback_pdpt:
    if (pdpt_table_created) {
        release_owned_empty_table(pdpt_entry);
    }
rollback_pml4:
    if (pml4_table_created) {
        release_owned_empty_table(pml4_entry);
    }
    spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
    return false;
}

bool vmm_map_page(uint64_t virtual_address, uint64_t physical_address, uint64_t flags) {
    return vmm_map_page_in(vmm.kernel_pml4_phys, virtual_address, physical_address, flags);
}

bool vmm_query_page_in(uint64_t pml4_phys, uint64_t virtual_address, uint64_t *physical_address, uint64_t *flags) {
    if (pml4_phys == 0 || pml4_phys % PAGE_SIZE != 0) {
        return false;
    }
    uint64_t interrupt_flags = spinlock_lock_irqsave(&vmm_lock);
    if (!vmm.initialized) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return false;
    }

    uint64_t *target_pml4 = physical_to_virtual(pml4_phys);
    uint64_t entry = target_pml4[page_table_index(virtual_address, 39)];
    if ((entry & PAGE_PRESENT) == 0) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return false;
    }
    uint64_t effective_flags = entry;
    uint64_t *pdpt = physical_to_virtual(entry & PAGE_ADDRESS_MASK);
    entry = pdpt[page_table_index(virtual_address, 30)];
    if ((entry & PAGE_PRESENT) == 0) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return false;
    }
    effective_flags = combine_effective_flags(effective_flags, entry);
    if ((entry & PAGE_HUGE) != 0) {
        if (physical_address != 0) {
            *physical_address = (entry & PAGE_1G_ADDRESS_MASK) | (virtual_address & ((1ull << 30) - 1));
        }
        if (flags != 0) {
            *flags = public_page_flags(effective_flags);
        }
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return true;
    }
    uint64_t *directory = physical_to_virtual(entry & PAGE_ADDRESS_MASK);
    entry = directory[page_table_index(virtual_address, 21)];
    if ((entry & PAGE_PRESENT) == 0) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return false;
    }
    effective_flags = combine_effective_flags(effective_flags, entry);
    if ((entry & PAGE_HUGE) != 0) {
        if (physical_address != 0) {
            *physical_address = (entry & PAGE_2M_ADDRESS_MASK) | (virtual_address & ((1ull << 21) - 1));
        }
        if (flags != 0) {
            *flags = public_page_flags(effective_flags);
        }
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return true;
    }
    uint64_t *table = physical_to_virtual(entry & PAGE_ADDRESS_MASK);
    entry = table[page_table_index(virtual_address, 12)];
    if ((entry & PAGE_PRESENT) == 0) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return false;
    }
    effective_flags = combine_effective_flags(effective_flags, entry);
    if (physical_address != 0) {
        *physical_address = (entry & PAGE_ADDRESS_MASK) | (virtual_address & (PAGE_SIZE - 1));
    }
    if (flags != 0) {
        *flags = public_page_flags(effective_flags);
    }
    spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
    return true;
}

bool vmm_query_page(uint64_t virtual_address, uint64_t *physical_address, uint64_t *flags) {
    return vmm_query_page_in(vmm.kernel_pml4_phys, virtual_address, physical_address, flags);
}

bool vmm_is_mapped(uint64_t virtual_address) {
    return vmm_query_page(virtual_address, 0, 0);
}

static bool set_leaf_permissions(uint64_t virtual_address, uint64_t *entry, uint64_t permissions) {
    *entry = (*entry & ~(VMM_PAGE_WRITABLE | VMM_PAGE_USER | VMM_PAGE_NO_EXECUTE)) | permissions;
    cpu_invalidate_page(virtual_address);
    return true;
}

static bool vmm_set_page_permissions_unlocked(uint64_t virtual_address, uint64_t permissions) {
    if (!vmm.initialized || (permissions & ~(VMM_PAGE_WRITABLE | VMM_PAGE_USER | VMM_PAGE_NO_EXECUTE)) != 0) {
        return false;
    }

    uint64_t *pml4_entry = &vmm.pml4[page_table_index(virtual_address, 39)];
    uint64_t pml4_value = *pml4_entry;
    if ((pml4_value & PAGE_PRESENT) == 0 || (pml4_value & PAGE_HUGE) != 0) {
        return false;
    }
    uint64_t *pdpt = physical_to_virtual(pml4_value & PAGE_ADDRESS_MASK);
    uint64_t *pdpt_entry = &pdpt[page_table_index(virtual_address, 30)];
    uint64_t pdpt_value = *pdpt_entry;
    if ((pdpt_value & PAGE_PRESENT) == 0) {
        return false;
    }
    if ((pdpt_value & PAGE_HUGE) != 0) {
        return set_leaf_permissions(virtual_address, pdpt_entry, permissions);
    }
    uint64_t *directory = physical_to_virtual(pdpt_value & PAGE_ADDRESS_MASK);
    uint64_t *directory_entry = &directory[page_table_index(virtual_address, 21)];
    uint64_t directory_value = *directory_entry;
    if ((directory_value & PAGE_PRESENT) == 0) {
        return false;
    }
    if ((directory_value & PAGE_HUGE) != 0) {
        return set_leaf_permissions(virtual_address, directory_entry, permissions);
    }
    uint64_t *table = physical_to_virtual(directory_value & PAGE_ADDRESS_MASK);
    uint64_t *page_entry = &table[page_table_index(virtual_address, 12)];
    if ((*page_entry & PAGE_PRESENT) == 0) {
        return false;
    }
    return set_leaf_permissions(virtual_address, page_entry, permissions);
}

bool vmm_set_page_permissions(uint64_t virtual_address, uint64_t permissions) {
    uint64_t interrupt_flags = spinlock_lock_irqsave(&vmm_lock);
    bool result = vmm_set_page_permissions_unlocked(virtual_address, permissions);
    spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
    return result;
}

uint64_t vmm_unmap_page_in(uint64_t pml4_phys, uint64_t virtual_address) {
    if (virtual_address % PAGE_SIZE != 0 || pml4_phys == 0 || pml4_phys % PAGE_SIZE != 0) {
        return 0;
    }
    uint64_t interrupt_flags = spinlock_lock_irqsave(&vmm_lock);
    if (!vmm.initialized) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return 0;
    }

    uint64_t *target_pml4 = physical_to_virtual(pml4_phys);
    uint64_t *pml4_entry = &target_pml4[page_table_index(virtual_address, 39)];
    uint64_t pml4_value = *pml4_entry;
    if ((pml4_value & PAGE_PRESENT) == 0 || (pml4_value & PAGE_HUGE) != 0) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return 0;
    }
    uint64_t *pdpt = physical_to_virtual(pml4_value & PAGE_ADDRESS_MASK);
    uint64_t *pdpt_entry = &pdpt[page_table_index(virtual_address, 30)];
    uint64_t pdpt_value = *pdpt_entry;
    if ((pdpt_value & PAGE_PRESENT) == 0 || (pdpt_value & PAGE_HUGE) != 0) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return 0;
    }
    uint64_t *directory = physical_to_virtual(pdpt_value & PAGE_ADDRESS_MASK);
    uint64_t *directory_entry = &directory[page_table_index(virtual_address, 21)];
    uint64_t directory_value = *directory_entry;
    if ((directory_value & PAGE_PRESENT) == 0 || (directory_value & PAGE_HUGE) != 0) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return 0;
    }
    uint64_t *table = physical_to_virtual(directory_value & PAGE_ADDRESS_MASK);
    uint64_t *page_entry = &table[page_table_index(virtual_address, 12)];
    uint64_t entry = *page_entry;
    if ((entry & (PAGE_PRESENT | PAGE_KOS_OWNED_MAPPING))
            != (PAGE_PRESENT | PAGE_KOS_OWNED_MAPPING)) {
        spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
        return 0;
    }

    *page_entry = 0;
    if ((cpu_read_cr3() & PAGE_ADDRESS_MASK) == pml4_phys) {
        cpu_invalidate_page(virtual_address);
    }
    uint64_t physical_address = entry & PAGE_ADDRESS_MASK;

    if (release_owned_empty_table(directory_entry)) {
        if (release_owned_empty_table(pdpt_entry)) {
            release_owned_empty_table(pml4_entry);
        }
    }
    spinlock_unlock_irqrestore(&vmm_lock, interrupt_flags);
    return physical_address;
}

uint64_t vmm_unmap_page(uint64_t virtual_address) {
    return vmm_unmap_page_in(vmm.kernel_pml4_phys, virtual_address);
}

bool vmm_map_pages(uint64_t virtual_address, uint64_t physical_address, uint64_t page_count, uint64_t flags) {
    if (page_count == 0) {
        return true;
    }
    for (uint64_t i = 0; i < page_count; ++i) {
        if (!vmm_map_page(virtual_address + i * PAGE_SIZE, physical_address + i * PAGE_SIZE, flags)) {
            for (uint64_t j = 0; j < i; ++j) {
                (void)vmm_unmap_page(virtual_address + j * PAGE_SIZE);
            }
            return false;
        }
    }
    return true;
}

uint64_t vmm_unmap_pages(uint64_t virtual_address, uint64_t page_count) {
    uint64_t unmapped = 0;
    for (uint64_t i = 0; i < page_count; ++i) {
        if (vmm_unmap_page(virtual_address + i * PAGE_SIZE) != 0) {
            unmapped++;
        }
    }
    return unmapped;
}

static bool vmm_self_test(void) {
    uint64_t initial_free = pmm_free_frame_count();

    uint64_t pml4_phys = vmm_create_address_space();
    if (pml4_phys == 0 || pml4_phys == vmm.kernel_pml4_phys) {
        return false;
    }

    uint64_t *new_pml4 = physical_to_virtual(pml4_phys);
    for (uint64_t i = 0; i < 256; ++i) {
        if (new_pml4[i] != 0) {
            vmm_destroy_address_space(pml4_phys);
            return false;
        }
    }
    for (uint64_t i = 256; i < 512; ++i) {
        if (new_pml4[i] != vmm.pml4[i]) {
            vmm_destroy_address_space(pml4_phys);
            return false;
        }
    }

    uint64_t dummy_frame = pmm_allocate_frame();
    if (dummy_frame == 0) {
        vmm_destroy_address_space(pml4_phys);
        return false;
    }

    /* Verify security: user mapping >= 0x0000800000000000ull rejected */
    if (vmm_map_page_in(pml4_phys, 0x0000800000000000ull, dummy_frame, VMM_PAGE_USER)) {
        pmm_free_frame(dummy_frame);
        vmm_destroy_address_space(pml4_phys);
        return false;
    }

    /* Verify valid user mapping in lower half */
    uint64_t user_va = 0x00400000ull;
    if (!vmm_map_page_in(pml4_phys, user_va, dummy_frame, VMM_PAGE_USER | VMM_PAGE_WRITABLE)) {
        pmm_free_frame(dummy_frame);
        vmm_destroy_address_space(pml4_phys);
        return false;
    }

    uint64_t q_phys = 0;
    uint64_t q_flags = 0;
    if (!vmm_query_page_in(pml4_phys, user_va, &q_phys, &q_flags) || q_phys != dummy_frame) {
        vmm_destroy_address_space(pml4_phys);
        return false;
    }
    if ((q_flags & VMM_PAGE_USER) == 0 || (q_flags & VMM_PAGE_WRITABLE) == 0) {
        vmm_destroy_address_space(pml4_phys);
        return false;
    }

    /* Verify unmapping leaf and table cleanup */
    uint64_t unmapped = vmm_unmap_page_in(pml4_phys, user_va);
    if (unmapped != dummy_frame) {
        vmm_destroy_address_space(pml4_phys);
        return false;
    }
    pmm_free_frame(dummy_frame);

    /* Test recursive destruction with multiple pages mapped */
    uint64_t f1 = pmm_allocate_frame();
    uint64_t f2 = pmm_allocate_frame();
    if (f1 != 0 && f2 != 0) {
        (void)vmm_map_page_in(pml4_phys, 0x00200000ull, f1, VMM_PAGE_USER);
        (void)vmm_map_page_in(pml4_phys, 0x00201000ull, f2, VMM_PAGE_USER | VMM_PAGE_WRITABLE);
    }
    vmm_destroy_address_space(pml4_phys);

    uint64_t final_free = pmm_free_frame_count();
    if (final_free != initial_free) {
        return false;
    }

    log_info("VMM address space lifecycle self-test passed (0 frame leaks).");

    if (!elf_self_test()) {
        return false;
    }

    return true;
}

void *vmm_map_mmio(uint64_t physical_address, uint64_t size_bytes) {
    if (size_bytes == 0) {
        return 0;
    }
    uint64_t page_offset = physical_address & (PAGE_SIZE - 1);
    uint64_t start_phys = physical_address & ~(PAGE_SIZE - 1);
    uint64_t end_phys = (physical_address + size_bytes + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    for (uint64_t p = start_phys; p < end_phys; p += PAGE_SIZE) {
        uint64_t v = (uint64_t)vmm_physical_to_virtual(p);
        if (!vmm_is_mapped(v)) {
            vmm_map_page(v, p, VMM_PAGE_WRITABLE | VMM_PAGE_NO_EXECUTE);
        }
    }
    return (void *)((uint64_t)vmm_physical_to_virtual(start_phys) + page_offset);
}

