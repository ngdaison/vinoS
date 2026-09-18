#include <stdbool.h>
#include <stdint.h>

#include <kos/heap.h>
#include <kos/memory.h>
#include <kos/pmm.h>
#include <kos/sync.h>
#include <kos/vmm.h>

enum {
    PAGE_SIZE = KOS_PAGE_SIZE,
    HEAP_BASE = 0xffffffffc0000000ull,
    HEAP_MAXIMUM_BYTES = 128ull * 1024 * 1024,
    HEAP_ALIGNMENT = 16,
};

struct heap_block {
    uint64_t size;
    struct heap_block *previous;
    struct heap_block *next;
    bool free;
};

struct kernel_heap {
    struct heap_block *first;
    struct heap_block *last;
    uint64_t mapped_bytes;
    uint64_t active_allocations;
    bool initialized;
};

static struct kernel_heap heap;
static struct kos_spinlock heap_lock = KOS_SPINLOCK_INITIALIZER;

static bool align_up(uint64_t value, uint64_t alignment, uint64_t *aligned_value) {
    if (value > UINT64_MAX - (alignment - 1)) {
        return false;
    }
    *aligned_value = (value + alignment - 1) & ~(alignment - 1);
    return true;
}

static bool blocks_are_adjacent(const struct heap_block *left, const struct heap_block *right) {
    return (const uint8_t *)left + sizeof(*left) + left->size == (const uint8_t *)right;
}

static void merge_with_next(struct heap_block *block) {
    struct heap_block *next = block->next;
    if (next == 0 || !next->free || !blocks_are_adjacent(block, next)) {
        return;
    }
    block->size += sizeof(*next) + next->size;
    block->next = next->next;
    if (next->next != 0) {
        next->next->previous = block;
    }
    else {
        heap.last = block;
    }
}

static struct heap_block *find_free_block(uint64_t size) {
    for (struct heap_block *block = heap.first; block != 0; block = block->next) {
        if (block->free && block->size >= size) {
            return block;
        }
    }
    return 0;
}

static struct heap_block *grow_heap(uint64_t requested_size) {
    if (requested_size > HEAP_MAXIMUM_BYTES - sizeof(struct heap_block)) {
        return 0;
    }
    uint64_t required_bytes = requested_size + sizeof(struct heap_block);
    uint64_t page_count = (required_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    uint64_t mapped_bytes = page_count * PAGE_SIZE;
    if (mapped_bytes > HEAP_MAXIMUM_BYTES - heap.mapped_bytes) {
        return 0;
    }

    uint64_t virtual_address = HEAP_BASE + heap.mapped_bytes;
    uint64_t mapped_pages = 0;
    for (; mapped_pages < page_count; ++mapped_pages) {
        uint64_t physical_frame = pmm_allocate_frame();
        if (physical_frame == 0) {
            break;
        }
        if (!vmm_map_page(virtual_address + mapped_pages * PAGE_SIZE, physical_frame,
                VMM_PAGE_WRITABLE | VMM_PAGE_NO_EXECUTE)) {
            pmm_free_frame(physical_frame);
            break;
        }
    }
    if (mapped_pages != page_count) {
        for (uint64_t page = 0; page < mapped_pages; ++page) {
            uint64_t physical_frame = vmm_unmap_page(virtual_address + page * PAGE_SIZE);
            if (physical_frame != 0) {
                pmm_free_frame(physical_frame);
            }
        }
        return 0;
    }

    struct heap_block *block = (struct heap_block *)virtual_address;
    block->size = mapped_bytes - sizeof(*block);
    block->previous = heap.last;
    block->next = 0;
    block->free = true;
    if (heap.last != 0) {
        heap.last->next = block;
    }
    else {
        heap.first = block;
    }
    heap.last = block;
    heap.mapped_bytes += mapped_bytes;
    return block;
}

static void reclaim_trailing_block(void) {
    struct heap_block *block = heap.last;
    if (block == 0 || !block->free || (uint64_t)block % PAGE_SIZE != 0) {
        return;
    }
    uint64_t block_bytes = sizeof(*block) + block->size;
    if (block_bytes % PAGE_SIZE != 0) {
        return;
    }
    uint64_t block_address = (uint64_t)block;
    if (block_address + block_bytes != HEAP_BASE + heap.mapped_bytes) {
        return;
    }
    struct heap_block *previous = block->previous;

    for (uint64_t offset = 0; offset < block_bytes; offset += PAGE_SIZE) {
        uint64_t physical_frame = vmm_unmap_page(block_address + offset);
        if (physical_frame == 0 || !pmm_free_frame(physical_frame)) {
            return;
        }
    }
    heap.last = previous;
    if (heap.last != 0) {
        heap.last->next = 0;
    }
    else {
        heap.first = 0;
    }
    heap.mapped_bytes -= block_bytes;
}

bool heap_initialize(void) {
    uint64_t flags = spinlock_lock_irqsave(&heap_lock);
    heap.first = 0;
    heap.last = 0;
    heap.mapped_bytes = 0;
    heap.active_allocations = 0;
    heap.initialized = true;
    spinlock_unlock_irqrestore(&heap_lock, flags);
    return true;
}

void *kmalloc(uint64_t size) {
    uint64_t flags = spinlock_lock_irqsave(&heap_lock);
    if (!heap.initialized || size == 0) {
        spinlock_unlock_irqrestore(&heap_lock, flags);
        return 0;
    }
    if (!align_up(size, HEAP_ALIGNMENT, &size)) {
        spinlock_unlock_irqrestore(&heap_lock, flags);
        return 0;
    }
    struct heap_block *block = find_free_block(size);
    if (block == 0) {
        block = grow_heap(size);
        if (block == 0) {
            spinlock_unlock_irqrestore(&heap_lock, flags);
            return 0;
        }
    }

    if (block->size >= size + sizeof(*block) + HEAP_ALIGNMENT) {
        struct heap_block *split = (struct heap_block *)((uint8_t *)block + sizeof(*block) + size);
        split->size = block->size - size - sizeof(*split);
        split->previous = block;
        split->next = block->next;
        split->free = true;
        if (block->next != 0) {
            block->next->previous = split;
        }
        else {
            heap.last = split;
        }
        block->next = split;
        block->size = size;
    }
    block->free = false;
    ++heap.active_allocations;
    void *allocation = (uint8_t *)block + sizeof(*block);
    spinlock_unlock_irqrestore(&heap_lock, flags);
    return allocation;
}

bool kfree(void *pointer) {
    uint64_t flags = spinlock_lock_irqsave(&heap_lock);
    if (!heap.initialized || pointer == 0) {
        spinlock_unlock_irqrestore(&heap_lock, flags);
        return false;
    }
    uint64_t pointer_address = (uint64_t)pointer;
    if (heap.mapped_bytes == 0 || pointer_address < HEAP_BASE + sizeof(struct heap_block)
        || pointer_address >= HEAP_BASE + heap.mapped_bytes) {
        spinlock_unlock_irqrestore(&heap_lock, flags);
        return false;
    }
    struct heap_block *candidate = (struct heap_block *)(pointer_address - sizeof(struct heap_block));
    struct heap_block *block = heap.first;
    while (block != 0 && block != candidate) {
        block = block->next;
    }
    if (block == 0 || block->free) {
        spinlock_unlock_irqrestore(&heap_lock, flags);
        return false;
    }

    if (heap.active_allocations == 0) {
        spinlock_unlock_irqrestore(&heap_lock, flags);
        return false;
    }
    block->free = true;
    --heap.active_allocations;
    merge_with_next(block);
    if (block->previous != 0 && block->previous->free) {
        merge_with_next(block->previous);
    }
    reclaim_trailing_block();
    spinlock_unlock_irqrestore(&heap_lock, flags);
    return true;
}

void *kcalloc(uint64_t num, uint64_t size) {
    if (num != 0 && size > UINT64_MAX / num) {
        return 0;
    }
    uint64_t total = num * size;
    void *ptr = kmalloc(total);
    if (ptr != 0) {
        for (uint64_t i = 0; i < total; ++i) {
            ((uint8_t *)ptr)[i] = 0;
        }
    }
    return ptr;
}

void *krealloc(void *pointer, uint64_t new_size) {
    if (pointer == 0) {
        return kmalloc(new_size);
    }
    if (new_size == 0) {
        (void)kfree(pointer);
        return 0;
    }

    uint64_t flags = spinlock_lock_irqsave(&heap_lock);
    if (!heap.initialized) {
        spinlock_unlock_irqrestore(&heap_lock, flags);
        return 0;
    }

    uint64_t pointer_address = (uint64_t)pointer;
    if (heap.mapped_bytes == 0 || pointer_address < HEAP_BASE + sizeof(struct heap_block)
        || pointer_address >= HEAP_BASE + heap.mapped_bytes) {
        spinlock_unlock_irqrestore(&heap_lock, flags);
        return 0;
    }

    struct heap_block *candidate = (struct heap_block *)(pointer_address - sizeof(struct heap_block));
    struct heap_block *block = heap.first;
    while (block != 0 && block != candidate) {
        block = block->next;
    }
    if (block == 0 || block->free) {
        spinlock_unlock_irqrestore(&heap_lock, flags);
        return 0;
    }

    uint64_t old_size = block->size;
    spinlock_unlock_irqrestore(&heap_lock, flags);

    if (new_size <= old_size) {
        return pointer;
    }

    void *new_ptr = kmalloc(new_size);
    if (new_ptr == 0) {
        return 0;
    }
    uint64_t copy_bytes = old_size < new_size ? old_size : new_size;
    for (uint64_t i = 0; i < copy_bytes; ++i) {
        ((uint8_t *)new_ptr)[i] = ((uint8_t *)pointer)[i];
    }
    (void)kfree(pointer);
    return new_ptr;
}

uint64_t heap_active_allocation_count(void) {
    uint64_t flags = spinlock_lock_irqsave(&heap_lock);
    uint64_t result = heap.active_allocations;
    spinlock_unlock_irqrestore(&heap_lock, flags);
    return result;
}

uint64_t heap_mapped_page_count(void) {
    uint64_t flags = spinlock_lock_irqsave(&heap_lock);
    uint64_t result = heap.mapped_bytes / PAGE_SIZE;
    spinlock_unlock_irqrestore(&heap_lock, flags);
    return result;
}
