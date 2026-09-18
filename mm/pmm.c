#include <stdbool.h>
#include <stdint.h>

#include <kos/memory.h>
#include <kos/pmm.h>
#include <kos/sync.h>

enum {
    FRAME_SIZE = KOS_PAGE_SIZE,
    MAX_TRACKED_PHYSICAL_MEMORY = 64ull * 1024 * 1024 * 1024,
    MAX_TRACKED_FRAMES = MAX_TRACKED_PHYSICAL_MEMORY / FRAME_SIZE,
    BITMAP_WORDS = MAX_TRACKED_FRAMES / 64,
};

struct physical_memory_manager {
    uint64_t usable_bitmap[BITMAP_WORDS];
    uint64_t free_bitmap[BITMAP_WORDS];
    uint64_t total_memory_bytes;
    uint64_t usable_memory_bytes;
    uint64_t kernel_memory_bytes;
    uint64_t framebuffer_memory_bytes;
    uint64_t bootloader_reclaimable_bytes;
    uint64_t tracked_usable_frames;
    uint64_t free_frames;
    uint64_t frame_search_limit;
    uint64_t allocation_hint;
    bool initialized;
};

static struct physical_memory_manager pmm;
static struct kos_spinlock pmm_lock = KOS_SPINLOCK_INITIALIZER;

static uint64_t saturating_add(uint64_t left, uint64_t right) {
    if (UINT64_MAX - left < right) {
        return UINT64_MAX;
    }
    return left + right;
}

static uint64_t align_up_frame(uint64_t address) {
    return address / FRAME_SIZE + (address % FRAME_SIZE != 0);
}

static uint64_t align_down_frame(uint64_t address) {
    return address / FRAME_SIZE;
}

static bool frame_is_tracked(uint64_t frame) {
    return frame < MAX_TRACKED_FRAMES;
}

static uint64_t frame_mask(uint64_t frame) {
    return 1ull << (frame % 64);
}

static bool bitmap_test(const uint64_t *bitmap, uint64_t frame) {
    return (bitmap[frame / 64] & frame_mask(frame)) != 0;
}

static void bitmap_set(uint64_t *bitmap, uint64_t frame) {
    bitmap[frame / 64] |= frame_mask(frame);
}

static void bitmap_clear(uint64_t *bitmap, uint64_t frame) {
    bitmap[frame / 64] &= ~frame_mask(frame);
}

static void zero_bitmap(uint64_t *bitmap) {
    for (uint64_t index = 0; index < BITMAP_WORDS; ++index) {
        bitmap[index] = 0;
    }
}

static uint64_t bitmap_range_mask(uint64_t word, uint64_t first_frame, uint64_t end_frame) {
    uint64_t word_first_frame = word * 64;
    uint64_t first_bit = first_frame > word_first_frame ? first_frame - word_first_frame : 0;
    uint64_t word_end_frame = word_first_frame + 64;
    uint64_t end_bit = end_frame < word_end_frame ? end_frame - word_first_frame : 64;
    if (first_bit >= end_bit) {
        return 0;
    }
    uint64_t lower_mask = UINT64_MAX << first_bit;
    uint64_t upper_mask = end_bit == 64 ? UINT64_MAX : (1ull << end_bit) - 1;
    return lower_mask & upper_mask;
}

static void mark_usable_frames(uint64_t first_frame, uint64_t end_frame) {
    if (first_frame >= end_frame) {
        return;
    }
    uint64_t first_word = first_frame / 64;
    uint64_t last_word = (end_frame - 1) / 64;
    for (uint64_t word = first_word; word <= last_word; ++word) {
        uint64_t mask = bitmap_range_mask(word, first_frame, end_frame);
        uint64_t newly_usable = mask & ~pmm.usable_bitmap[word];
        pmm.usable_bitmap[word] |= mask;
        pmm.free_bitmap[word] |= newly_usable;
        uint64_t added_frames = (uint64_t)__builtin_popcountll(newly_usable);
        pmm.tracked_usable_frames += added_frames;
        pmm.free_frames += added_frames;
    }
}

static bool memory_type_is_physical_ram(uint64_t type) {
    switch (type) {
        case LIMINE_MEMMAP_USABLE:
        case LIMINE_MEMMAP_ACPI_RECLAIMABLE:
        case LIMINE_MEMMAP_ACPI_NVS:
        case LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE:
        case LIMINE_MEMMAP_EXECUTABLE_AND_MODULES:
        case LIMINE_MEMMAP_FRAMEBUFFER:
            return true;
        default:
            return false;
    }
}

static void account_memory_type(const struct limine_memmap_entry *entry) {
    switch (entry->type) {
        case LIMINE_MEMMAP_EXECUTABLE_AND_MODULES:
            pmm.kernel_memory_bytes = saturating_add(pmm.kernel_memory_bytes, entry->length);
            break;
        case LIMINE_MEMMAP_FRAMEBUFFER:
            pmm.framebuffer_memory_bytes = saturating_add(pmm.framebuffer_memory_bytes, entry->length);
            break;
        case LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE:
            pmm.bootloader_reclaimable_bytes = saturating_add(pmm.bootloader_reclaimable_bytes, entry->length);
            break;
        default:
            break;
    }
}

static void mark_usable_range(uint64_t base, uint64_t length) {
    if (length == 0 || base >= MAX_TRACKED_PHYSICAL_MEMORY) {
        return;
    }

    uint64_t end = saturating_add(base, length);
    if (end > MAX_TRACKED_PHYSICAL_MEMORY) {
        end = MAX_TRACKED_PHYSICAL_MEMORY;
    }
    uint64_t first_frame = align_up_frame(base);
    uint64_t end_frame = align_down_frame(end);
    if (end_frame > pmm.frame_search_limit) {
        pmm.frame_search_limit = end_frame;
    }

    if (first_frame == 0) {
        first_frame = 1;
    }
    mark_usable_frames(first_frame, end_frame);
}

bool pmm_initialize(const struct limine_memmap_response *memory_map) {
    if (memory_map == 0 || memory_map->entries == 0) {
        return false;
    }

    uint64_t flags = spinlock_lock_irqsave(&pmm_lock);

    zero_bitmap(pmm.usable_bitmap);
    zero_bitmap(pmm.free_bitmap);
    pmm.total_memory_bytes = 0;
    pmm.usable_memory_bytes = 0;
    pmm.kernel_memory_bytes = 0;
    pmm.framebuffer_memory_bytes = 0;
    pmm.bootloader_reclaimable_bytes = 0;
    pmm.tracked_usable_frames = 0;
    pmm.free_frames = 0;
    pmm.frame_search_limit = 1;
    pmm.allocation_hint = 1;
    pmm.initialized = false;

    for (uint64_t index = 0; index < memory_map->entry_count; ++index) {
        const struct limine_memmap_entry *entry = memory_map->entries[index];
        if (entry == 0) {
            spinlock_unlock_irqrestore(&pmm_lock, flags);
            return false;
        }
        if (memory_type_is_physical_ram(entry->type)) {
            pmm.total_memory_bytes = saturating_add(pmm.total_memory_bytes, entry->length);
        }
        account_memory_type(entry);
        if (entry->type == LIMINE_MEMMAP_USABLE) {
            pmm.usable_memory_bytes = saturating_add(pmm.usable_memory_bytes, entry->length);
            mark_usable_range(entry->base, entry->length);
        }
    }

    if (pmm.frame_search_limit > MAX_TRACKED_FRAMES) {
        pmm.frame_search_limit = MAX_TRACKED_FRAMES;
    }
    pmm.initialized = pmm.free_frames != 0;
    bool initialized = pmm.initialized;
    spinlock_unlock_irqrestore(&pmm_lock, flags);
    return initialized;
}

static uint64_t find_free_frame(uint64_t start, uint64_t end) {
    if (start >= end) {
        return 0;
    }
    uint64_t first_word = start / 64;
    uint64_t last_word = (end - 1) / 64;
    for (uint64_t word = first_word; word <= last_word; ++word) {
        uint64_t candidates = pmm.free_bitmap[word] & bitmap_range_mask(word, start, end);
        if (candidates != 0) {
            return word * 64 + (uint64_t)__builtin_ctzll(candidates);
        }
    }
    return 0;
}

uint64_t pmm_allocate_frame(void) {
    uint64_t flags = spinlock_lock_irqsave(&pmm_lock);
    if (!pmm.initialized) {
        spinlock_unlock_irqrestore(&pmm_lock, flags);
        return 0;
    }

    uint64_t frame = find_free_frame(pmm.allocation_hint, pmm.frame_search_limit);
    if (frame == 0 && pmm.allocation_hint > 1) {
        frame = find_free_frame(1, pmm.allocation_hint);
    }
    if (frame == 0) {
        spinlock_unlock_irqrestore(&pmm_lock, flags);
        return 0;
    }

    bitmap_clear(pmm.free_bitmap, frame);
    --pmm.free_frames;
    pmm.allocation_hint = frame + 1;
    if (pmm.allocation_hint >= pmm.frame_search_limit) {
        pmm.allocation_hint = 1;
    }
    uint64_t physical_address = frame * FRAME_SIZE;
    spinlock_unlock_irqrestore(&pmm_lock, flags);
    return physical_address;
}

bool pmm_free_frame(uint64_t physical_address) {
    uint64_t flags = spinlock_lock_irqsave(&pmm_lock);
    if (!pmm.initialized || physical_address == 0 || physical_address % FRAME_SIZE != 0) {
        spinlock_unlock_irqrestore(&pmm_lock, flags);
        return false;
    }
    uint64_t frame = physical_address / FRAME_SIZE;
    if (!frame_is_tracked(frame) || !bitmap_test(pmm.usable_bitmap, frame) || bitmap_test(pmm.free_bitmap, frame)) {
        spinlock_unlock_irqrestore(&pmm_lock, flags);
        return false;
    }
    bitmap_set(pmm.free_bitmap, frame);
    ++pmm.free_frames;
    if (frame < pmm.allocation_hint) {
        pmm.allocation_hint = frame;
    }
    spinlock_unlock_irqrestore(&pmm_lock, flags);
    return true;
}

uint64_t pmm_alloc_page(void) {
    return pmm_allocate_frame();
}

bool pmm_free_page(uint64_t physical_address) {
    return pmm_free_frame(physical_address);
}

uint64_t pmm_alloc_pages(uint64_t count) {
    if (count == 0) {
        return 0;
    }
    if (count == 1) {
        return pmm_allocate_frame();
    }
    uint64_t flags = spinlock_lock_irqsave(&pmm_lock);
    if (!pmm.initialized || pmm.free_frames < count) {
        spinlock_unlock_irqrestore(&pmm_lock, flags);
        return 0;
    }

    uint64_t consecutive = 0;
    uint64_t start_frame = 0;
    for (uint64_t frame = pmm.allocation_hint; frame < pmm.frame_search_limit; ++frame) {
        if (bitmap_test(pmm.free_bitmap, frame)) {
            if (consecutive == 0) {
                start_frame = frame;
            }
            consecutive++;
            if (consecutive == count) {
                break;
            }
        } else {
            consecutive = 0;
        }
    }

    if (consecutive < count && pmm.allocation_hint > 1) {
        consecutive = 0;
        for (uint64_t frame = 1; frame < pmm.allocation_hint + count && frame < pmm.frame_search_limit; ++frame) {
            if (bitmap_test(pmm.free_bitmap, frame)) {
                if (consecutive == 0) {
                    start_frame = frame;
                }
                consecutive++;
                if (consecutive == count) {
                    break;
                }
            } else {
                consecutive = 0;
            }
        }
    }

    if (consecutive < count) {
        spinlock_unlock_irqrestore(&pmm_lock, flags);
        return 0;
    }

    for (uint64_t i = 0; i < count; ++i) {
        bitmap_clear(pmm.free_bitmap, start_frame + i);
    }
    pmm.free_frames -= count;
    pmm.allocation_hint = start_frame + count;
    if (pmm.allocation_hint >= pmm.frame_search_limit) {
        pmm.allocation_hint = 1;
    }
    uint64_t physical_address = start_frame * FRAME_SIZE;
    spinlock_unlock_irqrestore(&pmm_lock, flags);
    return physical_address;
}

bool pmm_free_pages(uint64_t physical_address, uint64_t count) {
    if (count == 0) {
        return false;
    }
    if (count == 1) {
        return pmm_free_frame(physical_address);
    }
    uint64_t flags = spinlock_lock_irqsave(&pmm_lock);
    if (!pmm.initialized || physical_address == 0 || physical_address % FRAME_SIZE != 0) {
        spinlock_unlock_irqrestore(&pmm_lock, flags);
        return false;
    }
    uint64_t start_frame = physical_address / FRAME_SIZE;
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t frame = start_frame + i;
        if (!frame_is_tracked(frame) || !bitmap_test(pmm.usable_bitmap, frame) || bitmap_test(pmm.free_bitmap, frame)) {
            spinlock_unlock_irqrestore(&pmm_lock, flags);
            return false;
        }
    }
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t frame = start_frame + i;
        bitmap_set(pmm.free_bitmap, frame);
    }
    pmm.free_frames += count;
    if (start_frame < pmm.allocation_hint) {
        pmm.allocation_hint = start_frame;
    }
    spinlock_unlock_irqrestore(&pmm_lock, flags);
    return true;
}

uint64_t pmm_total_memory_bytes(void) {
    uint64_t flags = spinlock_lock_irqsave(&pmm_lock);
    uint64_t result = pmm.total_memory_bytes;
    spinlock_unlock_irqrestore(&pmm_lock, flags);
    return result;
}

uint64_t pmm_usable_memory_bytes(void) {
    uint64_t flags = spinlock_lock_irqsave(&pmm_lock);
    uint64_t result = pmm.usable_memory_bytes;
    spinlock_unlock_irqrestore(&pmm_lock, flags);
    return result;
}

uint64_t pmm_tracked_memory_bytes(void) {
    uint64_t flags = spinlock_lock_irqsave(&pmm_lock);
    uint64_t result = pmm.tracked_usable_frames * FRAME_SIZE;
    spinlock_unlock_irqrestore(&pmm_lock, flags);
    return result;
}

uint64_t pmm_kernel_memory_bytes(void) {
    uint64_t flags = spinlock_lock_irqsave(&pmm_lock);
    uint64_t result = pmm.kernel_memory_bytes;
    spinlock_unlock_irqrestore(&pmm_lock, flags);
    return result;
}

uint64_t pmm_framebuffer_memory_bytes(void) {
    uint64_t flags = spinlock_lock_irqsave(&pmm_lock);
    uint64_t result = pmm.framebuffer_memory_bytes;
    spinlock_unlock_irqrestore(&pmm_lock, flags);
    return result;
}

uint64_t pmm_bootloader_reclaimable_bytes(void) {
    uint64_t flags = spinlock_lock_irqsave(&pmm_lock);
    uint64_t result = pmm.bootloader_reclaimable_bytes;
    spinlock_unlock_irqrestore(&pmm_lock, flags);
    return result;
}

uint64_t pmm_free_frame_count(void) {
    uint64_t flags = spinlock_lock_irqsave(&pmm_lock);
    uint64_t result = pmm.free_frames;
    spinlock_unlock_irqrestore(&pmm_lock, flags);
    return result;
}

uint64_t pmm_allocated_frame_count(void) {
    uint64_t flags = spinlock_lock_irqsave(&pmm_lock);
    uint64_t result = pmm.tracked_usable_frames - pmm.free_frames;
    spinlock_unlock_irqrestore(&pmm_lock, flags);
    return result;
}

uint64_t pmm_frame_size(void) {
    return FRAME_SIZE;
}
