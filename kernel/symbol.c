#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/symbol.h>

/* Linker script text section boundaries */
extern char __kernel_text_start[];
extern char __kernel_text_end[];

size_t symbol_count(void) {
    return kernel_symbol_count;
}

const char *symbol_lookup(uint64_t address, uint64_t *offset_out) {
    uint64_t text_start = (uint64_t)(uintptr_t)__kernel_text_start;
    uint64_t text_end = (uint64_t)(uintptr_t)__kernel_text_end;

    if (offset_out != NULL) {
        *offset_out = 0;
    }

    /* Fallback if table is empty or address is outside kernel code bounds */
    if (kernel_symbol_count == 0 || address < text_start || address >= text_end) {
        return "<unknown>";
    }

    if (address < kernel_symbols[0].address) {
        return "<unknown>";
    }

    /*
     * Freestanding iterative binary search:
     * Find the largest index `best` such that kernel_symbols[best].address <= address.
     */
    size_t low = 0;
    size_t high = kernel_symbol_count - 1;
    size_t best = 0;

    while (low <= high) {
        size_t mid = low + ((high - low) / 2);
        if (kernel_symbols[mid].address <= address) {
            best = mid;
            if (mid == SIZE_MAX || mid == kernel_symbol_count - 1) {
                break;
            }
            low = mid + 1;
        } else {
            if (mid == 0) {
                break;
            }
            high = mid - 1;
        }
    }

    if (offset_out != NULL) {
        *offset_out = address - kernel_symbols[best].address;
    }

    return kernel_symbols[best].name;
}
