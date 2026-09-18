#ifndef KOS_SYMBOL_H
#define KOS_SYMBOL_H

#include <stddef.h>
#include <stdint.h>

/*
 * Kernel symbol entry representing a function boundary.
 * Embedded at build-time in .rodata.
 */
struct kernel_symbol {
    uint64_t address;
    const char *name;
};

/*
 * Embedded symbol table and count generated at build-time by kos-tool.
 * Defined in build/kernel_symbols.c (.rodata).
 */
extern const struct kernel_symbol kernel_symbols[];
extern const size_t kernel_symbol_count;

/*
 * Freestanding binary search symbol lookup (O(log N)).
 *
 * Resolves a virtual instruction pointer `address` to the nearest enclosing
 * function symbol whose address <= `address`.
 *
 * Parameters:
 *   address: Instruction pointer (e.g. RIP from interrupt_context or stack frame).
 *   offset_out: Optional pointer to receive byte offset (address - symbol.address).
 *               If NULL, offset is not written.
 *
 * Returns:
 *   The function name string (static .rodata string).
 *   If address is outside kernel text bounds or symbol table is empty,
 *   returns "<unknown>" and sets *offset_out = 0.
 *
 * Safety:
 *   - Freestanding C, zero dynamic memory allocation (no malloc/kmalloc).
 *   - Zero locks or mutexes (safe for panic, exceptions, NMI).
 *   - Read-only access to .rodata.
 */
const char *symbol_lookup(uint64_t address, uint64_t *offset_out);

/*
 * Returns the total number of embedded kernel symbols.
 */
size_t symbol_count(void);

#endif /* KOS_SYMBOL_H */
